package main

import (
	_ "embed"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"syscall/js"
)

//go:embed ruleset.yaml
var embeddedRuleset string

var (
	UserAgent    = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
	ForwardedFor = "66.249.66.1"
	parsedRules  []Rule
)

// Simple rule structures for WASM (without YAML dependency)
type Rule struct {
	Domain    string
	Domains   []string
	Headers   RuleHeaders
	Injections []Injection
	RegexRules []RegexRule
	URLMods   URLModifications
	GoogleCache bool
}

type RuleHeaders struct {
	UserAgent     string
	XForwardedFor string
	Referer       string
	Cookie        string
	CSP           string
}

type Injection struct {
	Position string
	Append   string
	Prepend  string
	Replace  string
}

type RegexRule struct {
	Match   string
	Replace string
}

type URLModifications struct {
	Query []QueryMod
}

type QueryMod struct {
	Key   string
	Value string
}

func main() {
	fmt.Println("Ladderflare WASM starting...")

	// Initialize configurable user agent from environment (passed from JS)
	if userAgentEnv := js.Global().Get("USER_AGENT_ENV"); !userAgentEnv.IsUndefined() {
		UserAgent = userAgentEnv.String()
	}

	// Initialize configurable X-Forwarded-For from environment (passed from JS)
	if forwardedForEnv := js.Global().Get("X_FORWARDED_FOR_ENV"); !forwardedForEnv.IsUndefined() {
		ForwardedFor = forwardedForEnv.String()
	}

	// Parse embedded ruleset
	parseRuleset()

	// Keep references to prevent garbage collection
	var handleRequestFunc = js.FuncOf(handleRequest)
	var getRulesetFunc = js.FuncOf(getRuleset)
	var getRulesetDomainsFunc = js.FuncOf(getRulesetDomains)
	var fetchURLFunc = js.FuncOf(fetchURL)
	var processContentFunc = js.FuncOf(processContent)

	// Register JavaScript functions for Cloudflare Worker
	js.Global().Set("handleRequest", handleRequestFunc)
	js.Global().Set("getRuleset", getRulesetFunc)
	js.Global().Set("getRulesetDomains", getRulesetDomainsFunc)
	js.Global().Set("fetchURL", fetchURLFunc)
	js.Global().Set("processContent", processContentFunc)

	fmt.Printf("Ladderflare WASM initialized with %d rules, UserAgent: %s\n", len(parsedRules), UserAgent)

	// Wait indefinitely to keep the program alive
	select {}
}

// handleRequest processes HTTP requests from the Cloudflare Worker
func handleRequest(this js.Value, args []js.Value) interface{} {
	if len(args) < 3 {
		return createErrorResponse(400, "Invalid arguments")
	}

	method := args[0].String()
	path := args[1].String()
	// headers := args[2] // Request headers from JavaScript

	// Handle special endpoints
	switch {
	case path == "/test":
		return createRedirectResponse("/https://www.ft.com/content/5348ec64-010e-40f4-a27e-6d1252a0c537")
	case path == "/ruleset":
		return createRulesetResponse()
	}

	// Extract target URL from path
	targetURL, err := extractURL(path)
	if err != nil {
		return createErrorResponse(400, fmt.Sprintf("Invalid URL: %s", err.Error()))
	}

	// Only allow GET requests for proxy functionality
	if method != "GET" {
		return createErrorResponse(405, "Method Not Allowed")
	}

	// Return async proxy response placeholder
	// The actual fetching will be handled by JavaScript calling fetchURL
	result := js.Global().Get("Object").New()
	result.Set("status", 200)
	result.Set("proxyURL", targetURL)
	result.Set("needsFetch", true)

	headers := js.Global().Get("Object").New()
	headers.Set("Content-Type", "text/html")
	result.Set("headers", headers)

	return result
}

// extractURL extracts the target URL from the request path
func extractURL(path string) (string, error) {
	// Remove leading slash
	urlPath := strings.TrimPrefix(path, "/")

	// Try to parse as URL
	parsedURL, err := url.Parse(urlPath)
	if err != nil {
		return "", fmt.Errorf("error parsing URL '%s': %v", urlPath, err)
	}

	// Ensure we have a scheme
	if parsedURL.Scheme == "" {
		return "", fmt.Errorf("URL must include scheme (http/https): %s", urlPath)
	}

	return parsedURL.String(), nil
}

// fetchURL handles the actual HTTP fetching (called from JavaScript)
func fetchURL(this js.Value, args []js.Value) interface{} {
	if len(args) < 1 {
		return createErrorResponse(400, "URL required")
	}

	targetURL := args[0].String()

	// Parse the URL to get domain for rule matching
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return createErrorResponse(400, fmt.Sprintf("Invalid URL: %s", err.Error()))
	}

	// Find matching rule for this domain
	rule := findRuleForDomain(parsedURL.Host)

	// Apply URL modifications if present
	finalURL := applyURLModifications(targetURL, rule)

	// Create response with fetch instructions for JavaScript
	result := js.Global().Get("Object").New()
	result.Set("url", finalURL)

	// Apply domain-specific headers or defaults
	if rule.Headers.UserAgent != "" {
		result.Set("userAgent", rule.Headers.UserAgent)
	} else {
		result.Set("userAgent", UserAgent)
	}

	if rule.Headers.Referer != "" {
		if rule.Headers.Referer != "none" {
			result.Set("referer", rule.Headers.Referer)
		}
	} else {
		result.Set("referer", parsedURL.Scheme + "://" + parsedURL.Host)
	}

	if rule.Headers.XForwardedFor != "" {
		if rule.Headers.XForwardedFor != "none" {
			result.Set("xForwardedFor", rule.Headers.XForwardedFor)
		}
	} else {
		result.Set("xForwardedFor", ForwardedFor)
	}

	if rule.Headers.Cookie != "" {
		result.Set("cookie", rule.Headers.Cookie)
	}

	if rule.Headers.CSP != "" {
		result.Set("csp", rule.Headers.CSP)
	}

	// Include rule info for content processing
	result.Set("hasInjections", len(rule.Injections) > 0)
	result.Set("hasRegexRules", len(rule.RegexRules) > 0)

	return result
}

// rewriteHTML rewrites HTML content to proxy relative URLs
func rewriteHTML(body, originalHost string) string {
	// Rewrite relative URLs to go through proxy
	proxyPrefix := "/https://" + originalHost + "/"

	// Images
	imagePattern := `<img\s+([^>]*\s+)?src="(/)([^"]*)"`
	re := regexp.MustCompile(imagePattern)
	body = re.ReplaceAllString(body, fmt.Sprintf(`<img $1src="%s$3"`, proxyPrefix))

	// Scripts
	scriptPattern := `<script\s+([^>]*\s+)?src="(/)([^"]*)"`
	reScript := regexp.MustCompile(scriptPattern)
	body = reScript.ReplaceAllString(body, fmt.Sprintf(`<script $1src="%s$3"`, proxyPrefix))

	// Links
	body = strings.ReplaceAll(body, `href="/`, `href="`+proxyPrefix)

	// CSS urls
	body = strings.ReplaceAll(body, `url('/`, `url('`+proxyPrefix)
	body = strings.ReplaceAll(body, `url(/`, `url(`+proxyPrefix)

	// Absolute URLs back to proxy
	body = strings.ReplaceAll(body, `href="https://`+originalHost, `href="/https://`+originalHost+"/")

	return body
}

// Helper functions for creating responses
func createErrorResponse(status int, message string) js.Value {
	result := js.Global().Get("Object").New()
	result.Set("status", status)
	result.Set("body", message)

	headers := js.Global().Get("Object").New()
	headers.Set("Content-Type", "text/plain")
	result.Set("headers", headers)

	return result
}

func createRedirectResponse(location string) js.Value {
	result := js.Global().Get("Object").New()
	result.Set("status", 302)
	result.Set("body", `<html><body>Redirecting...</body></html>`)

	headers := js.Global().Get("Object").New()
	headers.Set("Content-Type", "text/html")
	headers.Set("Location", location)
	result.Set("headers", headers)

	return result
}

func createRulesetResponse() js.Value {
	result := js.Global().Get("Object").New()
	result.Set("status", 200)
	result.Set("body", embeddedRuleset)

	headers := js.Global().Get("Object").New()
	headers.Set("Content-Type", "application/x-yaml")
	result.Set("headers", headers)

	return result
}

// getRuleset returns the embedded ruleset
func getRuleset(this js.Value, args []js.Value) interface{} {
	return embeddedRuleset
}

// getRulesetDomains returns all domains covered by the ruleset
func getRulesetDomains(this js.Value, args []js.Value) interface{} {
	domains := make([]interface{}, 0)

	for _, rule := range parsedRules {
		if rule.Domain != "" {
			domains = append(domains, rule.Domain)
		}
		for _, domain := range rule.Domains {
			domains = append(domains, domain)
		}
	}

	return domains
}

// processContent applies content modifications (injections + regex rules)
func processContent(this js.Value, args []js.Value) interface{} {
	if len(args) < 2 {
		return createErrorResponse(400, "Content and URL required")
	}

	content := args[0].String()
	targetURL := args[1].String()

	// Parse URL to get domain
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return createErrorResponse(400, fmt.Sprintf("Invalid URL: %s", err.Error()))
	}

	// Find matching rule
	rule := findRuleForDomain(parsedURL.Host)

	// Apply regex rules first
	for _, regexRule := range rule.RegexRules {
		re, err := regexp.Compile(regexRule.Match)
		if err != nil {
			fmt.Printf("Invalid regex: %s\n", regexRule.Match)
			continue
		}
		content = re.ReplaceAllString(content, regexRule.Replace)
	}

	// Apply HTML rewriting
	content = rewriteHTML(content, parsedURL.Host)

	// Create result with processed content and injection info
	result := js.Global().Get("Object").New()
	result.Set("content", content)

	// Add injections for JavaScript to apply
	if len(rule.Injections) > 0 {
		injections := js.Global().Get("Array").New()
		for i, injection := range rule.Injections {
			inj := js.Global().Get("Object").New()
			inj.Set("position", injection.Position)
			inj.Set("append", injection.Append)
			inj.Set("prepend", injection.Prepend)
			inj.Set("replace", injection.Replace)
			injections.SetIndex(i, inj)
		}
		result.Set("injections", injections)
	}

	if rule.Headers.CSP != "" {
		result.Set("csp", rule.Headers.CSP)
	}

	return result
}

// parseRuleset parses the embedded YAML ruleset (simplified parser)
func parseRuleset() {
	lines := strings.Split(embeddedRuleset, "\n")
	var currentRule *Rule
	var currentInjection *Injection
	var inInjectionContent bool
	var injectionContent strings.Builder

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Skip empty lines and comments
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		// New rule starts with "- domain:" or "- domains:"
		if strings.HasPrefix(trimmed, "- domain:") {
			if currentRule != nil {
				parsedRules = append(parsedRules, *currentRule)
			}
			currentRule = &Rule{}
			domain := strings.TrimSpace(strings.TrimPrefix(trimmed, "- domain:"))
			currentRule.Domain = domain
		} else if strings.HasPrefix(trimmed, "- domains:") {
			if currentRule != nil {
				parsedRules = append(parsedRules, *currentRule)
			}
			currentRule = &Rule{}
		} else if currentRule != nil {
			// Parse rule properties
			if strings.HasPrefix(trimmed, "- ") && strings.Contains(line, "domains:") {
				// Skip domains list marker
				continue
			} else if strings.HasPrefix(line, "  - ") && currentRule.Domain == "" {
				// Domain in domains list
				domain := strings.TrimSpace(strings.TrimPrefix(trimmed, "- "))
				currentRule.Domains = append(currentRule.Domains, domain)
			} else if strings.Contains(trimmed, "headers:") {
				// Headers section
				continue
			} else if strings.Contains(trimmed, "user-agent:") || strings.Contains(trimmed, "ueser-agent:") { // Handle typo in ruleset
				value := extractValue(trimmed, "user-agent:", "ueser-agent:")
				currentRule.Headers.UserAgent = value
			} else if strings.Contains(trimmed, "x-forwarded-for:") {
				currentRule.Headers.XForwardedFor = extractValue(trimmed, "x-forwarded-for:")
			} else if strings.Contains(trimmed, "referer:") {
				currentRule.Headers.Referer = extractValue(trimmed, "referer:")
			} else if strings.Contains(trimmed, "cookie:") {
				currentRule.Headers.Cookie = extractValue(trimmed, "cookie:")
			} else if strings.Contains(trimmed, "content-security-policy:") {
				currentRule.Headers.CSP = extractValue(trimmed, "content-security-policy:")
			} else if strings.Contains(trimmed, "googleCache:") {
				currentRule.GoogleCache = strings.Contains(trimmed, "true")
			} else if strings.Contains(trimmed, "urlMods:") {
				// Start URL modifications section
				continue
			} else if strings.Contains(trimmed, "query:") && strings.HasPrefix(line, "    ") {
				// URL modifications query section
				continue
			} else if strings.Contains(trimmed, "- key:") && strings.HasPrefix(line, "      ") {
				// New query modification
				queryMod := QueryMod{
					Key: extractValue(trimmed, "key:"),
				}
				currentRule.URLMods.Query = append(currentRule.URLMods.Query, queryMod)
			} else if strings.Contains(trimmed, "value:") && strings.HasPrefix(line, "        ") && len(currentRule.URLMods.Query) > 0 {
				// Update last query mod with value
				lastIdx := len(currentRule.URLMods.Query) - 1
				currentRule.URLMods.Query[lastIdx].Value = extractValue(trimmed, "value:")
			} else if strings.Contains(trimmed, "injections:") {
				// Start injections section
				continue
			} else if strings.Contains(trimmed, "- position:") {
				// New injection
				if currentInjection != nil {
					if inInjectionContent {
						// Finish previous injection content
						setInjectionContent(currentInjection, injectionContent.String())
						injectionContent.Reset()
						inInjectionContent = false
					}
					currentRule.Injections = append(currentRule.Injections, *currentInjection)
				}
				currentInjection = &Injection{}
				currentInjection.Position = extractValue(trimmed, "position:")
			} else if currentInjection != nil && strings.Contains(trimmed, "append:") {
				if strings.Contains(trimmed, "|") {
					// Multi-line content starts
					inInjectionContent = true
					injectionContent.Reset()
				} else {
					currentInjection.Append = extractValue(trimmed, "append:")
				}
			} else if currentInjection != nil && strings.Contains(trimmed, "prepend:") {
				currentInjection.Prepend = extractValue(trimmed, "prepend:")
			} else if currentInjection != nil && strings.Contains(trimmed, "replace:") {
				currentInjection.Replace = extractValue(trimmed, "replace:")
			} else if inInjectionContent && currentInjection != nil {
				// Collect multi-line injection content
				if strings.HasPrefix(line, "      ") { // 6 spaces for injection content
					content := strings.TrimPrefix(line, "      ")
					injectionContent.WriteString(content + "\n")
				} else {
					// End of injection content
					setInjectionContent(currentInjection, injectionContent.String())
					injectionContent.Reset()
					inInjectionContent = false
					currentRule.Injections = append(currentRule.Injections, *currentInjection)
					currentInjection = nil
				}
			} else if strings.Contains(trimmed, "regexRules:") {
				// Start regex rules section
				continue
			} else if strings.Contains(trimmed, "- match:") {
				// New regex rule
				regexRule := RegexRule{
					Match: extractValue(trimmed, "match:"),
				}
				currentRule.RegexRules = append(currentRule.RegexRules, regexRule)
			} else if strings.Contains(trimmed, "replace:") && len(currentRule.RegexRules) > 0 {
				// Update last regex rule with replace value
				lastIdx := len(currentRule.RegexRules) - 1
				currentRule.RegexRules[lastIdx].Replace = extractValue(trimmed, "replace:")
			}
		}
	}

	// Add the last rule
	if currentRule != nil {
		if currentInjection != nil {
			if inInjectionContent {
				setInjectionContent(currentInjection, injectionContent.String())
			}
			currentRule.Injections = append(currentRule.Injections, *currentInjection)
		}
		parsedRules = append(parsedRules, *currentRule)
	}
}

// Helper function to extract value after colon
func extractValue(line string, keys ...string) string {
	for _, key := range keys {
		if idx := strings.Index(line, key); idx != -1 {
			value := strings.TrimSpace(line[idx+len(key):])
			// Remove quotes if present
			if len(value) > 1 && ((value[0] == '"' && value[len(value)-1] == '"') || (value[0] == '\'' && value[len(value)-1] == '\'')) {
				value = value[1 : len(value)-1]
			}
			return value
		}
	}
	return ""
}

// Helper function to set injection content based on type
func setInjectionContent(injection *Injection, content string) {
	content = strings.TrimSpace(content)
	if injection.Append == "" && injection.Prepend == "" && injection.Replace == "" {
		injection.Append = content // Default to append
	}
}

// findRuleForDomain finds the matching rule for a given domain
func findRuleForDomain(domain string) Rule {
	for _, rule := range parsedRules {
		// Check single domain
		if rule.Domain != "" && (rule.Domain == domain || strings.HasSuffix(domain, "."+rule.Domain)) {
			return rule
		}
		// Check domains list
		for _, ruleDomain := range rule.Domains {
			if ruleDomain == domain || strings.HasSuffix(domain, "."+ruleDomain) {
				return rule
			}
		}
	}
	return Rule{} // Return empty rule if no match
}

// applyURLModifications applies URL modifications from rules
func applyURLModifications(targetURL string, rule Rule) string {
	if len(rule.URLMods.Query) == 0 && !rule.GoogleCache {
		return targetURL
	}

	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return targetURL
	}

	// Apply query modifications
	values := parsedURL.Query()
	for _, queryMod := range rule.URLMods.Query {
		if queryMod.Value == "" {
			values.Del(queryMod.Key)
		} else {
			values.Set(queryMod.Key, queryMod.Value)
		}
	}
	parsedURL.RawQuery = values.Encode()

	// Apply Google Cache if enabled
	if rule.GoogleCache {
		return "https://webcache.googleusercontent.com/search?q=cache:" + parsedURL.String()
	}

	return parsedURL.String()
}

