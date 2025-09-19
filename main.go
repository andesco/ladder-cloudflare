package main

import (
	_ "embed"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"syscall/js"

	"github.com/PuerkitoBio/goquery"
	"gopkg.in/yaml.v3"
)

//go:embed ruleset.yaml
var embeddedRuleset string

var (
	UserAgent    = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
	ForwardedFor = "66.249.66.1"
	parsedRules  RuleSet
)

// Full-featured rule structures with yaml.v3 support (matching ladder/pkg/ruleset)
type Regex struct {
	Match   string `yaml:"match"`
	Replace string `yaml:"replace"`
}

type KV struct {
	Key   string `yaml:"key"`
	Value string `yaml:"value"`
}

type RuleSet []Rule

type Rule struct {
	Domain  string   `yaml:"domain,omitempty"`
	Domains []string `yaml:"domains,omitempty"`
	Paths   []string `yaml:"paths,omitempty"`
	Headers struct {
		UserAgent     string `yaml:"user-agent,omitempty"`
		XForwardedFor string `yaml:"x-forwarded-for,omitempty"`
		Referer       string `yaml:"referer,omitempty"`
		Cookie        string `yaml:"cookie,omitempty"`
		CSP           string `yaml:"content-security-policy,omitempty"`
	} `yaml:"headers,omitempty"`
	GoogleCache bool    `yaml:"googleCache,omitempty"`
	RegexRules  []Regex `yaml:"regexRules,omitempty"`

	URLMods struct {
		Domain []Regex `yaml:"domain,omitempty"`
		Path   []Regex `yaml:"path,omitempty"`
		Query  []KV    `yaml:"query,omitempty"`
	} `yaml:"urlMods,omitempty"`

	Injections []struct {
		Position string `yaml:"position,omitempty"`
		Append   string `yaml:"append,omitempty"`
		Prepend  string `yaml:"prepend,omitempty"`
		Replace  string `yaml:"replace,omitempty"`
	} `yaml:"injections,omitempty"`
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

// rewriteHTML rewrites HTML content to proxy relative URLs using GoQuery
func rewriteHTML(body, originalHost string) string {
	// Parse HTML with GoQuery
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(body))
	if err != nil {
		// Fallback to string-based rewriting if parsing fails
		return rewriteHTMLFallback(body, originalHost)
	}

	proxyPrefix := "/https://" + originalHost + "/"

	// Rewrite image sources
	doc.Find("img[src]").Each(func(i int, s *goquery.Selection) {
		src, exists := s.Attr("src")
		if exists && strings.HasPrefix(src, "/") && !strings.HasPrefix(src, "//") {
			s.SetAttr("src", proxyPrefix+strings.TrimPrefix(src, "/"))
		}
	})

	// Rewrite script sources
	doc.Find("script[src]").Each(func(i int, s *goquery.Selection) {
		src, exists := s.Attr("src")
		if exists && strings.HasPrefix(src, "/") && !strings.HasPrefix(src, "//") {
			s.SetAttr("src", proxyPrefix+strings.TrimPrefix(src, "/"))
		}
	})

	// Rewrite link hrefs
	doc.Find("a[href]").Each(func(i int, s *goquery.Selection) {
		href, exists := s.Attr("href")
		if exists {
			if strings.HasPrefix(href, "/") && !strings.HasPrefix(href, "//") {
				s.SetAttr("href", proxyPrefix+strings.TrimPrefix(href, "/"))
			} else if strings.HasPrefix(href, "https://"+originalHost) {
				// Convert absolute URLs back to proxy format
				s.SetAttr("href", "/https://"+originalHost+"/"+strings.TrimPrefix(href, "https://"+originalHost+"/"))
			}
		}
	})

	// Rewrite link rel=stylesheet hrefs
	doc.Find("link[href]").Each(func(i int, s *goquery.Selection) {
		href, exists := s.Attr("href")
		if exists && strings.HasPrefix(href, "/") && !strings.HasPrefix(href, "//") {
			s.SetAttr("href", proxyPrefix+strings.TrimPrefix(href, "/"))
		}
	})

	// Rewrite form actions
	doc.Find("form[action]").Each(func(i int, s *goquery.Selection) {
		action, exists := s.Attr("action")
		if exists && strings.HasPrefix(action, "/") && !strings.HasPrefix(action, "//") {
			s.SetAttr("action", proxyPrefix+strings.TrimPrefix(action, "/"))
		}
	})

	// Get the modified HTML
	html, err := doc.Html()
	if err != nil {
		// Fallback to string-based rewriting if serialization fails
		return rewriteHTMLFallback(body, originalHost)
	}

	// Still need to handle CSS url() rewrites with string replacement since GoQuery doesn't parse CSS
	html = strings.ReplaceAll(html, `url('/`, `url('`+proxyPrefix)
	html = strings.ReplaceAll(html, `url(/`, `url(`+proxyPrefix)

	return html
}

// rewriteHTMLFallback provides string-based rewriting as fallback
func rewriteHTMLFallback(body, originalHost string) string {
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

// processContent applies content modifications (injections + regex rules) using GoQuery
func processContent(this js.Value, args []js.Value) interface{} {
	if len(args) < 2 {
		return createErrorResponse(400, "Content and URL required")
	}

	content := args[0].String()
	targetURL := args[1].String()

	// Parse URL to get domain and path
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return createErrorResponse(400, fmt.Sprintf("Invalid URL: %s", err.Error()))
	}

	// Find matching rule with path support
	rule := findRuleForDomainAndPath(parsedURL.Host, parsedURL.Path)

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

	// Apply content injections using GoQuery
	content = applyContentInjections(content, rule.Injections)

	// Create result with processed content
	result := js.Global().Get("Object").New()
	result.Set("content", content)

	if rule.Headers.CSP != "" {
		result.Set("csp", rule.Headers.CSP)
	}

	return result
}

// applyContentInjections applies content injections using GoQuery for DOM manipulation
func applyContentInjections(content string, injections []struct {
	Position string `yaml:"position,omitempty"`
	Append   string `yaml:"append,omitempty"`
	Prepend  string `yaml:"prepend,omitempty"`
	Replace  string `yaml:"replace,omitempty"`
}) string {
	if len(injections) == 0 {
		return content
	}

	// Parse HTML with GoQuery
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(content))
	if err != nil {
		// Fallback to simple string injection if parsing fails
		return applyContentInjectionsStringFallback(content, injections)
	}

	for _, injection := range injections {
		// Determine target selector and content
		targetSelector := "head"
		injectionContent := ""

		// Determine content to inject
		if injection.Append != "" {
			injectionContent = injection.Append
		} else if injection.Prepend != "" {
			injectionContent = injection.Prepend
		} else if injection.Replace != "" {
			injectionContent = injection.Replace
		}

		// Determine target based on position
		switch injection.Position {
		case "head":
			targetSelector = "head"
		case "body":
			targetSelector = "body"
		case "html":
			targetSelector = "html"
		default:
			// If position looks like a CSS selector, use it directly
			if strings.Contains(injection.Position, ".") || strings.Contains(injection.Position, "#") || strings.Contains(injection.Position, "[") {
				targetSelector = injection.Position
			} else {
				targetSelector = "head" // Default fallback
			}
		}

		// Apply the injection
		target := doc.Find(targetSelector)
		if target.Length() > 0 {
			if injection.Replace != "" {
				// Replace content
				target.SetHtml(injectionContent)
			} else if injection.Prepend != "" {
				// Prepend content
				target.PrependHtml(injectionContent)
			} else {
				// Default to append
				target.AppendHtml(injectionContent)
			}
		} else {
			// If target not found, try fallback to head
			headTarget := doc.Find("head")
			if headTarget.Length() > 0 {
				headTarget.AppendHtml(injectionContent)
			}
		}
	}

	// Get the modified HTML
	html, err := doc.Html()
	if err != nil {
		// Fallback to string injection if serialization fails
		return applyContentInjectionsStringFallback(content, injections)
	}

	return html
}

// applyContentInjectionsStringFallback provides string-based injection as fallback
func applyContentInjectionsStringFallback(content string, injections []struct {
	Position string `yaml:"position,omitempty"`
	Append   string `yaml:"append,omitempty"`
	Prepend  string `yaml:"prepend,omitempty"`
	Replace  string `yaml:"replace,omitempty"`
}) string {
	for _, injection := range injections {
		injectionContent := ""
		if injection.Append != "" {
			injectionContent = injection.Append
		} else if injection.Prepend != "" {
			injectionContent = injection.Prepend
		} else if injection.Replace != "" {
			injectionContent = injection.Replace
		}

		// Simple string-based injection
		switch injection.Position {
		case "head":
			content = strings.Replace(content, "</head>", injectionContent+"\n</head>", 1)
		case "body":
			content = strings.Replace(content, "</body>", injectionContent+"\n</body>", 1)
		default:
			// Default to head
			content = strings.Replace(content, "</head>", injectionContent+"\n</head>", 1)
		}
	}
	return content
}

// parseRuleset parses the embedded YAML ruleset using yaml.v3
func parseRuleset() {
	err := yaml.Unmarshal([]byte(embeddedRuleset), &parsedRules)
	if err != nil {
		fmt.Printf("Error parsing YAML ruleset: %v\n", err)
		return
	}
	fmt.Printf("Successfully parsed %d rules from embedded YAML\n", len(parsedRules))
}


// findRuleForDomain finds the matching rule for a given domain and path
func findRuleForDomain(domain string) Rule {
	return findRuleForDomainAndPath(domain, "")
}

// findRuleForDomainAndPath finds the matching rule for a given domain and path
func findRuleForDomainAndPath(domain, path string) Rule {
	for _, rule := range parsedRules {
		// Check single domain
		if rule.Domain != "" && (rule.Domain == domain || strings.HasSuffix(domain, "."+rule.Domain)) {
			// Check path restrictions if present
			if len(rule.Paths) > 0 {
				matchesPath := false
				for _, rulePath := range rule.Paths {
					if strings.HasPrefix(path, rulePath) {
						matchesPath = true
						break
					}
				}
				if !matchesPath {
					continue
				}
			}
			return rule
		}
		// Check domains list
		for _, ruleDomain := range rule.Domains {
			if ruleDomain == domain || strings.HasSuffix(domain, "."+ruleDomain) {
				// Check path restrictions if present
				if len(rule.Paths) > 0 {
					matchesPath := false
					for _, rulePath := range rule.Paths {
						if strings.HasPrefix(path, rulePath) {
							matchesPath = true
							break
						}
					}
					if !matchesPath {
						continue
					}
				}
				return rule
			}
		}
	}
	return Rule{} // Return empty rule if no match
}

// applyURLModifications applies URL modifications from rules
func applyURLModifications(targetURL string, rule Rule) string {
	if len(rule.URLMods.Query) == 0 && len(rule.URLMods.Domain) == 0 && len(rule.URLMods.Path) == 0 && !rule.GoogleCache {
		return targetURL
	}

	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return targetURL
	}

	// Apply domain modifications
	for _, domainMod := range rule.URLMods.Domain {
		re, err := regexp.Compile(domainMod.Match)
		if err != nil {
			continue
		}
		parsedURL.Host = re.ReplaceAllString(parsedURL.Host, domainMod.Replace)
	}

	// Apply path modifications
	for _, pathMod := range rule.URLMods.Path {
		re, err := regexp.Compile(pathMod.Match)
		if err != nil {
			continue
		}
		parsedURL.Path = re.ReplaceAllString(parsedURL.Path, pathMod.Replace)
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

