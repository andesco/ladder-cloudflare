package main

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"syscall/js"
	"time"

	"github.com/PuerkitoBio/goquery"
	"gopkg.in/yaml.v3"
	"ladderflare/handlers"
)

//go:embed sites_aggregated.yaml
var embeddedRuleset string

// Manifest structure for RULESET_URL handling
type ManifestFile struct {
	Version string `json:"version"`
	URL     string `json:"url"`
}

type Manifest struct {
	SitesAggregatedYAML *ManifestFile `json:"sites_aggregated_yaml"`
	SitesAggregatedJSON *ManifestFile `json:"sites_aggregated_json"`
}

var (
	UserAgent    = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
	ForwardedFor = "66.249.66.1"
	parsedRules  RuleSet
	regexCache   = make(map[string]*regexp.Regexp)
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

type ContentScript struct {
	Action    string `yaml:"action,omitempty"`    // hide_elem, rm_class, rm_attrib, show_elem
	Selector  string `yaml:"selector,omitempty"`  // CSS selector
	Class     string `yaml:"class,omitempty"`     // For rm_class action
	Attribute string `yaml:"attribute,omitempty"` // For rm_attrib action
}

type Rule struct {
	Name    string   `yaml:"name,omitempty"`
	Domain  string   `yaml:"domain,omitempty"`
	Domains []string `yaml:"domains,omitempty"`
	Group   []string `yaml:"group,omitempty"`   // For grouped sites (when domain is ###_prefix)
	Paths   []string `yaml:"paths,omitempty"`

	// Cookie management
	AllowCookies              bool     `yaml:"allow_cookies,omitempty"`
	RemoveCookies             bool     `yaml:"remove_cookies,omitempty"`
	RemoveCookiesSelectHold   []string `yaml:"remove_cookies_select_hold,omitempty"`
	RemoveCookiesSelectDrop   []string `yaml:"remove_cookies_select_drop,omitempty"`

	// Request blocking
	BlockRegex string `yaml:"block_regex,omitempty"`

	// Headers and user agent
	Headers struct {
		UserAgent        string `yaml:"user_agent,omitempty"`
		UserAgentCustom  string `yaml:"user_agent_custom,omitempty"`
		XForwardedFor    string `yaml:"x-forwarded-for,omitempty"`
		Referer          string `yaml:"referer,omitempty"`
		RefererCustom    string `yaml:"referer_custom,omitempty"`
		Cookie           string `yaml:"cookie,omitempty"`
		CSP              string `yaml:"content-security-policy,omitempty"`
		Accept           string `yaml:"accept,omitempty"`
		AcceptLanguage   string `yaml:"accept-language,omitempty"`
		AcceptEncoding   string `yaml:"accept-encoding,omitempty"`
		Authorization    string `yaml:"authorization,omitempty"`
		XRealIP          string `yaml:"x-real-ip,omitempty"`
		XRequestedWith   string `yaml:"x-requested-with,omitempty"`
	} `yaml:"headers,omitempty"`

	// Archive/fallback sources
	GoogleCache  bool `yaml:"googleCache,omitempty"`
	CsDompurify  bool `yaml:"cs_dompurify,omitempty"`

	// Content processing
	RegexRules     []Regex         `yaml:"regexRules,omitempty"`
	ContentScripts []ContentScript `yaml:"content_scripts,omitempty"`

	// URL modifications (legacy)
	URLMods struct {
		Domain []Regex `yaml:"domain,omitempty"`
		Path   []Regex `yaml:"path,omitempty"`
		Query  []KV    `yaml:"query,omitempty"`
	} `yaml:"urlMods,omitempty"`

	// HTML injections
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

	// Check for RULESET_URL and try to fetch remote ruleset, otherwise use embedded
	if rulesetURLEnv := js.Global().Get("RULESET_URL"); !rulesetURLEnv.IsUndefined() {
		rulesetURL := rulesetURLEnv.String()
		fmt.Printf("RULESET_URL found: %s\n", rulesetURL)
		if !fetchRemoteRuleset(rulesetURL) {
			fmt.Println("Failed to fetch remote ruleset, falling back to embedded")
			parseEmbeddedRuleset()
		}
	} else {
		// Parse embedded ruleset
		parseEmbeddedRuleset()
	}

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
		// Convert JS response to Go response
		response := handlers.HandleTest(method, path, map[string]string{})
		return convertResponseToJS(response)
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
	userAgent := UserAgent
	if rule.Headers.UserAgent != "" {
		userAgent = rule.Headers.UserAgent
	} else if rule.Headers.UserAgentCustom != "" {
		userAgent = rule.Headers.UserAgentCustom
	}
	result.Set("userAgent", userAgent)

	// Handle referer
	if rule.Headers.RefererCustom != "" {
		result.Set("referer", rule.Headers.RefererCustom)
	} else if rule.Headers.Referer != "" && rule.Headers.Referer != "none" {
		result.Set("referer", rule.Headers.Referer)
	} else if rule.Headers.Referer == "none" {
		// Don't set referer when explicitly set to "none"
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

	// Include additional headers
	if rule.Headers.Accept != "" {
		result.Set("accept", rule.Headers.Accept)
	}
	if rule.Headers.AcceptLanguage != "" {
		result.Set("acceptLanguage", rule.Headers.AcceptLanguage)
	}
	if rule.Headers.AcceptEncoding != "" {
		result.Set("acceptEncoding", rule.Headers.AcceptEncoding)
	}
	if rule.Headers.Authorization != "" {
		result.Set("authorization", rule.Headers.Authorization)
	}
	if rule.Headers.XRealIP != "" {
		result.Set("xRealIP", rule.Headers.XRealIP)
	}
	if rule.Headers.XRequestedWith != "" {
		result.Set("xRequestedWith", rule.Headers.XRequestedWith)
	}

	// Include rule info for content processing
	result.Set("hasInjections", len(rule.Injections) > 0)
	result.Set("hasRegexRules", len(rule.RegexRules) > 0)

	// Include blocking information
	if rule.BlockRegex != "" {
		result.Set("blockRegex", rule.BlockRegex)
	}

	// Include cookie management info
	result.Set("allowCookies", rule.AllowCookies)
	result.Set("removeCookies", rule.RemoveCookies)
	if len(rule.RemoveCookiesSelectHold) > 0 {
		holdArray := js.Global().Get("Array").New()
		for i, cookie := range rule.RemoveCookiesSelectHold {
			holdArray.SetIndex(i, cookie)
		}
		result.Set("removeCookiesSelectHold", holdArray)
	}
	if len(rule.RemoveCookiesSelectDrop) > 0 {
		dropArray := js.Global().Get("Array").New()
		for i, cookie := range rule.RemoveCookiesSelectDrop {
			dropArray.SetIndex(i, cookie)
		}
		result.Set("removeCookiesSelectDrop", dropArray)
	}

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

	// CSS files - convert to absolute URLs (so they load properly)
	cssPattern := `href="(/[^"]*\.css[^"]*)"`
	reCss := regexp.MustCompile(cssPattern)
	body = reCss.ReplaceAllString(body, fmt.Sprintf(`href="https://%s$1"`, originalHost))

	// Font files - convert to absolute URLs
	fontPattern := `href="(/[^"]*\.(woff2?|ttf|otf|eot)[^"]*)"`
	reFont := regexp.MustCompile(fontPattern)
	body = reFont.ReplaceAllString(body, fmt.Sprintf(`href="https://%s$1"`, originalHost))

	// Navigation links - convert remaining href="/" to proxy URLs
	navPattern := `href="(/[^"]*)"`
	reNav := regexp.MustCompile(navPattern)
	body = reNav.ReplaceAllStringFunc(body, func(match string) string {
		// Extract the path
		path := strings.TrimPrefix(strings.TrimSuffix(match, `"`), `href="/`)
		// Skip if it's a resource file (already handled above)
		if strings.Contains(path, ".css") || strings.Contains(path, ".js") ||
		   strings.Contains(path, ".woff") || strings.Contains(path, ".ttf") ||
		   strings.Contains(path, ".otf") || strings.Contains(path, ".eot") {
			return match
		}
		return `href="` + proxyPrefix + path + `"`
	})

	// CSS urls - convert to absolute URLs
	cssUrlPattern := `url\(['"]?(/[^'"]*)`
	reCssUrl := regexp.MustCompile(cssUrlPattern)
	body = reCssUrl.ReplaceAllString(body, fmt.Sprintf(`url("https://%s$1`, originalHost))

	// Absolute URLs back to proxy (but skip CSS and resource files)
	absPattern := `href="https://` + regexp.QuoteMeta(originalHost) + `([^"]*)"`
	reAbs := regexp.MustCompile(absPattern)
	body = reAbs.ReplaceAllStringFunc(body, func(match string) string {
		// Extract the path
		path := strings.TrimPrefix(match, `href="https://`+originalHost)
		path = strings.TrimSuffix(path, `"`)
		// Skip if it's a resource file (keep absolute)
		if strings.Contains(path, ".css") || strings.Contains(path, ".js") ||
		   strings.Contains(path, ".woff") || strings.Contains(path, ".ttf") ||
		   strings.Contains(path, ".otf") || strings.Contains(path, ".eot") {
			return match
		}
		return `href="/https://` + originalHost + path + `"`
	})

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

func createErrorResponseWithMetrics(status int, message string, startTime time.Time) js.Value {
	result := js.Global().Get("Object").New()
	result.Set("status", status)
	result.Set("body", message)

	headers := js.Global().Get("Object").New()
	headers.Set("Content-Type", "text/plain")
	result.Set("headers", headers)

	// Add performance metrics
	metrics := js.Global().Get("Object").New()
	metrics.Set("totalProcessingTime", time.Since(startTime).Milliseconds())
	metrics.Set("error", true)
	result.Set("metrics", metrics)

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

func convertResponseToJS(response map[string]interface{}) js.Value {
	result := js.Global().Get("Object").New()

	// Set status and body
	if status, ok := response["status"].(int); ok {
		result.Set("status", status)
	}
	if body, ok := response["body"].(string); ok {
		result.Set("body", body)
	}

	// Convert headers map to JS object
	if headersMap, ok := response["headers"].(map[string]string); ok {
		headers := js.Global().Get("Object").New()
		for key, value := range headersMap {
			headers.Set(key, value)
		}
		result.Set("headers", headers)
	}

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
		// Handle single domain (non-grouped)
		if rule.Domain != "" && !strings.HasPrefix(rule.Domain, "###") {
			domains = append(domains, rule.Domain)
		}
		// Handle grouped domains
		for _, domain := range rule.Group {
			domains = append(domains, domain)
		}
		// Handle domains list
		for _, domain := range rule.Domains {
			domains = append(domains, domain)
		}
	}

	return domains
}

// processContent applies content modifications (injections + regex rules) using GoQuery
func processContent(this js.Value, args []js.Value) interface{} {
	startTime := time.Now()

	if len(args) < 2 {
		return createErrorResponse(400, "Content and URL required")
	}

	content := args[0].String()
	targetURL := args[1].String()

	// Parse URL to get domain and path
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return createErrorResponseWithMetrics(400, fmt.Sprintf("Invalid URL: %s", err.Error()), startTime)
	}

	// Find matching rule with path support
	ruleStartTime := time.Now()
	rule := findRuleForDomainAndPath(parsedURL.Host, parsedURL.Path)
	ruleLookupDuration := time.Since(ruleStartTime)

	// Apply regex rules first
	for _, regexRule := range rule.RegexRules {
		re, err := getCachedRegex(regexRule.Match)
		if err != nil {
			fmt.Printf("Invalid regex: %s\n", regexRule.Match)
			continue
		}
		content = re.ReplaceAllString(content, regexRule.Replace)
	}

	// Apply script blocking if regex is specified
	if rule.BlockRegex != "" {
		content = applyScriptBlocking(content, rule.BlockRegex)
	}

	// Apply content scripts (DOM manipulation) before HTML rewriting
	if len(rule.ContentScripts) > 0 {
		content = applyContentScripts(content, rule.ContentScripts)
	}

	// Apply HTML rewriting
	content = rewriteHTML(content, parsedURL.Host)

	// Apply content injections using GoQuery
	content = applyContentInjections(content, rule.Injections)

	// Create result with processed content and metrics
	totalDuration := time.Since(startTime)

	result := js.Global().Get("Object").New()
	result.Set("content", content)

	if rule.Headers.CSP != "" {
		result.Set("csp", rule.Headers.CSP)
	}

	// Add performance metrics
	metrics := js.Global().Get("Object").New()
	metrics.Set("totalProcessingTime", totalDuration.Milliseconds())
	metrics.Set("ruleLookupTime", ruleLookupDuration.Milliseconds())
	metrics.Set("ruleName", rule.Name)
	metrics.Set("contentLength", len(content))
	result.Set("metrics", metrics)

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

// parseEmbeddedRuleset parses the embedded YAML ruleset using yaml.v3
func parseEmbeddedRuleset() {
	err := yaml.Unmarshal([]byte(embeddedRuleset), &parsedRules)
	if err != nil {
		fmt.Printf("Error parsing embedded YAML ruleset: %v\n", err)
		return
	}
	fmt.Printf("Successfully parsed %d rules from embedded YAML\n", len(parsedRules))
}

// fetchRemoteRuleset fetches and parses ruleset from RULESET_URL (manifest.json)
func fetchRemoteRuleset(manifestURL string) bool {
	// Create a promise to fetch the manifest
	fetchPromise := js.Global().Call("fetch", manifestURL)

	// Create a channel to wait for the result
	done := make(chan bool, 1)

	// Handle the promise
	fetchPromise.Call("then", js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		if len(args) == 0 {
			fmt.Println("No response from manifest fetch")
			done <- false
			return nil
		}

		response := args[0]
		if !response.Get("ok").Bool() {
			fmt.Printf("Failed to fetch manifest: %d\n", response.Get("status").Int())
			done <- false
			return nil
		}

		// Parse JSON response
		jsonPromise := response.Call("text")
		jsonPromise.Call("then", js.FuncOf(func(this js.Value, args []js.Value) interface{} {
			if len(args) == 0 {
				fmt.Println("No text from manifest response")
				done <- false
				return nil
			}

			manifestText := args[0].String()
			var manifest Manifest

			if err := json.Unmarshal([]byte(manifestText), &manifest); err != nil {
				fmt.Printf("Error parsing manifest JSON: %v\n", err)
				done <- false
				return nil
			}

			// Try to fetch YAML ruleset first (preferred for Go WASM)
			if manifest.SitesAggregatedYAML != nil && manifest.SitesAggregatedYAML.URL != "" {
				fmt.Printf("Fetching YAML ruleset from: %s\n", manifest.SitesAggregatedYAML.URL)
				if fetchAndParseYAMLRuleset(manifest.SitesAggregatedYAML.URL) {
					done <- true
					return nil
				}
			}

			// Fallback to JSON ruleset if YAML fails
			if manifest.SitesAggregatedJSON != nil && manifest.SitesAggregatedJSON.URL != "" {
				fmt.Printf("Fetching JSON ruleset from: %s\n", manifest.SitesAggregatedJSON.URL)
				if fetchAndParseJSONRuleset(manifest.SitesAggregatedJSON.URL) {
					done <- true
					return nil
				}
			}

			fmt.Println("No valid ruleset URLs found in manifest")
			done <- false
			return nil
		}))

		return nil
	})).Call("catch", js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		fmt.Printf("Error fetching manifest: %v\n", args[0])
		done <- false
		return nil
	}))

	// Wait for the result with timeout
	select {
	case result := <-done:
		return result
	case <-time.After(10 * time.Second):
		fmt.Println("Timeout fetching remote ruleset")
		return false
	}
}

// fetchAndParseYAMLRuleset fetches and parses a YAML ruleset from URL
func fetchAndParseYAMLRuleset(yamlURL string) bool {
	fetchPromise := js.Global().Call("fetch", yamlURL)
	done := make(chan bool, 1)

	fetchPromise.Call("then", js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		if len(args) == 0 {
			done <- false
			return nil
		}

		response := args[0]
		if !response.Get("ok").Bool() {
			fmt.Printf("Failed to fetch YAML ruleset: %d\n", response.Get("status").Int())
			done <- false
			return nil
		}

		textPromise := response.Call("text")
		textPromise.Call("then", js.FuncOf(func(this js.Value, args []js.Value) interface{} {
			if len(args) == 0 {
				done <- false
				return nil
			}

			yamlText := args[0].String()
			err := yaml.Unmarshal([]byte(yamlText), &parsedRules)
			if err != nil {
				fmt.Printf("Error parsing remote YAML ruleset: %v\n", err)
				done <- false
				return nil
			}

			fmt.Printf("Successfully parsed %d rules from remote YAML\n", len(parsedRules))
			done <- true
			return nil
		}))

		return nil
	})).Call("catch", js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		fmt.Printf("Error fetching YAML ruleset: %v\n", args[0])
		done <- false
		return nil
	}))

	select {
	case result := <-done:
		return result
	case <-time.After(10 * time.Second):
		fmt.Println("Timeout fetching YAML ruleset")
		return false
	}
}

// fetchAndParseJSONRuleset fetches and parses a JSON ruleset from URL
func fetchAndParseJSONRuleset(jsonURL string) bool {
	fetchPromise := js.Global().Call("fetch", jsonURL)
	done := make(chan bool, 1)

	fetchPromise.Call("then", js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		if len(args) == 0 {
			done <- false
			return nil
		}

		response := args[0]
		if !response.Get("ok").Bool() {
			fmt.Printf("Failed to fetch JSON ruleset: %d\n", response.Get("status").Int())
			done <- false
			return nil
		}

		textPromise := response.Call("text")
		textPromise.Call("then", js.FuncOf(func(this js.Value, args []js.Value) interface{} {
			if len(args) == 0 {
				done <- false
				return nil
			}

			jsonText := args[0].String()
			// Parse JSON rules and convert to YAML-compatible structure
			var jsonRules []map[string]interface{}
			if err := json.Unmarshal([]byte(jsonText), &jsonRules); err != nil {
				fmt.Printf("Error parsing JSON ruleset: %v\n", err)
				done <- false
				return nil
			}

			// Convert JSON to YAML-compatible byte array and parse
			yamlBytes, err := json.Marshal(jsonRules)
			if err != nil {
				fmt.Printf("Error converting JSON to YAML: %v\n", err)
				done <- false
				return nil
			}

			err = yaml.Unmarshal(yamlBytes, &parsedRules)
			if err != nil {
				fmt.Printf("Error parsing converted JSON ruleset: %v\n", err)
				done <- false
				return nil
			}

			fmt.Printf("Successfully parsed %d rules from remote JSON\n", len(parsedRules))
			done <- true
			return nil
		}))

		return nil
	})).Call("catch", js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		fmt.Printf("Error fetching JSON ruleset: %v\n", args[0])
		done <- false
		return nil
	}))

	select {
	case result := <-done:
		return result
	case <-time.After(10 * time.Second):
		fmt.Println("Timeout fetching JSON ruleset")
		return false
	}
}


// findRuleForDomain finds the matching rule for a given domain and path
func findRuleForDomain(domain string) Rule {
	return findRuleForDomainAndPath(domain, "")
}

// findRuleForDomainAndPath finds the matching rule for a given domain and path
func findRuleForDomainAndPath(domain, path string) Rule {
	for _, rule := range parsedRules {
		// Check single domain (non-grouped)
		if rule.Domain != "" && !strings.HasPrefix(rule.Domain, "###") {
			if rule.Domain == domain || strings.HasSuffix(domain, "."+rule.Domain) {
				if matchesPath(rule, path) {
					return rule
				}
			}
			continue
		}

		// Check grouped domains (when domain starts with ###)
		if rule.Domain != "" && strings.HasPrefix(rule.Domain, "###") && len(rule.Group) > 0 {
			for _, groupDomain := range rule.Group {
				if groupDomain == domain || strings.HasSuffix(domain, "."+groupDomain) {
					if matchesPath(rule, path) {
						return rule
					}
				}
			}
			continue
		}

		// Check domains list (alternative to group)
		for _, ruleDomain := range rule.Domains {
			if ruleDomain == domain || strings.HasSuffix(domain, "."+ruleDomain) {
				if matchesPath(rule, path) {
					return rule
				}
			}
		}
	}
	return Rule{} // Return empty rule if no match
}

// matchesPath checks if the given path matches the rule's path restrictions
func matchesPath(rule Rule, path string) bool {
	if len(rule.Paths) == 0 {
		return true // No path restrictions
	}
	for _, rulePath := range rule.Paths {
		if strings.HasPrefix(path, rulePath) {
			return true
		}
	}
	return false
}

// applyURLModifications applies URL modifications from rules
func applyURLModifications(targetURL string, rule Rule) string {
	// Handle archive.is fallback (cs_dompurify)
	if rule.CsDompurify {
		return "https://archive.is/newest/" + targetURL
	}

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

// applyScriptBlocking blocks scripts matching the given regex pattern
func applyScriptBlocking(content, blockRegex string) string {
	// Parse HTML with GoQuery
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(content))
	if err != nil {
		// Fallback to regex-based script blocking if GoQuery parsing fails
		return applyScriptBlockingRegexFallback(content, blockRegex)
	}

	// Compile the blocking regex using cache
	re, err := getCachedRegex(blockRegex)
	if err != nil {
		fmt.Printf("Invalid block regex: %s\n", blockRegex)
		return content
	}

	// Find and remove/modify matching script tags
	doc.Find("script").Each(func(i int, s *goquery.Selection) {
		// Check script src attribute
		if src, exists := s.Attr("src"); exists {
			if re.MatchString(src) {
				s.Remove()
				return
			}
		}

		// Check inline script content
		scriptContent := s.Text()
		if scriptContent != "" && re.MatchString(scriptContent) {
			s.Remove()
			return
		}
	})

	// Get the modified HTML
	html, err := doc.Html()
	if err != nil {
		// Fallback to regex-based blocking if serialization fails
		return applyScriptBlockingRegexFallback(content, blockRegex)
	}

	return html
}

// applyScriptBlockingRegexFallback provides regex-based script blocking as fallback
func applyScriptBlockingRegexFallback(content, blockRegex string) string {
	// Compile the blocking regex
	re, err := regexp.Compile(blockRegex)
	if err != nil {
		return content
	}

	// Remove script tags with matching src attributes
	srcPattern := `<script[^>]+src\s*=\s*["']([^"']+)["'][^>]*>.*?</script>`
	srcRe := regexp.MustCompile(`(?s)` + srcPattern)
	content = srcRe.ReplaceAllStringFunc(content, func(match string) string {
		if re.MatchString(match) {
			return "<!-- Script blocked by regex -->"
		}
		return match
	})

	// Remove inline script tags with matching content
	inlinePattern := `<script[^>]*>(.*?)</script>`
	inlineRe := regexp.MustCompile(`(?s)` + inlinePattern)
	content = inlineRe.ReplaceAllStringFunc(content, func(match string) string {
		if re.MatchString(match) {
			return "<!-- Inline script blocked by regex -->"
		}
		return match
	})

	return content
}

// applyContentScripts applies Chrome extension-style content scripts (DOM manipulation)
func applyContentScripts(content string, contentScripts []ContentScript) string {
	// Parse HTML with GoQuery
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(content))
	if err != nil {
		// Fallback to string-based manipulation if GoQuery parsing fails
		return applyContentScriptsStringFallback(content, contentScripts)
	}

	for _, script := range contentScripts {
		switch script.Action {
		case "hide_elem":
			if script.Selector != "" {
				doc.Find(script.Selector).Each(func(i int, s *goquery.Selection) {
					s.SetAttr("style", s.AttrOr("style", "") + "; display: none !important;")
				})
			}
		case "rm_class":
			if script.Selector != "" && script.Class != "" {
				doc.Find(script.Selector).Each(func(i int, s *goquery.Selection) {
					s.RemoveClass(script.Class)
				})
			}
		case "rm_attrib":
			if script.Selector != "" && script.Attribute != "" {
				doc.Find(script.Selector).Each(func(i int, s *goquery.Selection) {
					s.RemoveAttr(script.Attribute)
				})
			}
		case "show_elem":
			if script.Selector != "" {
				doc.Find(script.Selector).Each(func(i int, s *goquery.Selection) {
					// Remove display: none from style attribute
					existingStyle := s.AttrOr("style", "")
					existingStyle = strings.ReplaceAll(existingStyle, "display: none", "")
					existingStyle = strings.ReplaceAll(existingStyle, "display:none", "")
					existingStyle = strings.TrimSpace(existingStyle)
					if existingStyle == "" {
						s.RemoveAttr("style")
					} else {
						s.SetAttr("style", existingStyle)
					}
				})
			}
		}
	}

	// Get the modified HTML
	html, err := doc.Html()
	if err != nil {
		// Fallback to string-based manipulation if serialization fails
		return applyContentScriptsStringFallback(content, contentScripts)
	}

	return html
}

// applyContentScriptsStringFallback provides string-based content script application as fallback
func applyContentScriptsStringFallback(content string, contentScripts []ContentScript) string {
	// This is a simplified fallback - in reality, proper DOM manipulation
	// would require a full HTML parser and CSS selector engine
	for _, script := range contentScripts {
		switch script.Action {
		case "hide_elem":
			// Inject CSS to hide elements
			hideCSS := fmt.Sprintf("<style>%s { display: none !important; }</style>", script.Selector)
			content = strings.Replace(content, "</head>", hideCSS+"\n</head>", 1)
		case "rm_class":
			// This is complex to do with regex - would need proper parsing
			// For now, just inject CSS to override common paywall classes
			if script.Class != "" {
				overrideCSS := fmt.Sprintf("<style>.%s { display: block !important; opacity: 1 !important; }</style>", script.Class)
				content = strings.Replace(content, "</head>", overrideCSS+"\n</head>", 1)
			}
		}
	}
	return content
}


// getCachedRegex returns a cached compiled regex or compiles and caches a new one
func getCachedRegex(pattern string) (*regexp.Regexp, error) {
	if cached, exists := regexCache[pattern]; exists {
		return cached, nil
	}

	compiled, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}

	regexCache[pattern] = compiled
	return compiled, nil
}
