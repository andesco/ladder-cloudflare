package main

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/url"
	"regexp"
	"strings"
	"syscall/js"
	"time"

	"github.com/PuerkitoBio/goquery"
)

//go:embed ruleset-embedded.json
var embeddedRuleset string

//go:embed ruleset-ladder-embedded.json
var embeddedLadderRuleset string

//go:embed ruleset-bpc-embedded.json
var embeddedBPCRuleset string

var (
	UserAgent                = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
	ForwardedFor             = "66.249.66.1"
	parsedRules              RuleSet // merged (default)
	parsedLadderRules        RuleSet // ladder-only (for /yaml/ routes)
	parsedBPCRules           RuleSet // BPC-only (for /json/ routes)
	globalBlockScriptsMerged []string
	globalBlockScriptsLadder []string
	globalBlockScriptsBPC    []string
	random                   = rand.New(rand.NewSource(time.Now().UnixNano()))
)

// Full-featured rule structures with YAML/JSON tags (matching ladder/pkg/ruleset)
type Regex struct {
	Match   string `yaml:"match" json:"match"`
	Replace any    `yaml:"replace" json:"replace"`
}

type KV struct {
	Key   string `yaml:"key" json:"key"`
	Value any    `yaml:"value" json:"value"`
}

type Injection struct {
	Position string `yaml:"position,omitempty" json:"position,omitempty"`
	Append   string `yaml:"append,omitempty" json:"append,omitempty"`
	Prepend  string `yaml:"prepend,omitempty" json:"prepend,omitempty"`
	Replace  string `yaml:"replace,omitempty" json:"replace,omitempty"`
}

type TestCase struct {
	URL  string `yaml:"url,omitempty" json:"url,omitempty"`
	Test string `yaml:"test,omitempty" json:"test,omitempty"`
}

type CsCodeOp struct {
	Cond      string `yaml:"cond,omitempty" json:"cond,omitempty"`
	HideElem  string `yaml:"hide_elem,omitempty" json:"hide_elem,omitempty"`
	RmElem    bool   `yaml:"rm_elem,omitempty" json:"rm_elem,omitempty"`
	RmClass   string `yaml:"rm_class,omitempty" json:"rm_class,omitempty"`
	RmAttrib  string `yaml:"rm_attrib,omitempty" json:"rm_attrib,omitempty"`
	SetAttrib string `yaml:"set_attrib,omitempty" json:"set_attrib,omitempty"` // "attr|value" format
	AddStyle  string `yaml:"add_style,omitempty" json:"add_style,omitempty"`
}

type RuleSet []Rule

type Rule struct {
	Domain  string   `yaml:"domain,omitempty" json:"domain,omitempty"`
	Domains []string `yaml:"domains,omitempty" json:"domains,omitempty"`
	Paths   []string `yaml:"paths,omitempty" json:"paths,omitempty"`
	Headers struct {
		UserAgent     string `yaml:"user-agent,omitempty" json:"user-agent,omitempty"`
		XForwardedFor string `yaml:"x-forwarded-for,omitempty" json:"x-forwarded-for,omitempty"`
		Referer       string `yaml:"referer,omitempty" json:"referer,omitempty"`
		Cookie        string `yaml:"cookie,omitempty" json:"cookie,omitempty"`
		CSP           string `yaml:"content-security-policy,omitempty" json:"content-security-policy,omitempty"`
	} `yaml:"headers,omitempty" json:"headers,omitempty"`
	GoogleCache bool    `yaml:"googleCache,omitempty" json:"googleCache,omitempty"`
	RegexRules  []Regex `yaml:"regexRules,omitempty" json:"regexRules,omitempty"`

	URLMods struct {
		Domain []Regex `yaml:"domain,omitempty" json:"domain,omitempty"`
		Path   []Regex `yaml:"path,omitempty" json:"path,omitempty"`
		Query  []KV    `yaml:"query,omitempty" json:"query,omitempty"`
	} `yaml:"urlMods,omitempty" json:"urlMods,omitempty"`

	Injections []Injection `yaml:"injections,omitempty" json:"injections,omitempty"`

	Tests []TestCase `yaml:"tests,omitempty" json:"tests,omitempty"`

	// BPC integration fields
	RandomIP            string            `yaml:"randomIP,omitempty" json:"randomIP,omitempty"`
	BlockScripts        []string          `yaml:"blockScripts,omitempty" json:"blockScripts,omitempty"`
	BlockScriptsGeneral []string          `yaml:"blockScriptsGeneral,omitempty" json:"blockScriptsGeneral,omitempty"`
	ExcludedDomains     []string          `yaml:"excludedDomains,omitempty" json:"excludedDomains,omitempty"`
	CsCode              []CsCodeOp        `yaml:"csCode,omitempty" json:"csCode,omitempty"`
	AmpUnhide           bool              `yaml:"ampUnhide,omitempty" json:"ampUnhide,omitempty"`
	BlockJsInline       string            `yaml:"blockJsInline,omitempty" json:"blockJsInline,omitempty"`
	ClearStorage        bool              `yaml:"clearStorage,omitempty" json:"clearStorage,omitempty"`
	PathExclusions      []string          `yaml:"pathExclusions,omitempty" json:"pathExclusions,omitempty"`
	ExtraHeaders        map[string]string `yaml:"extraHeaders,omitempty" json:"extraHeaders,omitempty"`
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
	var setBPCRulesetFunc = js.FuncOf(setBPCRuleset)

	// Register JavaScript functions for Cloudflare Worker
	js.Global().Set("handleRequest", handleRequestFunc)
	js.Global().Set("getRuleset", getRulesetFunc)
	js.Global().Set("getRulesetDomains", getRulesetDomainsFunc)
	js.Global().Set("fetchURL", fetchURLFunc)
	js.Global().Set("processContent", processContentFunc)
	js.Global().Set("setBPCRuleset", setBPCRulesetFunc)

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
	requestHeaders := jsHeadersToMap(args[2]) // Request headers from JavaScript

	// Detect ruleset mode from path prefix
	rulesetMode := "merged" // default
	cleanPath := path

	if strings.HasPrefix(path, "/yaml/") {
		rulesetMode = "yaml"
		cleanPath = "/" + strings.TrimPrefix(path, "/yaml/")
	} else if strings.HasPrefix(path, "/json/") {
		rulesetMode = "json"
		cleanPath = "/" + strings.TrimPrefix(path, "/json/")
	}

	// Handle special endpoints
	switch {
	case strings.HasPrefix(cleanPath, "/api/"):
		targetPath := strings.TrimPrefix(cleanPath, "/api/")
		targetURL, err := extractURL(targetPath, requestHeaders)
		if err != nil {
			return createErrorResponse(400, fmt.Sprintf("Invalid URL: %s", err.Error()))
		}

		if method != "GET" {
			return createErrorResponse(405, "Method Not Allowed")
		}

		result := js.Global().Get("Object").New()
		result.Set("status", 200)
		result.Set("proxyURL", targetURL)
		result.Set("needsFetch", true)
		result.Set("responseType", "api")
		result.Set("rulesetMode", rulesetMode)

		headers := js.Global().Get("Object").New()
		headers.Set("Content-Type", "application/json")
		result.Set("headers", headers)

		return result
	case strings.HasPrefix(cleanPath, "/raw/"):
		targetPath := strings.TrimPrefix(cleanPath, "/raw/")
		targetURL, err := extractURL(targetPath, requestHeaders)
		if err != nil {
			return createErrorResponse(400, fmt.Sprintf("Invalid URL: %s", err.Error()))
		}

		if method != "GET" {
			return createErrorResponse(405, "Method Not Allowed")
		}

		result := js.Global().Get("Object").New()
		result.Set("status", 200)
		result.Set("proxyURL", targetURL)
		result.Set("needsFetch", true)
		result.Set("responseType", "raw")
		result.Set("rulesetMode", rulesetMode)

		headers := js.Global().Get("Object").New()
		headers.Set("Content-Type", "text/plain")
		result.Set("headers", headers)

		return result
	case cleanPath == "/test":
		if testURL := getRandomTestURL(); testURL != "" {
			return createRedirectResponse("/" + testURL)
		}
		return createErrorResponse(404, "No test URLs available")
	case cleanPath == "/ruleset":
		return createRulesetResponse()
	}

	// Extract target URL from path
	targetURL, err := extractURL(cleanPath, requestHeaders)
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
	result.Set("rulesetMode", rulesetMode)

	headers := js.Global().Get("Object").New()
	headers.Set("Content-Type", "text/html")
	result.Set("headers", headers)

	return result
}

// extractURL extracts the target URL from the request path
func extractURL(path string, headers map[string]string) (string, error) {
	// Remove leading slash
	urlPath := strings.TrimPrefix(path, "/")

	// URL decode the path if possible
	if decoded, err := url.QueryUnescape(urlPath); err == nil {
		urlPath = decoded
	}

	// Try to parse as URL
	parsedURL, err := url.Parse(urlPath)
	if err != nil {
		return "", fmt.Errorf("error parsing URL '%s': %v", urlPath, err)
	}

	// Resolve relative paths using referer
	if parsedURL.Scheme == "" {
		referer := headers["referer"]
		if referer == "" {
			return "", fmt.Errorf("relative path requires referer header")
		}

		refererURL, err := url.Parse(referer)
		if err != nil {
			return "", fmt.Errorf("error parsing referer URL: %v", err)
		}

		realURL, err := url.Parse(strings.TrimPrefix(refererURL.Path, "/"))
		if err != nil {
			return "", fmt.Errorf("error parsing real URL from referer: %v", err)
		}

		relativePath := parsedURL.Path
		if relativePath != "" && !strings.HasPrefix(relativePath, "/") {
			relativePath = "/" + relativePath
		}

		fullURL := &url.URL{
			Scheme:   realURL.Scheme,
			Host:     realURL.Host,
			Path:     relativePath,
			RawQuery: parsedURL.RawQuery,
		}

		return fullURL.String(), nil
	}

	return parsedURL.String(), nil
}

// jsHeadersToMap converts a JS headers object into a Go map
func jsHeadersToMap(headersVal js.Value) map[string]string {
	headers := map[string]string{}
	if headersVal.IsUndefined() || headersVal.IsNull() {
		return headers
	}

	keys := js.Global().Get("Object").Call("keys", headersVal)
	for i := 0; i < keys.Length(); i++ {
		key := keys.Index(i).String()
		value := headersVal.Get(key)
		if value.IsUndefined() || value.IsNull() {
			continue
		}
		headers[key] = value.String()
	}

	return headers
}

// fetchURL handles the actual HTTP fetching (called from JavaScript)
func fetchURL(this js.Value, args []js.Value) interface{} {
	if len(args) < 1 {
		return createErrorResponse(400, "URL required")
	}

	targetURL := args[0].String()

	// Optional second argument: ruleset mode
	rulesetMode := "merged"
	if len(args) >= 2 && !args[1].IsUndefined() {
		rulesetMode = args[1].String()
	}

	// Parse the URL to get domain for rule matching
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return createErrorResponse(400, fmt.Sprintf("Invalid URL: %s", err.Error()))
	}

	// Find matching rule for this domain using the specified ruleset
	rule := findRuleForDomainAndPathWithMode(parsedURL.Host, parsedURL.Path, rulesetMode)

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
		result.Set("referer", targetURL)
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

	// #5: Random IP generation
	if rule.RandomIP != "" {
		var ip string
		if rule.RandomIP == "eu" {
			ip = fmt.Sprintf("185.%d.%d.%d", random.Intn(256), random.Intn(256), random.Intn(256))
		} else {
			ip = fmt.Sprintf("%d.%d.%d.%d", random.Intn(224)+1, random.Intn(256), random.Intn(256), random.Intn(256))
		}
		result.Set("xForwardedFor", ip)
	}

	// #6: Extra headers
	if len(rule.ExtraHeaders) > 0 {
		extraHeaders := js.Global().Get("Object").New()
		for key, val := range rule.ExtraHeaders {
			extraHeaders.Set(key, val)
		}
		result.Set("extraHeaders", extraHeaders)
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
	headers.Set("Content-Type", "application/json; charset=utf-8")
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

// getRandomTestURL returns a random test URL from the parsed ruleset
func getRandomTestURL() string {
	testURLs := getTestURLs()
	if len(testURLs) == 0 {
		return ""
	}
	return testURLs[random.Intn(len(testURLs))]
}

// getTestURLs extracts all test URLs from the ruleset
func getTestURLs() []string {
	testURLs := make([]string, 0)
	for _, rule := range parsedRules {
		for _, test := range rule.Tests {
			if test.URL != "" {
				testURLs = append(testURLs, test.URL)
			}
		}
	}
	return testURLs
}

// processContent applies content modifications (injections + regex rules) using GoQuery
// Refactored to single GoQuery parse for all DOM operations
func processContent(this js.Value, args []js.Value) interface{} {
	if len(args) < 2 {
		return createErrorResponse(400, "Content and URL required")
	}

	content := args[0].String()
	targetURL := args[1].String()

	// Optional third argument: ruleset mode
	rulesetMode := "merged"
	if len(args) >= 3 && !args[2].IsUndefined() {
		rulesetMode = args[2].String()
	}

	// Parse URL to get domain and path
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return createErrorResponse(400, fmt.Sprintf("Invalid URL: %s", err.Error()))
	}

	// Find matching rule with path support using the specified ruleset
	rule := findRuleForDomainAndPathWithMode(parsedURL.Host, parsedURL.Path, rulesetMode)

	// Step 1: Apply regex rules (string ops, before parse)
	for _, regexRule := range rule.RegexRules {
		re, err := regexp.Compile(regexRule.Match)
		if err != nil {
			fmt.Printf("Invalid regex: %s\n", regexRule.Match)
			continue
		}
		content = re.ReplaceAllString(content, fmt.Sprint(regexRule.Replace))
	}

	// Step 2: Parse HTML into GoQuery doc once
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(content))
	if err != nil {
		// Fallback to string-based processing if parsing fails
		content = rewriteHTMLFallback(content, parsedURL.Host)
		content = applyContentInjectionsStringFallback(content, rule.Injections)

		result := js.Global().Get("Object").New()
		result.Set("content", content)
		if rule.Headers.CSP != "" {
			result.Set("csp", rule.Headers.CSP)
		}
		return result
	}

	// Step 3: Block scripts (#7) including shared/general patterns
	blockPatterns := make([]string, 0, len(rule.BlockScripts)+len(rule.BlockScriptsGeneral))
	blockPatterns = append(blockPatterns, rule.BlockScripts...)
	blockPatterns = append(blockPatterns, rule.BlockScriptsGeneral...)
	blockPatterns = append(blockPatterns, globalBlockPatternsForMode(rulesetMode)...)
	if len(blockPatterns) > 0 {
		applyBlockScripts(doc, blockPatterns)
	}

	// Step 4: Block inline JS (#12)
	if rule.BlockJsInline != "" {
		applyBlockJsInline(doc, rule.BlockJsInline, targetURL)
	}

	// Step 5: Apply csCode operations (#9)
	if len(rule.CsCode) > 0 {
		applyCsCode(doc, rule.CsCode)
	}

	// Step 6: AMP unhide (#10)
	if rule.AmpUnhide {
		applyAmpUnhide(doc)
	}

	// Step 7: Rewrite HTML (existing, refactored to take doc)
	rewriteHTMLDoc(doc, parsedURL.Host)

	// Step 8: Apply content injections (existing, refactored to take doc)
	applyInjectionsDoc(doc, rule.Injections)

	// Step 9: Clear storage (#13)
	if rule.ClearStorage {
		doc.Find("head").PrependHtml(`<script>localStorage.clear();sessionStorage.clear()</script>`)
	}

	// Step 10: Serialize once
	html, err := doc.Html()
	if err != nil {
		// Fallback
		html = content
	}

	// CSS url() rewrites (GoQuery doesn't parse CSS)
	proxyPrefix := "/https://" + parsedURL.Host + "/"
	html = strings.ReplaceAll(html, `url('/`, `url('`+proxyPrefix)
	html = strings.ReplaceAll(html, `url(/`, `url(`+proxyPrefix)

	// Create result with processed content
	result := js.Global().Get("Object").New()
	result.Set("content", html)

	if rule.Headers.CSP != "" {
		result.Set("csp", rule.Headers.CSP)
	}

	return result
}

// applyContentInjections applies content injections using GoQuery for DOM manipulation
func applyContentInjections(content string, injections []Injection) string {
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
func applyContentInjectionsStringFallback(content string, injections []Injection) string {
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

// rewriteHTMLDoc rewrites HTML content to proxy relative URLs on an existing GoQuery doc
func rewriteHTMLDoc(doc *goquery.Document, originalHost string) {
	proxyPrefix := "/https://" + originalHost + "/"

	doc.Find("img[src]").Each(func(i int, s *goquery.Selection) {
		src, exists := s.Attr("src")
		if exists && strings.HasPrefix(src, "/") && !strings.HasPrefix(src, "//") {
			s.SetAttr("src", proxyPrefix+strings.TrimPrefix(src, "/"))
		}
	})

	doc.Find("script[src]").Each(func(i int, s *goquery.Selection) {
		src, exists := s.Attr("src")
		if exists && strings.HasPrefix(src, "/") && !strings.HasPrefix(src, "//") {
			s.SetAttr("src", proxyPrefix+strings.TrimPrefix(src, "/"))
		}
	})

	doc.Find("a[href]").Each(func(i int, s *goquery.Selection) {
		href, exists := s.Attr("href")
		if exists {
			if strings.HasPrefix(href, "/") && !strings.HasPrefix(href, "//") {
				s.SetAttr("href", proxyPrefix+strings.TrimPrefix(href, "/"))
			} else if strings.HasPrefix(href, "https://"+originalHost) {
				s.SetAttr("href", "/https://"+originalHost+"/"+strings.TrimPrefix(href, "https://"+originalHost+"/"))
			}
		}
	})

	doc.Find("link[href]").Each(func(i int, s *goquery.Selection) {
		href, exists := s.Attr("href")
		if exists && strings.HasPrefix(href, "/") && !strings.HasPrefix(href, "//") {
			s.SetAttr("href", proxyPrefix+strings.TrimPrefix(href, "/"))
		}
	})

	doc.Find("form[action]").Each(func(i int, s *goquery.Selection) {
		action, exists := s.Attr("action")
		if exists && strings.HasPrefix(action, "/") && !strings.HasPrefix(action, "//") {
			s.SetAttr("action", proxyPrefix+strings.TrimPrefix(action, "/"))
		}
	})
}

// applyInjectionsDoc applies content injections on an existing GoQuery doc
func applyInjectionsDoc(doc *goquery.Document, injections []Injection) {
	if len(injections) == 0 {
		return
	}

	for _, injection := range injections {
		targetSelector := "head"
		injectionContent := ""

		if injection.Append != "" {
			injectionContent = injection.Append
		} else if injection.Prepend != "" {
			injectionContent = injection.Prepend
		} else if injection.Replace != "" {
			injectionContent = injection.Replace
		}

		switch injection.Position {
		case "head":
			targetSelector = "head"
		case "body":
			targetSelector = "body"
		case "html":
			targetSelector = "html"
		default:
			if strings.Contains(injection.Position, ".") || strings.Contains(injection.Position, "#") || strings.Contains(injection.Position, "[") {
				targetSelector = injection.Position
			} else {
				targetSelector = "head"
			}
		}

		target := doc.Find(targetSelector)
		if target.Length() > 0 {
			if injection.Replace != "" {
				target.SetHtml(injectionContent)
			} else if injection.Prepend != "" {
				target.PrependHtml(injectionContent)
			} else {
				target.AppendHtml(injectionContent)
			}
		} else {
			headTarget := doc.Find("head")
			if headTarget.Length() > 0 {
				headTarget.AppendHtml(injectionContent)
			}
		}
	}
}

// applyBlockScripts removes script/link elements matching patterns (#7)
func applyBlockScripts(doc *goquery.Document, patterns []string) {
	compiled := make([]*regexp.Regexp, 0, len(patterns))
	for _, pattern := range patterns {
		re, err := regexp.Compile(pattern)
		if err != nil {
			fmt.Printf("Invalid blockScripts regex: %s\n", pattern)
			continue
		}
		compiled = append(compiled, re)
	}

	doc.Find("script[src]").Each(func(i int, s *goquery.Selection) {
		src, exists := s.Attr("src")
		if !exists {
			return
		}
		for _, re := range compiled {
			if re.MatchString(src) {
				s.Remove()
				return
			}
		}
	})

	doc.Find("link[href]").Each(func(i int, s *goquery.Selection) {
		href, exists := s.Attr("href")
		if !exists {
			return
		}
		for _, re := range compiled {
			if re.MatchString(href) {
				s.Remove()
				return
			}
		}
	})
}

// applyBlockJsInline removes all inline scripts if the page URL matches the pattern (#12)
func applyBlockJsInline(doc *goquery.Document, pattern, pageURL string) {
	re, err := regexp.Compile(pattern)
	if err != nil {
		fmt.Printf("Invalid blockJsInline regex: %s\n", pattern)
		return
	}

	if !re.MatchString(pageURL) {
		return
	}

	doc.Find("script:not([src])").Each(func(i int, s *goquery.Selection) {
		s.Remove()
	})
}

// applyCsCode applies content script DOM operations (#9)
func applyCsCode(doc *goquery.Document, ops []CsCodeOp) {
	for _, op := range ops {
		// hide_elem: hide elements matching selector
		if op.HideElem != "" {
			doc.Find(op.HideElem).Each(func(i int, s *goquery.Selection) {
				existing, _ := s.Attr("style")
				if existing != "" {
					s.SetAttr("style", existing+";display:none!important")
				} else {
					s.SetAttr("style", "display:none!important")
				}
			})
		}

		// Operations that require a condition selector
		if op.Cond != "" {
			if op.RmElem {
				doc.Find(op.Cond).Remove()
			}

			if op.RmClass != "" {
				classes := strings.Fields(op.RmClass)
				doc.Find(op.Cond).Each(func(i int, s *goquery.Selection) {
					for _, cls := range classes {
						s.RemoveClass(cls)
					}
				})
			}

			if op.RmAttrib != "" {
				doc.Find(op.Cond).Each(func(i int, s *goquery.Selection) {
					s.RemoveAttr(op.RmAttrib)
				})
			}

			if op.SetAttrib != "" {
				parts := strings.SplitN(op.SetAttrib, "|", 2)
				if len(parts) == 2 {
					doc.Find(op.Cond).Each(func(i int, s *goquery.Selection) {
						s.SetAttr(parts[0], parts[1])
					})
				}
			}
		}

		// add_style: inject CSS into head
		if op.AddStyle != "" {
			doc.Find("head").AppendHtml("<style>" + op.AddStyle + "</style>")
		}
	}
}

// applyAmpUnhide removes AMP access-hiding attributes (#10)
func applyAmpUnhide(doc *goquery.Document) {
	doc.Find(`[subscriptions-section="content-not-granted"]`).Remove()
	doc.Find("[subscriptions-section]").Each(func(i int, s *goquery.Selection) {
		s.RemoveAttr("subscriptions-section")
	})
	doc.Find("[amp-access-hide]").Each(func(i int, s *goquery.Selection) {
		s.RemoveAttr("amp-access-hide")
	})
}

// parseRuleset parses the embedded rulesets (embedded JSON for runtime efficiency)
func parseRuleset() {
	// Parse merged ruleset (JSON)
	err := json.Unmarshal([]byte(embeddedRuleset), &parsedRules)
	if err != nil {
		fmt.Printf("Error parsing merged JSON ruleset: %v\n", err)
		return
	}
	fmt.Printf("Successfully parsed %d merged rules from embedded JSON\n", len(parsedRules))

	// Parse ladder-only ruleset
	err = json.Unmarshal([]byte(embeddedLadderRuleset), &parsedLadderRules)
	if err != nil {
		fmt.Printf("Error parsing ladder JSON ruleset: %v\n", err)
		return
	}
	fmt.Printf("Successfully parsed %d ladder rules from embedded JSON\n", len(parsedLadderRules))
	globalBlockScriptsLadder = collectGlobalBlockScripts(parsedLadderRules)

	// Parse BPC-only ruleset (JSON)
	err = json.Unmarshal([]byte(embeddedBPCRuleset), &parsedBPCRules)
	if err != nil {
		fmt.Printf("Error parsing BPC JSON ruleset: %v\n", err)
		return
	}
	fmt.Printf("Successfully parsed %d BPC rules from embedded JSON\n", len(parsedBPCRules))
	globalBlockScriptsBPC = collectGlobalBlockScripts(parsedBPCRules)

	// Merged mode layers Ladder on top of BPC at runtime, so merged global patterns
	// should reflect both sources (and remain correct if BPC rules update at runtime).
	globalBlockScriptsMerged = unionStrings(globalBlockScriptsBPC, globalBlockScriptsLadder)
}

func unionStrings(a, b []string) []string {
	seen := make(map[string]struct{})
	out := make([]string, 0, len(a)+len(b))
	for _, v := range a {
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	for _, v := range b {
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

// setBPCRuleset replaces the in-memory BPC ruleset at runtime.
// args[0] must be a JSON string in Ladderflare embedded ruleset format (array of Rule objects).
func setBPCRuleset(this js.Value, args []js.Value) any {
	if len(args) < 1 {
		return "missing ruleset JSON argument"
	}
	rulesJSON := args[0].String()
	if rulesJSON == "" {
		return "empty ruleset JSON"
	}

	var next RuleSet
	if err := json.Unmarshal([]byte(rulesJSON), &next); err != nil {
		return fmt.Sprintf("failed to parse BPC ruleset JSON: %v", err)
	}

	parsedBPCRules = next
	globalBlockScriptsBPC = collectGlobalBlockScripts(parsedBPCRules)
	globalBlockScriptsMerged = unionStrings(globalBlockScriptsBPC, globalBlockScriptsLadder)

	return true
}

// collectGlobalBlockScripts gathers unique blockScriptsGeneral patterns from a ruleset
func collectGlobalBlockScripts(rules RuleSet) []string {
	seen := make(map[string]struct{})
	patterns := make([]string, 0)

	for _, rule := range rules {
		for _, pattern := range rule.BlockScriptsGeneral {
			if pattern == "" {
				continue
			}
			if _, exists := seen[pattern]; exists {
				continue
			}
			seen[pattern] = struct{}{}
			patterns = append(patterns, pattern)
		}
	}

	return patterns
}

// globalBlockPatternsForMode returns blockScriptsGeneral entries for the active ruleset
func globalBlockPatternsForMode(mode string) []string {
	switch mode {
	case "yaml":
		return globalBlockScriptsLadder
	case "json":
		return globalBlockScriptsBPC
	default:
		return globalBlockScriptsMerged
	}
}

// mergeRuleOverlay combines two rules into an "effective" rule. This is used for
// merged mode so Ladder rules can layer on top of BPC rules even when the BPC
// match is for a parent domain (e.g. nytimes.com) and Ladder is a subdomain
// (e.g. www.nytimes.com).
//
// Precedence:
// - BPC is the base (headers, blockScripts, csCode, etc)
// - Ladder adds/overlays client-side behavior (regexRules, injections, tests, urlMods)
// - For single-value fields (headers, blockJsInline, randomIP), BPC wins and Ladder fills blanks
func mergeRuleOverlay(bpc Rule, ladder Rule) Rule {
	merged := bpc

	// Keep domain fields for debugging when BPC doesn't match.
	if merged.Domain == "" && len(merged.Domains) == 0 {
		merged.Domain = ladder.Domain
		merged.Domains = ladder.Domains
	}

	// Headers: BPC wins, Ladder fills gaps.
	if merged.Headers.UserAgent == "" {
		merged.Headers.UserAgent = ladder.Headers.UserAgent
	}
	if merged.Headers.XForwardedFor == "" {
		merged.Headers.XForwardedFor = ladder.Headers.XForwardedFor
	}
	if merged.Headers.Referer == "" {
		merged.Headers.Referer = ladder.Headers.Referer
	}
	if merged.Headers.Cookie == "" {
		merged.Headers.Cookie = ladder.Headers.Cookie
	}
	if merged.Headers.CSP == "" {
		merged.Headers.CSP = ladder.Headers.CSP
	}

	// URL modifications: apply BPC first, then Ladder.
	merged.URLMods.Domain = append(merged.URLMods.Domain, ladder.URLMods.Domain...)
	merged.URLMods.Path = append(merged.URLMods.Path, ladder.URLMods.Path...)
	merged.URLMods.Query = append(merged.URLMods.Query, ladder.URLMods.Query...)

	// Other single-value fields.
	merged.GoogleCache = merged.GoogleCache || ladder.GoogleCache
	if merged.RandomIP == "" {
		merged.RandomIP = ladder.RandomIP
	}
	if merged.BlockJsInline == "" {
		merged.BlockJsInline = ladder.BlockJsInline
	}
	merged.AmpUnhide = merged.AmpUnhide || ladder.AmpUnhide
	merged.ClearStorage = merged.ClearStorage || ladder.ClearStorage

	// List fields: combine.
	merged.RegexRules = append(merged.RegexRules, ladder.RegexRules...)
	merged.Injections = append(merged.Injections, ladder.Injections...)
	merged.Tests = append(merged.Tests, ladder.Tests...)

	merged.BlockScripts = append(merged.BlockScripts, ladder.BlockScripts...)
	merged.BlockScriptsGeneral = append(merged.BlockScriptsGeneral, ladder.BlockScriptsGeneral...)
	merged.CsCode = append(merged.CsCode, ladder.CsCode...)

	merged.ExcludedDomains = append(merged.ExcludedDomains, ladder.ExcludedDomains...)
	merged.PathExclusions = append(merged.PathExclusions, ladder.PathExclusions...)

	// Extra headers: BPC wins, Ladder fills gaps.
	if len(ladder.ExtraHeaders) > 0 {
		if merged.ExtraHeaders == nil {
			merged.ExtraHeaders = map[string]string{}
		}
		for k, v := range ladder.ExtraHeaders {
			if _, exists := merged.ExtraHeaders[k]; !exists {
				merged.ExtraHeaders[k] = v
			}
		}
	}

	return merged
}

// selectRuleset returns the appropriate ruleset based on mode
func selectRuleset(mode string) RuleSet {
	switch mode {
	case "yaml":
		return parsedLadderRules
	case "json":
		return parsedBPCRules
	default:
		return parsedRules
	}
}

// findRuleForDomain finds the matching rule for a given domain and path
func findRuleForDomain(domain string) Rule {
	return findRuleForDomainAndPath(domain, "")
}

// findRuleForDomainAndPath finds the matching rule for a given domain and path
func findRuleForDomainAndPath(domain, path string) Rule {
	return findRuleForDomainAndPathInRuleset(domain, path, parsedRules)
}

// findRuleForDomainAndPathWithMode finds the matching rule using the specified ruleset mode
func findRuleForDomainAndPathWithMode(domain, path, mode string) Rule {
	switch mode {
	case "yaml":
		return findRuleForDomainAndPathInRuleset(domain, path, parsedLadderRules)
	case "json":
		return findRuleForDomainAndPathInRuleset(domain, path, parsedBPCRules)
	default:
		// Layer Ladder on top of BPC for merged mode.
		bpcRule := findRuleForDomainAndPathInRuleset(domain, path, parsedBPCRules)
		ladderRule := findRuleForDomainAndPathInRuleset(domain, path, parsedLadderRules)
		return mergeRuleOverlay(bpcRule, ladderRule)
	}
}

// findRuleForDomainAndPathInRuleset finds the matching rule in a specific ruleset
func findRuleForDomainAndPathInRuleset(domain, path string, rules RuleSet) Rule {
	for _, rule := range rules {
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
			// #19: Check path exclusions
			if len(rule.PathExclusions) > 0 {
				excluded := false
				for _, pattern := range rule.PathExclusions {
					re, err := regexp.Compile(pattern)
					if err != nil {
						continue
					}
					if re.MatchString(path) {
						excluded = true
						break
					}
				}
				if excluded {
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
				// #19: Check path exclusions
				if len(rule.PathExclusions) > 0 {
					excluded := false
					for _, pattern := range rule.PathExclusions {
						re, err := regexp.Compile(pattern)
						if err != nil {
							continue
						}
						if re.MatchString(path) {
							excluded = true
							break
						}
					}
					if excluded {
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
		parsedURL.Host = re.ReplaceAllString(parsedURL.Host, fmt.Sprint(domainMod.Replace))
	}

	// Apply path modifications
	for _, pathMod := range rule.URLMods.Path {
		re, err := regexp.Compile(pathMod.Match)
		if err != nil {
			continue
		}
		parsedURL.Path = re.ReplaceAllString(parsedURL.Path, fmt.Sprint(pathMod.Replace))
	}

	// Apply query modifications
	values := parsedURL.Query()
	for _, queryMod := range rule.URLMods.Query {
		switch v := queryMod.Value.(type) {
		case nil:
			values.Del(queryMod.Key)
		case string:
			if v == "" {
				values.Del(queryMod.Key)
			} else {
				values.Set(queryMod.Key, v)
			}
		default:
			// YAML parsing may preserve numbers/bools; JSON embed uses native JSON types.
			values.Set(queryMod.Key, fmt.Sprint(v))
		}
	}
	parsedURL.RawQuery = values.Encode()

	// Apply Google Cache if enabled
	if rule.GoogleCache {
		return "https://webcache.googleusercontent.com/search?q=cache:" + parsedURL.String()
	}

	return parsedURL.String()
}
