package handlers

import (
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
	"ladderflare/pkg/ruleset"
)

// HandleProxy handles the main proxy functionality with full rule application
func HandleProxy(method, targetURL string, headers map[string]string) map[string]interface{} {
	if method != "GET" {
		return createResponse(405, "Method Not Allowed", map[string]string{
			"Content-Type": "text/plain",
		})
	}

	// Extract and validate URL
	url, err := extractUrl(targetURL, headers)
	if err != nil {
		return createResponse(400, fmt.Sprintf("Invalid URL: %s", err.Error()), map[string]string{
			"Content-Type": "text/plain",
		})
	}

	// Validate domain restrictions
	if err := validateDomain(url); err != nil {
		return createResponse(403, fmt.Sprintf("Domain not allowed: %s", err.Error()), map[string]string{
			"Content-Type": "text/plain",
		})
	}

	// Proxy the request with full rule processing
	response := proxyRequest(url, headers)

	return response
}

// proxyRequest performs the actual proxy request with rule application
func proxyRequest(targetURL string, requestHeaders map[string]string) map[string]interface{} {
	// Parse the target URL
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return createResponse(400, fmt.Sprintf("Invalid URL: %s", err.Error()), map[string]string{
			"Content-Type": "text/plain",
		})
	}

	// Find applicable rule for this domain
	var rule *ruleset.Rule
	if rulesSet != nil {
		rule = rulesSet.FindRuleForURL(targetURL)
	}

	// Apply URL modifications if rule exists
	if rule != nil {
		targetURL = applyURLModifications(targetURL, rule)
	}

	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: time.Duration(defaultTimeout) * time.Second,
	}

	// Create request
	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return createResponse(500, fmt.Sprintf("Failed to create request: %s", err.Error()), map[string]string{
			"Content-Type": "text/plain",
		})
	}

	// Apply headers from rule and defaults
	applyRequestHeaders(req, rule, requestHeaders)

	// Capture request headers for API responses
	requestHeadersOut := make(map[string]string)
	for key, values := range req.Header {
		if len(values) > 0 {
			requestHeadersOut[key] = values[0]
		}
	}

	// Log URL if enabled
	if getenv("LOG_URLS", "true") == "true" {
		fmt.Printf("Proxying: %s\n", targetURL)
	}

	// Make the request
	resp, err := client.Do(req)
	if err != nil {
		return createResponse(500, fmt.Sprintf("Request failed: %s", err.Error()), map[string]string{
			"Content-Type": "text/plain",
		})
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return createResponse(500, fmt.Sprintf("Failed to read response: %s", err.Error()), map[string]string{
			"Content-Type": "text/plain",
		})
	}

	// Apply response modifications if rule exists and content is HTML
	contentType := resp.Header.Get("Content-Type")
	if rule != nil && strings.Contains(contentType, "text/html") {
		body = applyResponseModifications(body, rule, parsedURL)
	}

	// Prepare response headers
	responseHeaders := make(map[string]string)
	originHeaders := make(map[string]string)

	// Copy important headers from original response
	for key, values := range resp.Header {
		if len(values) > 0 {
			originHeaders[key] = values[0]
			// Remove CORS and security headers that might interfere
			lowerKey := strings.ToLower(key)
			if !strings.Contains(lowerKey, "cors") &&
				!strings.Contains(lowerKey, "x-frame") &&
				!strings.Contains(lowerKey, "content-security-policy") {
				responseHeaders[key] = values[0]
			}
		}
	}

	// Set content type
	if contentType != "" {
		responseHeaders["Content-Type"] = contentType
	}

	// Apply CSP header if specified in rule
	if rule != nil && rule.Headers.CSP != "" {
		responseHeaders["Content-Security-Policy"] = rule.Headers.CSP
		originHeaders["Content-Security-Policy"] = rule.Headers.CSP
	}

	// Add CORS headers to allow access
	responseHeaders["Access-Control-Allow-Origin"] = "*"
	responseHeaders["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
	responseHeaders["Access-Control-Allow-Headers"] = "*"

	response := createResponse(resp.StatusCode, string(body), responseHeaders)
	response["requestHeaders"] = requestHeadersOut
	response["originHeaders"] = originHeaders
	return response
}

// proxyRequestRaw performs a raw proxy request without rule application
func proxyRequestRaw(targetURL string, requestHeaders map[string]string) map[string]interface{} {
	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: time.Duration(defaultTimeout) * time.Second,
	}

	// Create request
	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return createResponse(500, fmt.Sprintf("Failed to create request: %s", err.Error()), map[string]string{
			"Content-Type": "text/plain",
		})
	}

	// Apply basic headers
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("X-Forwarded-For", ForwardedFor)

	// Copy referer if present
	if referer := requestHeaders["referer"]; referer != "" {
		req.Header.Set("Referer", referer)
	}

	// Make the request
	resp, err := client.Do(req)
	if err != nil {
		return createResponse(500, fmt.Sprintf("Request failed: %s", err.Error()), map[string]string{
			"Content-Type": "text/plain",
		})
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return createResponse(500, fmt.Sprintf("Failed to read response: %s", err.Error()), map[string]string{
			"Content-Type": "text/plain",
		})
	}

	// Prepare response headers
	responseHeaders := make(map[string]string)
	for key, values := range resp.Header {
		if len(values) > 0 {
			responseHeaders[key] = values[0]
		}
	}

	return createResponse(resp.StatusCode, string(body), responseHeaders)
}

// applyRequestHeaders applies headers from rule and defaults to the request
func applyRequestHeaders(req *http.Request, rule *ruleset.Rule, requestHeaders map[string]string) {
	// Set default headers
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("X-Forwarded-For", ForwardedFor)

	// Apply rule-specific headers if rule exists
	if rule != nil {
		if rule.Headers.UserAgent != "" {
			if rule.Headers.UserAgent == "none" {
				req.Header.Del("User-Agent")
			} else {
				req.Header.Set("User-Agent", rule.Headers.UserAgent)
			}
		}

		if rule.Headers.XForwardedFor != "" {
			if rule.Headers.XForwardedFor == "none" {
				req.Header.Del("X-Forwarded-For")
			} else {
				req.Header.Set("X-Forwarded-For", rule.Headers.XForwardedFor)
			}
		}

		if rule.Headers.Referer != "" {
			if rule.Headers.Referer == "none" {
				req.Header.Del("Referer")
			} else {
				req.Header.Set("Referer", rule.Headers.Referer)
			}
		}

		if rule.Headers.Cookie != "" {
			req.Header.Set("Cookie", rule.Headers.Cookie)
		}

		// #5: Random IP generation
		if rule.RandomIP != "" {
			var ip string
			if rule.RandomIP == "eu" {
				ip = fmt.Sprintf("185.%d.%d.%d", rand.Intn(256), rand.Intn(256), rand.Intn(256))
			} else {
				ip = fmt.Sprintf("%d.%d.%d.%d", rand.Intn(224)+1, rand.Intn(256), rand.Intn(256), rand.Intn(256))
			}
			req.Header.Set("X-Forwarded-For", ip)
		}

		// #6: Extra headers
		for key, val := range rule.ExtraHeaders {
			req.Header.Set(key, val)
		}
	}

	// Copy referer from request headers if not overridden
	if referer := requestHeaders["referer"]; referer != "" && req.Header.Get("Referer") == "" {
		req.Header.Set("Referer", referer)
	}
}

// applyURLModifications applies URL modifications from the rule
func applyURLModifications(targetURL string, rule *ruleset.Rule) string {
	if rule == nil {
		return targetURL
	}

	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return targetURL
	}

	// Apply domain modifications
	for _, domainMod := range rule.URLMods.Domain {
		if domainMod.Match != "" {
			re, err := regexp.Compile(domainMod.Match)
			if err == nil {
				parsedURL.Host = re.ReplaceAllString(parsedURL.Host, domainMod.Replace)
			}
		}
	}

	// Apply path modifications
	for _, pathMod := range rule.URLMods.Path {
		if pathMod.Match != "" {
			re, err := regexp.Compile(pathMod.Match)
			if err == nil {
				parsedURL.Path = re.ReplaceAllString(parsedURL.Path, pathMod.Replace)
			}
		}
	}

	// Apply query modifications
	if len(rule.URLMods.Query) > 0 {
		query := parsedURL.Query()
		for _, queryMod := range rule.URLMods.Query {
			if queryMod.Value == "" {
				query.Del(queryMod.Key)
			} else {
				query.Set(queryMod.Key, queryMod.Value)
			}
		}
		parsedURL.RawQuery = query.Encode()
	}

	// Apply Google Cache if enabled
	if rule.GoogleCache {
		return "https://webcache.googleusercontent.com/search?q=cache:" + parsedURL.String()
	}

	return parsedURL.String()
}

// applyResponseModifications applies regex rules and injections to the response body
// Refactored to single GoQuery parse for all DOM operations
func applyResponseModifications(body []byte, rule *ruleset.Rule, parsedURL *url.URL) []byte {
	if rule == nil {
		return body
	}

	bodyStr := string(body)

	// Step 1: Apply regex rules (string ops, before parse)
	for _, regexRule := range rule.RegexRules {
		if regexRule.Match != "" {
			re, err := regexp.Compile(regexRule.Match)
			if err == nil {
				bodyStr = re.ReplaceAllString(bodyStr, regexRule.Replace)
			}
		}
	}

	// Step 2: Parse HTML into GoQuery doc once
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(bodyStr))
	if err != nil {
		// Fallback to string-based processing
		bodyStr = rewriteHTMLFallback(bodyStr, parsedURL.Host)
		return []byte(bodyStr)
	}

	// Step 3: Block scripts (#7)
	if len(rule.BlockScripts) > 0 {
		applyBlockScriptsProxy(doc, rule.BlockScripts)
	}

	// Step 4: Block inline JS (#12)
	if rule.BlockJsInline != "" {
		applyBlockJsInlineProxy(doc, rule.BlockJsInline, parsedURL.String())
	}

	// Step 5: Apply csCode operations (#9)
	if len(rule.CsCode) > 0 {
		applyCsCodeProxy(doc, rule.CsCode)
	}

	// Step 6: AMP unhide (#10)
	if rule.AmpUnhide {
		applyAmpUnhideProxy(doc)
	}

	// Step 7: Rewrite HTML
	rewriteHTMLDoc(doc, parsedURL.Host)

	// Step 8: Apply injections
	if len(rule.Injections) > 0 {
		for _, injection := range rule.Injections {
			if injection.Position != "" {
				selection := doc.Find(injection.Position)
				if injection.Append != "" {
					selection.AppendHtml(injection.Append)
				}
				if injection.Prepend != "" {
					selection.PrependHtml(injection.Prepend)
				}
				if injection.Replace != "" {
					selection.ReplaceWithHtml(injection.Replace)
				}
			}
		}
	}

	// Step 9: Clear storage (#13)
	if rule.ClearStorage {
		doc.Find("head").PrependHtml(`<script>localStorage.clear();sessionStorage.clear()</script>`)
	}

	// Step 10: Serialize once
	html, err := doc.Html()
	if err != nil {
		return []byte(bodyStr)
	}

	// CSS url() rewrites
	proxyPrefix := "/https://" + parsedURL.Host + "/"
	html = strings.ReplaceAll(html, `url('/`, `url('`+proxyPrefix)
	html = strings.ReplaceAll(html, `url(/`, `url(`+proxyPrefix)

	return []byte(html)
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
	body = strings.ReplaceAll(body, `href="https://`+originalHost, `href="/https://`+originalHost+`/`)

	return body
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

// applyBlockScriptsProxy removes script/link elements matching patterns (#7)
func applyBlockScriptsProxy(doc *goquery.Document, patterns []string) {
	compiled := make([]*regexp.Regexp, 0, len(patterns))
	for _, pattern := range patterns {
		re, err := regexp.Compile(pattern)
		if err != nil {
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

// applyBlockJsInlineProxy removes all inline scripts if the page URL matches the pattern (#12)
func applyBlockJsInlineProxy(doc *goquery.Document, pattern, pageURL string) {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return
	}
	if !re.MatchString(pageURL) {
		return
	}
	doc.Find("script:not([src])").Each(func(i int, s *goquery.Selection) {
		s.Remove()
	})
}

// applyCsCodeProxy applies content script DOM operations (#9)
func applyCsCodeProxy(doc *goquery.Document, ops []ruleset.CsCodeOp) {
	for _, op := range ops {
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

		if op.AddStyle != "" {
			doc.Find("head").AppendHtml("<style>" + op.AddStyle + "</style>")
		}
	}
}

// applyAmpUnhideProxy removes AMP access-hiding attributes (#10)
func applyAmpUnhideProxy(doc *goquery.Document) {
	doc.Find(`[subscriptions-section="content-not-granted"]`).Remove()
	doc.Find("[subscriptions-section]").Each(func(i int, s *goquery.Selection) {
		s.RemoveAttr("subscriptions-section")
	})
	doc.Find("[amp-access-hide]").Each(func(i int, s *goquery.Selection) {
		s.RemoveAttr("amp-access-hide")
	})
}

// fixRelativeURLs converts relative URLs to go through the proxy
func fixRelativeURLs(body string, parsedURL *url.URL) string {
	baseURL := parsedURL.Scheme + "://" + parsedURL.Host

	// Fix relative links
	relativeRegex := regexp.MustCompile(`(href|src)="(/[^"]*)"`)
	body = relativeRegex.ReplaceAllStringFunc(body, func(match string) string {
		parts := strings.Split(match, `"`)
		if len(parts) >= 2 {
			relativePath := parts[1]
			absoluteURL := baseURL + relativePath
			return fmt.Sprintf(`%s"/%s"`, parts[0], absoluteURL)
		}
		return match
	})

	return body
}
