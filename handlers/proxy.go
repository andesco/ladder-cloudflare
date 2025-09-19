package handlers

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"ladderflare/pkg/ruleset"
	"github.com/PuerkitoBio/goquery"
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

	// Copy important headers from original response
	for key, values := range resp.Header {
		if len(values) > 0 {
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

	// Add CORS headers to allow access
	responseHeaders["Access-Control-Allow-Origin"] = "*"
	responseHeaders["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
	responseHeaders["Access-Control-Allow-Headers"] = "*"

	return createResponse(resp.StatusCode, string(body), responseHeaders)
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
			query.Set(queryMod.Key, queryMod.Value)
		}
		parsedURL.RawQuery = query.Encode()
	}

	return parsedURL.String()
}

// applyResponseModifications applies regex rules and injections to the response body
func applyResponseModifications(body []byte, rule *ruleset.Rule, parsedURL *url.URL) []byte {
	if rule == nil {
		return body
	}

	bodyStr := string(body)

	// Apply regex rules
	for _, regexRule := range rule.RegexRules {
		if regexRule.Match != "" {
			re, err := regexp.Compile(regexRule.Match)
			if err == nil {
				bodyStr = re.ReplaceAllString(bodyStr, regexRule.Replace)
			}
		}
	}

	// Apply injections
	if len(rule.Injections) > 0 {
		doc, err := goquery.NewDocumentFromReader(strings.NewReader(bodyStr))
		if err == nil {
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

			// Get the modified HTML
			if modifiedHTML, err := doc.Html(); err == nil {
				bodyStr = modifiedHTML
			}
		}
	}

	// Fix relative URLs to point through the proxy
	bodyStr = fixRelativeURLs(bodyStr, parsedURL)

	return []byte(bodyStr)
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