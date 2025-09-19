package handlers

import (
	"embed"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"

	"ladderflare/pkg/ruleset"
)

var (
	UserAgent      = getenv("USER_AGENT", "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)")
	ForwardedFor   = getenv("X_FORWARDED_FOR", "66.249.66.1")
	rulesSet       *ruleset.Ruleset
	allowedDomains = []string{}
	defaultTimeout = 15 // in seconds
	assets         embed.FS
)

// Initialize sets up the handlers with embedded ruleset and assets
func Initialize(embeddedRuleset string, embeddedAssets embed.FS) error {
	assets = embeddedAssets

	// Initialize ruleset from embedded data
	rs, err := ruleset.NewRulesetFromString(embeddedRuleset)
	if err != nil {
		return fmt.Errorf("failed to initialize ruleset: %v", err)
	}
	rulesSet = rs

	// Initialize allowed domains
	allowedDomains = strings.Split(os.Getenv("ALLOWED_DOMAINS"), ",")
	if getenv("ALLOWED_DOMAINS_RULESET", "false") == "true" {
		allowedDomains = append(allowedDomains, rulesSet.Domains()...)
	}

	// Set timeout
	if timeoutStr := os.Getenv("HTTP_TIMEOUT"); timeoutStr != "" {
		defaultTimeout, _ = strconv.Atoi(timeoutStr)
	}

	return nil
}

// getenv returns environment variable or default value
func getenv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// extractUrl extracts and validates URL from request path
func extractUrl(path string, headers map[string]string) (string, error) {
	// URL decode the path
	reqUrl, err := url.QueryUnescape(path)
	if err != nil {
		reqUrl = path // fallback to original
	}

	// Parse the URL
	urlQuery, err := url.Parse(reqUrl)
	if err != nil {
		return "", fmt.Errorf("error parsing request URL '%s': %v", reqUrl, err)
	}

	isRelativePath := urlQuery.Scheme == ""

	// Handle relative paths using referer
	if isRelativePath {
		referer := headers["referer"]
		if referer == "" {
			return "", fmt.Errorf("relative path requires referer header")
		}

		// Parse the referer URL
		refererUrl, err := url.Parse(referer)
		if err != nil {
			return "", fmt.Errorf("error parsing referer URL: %v", err)
		}

		// Extract the real url from referer path
		realUrl, err := url.Parse(strings.TrimPrefix(refererUrl.Path, "/"))
		if err != nil {
			return "", fmt.Errorf("error parsing real URL from referer: %v", err)
		}

		// Reconstruct the full URL
		fullUrl := &url.URL{
			Scheme:   realUrl.Scheme,
			Host:     realUrl.Host,
			Path:     urlQuery.Path,
			RawQuery: urlQuery.RawQuery,
		}

		return fullUrl.String(), nil
	}

	return urlQuery.String(), nil
}

// validateDomain checks if domain is allowed
func validateDomain(targetUrl string) error {
	if len(allowedDomains) == 0 || (len(allowedDomains) == 1 && allowedDomains[0] == "") {
		return nil // No restrictions
	}

	parsedUrl, err := url.Parse(targetUrl)
	if err != nil {
		return fmt.Errorf("invalid URL: %v", err)
	}

	hostname := parsedUrl.Hostname()
	for _, domain := range allowedDomains {
		if domain == "" {
			continue
		}
		if strings.Contains(hostname, domain) || hostname == domain {
			return nil
		}
	}

	return fmt.Errorf("domain not allowed: %s", hostname)
}

// createResponse creates a standardized response format
func createResponse(status int, body string, headers map[string]string) map[string]interface{} {
	response := map[string]interface{}{
		"status": status,
		"body":   body,
	}

	if headers != nil && len(headers) > 0 {
		response["headers"] = headers
	}

	return response
}