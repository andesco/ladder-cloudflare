package handlers

import (
	"fmt"
)

// HandleRaw handles raw endpoint requests and returns plain HTML
func HandleRaw(method, targetURL string, headers map[string]string) map[string]interface{} {
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

	// Proxy the request without any modifications
	response := proxyRequestRaw(url, headers)

	return response
}