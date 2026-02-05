package handlers

import (
	"encoding/json"
	"fmt"
)

// HandleAPI handles API endpoint requests and returns JSON response
func HandleAPI(method, targetURL string, headers map[string]string) map[string]interface{} {
	if method != "GET" {
		return createResponse(405, "Method Not Allowed", map[string]string{
			"Content-Type": "application/json",
		})
	}

	// Extract and validate URL
	url, err := extractUrl(targetURL, headers)
	if err != nil {
		return createResponse(400, fmt.Sprintf(`{"error": "Invalid URL: %s"}`, err.Error()), map[string]string{
			"Content-Type": "application/json",
		})
	}

	// Validate domain restrictions
	if err := validateDomain(url); err != nil {
		return createResponse(403, fmt.Sprintf(`{"error": "Domain not allowed: %s"}`, err.Error()), map[string]string{
			"Content-Type": "application/json",
		})
	}

	// Proxy the request
	response := proxyRequest(url, headers)

	body := fmt.Sprintf("%v", response["body"])
	version := getenv("VERSION", "0.0.0")

	apiResponse := map[string]interface{}{
		"version": version,
		"body":    body,
		"request": map[string]interface{}{
			"headers": headersMapToList(response["requestHeaders"]),
		},
		"response": map[string]interface{}{
			"headers": headersMapToList(response["originHeaders"]),
		},
	}

	// Convert to JSON
	jsonBytes, err := json.Marshal(apiResponse)
	if err != nil {
		return createResponse(500, fmt.Sprintf(`{"error": "Failed to generate JSON: %s"}`, err.Error()), map[string]string{
			"Content-Type": "application/json",
		})
	}

	return createResponse(200, string(jsonBytes), map[string]string{
		"Content-Type": "application/json; charset=utf-8",
	})
}

func headersMapToList(headers interface{}) []map[string]string {
	list := []map[string]string{}
	headerMap, ok := headers.(map[string]string)
	if !ok {
		return list
	}
	for key, value := range headerMap {
		list = append(list, map[string]string{
			"key":   key,
			"value": value,
		})
	}
	return list
}
