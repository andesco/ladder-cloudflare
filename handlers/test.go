package handlers

import (
	"fmt"
)

// TestResult represents a single test result
type TestResult struct {
	URL     string `json:"url"`
	Status  string `json:"status"` // "success", "error", "skipped"
	Message string `json:"message,omitempty"`
}

// TestResponse represents the complete test response
type TestResponse struct {
	Total   int          `json:"total"`
	Success int          `json:"success"`
	Errors  int          `json:"errors"`
	Results []TestResult `json:"results"`
}

// HandleTest redirects to a random test URL for actual proxy testing
func HandleTest(method, path string, headers map[string]string) map[string]interface{} {
	if method != "GET" {
		return createResponse(405, "Method Not Allowed", map[string]string{
			"Content-Type": "text/plain",
		})
	}

	if rulesSet == nil {
		return createResponse(500, "Ruleset not initialized", map[string]string{
			"Content-Type": "text/plain",
		})
	}

	// Get test URLs from the ruleset
	testURLs := rulesSet.GetTestURLs()

	if len(testURLs) == 0 {
		return createResponse(404, "No test URLs available", map[string]string{
			"Content-Type": "text/plain",
		})
	}

	// Filter valid test URLs (check domain restrictions)
	var validURLs []string
	for _, testURL := range testURLs {
		if err := validateDomain(testURL); err == nil {
			validURLs = append(validURLs, testURL)
		}
	}

	if len(validURLs) == 0 {
		return createResponse(403, "No test URLs allowed by domain restrictions", map[string]string{
			"Content-Type": "text/plain",
		})
	}

	// Select the first valid test URL (could be randomized later)
	selectedURL := validURLs[0]

	// Create redirect response to proxy the test URL
	redirectLocation := "/" + selectedURL

	return createResponse(302, fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <title>Redirecting to Test URL</title>
    <meta http-equiv="refresh" content="0;url=%s">
</head>
<body>
    <h1>Testing Ladderflare Proxy</h1>
    <p>Redirecting to test URL: <a href="%s">%s</a></p>
    <p>If you are not redirected automatically, <a href="%s">click here</a>.</p>
    <hr>
    <p><small>Available test URLs: %d | Selected: %s</small></p>
</body>
</html>`, redirectLocation, redirectLocation, selectedURL, redirectLocation, len(validURLs), selectedURL), map[string]string{
		"Content-Type": "text/html; charset=utf-8",
		"Location":     redirectLocation,
	})
}