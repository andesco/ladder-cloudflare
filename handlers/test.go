package handlers

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"time"
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

// HandleTest redirects to a random test URL from removepaywalls.com
func HandleTest(method, path string, headers map[string]string) map[string]interface{} {
	if method != "GET" {
		return createResponse(405, "Method Not Allowed", map[string]string{
			"Content-Type": "text/plain",
		})
	}

	// Generate random date within last 30 days
	now := time.Now()
	randomDaysAgo := rand.Intn(30) + 1 // 1-30 days ago
	randomDate := now.AddDate(0, 0, -randomDaysAgo)
	dateStr := randomDate.Format("20060102") // YYYYMMDD format

	// Fetch URLs from removepaywalls.com API
	apiURL := fmt.Sprintf("https://removepaywalls.com/top/top_%s.json", dateStr)

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	resp, err := client.Get(apiURL)
	if err != nil {
		return createResponse(500, fmt.Sprintf("Failed to fetch test URLs: %s", err.Error()), map[string]string{
			"Content-Type": "text/plain",
		})
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return createResponse(500, fmt.Sprintf("API returned status %d for date %s", resp.StatusCode, dateStr), map[string]string{
			"Content-Type": "text/plain",
		})
	}

	// Parse JSON response
	var urls []string
	if err := json.NewDecoder(resp.Body).Decode(&urls); err != nil {
		return createResponse(500, fmt.Sprintf("Failed to parse JSON response: %s", err.Error()), map[string]string{
			"Content-Type": "text/plain",
		})
	}

	if len(urls) == 0 {
		return createResponse(404, fmt.Sprintf("No URLs available for date %s", dateStr), map[string]string{
			"Content-Type": "text/plain",
		})
	}

	// Select random URL
	selectedURL := urls[rand.Intn(len(urls))]

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
    <p><small>Date: %s | Available URLs: %d | Selected: %s</small></p>
</body>
</html>`, redirectLocation, redirectLocation, selectedURL, redirectLocation, dateStr, len(urls), selectedURL), map[string]string{
		"Content-Type": "text/html; charset=utf-8",
		"Location":     redirectLocation,
	})
}