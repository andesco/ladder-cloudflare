package handlers

import (
	"fmt"
	"strings"
)

// HandleForm serves the main form/landing page
func HandleForm(method, path string, headers map[string]string) map[string]interface{} {
	if method != "GET" {
		return createResponse(405, "Method Not Allowed", map[string]string{
			"Content-Type": "text/plain",
		})
	}

	// Check if form is disabled
	if getenv("DISABLE_FORM", "false") == "true" {
		return createResponse(404, "Form disabled", map[string]string{
			"Content-Type": "text/plain",
		})
	}

	// Try to read custom form if FORM_PATH is set
	customFormPath := getenv("FORM_PATH", "")
	if customFormPath != "" {
		// For WASM, we can only serve embedded assets
		// Custom form path would need to be embedded at build time
		if customContent, err := assets.ReadFile("public/" + strings.TrimPrefix(customFormPath, "/")); err == nil {
			return createResponse(200, string(customContent), map[string]string{
				"Content-Type": "text/html; charset=utf-8",
			})
		}
	}

	// Serve the default index.html
	indexHTML, err := assets.ReadFile("public/index.html")
	if err != nil {
		return createResponse(500, fmt.Sprintf("Error reading index.html: %v", err), map[string]string{
			"Content-Type": "text/plain",
		})
	}

	return createResponse(200, string(indexHTML), map[string]string{
		"Content-Type": "text/html; charset=utf-8",
	})
}