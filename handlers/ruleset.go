package handlers

// HandleRuleset serves the current ruleset as YAML
func HandleRuleset(method, path string, headers map[string]string) map[string]interface{} {
	if method != "GET" {
		return createResponse(405, "Method Not Allowed", map[string]string{
			"Content-Type": "text/plain",
		})
	}

	// Check if ruleset exposure is enabled
	if getenv("EXPOSE_RULESET", "true") != "true" {
		return createResponse(404, "Ruleset not exposed", map[string]string{
			"Content-Type": "text/plain",
		})
	}

	if rulesSet == nil {
		return createResponse(500, "Ruleset not initialized", map[string]string{
			"Content-Type": "text/plain",
		})
	}

	yamlContent, err := rulesSet.Yaml()
	if err != nil {
		return createResponse(500, "Error generating YAML", map[string]string{
			"Content-Type": "text/plain",
		})
	}

	return createResponse(200, yamlContent, map[string]string{
		"Content-Type": "application/x-yaml; charset=utf-8",
	})
}