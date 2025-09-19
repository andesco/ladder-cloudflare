package ruleset

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

type Regex struct {
	Match   string `yaml:"match"`
	Replace string `yaml:"replace"`
}

type KV struct {
	Key   string `yaml:"key"`
	Value string `yaml:"value"`
}

type Ruleset []Rule

type Rule struct {
	Domain  string   `yaml:"domain,omitempty"`
	Domains []string `yaml:"domains,omitempty"`
	Paths   []string `yaml:"paths,omitempty"`
	Headers struct {
		UserAgent     string `yaml:"user-agent,omitempty"`
		XForwardedFor string `yaml:"x-forwarded-for,omitempty"`
		Referer       string `yaml:"referer,omitempty"`
		Cookie        string `yaml:"cookie,omitempty"`
		CSP           string `yaml:"content-security-policy,omitempty"`
	} `yaml:"headers,omitempty"`
	GoogleCache bool    `yaml:"googleCache,omitempty"`
	RegexRules  []Regex `yaml:"regexRules,omitempty"`

	URLMods struct {
		Domain []Regex `yaml:"domain,omitempty"`
		Path   []Regex `yaml:"path,omitempty"`
		Query  []KV    `yaml:"query,omitempty"`
	} `yaml:"urlMods,omitempty"`

	Injections []struct {
		Position string `yaml:"position,omitempty"`
		Append   string `yaml:"append,omitempty"`
		Prepend  string `yaml:"prepend,omitempty"`
		Replace  string `yaml:"replace,omitempty"`
	} `yaml:"injections,omitempty"`

	Tests []struct {
		URL  string `yaml:"url,omitempty"`
		Test string `yaml:"test,omitempty"`
	} `yaml:"tests,omitempty"`
}

var remoteRegex = regexp.MustCompile(`^https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()!@:%_\+.~#?&\/\/=]*)`)

// NewRulesetFromString creates a new Ruleset from embedded string data
func NewRulesetFromString(rulesData string) (*Ruleset, error) {
	var ruleSet Ruleset

	err := yaml.Unmarshal([]byte(rulesData), &ruleSet)
	if err != nil {
		return nil, fmt.Errorf("failed to parse embedded ruleset: %v", err)
	}

	ruleSet.PrintStats()
	return &ruleSet, nil
}

// NewRuleset loads a Ruleset from a given string of rule paths, separated by semicolons.
// For WASM, this primarily supports remote URLs since local file access is limited
func NewRuleset(rulePaths string) (*Ruleset, error) {
	var ruleSet Ruleset
	var errs []error

	rp := strings.Split(rulePaths, ";")
	for _, rule := range rp {
		rulePath := strings.Trim(rule, " ")
		isRemote := remoteRegex.MatchString(rulePath)

		if !isRemote {
			return nil, fmt.Errorf("WASM build only supports remote rulesets, got: %s", rulePath)
		}

		err := ruleSet.loadRulesFromRemoteFile(rulePath)
		if err != nil {
			e := fmt.Errorf("failed to load ruleset from '%s'", rulePath)
			errs = append(errs, errors.Join(e, err))
			continue
		}
	}

	if len(errs) != 0 {
		return &ruleSet, errors.Join(errs...)
	}

	ruleSet.PrintStats()
	return &ruleSet, nil
}

// loadRulesFromRemoteFile loads rules from a remote URL
func (rs *Ruleset) loadRulesFromRemoteFile(rulesURL string) error {
	var r Ruleset

	resp, err := http.Get(rulesURL)
	if err != nil {
		return fmt.Errorf("failed to load rules from remote url '%s': %v", rulesURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("failed to load rules from remote url (%s) on '%s'", resp.Status, rulesURL)
	}

	var reader io.Reader = resp.Body

	// Handle gzip compression if needed
	isGzip := strings.HasSuffix(rulesURL, ".gz") || strings.HasSuffix(rulesURL, ".gzip") || resp.Header.Get("content-encoding") == "gzip"
	if isGzip {
		// Note: For WASM, we might need to handle gzip differently or avoid it
		return fmt.Errorf("gzip compression not supported in WASM build")
	}

	err = yaml.NewDecoder(reader).Decode(&r)
	if err != nil {
		return fmt.Errorf("failed to parse rules from remote url '%s': %v", rulesURL, err)
	}

	*rs = append(*rs, r...)
	return nil
}

// Yaml returns the ruleset as a YAML string
func (rs *Ruleset) Yaml() (string, error) {
	y, err := yaml.Marshal(rs)
	if err != nil {
		return "", err
	}
	return string(y), nil
}

// Domains extracts and returns a slice of all domains present in the Ruleset
func (rs *Ruleset) Domains() []string {
	var domains []string
	for _, rule := range *rs {
		if rule.Domain != "" {
			domains = append(domains, rule.Domain)
		}
		domains = append(domains, rule.Domains...)
	}
	return domains
}

// DomainCount returns the count of unique domains present in the Ruleset
func (rs *Ruleset) DomainCount() int {
	return len(rs.Domains())
}

// Count returns the total number of rules in the Ruleset
func (rs *Ruleset) Count() int {
	return len(*rs)
}

// PrintStats logs the number of rules and domains loaded in the Ruleset
func (rs *Ruleset) PrintStats() {
	log.Printf("INFO: Loaded %d rules for %d domains\n", rs.Count(), rs.DomainCount())
}

// GetTestURLs extracts all test URLs from the ruleset
func (rs *Ruleset) GetTestURLs() []string {
	var testURLs []string
	for _, rule := range *rs {
		for _, test := range rule.Tests {
			if test.URL != "" {
				testURLs = append(testURLs, test.URL)
			}
		}
	}
	return testURLs
}

// FindRuleForDomain finds the appropriate rule for a given domain
func (rs *Ruleset) FindRuleForDomain(domain string) *Rule {
	for _, rule := range *rs {
		// Check main domain
		if rule.Domain != "" && strings.Contains(domain, rule.Domain) {
			return &rule
		}
		// Check additional domains
		for _, d := range rule.Domains {
			if strings.Contains(domain, d) {
				return &rule
			}
		}
	}
	return nil
}

// FindRuleForURL finds the appropriate rule for a given URL (domain + path matching)
func (rs *Ruleset) FindRuleForURL(url string) *Rule {
	// Simple implementation - extract domain from URL
	// This could be enhanced to also match paths
	if strings.HasPrefix(url, "http://") {
		url = strings.TrimPrefix(url, "http://")
	} else if strings.HasPrefix(url, "https://") {
		url = strings.TrimPrefix(url, "https://")
	}

	// Extract domain part
	parts := strings.Split(url, "/")
	if len(parts) > 0 {
		domain := parts[0]
		return rs.FindRuleForDomain(domain)
	}

	return nil
}