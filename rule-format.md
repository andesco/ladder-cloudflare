# Rule Format

## Overview
This document defines the rule format used in the aggregated ruleset files (`sites_aggregated.json` and `sites_aggregated.yaml`). Rules control how the proxy handles requests to bypass web content restrictions. The documentation and example rules below contain **example-only** domains, services, CSS selectors, DOM selectors, etc.

## Rule Structure

### Basic Properties
```yaml
- domain: "example.com"    # primary domain for this rule
  upd_version: "4.3.2.1"   # optional: Rule version identifier
```

### Domain Groups
Groups allow multiple domains to share the same ruleset. During rule expansion, each domain in the group becomes an individual rule.

```yaml
- domain: "###_group_name" # group identifier starts with: `###_`
  group:                   # list of domains in this group
    - "aaabbb.io"
    - "example.dev"
    - "company.ltd"
  allow_cookies: 1
  block_regex: \.tracking\.com\/
```

**Note:** During processing, this expands to individual rules for each domain while preserving all other properties.

### Cookie Management
```yaml
  allow_cookies: 1                        # allow cookies (0 or 1)
  remove_cookies: 1                       # remove all cookies
  remove_cookies_select_drop: ["cookie1"] # remove specific cookies
  remove_cookies_select_hold: ["session"] # keep only these cookies
```

### Request Blocking
Block external resources by regex pattern (without surrounding slashes):
```yaml
  block_regex: \.analytics\.dev\/         # block requests matching pattern
  block_regex_general: \.tracking\.io\/   # general blocking pattern
  block_js_inline: 1                      # block inline JavaScript
```
Examples:
- `\.tracjing\.io\/` block tracking service
- `\.ampproject\.org\/v0\/amp-(access|subscriptions)-.+\.js` block Google AMP access scripts
- `\.analytics\.dev\/` - block analytics service

### User Agent Spoofing
```yaml
  useragent: "googlebot" # predefined: googlebot, facebookbot, bingbot
  useragent_custom: "Custom UA String" # custom user agent
```

### Referer Manipulation
```yaml
  referer: "google" # predefined: google, facebook, twitter
  referer_custom: "https://custom-ref.com" # custom referer
```

### Custom Headers
```yaml
  headers_custom:
    ismobileapp: 'true'
    platform: app
    renderingkind: opened
  random_ip: 1 # add random `X-Forwarded-For` IP
```

### Content Script Actions · DOM Manipulation
The `cs_code` field contains JSON-encoded array of DOM manipulation actions:
```yaml
  cs_code: '[{"hide_elem":"div.restriction-banner"}]'
  cs_code: '[{"cond":"div.restricted", "rm_class":"restricted"}]'
  cs_code: '[{"cond":"div[data-gated]", "rm_attrib":"data-gated"}]'
```

Available Actions:
- `hide_elem` - Hide elements matching selector
- `rm_class` - Remove CSS class from elements
- `rm_attrib` - Remove HTML attribute
- `rm_elem` - Remove elements entirely
- `cond` - Conditional selector (element must exist for action to apply)
- `elems` - Nested actions to apply to child elements

Complex Example:
```yaml
  cs_code: >-
    [{"cond":"div.premium-wall", "rm_elem":1,
    "elems":[{"cond":"div.hidden-content", "rm_class":"hidden"}]}]
```
> [!Important]
> `cs_code` field must be valid `JSON`, even when embedded in `YAML`. Use single quotes or `>-` for multiline strings.

### Archive Integration
```yaml
  cs_dompurify: 1   # use archive.is as fallback source
  ld_archive_is: 1  # load directly from archive.is
```

### JSON-LD · Structured Data Extraction
Extract article content from JSON-LD structured data:

```yaml
  ld_json: "div.restriction|div.article" # replace selectors with JSON-LD content
  ld_json_next: "div.pagination" # next page selector
  ld_json_url: "meta[property='og:url']" # URL source selector
  ld_json_source: "script[type='application/ld+json']" # JSON-LD script source
```

### AMP Redirect
Automatically redirect to AMP version when restriction detected:
```yaml
  amp_redirect: "div#amp-modal" # CSS selector initiating redirect
  amp_unhide: 1                 # unhide AMP content post redirect
```

### Additional Features
```yaml
  cs_clear_lclstrg: 1       # clear localStorage
  cs_all_frames: 1          # apply content scripts to all frames
  cs_param: "param_value"   # additional content script parameter
  exception: 1              # mark as exception rule
  excluded_domains: ["sub.site.ca"] # exclude specific subdomains
  add_ext_link: "footer"    # add external link for content
  add_ext_link_type: "google_search_tool" # type of external link
  block_host_perm_add: 1    # request additional host permissions
```

## Complete Examples

### Simple Domain Rule
```yaml
- domain: example.io
  allow_cookies: 1
  block_regex: \.restrictive-cdn\.com\/
  cs_dompurify: 1
```

### Complex Rule with DOM Manipulation
```yaml
- domain: example.dev
  allow_cookies: 1
  remove_cookies_select_drop:
    - tracking_session
  block_regex: \.example\.dev\/wp-content\/plugins\/restriction\/
  useragent: googlebot
  referer: google
  ld_json: div.restriction|div.article-preview
  cs_code: '[{"cond":"div.restricted", "rm_class":"restricted"}]'
  upd_version: 4.2.0.3
```

### Domain Group Rule
```yaml
- domain: "###_company_group_aaa"
  group:
    - "aaa-daily.com"
    - "aaa-info.com"
    - "aaa-publication.com"
  allow_cookies: 1
  block_regex: \.restriction-service\.dev\/
  useragent: googlebot
  cs_dompurify: 1
```

### Mobile App Spoofing
```yaml
- domain: company.ltd
  allow_cookies: 1
  headers_custom:
    ismobileapp: 'true'
    platform: app
    renderingkind: opened
  useragent_custom: >-
    Mozilla/5.0 (Linux; Android 9) AppleWebKit/537.36 (KHTML, like Gecko)
    Chrome/120.0.0.0 Mobile Safari/537.36
```

## Data Types

#### Boolean Flags
binary values as boolean flags: `allow_cookies`, `cs_dompurify`, `amp_unhide`, `remove_cookies`
- `0` = false · disabled
- `1` = true · enabled

#### Strings
regular quoted strings for text values: `domain`, `useragent`, `referer`, `upd_version`

#### Arrays
lists of strings: `group`, `remove_cookies_select_drop`, `remove_cookies_select_hold`, `excluded_domains`

#### Objects
key-value pairs for custom HTTP headers: `headers_custom`

#### JSON Strings
JSON-encoded strings (structured data array) for DOM manipulation actions: `cs_code`

> [!Important]
> `cs_code` field must be valid `JSON`, even when embedded in `YAML`. Use single quotes or `>-` for multiline strings.

## Rule Priority System

When multiple rule sources are available, rules from higher priority sources completely override rules from lower priority sources for the same domain.


1. **custom rules**: `sites_custom.json` · highest priority
2. **updated rules**: `sites_updated.json`
3. **base rules**: `sites.js`** **`sites.json` · lowest priority

This can result in a single aggregated ruleset in `JSON` and/or `YAML`:

* `sites_aggregated.json`
* `sites_aggregated.yaml`

## Regex Pattern Format · </small>`IMPORTANT`</small>

Regex patterns in `block_regex` are written **without** surrounding slashes:

**correct:** `\.restriction\.com\/api\/`

**incorrect:** `/\.restriction\.com\/api\//`

Patterns should be properly escaped for YAML/JSON:
- use `\.` for literal dots
- use `\/` for literal slashes (though optional in JSON)
- use `\\` for backslash escaping when needed

## Processing Notes

1. **Domain Groups:** Rules with `domain: "###_*"` and a `group` array are expanded into individual rules for each domain in the group.

2. **Deletion Rules:** Rules with `domain: "###"` (without an underscore) mark domains for deletion from the ruleset.

3. **Numeric Booleans:** Most boolean flags use `1` for true and `0` (or omission) for false.

4. **Content Scripts:** The `cs_code` field must be valid JSON, even when embedded in YAML. Use single quotes or `>-` for multiline strings.

5. **Regex Validation:** Regex patterns are used directly without modification; ensure they are valid for the target environment.