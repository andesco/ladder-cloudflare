# Ladderflare Ruleset Spec (Embedded JSON)

Ladderflare is a rules-driven proxy. The **ruleset is data** (YAML/JSON) and the Go WASM runtime acts as the rules engine.

At build time, `scripts/build-rules.js` generates embedded JSON rulesets from:

- BPC aggregated rules: `https://bypass.andrewe.dev/sites_aggregated.json`
- Local Ladder rules: `ruleset-ladder.yaml`

Outputs written into the repo root:

- `ruleset-embedded.json` (merged; default runtime ruleset)
- `ruleset-bpc-embedded.json` (BPC-only; `/json/` route)
- `ruleset-ladder-embedded.json` (Ladder-only; `/yaml/` route)
- `test-urls.json`

The Cloudflare Worker loads the WASM rules engine (`main.go`) and uses these embedded JSON files via `go:embed`.

## Rule Shape

The embedded rulesets are JSON arrays of rule objects. A rule can contain:

- `domain` (string) or `domains` (string array)
- `paths` (string array): request path must start with one of these prefixes
- `pathExclusions` (string array): Go regex; if any matches the request path, the rule is skipped
- `headers` (object):
  - `user-agent` (string)
  - `x-forwarded-for` (string)
  - `referer` (string)
  - `cookie` (string)
  - `content-security-policy` (string)
- `extraHeaders` (object<string,string>): arbitrary request headers
- `googleCache` (bool): rewrite to Google Web Cache
- `urlMods` (object):
  - `domain`: array of `{ match, replace }` regex replacements (applied to host)
  - `path`: array of `{ match, replace }` regex replacements (applied to path)
  - `query`: array of `{ key, value }` (value may be string/number/bool/null)
- `regexRules` (array): `{ match, replace }` regex replacements (applied to response body as a string)
- `injections` (array): `{ position, append|prepend|replace }` HTML injections
  - `position` supports `"head"`, `"body"`, `"html"`, or a CSS selector. The current WASM runtime only treats it as a selector when it contains `.`, `#`, or `[`; otherwise it falls back to `"head"`.
- `tests` (array): `{ url, test }` (used for `/test` URL selection; not executed at runtime)

BPC-derived fields:

- `randomIP` (string): `"eu"` or `"true"` (see semantics below)
- `blockScripts` (string array): regex patterns for external scripts/styles to remove
- `blockScriptsGeneral` (string array): shared/global regex patterns
- `csCode` (array): DOM ops (`cond`, `hide_elem`, `rm_elem`, `rm_class`, `rm_attrib`, `set_attrib`, `add_style`)
- `ampUnhide` (bool)
- `blockJsInline` (string): regex; if matches page URL, remove inline `<script>` tags
- `clearStorage` (bool)

Unknown fields are ignored by the Go JSON unmarshal (safe to add fields, but new *behaviors* require code support).

## Matching Semantics

Implemented in `main.go` (`findRuleForDomainAndPathInRuleset`):

1. **Domain match**:
   - `rule.domain == host` OR `host` ends with `"." + rule.domain`
   - Same rule for each entry in `rule.domains`
   - Example: a rule for `nytimes.com` matches `www.nytimes.com`
2. **Paths (optional)**:
   - If `paths` is present, request path must start with one of the entries
3. **Path exclusions (optional)**:
   - If any regex in `pathExclusions` matches the request path, skip the rule
4. **First match wins**:
   - Rules are scanned in order; the first matching rule is used

## Merged Mode Layering (Default Route)

Merged mode selects a BPC rule and a Ladder rule **independently** (same host/path), then overlays them (`mergeRuleOverlay`):

- BPC is the base.
- Ladder fills gaps for single-value fields when BPC leaves them empty (notably `headers.*`).
- Lists are combined (e.g. `blockScripts`, `csCode`, `regexRules`, `injections`).
- `extraHeaders`: BPC wins on key collisions; Ladder fills missing keys.

This layering exists to avoid “parent domain shadows subdomain” problems (e.g. BPC matches `nytimes.com` while Ladder targets `www.nytimes.com`).

## Request Behavior (Headers + URL Rewrites)

Request behavior is computed in WASM (`fetchURL`) and applied in the Worker (`index.js`):

- `User-Agent`:
  - Uses `headers.user-agent` if set; otherwise falls back to the default `USER_AGENT` (Googlebot by default).
  - The Worker always sends a `User-Agent` header.
- `Referer`:
  - If `headers.referer == "none"`: omit the `Referer` header.
  - Else if set: send it.
  - Else: default referer is the target URL.
- `X-Forwarded-For`:
  - If `headers.x-forwarded-for == "none"`: omit the header.
  - Else if set: send it.
  - Else: default `X_FORWARDED_FOR` (66.249.66.1 by default).
- `Cookie`: sent only if non-empty.
- `extraHeaders`: copied into the request.
- `randomIP`:
  - If set, overrides `X-Forwarded-For` with a generated random IP.
  - `"eu"` generates `185.x.x.x`; any other non-empty value generates a random public-ish IPv4.
- `urlMods`:
  - `domain` and `path` use regex replacements.
  - `query` sets/removes query params:
    - `value: null` or `value: ""` deletes the key
    - numbers/bools are stringified
- `googleCache: true` rewrites the fetch URL to:
  - `https://webcache.googleusercontent.com/search?q=cache:{url}`

## Response Behavior (HTML + DOM Modifications)

Implemented in `processContent`:

1. Apply `regexRules` (string-based regex replace) before parsing HTML.
2. Parse HTML with GoQuery once.
3. Remove external scripts/styles using `blockScripts`, `blockScriptsGeneral`, and global `blockScriptsGeneral`.
4. Remove inline JS if `blockJsInline` matches the page URL.
5. Apply `csCode` DOM operations.
6. Apply `ampUnhide`.
7. Rewrite relative URLs to proxied URLs.
8. Apply `injections` to the DOM.
9. If `clearStorage`, inject a `<script>` to clear `localStorage` and `sessionStorage`.
10. Serialize the DOM back to HTML.

If `headers.content-security-policy` is set, it is returned to the Worker so the response CSP can be overridden.

## Reserved Values / Gotchas

- `headers.referer: "none"` and `headers.x-forwarded-for: "none"` are reserved sentinels meaning “do not send this header”.
- In `urlMods.query`, `value: ""` deletes the query key; you cannot set an empty-string query param value with this scheme.
- Parent-domain matching is a feature; merged mode layering exists to avoid it causing rule shadowing.

## Build-Time Guardrails (Fail Fast)

`scripts/build-rules.js` treats some BPC fields as enums (`useragent`, `referer`, `random_ip`). If upstream adds new token values, Ladderflare fails the build so changes are intentional (update mapping + the allowlist) instead of silently degrading.
