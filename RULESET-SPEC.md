# Bypasser Ruleset Spec

Bypasser is a rules-driven proxy. Rules are JSON objects loaded from KV (`CONFIG_KV`) and applied by the Worker runtime.
The active ruleset is built from BPC source data plus Ladder YAML overlays merged at update time.

## Lifecycle: Request -> Response

1. Parse request path and extract target URL.
2. Match best rule by host specificity (exact host first, then longest suffix), optional `paths`, and optional `pathExclusions`.
3. Build fetch instructions (`urlMods`, headers, `randomIP`, `extraHeaders`, `googleCache`).
4. Fetch origin content.
5. If response is HTML, apply transforms in this order:
   1. `regexRules`
   2. `blockScripts` + `blockScriptsGeneral` + global `blockScriptsGeneral`
   3. `blockJsInline`
   4. `contentExtraction`
   5. `archiveFallback`
   6. `csCode`
   7. `ampUnhide`
   8. proxy URL rewrite (`src`, `href`, `action`, CSS `url()`)
   9. `injections`
   10. `externalLink`
   11. `clearStorage`
6. If `headers.content-security-policy` is set, response CSP is overridden.

## Route Surface

Supported:

- `/{URL}`
- `/raw/{URL}`
- `/api/{URL}`
- `/ruleset`
- `/status`
- `/test`

Deprecated:

- `/yaml/{URL}` -> `410 Gone`
- `/json/{URL}` -> `410 Gone`

## Rule Shape

Rules are JSON array entries with optional fields:

- `domain` (string) or `domains` (string array)
- `paths` (string array): request path must start with one value
- `pathExclusions` (string array): regex patterns; match means skip rule
- `headers`:
  - `user-agent`
  - `x-forwarded-for`
  - `referer`
  - `cookie`
  - `content-security-policy`
- `extraHeaders` (object<string, string>)
- `cookiePolicy`:
  - `removeAll` (boolean): suppress configured outbound Cookie and filtered Set-Cookie values
  - `drop` (string array): drop matching Set-Cookie names
  - `hold` (string array): keep only matching Set-Cookie names
- `googleCache` (boolean)
- `urlMods`:
  - `domain`: regex replacements applied to hostname
  - `path`: regex replacements applied to pathname
  - `query`: `{ key, value }` pairs
- `regexRules`: `{ match, replace }` regex replacements on raw HTML string
- `injections`: `{ position, append|prepend|replace }`
- `tests`: `{ url, test }`
- `randomIP`
- `blockScripts`
- `blockScriptsGeneral`
- `csCode` (`cond`, `hide_elem`, `rm_elem`, `rm_class`, `rm_attrib`, `set_attrib`, `add_style`)
  - nested `elems` operations are applied inside each matched `cond` scope
- `contentExtraction`:
  - `ldJson`
  - `ldJsonNext`
  - `ldJsonUrl`
  - `ldJsonSource`
- `archiveFallback`: `{ selector }`; selector format is `paywallSelector|articleSelector|sourceSelector|archiveLinkSelector`
- `externalLink`: `{ selector, type }`; selector format is `paywallSelector|articleSelector`, type is `archive.is` or `google_search_tool`
- `ampUnhide`
- `blockJsInline`
- `clearStorage`

Unknown fields are ignored.

## Matching Semantics

- Most specific matching rule wins (exact host first, then longest suffix; then longest matching path prefix).
- Domain match:
  - exact host match, or
  - host suffix match (`host.endsWith("." + ruleDomain)`).
- If `paths` exists, one prefix must match.
- If any `pathExclusions` regex matches, rule is skipped.

## Header and URL Behavior

- `user-agent` default: `USER_AGENT` env or Googlebot default.
- `referer`:
  - `"none"` means omit header.
  - unset means use target URL.
- `x-forwarded-for`:
  - `"none"` means omit header.
  - unset means env `X_FORWARDED_FOR` or default (`66.249.66.1`).
- `randomIP` overrides `x-forwarded-for`:
  - `"eu"` -> `185.x.x.x`
  - non-empty other value -> random public-ish IPv4.
- `urlMods.query`:
  - `value: null` or `value: ""` deletes key.
  - number/bool values are stringified.
- `googleCache: true` rewrites fetch URL to `https://webcache.googleusercontent.com/search?q=cache:{url}`.

## Runtime Source of Truth

- Active rules are read from `CONFIG_KV` key `bpc:ruleset_bpc`.
- Version key: `bpc:ruleset_bpc:version`.
- Ruleset mode key: `bpc:ruleset_bpc:mode` (`bpc+ladder-v3`).
- Scheduled updates fetch BPC manifest data and merge Ladder YAML overlays before writing KV.
- If no rules are available and bootstrap update fails, request handling returns `503 Ruleset unavailable`.
- Scheduled updates populate KV from `RULESET_URL` manifest.
