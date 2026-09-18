# Ladderflare Ruleset Spec

Ladderflare is a rules-driven proxy. Rules are JSON objects loaded from KV (`CONFIG_KV`) and applied by the Worker runtime.
The active ruleset is built from BPC source data plus Ladder YAML overlays merged at update time.

## Lifecycle: Request -> Response

1. Parse request path and extract target URL.
2. Match best rule by host specificity (exact host first, then longest suffix), optional `paths`, and optional `pathExclusions`.
3. Build fetch instructions (`urlMods`, headers, `randomIP`, `extraHeaders`, `googleCache`).
4. Fetch origin content.
5. If configured and the paywall selector matches, fetch the declared AMP document.
6. Fetch a same-origin JSON article endpoint when `contentExtraction.ldJsonUrl` requires it.
7. If response is HTML, apply transforms in this order:
   1. `regexRules`
   2. `blockScripts` + `blockScriptsGeneral` + global `blockScriptsGeneral`
   3. `blockJsInline`
   4. `contentExtraction`
   5. `archiveFallback`
   6. `csCode`
   7. `ampUnhide`
   8. proxy URL rewrite (`src`, `href`, `action`, including iframes, CSS `url()`)
   9. `injections`
   10. `externalLink`
8. If `headers.content-security-policy` is set, response CSP is overridden.

## Route Surface

Supported:

- `/{URL}`
- `/fast/{URL}`
- `/raw/{URL}`
- `/api/{URL}`
- `/fast/raw/{URL}`
- `/fast/api/{URL}`
- `/browser/{URL}`
- `/ruleset`
- `/status`
- `/health`
- `/test`

Deprecated:

- `/yaml/{URL}` -> `410 Gone`
- `/json/{URL}` -> `410 Gone`

## Rule Shape

Rules are JSON array entries with optional fields:

- `domain` (string) or `domains` (string array)
- `global` (boolean): global BPC `block_regex_general` carrier with no matchable domain
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
  - nested `elems` operations run document-wide after the parent `cond` matches, matching BPC semantics
- `contentExtraction`:
  - `ldJson`
  - `ldJsonNext`
  - `ldJsonUrl`
  - `ldJsonSource`
- `archiveFallback`: `{ selector }`; selector format is `paywallSelector|articleSelector|sourceSelector|archiveLinkSelector`
- `externalLink`: `{ selector, type }`; selector format is `paywallSelector|articleSelector`, type is `archive.is` or `google_search_tool`
- `ampUnhide`
- `ampRedirect`: `paywallSelector|optionalAmpUrl`; supports `{path}` and `{host}` URL templates
- `blockJsInline`

Browser execution metadata is retained on BPC rules as `bpc`, `allowCookies`, `csParam`, `csBlock`, `csClearLocalStorage`, and `csAllFrames`. The default `/{URL}`, `/browser/`, `/api/`, and `/raw/` routes consume these fields through Kitesurf: they run the vendored BPC core/local content scripts and supply a bounded `chrome.*` compatibility shim. `/fast/` and `/fast/api/` are explicit server-side routes and do not run browser scripts; `/fast/raw/` is the unmodified FastHTTP diagnostic route. `block_host_perm_add` remains Chrome host-permission metadata; `cs_dompurify` is implicit because extracted HTML is always sanitized; `upd_version` and `nofix` are metadata.

The Kitesurf routes fail closed with HTTP `501` and error `browser_compatibility_gap` for the current audited 54-domain compatibility-gap union. `/fast/` and `/fast/api/` use the same gate; `/fast/raw/` bypasses rule processing and remains available for diagnostics.

Unknown Ladder overlay fields are ignored. Unknown upstream BPC fields and `cs_code` operations reject a ruleset update so new upstream rule types cannot be silently dropped.

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
- Ruleset mode key: `bpc:ruleset_bpc:mode` (`bpc+ladder-v4`).
- Scheduled updates fetch BPC manifest data and merge Ladder YAML overlays before writing KV.
- If no rules are available and bootstrap update fails, request handling returns `503 Ruleset unavailable`.
- Scheduled updates populate KV from `MANIFEST_URL`.
