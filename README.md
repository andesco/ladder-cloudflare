<p align="center">
  <img src="public/ladder.svg" width="100" alt="Ladderflare logo">
</p>

<h1 align="center">Ladderflare</h1>

Ladderflare is a Cloudflare Worker proxy that applies BPC-derived rules with Ladder YAML overlays at the edge.

## Runtime Model

- Pure JavaScript Worker runtime (no Go, no WebAssembly).
- Rules are loaded from KV at runtime (`CONFIG_KV`).
- Scheduled updates fetch `manifest.json`, map `sites_aggregated.js`, merge in Ladder YAML overlays, and store the merged rules in KV.
- Local builds use `MANIFEST_URL` or the `MANIFEST_URL` value in `wrangler.jsonc`; set `SOURCE_FILE=/path/to/sites_aggregated.json` for offline builds.

## Deploy

### Worker Identity

- Worker name: `ladderflare`
- Custom domains: `ladderflare.example.com`, `ladder.example.com`

### CLI

```bash
git clone https://github.com/andesco/ladderflare.git
cd ladderflare
npm install
npm run build
wrangler deploy
```

## Configuration

Set these in `wrangler.jsonc` or Cloudflare dashboard:

- `CONFIG_KV` (required): KV namespace binding for ruleset state
- `BROWSER` (required for the default route): Browser Run binding used by the Kitesurf CDP renderer
- `MANIFEST_URL` (required for updates): manifest URL (for example `https://bypass.example.com/manifest.json`)
- `EXPOSE_RULESET` (`true`/`false`)
- `BASIC_AUTH` (`username:password`)
- `USER_AGENT`
- `X_FORWARDED_FOR`
- `ALLOWED_DOMAINS`
- `ALLOWED_DOMAINS_RULESET` (`true`/`false`)
- `DISABLE_FORM` (`true`/`false`)

## Endpoints

- `GET /`: input form for BPC + Ladder browser rendering
- `GET /{URL}`: BPC + Ladder Kitesurf-rendered response (the default route)
- `GET /fast/{URL}`: explicit FastHTTP response with server-side rule processing
- `GET /raw/{URL}`: Kitesurf-rendered response using the raw route format
- `GET /api/{URL}`: JSON payload from the Kitesurf path with rendered body + request/response headers
- `GET /fast/raw/{URL}`: explicit FastHTTP unmodified diagnostic response
- `GET /fast/api/{URL}`: JSON payload from the explicit FastHTTP path with response body + request/response headers
- `GET /browser/{URL}`: explicit alias for the default Kitesurf CDP-rendered response
- `GET /ruleset`: current in-memory ruleset JSON (`EXPOSE_RULESET=true`)
- `GET /status`: loaded ruleset version, Cloudflare deploy identity, update status, and source manifest details
- `GET /health`: liveness (`200` / `ok`); does not load the ruleset
- `GET /test`: redirect to a random test URL from active rules

Every Worker response includes `X-Ladderflare-Version` (Cloudflare version id) when version metadata is bound. Optional `X-Ladderflare-Git` is set when `GIT_SHA` is provided at deploy.

Deprecated endpoints:

- `GET /yaml/{URL}` returns `410 Gone`
- `GET /json/{URL}` returns `410 Gone`

## Request Processing

1. Resolve target URL from request path.
2. Match best rule by host specificity (exact host, then longest suffix) + optional `paths` and `pathExclusions`.
3. Build fetch instructions (`urlMods`, headers, `randomIP`, `extraHeaders`, `googleCache`).
4. Fetch origin content.
5. Follow a configured, paywall-gated AMP page and fetch configured JSON article endpoints when needed.
6. For HTML responses, apply transforms in order:
   - `regexRules`
   - script/style blocking (`blockScripts`, `blockScriptsGeneral`, global patterns)
   - inline script blocking (`blockJsInline`)
   - `contentExtraction`
   - archive fallback (`archiveFallback`)
   - `csCode` operations
   - `ampUnhide`
   - proxy URL rewrites (`src`/`href`/`action`, including iframes, CSS `url()`)
   - `injections`
   - external article links (`externalLink`)

## BPC Compatibility Boundary

The explicit `/fast/` route and `/fast/api/` route map all generic server-compatible fields in the upstream aggregated ruleset, including request headers, URL/request blocking, selective cookie removal, `cs_code`, AMP redirect/unhide, all four JSON extraction forms, archive fallback, and external links. `/fast/raw/` is the unmodified FastHTTP diagnostic route. The default route, `/browser/`, `/api/`, and `/raw/` use Browser Run Kitesurf through CDP to execute the selected rule's early injections, run the matching vendored BPC `contentScript.js` + language-specific `cs_local` file, bridge BPC external-fetch messages through the Worker, and apply mapped DOM operations after navigation.

Kitesurf routes are fail-closed for the current compatibility audit. They return `501 browser_compatibility_gap` for the 54-domain union covering refresh/reload semantics, language-dispatch mismatches, cookie-domain clearing, and main-frame-only serialization. `/fast/` and `/fast/api/` are subject to the same gate; `/fast/raw/` remains an unmodified diagnostic fetch.

The browser route now preserves and consumes these extension fields:

- `cs_param`: passed to the selected BPC `cs_local` script instead of being mistaken for origin request headers.
- `cs_block`: prevents the local script from running while retaining generic BPC operations.
- `cs_clear_lclstrg`: clears only the disposable Kitesurf page's local/session storage.
- `cs_all_frames`: document-start CDP injection reaches frames in the browser target; post-navigation DOM serialization is still main-frame HTML.
- `allow_cookies`: the isolated browser session preserves its own cookies; it never exposes the caller's browser cookie jar.

The following Chrome-extension behavior remains intentionally bounded:

- `block_host_perm_add`: Chrome host-permission metadata; Workers do not use browser permissions.
- `upd_version` and `nofix`: upstream metadata, not executable rules.
- Extension lifecycle APIs are shimmed only for the operations used by BPC content scripts: runtime messaging, storage, cookies, tabs, scripting, permissions, and request-rule events. `getExtFetch`/`getExtSrc` are bridged through a Worker-side fetch when Puppeteer exposes the binding; unsupported operations become observable no-ops in `window.__ladderflareBpc`.
- The vendored `cs_local` snapshot does not make Kitesurf a native extension host. Updates to BPC's extension source require refreshing `src/vendor/bpc` and regenerating the bundle.

`cs_dompurify` is not mapped as a switch because extracted HTML is always sanitized by the Worker.

## Build Commands

```bash
npm run build:rules
npm run build:bpc-scripts
npm run build
npm run deploy
npm run deploy:local
npm run dev
npm run dev:local
```

## Documentation

- [BPC/Kitesurf browser-first implementation](documentation/bpc-kitesurf-browser-first-implementation.md)
- [BPC/Kitesurf compatibility-gap audit](documentation/bpc-kitesurf-compatibility-gap-audit.md)

## Notes

- Runtime rules are KV-backed; if KV is empty and bootstrap update fails, proxy routes return `503 Ruleset unavailable`.
- Ladder YAML is not exposed as `/yaml/*`; it is compiled into overlay JSON and merged into runtime rules.
- Static UI assets continue to be served from `public/`.

Ladderflare is licensed under the MIT License.
