<p align="center">
  <img src="public/ladder.svg" width="100" alt="Bypasser logo">
</p>

<h1 align="center">Bypasser</h1>

Bypasser is a Cloudflare Worker proxy that applies BPC-derived rules with Ladder YAML overlays at the edge.

## Runtime Model

- Pure JavaScript Worker runtime (no Go, no WebAssembly).
- Rules are loaded from KV at runtime (`CONFIG_KV`).
- Scheduled updates fetch `manifest.json`, map `sites_aggregated.js`, merge in Ladder YAML overlays, and store the merged rules in KV.
- Local builds use `BPC_MANIFEST_URL`, `RULESET_URL`, or the `RULESET_URL` value in `wrangler.toml`; set `BPC_SOURCE=local` or `BPC_SOURCE_FILE=/path/to/sites_aggregated.json` for offline builds.

## Deploy

### Worker Identity

- Worker name: `bypasser`
- Custom domain: `bypasser.andrewe.dev`

### CLI

```bash
git clone https://github.com/andesco/ladderflare.git
cd ladderflare
npm install
npm run build
wrangler deploy
```

## Configuration

Set these in `wrangler.toml` or Cloudflare dashboard:

- `CONFIG_KV` (required): KV namespace binding for ruleset state
- `RULESET_URL` (required for updates): manifest URL (for example `https://bypass.andrewe.dev/manifest.json`)
- `EXPOSE_RULESET` (`true`/`false`)
- `USERPASS` (`username:password`)
- `USER_AGENT`
- `X_FORWARDED_FOR`
- `ALLOWED_DOMAINS`
- `ALLOWED_DOMAINS_RULESET` (`true`/`false`)
- `DISABLE_FORM` (`true`/`false`)

## Endpoints

- `GET /{URL}`: proxied response with rule processing
- `GET /raw/{URL}`: raw proxied response
- `GET /api/{URL}`: JSON payload with response body + request/response headers
- `GET /ruleset`: current in-memory ruleset JSON (`EXPOSE_RULESET=true`)
- `GET /status`: loaded ruleset version, update status, and source manifest details
- `GET /test`: redirect to a random test URL from active rules

Deprecated endpoints:

- `GET /yaml/{URL}` returns `410 Gone`
- `GET /json/{URL}` returns `410 Gone`

## Request Processing

1. Resolve target URL from request path.
2. Match best rule by host specificity (exact host, then longest suffix) + optional `paths` and `pathExclusions`.
3. Build fetch instructions (`urlMods`, headers, `randomIP`, `extraHeaders`, `googleCache`).
4. Fetch origin content.
5. For HTML responses, apply transforms in order:
   - `regexRules`
   - script/style blocking (`blockScripts`, `blockScriptsGeneral`, global patterns)
   - inline script blocking (`blockJsInline`)
   - `contentExtraction`
   - archive fallback (`archiveFallback`)
   - `csCode` operations
   - `ampUnhide`
   - proxy URL rewrites (`src`/`href`/`action`, CSS `url()`)
   - `injections`
   - external article links (`externalLink`)
   - `clearStorage`

## Build Commands

```bash
npm run build:rules
npm run build
npm run deploy
npm run deploy:local
npm run dev
npm run dev:local
```

## Notes

- Runtime rules are KV-backed; if KV is empty and bootstrap update fails, proxy routes return `503 Ruleset unavailable`.
- Ladder YAML is not exposed as `/yaml/*`; it is compiled into overlay JSON and merged into runtime rules.
- Static UI assets continue to be served from `public/`.

Bypasser is licensed under the MIT License.
