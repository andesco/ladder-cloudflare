<p align="center">
    <img src="public/ladder.svg" width="100px">
</p>

<h1 align="center">Ladderflare</h1>

[Ladderflare][ladderflare] is a web proxy designed to bypass web restrictions through sophisticated header rewrites, content modification, and rules-based processing. It was initially built as a serverless implementation of [Ladder][ladder].

1. **rule processing**: \
applies domain-specific bypass rules: UA/referer, cookie controls, regex, AMP redirects, JSON-LD extraction, and archive fallback
2. **ruleset refresh**: \
pulls `manifest.json`, prefers `sites_aggregated.json` (YAML fallback), and refreshes on cron
3. **WebAssembly**: \
compiles Go proxy logic into WebAssembly (WASM) for browser/edge execution (embedded ruleset snapshot)
4. **JavaScript bridge**: `index.js` provides fetch() integration and manages communication between WASM and Cloudflare Workers platform
5. **serverless edge deployment**:\
deployed as a Cloudflare Worker with support for the user-friendly [Deploy to Cloudflare](https://deploy.workers.cloudflare.com/?url=https://github.com/andesco/ladderflare)

The result is a **fast bypass proxy** that successfully circumvents many web restrictions.

## Deploy to Cloudflare

### Cloudflare Dashboard

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/andesco/ladderflare)

<nobr>Workers & Pages</nobr> ⇢ Create an application ⇢ [Clone a repository](https://dash.cloudflare.com/?to=/:account/workers-and-pages/create/deploy-to-workers): \
   ```
   http://github.com/andesco/ladderflare
   ```

### Wrangler CLI
   
```bash
git clone https://github.com/andesco/ladderflare.git
cd ladderflare
npm run build
wrangler deploy
```
   
## Usage

Visit your worker and enter a URL: \
`https://ladder.{subdomain}.workers.dev`

Directly appended a URL to the end of Ladderflare’s hostname: \
`https://ladder.{subdomain}.workers.dev/https://example.com`

Create a [bookmarklet](https://wikipedia.org/wiki/Bookmarklet) with the following URL: \
`javascript:window.location.href="https://ladder.{subdomain}.workers.dev/"+location.href`

Add a shortcut to the share sheet on macOS and iOS: \
[`andesco/ladder-shortcut`][ladder-shortcut]


### Required Environment Variable: `RULESET_URL`

- **`RULESET_URL`**
    - remote ruleset URL pointing to manifest.json: \
      <b>`https://`&zwj;`[…]`&zwj;`/manifest.json`</b>

### Optional Secrets and Environment Variables

- `USERNAME` & `PASSWORD`
   - enable basic https authentication: \
      `wrangler secret put PASSWORD` \
      `wrangler secret put USERNAME`
      
- `DISABLE_FORM` - Disable web form interface
   - default: `false` · form enabled

- `USER_AGENT`
   - custom user agent for proxied requests
   - default: `Mozilla/5.0`&zwj;`[…]`&zwj;`Googlebot`&zwj;`[…]`

- `X_FORWARDED_FOR`
   - custom IP for `X-Forwarded-For` header
   - default: `66.249.66.1`

- `ALLOWED_DOMAINS`
   - limits domains to those listed in ruleset
   - default: `false` · any domain allowed


### KV Namespaces · <small>`optional`</small>

Set these in `wrangler.toml` under `[[kv_namespaces]]`:
  
`ANALYTICS_KV`
- usage analytics and rate limiting
- create: `wrangler kv:namespace create "analytics"`
  
`CACHE_KV`
- content caching for faster responses
- create: `wrangler kv:namespace create "cache"`

> [!IMPORTANT]
> Ladderflare does not log fetched URLs. Consider enabling Cloudflare Analytics to log usage.


## Development

### Build Commands

```bash
npm run build:wasm    # compile WebAssembly binary with embedded sites_aggregated.yaml
npm run build
npm run dev:local     # deploy locally using wrangler.local.toml
npm run deploy:local  # deploy using wrangler.local.toml
npm run deploy
```

### WebAssembly Implementation

- **minimal dependencies**: small Go binary with yaml parsing
- **JavaScript interoperability**: `syscall/js` bridge for fetch() and DOM manipulation
- **edge optimization**: Cloudflare Workers-specific optimizations for performance

### WebAssembly Build Process

1. `sites_aggregated.yaml` stored in this repo
2. `GOOS=js GOARCH=wasm go build -ldflags="-s -w" -tags=wasm`
3. `go:embed` embedds rules directly into WASM binary

### Interface Updates

- `form.html` has been renamed to `index.html`
   - add Apple Shortcut
   - save bookmarklet
- `styles.css` is served without dependencies
- `/test` endpoint

### Endpoints

- **TEST**: `ladder.{subdomain}.workers.dev/test`
- **HEALTH**: `ladder.{subdomain}.workers.dev/health`
- **API**: `/api/stats`, `/api/system`, `/api/metrics`, `/api/rules/*`

&zwnj;

---

Ladderflare is licensed under the [MIT License](LICENSE).

[ladder]: https://github.com/everywall/ladder
[ladder-rules]: https://github.com/everywall/ladder-rules
[ladder-shortcut]: https://github.com/andesco/ladder-shortcut
[ladderflare]: https://github.com/andesco/ladder-cloudflare
