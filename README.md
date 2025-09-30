<p align="center">
    <img src="public/logo.svg" width="100px">
</p>

<h1 align="center">Ladderflare</h1>

[Ladder][ladder] is a HTTP web proxy designed to bypass web restrictions through sophisticated header spoofing, content modification, and [rule-based processing][ladder-rules].

[Ladderflare][ladderflare] is a complete implementation of Ladder as a serverless application:

1. **WebAssembly**: \
compiles Go proxy logic from [`ladder`][ladder] into WebAssembly (WASM) for browser/edge execution
2. **rule processing**: \
embeds domain-specific bypass rules from [`ladder-rules`][ladder-rules] at build-time
3. **JavaScript bridge**: `index.js` provides fetch() integration and manages  communication between WASM and Cloudflare Workers platform
4. **updated interface**: \
`index.html` and `styles.css` serve an updated web interface
5. **edge deployment**:\
the complete package is deployed to Cloudflare Workers with support for the user-friendly [Deploy to Cloudflare](https://deploy.workers.cloudflare.com/?url=https://github.com/andesco/ladderflare) option

The result is a **fast bypass proxy** that successfully circumvents many web restrictions through sophisticated rule-based processing.


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
npm run build:rules   # download latest ruleset from ladder-rules repository
npm run build:wasm    # compile WebAssembly binary
npm run build
npm run dev:local     # deploy locally using wrangler.local.toml
npm run deploy:local  # deploy using wrangler.local.toml
npm run deploy
```

### WebAssembly Implementation

- **no dependencies**: Go stdlib compilation for minimal WASM binary size
- **custom YAML parser**: simplified parser avoids heavy dependencies in WASM
- **JavaScript interoperability**: `syscall/js` bridge for fetch() and DOM manipulation
- **edge optimization**: Cloudflare Workers-specific optimizations for performance

### WebAssembly Build Process

1. `ruleset.yaml` downloaded from [`everywall/ladder-rules`][ladder-rules]
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

- **API**: `curl -X GET "ladder.{subdomain}.workers.dev/api/{URL}"`

- **RAW:** `ladder.{subdomain}.workers.dev/raw/{URL}`

&zwnj;

---

Ladderflare is licensed under the [MIT License](LICENSE).

[ladder]: https://github.com/everywall/ladder
[ladder-rules]: https://github.com/everywall/ladder-rules
[ladder-shortcut]: https://github.com/andesco/ladder-shortcut
[ladderflare]: https://github.com/andesco/ladder-cloudflare