<p align="center">
  <img src="public/ladder.svg" width="100" alt="Ladderflare logo">
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
the complete package is deployed to Cloudflare Workers with support for the user-friendly [Deploy to Cloudflare](https://deploy.workers.cloudflare.com/?url=https://github.com/andesco/ladderflare) option

The result is a **fast bypass proxy** that successfully circumvents many web restrictions through sophisticated rule-based processing.

## Deploy to Cloudflare

### Cloudflare Dashboard

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/andesco/ladderflare)

<nobr>Workers & Pages</nobr> ⇢ Create an application ⇢ [Clone a repository](https://dash.cloudflare.com/?to=/:account/workers-and-pages/create/deploy-to-workers): \
   `http://github.com/andesco/ladderflare`

### Wrangler CLI
   
```bash
git clone https://github.com/andesco/ladderflare.git
cd ladderflare
npm run build
wrangler deploy
```

> [!IMPORTANT]
> To secure your worker from public acces use either Cloudflare Access or set `USERPASS`.
   
## Usage

Visit your worker and enter a URL:
`https://ladder.{subdomain}.workers.dev`

Directly append a URL to the end of Ladderflare’s hostname:
`https://ladder.{subdomain}.workers.dev/https://example.com`

Create a [bookmarklet](https://wikipedia.org/wiki/Bookmarklet) with the following URL:
`javascript:window.location.href="https://ladder.{subdomain}.workers.dev/"+location.href`

Add a shortcut to the share sheet on macOS and iOS:
[`andesco/ladder-shortcut`][ladder-shortcut]

### Limitations

* Some sites do not expose content to search engines, which means the proxy cannot access the content.
* Certain sites may display missing images or encounter formatting issues due to JavaScript- or CSS-driven rendering.


### Configuration

The worker is configured using environment variables. Set these in `wrangler.toml` file or in the Cloudflare Dashboard:

- **`USERPASS`** `{username}:{password}`
- **`DISABLE_FORM`** `false`
- **`USER_AGENT`** `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`
- **`X_FORWARDED_FOR`** `66.249.66.1`
- **`EXPOSE_RULESET`** `true`
- **`ALLOWED_DOMAINS`** `{domain},{domain}`
- **`ALLOWED_DOMAINS_RULESET`** `false`

Ladderflare does not support these legacy variables:

- `FORM_PATH`
- `LOG_URLS`
- `PORT`
- `RULESET`

> [!tip]
> Ladderflare does not log fetched URLs. Consider enabling Cloudflare Analytics to log usage.

## Development

### Request and Ruleset Processing

The Worker is a thin wrapper around the Ladder WASM runtime. The ruleset drives nearly all behavior.

1. **parse incoming request**
   - worker uses form input or extracts target URL from the request path `/{URL}`
2. **select ruleset mode**
   - default merged ruleset: `/{URL}`
   - BPC-only: `/json/{URL}`
   - Ladder-only: `/yaml/{URL}`
3. **match rules**
   - sing ruleset: WASM runtime finds first matching rule by `host` and optional `paths`/`pathExclusions`
   - merged ruleset: WASM runtime finds first matching rule in each ruleset independently, then overlays them into an effective rule
4. **compute fetch instructions**
   - apply `urlMods` / `googleCache` to produce the final fetch URL.
   - muild request headers: `User-Agent`, `Referer`, `X-Forwarded-For`, `Cookie`, optional `extraHeaders`
   - optionally generate a random `X-Forwarded-For` when `randomIP` is set
5. **fetch origin content**
   - worker performs `fetch()` with the computed URL + headers
6. **process response**
   - non-HTML assets: worker returns payload without DOM processing to avoid corrupting response
   - HTML: WASM runtime applies (in order):
     - `regexRules`
     - `blockScripts` / `blockScriptsGeneral`
     - `blockJsInline`
     - `csCode` DOM operations
     - `ampUnhide`
     - rewrite relative URLs to use proxy: `/https://host/...`
     - `injections`
     - `clearStorage`
   - if rule sets `headers.content-security-policy`, override response CSP header to match

> [!note]
> See [`RULESET-SPEC.md`](RULESET-SPEC.md) for the Ladderflare-specific embedded ruleset schema, reserved values, and runtime semantics.

### How It Works

```mermaid
sequenceDiagram
    participant Client
    participant Worker as Ladderflare Worker
    participant WASM as Ladder WASM
    participant Origin as Website

    Client->>Worker: GET /{url}
    Worker-->>WASM: apply RequestModifications (ruleset)
    WASM->>Origin: fetch URL
    Origin-->>WASM: 200 OK (HTML/assets)
    WASM-->>Worker: apply ResultModifications (ruleset)
    Worker-->>Client: 200 OK
```

### Build Commands

```bash
npm run build
npm run build:rules   # build embed rulesets using sites_aggregated.js + ruleset-ladder.yaml
npm run build:wasm    # compile WebAssembly binary
npm run deploy
npm run deploy:local  # deploy using wrangler.local.toml
npm run dev:local     # run locally using wrangler.local.toml
```

### WebAssembly Implementation

- **rule parsing**: embedded JSON rulesets are loaded via `encoding/json`
- **HTML manipulation**: `goquery` applies DOM-level modifications in WASM
- **JavaScript interoperability**: `syscall/js` bridges WASM to the Worker, while fetch runs in `index.js`
- **edge deployment**: tuned for Cloudflare Workers execution

### WebAssembly Build Process

1. Generate embed rulesets:
   - `ruleset-bpc-embedded.json` (BPC-only)
   - `ruleset-ladder-embedded.json` (Ladder-only, from `ruleset-ladder.yaml`)
   - `ruleset-embedded.json` (merged output for `/ruleset` + `/test`)
2. `GOOS=js GOARCH=wasm go build -ldflags="-s -w" -tags=wasm`
3. `go:embed` embedds rules directly into WASM binary

```mermaid
flowchart LR
    Rulesets[embedded JSON rulesets] --> Build[WASM build + embed]
    Ladder[ladder Go code] --> Build
    Build --> Worker[Cloudflare Worker bundle]
    Worker --> Deploy[Workers deployment]
```

### Endpoints

- **TEST**: `ladder.{subdomain}.workers.dev/test`

- **API**: `curl -X GET "ladder.{subdomain}.workers.dev/api/{URL}"`

- **RAW:** `ladder.{subdomain}.workers.dev/raw/{URL}`

- **RULESET**: `ladder.{subdomain}.workers.dev/ruleset`

---

Ladderflare is licensed under the [MIT License](LICENSE).

[ladder]: https://github.com/everywall/ladder
[ladder-rules]: https://github.com/everywall/ladder-rules
[ruleset-examples]: ruleset-embedded.json
[ladder-shortcut]: https://github.com/andesco/ladder-shortcut
[ladderflare]: https://github.com/andesco/ladder-cloudflare
