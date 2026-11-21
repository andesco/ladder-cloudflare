# Kitesurf browser-first implementation

Snapshot: 2026-08-06  
Repository: [`ladder-cloudflare`](../)  
Production version: `3115be89-7da1-4b03-8d96-748e0ac5f1d8`  
Production URL: <https://ladderflare.example.workers.dev>

## Result

Ladderflare now routes ordinary target requests to Kitesurf by default. FastHTTP remains available only through an explicit route, and the current browser-compatibility audit is fail-closed.

| Route | Behavior |
| --- | --- |
| `/{URL}` | Upstream + Ladder Kitesurf browser rendering |
| `/browser/{URL}` | Explicit alias for the browser route |
| `/fast/{URL}` | Explicit FastHTTP/server-side rules route |
| `/api/{URL}` | Kitesurf inspection payload with rendered body + browser request/response headers |
| `/raw/{URL}` | Kitesurf-rendered response using the raw route format |
| `/fast/api/{URL}` | Explicit FastHTTP inspection payload |
| `/fast/raw/{URL}` | Explicit FastHTTP unmodified diagnostic fetch |

The root form has one mode: Upstream + Ladder browser rendering. The FastHTTP route is intentionally not presented as a normal UI option.

## Compatibility gate

The gate is implemented in [`src/runtime/browser-gaps.js`](../src/runtime/browser-gaps.js) and enforced before dispatch in [`index.js`](../index.js). It returns HTTP `501` with error `browser_compatibility_gap` and an `X-Ladderflare-Browser-Gap` header.

The current live merged ruleset has 1,399 unique domains. The four audit categories contain 42, 10, 3, and 2 domains; after overlap removal their union is 54 domains, or 3.86% of the domain denominator. The gate therefore leaves 1,345 domains, or 96.14%, outside the current compatibility block.

| Gate reason | Domains in category | Meaning |
| --- | ---: | --- |
| `refresh` | 42 | Upstream can request a second navigation, but the adapter does not restart Kitesurf yet |
| `language-dispatch` | 10 | The selected local upstream language script differs from the extension dispatcher |
| `cookie-clear` | 3 | `clear_cookies_domain` is not implemented in the browser shim |
| `all-frames` | 2 | The browser can mutate frames, but the Worker serializes the main frame only |

The category counts are not additive because `lastampa.it`, `historytoday.com`, and `newscientist.com` overlap categories. Kitesurf routes, `/fast/`, and `/fast/api/` use the same gate so callers cannot accidentally bypass the compatibility policy; `/fast/raw/` remains available for diagnostics.

## 42-domain comparison

The comparison was run against the pre-gate production `/browser/` route so it measured the implementation rather than the new `501` response. Regular fetch means a direct origin fetch with no Ladderflare rules. Kitesurf means the production browser route with the active upstream + Ladder rules.

| Measurement | Result |
| --- | ---: |
| Refresh candidates tested | 42 / 42 |
| Direct regular fetches returning 2xx | 36 / 42 (85.7%) |
| Kitesurf responses returning 2xx | 38 / 42 (90.5%) |
| Records flagged with an article hash or paywall-signal change | 19 / 42 (45.2%) |
| Kitesurf errors/timeouts | 4 / 42 (9.5%) |

The four Kitesurf failures were two HTTP 500 responses (`challenges.fr`, `lesechos.fr`) and two timeouts (`historia.fr`, `thewest.com.au`). Six domains that did not return a successful direct response did return a Kitesurf 2xx response (`dvhn.nl`, `ipolitics.ca`, `lc.nl`, `nationalreview.com`, `newscientist.com`, and `vn.nl`).

The 19 changed records include four records whose Kitesurf request failed and therefore had an empty browser body to compare. Excluding those errors, 15 successful browser responses showed a detected article/paywall DOM change. A changed DOM is evidence that the rules altered the response; it is not proof that every conditional paywall path was fully removed.

The harness is [`scripts/compare-refresh-candidates.mjs`](../scripts/compare-refresh-candidates.mjs):

```bash
npm run compare:refresh-candidates
```

It reads the 42-domain list from the audit, prefers a ruleset test URL, otherwise discovers a same-domain homepage article link, and records status, title, body/article hashes, text lengths, and paywall selectors for both sides.

## Live smoke tests

- `/` returns the updated form without the old rendering-mode selector.
- `/{URL}` returned HTTP 200 and the American Banker title through Kitesurf.
- `/api/{URL}` returned a Kitesurf JSON payload containing the rendered article.
- `/raw/{URL}` returned the Kitesurf-rendered HTML response.
- `/fast/{URL}` returned HTTP 200 for the same article through FastHTTP.
- `/fast/api/{URL}` returned the FastHTTP JSON payload.
- `/fast/raw/{URL}` returned the FastHTTP unmodified HTML response.
- `/https://www.afr.com/` returned HTTP 501 with `X-Ladderflare-Browser-Gap: refresh`.
- `/api/https://www.afr.com/` and `/raw/https://www.afr.com/` returned the same Kitesurf compatibility gate.
- `/fast/api/https://www.afr.com/` returned the same gate; `/fast/raw/https://www.afr.com/` bypassed the gate as the diagnostic route.
- `/fast/https://www.afr.com/` returned the same HTTP 501 gate response.
- `/https://www.lastampa.it/` returned both `refresh` and `cookie-clear` reasons.

Local verification passed: 27 tests, JavaScript syntax checks, `npm run build`, and Wrangler deploy dry-run.
