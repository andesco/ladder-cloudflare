# Ruleset Comparison: BPC vs Ladder

## Sources

| File | Origin | Content |
|------|--------|---------|
| `ruleset-ladder.yaml` | Hand-crafted (Ladder) | 16 rules, 33 domains. Client-side injections, tests, regexRules, site-specific headers |
| BPC `sites_aggregated.json` | [bypass.andrewe.dev](https://bypass.andrewe.dev) | 1300+ sites. Server-side: headers, script blocking, DOM ops, AMP handling |
| `ruleset-embedded.json` | Auto-generated | Merged output for embedding (/ruleset + /test). BPC mapped to Ladderflare format, Ladder rules included |

## Why both are needed

BPC and Ladder rules operate at different layers and are complementary, not redundant.

### Server-side (BPC via GoQuery)

BPC's `cs_code` is translated to GoQuery operations that run at proxy time on the static HTML. This handles:

- Hiding/removing elements present in the initial HTML
- Removing classes and attributes
- Injecting `<style>` blocks
- Blocking `<script>` and `<link>` elements by URL pattern (`block_regex`)

Limitation: cannot affect content loaded dynamically by JavaScript after page load.

### Client-side (Ladder via `<script>` injections)

Ladder injections insert `<script>` tags that run in the browser with `DOMContentLoaded` or `scroll` listeners. This handles:

- Paywalls and overlays injected by JavaScript at runtime
- Scroll-lock restoration
- Encrypted content decryption (e.g. Toronto Star's `unscramble()` + DOMPurify)
- Dynamic ad/banner removal

### Feature comparison

| Feature | BPC (`cs_code`, `block_regex`) | Ladder (`injections`, `regexRules`) |
|---------|-------------------------------|-------------------------------------|
| DOM manipulation timing | Server-side (static HTML) | Client-side (`DOMContentLoaded`) |
| Dynamic JS-loaded content | Misses it | Catches it |
| Script blocking by URL | `block_regex` removes `<script>`/`<link>` elements | Not used for this |
| Content rewriting | Not supported | `regexRules` (e.g. stripping `window.temptation`) |
| CSP override | No | Sets `content-security-policy` header |
| Test assertions | None | Test URLs + DOM queries |
| Site-specific cookies | Basic (`headers_custom`) | Fine-grained (e.g. `nyt-gdpr=0; nyt-geo=DE`) |

## Merge strategy

Build pipeline (`scripts/build-rules.js`) merges with this precedence:

1. Map all BPC entries to Ladderflare rule format (headers, blocking, DOM ops)
2. For domains that exist in both sources, overlay Ladder properties:
   - Ladder `injections`, `tests`, `regexRules`, `paths` are preserved
   - BPC headers are kept unless the Ladder rule defines its own
3. Rules that exist only in Ladder (e.g. foxbusiness.com, foxnews.com) pass through unchanged

The result: BPC provides broad server-side coverage, Ladder rules add the client-side layer where needed.

## Shadowed subdomains (why runtime layering exists)

Ladder often targets `www.*` subdomains while BPC targets the parent domain. Because Ladderflare's domain matching treats `nytimes.com` as a match for `www.nytimes.com`, a naive "first match wins" scan can cause the BPC rule to shadow the Ladder rule.

To avoid losing Ladder's client-side injections on these sites, the default `/{URL}` route selects a match from BPC and Ladder independently and merges them into an effective rule at runtime (BPC as base; Ladder overlays client-side behavior).

## Sites requiring Ladder rules

| Site(s) | Why Ladder is needed |
|---------|---------------------|
| theathletic.com | JS-injected overlays, scroll-lock, dynamic `#free-apron-cta` |
| foxbusiness.com, foxnews.com | Not in BPC at all |
| Toronto Star network (7 domains) | Encrypted content unscrambling via `DOMPurify` |
| demorgen.be | `regexRules` to strip `window.temptation` + client-side paywall removal |
| ft.com | Proxy-specific stylesheet URL fixing + CSP override |
| nytimes.com, time.com | Specific cookies + client-side ad/banner removal |
| Conde Nast sites (9 domains) | Paywall banner removal not covered by BPC `cs_code` |
| apache.be | Client-side popup removal + scroll restoration |
| kw.be | Client-side paywall modal + scroll-lock removal |
| americanbanker.com | Path-scoped gate removal |
| tagesspiegel.de | AMP redirect via `urlMods` |
| medium.com | Custom referer + CSP override |
| DPG Media (2 domains) | Bot cookie headers |
