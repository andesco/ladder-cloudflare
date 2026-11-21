# Kitesurf compatibility-gap audit

Snapshot: 2026-08-06  
Implementation: [`ladder-cloudflare`](../)  
Upstream ruleset audited: [upstream manifest](https://bypass.example.com/manifest.json), version `4.4.1.6`

## Executive result

The upstream rule mapper does not currently drop any recognized executable upstream rule field. The original upstream core content script and all eight language-specific `cs_local` scripts are vendored and executed on the default `/{URL}` route and its explicit `/browser/{URL}` alias.

The largest remaining behavioral gap is reload semantics. The adapter records upstream `refreshCurrentTab` requests but does not restart the Kitesurf navigation. A static audit found 42 domain rules with an upstream code path that can request a refresh. That is a potential-impact count: it does not mean all 42 pages will fail, because the call is conditional on the page state.

The largest hard-unimplemented extension action is `clear_cookies_domain`, affecting only three active domain rules.

## Impact chart

The primary denominator is 1,362 normal domain entries in the current upstream source. The source also contains 18 global/option entries, giving 1,380 total manifest entries. Global entries are excluded from the primary percentage because they do not represent a target site.

| Gap | Explanation | Number of rules impacted |
| --- | --- | ---: |
| **Refresh/reload semantics** | `refreshCurrentTab()` and `refreshCurrentTab_bg()` are converted into an observable flag; they do not reload or restart the Kitesurf page. Rules that need a second navigation after a URL, cookie, or page-state change may not converge. | **42 / 1,362 — 3.08% potential impact** |
| **Wrong `cs_local` group dispatch** | The adapter's language selector does not match upstream's special French group lists. Ten domains currently receive the wrong language-specific content script. | **10 / 1,362 — 0.73%** |
| **Domain cookie clearing** | Upstream local scripts send `clear_cookies_domain` for `enotes.com`, `investors.com`, and `lastampa.it`. The runtime message shim records the request but does not clear the Kitesurf browser's cookies. | **3 / 1,362 — 0.22% hard gap** |
| **Main-frame-only serialization** | `cs_all_frames` is injected at document start, but the response is serialized with `document.documentElement.outerHTML`, so iframe-only mutations/content are not returned as a complete frame tree. | **2 / 1,362 — 0.15% partial gap** |
| **Caller browser profile unavailable** | `allow_cookies` appears on 1,251 rules. Kitesurf has an isolated browser session and cannot access the caller's existing Chrome profile, login state, or cookie jar. The upstream rule still runs; authenticated caller-session parity is what is unavailable. | **1,251 / 1,362 — 91.85% contextual limitation** |

For the normalized generated ruleset, the same categories correspond approximately to 21, 3, 4, and 2 grouped rules respectively. Group counts are less intuitive because identical upstream rules are grouped by domain and exceptions can produce more than one generated object for a single source domain.

## How the counts were derived

The audit used the current `sites_aggregated.json` from the upstream manifest and separated:

- 1,362 normal domain entries;
- 18 global or option entries;
- 617 generated upstream rule objects after grouping, of which 607 contain target domains.

The 42 refresh candidates are the union of:

1. 31 domains whose selected local script contains a direct `refreshCurrentTab` or `refreshCurrentTab_bg` branch;
2. four domains using the shared upstream `ld_json_next` path, which can request a refresh when the article slug does not match;
3. two Pugpig-style domains using the shared `restorePugpigPage()` helper;
4. five Quintype-style domains using the shared `getArticleQuintype()` helper.

The 42 candidates are:

```text
aftermath.site              asia.nikkei.com          barandbench.com
afr.com                     beobachter.ch             business-standard.com
challenges.fr               discovermagazine.com      dn.pt
doorbraak.be                dvhn.nl                   handelszeitung.ch
historia.fr                 historytoday.com           ilmanifesto.it
jgnt.co                     ipolitics.ca              jacobin.de
joc.com                     kinotico.es               lastampa.it
lc.nl                       lesechos.fr               lesoleil.com
linda.nl                    macrobusiness.com.au      nationalreview.com
newscientist.com            qpbriefing.com            sfstandard.com
sloanreview.mit.edu         stylist.co.uk             thejuggernaut.com
theleaflet.in               thenewsminute.com         thequint.com
thesaturdaypaper.com.au     thewest.com.au            tradewindsnews.com
tuttosport.com              vn.at                     vn.nl
```

## Known dispatch mismatch

Upstream's extension background dispatcher includes these special groups in the French selector:

- ESH Médias: `arcinfo.ch`, `lacote.ch`, `lenouvelliste.ch`;
- IPM: `dhnet.be`, `lalibre.be`, `lavenir.net`, `moustique.be`;
- Nice-Matin: `monacomatin.mc`, `nicematin.com`, `varmatin.com`.

The current adapter instead has a `FRENCH_GROUP_DOMAINS` list containing `actu.fr`, `charentelibre.fr`, `larepubliquedespyrenees.fr`, and `sudouest.fr`. The result is a language mismatch for the ten domains above:

| Domain group | Current adapter | Upstream dispatcher | Domains |
| --- | --- | --- | --- |
| ESH Médias | `de` | `fr` | `arcinfo.ch`, `lacote.ch`, `lenouvelliste.ch` |
| IPM | usually `nl` or `en` | `fr` | `dhnet.be`, `lalibre.be`, `lavenir.net`, `moustique.be` |
| Nice-Matin | usually `en` | `fr` | `monacomatin.mc`, `nicematin.com`, `varmatin.com` |

Relevant implementation: [`bpc-compat.js:74`](../src/runtime/bpc-compat.js:74) and [`bpc-compat.js:98`](../src/runtime/bpc-compat.js:98). The reference dispatcher is `background.js:1329`.

## Hard-unimplemented extension message

The compatibility shim handles these upstream runtime messages:

- `getExtFetch` — bridged to a Worker-side `fetch`;
- `getExtSrc` — bridged to a Worker-side `fetch` plus DOM extraction;
- `refreshCurrentTab` — recorded, but not executed as a reload.

It does not currently implement `clear_cookies_domain`. The source calls are in:

- [`contentScript_en.js:2170`](../src/vendor/bpc/cs_local/contentScript_en.js:2170) — `enotes.com`;
- [`contentScript_en.js:2685`](../src/vendor/bpc/cs_local/contentScript_en.js:2685) — `investors.com`;
- [`contentScript_it.js:250`](../src/vendor/bpc/cs_local/contentScript_it.js:250) — `lastampa.it`.

`huffingtonpost.it` contains the same Italian branch, but its upstream record has `cs_block`, so the local script is intentionally not run and it is not counted as an affected rule.

The message handling is visible at [`bpc-compat.js:266`](../src/runtime/bpc-compat.js:266). The browser-side `chrome.cookies` methods are also compatibility stubs at [`bpc-compat.js:327`](../src/runtime/bpc-compat.js:327), although the vendored upstream content scripts use the runtime message rather than calling those methods directly.

## What is already implemented

The current browser path preserves and consumes the main upstream browser fields:

| Upstream capability | Current coverage | Current source-entry count |
| --- | --- | ---: |
| `cs_code` | Mapped and executed by the original upstream core and by the Worker DOM pass. | 131 |
| `cs_param` | Passed to the selected `cs_local` script. | 14 |
| `cs_block` | Suppresses local-script execution while retaining generic upstream processing. | 4 |
| `cs_clear_lclstrg` | Clears the disposable page's local/session storage. | 6 |
| `cs_all_frames` | Document-start CDP injection is installed; output remains main-frame HTML. | 2 |
| `allow_cookies` | Rule-level cookie preservation is retained; the isolated browser session preserves cookies it acquires. | 1,251 |
| `block_regex` | Applied through CDP Fetch interception for script/style requests. | 754 |
| JSON/AMP/archive/external-link rules | Mapped into the upstream payload and/or Worker post-processing. | 92 combined extraction entries; 93 external-link entries |

The vendored script bundle includes `en`, `fr`, `de`, `es.pt`, `fi.se`, `it`, `nl`, and `pl`. External upstream fetches are intentionally bounded to 16 requests per browser run and 4 MiB per response; those are resource-safety limits, not unmapped rule fields. See [`browser-renderer.js:452`](../src/runtime/browser-renderer.js:452).

The following upstream fields are metadata or already covered by an equivalent Worker behavior:

- `block_host_perm_add`: extension host-permission metadata, not a page transformation;
- `cs_dompurify`: extracted HTML is always sanitized;
- `nofix` and `upd_version`: informational metadata;
- global `block_regex_general`: retained as global CDP request-blocking patterns.

## Recommended remediation order

1. Implement a bounded reload/restart state machine for `refreshCurrentTab` and `refreshCurrentTab_bg`, with a maximum number of navigations per request.
2. Replace the hard-coded French group list with the same group data used by upstream's dispatcher, or generate the language map during the upstream rules build.
3. Add a CDP cookie-clear operation for `clear_cookies_domain`, scoped to the disposable Kitesurf browser session.
4. Decide whether `/browser/` should return only the main frame by contract or expose a frame-aware result format for the two `cs_all_frames` rules.

## Verification and version note

The current implementation has passed the 27-test suite, rules build, Wrangler dry-run, and live Kitesurf checks. The generated rules artifact is built from upstream `4.4.1.6`. The source-entry percentages in this audit use the 1,362 normal upstream domain entries; deployment-level routing percentages use the 1,399 unique domains in the merged live ruleset and are reported in the browser-first implementation document.

The browser-first routing policy and 54-domain fail-closed gate were deployed on 2026-08-06. See [`kitesurf-browser-first-implementation.md`](kitesurf-browser-first-implementation.md) for the production version and live smoke-test results.

