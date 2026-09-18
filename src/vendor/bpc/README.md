# Vendored BPC content scripts

This directory contains the Bypass Paywalls Clean content-script snapshot used
by Ladderflare's optional Kitesurf browser route. It is distributed under the
upstream MIT license in [`LICENSE.txt`](./LICENSE.txt).

The snapshot includes the shared `contentScript.js`, the language-specific
`cs_local/contentScript_*.js` files, and BPC's Chromium DOMPurify placeholder.
Run `npm run build:bpc-scripts` after refreshing these files to regenerate the
Worker source module.
