# Ruleset Comparison Routes - Verification

## Implementation Complete

Three independent rulesets are now available via route prefixes:

### Route Mapping

| Route | Ruleset | Source | Description |
|-------|---------|--------|-------------|
| `/{URL}` | Layered (default) | BPC + Ladder | BPC rule selected + Ladder rule selected, then merged at runtime to avoid subdomain shadowing |
| `/yaml/{URL}` | Ladder-only | `ruleset-ladder.yaml` | Only Ladder rules |
| `/json/{URL}` | BPC-only | `ruleset-bpc-embedded.json` | Only BPC rules (no Ladder merge) |

## Build Status

```
✓ scripts/build-rules.js generates JSON embed rulesets
  - ruleset-embedded.json: 398 rules covering ~1490 domains (merged output; used by /ruleset + /test)
  - ruleset-bpc-embedded.json: 380 rules covering ~1460 domains (BPC-only)
  - ruleset-ladder-embedded.json: 16 rules covering 33 domains (Ladder-only)
  - ruleset-ladder.yaml: 16 rules covering 33 domains (Ladder)

✓ main.go embeds all three rulesets
  - parsedRules (merged output; used by /ruleset + /test)
  - parsedLadderRules (/yaml/)
  - parsedBPCRules (/json/)

✓ Routing detects /yaml/ and /json/ prefixes
  - Strips prefix before URL extraction
  - Passes rulesetMode through pipeline

✓ Default route now uses runtime layering (fixes shadowed subdomains)
  - Example: BPC has `nytimes.com`, Ladder has `www.nytimes.com`
  - Old behavior: first match wins, so BPC rule could shadow Ladder
  - New behavior: match in BPC + match in Ladder, then overlay

✓ WASM compiled successfully
  - public/main.wasm: 6.2M (includes all 3 rulesets)
```

## Test Examples

### Example 1: BPC-only domain (lepoint.fr)

**Not in Ladder ruleset, only in BPC:**

```bash
# Merged (BPC rules applied)
curl "http://localhost:8787/https://lepoint.fr/"

# Ladder-only (NO rules, not in Ladder)
curl "http://localhost:8787/yaml/https://lepoint.fr/"

# BPC-only (BPC rules applied)
curl "http://localhost:8787/json/https://lepoint.fr/"
```

Expected: Default and /json/ should apply BPC blockScripts, /yaml/ should have no rules.

### Example 2: Ladder domain (theathletic.com)

**Has Ladder injections:**

```bash
# Merged (Ladder injections + any BPC rules)
curl "http://localhost:8787/https://theathletic.com/test"

# Ladder-only (Ladder injections only)
curl "http://localhost:8787/yaml/https://theathletic.com/test"

# BPC-only (any BPC rules, no Ladder injections)
curl "http://localhost:8787/json/https://theathletic.com/test"
```

Expected: Default and /yaml/ should apply Ladder injections, /json/ should not.

### Example 3: Testing with /test endpoint

```bash
# Random URL from merged ruleset
curl "http://localhost:8787/test"
```

## Verification Steps

1. ✅ Build rulesets: `npm run build:rules`
   - Generated embedded JSON rulesets

2. ✅ Build WASM: `npm run build:wasm`
   - Compiled with all 3 rulesets embedded

3. ✅ Dev server: `npx wrangler dev`
   - All routes return 200 OK

4. ⏳ Route testing: Compare behavior across routes
   - Check BPC-only domains apply rules on default and /json/
   - Check Ladder-only domains apply rules on default and /yaml/
   - Verify /yaml/ excludes BPC rules
   - Verify /json/ excludes Ladder rules

## Files Modified

- `.gitignore`: Added embedded JSON rulesets
- `scripts/build-rules.js`: Generate BPC-only output
- `main.go`: Embed 3 rulesets, prefix routing, parameterized rule lookup
- `index.js`: Pass rulesetMode to WASM handlers
- `public/main.wasm`: Rebuilt with new logic

## Next Steps

For deployment:

```bash
npm run build          # Build all (rules + WASM)
npm run deploy         # Deploy to Cloudflare
```

Then test in production:
- `https://your-domain.com/https://lepoint.fr/`
- `https://your-domain.com/yaml/https://lepoint.fr/`
- `https://your-domain.com/json/https://lepoint.fr/`
