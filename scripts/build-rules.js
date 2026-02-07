#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const yaml = require('yaml');

const BPC_URL = 'https://bypass.andrewe.dev/sites_aggregated.json';
const LADDER_FILE = 'ruleset-ladder.yaml';
// Faster-to-parse rulesets for WASM embedding (JSON). We do not generate YAML copies.
const EMBED_OUTPUT_FILE = 'ruleset-embedded.json';
const EMBED_BPC_OUTPUT_FILE = 'ruleset-bpc-embedded.json';
const EMBED_LADDER_OUTPUT_FILE = 'ruleset-ladder-embedded.json';
const TEST_URLS_FILE = 'test-urls.json';

// Known user-agent strings
const UA_GOOGLEBOT = 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)';
const UA_BINGBOT = 'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)';
const UA_FACEBOOKBOT = 'facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)';

// Known referer URLs
const REFERER_GOOGLE = 'https://www.google.com/';
const REFERER_FACEBOOK = 'https://www.facebook.com/';
const REFERER_TWITTER = 'https://t.co/x?amp=1';

async function fetchBPC() {
  console.log('Fetching BPC data from:', BPC_URL);
  const resp = await fetch(BPC_URL);
  if (!resp.ok) throw new Error(`Failed to fetch BPC: ${resp.status}`);
  return resp.json();
}

function loadLadderRules() {
  const ladderPath = path.resolve(LADDER_FILE);
  if (!fs.existsSync(ladderPath)) {
    console.log('No ladder ruleset found at', ladderPath);
    return [];
  }
  const data = fs.readFileSync(ladderPath, 'utf-8');
  return yaml.parse(data) || [];
}

// Build a domain → Ladder rule index
function indexLadderRules(ladderRules) {
  const index = {};
  for (const rule of ladderRules) {
    const domains = [];
    if (rule.domain) domains.push(rule.domain);
    if (rule.domains) domains.push(...rule.domains);
    for (const d of domains) {
      index[d] = rule;
    }
  }
  return index;
}

// Map a single BPC entry to a Ladderflare rule object
function mapBPCEntry(entry) {
  const domain = entry.domain;
  if (!domain || domain.startsWith('###') || domain.startsWith('#')) return null;

  const rule = { domain };
  const headers = {};
  let hasHeaders = false;

  // #3: User-agent mapping
  if (entry.useragent) {
    switch (entry.useragent) {
      case 'googlebot':
        headers['user-agent'] = UA_GOOGLEBOT;
        headers['referer'] = REFERER_GOOGLE;
        headers['x-forwarded-for'] = '66.249.66.1';
        break;
      case 'bingbot':
        headers['user-agent'] = UA_BINGBOT;
        break;
      case 'facebookbot':
        headers['user-agent'] = UA_FACEBOOKBOT;
        break;
    }
    hasHeaders = true;
  }

  if (entry.useragent_custom) {
    headers['user-agent'] = entry.useragent_custom;
    hasHeaders = true;
  }

  // #4: Referer mapping
  if (entry.referer) {
    switch (entry.referer) {
      case 'google':
        headers['referer'] = REFERER_GOOGLE;
        break;
      case 'facebook':
        headers['referer'] = REFERER_FACEBOOK;
        break;
      case 'twitter':
        headers['referer'] = REFERER_TWITTER;
        break;
      default:
        headers['referer'] = entry.referer;
    }
    hasHeaders = true;
  }

  if (entry.referer_custom) {
    headers['referer'] = entry.referer_custom;
    hasHeaders = true;
  }

  // #6: Custom headers → cookie + extraHeaders
  if (entry.headers_custom) {
    const extraHeaders = {};
    for (const [key, val] of Object.entries(entry.headers_custom)) {
      if (key.toLowerCase() === 'cookie') {
        headers['cookie'] = val;
        hasHeaders = true;
      } else {
        extraHeaders[key] = String(val);
      }
    }
    if (Object.keys(extraHeaders).length > 0) {
      rule.extraHeaders = extraHeaders;
    }
  }

  if (hasHeaders) {
    rule.headers = headers;
  }

  // #5: Random IP
  if (entry.random_ip) {
    rule.randomIP = entry.random_ip === 'eu' ? 'eu' : 'true';
  }

  // #7: Block regex (script blocking)
  if (entry.block_regex) {
    const patterns = typeof entry.block_regex === 'string' ? [entry.block_regex] : entry.block_regex;
    rule.blockScripts = patterns.map(p => p.replace(/\{domain\}/g, domain.replace(/\./g, '\\.')));
  }

  // #8: Block regex general
  if (entry.block_regex_general) {
    const patterns = typeof entry.block_regex_general === 'string' ? [entry.block_regex_general] : entry.block_regex_general;
    rule.blockScriptsGeneral = patterns.map(p => p.replace(/\{domain\}/g, domain.replace(/\./g, '\\.')));
  }

  // #9: cs_code (content script operations)
  if (entry.cs_code) {
    let ops;
    if (typeof entry.cs_code === 'string') {
      try {
        ops = JSON.parse(entry.cs_code);
      } catch (e) {
        console.warn(`Failed to parse cs_code for ${domain}:`, e.message);
        ops = null;
      }
    } else if (Array.isArray(entry.cs_code)) {
      ops = entry.cs_code;
    }
    if (ops && Array.isArray(ops)) {
      rule.csCode = ops.map(op => {
        const mapped = {};
        if (op.cond) mapped.cond = op.cond;
        if (op.hide_elem) mapped.hide_elem = op.hide_elem;
        if (op.rm_elem) mapped.rm_elem = true;
        if (op.rm_class) mapped.rm_class = op.rm_class;
        if (op.rm_attrib) mapped.rm_attrib = op.rm_attrib;
        if (op.set_attrib) mapped.set_attrib = op.set_attrib;
        if (op.add_style) mapped.add_style = op.add_style;
        return mapped;
      });
    }
  }

  // #10: AMP unhide
  if (entry.amp_unhide) {
    rule.ampUnhide = true;
  }

  // #11: AMP redirect → urlMods query
  if (entry.amp_redirect) {
    rule.urlMods = { query: [{ key: 'amp', value: '1' }] };
  }

  // #12: Block inline JS
  if (entry.block_js_inline) {
    rule.blockJsInline = entry.block_js_inline;
  }

  // #13: Clear local/session storage
  if (entry.cs_clear_lclstrg) {
    rule.clearStorage = true;
  }

  return rule;
}

// Handle exception arrays: produce separate rules for excepted domains
function handleExceptions(entry, baseRule) {
  const exceptionRules = [];
  if (!entry.exception || !Array.isArray(entry.exception)) return exceptionRules;

  for (const exc of entry.exception) {
    // Exception domain can be string or array
    const excDomains = Array.isArray(exc.domain) ? exc.domain : [exc.domain];

    for (const excDomain of excDomains) {
      if (!excDomain) continue;

      // Map the exception entry as its own BPC entry
      const excEntry = { ...exc, domain: excDomain };
      const excRule = mapBPCEntry(excEntry);
      if (excRule) {
        exceptionRules.push(excRule);
      }
    }
  }

  return exceptionRules;
}

// Generate a stable key for grouping rules with identical properties
function ruleGroupKey(rule) {
  const copy = { ...rule };
  delete copy.domain;
  delete copy.domains;
  // Sort keys for stable comparison
  return JSON.stringify(copy, Object.keys(copy).sort());
}

// Re-group: domains with identical non-domain properties → single rule with domains: [...]
// Rules with injections, tests, or regexRules are NOT grouped (they're unique per domain)
function regroupRules(rules) {
  const groups = new Map();
  const ungroupable = [];

  for (const rule of rules) {
    // Don't group rules that have domain-specific content
    const hasUniqueContent = (rule.injections && rule.injections.length > 0) ||
                              (rule.tests && (Array.isArray(rule.tests) ? rule.tests.length > 0 : !!rule.tests)) ||
                              (rule.regexRules && rule.regexRules.length > 0) ||
                              (rule.paths && rule.paths.length > 0);

    if (hasUniqueContent) {
      ungroupable.push(rule);
      continue;
    }

    const key = ruleGroupKey(rule);
    // Collect all domains from both domain and domains fields
    const ruleDomains = [];
    if (rule.domain) ruleDomains.push(rule.domain);
    if (rule.domains) ruleDomains.push(...rule.domains);

    if (!groups.has(key)) {
      groups.set(key, { ...rule, _domains: [...ruleDomains] });
    } else {
      groups.get(key)._domains.push(...ruleDomains);
    }
  }

  const result = [];

  // Add grouped rules
  for (const group of groups.values()) {
    const domains = group._domains.filter(Boolean);
    delete group._domains;
    delete group.domain;
    delete group.domains;

    if (domains.length === 1) {
      group.domain = domains[0];
    } else {
      group.domains = domains.sort();
    }
    result.push(group);
  }

  // Add ungroupable rules as-is
  for (const rule of ungroupable) {
    result.push(rule);
  }

  return result;
}

// Merge BPC rule with Ladder rule: BPC provides headers/blocking, Ladder provides injections/tests/regexRules
function mergeRules(bpcRule, ladderRule) {
  const merged = { ...bpcRule };

  // Keep Ladder injections
  if (ladderRule.injections) {
    merged.injections = ladderRule.injections;
  }

  // Keep Ladder tests
  if (ladderRule.tests) {
    merged.tests = ladderRule.tests;
  }

  // Keep Ladder regexRules
  if (ladderRule.regexRules) {
    merged.regexRules = ladderRule.regexRules;
  }

  // Keep Ladder paths
  if (ladderRule.paths) {
    merged.paths = ladderRule.paths;
  }

  // Keep Ladder urlMods (unless BPC also has them, then merge)
  if (ladderRule.urlMods) {
    if (merged.urlMods) {
      // Merge: BPC query + Ladder query etc
      merged.urlMods = {
        domain: [...(merged.urlMods.domain || []), ...(ladderRule.urlMods.domain || [])],
        path: [...(merged.urlMods.path || []), ...(ladderRule.urlMods.path || [])],
        query: [...(merged.urlMods.query || []), ...(ladderRule.urlMods.query || [])],
      };
      // Clean up empty arrays
      if (merged.urlMods.domain.length === 0) delete merged.urlMods.domain;
      if (merged.urlMods.path.length === 0) delete merged.urlMods.path;
      if (merged.urlMods.query.length === 0) delete merged.urlMods.query;
    } else {
      merged.urlMods = ladderRule.urlMods;
    }
  }

  // Merge headers: BPC headers take precedence, Ladder headers fill gaps
  if (ladderRule.headers) {
    merged.headers = merged.headers || {};
    for (const [key, val] of Object.entries(ladderRule.headers)) {
      if (!merged.headers[key]) {
        merged.headers[key] = val;
      }
    }
  }

  // Keep Ladder googleCache
  if (ladderRule.googleCache) {
    merged.googleCache = ladderRule.googleCache;
  }

  return merged;
}

// Clean up a rule for YAML output (remove empty/falsy fields)
function cleanRule(rule) {
  const cleaned = {};

  // Domain fields first
  if (rule.domain) cleaned.domain = rule.domain;
  if (rule.domains && rule.domains.length > 0) cleaned.domains = rule.domains;
  if (rule.paths && rule.paths.length > 0) cleaned.paths = rule.paths;

  // Headers
  if (rule.headers && Object.keys(rule.headers).length > 0) cleaned.headers = rule.headers;

  // URL mods
  if (rule.urlMods) cleaned.urlMods = rule.urlMods;

  // Google Cache
  if (rule.googleCache) cleaned.googleCache = rule.googleCache;

  // Extra headers
  if (rule.extraHeaders && Object.keys(rule.extraHeaders).length > 0) cleaned.extraHeaders = rule.extraHeaders;

  // New BPC fields
  if (rule.randomIP) cleaned.randomIP = rule.randomIP;
  if (rule.blockScripts && rule.blockScripts.length > 0) cleaned.blockScripts = rule.blockScripts;
  if (rule.blockScriptsGeneral && rule.blockScriptsGeneral.length > 0) cleaned.blockScriptsGeneral = rule.blockScriptsGeneral;
  if (rule.csCode && rule.csCode.length > 0) cleaned.csCode = rule.csCode;
  if (rule.ampUnhide) cleaned.ampUnhide = rule.ampUnhide;
  if (rule.blockJsInline) cleaned.blockJsInline = rule.blockJsInline;
  if (rule.clearStorage) cleaned.clearStorage = rule.clearStorage;
  if (rule.pathExclusions && rule.pathExclusions.length > 0) cleaned.pathExclusions = rule.pathExclusions;

  // Regex rules
  if (rule.regexRules && rule.regexRules.length > 0) cleaned.regexRules = rule.regexRules;

  // Injections
  if (rule.injections && rule.injections.length > 0) cleaned.injections = rule.injections;

  // Tests
  if (rule.tests) {
    if (Array.isArray(rule.tests) && rule.tests.length > 0) {
      cleaned.tests = rule.tests;
    } else if (!Array.isArray(rule.tests) && rule.tests.url) {
      cleaned.tests = [rule.tests];
    }
  }

  return cleaned;
}

async function main() {
  try {
    // Step 1: Fetch BPC data
    const bpcData = await fetchBPC();
    console.log(`Fetched ${bpcData.length} BPC entries`);

    // Step 2: Load Ladder rules
    const ladderRules = loadLadderRules();
    const ladderIndex = indexLadderRules(ladderRules);
    console.log(`Loaded ${ladderRules.length} ladder rules covering ${Object.keys(ladderIndex).length} domains`);
    fs.writeFileSync(EMBED_LADDER_OUTPUT_FILE, JSON.stringify(ladderRules));
    console.log(`Generated ${EMBED_LADDER_OUTPUT_FILE} (JSON embed) with ${ladderRules.length} ladder rules`);

    // Step 3-4: Map BPC entries to Ladderflare rules
    const bpcRules = [];
    const seenDomains = new Set();

    for (const entry of bpcData) {
      const rule = mapBPCEntry(entry);
      if (!rule) continue;

      bpcRules.push(rule);
      seenDomains.add(rule.domain);

      // Handle exceptions (#18)
      const excRules = handleExceptions(entry, rule);
      for (const excRule of excRules) {
        bpcRules.push(excRule);
        seenDomains.add(excRule.domain);
      }
    }

    console.log(`Mapped ${bpcRules.length} BPC rules for ${seenDomains.size} domains`);

    // Step 5: Merge with Ladder rules
    const mergedRules = [];
    const ladderDomainsUsed = new Set();

    for (const bpcRule of bpcRules) {
      const domain = bpcRule.domain;
      const ladderRule = ladderIndex[domain];

      if (ladderRule) {
        mergedRules.push(mergeRules(bpcRule, ladderRule));
        ladderDomainsUsed.add(domain);
        // Mark all domains in the Ladder rule as used
        if (ladderRule.domains) {
          for (const d of ladderRule.domains) ladderDomainsUsed.add(d);
        }
        if (ladderRule.domain) ladderDomainsUsed.add(ladderRule.domain);
      } else {
        mergedRules.push(bpcRule);
      }
    }

    // Add Ladder-only rules (not covered by BPC)
    for (const ladderRule of ladderRules) {
      const ladderDomains = [];
      if (ladderRule.domain) ladderDomains.push(ladderRule.domain);
      if (ladderRule.domains) ladderDomains.push(...ladderRule.domains);

      const allUsed = ladderDomains.every(d => ladderDomainsUsed.has(d));
      if (!allUsed) {
        mergedRules.push(ladderRule);
      }
    }

    // Step 6: Re-group identical rules (#17)
    const groupedRules = regroupRules(mergedRules);

    // Step 7: Clean and output
    const cleanedRules = groupedRules.map(cleanRule);

    // Count domains
    let domainCount = 0;
    for (const rule of cleanedRules) {
      if (rule.domain) domainCount++;
      if (rule.domains) domainCount += rule.domains.length;
    }

    fs.writeFileSync(EMBED_OUTPUT_FILE, JSON.stringify(cleanedRules));
    console.log(`Generated ${EMBED_OUTPUT_FILE} (JSON embed) with ${cleanedRules.length} rules covering ${domainCount} domains`);

    // Generate BPC-only ruleset (without Ladder merge)
    const bpcOnlyGrouped = regroupRules(bpcRules);
    const bpcOnlyCleaned = bpcOnlyGrouped.map(cleanRule);

    // Count domains in BPC-only ruleset
    let bpcDomainCount = 0;
    for (const rule of bpcOnlyCleaned) {
      if (rule.domain) bpcDomainCount++;
      if (rule.domains) bpcDomainCount += rule.domains.length;
    }

    fs.writeFileSync(EMBED_BPC_OUTPUT_FILE, JSON.stringify(bpcOnlyCleaned));
    console.log(`Generated ${EMBED_BPC_OUTPUT_FILE} (JSON embed) with ${bpcOnlyCleaned.length} rules covering ${bpcDomainCount} domains`);

    // Extract test URLs
    const testUrls = [];
    for (const rule of cleanedRules) {
      if (rule.tests && Array.isArray(rule.tests)) {
        for (const test of rule.tests) {
          if (test.url) testUrls.push(test.url);
        }
      }
    }

    const uniqueTestUrls = [...new Set(testUrls)];
    fs.writeFileSync(TEST_URLS_FILE, JSON.stringify(uniqueTestUrls, null, 2));
    console.log(`Saved ${uniqueTestUrls.length} test URLs to ${TEST_URLS_FILE}`);

  } catch (error) {
    console.error('Error building ruleset:', error);
    process.exit(1);
  }
}

main();
