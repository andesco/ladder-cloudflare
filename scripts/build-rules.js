#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const yaml = require('yaml');

// BPC data is loaded from a local repo copy (sites_aggregated.js) so builds are reproducible
// and do not depend on network access.
const BPC_FILE = 'sites_aggregated.js';
const LADDER_FILE = 'ruleset-ladder.yaml';
// Faster-to-parse rulesets for WASM embedding (JSON). We do not generate YAML copies.
const EMBED_OUTPUT_FILE = 'ruleset-embedded.json';
const EMBED_BPC_OUTPUT_FILE = 'ruleset-bpc-embedded.json';
const EMBED_LADDER_OUTPUT_FILE = 'ruleset-ladder-embedded.json';
const TEST_URLS_FILE = 'test-urls.json';

let bpcMapper = null;
async function loadBpcMapper() {
  if (bpcMapper) return bpcMapper;
  // Use dynamic import so this script can stay CommonJS (Node >=16).
  bpcMapper = await import('./bpc-mapper.mjs');
  return bpcMapper;
}

function loadLocalBPC() {
  const bpcPath = path.resolve(BPC_FILE);
  if (!fs.existsSync(bpcPath)) {
    throw new Error(`Missing local BPC file '${BPC_FILE}' (expected at ${bpcPath})`);
  }
  return fs.readFileSync(bpcPath, 'utf-8');
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

async function main() {
  try {
    const mapper = await loadBpcMapper();

    // Step 1: Load local BPC data
    const bpcText = loadLocalBPC();
    const bpcData = mapper.parseSitesAggregatedText(bpcText);
    console.log(`Loaded ${bpcData.length} BPC entries from ${BPC_FILE}`);
    mapper.validateBPCData(bpcData);

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
      const rule = mapper.mapBPCEntry(entry);
      if (!rule) continue;

      bpcRules.push(rule);
      seenDomains.add(rule.domain);

      // Handle exceptions (#18)
      const excRules = mapper.handleExceptions(entry, rule);
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
        mergedRules.push(mapper.mergeRules(bpcRule, ladderRule));
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
    const groupedRules = mapper.regroupRules(mergedRules);

    // Step 7: Clean and output
    const cleanedRules = groupedRules.map(mapper.cleanRule);

    // Count domains
    let domainCount = 0;
    for (const rule of cleanedRules) {
      if (rule.domain) domainCount++;
      if (rule.domains) domainCount += rule.domains.length;
    }

    fs.writeFileSync(EMBED_OUTPUT_FILE, JSON.stringify(cleanedRules));
    console.log(`Generated ${EMBED_OUTPUT_FILE} (JSON embed) with ${cleanedRules.length} rules covering ${domainCount} domains`);

    // Generate BPC-only ruleset (without Ladder merge)
    const bpcOnlyGrouped = mapper.regroupRules(bpcRules);
    const bpcOnlyCleaned = bpcOnlyGrouped.map(mapper.cleanRule);

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
