export const BPC_KV_VERSION_KEY = 'bpc:ruleset_bpc:version';
export const BPC_KV_RULESET_KEY = 'bpc:ruleset_bpc';
export const BPC_KV_SITES_JS_KEY = 'bpc:sites_aggregated_js';
export const BPC_KV_SITES_VERSION_KEY = 'bpc:sites_aggregated_js:version';
export const BPC_KV_MANIFEST_KEY = 'bpc:manifest';

export const BPC_RUNTIME_REFRESH_MS = 60 * 1000;

let activeRules = [];
let activeRulesJSON = '';
let activeDomains = [];
let activeTestURLs = [];
let activeGlobalBlockPatterns = [];
let loadedVersion = null;
let lastRefreshAt = 0;

function normalizeRules(value) {
  return Array.isArray(value) ? value : [];
}

function uniqueStrings(values) {
  const seen = new Set();
  const output = [];

  for (const value of values) {
    if (typeof value !== 'string' || value.length === 0 || seen.has(value)) {
      continue;
    }
    seen.add(value);
    output.push(value);
  }

  return output;
}

function stablePatternKey(value) {
  if (typeof value === 'string') {
    return value;
  }

  if (!value || typeof value !== 'object') {
    return '';
  }

  return JSON.stringify({
    pattern: value.pattern || '',
    excludedDomains: Array.isArray(value.excludedDomains) ? [...value.excludedDomains].sort() : [],
  });
}

function uniquePatterns(values) {
  const seen = new Set();
  const output = [];

  for (const value of values) {
    const key = stablePatternKey(value);
    if (!key || seen.has(key)) {
      continue;
    }
    seen.add(key);
    output.push(value);
  }

  return output;
}

function collectDomains(rules) {
  const output = [];

  for (const rule of rules) {
    if (!rule || typeof rule !== 'object') {
      continue;
    }

    if (typeof rule.domain === 'string' && rule.domain.length > 0) {
      output.push(rule.domain);
    }

    if (Array.isArray(rule.domains)) {
      for (const domain of rule.domains) {
        if (typeof domain === 'string' && domain.length > 0) {
          output.push(domain);
        }
      }
    }
  }

  return uniqueStrings(output);
}

function collectTestURLs(rules) {
  const output = [];

  for (const rule of rules) {
    if (!rule || typeof rule !== 'object' || !Array.isArray(rule.tests)) {
      continue;
    }

    for (const test of rule.tests) {
      if (test && typeof test.url === 'string' && test.url.length > 0) {
        output.push(test.url);
      }
    }
  }

  return output;
}

function collectGlobalBlockPatterns(rules) {
  const output = [];

  for (const rule of rules) {
    if (!rule || typeof rule !== 'object' || !Array.isArray(rule.blockScriptsGeneral)) {
      continue;
    }

    for (const pattern of rule.blockScriptsGeneral) {
      if (typeof pattern === 'string' && pattern.length > 0) {
        output.push(pattern);
      } else if (pattern && typeof pattern === 'object' && typeof pattern.pattern === 'string' && pattern.pattern.length > 0) {
        output.push(pattern);
      }
    }
  }

  return uniquePatterns(output);
}

function replaceState(rules, rulesJSON, version) {
  activeRules = rules;
  activeRulesJSON = rulesJSON;
  activeDomains = collectDomains(rules);
  activeTestURLs = collectTestURLs(rules);
  activeGlobalBlockPatterns = collectGlobalBlockPatterns(rules);
  if (version !== undefined) {
    loadedVersion = version;
  }
}

export function setRulesetJSON(rulesJSON, version = null) {
  const parsed = JSON.parse(rulesJSON);
  const rules = normalizeRules(parsed);

  replaceState(rules, JSON.stringify(rules), version);
  return true;
}

export function isRulesetLoaded() {
  return activeRules.length > 0;
}

export function getRules() {
  return activeRules;
}

export function getRulesetJSON() {
  return activeRulesJSON;
}

export function getRulesetDomains() {
  return activeDomains;
}

export function getRulesetVersion() {
  return loadedVersion;
}

export function getRulesetStats() {
  return {
    version: loadedVersion,
    rules: activeRules.length,
    domains: activeDomains.length,
    tests: activeTestURLs.length,
    globalBlockPatterns: activeGlobalBlockPatterns.length,
  };
}

export function getGlobalBlockPatterns() {
  return activeGlobalBlockPatterns;
}

export function getRandomTestURL() {
  if (activeTestURLs.length === 0) {
    return '';
  }

  const index = Math.floor(Math.random() * activeTestURLs.length);
  return activeTestURLs[index] || '';
}

export async function loadRulesetFromKV(env, { force = false } = {}) {
  const kv = env?.CONFIG_KV;
  if (!kv) {
    return false;
  }

  const nextVersion = await kv.get(BPC_KV_VERSION_KEY);
  if (!force && nextVersion && loadedVersion && nextVersion === loadedVersion) {
    return false;
  }

  const nextRulesJSON = await kv.get(BPC_KV_RULESET_KEY);
  if (!nextRulesJSON) {
    return false;
  }

  try {
    setRulesetJSON(nextRulesJSON, nextVersion || loadedVersion);
    return true;
  } catch (error) {
    console.error('Failed to parse ruleset from KV:', error);
    return false;
  }
}

export async function maybeRefreshRulesetFromKV(env, { force = false } = {}) {
  if (!env?.CONFIG_KV) {
    return false;
  }

  const now = Date.now();
  if (!force && now - lastRefreshAt < BPC_RUNTIME_REFRESH_MS) {
    return false;
  }

  lastRefreshAt = now;
  return loadRulesetFromKV(env, { force });
}
