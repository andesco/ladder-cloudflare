// Shared BPC -> Ladderflare rules mapping utilities.
// This module is used both at build-time (Node) and at runtime (Worker scheduled updater).

// Known user-agent strings
const UA_GOOGLEBOT =
  'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)';
const UA_BINGBOT =
  'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)';
const UA_FACEBOOKBOT =
  'facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)';

// Known referer URLs
const REFERER_GOOGLE = 'https://www.google.com/';
const REFERER_FACEBOOK = 'https://www.facebook.com/';
const REFERER_TWITTER = 'https://t.co/x?amp=1';

// BPC fields like `useragent`, `referer`, and `random_ip` behave like enums in
// `sites_aggregated.*`. If upstream adds new values, we want a loud failure
// instead of silently generating degraded rules.
const KNOWN_BPC_USERAGENTS = new Set(['googlebot', 'bingbot', 'facebookbot']);
const KNOWN_BPC_REFERER_TOKENS = new Set(['google', 'facebook', 'twitter']);

function looksLikeURL(value) {
  return typeof value === 'string' && /^https?:\/\//i.test(value);
}

export function parseSitesAggregatedText(text) {
  if (typeof text !== 'string') throw new Error('sites_aggregated input must be a string');
  const trimmed = text.trim();
  if (!trimmed) throw new Error('sites_aggregated input is empty');

  // Support raw JSON (common for local copies).
  if (trimmed[0] === '[' || trimmed[0] === '{') {
    const parsed = JSON.parse(trimmed);
    if (Array.isArray(parsed)) return parsed;
    // Some formats might wrap the array; fall through to extraction.
  }

  // Support upstream .js formats by extracting the first JSON array.
  const start = trimmed.indexOf('[');
  const end = trimmed.lastIndexOf(']');
  if (start === -1 || end === -1 || end <= start) {
    throw new Error('Failed to locate JSON array in sites_aggregated.js');
  }

  const jsonSlice = trimmed.slice(start, end + 1);
  const parsed = JSON.parse(jsonSlice);
  if (!Array.isArray(parsed)) throw new Error('sites_aggregated.js did not contain a JSON array');
  return parsed;
}

export function validateBPCData(bpcData) {
  const unknown = {
    useragent: new Map(), // value -> Set(domains)
    referer: new Map(), // value -> Set(domains)
    random_ip: new Map(), // value -> Set(domains)
    types: new Map(), // description -> Set(domains)
  };

  function record(map, key, domain) {
    const k = String(key);
    if (!map.has(k)) map.set(k, new Set());
    const set = map.get(k);
    if (set.size < 5) set.add(domain);
  }

  function checkEntry(entry, domain, ctxLabel) {
    if (!domain || domain.startsWith('###') || domain.startsWith('#')) return;

    if (entry.useragent) {
      if (typeof entry.useragent !== 'string') {
        record(unknown.types, `useragent type=${typeof entry.useragent} (${ctxLabel})`, domain);
      } else if (!KNOWN_BPC_USERAGENTS.has(entry.useragent)) {
        record(unknown.useragent, entry.useragent, domain);
      }
    }

    if (entry.referer) {
      if (typeof entry.referer !== 'string') {
        record(unknown.types, `referer type=${typeof entry.referer} (${ctxLabel})`, domain);
      } else if (!KNOWN_BPC_REFERER_TOKENS.has(entry.referer) && !looksLikeURL(entry.referer)) {
        record(unknown.referer, entry.referer, domain);
      }
    }

    if (entry.random_ip) {
      // Allow: "eu" (special), true/"true"/"all" (generic random)
      const v = entry.random_ip;
      const ok = v === 'eu' || v === true || v === 'true' || v === 'all';
      if (!ok) record(unknown.random_ip, v, domain);
    }
  }

  for (const entry of bpcData) {
    checkEntry(entry, entry.domain, 'root');

    if (!entry.exception || !Array.isArray(entry.exception)) continue;
    for (const exc of entry.exception) {
      const excDomains = Array.isArray(exc.domain) ? exc.domain : [exc.domain];
      for (const d of excDomains) {
        checkEntry(exc, d, 'exception');
      }
    }
  }

  const lines = [];
  if (unknown.useragent.size > 0) {
    lines.push(`- Unknown BPC useragent values: ${[...unknown.useragent.keys()].sort().join(', ')}`);
  }
  if (unknown.referer.size > 0) {
    lines.push(`- Unknown BPC referer values (non-URL): ${[...unknown.referer.keys()].sort().join(', ')}`);
  }
  if (unknown.random_ip.size > 0) {
    lines.push(`- Unknown BPC random_ip values: ${[...unknown.random_ip.keys()].sort().join(', ')}`);
  }
  if (unknown.types.size > 0) {
    lines.push(`- Unexpected BPC field types: ${[...unknown.types.keys()].sort().join(', ')}`);
  }

  if (lines.length === 0) return;

  // Include a few example domains for debugging. Keep it short so logs are usable.
  const examples = [];
  for (const [val, domains] of unknown.useragent.entries()) {
    examples.push(`  useragent=${val}: ${[...domains].join(', ')}`);
  }
  for (const [val, domains] of unknown.referer.entries()) {
    examples.push(`  referer=${val}: ${[...domains].join(', ')}`);
  }
  for (const [val, domains] of unknown.random_ip.entries()) {
    examples.push(`  random_ip=${val}: ${[...domains].join(', ')}`);
  }
  for (const [val, domains] of unknown.types.entries()) {
    examples.push(`  ${val}: ${[...domains].join(', ')}`);
  }

  throw new Error(
    [
      'Unknown/unsupported BPC tokens detected in sites_aggregated.* (refusing to update).',
      ...lines,
      '',
      'Examples:',
      ...examples.slice(0, 30),
    ].join('\n'),
  );
}

// Map a single BPC entry to a Ladderflare rule object
export function mapBPCEntry(entry) {
  const domain = entry.domain;
  if (!domain || domain.startsWith('###') || domain.startsWith('#')) return null;

  const rule = { domain };
  const headers = {};
  let hasHeaders = false;

  // User-agent mapping
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
      default:
        throw new Error(`Unknown BPC useragent token '${entry.useragent}' for domain '${domain}'`);
    }
    hasHeaders = true;
  }

  if (entry.useragent_custom) {
    headers['user-agent'] = entry.useragent_custom;
    hasHeaders = true;
  }

  // Referer mapping
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
        if (looksLikeURL(entry.referer)) {
          headers['referer'] = entry.referer;
        } else {
          throw new Error(`Unknown BPC referer token '${entry.referer}' for domain '${domain}'`);
        }
    }
    hasHeaders = true;
  }

  if (entry.referer_custom) {
    headers['referer'] = entry.referer_custom;
    hasHeaders = true;
  }

  // Custom headers -> cookie + extraHeaders
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

  // Random IP
  if (entry.random_ip) {
    if (entry.random_ip === 'eu') {
      rule.randomIP = 'eu';
    } else if (entry.random_ip === true || entry.random_ip === 'true' || entry.random_ip === 'all') {
      rule.randomIP = 'true';
    } else {
      throw new Error(`Unknown BPC random_ip value '${entry.random_ip}' for domain '${domain}'`);
    }
  }

  // Block regex (script blocking)
  if (entry.block_regex) {
    const patterns = typeof entry.block_regex === 'string' ? [entry.block_regex] : entry.block_regex;
    rule.blockScripts = patterns.map((p) => p.replace(/\{domain\}/g, domain.replace(/\./g, '\\.')));
  }

  // Block regex general
  if (entry.block_regex_general) {
    const patterns =
      typeof entry.block_regex_general === 'string'
        ? [entry.block_regex_general]
        : entry.block_regex_general;
    rule.blockScriptsGeneral = patterns.map((p) => p.replace(/\{domain\}/g, domain.replace(/\./g, '\\.')));
  }

  // cs_code (content script operations)
  if (entry.cs_code) {
    let ops;
    if (typeof entry.cs_code === 'string') {
      try {
        ops = JSON.parse(entry.cs_code);
      } catch (e) {
        // Keep going; this mirrors previous behavior (warn + skip csCode).
        ops = null;
      }
    } else if (Array.isArray(entry.cs_code)) {
      ops = entry.cs_code;
    }
    if (ops && Array.isArray(ops)) {
      rule.csCode = ops.map((op) => {
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

  // AMP unhide
  if (entry.amp_unhide) {
    rule.ampUnhide = true;
  }

  // AMP redirect -> urlMods query
  if (entry.amp_redirect) {
    rule.urlMods = { query: [{ key: 'amp', value: '1' }] };
  }

  // Block inline JS
  if (entry.block_js_inline) {
    rule.blockJsInline = entry.block_js_inline;
  }

  // Clear local/session storage
  if (entry.cs_clear_lclstrg) {
    rule.clearStorage = true;
  }

  return rule;
}

// Handle exception arrays: produce separate rules for excepted domains
export function handleExceptions(entry) {
  const exceptionRules = [];
  if (!entry.exception || !Array.isArray(entry.exception)) return exceptionRules;

  for (const exc of entry.exception) {
    const excDomains = Array.isArray(exc.domain) ? exc.domain : [exc.domain];
    for (const excDomain of excDomains) {
      if (!excDomain) continue;
      const excEntry = { ...exc, domain: excDomain };
      const excRule = mapBPCEntry(excEntry);
      if (excRule) exceptionRules.push(excRule);
    }
  }

  return exceptionRules;
}

function ruleGroupKey(rule) {
  const copy = { ...rule };
  delete copy.domain;
  delete copy.domains;
  const stable = (value) => {
    if (Array.isArray(value)) return value.map(stable);
    if (value && typeof value === 'object') {
      const out = {};
      for (const k of Object.keys(value).sort()) out[k] = stable(value[k]);
      return out;
    }
    return value;
  };
  return JSON.stringify(stable(copy));
}

// Re-group: domains with identical non-domain properties -> single rule with domains: [...]
// Rules with injections, tests, regexRules, or paths are NOT grouped (they're unique per domain).
export function regroupRules(rules) {
  const groups = new Map();
  const ungroupable = [];

  for (const rule of rules) {
    const hasUniqueContent =
      (rule.injections && rule.injections.length > 0) ||
      (rule.tests && (Array.isArray(rule.tests) ? rule.tests.length > 0 : !!rule.tests)) ||
      (rule.regexRules && rule.regexRules.length > 0) ||
      (rule.paths && rule.paths.length > 0);

    if (hasUniqueContent) {
      ungroupable.push(rule);
      continue;
    }

    const key = ruleGroupKey(rule);
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

  for (const rule of ungroupable) result.push(rule);
  return result;
}

// Merge BPC rule with Ladder rule: BPC provides headers/blocking, Ladder provides injections/tests/regexRules
export function mergeRules(bpcRule, ladderRule) {
  const merged = JSON.parse(JSON.stringify(bpcRule));

  if (ladderRule.injections) merged.injections = ladderRule.injections;
  if (ladderRule.tests) merged.tests = ladderRule.tests;
  if (ladderRule.regexRules) merged.regexRules = ladderRule.regexRules;
  if (ladderRule.paths) merged.paths = ladderRule.paths;

  if (ladderRule.urlMods) {
    if (merged.urlMods) {
      merged.urlMods = {
        domain: [...(merged.urlMods.domain || []), ...(ladderRule.urlMods.domain || [])],
        path: [...(merged.urlMods.path || []), ...(ladderRule.urlMods.path || [])],
        query: [...(merged.urlMods.query || []), ...(ladderRule.urlMods.query || [])],
      };
      if (merged.urlMods.domain.length === 0) delete merged.urlMods.domain;
      if (merged.urlMods.path.length === 0) delete merged.urlMods.path;
      if (merged.urlMods.query.length === 0) delete merged.urlMods.query;
    } else {
      merged.urlMods = ladderRule.urlMods;
    }
  }

  if (ladderRule.headers) {
    merged.headers = merged.headers || {};
    for (const [key, val] of Object.entries(ladderRule.headers)) {
      if (!merged.headers[key]) merged.headers[key] = val;
    }
  }

  if (ladderRule.googleCache) merged.googleCache = ladderRule.googleCache;
  return merged;
}

export function cleanRule(rule) {
  const cleaned = {};

  if (rule.domain) cleaned.domain = rule.domain;
  if (rule.domains && rule.domains.length > 0) cleaned.domains = rule.domains;
  if (rule.paths && rule.paths.length > 0) cleaned.paths = rule.paths;

  if (rule.headers && Object.keys(rule.headers).length > 0) cleaned.headers = rule.headers;
  if (rule.urlMods) cleaned.urlMods = rule.urlMods;
  if (rule.googleCache) cleaned.googleCache = rule.googleCache;

  if (rule.extraHeaders && Object.keys(rule.extraHeaders).length > 0) cleaned.extraHeaders = rule.extraHeaders;

  if (rule.randomIP) cleaned.randomIP = rule.randomIP;
  if (rule.blockScripts && rule.blockScripts.length > 0) cleaned.blockScripts = rule.blockScripts;
  if (rule.blockScriptsGeneral && rule.blockScriptsGeneral.length > 0) cleaned.blockScriptsGeneral = rule.blockScriptsGeneral;
  if (rule.csCode && rule.csCode.length > 0) cleaned.csCode = rule.csCode;
  if (rule.ampUnhide) cleaned.ampUnhide = rule.ampUnhide;
  if (rule.blockJsInline) cleaned.blockJsInline = rule.blockJsInline;
  if (rule.clearStorage) cleaned.clearStorage = rule.clearStorage;
  if (rule.pathExclusions && rule.pathExclusions.length > 0) cleaned.pathExclusions = rule.pathExclusions;

  if (rule.regexRules && rule.regexRules.length > 0) cleaned.regexRules = rule.regexRules;
  if (rule.injections && rule.injections.length > 0) cleaned.injections = rule.injections;

  if (rule.tests) {
    if (Array.isArray(rule.tests) && rule.tests.length > 0) {
      cleaned.tests = rule.tests;
    } else if (!Array.isArray(rule.tests) && rule.tests.url) {
      cleaned.tests = [rule.tests];
    }
  }

  return cleaned;
}

export function buildBpcOnlyRuleset(bpcData) {
  const bpcRules = mapBpcDataToRules(bpcData);
  const grouped = regroupRules(bpcRules);
  return grouped.map(cleanRule);
}

function mapBpcDataToRules(bpcData) {
  const bpcRules = [];

  for (const entry of bpcData) {
    const rule = mapBPCEntry(entry);
    if (!rule) continue;

    bpcRules.push(rule);

    const excRules = handleExceptions(entry);
    for (const excRule of excRules) {
      bpcRules.push(excRule);
    }
  }

  return bpcRules;
}

function indexLadderRules(ladderRules) {
  const index = {};

  for (const rule of ladderRules) {
    if (!rule || typeof rule !== 'object') {
      continue;
    }

    const domains = [];
    if (typeof rule.domain === 'string' && rule.domain.length > 0) {
      domains.push(rule.domain);
    }
    if (Array.isArray(rule.domains)) {
      for (const d of rule.domains) {
        if (typeof d === 'string' && d.length > 0) {
          domains.push(d);
        }
      }
    }

    for (const domain of domains) {
      index[domain] = rule;
    }
  }

  return index;
}

export function buildMergedRuleset(bpcData, ladderRules = []) {
  const bpcRules = mapBpcDataToRules(bpcData);
  const ladderIndex = indexLadderRules(Array.isArray(ladderRules) ? ladderRules : []);

  const mergedRules = [];
  const ladderDomainsUsed = new Set();

  for (const bpcRule of bpcRules) {
    const domain = bpcRule?.domain;
    const ladderRule = domain ? ladderIndex[domain] : null;

    if (ladderRule) {
      mergedRules.push(mergeRules(bpcRule, ladderRule));
      ladderDomainsUsed.add(domain);

      if (typeof ladderRule.domain === 'string' && ladderRule.domain.length > 0) {
        ladderDomainsUsed.add(ladderRule.domain);
      }
      if (Array.isArray(ladderRule.domains)) {
        for (const d of ladderRule.domains) {
          if (typeof d === 'string' && d.length > 0) {
            ladderDomainsUsed.add(d);
          }
        }
      }
    } else {
      mergedRules.push(bpcRule);
    }
  }

  for (const ladderRule of Array.isArray(ladderRules) ? ladderRules : []) {
    if (!ladderRule || typeof ladderRule !== 'object') {
      continue;
    }

    const domains = [];
    if (typeof ladderRule.domain === 'string' && ladderRule.domain.length > 0) {
      domains.push(ladderRule.domain);
    }
    if (Array.isArray(ladderRule.domains)) {
      for (const d of ladderRule.domains) {
        if (typeof d === 'string' && d.length > 0) {
          domains.push(d);
        }
      }
    }

    const allUsed = domains.length > 0 && domains.every((d) => ladderDomainsUsed.has(d));
    if (!allUsed) {
      mergedRules.push(ladderRule);
    }
  }

  const grouped = regroupRules(mergedRules);
  return grouped.map(cleanRule);
}
