/**
 * Ladderflare - Cloudflare Worker wrapper for Ladder WASM
 */

import wasm from './public/main.wasm';

// Load the Go WASM runtime
import './public/wasm_exec.js';

/**
 * Chrome Extension Bypass Paywall Rules System
 * Implements the complete 3-layer rule aggregation with ### deletion support
 */

// Global rule cache
let aggregatedRules = null;
let rulesLastUpdated = null;
let rulesetVersion = null;
let rulesetMetaLastChecked = 0;
let globalBlockRegexRules = null;
let globalBlockRegexVersion = null;
const RULES_CACHE_TTL = 24 * 60 * 60 * 1000; // 24 hours
const RULESET_META_CHECK_INTERVAL = 5 * 60 * 1000; // 5 minutes

const USER_AGENT_DESKTOP_G = 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)';
const USER_AGENT_MOBILE_G = 'Chrome/137.0.7151.119 Mobile Safari/537.36 (compatible ; Googlebot/2.1 ; +http://www.google.com/bot.html)';
const USER_AGENT_DESKTOP_B = 'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)';
const USER_AGENT_MOBILE_B = 'Chrome/137.0.7151.119 Mobile Safari/537.36 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)';
const USER_AGENT_DESKTOP_F = 'facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)';
const GOOGLEBOT_XFF = '66.249.66.1';

const REFERER_PRESETS = {
  google: 'https://www.google.com/',
  facebook: 'https://www.facebook.com/',
  twitter: 'https://t.co/'
};

const ARCHIVE_DOMAINS = ['archive.is', 'archive.today', 'archive.ph', 'archive.li'];

/**
 * Expand domain groups into individual rules (Phase 2)
 * Replicates Chrome extension expandSiteRules() functionality
 */
function expandSiteRules(sites) {
  const expandedSites = { ...sites };

  for (const [siteName, rule] of Object.entries(sites)) {
    if (rule.hasOwnProperty('group') && Array.isArray(rule.group)) {
      // Expand group domains into individual rules
      for (const domain of rule.group) {
        const expandedRuleName = `${siteName} (${domain})`;
        expandedSites[expandedRuleName] = {
          ...rule,
          domain: domain,
          // Remove group property from expanded rules
          group: undefined
        };
      }
      // Keep the original group rule for reference but mark as group
      expandedSites[siteName] = { ...rule, isGroup: true };
    }
  }

  return expandedSites;
}

/**
 * Check if a rule marks a domain for deletion
 * Supports multiple deletion methods from Chrome extension
 */
function isDeletionRule(rule) {
  return !rule.domain ||
         rule.domain === "###" ||
         rule.domain === "" ||
         rule.delete === true ||
         (rule.domain && rule.domain.startsWith("###_") && !rule.group); // Group deletion
}

function getRulesetCacheKeys(rulesetUrl) {
  const safeKey = rulesetUrl.replace(/[^a-zA-Z0-9]/g, '_');
  return {
    dataKey: `ruleset_url_${safeKey}`,
    metaKey: `ruleset_meta_${safeKey}`
  };
}

function pickRulesetSourceFromManifest(manifest) {
  if (manifest?.sites_aggregated_json?.url) {
    return {
      url: manifest.sites_aggregated_json.url,
      version: manifest.sites_aggregated_json.version || null,
      format: 'json'
    };
  }

  if (manifest?.sites_aggregated_yaml?.url) {
    return {
      url: manifest.sites_aggregated_yaml.url,
      version: manifest.sites_aggregated_yaml.version || null,
      format: 'yaml'
    };
  }

  return null;
}

async function fetchRulesetSource(source) {
  const response = await fetch(source.url, {
    cf: { cacheTtl: 0 }
  });

  if (!response.ok) {
    throw new Error(`Failed to fetch ruleset from ${source.url}: ${response.status}`);
  }

  if (source.format === 'yaml') {
    const yamlText = await response.text();
    return parseYamlRules(yamlText);
  }

  const jsonRules = await response.json();
  return convertJsonToRuleFormat(jsonRules);
}

async function refreshRulesetCache(env, options = {}) {
  const { reason = 'manual', force = false } = options;

  if (!env.RULESET_URL) {
    console.warn(`Ruleset refresh skipped (${reason}): RULESET_URL not set`);
    return { updated: false, reason: 'missing_ruleset_url' };
  }

  const rulesetUrl = env.RULESET_URL;
  const keys = getRulesetCacheKeys(rulesetUrl);

  if (!env.CONFIG_KV) {
    console.warn(`Ruleset refresh (${reason}): CONFIG_KV not configured, fetching without cache`);
  }

  const existingMeta = env.CONFIG_KV
    ? await env.CONFIG_KV.get(keys.metaKey, { type: 'json' })
    : null;

  const manifestResponse = await fetch(rulesetUrl, {
    cf: { cacheTtl: 0 }
  });

  if (!manifestResponse.ok) {
    throw new Error(`Failed to fetch RULESET_URL ${rulesetUrl}: ${manifestResponse.status}`);
  }

  const contentType = manifestResponse.headers.get('content-type') || '';
  let rulesData = null;
  let meta = {
    manifest_url: null,
    manifest_version: null,
    ruleset_url: rulesetUrl,
    ruleset_version: null,
    ruleset_format: null,
    updated_at: Date.now(),
    last_checked: Date.now()
  };

  if (contentType.includes('application/json') || rulesetUrl.endsWith('.json')) {
    const jsonPayload = await manifestResponse.json();

    if (jsonPayload.sites_aggregated_json || jsonPayload.sites_aggregated_yaml) {
      meta.manifest_url = rulesetUrl;
      const rulesetSource = pickRulesetSourceFromManifest(jsonPayload);

      if (!rulesetSource) {
        throw new Error('Manifest does not include sites_aggregated_json or sites_aggregated_yaml');
      }

      meta.ruleset_url = rulesetSource.url;
      meta.ruleset_version = rulesetSource.version || null;
      meta.ruleset_format = rulesetSource.format;
      meta.manifest_version = rulesetSource.version || null;

      const versionUnchanged =
        !force &&
        meta.ruleset_version &&
        existingMeta?.ruleset_version === meta.ruleset_version &&
        existingMeta?.ruleset_url === meta.ruleset_url;

      if (versionUnchanged) {
        if (env.CONFIG_KV) {
          await env.CONFIG_KV.put(keys.metaKey, JSON.stringify({
            ...existingMeta,
            last_checked: Date.now()
          }), { expirationTtl: RULES_CACHE_TTL });
        }
        return { updated: false, reason: 'version_unchanged', meta };
      }

      rulesData = await fetchRulesetSource(rulesetSource);
    } else if (jsonPayload.sites_js_url || jsonPayload.sites_json_url || jsonPayload.sites_updated_url) {
      // Legacy manifest support
      rulesData = await loadRulesFromManifest(jsonPayload, env);
      meta.ruleset_format = 'json';
    } else {
      rulesData = Array.isArray(jsonPayload) ? convertJsonToRuleFormat(jsonPayload) : jsonPayload;
      meta.ruleset_format = 'json';
    }
  } else if (
    contentType.includes('text/yaml') ||
    contentType.includes('application/yaml') ||
    rulesetUrl.endsWith('.yaml') ||
    rulesetUrl.endsWith('.yml')
  ) {
    const yamlText = await manifestResponse.text();
    rulesData = parseYamlRules(yamlText);
    meta.ruleset_format = 'yaml';
  } else {
    console.warn('Unknown RULESET_URL format, treating as JSON');
    const jsonPayload = await manifestResponse.json();
    rulesData = Array.isArray(jsonPayload) ? convertJsonToRuleFormat(jsonPayload) : jsonPayload;
    meta.ruleset_format = 'json';
  }

  if (!rulesData) {
    throw new Error('Failed to load ruleset data');
  }

  meta.rules_count = Object.keys(rulesData).length;

  if (env.CONFIG_KV) {
    await env.CONFIG_KV.put(keys.dataKey, JSON.stringify({
      data: rulesData,
      timestamp: Date.now()
    }), { expirationTtl: RULES_CACHE_TTL });

    await env.CONFIG_KV.put(keys.metaKey, JSON.stringify(meta), {
      expirationTtl: RULES_CACHE_TTL
    });
  }

  rulesetVersion = meta.ruleset_version || rulesetVersion;
  aggregatedRules = null;
  rulesLastUpdated = 0;
  globalBlockRegexRules = null;
  globalBlockRegexVersion = null;

  return { updated: true, rulesData, meta };
}

async function maybeRefreshInMemoryRules(env) {
  if (!env.CONFIG_KV || !env.RULESET_URL) return;

  const now = Date.now();
  if ((now - rulesetMetaLastChecked) < RULESET_META_CHECK_INTERVAL) {
    return;
  }

  rulesetMetaLastChecked = now;
  const keys = getRulesetCacheKeys(env.RULESET_URL);
  const meta = await env.CONFIG_KV.get(keys.metaKey, { type: 'json' });

  if (!meta) return;

  if (!rulesetVersion && meta.ruleset_version) {
    rulesetVersion = meta.ruleset_version;
  }

  if (meta.ruleset_version && rulesetVersion && meta.ruleset_version !== rulesetVersion) {
    aggregatedRules = null;
    rulesLastUpdated = 0;
    globalBlockRegexRules = null;
    globalBlockRegexVersion = null;
    rulesetVersion = meta.ruleset_version;
    return;
  }

  if (meta.updated_at && rulesLastUpdated && meta.updated_at > rulesLastUpdated) {
    aggregatedRules = null;
    rulesLastUpdated = 0;
    globalBlockRegexRules = null;
    globalBlockRegexVersion = null;
  }
}

function parseJsonSafe(value, fallback = null) {
  if (value == null) return fallback;
  if (typeof value !== 'string') return value;
  try {
    return JSON.parse(value);
  } catch (error) {
    console.warn('Failed to parse JSON value:', error);
    return fallback;
  }
}

function toBooleanFlag(value) {
  return value === 1 || value === true || value === '1' || value === 'true';
}

function normalizeArray(value) {
  if (!value) return [];
  return Array.isArray(value) ? value : [value];
}

function normalizeRule(rule) {
  if (!rule) return null;
  const normalized = { ...rule };

  normalized.allow_cookies = toBooleanFlag(rule.allow_cookies);
  normalized.remove_cookies = toBooleanFlag(rule.remove_cookies);
  normalized.cs_dompurify = toBooleanFlag(rule.cs_dompurify);
  normalized.cs_clear_lclstrg = toBooleanFlag(rule.cs_clear_lclstrg);
  normalized.cs_all_frames = toBooleanFlag(rule.cs_all_frames);
  normalized.block_host_perm_add = toBooleanFlag(rule.block_host_perm_add);
  normalized.exception = toBooleanFlag(rule.exception);
  normalized.amp_unhide = toBooleanFlag(rule.amp_unhide);

  normalized.remove_cookies_select_drop = normalizeArray(rule.remove_cookies_select_drop);
  normalized.remove_cookies_select_hold = normalizeArray(rule.remove_cookies_select_hold);
  normalized.excluded_domains = normalizeArray(rule.excluded_domains);

  if (normalized.remove_cookies_select_drop.length || normalized.remove_cookies_select_hold.length) {
    normalized.allow_cookies = true;
    normalized.remove_cookies = true;
  }

  if (rule.cs_code) {
    const parsed = parseJsonSafe(rule.cs_code, []);
    normalized.cs_code = Array.isArray(parsed) ? parsed : [];
  } else {
    normalized.cs_code = [];
  }

  if (rule.headers_custom && typeof rule.headers_custom === 'object') {
    normalized.headers_custom = { ...rule.headers_custom };
  }

  if (rule.cs_param && typeof rule.cs_param === 'object') {
    normalized.cs_param = { ...rule.cs_param };
  }

  return normalized;
}

function isValidRuleDomain(ruleDomain) {
  return typeof ruleDomain === 'string' && ruleDomain.length > 0 && !ruleDomain.startsWith('#');
}

function normalizeHostname(hostname) {
  return hostname.replace(/^www\./i, '');
}

function extractHeaderParams(value) {
  if (!value || typeof value !== 'object') return {};
  const headers = {};
  for (const [rawKey, rawValue] of Object.entries(value)) {
    if (rawValue == null) continue;
    const key = String(rawKey).trim();
    if (!key) continue;
    const lower = key.toLowerCase();
    const isHeader = lower.startsWith('x-') || [
      'authorization',
      'cookie',
      'referer',
      'user-agent',
      'accept',
      'accept-language',
      'accept-encoding',
      'x-real-ip',
      'x-requested-with'
    ].includes(lower);
    if (isHeader) {
      headers[key] = String(rawValue);
    }
  }
  return headers;
}

function getRuleHeaderOverrides(rule) {
  const headers = {};
  if (!rule) return headers;
  if (rule.headers_custom && typeof rule.headers_custom === 'object') {
    for (const [key, value] of Object.entries(rule.headers_custom)) {
      headers[key] = value;
    }
  }
  const csParamHeaders = extractHeaderParams(rule.cs_param);
  for (const [key, value] of Object.entries(csParamHeaders)) {
    if (!Object.prototype.hasOwnProperty.call(headers, key)) {
      headers[key] = value;
    }
  }
  return headers;
}

function prepRegexString(pattern, domain = '') {
  if (!pattern) return '';
  let result = pattern;
  if (domain) {
    const safeDomain = domain.replace(/\./g, '\\.');
    result = result.replace(/{domain}/g, safeDomain);
  }
  return result.replace(/^\//, '').replace(/\/\//g, '/').replace(/([^\\])\/$/, '$1');
}

function escapeRegExp(value) {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function buildRegex(pattern, domain) {
  if (!pattern) return null;
  try {
    const source = pattern instanceof RegExp ? pattern.source : prepRegexString(String(pattern), domain);
    return new RegExp(source);
  } catch (error) {
    console.warn('Invalid regex pattern:', pattern, error);
    return null;
  }
}

function shouldExcludeDomain(rule, hostname) {
  if (!rule || !rule.excluded_domains || rule.excluded_domains.length === 0) {
    return false;
  }
  const base = normalizeHostname(hostname);
  return rule.excluded_domains.some((excluded) => {
    const excludedBase = normalizeHostname(excluded);
    return base === excludedBase || base.endsWith(`.${excludedBase}`);
  });
}

function findRuleForDomain(domain, rules) {
  const baseDomain = normalizeHostname(domain);

  for (const [, rawRule] of Object.entries(rules)) {
    if (!rawRule || !isValidRuleDomain(rawRule.domain)) {
      continue;
    }

    const normalized = normalizeRule(rawRule);
    if (normalized.exception) {
      continue;
    }

    const ruleDomain = normalizeHostname(normalized.domain);
    if (ruleDomain === baseDomain || baseDomain.endsWith(`.${ruleDomain}`)) {
      if (shouldExcludeDomain(normalized, baseDomain)) {
        continue;
      }
      return normalized;
    }

    if (Array.isArray(normalized.group)) {
      for (const grouped of normalized.group) {
        const groupedBase = normalizeHostname(grouped);
        if (groupedBase === baseDomain || baseDomain.endsWith(`.${groupedBase}`)) {
          if (shouldExcludeDomain(normalized, baseDomain)) {
            continue;
          }
          return normalized;
        }
      }
    }
  }

  return null;
}

function getGlobalBlockRegexRules(rules) {
  if (globalBlockRegexRules && globalBlockRegexVersion === rulesLastUpdated) {
    return globalBlockRegexRules;
  }

  const globalRules = [];
  for (const rawRule of Object.values(rules || {})) {
    if (!rawRule || !rawRule.block_regex_general || !isValidRuleDomain(rawRule.domain)) {
      continue;
    }
    const normalized = normalizeRule(rawRule);
    if (!normalized || normalized.exception) {
      continue;
    }
    globalRules.push(normalized);
  }

  globalBlockRegexRules = globalRules;
  globalBlockRegexVersion = rulesLastUpdated;
  return globalRules;
}

function getGlobalBlockRegexesForDomain(rules, hostname) {
  const globalRules = getGlobalBlockRegexRules(rules);
  if (!globalRules.length) return [];

  const baseDomain = normalizeHostname(hostname);
  const regexes = [];
  for (const rule of globalRules) {
    if (shouldExcludeDomain(rule, baseDomain)) {
      continue;
    }
    const regex = buildRegex(rule.block_regex_general, rule.domain);
    if (regex) {
      regexes.push(regex);
    }
  }
  return regexes;
}

function isMobileUserAgent(ua) {
  return typeof ua === 'string' && ua.toLowerCase().includes('mobile');
}

function resolveUserAgent(rule, env, clientUserAgent) {
  if (!rule) {
    return env.USER_AGENT || USER_AGENT_DESKTOP_G;
  }

  if (rule.useragent_custom) {
    return rule.useragent_custom;
  }

  if (rule.useragent) {
    const mobile = isMobileUserAgent(clientUserAgent);
    switch (rule.useragent) {
      case 'googlebot':
        return mobile ? USER_AGENT_MOBILE_G : USER_AGENT_DESKTOP_G;
      case 'bingbot':
        return mobile ? USER_AGENT_MOBILE_B : USER_AGENT_DESKTOP_B;
      case 'facebookbot':
        return USER_AGENT_DESKTOP_F;
      default:
        break;
    }
  }

  return env.USER_AGENT || USER_AGENT_DESKTOP_G;
}

function resolveReferer(rule, targetUrl) {
  if (!rule) return null;
  if (rule.referer_custom) return rule.referer_custom;
  if (rule.referer && REFERER_PRESETS[rule.referer]) {
    return REFERER_PRESETS[rule.referer];
  }
  return `${targetUrl.protocol}//${targetUrl.host}`;
}

function randomIpForRule(rule) {
  if (!rule || !rule.random_ip) return null;
  const randomByte = () => Math.floor(Math.random() * 254) + 1;
  if (rule.random_ip === 'eu') {
    return `185.${randomByte()}.${randomByte()}.${randomByte()}`;
  }
  return `${randomByte()}.${randomByte()}.${randomByte()}.${randomByte()}`;
}

function resolveRequestHeaders(rule, env, targetUrl, clientUserAgent, fetchInstructions) {
  const headers = {
    'User-Agent': resolveUserAgent(rule, env, clientUserAgent),
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    'Accept-Encoding': 'gzip, deflate',
    'DNT': '1',
    'Connection': 'keep-alive',
    'Upgrade-Insecure-Requests': '1'
  };

  let userAgentSetByRule = false;
  if (rule?.useragent_custom) {
    headers['User-Agent'] = rule.useragent_custom;
    userAgentSetByRule = true;
  } else if (rule?.useragent) {
    userAgentSetByRule = true;
    switch (rule.useragent) {
      case 'googlebot':
        headers['User-Agent'] = isMobileUserAgent(clientUserAgent) ? USER_AGENT_MOBILE_G : USER_AGENT_DESKTOP_G;
        break;
      case 'bingbot':
        headers['User-Agent'] = isMobileUserAgent(clientUserAgent) ? USER_AGENT_MOBILE_B : USER_AGENT_DESKTOP_B;
        break;
      case 'facebookbot':
        headers['User-Agent'] = USER_AGENT_DESKTOP_F;
        break;
      default:
        break;
    }
  }

  if (!userAgentSetByRule) {
    if (env.USER_AGENT) {
      headers['User-Agent'] = env.USER_AGENT;
    } else if (fetchInstructions?.userAgent) {
      headers['User-Agent'] = fetchInstructions.userAgent;
    }
  }

  let referer = null;
  let skipReferer = false;
  if (rule?.useragent === 'googlebot') {
    referer = REFERER_PRESETS.google;
  } else if (!rule?.useragent && !rule?.useragent_custom && !rule?.headers_custom) {
    if (rule?.referer_custom) {
      referer = rule.referer_custom;
    } else if (rule?.referer) {
      if (rule.referer === 'none') {
        skipReferer = true;
      } else if (REFERER_PRESETS[rule.referer]) {
        referer = REFERER_PRESETS[rule.referer];
      } else {
        referer = rule.referer;
      }
    }
  }

  if (!referer && !skipReferer) {
    referer = fetchInstructions?.referer || `${targetUrl.protocol}//${targetUrl.host}`;
  }

  if (referer) {
    headers['Referer'] = referer;
  }

  let xForwardedFor = null;
  if (rule?.random_ip) {
    xForwardedFor = randomIpForRule(rule);
  } else if (rule?.useragent === 'googlebot') {
    xForwardedFor = GOOGLEBOT_XFF;
  } else if (env.X_FORWARDED_FOR) {
    xForwardedFor = env.X_FORWARDED_FOR;
  } else if (fetchInstructions?.xForwardedFor) {
    xForwardedFor = fetchInstructions.xForwardedFor;
  }

  if (xForwardedFor) {
    headers['X-Forwarded-For'] = xForwardedFor;
  }

  if (fetchInstructions?.accept) headers['Accept'] = fetchInstructions.accept;
  if (fetchInstructions?.acceptLanguage) headers['Accept-Language'] = fetchInstructions.acceptLanguage;
  if (fetchInstructions?.acceptEncoding) headers['Accept-Encoding'] = fetchInstructions.acceptEncoding;
  if (fetchInstructions?.authorization) headers['Authorization'] = fetchInstructions.authorization;
  if (fetchInstructions?.xRealIP) headers['X-Real-IP'] = fetchInstructions.xRealIP;
  if (fetchInstructions?.xRequestedWith) headers['X-Requested-With'] = fetchInstructions.xRequestedWith;

  const headerOverrides = getRuleHeaderOverrides(rule);
  for (const [key, value] of Object.entries(headerOverrides)) {
    headers[key] = value;
  }

  if (rule?.allow_cookies && fetchInstructions?.cookie && !headers['Cookie']) {
    headers['Cookie'] = fetchInstructions.cookie;
  }

  return headers;
}

function shouldBlockUrl(targetUrl, rule, globalRegexes = []) {
  const regexes = Array.isArray(globalRegexes) ? [...globalRegexes] : [];

  if (rule?.block_regex) {
    const regex = buildRegex(rule.block_regex, rule.domain);
    if (regex) regexes.push(regex);
  }

  if (rule?.block_regex_general) {
    const regex = buildRegex(rule.block_regex_general, rule.domain);
    if (regex) regexes.push(regex);
  }

  if (!regexes.length) return false;

  for (const regex of regexes) {
    if (regex && regex.test(targetUrl)) {
      return true;
    }
  }

  return false;
}

function splitSetCookieHeader(headerValue) {
  if (!headerValue) return [];

  const parts = [];
  let current = '';
  let inExpires = false;

  for (let i = 0; i < headerValue.length; i++) {
    const char = headerValue[i];
    current += char;

    if (char === ',' && !inExpires) {
      const next = headerValue.slice(i + 1);
      if (/^\s*[^=]+?=/.test(next)) {
        parts.push(current.slice(0, -1).trim());
        current = '';
      }
    }

    if (headerValue.slice(i - 7, i + 1).toLowerCase() === 'expires=') {
      inExpires = true;
    }
    if (inExpires && char === ';') {
      inExpires = false;
    }
  }

  if (current.trim()) {
    parts.push(current.trim());
  }

  return parts;
}

function filterSetCookieHeaders(headerValue, rule) {
  if (!headerValue) return null;
  if (!rule) {
    return null;
  }

  const cookies = splitSetCookieHeader(headerValue);
  if (!cookies.length) return null;

  const dropList = new Set(rule.remove_cookies_select_drop || []);
  const holdList = new Set(rule.remove_cookies_select_hold || []);
  const hasSelectLists = dropList.size > 0 || holdList.size > 0;
  const consentRegex = /(consent|^optanon)/i;

  const filtered = cookies.filter((cookie) => {
    const name = cookie.split('=')[0].trim();
    if (consentRegex.test(name)) {
      return true;
    }
    if (dropList.size > 0) {
      return !dropList.has(name);
    }
    if (holdList.size > 0) {
      return holdList.has(name);
    }
    if (rule.remove_cookies) {
      return false;
    }
    if (!rule.allow_cookies) {
      return false;
    }
    return true;
  });

  if (!rule.allow_cookies && !rule.remove_cookies && !hasSelectLists) {
    return null;
  }

  return filtered.length ? filtered.join(', ') : null;
}

function sanitizeHtmlSnippet(html) {
  if (!html) return '';
  return html
    .replace(/<script[\s\S]*?>[\s\S]*?<\/script>/gi, '')
    .replace(/<style[\s\S]*?>[\s\S]*?<\/style>/gi, '')
    .replace(/\son\w+="[^"]*"/gi, '')
    .replace(/\son\w+='[^']*'/gi, '')
    .replace(/javascript:/gi, '');
}

function decodeHtmlEntities(text) {
  if (!text || typeof text !== 'string') return '';
  return text
    .replace(/&nbsp;/gi, ' ')
    .replace(/&amp;/gi, '&')
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/&quot;/gi, '"')
    .replace(/&#39;/gi, "'")
    .replace(/&#x([0-9a-fA-F]+);/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)))
    .replace(/&#([0-9]+);/g, (_, num) => String.fromCharCode(parseInt(num, 10)));
}

function buildExternalLinkHtml(targetUrl, type) {
  const cleanUrl = targetUrl.split('#')[0];
  const encodedUrl = encodeURIComponent(cleanUrl);
  let linkLabel = 'External link';
  let linkHref = cleanUrl;

  if (type === 'archive.is' || type === 'archive.today') {
    linkLabel = 'archive.is';
    linkHref = `https://archive.is/?run=1&url=${encodedUrl}`;
  } else if (type === 'google_search_tool') {
    linkLabel = 'Google Rich Results';
    linkHref = `https://search.google.com/test/rich-results?url=${encodedUrl}`;
  }

  return `
    <div id="bpc_ext_link" style="margin:20px 0;font-size:16px;font-weight:bold;color:#c00;">
      <span>Bypass helper:</span>
      <a href="${linkHref}" target="_blank" rel="noopener noreferrer" style="color:#c00;margin-left:8px;">${linkLabel}</a>
    </div>
  `;
}

function buildArchiveUrl(targetUrl) {
  const cleanUrl = targetUrl.split(/[#?]/)[0];
  const domain = ARCHIVE_DOMAINS[Math.floor(Math.random() * ARCHIVE_DOMAINS.length)];
  return `https://${domain}/${cleanUrl}`;
}

async function fetchArchiveSnapshot(targetUrl) {
  try {
    const archiveUrl = buildArchiveUrl(targetUrl);
    const response = await fetch(archiveUrl);
    if (!response.ok) return null;
    const content = await response.text();
    return {
      url: archiveUrl,
      host: new URL(archiveUrl).host,
      contentType: response.headers.get('Content-Type') || 'text/html',
      content
    };
  } catch (error) {
    console.warn('Archive fetch failed:', error);
    return null;
  }
}

function splitRuleSelectors(value) {
  if (!value || typeof value !== 'string') return [];
  return value.split('|').map((item) => item.trim());
}

function expandCsCodeActions(actions, parentSelector = '') {
  const expanded = [];
  for (const action of actions || []) {
    if (!action || typeof action !== 'object') continue;

    if (action.add_style) {
      expanded.push({ type: 'add_style', value: action.add_style });
    }

    if (action.hide_elem) {
      const selector = parentSelector ? `${parentSelector} ${action.hide_elem}` : action.hide_elem;
      expanded.push({ type: 'hide_elem', selector });
    }

    if (action.rm_elem_wait) {
      const selector = parentSelector ? `${parentSelector} ${action.rm_elem_wait}` : action.rm_elem_wait;
      expanded.push({ type: 'rm_elem', selector });
    }

    if (action.cond) {
      const selector = parentSelector ? `${parentSelector} ${action.cond}` : action.cond;
      if (action.rm_elem) {
        expanded.push({ type: 'rm_elem', selector });
      }
      if (action.rm_class) {
        expanded.push({ type: 'rm_class', selector, value: action.rm_class });
      }
      if (action.rm_attrib) {
        expanded.push({ type: 'rm_attrib', selector, value: action.rm_attrib });
      }
      if (action.set_attrib) {
        expanded.push({ type: 'set_attrib', selector, value: action.set_attrib });
      }
      if (action.elems) {
        expanded.push(...expandCsCodeActions(action.elems, selector));
      }
    }
  }
  return expanded;
}

function registerCsCodeHandlers(rewriter, actions, headSnippets) {
  for (const action of actions) {
    if (action.type === 'add_style') {
      headSnippets.push(`<style>${action.value}</style>`);
      continue;
    }

    if (!action.selector) continue;

    if (action.type === 'hide_elem') {
      rewriter.on(action.selector, {
        element(element) {
          const existing = element.getAttribute('style') || '';
          element.setAttribute('style', `${existing} display:none !important;`);
        }
      });
      continue;
    }

    if (action.type === 'rm_elem') {
      rewriter.on(action.selector, {
        element(element) {
          element.remove();
        }
      });
      continue;
    }

    if (action.type === 'rm_class') {
      const classes = String(action.value || '').split(/[,|]/).map((item) => item.trim()).filter(Boolean);
      if (!classes.length) continue;
      rewriter.on(action.selector, {
        element(element) {
          const current = element.getAttribute('class') || '';
          if (!current) return;
          const remaining = current
            .split(/\s+/)
            .filter((cls) => cls && !classes.includes(cls));
          if (remaining.length) {
            element.setAttribute('class', remaining.join(' '));
          } else {
            element.removeAttribute('class');
          }
        }
      });
      continue;
    }

    if (action.type === 'rm_attrib') {
      const attribs = String(action.value || '').split('|').map((item) => item.trim()).filter(Boolean);
      if (!attribs.length) continue;
      rewriter.on(action.selector, {
        element(element) {
          for (const attrib of attribs) {
            element.removeAttribute(attrib);
          }
        }
      });
      continue;
    }

    if (action.type === 'set_attrib') {
      const [attrib, value] = String(action.value || '').split('|');
      if (!attrib) continue;
      rewriter.on(action.selector, {
        element(element) {
          element.setAttribute(attrib.trim(), (value || '').trim());
        }
      });
      continue;
    }
  }
}

function buildBlockRegexList(rule, globalRegexes = []) {
  const regexes = Array.isArray(globalRegexes) ? [...globalRegexes] : [];
  if (!rule) return regexes;
  const patterns = [rule.block_regex, rule.block_regex_general].filter(Boolean);
  for (const pattern of patterns) {
    const regex = buildRegex(pattern, rule.domain);
    if (regex) regexes.push(regex);
  }
  return regexes;
}

function registerBlockedResourceHandlers(rewriter, rule, baseUrl, globalRegexes = []) {
  const regexes = buildBlockRegexList(rule, globalRegexes);
  if (!regexes.length) return;

  const shouldBlock = (url) => regexes.some((regex) => regex.test(url));

  const handleAttr = (attrName) => ({
    element(element) {
      const attrValue = element.getAttribute(attrName);
      if (!attrValue) return;

      const candidates = [];
      if (attrName === 'srcset') {
        const parts = attrValue.split(',').map((part) => part.trim().split(/\s+/)[0]);
        candidates.push(...parts.filter(Boolean));
      } else {
        candidates.push(attrValue);
      }

      for (let candidate of candidates) {
        if (candidate.startsWith('/http')) {
          candidate = candidate.slice(1);
        }
        let absoluteUrl = candidate;
        try {
          absoluteUrl = new URL(candidate, baseUrl).toString();
        } catch (error) {
          continue;
        }
        if (shouldBlock(absoluteUrl)) {
          element.remove();
          return;
        }
      }
    }
  });

  rewriter.on('script[src]', handleAttr('src'));
  rewriter.on('link[href]', handleAttr('href'));
  rewriter.on('iframe[src]', handleAttr('src'));
  rewriter.on('img[src]', handleAttr('src'));
  rewriter.on('source[src]', handleAttr('src'));
  rewriter.on('source[srcset]', handleAttr('srcset'));
}

function buildJsonLdInjection(html, rule) {
  if (!rule) return null;
  const payload = rule.ld_json;
  if (!payload) return null;

  const parts = splitRuleSelectors(payload);
  if (parts.length < 2) return null;

  const [paywallSelector, articleSelector, articleAppend, articleHold] = parts;
  const scripts = parseJsonLdScripts(html);
  let jsonText = null;

  const findText = (json) => {
    if (!json) return null;
    return findKeyJson(json, [/^articlebody$/i, /^text$/i]);
  };

  for (const script of scripts) {
    if (Array.isArray(script)) {
      for (const entry of script) {
        jsonText = findText(entry);
        if (jsonText) break;
      }
    } else if (script['@graph'] && Array.isArray(script['@graph'])) {
      for (const entry of script['@graph']) {
        jsonText = findText(entry);
        if (jsonText) break;
      }
    } else {
      jsonText = findText(script);
    }
    if (jsonText) break;
  }

  if (!jsonText) return null;

  let normalizedText = decodeHtmlEntities(jsonText)
    .replace(/[\r\n]/g, '')
    .replace(/(\\r)?\\n/g, '<br>')
    .replace(/\[[^\[]+]/g, '');

  if (!normalizedText.match(/\s(src|href)=/)) {
    normalizedText = normalizedText.replace(/\n\n/g, '<br><br>');
  }

  const sanitized = sanitizeHtmlSnippet(normalizedText);

  return {
    paywallSelector,
    articleSelector,
    html: `<div style="margin: 25px 0px">${sanitized}</div>`,
    append: toBooleanFlag(articleAppend) || toBooleanFlag(articleHold)
  };
}

function buildNextDataInjection(html, rule) {
  if (!rule || !rule.ld_json_next) return null;
  const parts = splitRuleSelectors(rule.ld_json_next);
  if (parts.length < 2) return null;

  const [paywallSelector, articleSelector, articleAppend, articleHold] = parts;
  const data = extractNextDataJson(html);
  if (!data) return null;

  const jsonText = findKeyJson(data, ['blocks', 'body', 'BodyPlainText', 'content', 'contentHtml', 'description', 'html'], 500);
  if (!jsonText) return null;

  let normalizedText = jsonText;
  if (Array.isArray(jsonText)) {
    normalizedText = jsonText.map((item) => {
      if (typeof item === 'string') return item;
      if (item && typeof item === 'object') {
        if (item.text) return item.text;
        if (item.children) return item.children.map((child) => child.text || '').join('');
        if (item.innerHTML) return item.innerHTML;
      }
      return '';
    }).join('<br><br>');
  }

  normalizedText = decodeHtmlEntities(String(normalizedText));
  const sanitized = sanitizeHtmlSnippet(normalizedText);

  return {
    paywallSelector,
    articleSelector,
    html: `<div>${sanitized}</div>`,
    append: toBooleanFlag(articleAppend) || toBooleanFlag(articleHold)
  };
}

function buildSourceJsonInjection(html, rule) {
  if (!rule || !rule.ld_json_source) return null;
  const parts = splitRuleSelectors(rule.ld_json_source);
  if (parts.length < 4) return null;

  const [paywallSelector, articleSelector, filterText, jsonKey, articleAppend, articleHold] = parts;
  const filterRegex = new RegExp(filterText.replace(/\./g, '\\.').replace('=', '\\s?=\\s?'));
  const json = extractSourceJson(html, filterRegex);
  if (!json) return null;

  const jsonValue = getNestedKeys(json, jsonKey);
  if (!jsonValue) return null;

  const normalizedText = decodeHtmlEntities(String(jsonValue));
  const sanitized = sanitizeHtmlSnippet(normalizedText);

  return {
    paywallSelector,
    articleSelector,
    html: `<div>${sanitized}</div>`,
    append: toBooleanFlag(articleAppend) || toBooleanFlag(articleHold)
  };
}

async function buildJsonUrlInjection(html, rule, targetUrl) {
  if (!rule || !rule.ld_json_url) return null;
  const parts = splitRuleSelectors(rule.ld_json_url);
  if (parts.length < 2) return null;

  const [paywallSelector, articleSelector, articleAppend, articleHold, articleIdSelector, key, urlRest, urlSlash] = parts;

  let jsonUrl = null;
  const linkMatch = html.match(/<link[^>]*rel=["']alternate["'][^>]*type=["']application\/json["'][^>]*href=["']([^"']+)["'][^>]*>/i);
  if (linkMatch) {
    jsonUrl = linkMatch[1];
  }

  if (!jsonUrl && articleIdSelector) {
    const selectorMatch = articleIdSelector.match(new RegExp("meta\\\\[([^=]+)=['\\\"]([^'\\\"]+)['\\\"]\\\\]", 'i'));
    if (selectorMatch) {
      const attr = selectorMatch[1].trim();
      const val = selectorMatch[2].trim();
      const metaRegex = new RegExp(`<meta[^>]*${escapeRegExp(attr)}=["']${escapeRegExp(val)}["'][^>]*content=["']([^"']+)["'][^>]*>`, 'i');
      const metaMatch = html.match(metaRegex);
      if (metaMatch) {
        const articleId = metaMatch[1];
        jsonUrl = `${targetUrl.origin}/wp-json/wp/v2/posts/${articleId}`;
      }
    }
  }

  if (!jsonUrl) return null;

  const useUrlRest = urlRest && (toBooleanFlag(urlRest) || String(urlRest).toLowerCase().includes('rest'));
  const useUrlSlash = (urlSlash && (toBooleanFlag(urlSlash) || String(urlSlash).toLowerCase().includes('slash'))) ||
    (urlRest && String(urlRest).toLowerCase().includes('slash'));

  if (useUrlRest) {
    jsonUrl = jsonUrl.replace('/wp-json/', '/?rest_route=/');
  } else if (useUrlSlash) {
    jsonUrl = jsonUrl.replace('/wp-json/', '//wp-json/');
  }

  try {
    const jsonHeaders = getRuleHeaderOverrides(rule);
    if (!Object.prototype.hasOwnProperty.call(jsonHeaders, 'Accept')) {
      jsonHeaders['Accept'] = 'application/json';
    }
    const response = await fetch(jsonUrl, { headers: jsonHeaders });
    if (!response.ok) return null;
    const raw = await response.text();
    const cleaned = raw.replace(/<script>[\s\S]*?<\/script>/gi, '');
    const json = JSON.parse(cleaned);
    const jsonValue = key ? getNestedKeys(json, key) : json?.content?.rendered;
    if (!jsonValue) return null;
    const normalizedText = decodeHtmlEntities(String(jsonValue));
    const sanitized = sanitizeHtmlSnippet(normalizedText);
    return {
      paywallSelector,
      articleSelector,
      html: `<div style="margin: 25px 0px">${sanitized}</div>`,
      append: toBooleanFlag(articleAppend) || toBooleanFlag(articleHold)
    };
  } catch (error) {
    console.warn('Failed to fetch JSON URL:', error);
    return null;
  }
}

function parseJsonLdScripts(html) {
  const results = [];
  const regex = /<script[^>]*type=["']application\/ld\+json["'][^>]*>([\s\S]*?)<\/script>/gi;
  let match = null;
  while ((match = regex.exec(html)) !== null) {
    try {
      const jsonText = match[1].trim();
      if (!jsonText) continue;
      const parsed = JSON.parse(jsonText);
      results.push(parsed);
    } catch (error) {
      continue;
    }
  }
  return results;
}

function findKeyJson(source, keys, minLength = 0) {
  if (!source || typeof source !== 'object') return null;

  const keyList = Array.isArray(keys) ? keys : [keys];
  for (const [key, value] of Object.entries(source)) {
    if (typeof value === 'string') {
      const matched = keyList.some((k) => (k instanceof RegExp ? k.test(key) : k === key));
      if (matched && value.length >= minLength) {
        return value;
      }
    } else if (Array.isArray(value)) {
      const matched = keyList.some((k) => (k instanceof RegExp ? k.test(key) : k === key));
      if (matched && value.length) {
        return value;
      }
    } else if (value && typeof value === 'object') {
      const nested = findKeyJson(value, keys, minLength);
      if (nested) return nested;
    }
  }
  return null;
}

function getNestedKeys(obj, keyPath) {
  if (!obj || !keyPath) return null;
  if (Object.prototype.hasOwnProperty.call(obj, keyPath)) {
    return obj[keyPath];
  }
  const keys = keyPath.split('.');
  let value = obj;
  for (const key of keys) {
    if (value && typeof value === 'object') {
      value = value[key];
    } else {
      return null;
    }
  }
  return value;
}

function extractNextDataJson(html) {
  const match = html.match(/<script[^>]*id=["']__NEXT_DATA__["'][^>]*>([\s\S]*?)<\/script>/i);
  if (!match) return null;
  try {
    return JSON.parse(match[1]);
  } catch (error) {
    return null;
  }
}

function extractSourceJson(html, filter) {
  const scripts = html.match(/<script[^>]*>([\s\S]*?)<\/script>/gi) || [];
  for (const script of scripts) {
    const contentMatch = script.match(/<script[^>]*>([\s\S]*?)<\/script>/i);
    const content = contentMatch ? contentMatch[1] : '';
    if (!filter.test(content)) continue;
    const index = content.search(filter);
    if (index === -1) continue;
    const after = content.slice(index);
    const firstBrace = after.indexOf('{');
    if (firstBrace === -1) continue;
    const jsonCandidate = extractBalancedJson(after.slice(firstBrace));
    if (!jsonCandidate) continue;
    try {
      return JSON.parse(jsonCandidate);
    } catch (error) {
      continue;
    }
  }
  return null;
}

function extractBalancedJson(text) {
  let depth = 0;
  let start = -1;
  for (let i = 0; i < text.length; i++) {
    const char = text[i];
    if (char === '{') {
      if (depth === 0) start = i;
      depth++;
    } else if (char === '}') {
      depth--;
      if (depth === 0 && start !== -1) {
        return text.slice(start, i + 1);
      }
    }
  }
  return null;
}

/**
 * Load rules from RULESET_URL with local/remote manifest comparison
 */
async function loadRulesFromUrl(env) {
  try {
    if (!env.RULESET_URL) {
      throw new Error('RULESET_URL is required. Set it in wrangler.toml [vars] or environment variables.');
    }

    console.log('Fetching remote ruleset from:', env.RULESET_URL);

    if (env.CONFIG_KV) {
      const keys = getRulesetCacheKeys(env.RULESET_URL);
      const cached = await env.CONFIG_KV.get(keys.dataKey, { type: 'json' });
      if (cached && cached.timestamp && (Date.now() - cached.timestamp) < RULES_CACHE_TTL) {
        const meta = await env.CONFIG_KV.get(keys.metaKey, { type: 'json' });
        if (meta?.ruleset_version) {
          rulesetVersion = meta.ruleset_version;
        }
        return cached.data || {};
      }
    }

    const refreshResult = await refreshRulesetCache(env, { reason: 'request', force: true });
    if (refreshResult.rulesData) {
      return refreshResult.rulesData;
    }

    throw new Error('Failed to load ruleset data after refresh');
  } catch (error) {
    console.error('Error loading rules from RULESET_URL:', error);
    throw error; // Re-throw to fail fast without fallback
  }
}

/**
 * Load rules from new manifest format (sites_aggregated_yaml/json)
 */
async function loadRulesFromNewManifest(manifest, env) {
  try {
    // Prefer JSON for performance, fallback to YAML
    if (manifest.sites_aggregated_json?.url) {
      console.log('Loading rules from manifest JSON URL:', manifest.sites_aggregated_json.url);
      const response = await fetch(manifest.sites_aggregated_json.url);
      if (response.ok) {
        const jsonRules = await response.json();
        return convertJsonToRuleFormat(jsonRules);
      }
    }

    if (manifest.sites_aggregated_yaml?.url) {
      console.log('Loading rules from manifest YAML URL:', manifest.sites_aggregated_yaml.url);
      const response = await fetch(manifest.sites_aggregated_yaml.url);
      if (response.ok) {
        const yamlText = await response.text();
        return parseYamlRules(yamlText);
      }
    }

    console.warn('No valid ruleset URLs in new manifest format');
    return {};
  } catch (error) {
    console.warn('Error loading rules from new manifest:', error);
    return {};
  }
}

/**
 * Load rules from manifest.json format
 */
async function loadRulesFromManifest(manifest, env) {
  try {
    const rules = {};

    // Load base sites from sites.js/sites.json
    if (manifest.sites_js_url) {
      try {
        const response = await fetch(manifest.sites_js_url, { cf: { cacheTtl: 3600 } });
        if (response.ok) {
          const jsText = await response.text();
          // Extract JSON from JS variable assignment
          const jsonMatch = jsText.match(/const\s+sites\s*=\s*({[\s\S]*?});?\s*$/);
          if (jsonMatch) {
            const baseSites = JSON.parse(jsonMatch[1]);
            Object.assign(rules, baseSites);
          }
        }
      } catch (error) {
        console.warn('Error loading sites.js:', error);
      }
    } else if (manifest.sites_json_url) {
      try {
        const response = await fetch(manifest.sites_json_url, { cf: { cacheTtl: 3600 } });
        if (response.ok) {
          const baseSites = await response.json();
          Object.assign(rules, baseSites);
        }
      } catch (error) {
        console.warn('Error loading sites.json:', error);
      }
    }

    // Load updated sites
    if (manifest.sites_updated_url) {
      try {
        const response = await fetch(manifest.sites_updated_url, { cf: { cacheTtl: 3600 } });
        if (response.ok) {
          const updatedSites = await response.json();
          Object.assign(rules, updatedSites);
        }
      } catch (error) {
        console.warn('Error loading sites_updated.json:', error);
      }
    }

    return rules;
  } catch (error) {
    console.warn('Error loading rules from manifest:', error);
    return {};
  }
}

/**
 * Convert JSON array format to Chrome extension rule format
 */
function convertJsonToRuleFormat(jsonArray) {
  try {
    const rules = {};

    if (Array.isArray(jsonArray)) {
      jsonArray.forEach((rule, index) => {
        if (rule.domain) {
          // Use domain as key, or create a unique key if domain is duplicated
          let key = rule.domain;
          if (rules[key]) {
            key = `${rule.domain}_${index}`;
          }
          rules[key] = rule;
        }
      });
    }

    console.log(`Converted ${Object.keys(rules).length} JSON rules to Chrome extension format`);
    return rules;
  } catch (error) {
    console.warn('Error converting JSON rules:', error);
    return {};
  }
}

/**
 * Parse YAML rules (simple parser for aggregated format)
 */
function parseYamlRules(yamlText) {
  try {
    // Simple YAML parser for aggregated ruleset format
    const rules = {};
    const lines = yamlText.split('\n');
    let currentSite = null;
    let currentRule = {};

    for (const line of lines) {
      const trimmed = line.trim();

      if (!trimmed || trimmed.startsWith('#')) continue;

      // Site entry (starts with domain name followed by colon)
      if (trimmed.match(/^[a-zA-Z0-9.-]+:$/)) {
        if (currentSite && Object.keys(currentRule).length > 0) {
          rules[currentSite] = currentRule;
        }
        currentSite = trimmed.slice(0, -1);
        currentRule = { domain: currentSite };
        continue;
      }

      // Property assignment
      const match = trimmed.match(/^([a-zA-Z_]+):\s*(.*)$/);
      if (match && currentSite) {
        const [, key, value] = match;

        // Parse different value types
        if (value === 'true') currentRule[key] = true;
        else if (value === 'false') currentRule[key] = false;
        else if (value.match(/^\d+$/)) currentRule[key] = parseInt(value);
        else if (value.startsWith('[') && value.endsWith(']')) {
          // Simple array parsing
          currentRule[key] = value.slice(1, -1).split(',').map(s => s.trim().replace(/^["']|["']$/g, ''));
        } else {
          currentRule[key] = value.replace(/^["']|["']$/g, '');
        }
      }
    }

    // Add final rule
    if (currentSite && Object.keys(currentRule).length > 0) {
      rules[currentSite] = currentRule;
    }

    return rules;
  } catch (error) {
    console.warn('Error parsing YAML rules:', error);
    return {};
  }
}

/**
 * Load updated rules from bpc_updates endpoint (fallback)
 */
async function loadUpdatedSites(env) {
  try {
    // Try to get cached updated rules first
    if (env.CONFIG_KV) {
      const cached = await env.CONFIG_KV.get('sites_updated', { type: 'json' });
      if (cached && cached.timestamp && (Date.now() - cached.timestamp) < RULES_CACHE_TTL) {
        return cached.data || {};
      }
    }

    // Fetch fresh updated rules
    const response = await fetch('https://bpc-update.andrewe.workers.dev/sites_updated.json', {
      cf: { cacheTtl: 3600 }
    });

    if (!response.ok) {
      console.warn('Failed to fetch sites_updated.json:', response.status);
      return {};
    }

    const updatedSites = await response.json();

    // Cache the updated rules
    if (env.CONFIG_KV) {
      await env.CONFIG_KV.put('sites_updated', JSON.stringify({
        data: updatedSites,
        timestamp: Date.now()
      }), { expirationTtl: RULES_CACHE_TTL });
    }

    return updatedSites;
  } catch (error) {
    console.warn('Error loading updated sites:', error);
    return {};
  }
}

/**
 * Load custom user rules from KV storage
 */
async function loadCustomSites(env) {
  try {
    if (!env.CONFIG_KV) return {};

    const customSites = await env.CONFIG_KV.get('sites_custom', { type: 'json' });
    return customSites || {};
  } catch (error) {
    console.warn('Error loading custom sites:', error);
    return {};
  }
}

/**
 * Aggregate rules from all three sources with ### deletion support
 * Priority: custom > updated > base
 */
function aggregateRules(baseSites, updatedSites, customSites) {
  // Start with expanded base rules
  let finalRules = expandSiteRules(baseSites);

  // Apply updates (can add, modify, or DELETE via ###)
  for (const [name, rule] of Object.entries(updatedSites)) {
    if (isDeletionRule(rule)) {
      delete finalRules[name]; // Remove from final ruleset
      console.log(`Deleted rule via updates: ${name}`);
    } else {
      finalRules[name] = rule; // Replace rule (extension precedence)
    }
  }

  // Apply custom rules (highest priority)
  for (const [name, rule] of Object.entries(customSites)) {
    if (isDeletionRule(rule)) {
      delete finalRules[name]; // User can delete any rule
      console.log(`Deleted rule via custom: ${name}`);
    } else {
      finalRules[name] = rule; // Replace with user rule
    }
  }

  return finalRules;
}

/**
 * Get aggregated rules (cached for performance)
 */
async function getAggregatedRules(env) {
  await maybeRefreshInMemoryRules(env);

  // Return cached rules if still valid
  if (aggregatedRules && rulesLastUpdated &&
      (Date.now() - rulesLastUpdated) < RULES_CACHE_TTL) {
    return aggregatedRules;
  }

  console.log('Loading and aggregating rules...');

  // Load rule sources from remote URL and custom rules
  const [updatedSites, customSites] = await Promise.all([
    loadRulesFromUrl(env),      // Rules from RULESET_URL (required)
    loadCustomSites(env)        // Custom user rules
  ]);

  // Aggregate with deletion support (no base rules)
  aggregatedRules = aggregateRules({}, updatedSites, customSites);
  rulesLastUpdated = Date.now();

  const totalRules = Object.keys(aggregatedRules).length;
  const updatedCount = Object.keys(updatedSites).length;
  const customCount = Object.keys(customSites).length;

  console.log(`Rules aggregated: ${totalRules} total (${updatedCount} remote + ${customCount} custom)`);

  return aggregatedRules;
}

/**
 * Apply Chrome Extension rule processing (Phase 4)
 * Handles cookies, content blocking, and HTML modification
 */
async function applyChromExtensionRules(content, targetURL, response, rule, env, globalRegexes = []) {
  const url = new URL(targetURL);
  const contentType = response.headers.get('Content-Type') || 'text/html';
  const isHtml = contentType.includes('text/html');

  // Default processing result
  let processedContent = content;
  const responseHeaders = {
    'Content-Type': contentType,
    'Cache-Control': 'public, max-age=300'
  };

  // Apply URL rewriting for HTML content (keep our fix for CSS)
  if (isHtml) {
    processedContent = rewriteHTMLBasic(processedContent, url.host);
  }

  // If no matching rule found, return basic processing
  if (!rule) {
    console.log(`No rule found for ${url.hostname}, applying basic processing only`);
    return {
      content: processedContent,
      headers: responseHeaders
    };
  }

  console.log(`Applying rule for ${url.hostname}:`, {
    allow_cookies: rule.allow_cookies,
    block_regex: !!rule.block_regex,
    cs_dompurify: rule.cs_dompurify,
    remove_cookies_select_drop: rule.remove_cookies_select_drop
  });

  // Cookie Management
  const setCookieHeader = response.headers.get('Set-Cookie');
  const filteredSetCookie = filterSetCookieHeaders(setCookieHeader, rule);
  if (filteredSetCookie) {
    responseHeaders['Set-Cookie'] = filteredSetCookie;
  }

  // Inline JS blocking via CSP (when rule matches URL)
  if (rule.block_js_inline) {
    const regex = buildRegex(rule.block_js_inline, rule.domain);
    if (regex && regex.test(targetURL)) {
      const existingCsp = response.headers.get('Content-Security-Policy');
      if (!existingCsp || !existingCsp.includes('script-src')) {
        responseHeaders['Content-Security-Policy'] = existingCsp
          ? `${existingCsp}; script-src *`
          : 'script-src *';
      }
    }
  }

  if (rule.cs_dompurify) {
    responseHeaders['X-Content-Sanitized'] = 'true';
  }

  if (!isHtml) {
    return {
      content: processedContent,
      headers: responseHeaders
    };
  }

  const headSnippets = [];
  if (rule.cs_clear_lclstrg) {
    headSnippets.push('<script>try{localStorage.clear();sessionStorage.clear();}catch(e){}</script>');
  }

  const rewriter = new HTMLRewriter();

  const csActions = expandCsCodeActions(rule.cs_code || []);
  registerCsCodeHandlers(rewriter, csActions, headSnippets);

  if (headSnippets.length) {
    rewriter.on('head', {
      element(element) {
        for (const snippet of headSnippets) {
          element.append(snippet, { html: true });
        }
      }
    });
  }

  registerBlockedResourceHandlers(rewriter, rule, targetURL, globalRegexes);

  if (rule.block_js_inline) {
    const regex = buildRegex(rule.block_js_inline, rule.domain);
    if (regex && regex.test(targetURL)) {
      rewriter.on('script:not([src])', {
        element(element) {
          element.remove();
        }
      });
    }
  }

  if (rule.add_ext_link && rule.add_ext_link_type) {
    const [paywallSel, articleSel] = splitRuleSelectors(rule.add_ext_link);
    if (paywallSel) {
      rewriter.on(paywallSel, {
        element(element) {
          element.remove();
        }
      });
    }
    if (articleSel) {
      const externalHtml = buildExternalLinkHtml(targetURL, rule.add_ext_link_type);
      rewriter.on(articleSel, {
        element(element) {
          element.prepend(externalHtml, { html: true });
        }
      });
    }
  }

  let jsonInjection = buildJsonLdInjection(processedContent, rule);
  if (!jsonInjection) {
    jsonInjection = buildNextDataInjection(processedContent, rule);
  }
  if (!jsonInjection) {
    jsonInjection = buildSourceJsonInjection(processedContent, rule);
  }
  if (!jsonInjection) {
    jsonInjection = await buildJsonUrlInjection(processedContent, rule, url);
  }

  if (jsonInjection) {
    if (jsonInjection.paywallSelector) {
      rewriter.on(jsonInjection.paywallSelector, {
        element(element) {
          element.remove();
        }
      });
    }
    if (jsonInjection.articleSelector) {
      rewriter.on(jsonInjection.articleSelector, {
        element(element) {
          if (jsonInjection.append) {
            element.append(jsonInjection.html, { html: true });
          } else {
            element.setInnerContent(jsonInjection.html, { html: true });
          }
        }
      });
    }
  }

  if (rule.ld_archive_is) {
    const parts = splitRuleSelectors(rule.ld_archive_is);
    const paywallSel = parts[0];
    const articleSel = parts[1];
    if (paywallSel) {
      rewriter.on(paywallSel, {
        element(element) {
          element.remove();
        }
      });
    }
    if (articleSel) {
      const externalHtml = buildExternalLinkHtml(targetURL, 'archive.is');
      rewriter.on(articleSel, {
        element(element) {
          element.prepend(externalHtml, { html: true });
        }
      });
    }
  }

  if (rule.amp_unhide) {
    rewriter.on('[amp-access-hide]', {
      element(element) {
        element.removeAttribute('amp-access-hide');
        const existing = element.getAttribute('style') || '';
        element.setAttribute('style', `${existing} display:block !important;`);
      }
    });
    rewriter.on('[subscriptions-section="content"]', {
      element(element) {
        const existing = element.getAttribute('style') || '';
        element.setAttribute('style', `${existing} display:block !important;`);
      }
    });
  }

  const transformed = await rewriter
    .transform(new Response(processedContent, { headers: { 'Content-Type': 'text/html' } }))
    .text();

  return {
    content: transformed,
    headers: responseHeaders
  };
}

// Static assets mapping
const STATIC_ASSETS = {
  '/': 'index.html',
  '/index.html': 'index.html',
  '/styles.css': 'styles.css',
  '/ladder.svg': 'ladder.svg',
  '/share-icon.svg': 'share-icon.svg',
  '/wasm_exec.js': 'wasm_exec.js'
};

// MIME type mapping
const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.wasm': 'application/wasm'
};

// Global WASM instance
let wasmInstance = null;
let goInstance = null;

// Phase 5 Analytics and Performance Tracking
let requestCount = 0;
let errorCount = 0;
let startTime = Date.now();

// Polyfills for Cloudflare Workers environment
function setupPolyfills() {
  if (!globalThis.crypto) {
    globalThis.crypto = crypto;
  }
  if (!globalThis.performance) {
    globalThis.performance = {
      now: () => Date.now()
    };
  }
  if (!globalThis.TextEncoder) {
    globalThis.TextEncoder = TextEncoder;
  }
  if (!globalThis.TextDecoder) {
    globalThis.TextDecoder = TextDecoder;
  }
}

/**
 * Phase 5 Enterprise Analytics Functions
 */
async function trackRequest(env, requestInfo) {
  try {
    requestCount++;

    // Usage indicator with aggregate count (no personal data)
    if (env.ANALYTICS_KV) {
      const today = new Date().toISOString().split('T')[0];
      const countKey = `count_${today}`;

      // Get current count and increment
      const currentCount = await env.ANALYTICS_KV.get(countKey);
      const newCount = currentCount ? parseInt(currentCount) + 1 : 1;

      await env.ANALYTICS_KV.put(countKey, newCount.toString(), {
        expirationTtl: 86400 // 24 hours
      });
    }
  } catch (error) {
    console.error('Usage tracking error:', error);
  }
}

async function trackError(env, errorInfo) {
  try {
    errorCount++;

    // Error count with aggregate total (no personal data)
    if (env.ANALYTICS_KV) {
      const today = new Date().toISOString().split('T')[0];
      const errorKey = `errors_${today}`;

      // Get current error count and increment
      const currentErrors = await env.ANALYTICS_KV.get(errorKey);
      const newErrorCount = currentErrors ? parseInt(currentErrors) + 1 : 1;

      await env.ANALYTICS_KV.put(errorKey, newErrorCount.toString(), {
        expirationTtl: 86400 // 24 hours
      });
    }
  } catch (error) {
    console.error('Error tracking error:', error);
  }
}

async function getCachedContent(env, cacheKey) {
  try {
    if (!env.CACHE_KV) return null;

    const cached = await env.CACHE_KV.get(cacheKey, 'json');
    if (cached && cached.expires > Date.now()) {
      return cached.content;
    }
    return null;
  } catch (error) {
    console.error('Cache retrieval error:', error);
    return null;
  }
}

async function setCachedContent(env, cacheKey, content, ttlSeconds = 3600) {
  try {
    if (!env.CACHE_KV) return;

    const cacheData = {
      content,
      expires: Date.now() + (ttlSeconds * 1000),
      cached_at: Date.now()
    };

    await env.CACHE_KV.put(cacheKey, JSON.stringify(cacheData), {
      expirationTtl: ttlSeconds
    });
  } catch (error) {
    console.error('Cache storage error:', error);
  }
}

async function getRateLimitStatus(env, clientIP) {
  try {
    if (!env.ANALYTICS_KV) return { allowed: true, remaining: 1000 };

    const minute = Math.floor(Date.now() / 60000);
    const key = `ratelimit_${clientIP}_${minute}`;
    const current = await env.ANALYTICS_KV.get(key);
    const count = current ? parseInt(current) : 0;

    const limit = 100; // requests per minute
    const remaining = Math.max(0, limit - count);

    if (count >= limit) {
      return { allowed: false, remaining: 0, resetTime: (minute + 1) * 60000 };
    }

    await env.ANALYTICS_KV.put(key, (count + 1).toString(), { expirationTtl: 60 });
    return { allowed: true, remaining: remaining - 1 };
  } catch (error) {
    console.error('Rate limit check error:', error);
    return { allowed: true, remaining: 1000 };
  }
}

/**
 * Initialize the WASM module
 */
async function initWasm(env) {
  if (wasmInstance) {
    return wasmInstance;
  }

  // Setup required polyfills
  setupPolyfills();

  // Pass environment variables to WASM
  if (env && env.USER_AGENT) {
    globalThis.USER_AGENT_ENV = env.USER_AGENT;
  }
  if (env && env.X_FORWARDED_FOR) {
    globalThis.X_FORWARDED_FOR_ENV = env.X_FORWARDED_FOR;
  }
  if (env && env.RULESET_URL) {
    globalThis.RULESET_URL = env.RULESET_URL;
  }

  // Create Go instance
  goInstance = new Go();

  // Instantiate the WASM module
  const instantiated = await WebAssembly.instantiate(wasm, goInstance.importObject);
  const instance = instantiated instanceof WebAssembly.Instance ? instantiated : instantiated.instance;
  if (!instance) {
    throw new Error('Failed to instantiate WASM module');
  }

  // Start the Go program but don't wait for it to complete
  // The Go program will run in the background and set up the global functions
  let runPromise;
  try {
    runPromise = goInstance.run(instance);
  } catch (error) {
    console.error('Go WASM run failed:', error);
    throw error;
  }
  if (runPromise && typeof runPromise.then === 'function') {
    runPromise.catch((error) => {
      console.error('Go WASM runtime failed:', error);
    });
  }

  wasmInstance = instance;

  // Wait for handleRequest to be registered by the Go runtime
  for (let attempt = 0; attempt < 50; attempt++) {
    if (globalThis.handleRequest) {
      console.log('Ladderflare WASM initialized');
      return instance;
    }
    await new Promise(resolve => setTimeout(resolve, 20));
  }

  console.warn('WASM initialized but handleRequest is still unavailable');
  return instance;
}

/**
 * Serve static assets
 */
async function serveStaticAsset(pathname, env) {
  const assetPath = STATIC_ASSETS[pathname];
  if (!assetPath) {
    return null;
  }

  try {
    // Get the asset from the public directory
    const asset = await env.ASSETS.fetch(new URL(pathname, 'https://placeholder.com').href);
    if (!asset.ok) {
      return null;
    }

    // Determine content type
    const extension = '.' + assetPath.split('.').pop();
    const contentType = MIME_TYPES[extension] || 'application/octet-stream';

    return new Response(asset.body, {
      headers: {
        'Content-Type': contentType,
        'Cache-Control': 'public, max-age=3600'
      }
    });
  } catch (error) {
    console.error('Error serving static asset:', error);
    return null;
  }
}

/**
 * Call the WASM handler function
 */
function callWasmHandler(method, path, headers) {
  try {
    // Check if the Go function is available
    if (!globalThis.handleRequest) {
      throw new Error('WASM handleRequest function not available');
    }

    // Convert headers to JavaScript object
    const headerObj = {};
    for (const [key, value] of headers.entries()) {
      headerObj[key.toLowerCase()] = value;
    }

    // Call the Go function
    const result = globalThis.handleRequest(method, path, headerObj);

    // Ensure result is a valid object
    if (!result || typeof result !== 'object') {
      return {
        status: 500,
        body: 'Invalid WASM response format',
        headers: { 'Content-Type': 'text/plain' }
      };
    }

    return result;
  } catch (error) {
    console.error('Error calling WASM handler:', error);
    return {
      status: 500,
      body: `WASM handler error: ${error.message}`,
      headers: { 'Content-Type': 'text/plain' }
    };
  }
}

/**
 * Fetch and process proxied content
 */
async function fetchProxiedContent(targetURL, env, request, options = {}) {
  try {
    // Phase 5 Caching: Check cache first
    const cacheKey = `content_${encodeURIComponent(targetURL)}`;
    const cachedContent = await getCachedContent(env, cacheKey);
    if (cachedContent) {
      return cachedContent;
    }
    // Get fetch instructions from WASM
    const fetchInstructions = globalThis.fetchURL ? globalThis.fetchURL(targetURL) : null;

    if (!fetchInstructions) {
      throw new Error('WASM fetchURL function not available');
    }

    // Get Chrome extension rule for user agent override
    const url = new URL(targetURL);
    const rules = await getAggregatedRules(env);
    const matchingRule = findRuleForDomain(url.hostname, rules);
    const globalRegexes = getGlobalBlockRegexesForDomain(rules, url.hostname);
    const clientUserAgent = request?.headers?.get('User-Agent') || '';

    if (shouldBlockUrl(targetURL, matchingRule, globalRegexes)) {
      return {
        status: 403,
        body: 'Blocked by ruleset',
        headers: { 'Content-Type': 'text/plain' }
      };
    }

    const headers = resolveRequestHeaders(matchingRule, env, url, clientUserAgent, fetchInstructions);

    // Fetch the target URL
    const response = await fetch(targetURL, {
      headers,
      cf: {
        // Cloudflare-specific options
        cacheTtl: 300, // Cache for 5 minutes
        cacheEverything: true
      }
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }

    let content = await response.text();

    console.log(`Processing ${url.hostname}, found rule: ${matchingRule ? 'YES' : 'NO'}`);

    if (matchingRule?.ld_archive_is) {
      const archiveSnapshot = await fetchArchiveSnapshot(targetURL);
      if (archiveSnapshot && archiveSnapshot.content) {
        const archiveBody = archiveSnapshot.contentType.includes('text/html')
          ? rewriteHTMLBasic(archiveSnapshot.content, archiveSnapshot.host)
          : archiveSnapshot.content;

        const archiveResult = {
          status: 200,
          body: archiveBody,
          headers: {
            'Content-Type': archiveSnapshot.contentType,
            'Cache-Control': 'public, max-age=300',
            'X-Archive-Source': archiveSnapshot.url
          }
        };

        await setCachedContent(env, cacheKey, archiveResult, 120);
        return archiveResult;
      }
    }

    if (!options.ampAttempt && matchingRule?.amp_redirect) {
      const ampLinkMatch = content.match(/<link[^>]*rel=["']amphtml["'][^>]*href=["']([^"']+)["'][^>]*>/i);
      let ampUrl = ampLinkMatch ? ampLinkMatch[1] : null;

      const parts = splitRuleSelectors(matchingRule.amp_redirect);
      if (parts.length > 1 && parts[1]) {
        ampUrl = parts[1];
        if (ampUrl.includes('{path}')) {
          ampUrl = ampUrl.replace('{path}', url.pathname).replace(/\/\//g, '/');
        }
        if (ampUrl.includes('{host}')) {
          ampUrl = 'https://' + ampUrl.replace('{host}', url.hostname.replace('www.', ''));
        }
      }

      if (ampUrl) {
        let resolvedAmpUrl = ampUrl;
        try {
          resolvedAmpUrl = new URL(ampUrl, url.origin).toString();
        } catch (error) {
          resolvedAmpUrl = ampUrl;
        }

        if (resolvedAmpUrl !== targetURL) {
          try {
            const ampResponse = await fetch(resolvedAmpUrl, { headers });
          if (ampResponse.ok) {
            content = await ampResponse.text();
          }
          } catch (error) {
            console.warn('AMP fetch failed:', error);
          }
        }
      }
    }

    // Apply Chrome extension rule processing
    const processedResult = await applyChromExtensionRules(
      content,
      targetURL,
      response,
      matchingRule,
      env,
      globalRegexes
    );

    const result = {
      status: 200,
      body: processedResult.content,
      headers: processedResult.headers
    };

    // Cache the result briefly for performance
    await setCachedContent(env, cacheKey, result, 120); // 2 minutes TTL

    return result;

  } catch (error) {
    console.error('Error fetching proxied content:', error);
    return {
      status: 500,
      body: `Proxy error: ${error.message}`,
      headers: { 'Content-Type': 'text/plain' }
    };
  }
}

/**
 * Enhanced HTML rewriting with proper URL handling
 */
function rewriteHTMLBasic(content, originalHost) {
  // Step 1: Fix resource files to use absolute URLs

  // CSS files
  content = content.replace(/href="\/([^"]*\.css[^"]*)"/gi,
    `href="https://${originalHost}/$1"`);

  // JavaScript files
  content = content.replace(/src="\/([^"]*\.js[^"]*)"/gi,
    `src="https://${originalHost}/$1"`);

  // Font files
  content = content.replace(/href="\/([^"]*\.(woff2?|ttf|otf|eot)[^"]*)"/gi,
    `href="https://${originalHost}/$1"`);
  content = content.replace(/src="\/([^"]*\.(woff2?|ttf|otf|eot)[^"]*)"/gi,
    `src="https://${originalHost}/$1"`);

  // Image files
  content = content.replace(/src="\/([^"]*\.(png|jpg|jpeg|gif|svg|webp|ico)[^"]*)"/gi,
    `src="https://${originalHost}/$1"`);

  // CSS url() statements
  content = content.replace(/url\(['"]?\/([^'"]*)/gi,
    `url("https://${originalHost}/$1`);

  // Step 2: Navigation links - convert remaining href to proxy URLs
  content = content.replace(/href="\/([^"]*)"/gi, (match, path) => {
    // Skip if it's a resource file (already converted to absolute above)
    if (path.match(/\.(css|js|woff2?|ttf|otf|eot|png|jpg|jpeg|gif|svg|webp|ico)(\?|$)/i)) {
      return match; // Keep as-is (should already be absolute)
    }
    return `href="/https://${originalHost}/${path}"`;
  });

  return content;
}

/**
 * Apply content injections from ruleset
 */
function applyContentInjections(content, injections) {
  for (const injection of injections) {
    const position = injection.position || 'head';

    if (injection.append) {
      // Append content to the specified position
      if (position === 'head') {
        content = content.replace(/<\/head>/i, `${injection.append}\n</head>`);
      } else if (position === 'body') {
        content = content.replace(/<\/body>/i, `${injection.append}\n</body>`);
      } else {
        // Try to find the position selector and append after it
        const positionRegex = new RegExp(`(<${position}[^>]*>)`, 'i');
        content = content.replace(positionRegex, `$1${injection.append}`);
      }
    }

    if (injection.prepend) {
      // Prepend content to the specified position
      if (position === 'head') {
        content = content.replace(/<head[^>]*>/i, `$&\n${injection.prepend}`);
      } else if (position === 'body') {
        content = content.replace(/<body[^>]*>/i, `$&\n${injection.prepend}`);
      } else {
        // Try to find the position selector and prepend to it
        const positionRegex = new RegExp(`(<${position}[^>]*>)`, 'i');
        content = content.replace(positionRegex, `$1${injection.prepend}`);
      }
    }

    if (injection.replace) {
      // Replace the entire element at the specified position
      if (position === 'head') {
        content = content.replace(/<head[^>]*>[\s\S]*?<\/head>/i, `<head>${injection.replace}</head>`);
      } else if (position === 'body') {
        content = content.replace(/<body[^>]*>[\s\S]*?<\/body>/i, `<body>${injection.replace}</body>`);
      } else {
        // Try to replace the specific selector
        const positionRegex = new RegExp(`<${position}[^>]*>[\\s\\S]*?<\\/${position}>`, 'i');
        content = content.replace(positionRegex, injection.replace);
      }
    }
  }

  return content;
}

/**
 * Check Basic Authentication
 */
function checkBasicAuth(request, env) {
  const username = env.USERNAME;
  const password = env.PASSWORD;

  if (!username || !password) {
    return true; // No auth required if either username or password is missing
  }

  const authHeader = request.headers.get('Authorization');
  if (!authHeader || !authHeader.startsWith('Basic ')) {
    return false;
  }

  const encoded = authHeader.substring(6);
  let decoded;
  try {
    decoded = atob(encoded);
  } catch (e) {
    return false;
  }

  // Check USERNAME:PASSWORD format
  return decoded === `${username}:${password}`;
}

/**
 * Check if domain is allowed
 */
async function isDomainAllowed(url, env) {
  const allowedDomains = env.ALLOWED_DOMAINS;

  // If ALLOWED_DOMAINS is not enabled (default: false), allow all
  if (!allowedDomains || (allowedDomains !== "1" && allowedDomains !== "true")) {
    return true;
  }

  const urlObj = new URL(url);
  const domain = urlObj.hostname;

  // ALLOWED_DOMAINS uses ruleset-based checking (exact match and subdomains)
  try {
    // Use our Chrome extension aggregated rules
    const rules = await getAggregatedRules(env);

    // Check if domain exactly matches any rule domain or is a subdomain
    for (const [name, rule] of Object.entries(rules)) {
      if (rule.domain === domain || domain.endsWith('.' + rule.domain)) {
        return true;
      }
    }

    console.log(`Domain '${domain}' not found in ruleset domains (including subdomains)`);
  } catch (error) {
    console.error('Error checking ruleset domains:', error);
    // Fallback to WASM domains if Chrome extension rules fail
    if (globalThis.getRulesetDomains) {
      const rulesetDomains = globalThis.getRulesetDomains();
      if (rulesetDomains && (rulesetDomains.includes(domain) || rulesetDomains.some(d => domain.endsWith('.' + d)))) {
        return true;
      }
    }
  }

  return false;
}

/**
 * Main request handler
 */
export default {
  async fetch(request, env, ctx) {
    try {
      // Initialize WASM on first request
      if (!wasmInstance) {
        await initWasm(env);

        // Give the Go runtime a moment to initialize
        await new Promise(resolve => setTimeout(resolve, 100));
      }

      const url = new URL(request.url);
      const pathname = url.pathname;
      const method = request.method;

      // Check Basic Auth
      if (!checkBasicAuth(request, env)) {
        return new Response('Unauthorized', {
          status: 401,
          headers: {
            'WWW-Authenticate': 'Basic realm="Ladderflare"',
            'Content-Type': 'text/plain'
          }
        });
      }


      // Handle /health endpoint for Phase 4 monitoring
      if (pathname === '/health') {
        const health = {
          status: 'healthy',
          timestamp: new Date().toISOString(),
          wasm: {
            initialized: !!wasmInstance,
            functions_available: {
              handleRequest: !!globalThis.handleRequest,
              fetchURL: !!globalThis.fetchURL,
              processContent: !!globalThis.processContent,
              getRuleset: !!globalThis.getRuleset,
              getRulesetDomains: !!globalThis.getRulesetDomains
            }
          },
          rules: {
            embedded_count: globalThis.getRulesetDomains ? globalThis.getRulesetDomains().length : 0,
            version: rulesetVersion || 'unknown',
            source: env.RULESET_URL || 'embedded'
          },
          version: env.WORKER_VERSION || 'development'
        };

        return new Response(JSON.stringify(health, null, 2), {
          status: 200,
          headers: {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*'
          }
        });
      }

      // Handle /api/stats endpoint for aggregate usage indicators
      if (pathname === '/api/stats') {
        // Get aggregate counts for today (no personal data)
        let dailyRequests = 0;
        let dailyErrors = 0;

        if (env.ANALYTICS_KV) {
          const today = new Date().toISOString().split('T')[0];
          const requestCount = await env.ANALYTICS_KV.get(`count_${today}`);
          const errorCount = await env.ANALYTICS_KV.get(`errors_${today}`);
          dailyRequests = requestCount ? parseInt(requestCount) : 0;
          dailyErrors = errorCount ? parseInt(errorCount) : 0;
        }

        const stats = {
          timestamp: new Date().toISOString(),
          privacy_note: 'Only aggregate counts - no tracking of sites, URLs, or users',
          system: {
            uptime_ms: Date.now() - startTime,
            wasm_initialized: !!wasmInstance,
            rules_loaded: globalThis.getRulesetDomains ? globalThis.getRulesetDomains().length : 0
          },
          usage_indicators: {
            daily_requests: dailyRequests,
            daily_errors: dailyErrors,
            session_requests: requestCount,
            session_errors: errorCount,
            note: 'Aggregate counts only - no personal data stored'
          },
          cache: {
            enabled: !!env.CACHE_KV,
            ttl: '2 minutes for proxied content'
          },
          rate_limiting: {
            enabled: !!env.ANALYTICS_KV,
            limit: '100 req/min per IP'
          },
          version: env.WORKER_VERSION || 'privacy-focused-phase5'
        };

        return new Response(JSON.stringify(stats, null, 2), {
          status: 200,
          headers: {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*'
          }
        });
      }

      // Handle /api/system endpoint for privacy-focused system health
      if (pathname === '/api/system') {
        const systemInfo = {
          timestamp: new Date().toISOString(),
          privacy_policy: 'No URLs, domains, or user data stored',
          data_retention: 'Only aggregate counts (30 days)',
          system_health: {
            wasm_initialized: !!wasmInstance,
            functions_available: Object.keys({
              handleRequest: !!globalThis.handleRequest,
              fetchURL: !!globalThis.fetchURL,
              processContent: !!globalThis.processContent,
              getRuleset: !!globalThis.getRuleset
            }).length,
            storage_available: {
              cache: !!env.CACHE_KV,
              analytics: !!env.ANALYTICS_KV,
              config: !!env.CONFIG_KV
            }
          },
          session_stats: {
            requests_served: requestCount,
            errors_occurred: errorCount,
            uptime_ms: Date.now() - startTime
          },
          note: 'This endpoint provides system health without compromising user privacy'
        };

        return new Response(JSON.stringify(systemInfo, null, 2), {
          status: 200,
          headers: {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*'
          }
        });
      }

      // Handle /api/metrics endpoint for performance monitoring
      if (pathname === '/api/metrics') {
        const metrics = {
          timestamp: new Date().toISOString(),
          performance: {
            uptime_ms: Date.now() - startTime,
            requests_per_second: requestCount > 0 ? requestCount / ((Date.now() - startTime) / 1000) : 0,
            error_rate: requestCount > 0 ? (errorCount / requestCount) * 100 : 0,
            memory_usage: 'N/A - Worker environment'
          },
          health_indicators: {
            wasm_status: !!wasmInstance ? 'healthy' : 'unhealthy',
            functions_available: {
              handleRequest: !!globalThis.handleRequest,
              fetchURL: !!globalThis.fetchURL,
              processContent: !!globalThis.processContent,
              getRuleset: !!globalThis.getRuleset
            },
            storage_status: {
              analytics_kv: !!env.ANALYTICS_KV,
              cache_kv: !!env.CACHE_KV,
              config_kv: !!env.CONFIG_KV
            }
          },
          thresholds: {
            error_rate_warning: 5,
            error_rate_critical: 10,
            response_time_warning: 5000,
            response_time_critical: 10000
          },
          alerts: []
        };

        // Generate alerts based on thresholds
        if (metrics.performance.error_rate > metrics.thresholds.error_rate_critical) {
          metrics.alerts.push({
            level: 'critical',
            message: `Error rate ${metrics.performance.error_rate.toFixed(2)}% exceeds critical threshold`,
            timestamp: new Date().toISOString()
          });
        } else if (metrics.performance.error_rate > metrics.thresholds.error_rate_warning) {
          metrics.alerts.push({
            level: 'warning',
            message: `Error rate ${metrics.performance.error_rate.toFixed(2)}% exceeds warning threshold`,
            timestamp: new Date().toISOString()
          });
        }

        if (!metrics.health_indicators.wasm_status) {
          metrics.alerts.push({
            level: 'critical',
            message: 'WASM module not initialized',
            timestamp: new Date().toISOString()
          });
        }

        return new Response(JSON.stringify(metrics, null, 2), {
          status: 200,
          headers: {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*'
          }
        });
      }

      // Handle static assets (unless DISABLE_FORM is true for form assets)
      if (STATIC_ASSETS[pathname]) {
        // Check if DISABLE_FORM is enabled and this is a form-related asset
        if (env.DISABLE_FORM === 'true' && (pathname === '/' || pathname === '/index.html' || pathname === '/styles.css' || pathname === '/ladder.svg' || pathname === '/share-icon.svg')) {
          return new Response('Form disabled', {
            status: 404,
            headers: { 'Content-Type': 'text/plain' }
          });
        }

        const staticResponse = await serveStaticAsset(pathname, env);
        if (staticResponse) {
          return staticResponse;
        }
      }

      // Handle CORS preflight requests
      if (method === 'OPTIONS') {
        return new Response(null, {
          status: 204,
          headers: {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
            'Access-Control-Allow-Headers': '*'
          }
        });
      }

      // Handle POST API endpoints for Phase 4 management
      if (pathname === '/api/rules/validate' && method === 'POST') {
        try {
          const requestBody = await request.json();
          const rule = requestBody.rule;

          if (!rule || typeof rule !== 'object') {
            return new Response(JSON.stringify({
              valid: false,
              errors: ['Rule must be a valid object']
            }), {
              status: 400,
              headers: {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
              }
            });
          }

          // Basic rule validation
          const errors = [];
          if (!rule.name || typeof rule.name !== 'string') {
            errors.push('Rule must have a name (string)');
          }
          if (!rule.domain && !rule.domains) {
            errors.push('Rule must have either domain or domains');
          }

          return new Response(JSON.stringify({
            valid: errors.length === 0,
            errors: errors,
            rule: rule
          }), {
            status: 200,
            headers: {
              'Content-Type': 'application/json',
              'Access-Control-Allow-Origin': '*'
            }
          });

        } catch (error) {
          return new Response(JSON.stringify({
            valid: false,
            errors: [`Invalid JSON: ${error.message}`]
          }), {
            status: 400,
            headers: {
              'Content-Type': 'application/json',
              'Access-Control-Allow-Origin': '*'
            }
          });
        }
      }

      // Handle /api/rules/custom endpoint - CRUD operations for custom rules
      if (pathname === '/api/rules/custom' && method === 'GET') {
        try {
          const customSites = await loadCustomSites(env);
          return new Response(JSON.stringify({
            success: true,
            rules: customSites,
            count: Object.keys(customSites).length
          }), {
            status: 200,
            headers: {
              'Content-Type': 'application/json',
              'Access-Control-Allow-Origin': '*'
            }
          });
        } catch (error) {
          return new Response(JSON.stringify({
            success: false,
            error: error.message
          }), {
            status: 500,
            headers: {
              'Content-Type': 'application/json',
              'Access-Control-Allow-Origin': '*'
            }
          });
        }
      }

      if (pathname === '/api/rules/custom' && method === 'POST') {
        try {
          const requestBody = await request.json();
          const { name, rule } = requestBody;

          if (!name || !rule) {
            return new Response(JSON.stringify({
              success: false,
              error: 'Both name and rule are required'
            }), {
              status: 400,
              headers: {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
              }
            });
          }

          // Load current custom rules
          const customSites = await loadCustomSites(env);

          // Add/update the rule
          customSites[name] = rule;

          // Save back to KV
          if (env.CONFIG_KV) {
            await env.CONFIG_KV.put('sites_custom', JSON.stringify(customSites));

            // Clear rules cache to force refresh
            rulesLastUpdated = 0;
            aggregatedRules = null;
          }

          return new Response(JSON.stringify({
            success: true,
            message: `Rule '${name}' ${customSites[name] ? 'updated' : 'added'}`,
            rule: rule
          }), {
            status: 200,
            headers: {
              'Content-Type': 'application/json',
              'Access-Control-Allow-Origin': '*'
            }
          });
        } catch (error) {
          return new Response(JSON.stringify({
            success: false,
            error: error.message
          }), {
            status: 500,
            headers: {
              'Content-Type': 'application/json',
              'Access-Control-Allow-Origin': '*'
            }
          });
        }
      }

      if (pathname.startsWith('/api/rules/custom/') && method === 'DELETE') {
        try {
          const ruleName = decodeURIComponent(pathname.replace('/api/rules/custom/', ''));

          if (!ruleName) {
            return new Response(JSON.stringify({
              success: false,
              error: 'Rule name is required'
            }), {
              status: 400,
              headers: {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
              }
            });
          }

          // Load current custom rules
          const customSites = await loadCustomSites(env);

          if (!customSites[ruleName]) {
            return new Response(JSON.stringify({
              success: false,
              error: `Rule '${ruleName}' not found`
            }), {
              status: 404,
              headers: {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
              }
            });
          }

          // Delete the rule
          delete customSites[ruleName];

          // Save back to KV
          if (env.CONFIG_KV) {
            await env.CONFIG_KV.put('sites_custom', JSON.stringify(customSites));

            // Clear rules cache to force refresh
            rulesLastUpdated = 0;
            aggregatedRules = null;
          }

          return new Response(JSON.stringify({
            success: true,
            message: `Rule '${ruleName}' deleted`
          }), {
            status: 200,
            headers: {
              'Content-Type': 'application/json',
              'Access-Control-Allow-Origin': '*'
            }
          });
        } catch (error) {
          return new Response(JSON.stringify({
            success: false,
            error: error.message
          }), {
            status: 500,
            headers: {
              'Content-Type': 'application/json',
              'Access-Control-Allow-Origin': '*'
            }
          });
        }
      }

      // Handle /api/rules/aggregate endpoint - Get final aggregated ruleset
      if (pathname === '/api/rules/aggregate' && method === 'GET') {
        try {
          const rules = await getAggregatedRules(env);
          const ruleCount = Object.keys(rules).length;

          // Count different types of rules
          let regularRules = 0;
          let groupRules = 0;
          let deletionRules = 0;

          for (const [name, rule] of Object.entries(rules)) {
            if (isDeletionRule(rule)) {
              deletionRules++;
            } else if (rule.group) {
              groupRules++;
            } else {
              regularRules++;
            }
          }

          return new Response(JSON.stringify({
            success: true,
            rules: rules,
            stats: {
              total: ruleCount,
              regular: regularRules,
              groups: groupRules,
              deletions: deletionRules
            },
            last_updated: rulesLastUpdated,
            cache_ttl: RULES_CACHE_TTL
          }), {
            status: 200,
            headers: {
              'Content-Type': 'application/json',
              'Access-Control-Allow-Origin': '*'
            }
          });
        } catch (error) {
          return new Response(JSON.stringify({
            success: false,
            error: error.message
          }), {
            status: 500,
            headers: {
              'Content-Type': 'application/json',
              'Access-Control-Allow-Origin': '*'
            }
          });
        }
      }

      // Handle /api/rules/refresh endpoint - Force refresh of all rules
      if (pathname === '/api/rules/refresh' && method === 'POST') {
        try {
          // Clear cache
          rulesLastUpdated = 0;
          aggregatedRules = null;
          rulesetVersion = null;

          // Clear KV cache for ruleset and metadata
          if (env.CONFIG_KV && env.RULESET_URL) {
            const keys = getRulesetCacheKeys(env.RULESET_URL);
            await env.CONFIG_KV.delete(keys.dataKey);
            await env.CONFIG_KV.delete(keys.metaKey);
          }

          // Force reload
          const rules = await getAggregatedRules(env);

          return new Response(JSON.stringify({
            success: true,
            message: 'Rules refreshed successfully',
            rule_count: Object.keys(rules).length,
            timestamp: new Date().toISOString()
          }), {
            status: 200,
            headers: {
              'Content-Type': 'application/json',
              'Access-Control-Allow-Origin': '*'
            }
          });
        } catch (error) {
          return new Response(JSON.stringify({
            success: false,
            error: error.message
          }), {
            status: 500,
            headers: {
              'Content-Type': 'application/json',
              'Access-Control-Allow-Origin': '*'
            }
          });
        }
      }

      // Handle /api/rules/match endpoint - Test rule matching for a domain
      if (pathname === '/api/rules/match' && method === 'GET') {
        try {
          const domain = url.searchParams.get('domain');
          if (!domain) {
            return new Response(JSON.stringify({
              success: false,
              error: 'domain parameter is required'
            }), {
              status: 400,
              headers: {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
              }
            });
          }

          const rules = await getAggregatedRules(env);
          const matchingRule = findRuleForDomain(domain, rules);

          return new Response(JSON.stringify({
            success: true,
            domain: domain,
            matched: !!matchingRule,
            rule: matchingRule,
            total_rules: Object.keys(rules).length
          }), {
            status: 200,
            headers: {
              'Content-Type': 'application/json',
              'Access-Control-Allow-Origin': '*'
            }
          });
        } catch (error) {
          return new Response(JSON.stringify({
            success: false,
            error: error.message
          }), {
            status: 500,
            headers: {
              'Content-Type': 'application/json',
              'Access-Control-Allow-Origin': '*'
            }
          });
        }
      }

      // For non-API paths, only allow GET requests for proxy functionality
      if ((method === 'POST' || method === 'DELETE') && !pathname.startsWith('/api/')) {
        return new Response('Method Not Allowed - POST and DELETE only allowed for API endpoints', {
          status: 405,
          headers: { 'Content-Type': 'text/plain' }
        });
      }

      // Handle CORS preflight requests
      if (method === 'OPTIONS') {
        return new Response(null, {
          status: 200,
          headers: {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type, Authorization',
            'Access-Control-Max-Age': '86400'
          }
        });
      }

      // Only allow GET, POST, and DELETE requests
      if (method !== 'GET' && method !== 'POST' && method !== 'DELETE') {
        return new Response('Method Not Allowed', {
          status: 405,
          headers: { 'Content-Type': 'text/plain' }
        });
      }

      // Phase 5 Rate Limiting and Analytics
      const clientIP = request.headers.get('CF-Connecting-IP') || 'unknown';
      const rateLimitStatus = await getRateLimitStatus(env, clientIP);

      if (!rateLimitStatus.allowed) {
        await trackError(env, {});

        return new Response('Rate limit exceeded', {
          status: 429,
          headers: {
            'Content-Type': 'text/plain',
            'X-RateLimit-Limit': '100',
            'X-RateLimit-Remaining': '0',
            'X-RateLimit-Reset': Math.ceil(rateLimitStatus.resetTime / 1000).toString(),
            'Retry-After': '60'
          }
        });
      }

      // Track this request (privacy-focused - no personal data stored)
      await trackRequest(env, {});

      // Try to call the WASM handler
      const wasmPath = `${pathname}${url.search || ''}`;
      const wasmResult = callWasmHandler(method, wasmPath, request.headers) || {};

      // Check if this is a proxy request that needs fetching
      if (wasmResult.needsFetch && wasmResult.proxyURL) {
        // Check domain restrictions for proxy requests
        const domainAllowed = await isDomainAllowed(wasmResult.proxyURL, env);
        if (!domainAllowed) {
          return new Response('Domain not allowed', {
            status: 403,
            headers: { 'Content-Type': 'text/plain' }
          });
        }

        const proxyResult = await fetchProxiedContent(wasmResult.proxyURL, env, request);

        // Convert proxy result to Response
        const responseHeaders = new Headers();

        // Set default CORS headers
        responseHeaders.set('Access-Control-Allow-Origin', '*');
        responseHeaders.set('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
        responseHeaders.set('Access-Control-Allow-Headers', '*');

        // Add headers from proxy response
        if (proxyResult.headers && typeof proxyResult.headers === 'object') {
          for (const [key, value] of Object.entries(proxyResult.headers)) {
            responseHeaders.set(key, value);
          }
        }

        return new Response(proxyResult.body || '', {
          status: proxyResult.status || 200,
          headers: responseHeaders
        });
      }

      // Handle normal WASM responses (static endpoints like /test, /ruleset)
      const responseHeaders = new Headers();

      // Set default CORS headers
      responseHeaders.set('Access-Control-Allow-Origin', '*');
      responseHeaders.set('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
      responseHeaders.set('Access-Control-Allow-Headers', '*');

      // Add headers from WASM response
      if (wasmResult && wasmResult.headers && typeof wasmResult.headers === 'object') {
        for (const [key, value] of Object.entries(wasmResult.headers)) {
          responseHeaders.set(key, value);
        }
      }

      return new Response(wasmResult.body || '', {
        status: wasmResult.status || 200,
        headers: responseHeaders
      });

    } catch (error) {
      console.error('Worker error:', error);

      return new Response(`Worker error: ${error.message}`, {
        status: 500,
        headers: {
          'Content-Type': 'text/plain',
          'Access-Control-Allow-Origin': '*'
        }
      });
    }
  },
  async scheduled(event, env, ctx) {
    ctx.waitUntil(
      refreshRulesetCache(env, {
        reason: `cron:${event.cron || 'scheduled'}`,
        force: false
      }).catch((error) => {
        console.error('Scheduled ruleset refresh failed:', error);
      })
    );
  }
};
