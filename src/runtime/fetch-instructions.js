import { findRuleForURL } from './rule-matcher.js';

const DEFAULT_USER_AGENT = 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)';
const DEFAULT_X_FORWARDED_FOR = '66.249.66.1';

function normalizeHeaders(rule) {
  if (rule && rule.headers && typeof rule.headers === 'object') {
    return rule.headers;
  }
  return {};
}

function stringifyReplacement(value) {
  if (value === null || value === undefined) {
    return '';
  }
  return String(value);
}

function applyRegexReplacements(input, replacements) {
  if (!Array.isArray(replacements) || replacements.length === 0) {
    return input;
  }

  let output = input;

  for (const replacement of replacements) {
    if (!replacement || typeof replacement.match !== 'string') {
      continue;
    }

    try {
      const regex = new RegExp(replacement.match);
      output = output.replace(regex, stringifyReplacement(replacement.replace));
    } catch {
      // Ignore invalid regex patterns.
    }
  }

  return output;
}

export function applyURLModifications(targetURL, rule) {
  if (!rule || typeof rule !== 'object') {
    return targetURL;
  }

  const urlMods = rule.urlMods || {};
  const hasMods =
    (Array.isArray(urlMods.query) && urlMods.query.length > 0) ||
    (Array.isArray(urlMods.domain) && urlMods.domain.length > 0) ||
    (Array.isArray(urlMods.path) && urlMods.path.length > 0) ||
    Boolean(rule.googleCache);

  if (!hasMods) {
    return targetURL;
  }

  let parsedURL;
  try {
    parsedURL = new URL(targetURL);
  } catch {
    return targetURL;
  }

  parsedURL.hostname = applyRegexReplacements(parsedURL.hostname, urlMods.domain);
  parsedURL.pathname = applyRegexReplacements(parsedURL.pathname, urlMods.path);

  if (Array.isArray(urlMods.query)) {
    const query = parsedURL.searchParams;

    for (const queryMod of urlMods.query) {
      if (!queryMod || typeof queryMod.key !== 'string' || queryMod.key.length === 0) {
        continue;
      }

      const value = queryMod.value;
      if (value === null || value === '') {
        query.delete(queryMod.key);
      } else {
        query.set(queryMod.key, String(value));
      }
    }
  }

  const rewrittenURL = parsedURL.toString();

  if (rule.googleCache) {
    return `https://webcache.googleusercontent.com/search?q=cache:${rewrittenURL}`;
  }

  return rewrittenURL;
}

function generateRandomIP(randomIPMode) {
  const randByte = () => Math.floor(Math.random() * 256);

  if (randomIPMode === 'eu') {
    return `185.${randByte()}.${randByte()}.${randByte()}`;
  }

  const firstOctet = Math.floor(Math.random() * 224) + 1;
  return `${firstOctet}.${randByte()}.${randByte()}.${randByte()}`;
}

export function buildFetchInstructions(targetURL, rules, env = {}) {
  const rule = findRuleForURL(targetURL, rules) || {};
  const headers = normalizeHeaders(rule);

  const fetchInstructions = {
    rule,
    url: applyURLModifications(targetURL, rule),
    userAgent: headers['user-agent'] || env.USER_AGENT || DEFAULT_USER_AGENT,
  };

  if (headers.referer) {
    if (headers.referer !== 'none') {
      fetchInstructions.referer = headers.referer;
    }
  } else {
    fetchInstructions.referer = targetURL;
  }

  if (headers['x-forwarded-for']) {
    if (headers['x-forwarded-for'] !== 'none') {
      fetchInstructions.xForwardedFor = headers['x-forwarded-for'];
    }
  } else {
    fetchInstructions.xForwardedFor = env.X_FORWARDED_FOR || DEFAULT_X_FORWARDED_FOR;
  }

  if (headers.cookie) {
    fetchInstructions.cookie = headers.cookie;
  }

  if (headers['content-security-policy']) {
    fetchInstructions.csp = headers['content-security-policy'];
  }

  if (rule.randomIP) {
    fetchInstructions.xForwardedFor = generateRandomIP(rule.randomIP);
  }

  if (rule.extraHeaders && typeof rule.extraHeaders === 'object') {
    fetchInstructions.extraHeaders = rule.extraHeaders;
  }

  return fetchInstructions;
}
