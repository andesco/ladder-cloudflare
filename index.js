/**
 * Ladderflare - Cloudflare Worker runtime (BPC + Ladder overlays, no WASM)
 */

import {
  parseSitesAggregatedText,
  validateBPCData,
  buildMergedRuleset,
} from './scripts/bpc-mapper.mjs';
import ladderRules from './src/runtime/ladder-rules.generated.js';

import { handleRequest, getFetchInstructions, processHTMLContent } from './src/runtime/engine.js';
import { fetchKitesurfContent } from './src/runtime/browser-renderer.js';
import { getBrowserGapForURL } from './src/runtime/browser-gaps.js';
import { applyDeployIdentity, getDeployIdentity } from './src/runtime/deploy-identity.js';
import {
  findAmpRedirectURL,
  getJSONExtractionRequest,
} from './src/runtime/content-processor.js';
import {
  BPC_KV_MANIFEST_KEY,
  BPC_KV_RULESET_KEY,
  BPC_KV_SITES_JS_KEY,
  BPC_KV_SITES_VERSION_KEY,
  BPC_KV_VERSION_KEY,
  getRulesetDomains,
  getRulesetStats,
  isRulesetLoaded,
  loadRulesetFromKV,
  maybeRefreshRulesetFromKV,
} from './src/runtime/rules-store.js';

const STATIC_ASSETS = {
  '/': 'index.html',
  '/index.html': 'index.html',
  '/styles.css': 'styles.css',
  '/ladder.svg': 'ladder.svg',
  '/share-icon.svg': 'share-icon.svg',
};

const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.svg': 'image/svg+xml',
};

const DEFAULT_USER_AGENT = 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)';
const DEFAULT_X_FORWARDED_FOR = '66.249.66.1';
const MAX_HTML_BYTES = 12 * 1024 * 1024;
const MAX_JSON_BYTES = 4 * 1024 * 1024;
const BPC_KV_RULESET_MODE_KEY = 'bpc:ruleset_bpc:mode';
const BPC_KV_LAST_UPDATE_KEY = 'bpc:ruleset_bpc:last_update';
// v4 adds browser execution metadata and forces existing KV installations to
// rebuild their rules instead of silently retaining v3 rules without `bpc`
// markers or cs_local inputs.
const BPC_RULESET_MODE = 'bpc+ladder-v4';

let bootstrapAttempted = false;

function toHeaderMap(headers) {
  const out = {};
  for (const [key, value] of headers.entries()) {
    out[key.toLowerCase()] = value;
  }
  return out;
}

function applyCORSHeaders(headers) {
  headers.set('Access-Control-Allow-Origin', '*');
  headers.set('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  headers.set('Access-Control-Allow-Headers', '*');
}

function browserGapResponse(targetURL, gap) {
  const reasons = Array.isArray(gap?.reasons) ? gap.reasons : [];
  const payload = {
    error: 'browser_compatibility_gap',
    message: 'This domain is temporarily blocked because the active BPC rule has a known or potential browser compatibility gap.',
    targetURL,
    host: gap?.host || '',
    reasons,
    descriptions: Array.isArray(gap?.descriptions) ? gap.descriptions : [],
  };

  return new Response(JSON.stringify(payload, null, 2), {
    status: 501,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
      'X-Ladderflare-Browser-Gap': reasons.join(','),
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': '*',
    },
  });
}

async function serveStaticAsset(pathname, env) {
  const assetPath = STATIC_ASSETS[pathname];
  if (!assetPath) {
    return null;
  }

  try {
    const asset = await env.ASSETS.fetch(new URL(pathname, 'https://placeholder.com').href);
    if (!asset.ok) {
      return null;
    }

    const extension = `.${assetPath.split('.').pop()}`;
    const contentType = MIME_TYPES[extension] || 'application/octet-stream';

    return new Response(asset.body, {
      headers: {
        'Content-Type': contentType,
        'Cache-Control': 'public, max-age=3600',
      },
    });
  } catch (error) {
    console.error('Error serving static asset:', error);
    return null;
  }
}

function copyResponseHeaders(response) {
  const headers = {};
  response.headers.forEach((value, key) => {
    headers[key] = value;
  });
  return headers;
}

async function readBoundedText(response, maxBytes, label) {
  const declaredLength = Number(response.headers.get('Content-Length'));
  if (Number.isFinite(declaredLength) && declaredLength > maxBytes) {
    throw new Error(`${label} exceeds ${maxBytes} bytes`);
  }
  if (!response.body) return '';

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let total = 0;
  let text = '';
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel(`${label} exceeds ${maxBytes} bytes`);
      throw new Error(`${label} exceeds ${maxBytes} bytes`);
    }
    text += decoder.decode(value, { stream: true });
  }
  return text + decoder.decode();
}

function getCookieName(setCookieValue) {
  const firstPart = String(setCookieValue || '').split(';')[0] || '';
  const separatorIndex = firstPart.indexOf('=');
  return separatorIndex > -1 ? firstPart.slice(0, separatorIndex).trim() : '';
}

function shouldKeepSetCookie(setCookieValue, cookiePolicy) {
  if (!cookiePolicy || typeof cookiePolicy !== 'object') {
    return true;
  }

  const cookieName = getCookieName(setCookieValue);
  if (!cookieName) {
    return true;
  }

  if (Array.isArray(cookiePolicy.hold) && cookiePolicy.hold.length > 0) {
    return cookiePolicy.hold.includes(cookieName);
  }

  if (cookiePolicy.removeAll) {
    return false;
  }

  if (Array.isArray(cookiePolicy.drop) && cookiePolicy.drop.includes(cookieName)) {
    return false;
  }

  return true;
}

function copyFilteredResponseHeaders(response, cookiePolicy) {
  const headers = {};
  response.headers.forEach((value, key) => {
    if (key.toLowerCase() === 'set-cookie' && !shouldKeepSetCookie(value, cookiePolicy)) {
      return;
    }
    headers[key] = value;
  });
  return headers;
}

function filterProxiedHTMLHeaders(headers) {
  const output = {};
  for (const [key, value] of Object.entries(headers || {})) {
    const normalized = key.toLowerCase();
    if (
      normalized === 'content-length' ||
      normalized === 'content-encoding' ||
      normalized === 'transfer-encoding' ||
      normalized === 'content-type' ||
      normalized === 'cache-control' ||
      normalized === 'content-security-policy'
    ) {
      continue;
    }
    output[key] = value;
  }
  return output;
}

function headersObjectToList(headersObj) {
  const list = [];
  if (!headersObj || typeof headersObj !== 'object') {
    return list;
  }

  for (const [key, value] of Object.entries(headersObj)) {
    if (value === undefined || value === null) {
      continue;
    }
    list.push({ key, value: String(value) });
  }

  return list;
}

function getArchiveURL(targetURL) {
  try {
    const parsed = new URL(targetURL);
    parsed.hash = '';
    parsed.search = '';
    return `https://archive.is/${parsed.toString()}`;
  } catch {
    return '';
  }
}

async function fetchArchiveHTML(targetURL, rule, outboundHeaders) {
  if (!rule?.archiveFallback) {
    return null;
  }

  const archiveURL = getArchiveURL(targetURL);
  if (!archiveURL) {
    return null;
  }

  try {
    const response = await fetch(archiveURL, {
      headers: secondaryFetchHeaders(outboundHeaders, 'text/html,application/xhtml+xml'),
      cf: {
        cacheTtl: 300,
        cacheEverything: true,
      },
    });

    if (!response.ok) {
      return { archiveURL, archiveHTML: '' };
    }

    const contentType = response.headers.get('Content-Type') || '';
    if (!contentType.includes('text/html') && !contentType.includes('application/xhtml+xml')) {
      return { archiveURL, archiveHTML: '' };
    }

    return { archiveURL, archiveHTML: await readBoundedText(response, MAX_HTML_BYTES, 'archive HTML') };
  } catch (error) {
    console.error('Archive fallback fetch failed:', error?.message || String(error));
    return { archiveURL, archiveHTML: '' };
  }
}

function secondaryFetchHeaders(outboundHeaders, accept) {
  const headers = {
    Accept: accept,
  };
  for (const key of ['User-Agent', 'Accept-Language', 'DNT']) {
    if (outboundHeaders[key]) headers[key] = outboundHeaders[key];
  }
  return headers;
}

async function fetchAmpHTML(ampURL, outboundHeaders) {
  if (!ampURL) return '';
  try {
    const response = await fetch(ampURL, {
      headers: secondaryFetchHeaders(outboundHeaders, 'text/html,application/xhtml+xml'),
      cf: { cacheTtl: 300, cacheEverything: true },
    });
    const contentType = response.headers.get('Content-Type') || '';
    if (!response.ok || (!contentType.includes('text/html') && !contentType.includes('application/xhtml+xml'))) {
      return '';
    }
    return readBoundedText(response, MAX_HTML_BYTES, 'AMP HTML');
  } catch (error) {
    console.error('AMP redirect fetch failed:', error?.message || String(error));
    return '';
  }
}

async function fetchJSONExtractionPayload(html, targetURL, rule, outboundHeaders) {
  const request = getJSONExtractionRequest(html, targetURL, rule?.contentExtraction);
  if (!request) return '';

  try {
    const response = await fetch(request.url, {
      headers: secondaryFetchHeaders(outboundHeaders, 'application/json'),
      cf: { cacheTtl: 300, cacheEverything: true },
    });
    if (!response.ok) return '';
    return readBoundedText(response, MAX_JSON_BYTES, 'JSON article response');
  } catch (error) {
    console.error('JSON article fetch failed:', error?.message || String(error));
    return '';
  }
}

async function fetchProxiedContent(targetURL, requestHeaders, env) {
  try {
    const fetchInstructions = getFetchInstructions(targetURL, env);

    const outboundHeaders = {
      'User-Agent': fetchInstructions.userAgent || DEFAULT_USER_AGENT,
      Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
      'Accept-Language': 'en-US,en;q=0.5',
      'Accept-Encoding': 'gzip, deflate',
      DNT: '1',
      Connection: 'keep-alive',
      'Upgrade-Insecure-Requests': '1',
    };

    if (fetchInstructions.referer) {
      outboundHeaders.Referer = fetchInstructions.referer;
    }

    if (fetchInstructions.xForwardedFor) {
      outboundHeaders['X-Forwarded-For'] = fetchInstructions.xForwardedFor;
    }

    if (fetchInstructions.cookie && !fetchInstructions.cookiePolicy?.removeAll) {
      outboundHeaders.Cookie = fetchInstructions.cookie;
    }

    if (fetchInstructions.extraHeaders && typeof fetchInstructions.extraHeaders === 'object') {
      for (const [key, value] of Object.entries(fetchInstructions.extraHeaders)) {
        if (value !== undefined && value !== null) {
          outboundHeaders[key] = String(value);
        }
      }
    }

    const fetchURL = fetchInstructions.url || targetURL;

    const response = await fetch(fetchURL, {
      headers: outboundHeaders,
      cf: {
        cacheTtl: 300,
        cacheEverything: true,
      },
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }

    const contentType = response.headers.get('Content-Type') || '';
    const originHeaders = copyFilteredResponseHeaders(response, fetchInstructions.cookiePolicy);

    const isHtml = contentType.includes('text/html') || contentType.includes('application/xhtml+xml');
    if (!isHtml) {
      const isTextLike =
        contentType.startsWith('text/') ||
        contentType.includes('javascript') ||
        contentType.includes('json') ||
        contentType.includes('xml') ||
        contentType.includes('svg');

      let body = response.body;
      if (isTextLike) {
        body = await response.text();
      }

      return {
        status: response.status,
        body,
        headers: {
          'Content-Type': contentType || 'application/octet-stream',
          'Cache-Control': 'public, max-age=300',
        },
        requestHeaders: outboundHeaders,
        originHeaders,
      };
    }

    let html = await readBoundedText(response, MAX_HTML_BYTES, 'origin HTML');
    const ampURL = findAmpRedirectURL(html, targetURL, fetchInstructions.rule?.ampRedirect);
    if (ampURL) {
      const ampHTML = await fetchAmpHTML(ampURL, outboundHeaders);
      if (ampHTML) html = ampHTML;
    }

    const [archiveResult, jsonURLPayload] = await Promise.all([
      fetchArchiveHTML(targetURL, fetchInstructions.rule, outboundHeaders),
      fetchJSONExtractionPayload(html, ampURL || targetURL, fetchInstructions.rule, outboundHeaders),
    ]);
    const processed = processHTMLContent(html, targetURL, fetchInstructions.rule, {
      ...(archiveResult || {}),
      jsonURLPayload,
    });
    const responseHeaders = {
      'Content-Type': response.headers.get('Content-Type') || 'text/html',
      'Cache-Control': 'public, max-age=300',
    };

    if (processed.csp) {
      responseHeaders['Content-Security-Policy'] = processed.csp;
      originHeaders['Content-Security-Policy'] = processed.csp;
    }

    return {
      status: 200,
      body: processed.content,
      headers: {
        ...filterProxiedHTMLHeaders(originHeaders),
        ...responseHeaders,
      },
      requestHeaders: outboundHeaders,
      originHeaders,
    };
  } catch (error) {
    console.error('Error fetching proxied content:', error);
    return {
      status: 500,
      body: `Proxy error: ${error.message}`,
      headers: { 'Content-Type': 'text/plain' },
    };
  }
}

async function fetchRawContent(targetURL, requestHeaders, env) {
  try {
    const headers = {
      'User-Agent': env.USER_AGENT || DEFAULT_USER_AGENT,
      'X-Forwarded-For': env.X_FORWARDED_FOR || DEFAULT_X_FORWARDED_FOR,
    };

    const referer = requestHeaders.get('Referer') || requestHeaders.get('referer') || '';
    if (referer) {
      headers.Referer = referer;
    }

    const response = await fetch(targetURL, {
      headers,
      cf: {
        cacheTtl: 300,
        cacheEverything: true,
      },
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }

    return {
      status: response.status,
      body: response.body,
      headers: copyResponseHeaders(response),
    };
  } catch (error) {
    console.error('Error fetching raw content:', error);
    return {
      status: 500,
      body: `Proxy error: ${error.message}`,
      headers: { 'Content-Type': 'text/plain' },
    };
  }
}

function checkBasicAuth(request, env) {
  const basicAuth = env.BASIC_AUTH;
  if (!basicAuth) {
    return true;
  }

  const authHeader = request.headers.get('Authorization');
  if (!authHeader || !authHeader.startsWith('Basic ')) {
    return false;
  }

  try {
    const decoded = atob(authHeader.substring(6));
    return decoded === basicAuth;
  } catch {
    return false;
  }
}

function isDomainAllowed(url, env) {
  const allowedDomains = env.ALLOWED_DOMAINS;
  const allowedDomainsRuleset = env.ALLOWED_DOMAINS_RULESET === 'true';

  if (!allowedDomains && !allowedDomainsRuleset) {
    return true;
  }

  const domain = new URL(url).hostname;

  if (allowedDomains) {
    const domains = allowedDomains.split(',').map((d) => d.trim()).filter(Boolean);
    for (const allowedDomain of domains) {
      if (domain === allowedDomain || domain.endsWith(`.${allowedDomain}`)) {
        return true;
      }
    }
  }

  if (allowedDomainsRuleset) {
    for (const rulesetDomain of getRulesetDomains()) {
      if (domain === rulesetDomain || domain.endsWith(`.${rulesetDomain}`)) {
        return true;
      }
    }
  }

  return false;
}

async function updateBpcFromManifest(env) {
  const kv = env?.CONFIG_KV;
  const manifestURL = env?.MANIFEST_URL;
  if (!kv || !manifestURL) {
    return false;
  }

  async function writeUpdateStatus(status) {
    try {
      await kv.put(
        BPC_KV_LAST_UPDATE_KEY,
        JSON.stringify({
          checkedAt: new Date().toISOString(),
          ...status,
        }),
      );
    } catch (error) {
      console.error('BPC update: failed to store update status:', error?.message || String(error));
    }
  }

  let manifest;
  try {
    const resp = await fetch(manifestURL, { cf: { cacheTtl: 0, cacheEverything: false } });
    if (!resp.ok) {
      throw new Error(`manifest fetch failed: ${resp.status}`);
    }
    manifest = await resp.json();
  } catch (error) {
    console.error('BPC update: failed to fetch/parse manifest:', error?.message || String(error));
    await writeUpdateStatus({ ok: false, error: error?.message || String(error), phase: 'manifest' });
    return false;
  }

  const jsonEntry = manifest?.sites_aggregated_json;
  const jsEntry = manifest?.sites_aggregated_js;
  const entry =
    jsonEntry && jsonEntry.version && jsonEntry.url
      ? jsonEntry
      : jsEntry;
  const nextVersion = entry?.version;
  const sitesURL = entry?.url;
  if (!nextVersion || !sitesURL) {
    console.error('BPC update: manifest missing sites_aggregated_json/sites_aggregated_js version/url');
    await writeUpdateStatus({ ok: false, error: 'manifest missing sites_aggregated entry', phase: 'manifest' });
    return false;
  }

  const currentVersion = await kv.get(BPC_KV_SITES_VERSION_KEY);
  const currentRulesVersion = await kv.get(BPC_KV_VERSION_KEY);
  const currentRulesJSON = await kv.get(BPC_KV_RULESET_KEY);
  const currentRulesetMode = await kv.get(BPC_KV_RULESET_MODE_KEY);
  if (
    currentVersion === nextVersion &&
    currentRulesVersion === nextVersion &&
    currentRulesJSON &&
    currentRulesetMode === BPC_RULESET_MODE
  ) {
    await writeUpdateStatus({ ok: true, changed: false, version: nextVersion });
    return false;
  }

  let sitesText;
  try {
    const resp = await fetch(sitesURL, { cf: { cacheTtl: 0, cacheEverything: false } });
    if (!resp.ok) {
      throw new Error(`sites_aggregated fetch failed: ${resp.status}`);
    }
    sitesText = await resp.text();
  } catch (error) {
    console.error('BPC update: failed to fetch sites_aggregated payload:', error?.message || String(error));
    await writeUpdateStatus({ ok: false, error: error?.message || String(error), phase: 'ruleset_fetch', version: nextVersion });
    return false;
  }

  let bpcData;
  try {
    bpcData = parseSitesAggregatedText(sitesText);
    validateBPCData(bpcData);
  } catch (error) {
    console.error('BPC update: refusing to update due to parse/validate failure:', error?.message || String(error));
    await writeUpdateStatus({ ok: false, error: error?.message || String(error), phase: 'ruleset_parse', version: nextVersion });
    return false;
  }

  let mergedRuleset;
  try {
    mergedRuleset = buildMergedRuleset(bpcData, ladderRules);
  } catch (error) {
    console.error('BPC update: failed to build merged ruleset:', error?.message || String(error));
    await writeUpdateStatus({ ok: false, error: error?.message || String(error), phase: 'ruleset_build', version: nextVersion });
    return false;
  }

  const rulesetJSON = JSON.stringify(mergedRuleset);

  await kv.put(BPC_KV_SITES_JS_KEY, sitesText);
  await kv.put(BPC_KV_SITES_VERSION_KEY, nextVersion);
  await kv.put(BPC_KV_RULESET_KEY, rulesetJSON);
  await kv.put(BPC_KV_VERSION_KEY, nextVersion);
  await kv.put(BPC_KV_RULESET_MODE_KEY, BPC_RULESET_MODE);
  await kv.put(BPC_KV_MANIFEST_KEY, JSON.stringify(manifest));
  await writeUpdateStatus({ ok: true, changed: true, version: nextVersion, rules: mergedRuleset.length });

  console.log('BPC update: stored sites_aggregated.js + merged ruleset in KV version:', nextVersion);
  return true;
}

async function ensureRulesetAvailable(env) {
  if (!env?.CONFIG_KV) {
    console.error('CONFIG_KV binding is required for runtime-only ruleset mode');
    return false;
  }

  if (isRulesetLoaded()) {
    await maybeRefreshRulesetFromKV(env);
  } else {
    await loadRulesetFromKV(env, { force: true });
  }

  if (!bootstrapAttempted) {
    bootstrapAttempted = true;

    const currentRulesetMode = await env.CONFIG_KV.get(BPC_KV_RULESET_MODE_KEY);
    if (!isRulesetLoaded() || currentRulesetMode !== BPC_RULESET_MODE) {
      await updateBpcFromManifest(env);
      await loadRulesetFromKV(env, { force: true });
    }
  }

  return isRulesetLoaded();
}

async function handleFetch(request, env, ctx) {
      const url = new URL(request.url);
      const pathname = url.pathname;
      const pathWithQuery = pathname + url.search;
      const method = request.method;

      if (!checkBasicAuth(request, env)) {
        return new Response('Unauthorized', {
          status: 401,
          headers: {
            'WWW-Authenticate': 'Basic realm="Ladderflare"',
            'Content-Type': 'text/plain',
          },
        });
      }

      if (STATIC_ASSETS[pathname]) {
        if (
          env.DISABLE_FORM === 'true' &&
          (pathname === '/' || pathname === '/index.html' || pathname === '/styles.css' || pathname === '/ladder.svg' || pathname === '/share-icon.svg')
        ) {
          return new Response('Form disabled', {
            status: 404,
            headers: { 'Content-Type': 'text/plain' },
          });
        }

        const staticResponse = await serveStaticAsset(pathname, env);
        if (staticResponse) {
          return staticResponse;
        }
      }

      if (method === 'OPTIONS') {
        const headers = new Headers();
        applyCORSHeaders(headers);
        return new Response(null, { status: 204, headers });
      }

      if (pathname === '/health') {
        const headers = new Headers({
          'Content-Type': 'text/plain; charset=utf-8',
          'Cache-Control': 'no-store',
        });
        applyCORSHeaders(headers);
        return new Response('ok', { status: 200, headers });
      }

      if (pathname === '/ruleset' && env.EXPOSE_RULESET === 'false') {
        return new Response('Not Found', {
          status: 404,
          headers: { 'Content-Type': 'text/plain' },
        });
      }

      if (!pathname.startsWith('/yaml/') && !pathname.startsWith('/json/')) {
        const rulesetReady = await ensureRulesetAvailable(env);
        if (!rulesetReady) {
          return new Response('Ruleset unavailable', {
            status: 503,
            headers: {
              'Content-Type': 'text/plain; charset=utf-8',
              'Access-Control-Allow-Origin': '*',
            },
          });
        }

      }

      if (pathname === '/status') {
        const [lastUpdate, manifest] = await Promise.all([
          env.CONFIG_KV?.get(BPC_KV_LAST_UPDATE_KEY),
          env.CONFIG_KV?.get(BPC_KV_MANIFEST_KEY),
        ]);
        const payload = {
          version: env.VERSION || '0.0.0',
          deploy: getDeployIdentity(env),
          rulesetMode: BPC_RULESET_MODE,
          ruleset: getRulesetStats(),
          lastUpdate: lastUpdate ? JSON.parse(lastUpdate) : null,
          manifest: manifest ? JSON.parse(manifest) : null,
        };
        return new Response(JSON.stringify(payload, null, 2), {
          status: 200,
          headers: {
            'Content-Type': 'application/json; charset=utf-8',
            'Access-Control-Allow-Origin': '*',
          },
        });
      }

      const routeResult = handleRequest(method, pathWithQuery, toHeaderMap(request.headers));

      if (routeResult.type === 'response') {
        const headers = new Headers(routeResult.headers || {});
        applyCORSHeaders(headers);
        return new Response(routeResult.body || '', {
          status: routeResult.status || 200,
          headers,
        });
      }

      if (routeResult.type !== 'proxy' || !routeResult.targetURL) {
        return new Response('Invalid request', {
          status: 400,
          headers: { 'Content-Type': 'text/plain' },
        });
      }

      if (!isDomainAllowed(routeResult.targetURL, env)) {
        return new Response('Domain not allowed', {
          status: 403,
          headers: { 'Content-Type': 'text/plain' },
        });
      }

      // Rules-applied routes must not silently return a partial BPC result for
      // domains with an identified browser compatibility gap. The explicit
      // FastHTTP raw route remains available as an unmodified diagnostic fetch.
      if (['browser', 'browser-api', 'browser-raw', 'fast', 'fast-api'].includes(routeResult.responseType)) {
        const browserGap = getBrowserGapForURL(routeResult.targetURL);
        if (browserGap) {
          return browserGapResponse(routeResult.targetURL, browserGap);
        }
      }

      const usesKitesurf = ['browser', 'browser-api', 'browser-raw'].includes(routeResult.responseType);
      const isAPI = ['browser-api', 'fast-api'].includes(routeResult.responseType);

      const proxyResult =
        routeResult.responseType === 'fast-raw'
          ? await fetchRawContent(routeResult.targetURL, request.headers, env)
          : usesKitesurf
            ? await fetchKitesurfContent(routeResult.targetURL, getFetchInstructions(routeResult.targetURL, env), env)
          : await fetchProxiedContent(routeResult.targetURL, request.headers, env);

      const responseHeaders = new Headers();
      applyCORSHeaders(responseHeaders);

      if (proxyResult.headers && typeof proxyResult.headers === 'object') {
        for (const [key, value] of Object.entries(proxyResult.headers)) {
          responseHeaders.set(key, value);
        }
      }

      if (isAPI) {
        const content =
          typeof proxyResult.body === 'string'
            ? proxyResult.body
            : proxyResult.body
              ? await new Response(proxyResult.body).text()
              : '';

        const responseHeadersForAPI =
          proxyResult.originHeaders && Object.keys(proxyResult.originHeaders).length > 0
            ? proxyResult.originHeaders
            : proxyResult.headers;

        const apiPayload = {
          version: env.VERSION || '0.0.0',
          body: content,
          request: {
            headers: headersObjectToList(proxyResult.requestHeaders),
          },
          response: {
            headers: headersObjectToList(responseHeadersForAPI),
          },
        };

        responseHeaders.set('Content-Type', 'application/json; charset=utf-8');

        return new Response(JSON.stringify(apiPayload), {
          status: 200,
          headers: responseHeaders,
        });
      }

      return new Response(proxyResult.body || '', {
        status: proxyResult.status || 200,
        headers: responseHeaders,
      });
}

export default {
  async fetch(request, env, ctx) {
    try {
      return applyDeployIdentity(await handleFetch(request, env, ctx), env);
    } catch (error) {
      console.error('Worker error:', error);
      return applyDeployIdentity(
        new Response(`Worker error: ${error.message}`, {
          status: 500,
          headers: {
            'Content-Type': 'text/plain',
            'Access-Control-Allow-Origin': '*',
          },
        }),
        env,
      );
    }
  },

  async scheduled(event, env, ctx) {
    ctx.waitUntil(
      (async () => {
        const changed = await updateBpcFromManifest(env);
        if (changed) {
          await loadRulesetFromKV(env, { force: true });
        }
      })(),
    );
  },
};
