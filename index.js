/**
 * Bypasser - Cloudflare Worker runtime (BPC + Ladder overlays, no WASM)
 */

import {
  parseSitesAggregatedText,
  validateBPCData,
  buildMergedRuleset,
} from './scripts/bpc-mapper.mjs';
import ladderRules from './src/runtime/ladder-rules.generated.js';

import { handleRequest, getFetchInstructions, processHTMLContent } from './src/runtime/engine.js';
import {
  BPC_KV_MANIFEST_KEY,
  BPC_KV_RULESET_KEY,
  BPC_KV_SITES_JS_KEY,
  BPC_KV_SITES_VERSION_KEY,
  BPC_KV_VERSION_KEY,
  getRulesetDomains,
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
const BPC_KV_RULESET_MODE_KEY = 'bpc:ruleset_bpc:mode';
const BPC_RULESET_MODE = 'bpc+ladder-v2';

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

    if (fetchInstructions.cookie) {
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
    const originHeaders = copyResponseHeaders(response);

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

    const html = await response.text();
    const processed = processHTMLContent(html, targetURL, fetchInstructions.rule);
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
      headers: responseHeaders,
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
  const userpass = env.USERPASS;
  if (!userpass) {
    return true;
  }

  const authHeader = request.headers.get('Authorization');
  if (!authHeader || !authHeader.startsWith('Basic ')) {
    return false;
  }

  try {
    const decoded = atob(authHeader.substring(6));
    return decoded === userpass;
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
  const manifestURL = env?.RULESET_URL;
  if (!kv || !manifestURL) {
    return false;
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
    return false;
  }

  let bpcData;
  try {
    bpcData = parseSitesAggregatedText(sitesText);
    validateBPCData(bpcData);
  } catch (error) {
    console.error('BPC update: refusing to update due to parse/validate failure:', error?.message || String(error));
    return false;
  }

  let mergedRuleset;
  try {
    mergedRuleset = buildMergedRuleset(bpcData, ladderRules);
  } catch (error) {
    console.error('BPC update: failed to build merged ruleset:', error?.message || String(error));
    return false;
  }

  const rulesetJSON = JSON.stringify(mergedRuleset);

  await kv.put(BPC_KV_SITES_JS_KEY, sitesText);
  await kv.put(BPC_KV_SITES_VERSION_KEY, nextVersion);
  await kv.put(BPC_KV_RULESET_KEY, rulesetJSON);
  await kv.put(BPC_KV_VERSION_KEY, nextVersion);
  await kv.put(BPC_KV_RULESET_MODE_KEY, BPC_RULESET_MODE);
  await kv.put(BPC_KV_MANIFEST_KEY, JSON.stringify(manifest));

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

export default {
  async fetch(request, env, ctx) {
    try {
      const url = new URL(request.url);
      const pathname = url.pathname;
      const pathWithQuery = pathname + url.search;
      const method = request.method;

      if (!checkBasicAuth(request, env)) {
        return new Response('Unauthorized', {
          status: 401,
          headers: {
            'WWW-Authenticate': 'Basic realm="Bypasser"',
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

      const proxyResult =
        routeResult.responseType === 'raw'
          ? await fetchRawContent(routeResult.targetURL, request.headers, env)
          : await fetchProxiedContent(routeResult.targetURL, request.headers, env);

      const responseHeaders = new Headers();
      applyCORSHeaders(responseHeaders);

      if (proxyResult.headers && typeof proxyResult.headers === 'object') {
        for (const [key, value] of Object.entries(proxyResult.headers)) {
          responseHeaders.set(key, value);
        }
      }

      if (routeResult.responseType === 'api') {
        const content =
          typeof proxyResult.body === 'string'
            ? proxyResult.body
            : proxyResult.body
              ? await new Response(proxyResult.body).text()
              : '';

        const apiPayload = {
          version: env.VERSION || '0.0.0',
          body: content,
          request: {
            headers: headersObjectToList(proxyResult.requestHeaders),
          },
          response: {
            headers: headersObjectToList(proxyResult.originHeaders),
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
    } catch (error) {
      console.error('Worker error:', error);
      return new Response(`Worker error: ${error.message}`, {
        status: 500,
        headers: {
          'Content-Type': 'text/plain',
          'Access-Control-Allow-Origin': '*',
        },
      });
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
