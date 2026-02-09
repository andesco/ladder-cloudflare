/**
 * Ladderflare - Cloudflare Worker wrapper for Ladder WASM
 */

import wasm from './public/main.wasm';

// Load the Go WASM runtime
import './public/wasm_exec.js';

import {
  parseSitesAggregatedText,
  validateBPCData,
  buildBpcOnlyRuleset,
} from './scripts/bpc-mapper.mjs';

// Static assets mapping
const STATIC_ASSETS = {
  '/': 'index.html',
  '/index.html': 'index.html',
  '/styles.css': 'styles.css',
  '/logo.svg': 'logo.svg',
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

// Optional KV-backed BPC ruleset loading.
// KV binding is optional: when not configured, embedded BPC ruleset is used.
const BPC_KV_VERSION_KEY = 'bpc:ruleset_bpc:version';
const BPC_KV_RULESET_KEY = 'bpc:ruleset_bpc';
const BPC_KV_SITES_JS_KEY = 'bpc:sites_aggregated_js';
const BPC_KV_SITES_VERSION_KEY = 'bpc:sites_aggregated_js:version';
const BPC_KV_MANIFEST_KEY = 'bpc:manifest';
const BPC_RUNTIME_REFRESH_MS = 60 * 1000; // isolate-level refresh throttle
let bpcLoadedVersion = null;
let bpcLastRefreshAt = 0;

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

  // Create Go instance
  goInstance = new Go();

  // Instantiate the WASM module
  const instance = await WebAssembly.instantiate(wasm, goInstance.importObject);

  // Start the Go program but don't wait for it to complete
  // The Go program will run in the background and set up the global functions
  goInstance.run(instance);

  wasmInstance = instance;

  console.log('Ladderflare WASM initialized');
  return instance;
}

async function maybeLoadBpcRulesetFromKV(env, { force = false } = {}) {
  const kv = env?.CONFIG_KV;
  if (!kv) return false;

  const now = Date.now();
  if (!force && now - bpcLastRefreshAt < BPC_RUNTIME_REFRESH_MS) return false;
  bpcLastRefreshAt = now;

  const nextVersion = await kv.get(BPC_KV_VERSION_KEY);
  if (!nextVersion || nextVersion === bpcLoadedVersion) return false;

  const rulesJSON = await kv.get(BPC_KV_RULESET_KEY);
  if (!rulesJSON) return false;

  // WASM initializes globalThis.setBPCRuleset at startup.
  if (typeof globalThis.setBPCRuleset !== 'function') return false;

  const res = globalThis.setBPCRuleset(rulesJSON);
  if (res !== true) {
    console.error('Failed to set BPC ruleset in WASM:', res);
    return false;
  }

  bpcLoadedVersion = nextVersion;
  console.log('Loaded BPC ruleset from KV version:', bpcLoadedVersion);
  return true;
}

async function updateBpcFromManifest(env) {
  const kv = env?.CONFIG_KV;
  const manifestURL = env?.RULESET_URL;
  if (!kv || !manifestURL) return;

  let manifest;
  try {
    const resp = await fetch(manifestURL, { cf: { cacheTtl: 0, cacheEverything: false } });
    if (!resp.ok) throw new Error(`manifest fetch failed: ${resp.status}`);
    manifest = await resp.json();
  } catch (err) {
    console.error('BPC update: failed to fetch/parse manifest:', err?.message || String(err));
    return;
  }

  const entry = manifest?.sites_aggregated_js;
  const nextVersion = entry?.version;
  const sitesURL = entry?.url;
  if (!nextVersion || !sitesURL) {
    console.error('BPC update: manifest missing sites_aggregated_js.version/url');
    return;
  }

  const currentVersion = await kv.get(BPC_KV_SITES_VERSION_KEY);
  if (currentVersion === nextVersion) return;

  let sitesText;
  try {
    const resp = await fetch(sitesURL, { cf: { cacheTtl: 0, cacheEverything: false } });
    if (!resp.ok) throw new Error(`sites_aggregated.js fetch failed: ${resp.status}`);
    sitesText = await resp.text();
  } catch (err) {
    console.error('BPC update: failed to fetch sites_aggregated.js:', err?.message || String(err));
    return;
  }

  let bpcData;
  try {
    bpcData = parseSitesAggregatedText(sitesText);
    validateBPCData(bpcData);
  } catch (err) {
    console.error('BPC update: refusing to update due to parse/validate failure:', err?.message || String(err));
    return;
  }

  let rulesetBpc;
  try {
    rulesetBpc = buildBpcOnlyRuleset(bpcData);
  } catch (err) {
    console.error('BPC update: failed to map BPC data to ruleset:', err?.message || String(err));
    return;
  }

  const rulesetJSON = JSON.stringify(rulesetBpc);

  await kv.put(BPC_KV_SITES_JS_KEY, sitesText);
  await kv.put(BPC_KV_SITES_VERSION_KEY, nextVersion);
  await kv.put(BPC_KV_RULESET_KEY, rulesetJSON);
  await kv.put(BPC_KV_VERSION_KEY, nextVersion);
  await kv.put(BPC_KV_MANIFEST_KEY, JSON.stringify(manifest));

  console.log('BPC update: stored sites_aggregated.js + mapped ruleset in KV version:', nextVersion);
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
async function fetchProxiedContent(targetURL, rulesetMode) {
  try {
    // Get fetch instructions from WASM
    const fetchInstructions = globalThis.fetchURL ? globalThis.fetchURL(targetURL, rulesetMode || 'merged') : null;

    if (!fetchInstructions) {
      throw new Error('WASM fetchURL function not available');
    }

    // Build headers for the request
    const requestHeaders = {
      'User-Agent': fetchInstructions.userAgent || 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
      'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
      'Accept-Language': 'en-US,en;q=0.5',
      'Accept-Encoding': 'gzip, deflate',
      'DNT': '1',
      'Connection': 'keep-alive',
      'Upgrade-Insecure-Requests': '1'
    };

    // Add optional headers from WASM
    if (fetchInstructions.referer) {
      requestHeaders['Referer'] = fetchInstructions.referer;
    }
    if (fetchInstructions.xForwardedFor) {
      requestHeaders['X-Forwarded-For'] = fetchInstructions.xForwardedFor;
    }
    if (fetchInstructions.cookie) {
      requestHeaders['Cookie'] = fetchInstructions.cookie;
    }

    // #6: Apply extra headers from rule
    if (fetchInstructions.extraHeaders && typeof fetchInstructions.extraHeaders === 'object') {
      const keys = Object.keys(fetchInstructions.extraHeaders);
      for (const key of keys) {
        const val = fetchInstructions.extraHeaders[key];
        if (val !== undefined && val !== null) {
          requestHeaders[key] = String(val);
        }
      }
    }

    const fetchURL = fetchInstructions.url || targetURL;

    // Fetch the target URL
    const response = await fetch(fetchURL, {
      headers: requestHeaders,
      cf: {
        // Cloudflare-specific options
        cacheTtl: 300, // Cache for 5 minutes
        cacheEverything: true
      }
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }

    const contentType = response.headers.get('Content-Type') || '';
    const originHeaders = copyResponseHeaders(response);

    const isHtml = contentType.includes('text/html') || contentType.includes('application/xhtml+xml');

    // Do not run HTML rewriting/WASM DOM processing on non-HTML assets (JS/CSS/images/fonts/etc).
    // Doing so corrupts the payload (e.g. JS becomes HTML-escaped) and breaks rendering.
    if (!isHtml) {
      const isTextLike =
        contentType.startsWith('text/') ||
        contentType.includes('javascript') ||
        contentType.includes('json') ||
        contentType.includes('xml') ||
        contentType.includes('svg');

      let body = response.body;

      // For text-like assets, return a string body (lets callers like /api stringify the payload).
      // Keep as close to origin as possible; avoid DOM processing.
      if (isTextLike) {
        body = await response.text();
      }

      return {
        status: response.status,
        body,
        headers: {
          'Content-Type': contentType || 'application/octet-stream',
          'Cache-Control': 'public, max-age=300'
        },
        requestHeaders,
        originHeaders
      };
    }

    let content = await response.text();

    // Process content through WASM (applies rules, injections, regex)
    const processedResult = globalThis.processContent ? globalThis.processContent(content, targetURL, rulesetMode || 'merged') : null;

    if (processedResult) {
      content = processedResult.content || content;

      // Apply content injections if present
      if (processedResult.injections && processedResult.injections.length > 0) {
        content = applyContentInjections(content, processedResult.injections);
      }

      const responseHeaders = {
        'Content-Type': response.headers.get('Content-Type') || 'text/html',
        'Cache-Control': 'public, max-age=300'
      };

      // Apply CSP header if specified in rule
      if (processedResult.csp) {
        responseHeaders['Content-Security-Policy'] = processedResult.csp;
        originHeaders['Content-Security-Policy'] = processedResult.csp;
      }

      return {
        status: 200,
        body: content,
        headers: responseHeaders,
        requestHeaders,
        originHeaders
      };
    } else {
      // Fallback to basic processing
      const url = new URL(targetURL);
      content = rewriteHTMLBasic(content, url.host);

      return {
        status: 200,
        body: content,
        headers: {
          'Content-Type': response.headers.get('Content-Type') || 'text/html',
          'Cache-Control': 'public, max-age=300'
        },
        requestHeaders,
        originHeaders
      };
    }

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
 * Copy headers from a Response into a plain object
 */
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

/**
 * Basic HTML rewriting (JavaScript version)
 */
function rewriteHTMLBasic(content, originalHost) {
  const proxyPrefix = `/https://${originalHost}/`;

  // Rewrite relative URLs
  content = content.replace(/src="\/([^"]*)"/g, `src="${proxyPrefix}$1"`);
  content = content.replace(/href="\/([^"]*)"/g, `href="${proxyPrefix}$1"`);
  content = content.replace(/url\('\/([^']*)'\)/g, `url('${proxyPrefix}$1')`);
  content = content.replace(/url\(\/([^)]*)\)/g, `url(${proxyPrefix}$1)`);

  // Rewrite absolute URLs back to proxy
  content = content.replace(new RegExp(`href="https://${originalHost.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}`, 'g'), `href="/https://${originalHost}/`);

  return content;
}

/**
 * Fetch raw proxied content without rule processing
 */
async function fetchRawContent(targetURL, requestHeaders) {
  try {
    const headers = {
      'User-Agent': globalThis.USER_AGENT_ENV || 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
      'X-Forwarded-For': globalThis.X_FORWARDED_FOR_ENV || '66.249.66.1'
    };

    const referer = requestHeaders && requestHeaders.get ? requestHeaders.get('Referer') || requestHeaders.get('referer') : '';
    if (referer) {
      headers['Referer'] = referer;
    }

    const response = await fetch(targetURL, {
      headers,
      cf: {
        cacheTtl: 300,
        cacheEverything: true
      }
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }

    return {
      status: response.status,
      body: response.body,
      headers: copyResponseHeaders(response)
    };
  } catch (error) {
    console.error('Error fetching raw content:', error);
    return {
      status: 500,
      body: `Proxy error: ${error.message}`,
      headers: { 'Content-Type': 'text/plain' }
    };
  }
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
  const userpass = env.USERPASS;
  if (!userpass) {
    return true; // No auth required
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

  return decoded === userpass;
}

/**
 * Check if domain is allowed
 */
function isDomainAllowed(url, env) {
  const allowedDomains = env.ALLOWED_DOMAINS;
  const allowedDomainsRuleset = env.ALLOWED_DOMAINS_RULESET === 'true';

  // If no restrictions, allow all
  if (!allowedDomains && !allowedDomainsRuleset) {
    return true;
  }

  const urlObj = new URL(url);
  const domain = urlObj.hostname;

  // Check explicit allowed domains
  if (allowedDomains) {
    const domains = allowedDomains.split(',').map(d => d.trim()).filter(d => d);
    for (const allowedDomain of domains) {
      if (domain === allowedDomain || domain.endsWith('.' + allowedDomain)) {
        return true;
      }
    }
  }

  // Check ruleset domains if enabled
  if (allowedDomainsRuleset && globalThis.getRulesetDomains) {
    const rulesetDomains = globalThis.getRulesetDomains();
    if (rulesetDomains && Array.isArray(rulesetDomains)) {
      for (const rulesetDomain of rulesetDomains) {
        if (!rulesetDomain) {
          continue;
        }
        if (domain === rulesetDomain || domain.endsWith('.' + rulesetDomain)) {
          return true;
        }
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

      // If KV is configured and has a newer BPC ruleset, load it into WASM.
      // This is isolate-cached and throttled so it doesn't KV-read on every request.
      await maybeLoadBpcRulesetFromKV(env);

      const url = new URL(request.url);
      const pathname = url.pathname;
      const pathWithQuery = pathname + url.search;
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

      // Handle /ruleset endpoint
      if (pathname === '/ruleset') {
        if (env.EXPOSE_RULESET === 'false') {
          return new Response('Not Found', {
            status: 404,
            headers: { 'Content-Type': 'text/plain' }
          });
        }

        // Get ruleset from WASM
        const ruleset = globalThis.getRuleset ? globalThis.getRuleset() : '';
        return new Response(ruleset, {
          status: 200,
          headers: {
            'Content-Type': 'application/json; charset=utf-8',
            'Access-Control-Allow-Origin': '*'
          }
        });
      }

      // Handle static assets (unless DISABLE_FORM is true for form assets)
      if (STATIC_ASSETS[pathname]) {
        // Check if DISABLE_FORM is enabled and this is a form-related asset
        if (env.DISABLE_FORM === 'true' && (pathname === '/' || pathname === '/index.html' || pathname === '/styles.css' || pathname === '/logo.svg' || pathname === '/share-icon.svg')) {
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

      // Only allow GET requests for proxy functionality
      if (method !== 'GET') {
        return new Response('Method Not Allowed', {
          status: 405,
          headers: { 'Content-Type': 'text/plain' }
        });
      }

      // Try to call the WASM handler
      const wasmResult = callWasmHandler(method, pathWithQuery, request.headers) || {};

      // Check if this is a proxy request that needs fetching
      if (wasmResult.needsFetch && wasmResult.proxyURL) {
        // Check domain restrictions for proxy requests
        if (!isDomainAllowed(wasmResult.proxyURL, env)) {
          return new Response('Domain not allowed', {
            status: 403,
            headers: { 'Content-Type': 'text/plain' }
          });
        }

        const responseType = wasmResult.responseType || 'proxy';
        const rulesetMode = wasmResult.rulesetMode || 'merged';
        const proxyResult = responseType === 'raw'
          ? await fetchRawContent(wasmResult.proxyURL, request.headers)
          : await fetchProxiedContent(wasmResult.proxyURL, rulesetMode);

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

        if (responseType === 'api') {
          const content = typeof proxyResult.body === 'string'
            ? proxyResult.body
            : proxyResult.body
              ? await new Response(proxyResult.body).text()
              : '';

          const version = env.VERSION || '0.0.0';
          const apiPayload = {
            version,
            body: content,
            request: {
              headers: headersObjectToList(proxyResult.requestHeaders)
            },
            response: {
              headers: headersObjectToList(proxyResult.originHeaders)
            }
          };

          responseHeaders.set('Content-Type', 'application/json; charset=utf-8');

          return new Response(JSON.stringify(apiPayload), {
            status: 200,
            headers: responseHeaders
          });
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
  }
  ,

  async scheduled(event, env, ctx) {
    // KV is optional. If not configured (or RULESET_URL not set), this is a no-op.
    ctx.waitUntil(updateBpcFromManifest(env));
  }
};
