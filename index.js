/**
 * Ladderflare - Cloudflare Worker wrapper for Ladder WASM
 */

import wasm from './public/main.wasm';

// Load the Go WASM runtime
import './public/wasm_exec.js';

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
async function fetchProxiedContent(targetURL) {
  try {
    // Get fetch instructions from WASM
    const fetchInstructions = globalThis.fetchURL ? globalThis.fetchURL(targetURL) : null;

    if (!fetchInstructions) {
      throw new Error('WASM fetchURL function not available');
    }

    // Build headers for the request
    const headers = {
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
      headers['Referer'] = fetchInstructions.referer;
    }
    if (fetchInstructions.xForwardedFor) {
      headers['X-Forwarded-For'] = fetchInstructions.xForwardedFor;
    }
    if (fetchInstructions.cookie) {
      headers['Cookie'] = fetchInstructions.cookie;
    }

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

    // Process content through WASM (applies rules, injections, regex)
    const processedResult = globalThis.processContent ? globalThis.processContent(content, targetURL) : null;

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
      }

      return {
        status: 200,
        body: content,
        headers: responseHeaders
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
        }
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
    if (rulesetDomains && rulesetDomains.includes(domain)) {
      return true;
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
            'Content-Type': 'text/yaml',
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
      const wasmResult = callWasmHandler(method, pathname, request.headers) || {};

      // Check if this is a proxy request that needs fetching
      if (wasmResult.needsFetch && wasmResult.proxyURL) {
        // Check domain restrictions for proxy requests
        if (!isDomainAllowed(wasmResult.proxyURL, env)) {
          return new Response('Domain not allowed', {
            status: 403,
            headers: { 'Content-Type': 'text/plain' }
          });
        }

        const proxyResult = await fetchProxiedContent(wasmResult.proxyURL);

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
  }
};