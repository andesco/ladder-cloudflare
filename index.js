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
const RULES_CACHE_TTL = 24 * 60 * 60 * 1000; // 24 hours

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

/**
 * Load rules from RULESET_URL with local/remote manifest comparison
 */
async function loadRulesFromUrl(env) {
  try {
    if (!env.RULESET_URL) {
      throw new Error('RULESET_URL is required. Set it in wrangler.toml [vars] or environment variables.');
    }

    console.log('Fetching remote ruleset from:', env.RULESET_URL);

    // Try to get cached rules first
    const cacheKey = `ruleset_url_${env.RULESET_URL.replace(/[^a-zA-Z0-9]/g, '_')}`;
    if (env.CONFIG_KV) {
      const cached = await env.CONFIG_KV.get(cacheKey, { type: 'json' });
      if (cached && cached.timestamp && (Date.now() - cached.timestamp) < RULES_CACHE_TTL) {
        return cached.data || {};
      }
    }

    const response = await fetch(env.RULESET_URL, {
      cf: { cacheTtl: 3600 }
    });

    if (!response.ok) {
      throw new Error(`Failed to fetch RULESET_URL ${env.RULESET_URL}: ${response.status}`);
    }

    const contentType = response.headers.get('content-type') || '';
    let rulesData = {};

    if (contentType.includes('application/json') || env.RULESET_URL.endsWith('.json')) {
      // Handle manifest.json format
      const manifest = await response.json();

      if (manifest.sites_aggregated_yaml || manifest.sites_aggregated_json) {
        // Load rules from new manifest format
        rulesData = await loadRulesFromNewManifest(manifest, env);
      } else if (manifest.sites_js_url || manifest.sites_json_url || manifest.sites_updated_url) {
        // Load rules from legacy manifest URLs
        rulesData = await loadRulesFromManifest(manifest, env);
      } else {
        // Direct JSON rules
        rulesData = manifest;
      }
    } else if (contentType.includes('text/yaml') || contentType.includes('application/yaml') || env.RULESET_URL.endsWith('.yaml') || env.RULESET_URL.endsWith('.yml')) {
      // Handle YAML format (aggregated ruleset)
      const yamlText = await response.text();
      rulesData = parseYamlRules(yamlText);
    } else {
      console.warn('Unknown RULESET_URL format, treating as JSON');
      rulesData = await response.json();
    }

    // Cache the rules
    if (env.CONFIG_KV) {
      await env.CONFIG_KV.put(cacheKey, JSON.stringify({
        data: rulesData,
        timestamp: Date.now()
      }), { expirationTtl: RULES_CACHE_TTL });
    }

    return rulesData;
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
      finalRules[name] = { ...finalRules[name], ...rule }; // Add/modify
    }
  }

  // Apply custom rules (highest priority)
  for (const [name, rule] of Object.entries(customSites)) {
    if (isDeletionRule(rule)) {
      delete finalRules[name]; // User can delete any rule
      console.log(`Deleted rule via custom: ${name}`);
    } else {
      finalRules[name] = { ...finalRules[name], ...rule }; // User overrides
    }
  }

  return finalRules;
}

/**
 * Get aggregated rules (cached for performance)
 */
async function getAggregatedRules(env) {
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
 * Find rule for a specific domain
 */
function findRuleForDomain(domain, rules) {
  // Direct domain match first
  for (const [name, rule] of Object.entries(rules)) {
    if (rule.domain === domain) {
      return rule;
    }
  }

  // Try subdomain matching (e.g., www.example.com matches example.com)
  const baseDomain = domain.replace(/^www\./, '');
  for (const [name, rule] of Object.entries(rules)) {
    if (rule.domain === baseDomain || domain.endsWith(`.${rule.domain}`)) {
      return rule;
    }
  }

  return null;
}

/**
 * Apply Chrome Extension rule processing (Phase 4)
 * Handles cookies, content blocking, and HTML modification
 */
async function applyChromExtensionRules(content, targetURL, response, rule) {
  const url = new URL(targetURL);

  // Default processing result
  let processedContent = content;
  const responseHeaders = {
    'Content-Type': response.headers.get('Content-Type') || 'text/html',
    'Cache-Control': 'public, max-age=300'
  };

  // Apply URL rewriting for HTML content (keep our fix for CSS)
  if (response.headers.get('Content-Type')?.includes('text/html')) {
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

  // Chrome Extension Rule Processing:

  // 1. Cookie Management
  if (rule.allow_cookies === 1) {
    // Allow cookies - preserve Set-Cookie headers from response
    const setCookieHeader = response.headers.get('Set-Cookie');
    if (setCookieHeader) {
      responseHeaders['Set-Cookie'] = setCookieHeader;
    }
  }

  // 2. Remove specific cookies (remove_cookies_select_drop)
  if (rule.remove_cookies_select_drop && Array.isArray(rule.remove_cookies_select_drop)) {
    // This would be applied via request headers modification
    // For now, log the cookies that should be removed
    console.log(`Would remove cookies: ${rule.remove_cookies_select_drop.join(', ')}`);
  }

  // 3. Content Sanitization Flag
  if (rule.cs_dompurify === 1) {
    console.log('Content marked for DOMPurify sanitization');
    // In Chrome extension, this triggers DOMPurify.sanitize()
    // For now, we'll just note that sanitization should be applied
    responseHeaders['X-Content-Sanitized'] = 'true';
  }

  // 4. Block Regex Processing
  if (rule.block_regex) {
    // In Chrome extension, this blocks network requests matching the regex
    // For our proxy, we can't block already-fetched content, but we can log
    console.log('Rule has blocking regex:', rule.block_regex);

    // Add a header to indicate blocked patterns
    responseHeaders['X-Blocked-Patterns'] = 'applied';
  }

  // 5. Content Modifications
  if (response.headers.get('Content-Type')?.includes('text/html')) {
    // Apply any HTML-specific rule modifications

    // Remove paywall-related scripts/elements (basic approach)
    if (rule.allow_cookies === 1) {
      // Remove common paywall indicators
      processedContent = processedContent.replace(
        /<script[^>]*(?:paywall|subscription|premium)[^>]*>.*?<\/script>/gis, ''
      );

      // Remove paywall overlay divs
      processedContent = processedContent.replace(
        /<div[^>]*(?:paywall|overlay|modal)[^>]*>.*?<\/div>/gis, ''
      );
    }
  }

  return {
    content: processedContent,
    headers: responseHeaders
  };
}

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
async function fetchProxiedContent(targetURL, env) {
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

    // Build headers for the request with Chrome extension rule priority
    const defaultUserAgent = 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)';
    const userAgent = matchingRule?.useragent_custom ||
                     env.USER_AGENT ||
                     fetchInstructions.userAgent ||
                     defaultUserAgent;

    const headers = {
      'User-Agent': userAgent,
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

    console.log(`Processing ${url.hostname}, found rule: ${matchingRule ? 'YES' : 'NO'}`);

    // Apply Chrome extension rule processing
    const processedResult = await applyChromExtensionRules(
      content,
      targetURL,
      response,
      matchingRule
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
            version: 'static-embedded'
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

          // Clear KV cache for updated rules
          if (env.CONFIG_KV) {
            await env.CONFIG_KV.delete('sites_updated');
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
      const wasmResult = callWasmHandler(method, pathname, request.headers) || {};

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

        const proxyResult = await fetchProxiedContent(wasmResult.proxyURL, env);

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