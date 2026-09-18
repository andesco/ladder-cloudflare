import puppeteer from '@cloudflare/puppeteer';

import { buildBpcCompatibilityScript } from './bpc-compat.js';
import { processHTMLContent } from './engine.js';
import { getGlobalBlockPatterns } from './rules-store.js';

const MAX_RENDERED_HTML_BYTES = 12 * 1024 * 1024;
const MAX_BPC_EXTERNAL_FETCH_BYTES = 4 * 1024 * 1024;
const DEFAULT_BROWSER_WAIT_MS = 1500;
const MAX_BROWSER_WAIT_MS = 10000;
const DEFAULT_BPC_POST_NAVIGATION_WAIT_MS = 1000;
const MAX_BPC_POST_NAVIGATION_WAIT_MS = 3000;
const MAX_BPC_EXTERNAL_FETCHES = 16;

function asString(value) {
  return value === undefined || value === null ? '' : String(value);
}

function getInjectionContent(injection) {
  if (!injection || typeof injection !== 'object') {
    return '';
  }

  if (typeof injection.append === 'string' && injection.append.length > 0) {
    return injection.append;
  }

  if (typeof injection.prepend === 'string' && injection.prepend.length > 0) {
    return injection.prepend;
  }

  if (typeof injection.replace === 'string' && injection.replace.length > 0) {
    return injection.replace;
  }

  return '';
}

function extractScriptBodies(injections) {
  const bodies = [];

  for (const injection of Array.isArray(injections) ? injections : []) {
    const content = getInjectionContent(injection);
    const scriptPattern = /<script\b[^>]*>([\s\S]*?)<\/script\s*>/gi;
    let match;

    while ((match = scriptPattern.exec(content))) {
      if (match[1].trim()) {
        bodies.push(match[1]);
      }
    }
  }

  return bodies;
}

function stripScriptElements(content) {
  return asString(content).replace(/<script\b[^>]*>[\s\S]*?<\/script\s*>/gi, '');
}

function buildEarlyInjectionScript(injections) {
  const bodies = extractScriptBodies(injections);
  if (bodies.length === 0) {
    return '';
  }

  return bodies
    .map(
      (body) => `
        try {
          ${body}
        } catch (error) {
          console.debug('Ladderflare browser injection failed', error);
        }
      `,
    )
    .join('\n');
}

function getBrowserWaitMs(env) {
  const value = Number(env?.BROWSER_WAIT_MS);
  if (!Number.isFinite(value)) {
    return DEFAULT_BROWSER_WAIT_MS;
  }

  return Math.min(Math.max(Math.round(value), 0), MAX_BROWSER_WAIT_MS);
}

function getBpcPostNavigationWaitMs(env) {
  const value = Number(env?.BPC_POST_NAVIGATION_WAIT_MS);
  if (!Number.isFinite(value)) {
    return DEFAULT_BPC_POST_NAVIGATION_WAIT_MS;
  }

  return Math.min(Math.max(Math.round(value), 0), MAX_BPC_POST_NAVIGATION_WAIT_MS);
}

function isSafeBpcExternalURL(value) {
  if (typeof value !== 'string' || !/^https?:\/\//i.test(value)) return false;

  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    return false;
  }

  const hostname = parsed.hostname.toLowerCase().replace(/^\[|\]$/g, '');
  if (
    hostname === 'localhost' ||
    hostname.endsWith('.localhost') ||
    hostname === '::1' ||
    hostname === '0.0.0.0' ||
    /^127\./.test(hostname) ||
    /^10\./.test(hostname) ||
    /^192\.168\./.test(hostname) ||
    /^169\.254\./.test(hostname) ||
    /^172\.(1[6-9]|2\d|3[0-1])\./.test(hostname) ||
    /^(fc|fd|fe8|fe9|fea|feb)/.test(hostname)
  ) {
    return false;
  }

  return true;
}

function normalizeBrowserHeaders(fetchInstructions) {
  const headers = {
    Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    DNT: '1',
    'Upgrade-Insecure-Requests': '1',
  };

  if (fetchInstructions?.referer) {
    headers.Referer = fetchInstructions.referer;
  }

  if (fetchInstructions?.xForwardedFor) {
    headers['X-Forwarded-For'] = fetchInstructions.xForwardedFor;
  }

  if (fetchInstructions?.cookie && !fetchInstructions.cookiePolicy?.removeAll) {
    headers.Cookie = fetchInstructions.cookie;
  }

  if (fetchInstructions?.extraHeaders && typeof fetchInstructions.extraHeaders === 'object') {
    for (const [key, value] of Object.entries(fetchInstructions.extraHeaders)) {
      if (value !== undefined && value !== null) {
        headers[key] = String(value);
      }
    }
  }

  return headers;
}

function hostMatches(host, candidate) {
  const normalizedHost = asString(host).toLowerCase();
  const normalizedCandidate = asString(candidate).toLowerCase().replace(/^\*\./, '');
  return Boolean(
    normalizedCandidate &&
      (normalizedHost === normalizedCandidate || normalizedHost.endsWith(`.${normalizedCandidate}`)),
  );
}

function getPatternAndExclusions(entry) {
  if (typeof entry === 'string') {
    return { pattern: entry, excludedDomains: [] };
  }

  if (entry && typeof entry === 'object' && typeof entry.pattern === 'string') {
    return {
      pattern: entry.pattern,
      excludedDomains: Array.isArray(entry.excludedDomains) ? entry.excludedDomains : [],
    };
  }

  return { pattern: '', excludedDomains: [] };
}

function compileBlockPatterns(rule) {
  const entries = [
    ...(Array.isArray(rule?.blockScripts) ? rule.blockScripts : []),
    ...(Array.isArray(rule?.blockScriptsGeneral) ? rule.blockScriptsGeneral : []),
    ...getGlobalBlockPatterns(),
  ];

  return entries
    .map((entry) => {
      const { pattern, excludedDomains } = getPatternAndExclusions(entry);
      if (!pattern) return null;

      try {
        return {
          regex: new RegExp(pattern),
          excludedDomains,
        };
      } catch {
        return null;
      }
    })
    .filter(Boolean);
}

function requestShouldBeBlocked(request, compiledPatterns, targetHost) {
  if (!request || !compiledPatterns.length) {
    return false;
  }

  const resourceType = request.resourceType || '';
  if (resourceType && !['Script', 'Stylesheet'].includes(resourceType)) {
    return false;
  }

  const requestURL = asString(request.url);
  return compiledPatterns.some(({ regex, excludedDomains }) => {
    if (excludedDomains.some((domain) => hostMatches(targetHost, domain))) {
      return false;
    }
    return regex.test(requestURL);
  });
}

async function installRequestBlocking(page, rule, targetURL) {
  const compiledPatterns = compileBlockPatterns(rule);
  if (compiledPatterns.length === 0) {
    return null;
  }

  const client = await page.target().createCDPSession();
  const onRequestPaused = (event) => {
    void (async () => {
      try {
        if (requestShouldBeBlocked(event.request, compiledPatterns, new URL(targetURL).hostname)) {
          await client.send('Fetch.failRequest', {
            requestId: event.requestId,
            errorReason: 'BlockedByClient',
          });
        } else {
          await client.send('Fetch.continueRequest', {
            requestId: event.requestId,
          });
        }
      } catch (error) {
        console.warn('Ladderflare browser request handling failed:', error?.message || String(error));
      }
    })();
  };

  try {
    client.on('Fetch.requestPaused', onRequestPaused);
    await client.send('Fetch.enable', {
      patterns: [{ urlPattern: '*', requestStage: 'Request' }],
    });
    return { client, onRequestPaused };
  } catch (error) {
    console.warn('Ladderflare browser request blocking unavailable:', error?.message || String(error));
    return null;
  }
}

async function disableRequestBlocking(state) {
  if (!state) return;

  try {
    await state.client.send('Fetch.disable');
  } catch {
    // The browser may already be closing.
  }

  try {
    state.client.off('Fetch.requestPaused', state.onRequestPaused);
  } catch {
    // Older CDP clients may not expose off(); browser shutdown still removes it.
  }
}

async function applyRenderedRule(page, targetURL, rule) {
  const safeRule = {
    blockJsInline: rule?.blockJsInline || '',
    csCode: Array.isArray(rule?.csCode) ? rule.csCode : [],
    ampUnhide: Boolean(rule?.ampUnhide),
    injections: Array.isArray(rule?.injections)
      ? rule.injections.map((injection) => ({
          position: injection?.position || 'head',
          append: stripScriptElements(injection?.append),
          prepend: stripScriptElements(injection?.prepend),
          replace: stripScriptElements(injection?.replace),
        }))
      : [],
  };

  await page.evaluate(
    ({ pageURL, currentRule }) => {
      const queryAll = (scope, selector) => {
        try {
          return Array.from(scope.querySelectorAll(selector));
        } catch {
          return [];
        }
      };

      const applyCsCodeOperation = (operation, scope = document) => {
        if (!operation || typeof operation !== 'object') return;

        if (typeof operation.hide_elem === 'string' && operation.hide_elem.length > 0) {
          for (const element of queryAll(scope, operation.hide_elem)) {
            const existingStyle = element.getAttribute('style') || '';
            element.setAttribute(
              'style',
              existingStyle ? `${existingStyle};display:none!important` : 'display:none!important',
            );
          }
        }

        let conditionMatches = [];
        if (typeof operation.cond === 'string' && operation.cond.length > 0) {
          conditionMatches = queryAll(scope, operation.cond);

          if (operation.rm_elem) {
            for (const element of conditionMatches) element.remove();
          }

          if (typeof operation.rm_class === 'string' && operation.rm_class.length > 0) {
            const classes = operation.rm_class.split(/[,|\s]+/).filter(Boolean);
            for (const element of conditionMatches) {
              for (const className of classes) element.classList.remove(className);
            }
          }

          if (typeof operation.rm_attrib === 'string' && operation.rm_attrib.length > 0) {
            const attributes = operation.rm_attrib.split('|').map((value) => value.trim()).filter(Boolean);
            for (const element of conditionMatches) {
              for (const attribute of attributes) element.removeAttribute(attribute);
            }
          }

          if (typeof operation.set_attrib === 'string' && operation.set_attrib.length > 0) {
            const separatorIndex = operation.set_attrib.indexOf('|');
            if (separatorIndex > -1) {
              const attribute = operation.set_attrib.slice(0, separatorIndex);
              const value = operation.set_attrib.slice(separatorIndex + 1);
              for (const element of conditionMatches) element.setAttribute(attribute, value);
            }
          }
        }

        if (Array.isArray(operation.elems) && operation.elems.length > 0) {
          if (conditionMatches.length > 0 || !operation.cond) {
            for (const childOperation of operation.elems) {
              applyCsCodeOperation(childOperation, document);
            }
          }
        }

        if (typeof operation.add_style === 'string' && operation.add_style.length > 0) {
          const head = document.querySelector('head');
          if (head) head.insertAdjacentHTML('beforeend', `<style>${operation.add_style}</style>`);
        }
      };

      if (currentRule.blockJsInline) {
        try {
          if (new RegExp(currentRule.blockJsInline).test(pageURL)) {
            for (const element of queryAll(document, 'script:not([src])')) element.remove();
          }
        } catch {
          // Ignore invalid page-specific inline-script patterns.
        }
      }

      for (const operation of currentRule.csCode) applyCsCodeOperation(operation);

      if (currentRule.ampUnhide) {
        for (const element of queryAll(document, '[subscriptions-section="content-not-granted"]')) {
          element.remove();
        }
        for (const element of queryAll(document, '[subscriptions-section]')) {
          element.removeAttribute('subscriptions-section');
        }
        for (const element of queryAll(document, '[amp-access-hide]')) {
          element.removeAttribute('amp-access-hide');
        }
        for (const element of queryAll(document, 'amp-img[src]')) {
          const image = document.createElement('img');
          for (const attribute of Array.from(element.attributes || [])) {
            image.setAttribute(attribute.name, attribute.value);
          }
          element.replaceWith(image);
        }
      }

      for (const injection of currentRule.injections) {
        const content = injection.append || injection.prepend || injection.replace || '';
        if (!content) continue;

        let selector = injection.position || 'head';
        if (selector === 'head' || selector === 'body' || selector === 'html') {
          // Keep the semantic selectors unchanged.
        } else if (!selector.includes('.') && !selector.includes('#') && !selector.includes('[')) {
          selector = 'head';
        }

        let targets = queryAll(document, selector);
        if (targets.length === 0) {
          const fallbackHead = document.querySelector('head');
          targets = fallbackHead ? [fallbackHead] : [];
        }

        for (const target of targets) {
          if (injection.replace) {
            target.innerHTML = content;
          } else if (injection.prepend) {
            target.insertAdjacentHTML('afterbegin', content);
          } else {
            target.insertAdjacentHTML('beforeend', content);
          }
        }
      }
    },
    { pageURL: targetURL, currentRule: safeRule },
  );
}

function buildPostProcessRule(rule) {
  return {
    domain: '__ladderflare_rendered__',
    regexRules: Array.isArray(rule?.regexRules) ? rule.regexRules : [],
    contentExtraction: rule?.contentExtraction,
    externalLink: rule?.externalLink,
  };
}

export async function fetchKitesurfContent(targetURL, fetchInstructions, env) {
  if (!env?.BROWSER) {
    throw new Error('Kitesurf rendering requires a BROWSER binding');
  }

  const browser = await puppeteer.launch(env.BROWSER, {
    browser: 'kitesurf',
  });

  let requestBlockingState = null;

  try {
    const page = await browser.newPage();
    const headers = normalizeBrowserHeaders(fetchInstructions);
    const bpcBridgeToken = crypto.randomUUID();
    let bpcExternalFetches = 0;

    try {
      await page.exposeFunction('__ladderflareBpcFetch', async ({ token, url, headers: requestHeaders } = {}) => {
        if (token !== bpcBridgeToken || !isSafeBpcExternalURL(url) || bpcExternalFetches >= MAX_BPC_EXTERNAL_FETCHES) {
          return { ok: false, status: 400, text: '' };
        }

        bpcExternalFetches += 1;
        const response = await fetch(url, {
          headers: requestHeaders && typeof requestHeaders === 'object' ? requestHeaders : {},
        });
        const text = await response.text();
        if (text.length > MAX_BPC_EXTERNAL_FETCH_BYTES) {
          return { ok: false, status: 413, text: '' };
        }
        return { ok: response.ok, status: response.status, text };
      });
    } catch (error) {
      console.warn('Ladderflare BPC external-fetch bridge unavailable:', error?.message || String(error));
    }

    await page.setUserAgent(fetchInstructions.userAgent);
    await page.setExtraHTTPHeaders(headers);

    const client = await page.target().createCDPSession();
    if (fetchInstructions.rule?.bpc) {
      await client.send('Page.addScriptToEvaluateOnNewDocument', {
        source: buildBpcCompatibilityScript(targetURL, fetchInstructions.rule, bpcBridgeToken),
      });
    }
    const earlyInjectionScript = buildEarlyInjectionScript(fetchInstructions.rule?.injections);
    if (earlyInjectionScript) {
      await client.send('Page.addScriptToEvaluateOnNewDocument', {
        source: earlyInjectionScript,
      });
    }

    requestBlockingState = await installRequestBlocking(page, fetchInstructions.rule, targetURL);

    await page.goto(fetchInstructions.url || targetURL, {
      referer: fetchInstructions.referer || undefined,
      waitUntil: 'domcontentloaded',
      timeout: 60000,
    });

    const waitMs = getBrowserWaitMs(env);
    if (waitMs > 0) {
      await new Promise((resolve) => setTimeout(resolve, waitMs));
    }

    if (fetchInstructions.rule?.bpc) {
      await page.evaluate(() => globalThis.__ladderflareBpcPostNavigationRun?.());
      const postNavigationWaitMs = getBpcPostNavigationWaitMs(env);
      if (postNavigationWaitMs > 0) {
        await new Promise((resolve) => setTimeout(resolve, postNavigationWaitMs));
      }
    }

    await applyRenderedRule(page, targetURL, fetchInstructions.rule);

    if (env?.BROWSER_DEBUG === 'true') {
      try {
        const bpcDebug = await page.evaluate(() => ({
          state: globalThis.__ladderflareBpc || null,
          extStyles: document.querySelectorAll('style#ext1').length,
          body: Boolean(document.body),
          head: Boolean(document.head),
        }));
        console.log('Ladderflare BPC browser debug:', JSON.stringify(bpcDebug));
      } catch (error) {
        console.warn('Ladderflare BPC browser debug unavailable:', error?.message || String(error));
      }
    }

    // Kitesurf does not implement Puppeteer's page.content() serializer. Read
    // the DOM through Runtime.evaluate, which is available over its CDP path.
    const renderedHTML = await page.evaluate(() => document.documentElement.outerHTML);
    if (renderedHTML.length > MAX_RENDERED_HTML_BYTES) {
      throw new Error(`Rendered HTML exceeds ${MAX_RENDERED_HTML_BYTES} bytes`);
    }

    const processed = processHTMLContent(
      renderedHTML,
      targetURL,
      buildPostProcessRule(fetchInstructions.rule),
    );

    return {
      status: 200,
      body: processed.content,
      headers: {
        'Content-Type': 'text/html; charset=utf-8',
        'Cache-Control': 'no-store',
      },
      requestHeaders: headers,
      originHeaders: {},
    };
  } finally {
    await disableRequestBlocking(requestBlockingState);
    await browser.close();
  }
}
