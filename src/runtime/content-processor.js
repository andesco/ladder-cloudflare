import { parseHTML } from 'linkedom';

const CSS_URL_FUNC_PATTERN = /url\(\s*("[^"]*"|'[^']*'|[^'")]+)\s*\)/gi;
const HTML_ATTR_PATTERN = /\b(src|href|action)\s*=\s*("[^"]*"|'[^']*')/gi;

function compileRegex(pattern, { global = false } = {}) {
  if (typeof pattern !== 'string' || pattern.length === 0) {
    return null;
  }

  const flags = global ? 'g' : '';

  try {
    return new RegExp(pattern, flags);
  } catch {
    if (pattern.startsWith('(?i)')) {
      try {
        return new RegExp(pattern.slice(4), `${flags}i`);
      } catch {
        return null;
      }
    }

    return null;
  }
}

function rewriteProxyURLRef(rawValue, originalHost) {
  const trimmed = String(rawValue || '').trim();
  if (!trimmed || !originalHost) {
    return rawValue;
  }

  if (trimmed.startsWith('//')) {
    return rawValue;
  }

  if (trimmed.startsWith('/https://') || trimmed.startsWith('/http://')) {
    return `/${trimmed.replace(/^\//, '')}`;
  }

  if (trimmed.startsWith('/')) {
    return `/https://${originalHost}/${trimmed.replace(/^\//, '')}`;
  }

  const httpsPrefix = `https://${originalHost}/`;
  const httpPrefix = `http://${originalHost}/`;

  if (trimmed.startsWith(httpsPrefix)) {
    return `/https://${originalHost}/${trimmed.slice(httpsPrefix.length)}`;
  }

  if (trimmed.startsWith(httpPrefix)) {
    return `/http://${originalHost}/${trimmed.slice(httpPrefix.length)}`;
  }

  if (trimmed === `https://${originalHost}`) {
    return `/https://${originalHost}/`;
  }

  if (trimmed === `http://${originalHost}`) {
    return `/http://${originalHost}/`;
  }

  return rawValue;
}

function rewriteCSSURLRefs(content, originalHost) {
  return String(content || '').replace(CSS_URL_FUNC_PATTERN, (match, token) => {
    const trimmedToken = String(token || '').trim();
    if (!trimmedToken) {
      return match;
    }

    let quote = '';
    let value = trimmedToken;

    if (value.length >= 2) {
      const first = value[0];
      const last = value[value.length - 1];
      if ((first === '"' && last === '"') || (first === "'" && last === "'")) {
        quote = first;
        value = value.slice(1, -1);
      }
    }

    const rewritten = rewriteProxyURLRef(value, originalHost);
    if (rewritten === value) {
      return match;
    }

    return `url(${quote}${rewritten}${quote})`;
  });
}

function rewriteHTMLFallback(content, originalHost) {
  const rewritten = String(content || '').replace(HTML_ATTR_PATTERN, (match, attr, quotedValue) => {
    if (typeof quotedValue !== 'string' || quotedValue.length < 2) {
      return match;
    }

    const quote = quotedValue[0];
    const value = quotedValue.slice(1, -1);
    const nextValue = rewriteProxyURLRef(value, originalHost);

    if (nextValue === value) {
      return match;
    }

    return `${attr}=${quote}${nextValue}${quote}`;
  });

  return rewriteCSSURLRefs(rewritten, originalHost);
}

function queryAllSafe(document, selector) {
  try {
    return Array.from(document.querySelectorAll(selector));
  } catch {
    return [];
  }
}

function escapeHTML(value) {
  return String(value || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function parseExtractionSelectorSpec(spec) {
  const parts = String(spec || '').split('|');
  return {
    paywallSelector: parts[0] || '',
    articleSelector: parts[1] || '',
    sourceSelector: parts[2] || parts[1] || '',
    archiveLinkSelector: parts[3] || parts[1] || '',
  };
}

function normalizeArticleText(value) {
  if (Array.isArray(value)) {
    return value.map(normalizeArticleText).filter(Boolean).join('\n\n');
  }

  if (typeof value === 'string') {
    return value.trim();
  }

  return '';
}

function findArticleTextInJSON(value, seen = new Set()) {
  if (!value || typeof value !== 'object' || seen.has(value)) {
    return '';
  }

  seen.add(value);

  const direct =
    normalizeArticleText(value.articleBody) ||
    normalizeArticleText(value.text) ||
    normalizeArticleText(value.description);
  if (direct) {
    return direct;
  }

  for (const child of Object.values(value)) {
    if (Array.isArray(child)) {
      for (const item of child) {
        const found = findArticleTextInJSON(item, seen);
        if (found) {
          return found;
        }
      }
    } else if (child && typeof child === 'object') {
      const found = findArticleTextInJSON(child, seen);
      if (found) {
        return found;
      }
    }
  }

  return '';
}

function parseJSONScriptText(text) {
  try {
    return JSON.parse(String(text || '').trim());
  } catch {
    return null;
  }
}

function extractArticleTextFromDocument(document, mode) {
  const selectors =
    mode === 'next'
      ? ['script#__NEXT_DATA__', 'script[type="application/json"]']
      : ['script[type="application/ld+json"]', 'script[data-rh="true"][type="application/ld+json"]'];

  for (const selector of selectors) {
    for (const script of queryAllSafe(document, selector)) {
      const parsed = parseJSONScriptText(script.textContent);
      const text = findArticleTextInJSON(parsed);
      if (text) {
        return text;
      }
    }
  }

  return '';
}

function articleTextToHTML(text) {
  return String(text || '')
    .split(/\n{2,}/)
    .map((paragraph) => paragraph.trim())
    .filter(Boolean)
    .map((paragraph) => `<p>${escapeHTML(paragraph)}</p>`)
    .join('\n');
}

function strippedURL(value) {
  try {
    const url = new URL(value);
    url.hash = '';
    url.search = '';
    return url.toString();
  } catch {
    return String(value || '').split(/[?#]/)[0];
  }
}

function buildExternalLinkURL(type, targetURL) {
  const cleanURL = strippedURL(targetURL);
  switch (type) {
    case 'google_search_tool':
      return `https://search.google.com/test/rich-results?url=${encodeURIComponent(cleanURL)}`;
    case 'archive.is':
    default:
      return `https://archive.today?run=1&url=${encodeURIComponent(cleanURL)}`;
  }
}

function buildExternalLinkLabel(type) {
  switch (type) {
    case 'google_search_tool':
      return 'Try Google rich results';
    case 'archive.is':
    default:
      return 'Try archived article';
  }
}

function createExternalLinkHTML(type, targetURL, prefix = 'Try for full article text:') {
  const href = buildExternalLinkURL(type, targetURL);
  const label = buildExternalLinkLabel(type);
  return [
    '<div id="bpc_archive" style="margin:20px;font-size:18px;font-weight:bold;color:#b00020;line-height:normal;">',
    `<span>${escapeHTML(prefix)} </span>`,
    `<a href="${escapeHTML(href)}" target="_blank" rel="noopener noreferrer">${escapeHTML(label)}</a>`,
    '</div>',
  ].join('');
}

function insertHTMLBeforeFirstChildOrAppend(element, html) {
  if (!element) {
    return;
  }

  element.insertAdjacentHTML(element.firstChild ? 'afterbegin' : 'beforeend', html);
}

function applyExternalLink(document, targetURL, externalLink) {
  if (!externalLink || typeof externalLink !== 'object' || typeof externalLink.selector !== 'string') {
    return;
  }

  const { paywallSelector, articleSelector } = parseExtractionSelectorSpec(externalLink.selector);
  if (!paywallSelector || !articleSelector) {
    return;
  }

  const paywalls = queryAllSafe(document, paywallSelector);
  if (paywalls.length === 0) {
    return;
  }

  for (const paywall of paywalls) {
    paywall.remove();
  }

  const article = document.querySelector(articleSelector);
  if (!article) {
    return;
  }

  insertHTMLBeforeFirstChildOrAppend(article, createExternalLinkHTML(externalLink.type, targetURL));
}

function applyJSONContentExtraction(document, extraction) {
  if (!extraction || typeof extraction !== 'object') {
    return;
  }

  const candidates = [
    ['ldJsonNext', 'next'],
    ['ldJson', 'ld'],
    ['ldJsonUrl', 'ld'],
    ['ldJsonSource', 'ld'],
  ];

  for (const [key, mode] of candidates) {
    if (typeof extraction[key] !== 'string' || extraction[key].length === 0) {
      continue;
    }

    const text = extractArticleTextFromDocument(document, mode);
    if (!text) {
      continue;
    }

    const { paywallSelector, articleSelector } = parseExtractionSelectorSpec(extraction[key]);
    const articleTargets = articleSelector ? queryAllSafe(document, articleSelector) : [];
    const paywallTargets = paywallSelector ? queryAllSafe(document, paywallSelector) : [];
    const target = articleTargets[0] || paywallTargets[0]?.parentElement || document.querySelector('article') || document.body;

    if (!target) {
      continue;
    }

    target.innerHTML = articleTextToHTML(text);
    for (const paywall of paywallTargets) {
      if (paywall !== target) {
        paywall.remove();
      }
    }
    return;
  }
}

function applyArchiveFallback(document, targetURL, archiveFallback, archiveHTML = '', archiveURL = '') {
  if (!archiveFallback || typeof archiveFallback !== 'object' || typeof archiveFallback.selector !== 'string') {
    return;
  }

  const { paywallSelector, articleSelector, sourceSelector, archiveLinkSelector } = parseExtractionSelectorSpec(
    archiveFallback.selector,
  );
  if (!paywallSelector || !articleSelector) {
    return;
  }

  const paywalls = queryAllSafe(document, paywallSelector);
  if (paywalls.length === 0) {
    return;
  }

  for (const paywall of paywalls) {
    paywall.remove();
  }

  const article = document.querySelector(articleSelector);
  if (!article) {
    const body = document.querySelector('body');
    if (body) {
      insertHTMLBeforeFirstChildOrAppend(body, createExternalLinkHTML('archive.is', targetURL));
    }
    return;
  }

  if (!archiveHTML) {
    insertHTMLBeforeFirstChildOrAppend(article, createExternalLinkHTML('archive.is', targetURL));
    return;
  }

  let archiveDocument;
  try {
    ({ document: archiveDocument } = parseHTML(archiveHTML));
  } catch {
    insertHTMLBeforeFirstChildOrAppend(article, createExternalLinkHTML('archive.is', targetURL));
    return;
  }

  const source = archiveDocument.querySelector(sourceSelector || articleSelector);
  if (!source) {
    insertHTMLBeforeFirstChildOrAppend(article, createExternalLinkHTML('archive.is', targetURL));
    return;
  }

  const replacementHTML = source.outerHTML || source.innerHTML || '';
  if (!replacementHTML) {
    insertHTMLBeforeFirstChildOrAppend(article, createExternalLinkHTML('archive.is', targetURL));
    return;
  }

  article.outerHTML = replacementHTML;
  const replacementTarget = document.querySelector(archiveLinkSelector || articleSelector) || document.querySelector(articleSelector);
  if (replacementTarget) {
    insertHTMLBeforeFirstChildOrAppend(
      replacementTarget,
      createExternalLinkHTML(
        'archive.is',
        archiveURL || targetURL,
        'Full article text fetched from external archive:',
      ),
    );
  }
}

function applyRegexRules(content, regexRules) {
  if (!Array.isArray(regexRules) || regexRules.length === 0) {
    return content;
  }

  let output = content;

  for (const regexRule of regexRules) {
    if (!regexRule || typeof regexRule.match !== 'string') {
      continue;
    }

    const regex = compileRegex(regexRule.match, { global: true });
    if (!regex) {
      continue;
    }

    output = output.replace(regex, String(regexRule.replace ?? ''));
  }

  return output;
}

function domainMatches(host, domain) {
  return host === domain || host.endsWith(`.${domain}`);
}

function patternAppliesToHost(patternEntry, host) {
  if (!patternEntry || typeof patternEntry !== 'object') {
    return true;
  }

  if (!Array.isArray(patternEntry.excludedDomains) || patternEntry.excludedDomains.length === 0) {
    return true;
  }

  return !patternEntry.excludedDomains.some((domain) => {
    return typeof domain === 'string' && domain.length > 0 && domainMatches(host, domain);
  });
}

function getPatternValue(patternEntry) {
  if (typeof patternEntry === 'string') {
    return patternEntry;
  }

  if (patternEntry && typeof patternEntry.pattern === 'string') {
    return patternEntry.pattern;
  }

  return '';
}

function applyBlockScripts(document, patterns, pageHost = '') {
  if (!Array.isArray(patterns) || patterns.length === 0) {
    return;
  }

  const compiled = [];
  for (const patternEntry of patterns) {
    if (!patternAppliesToHost(patternEntry, pageHost)) {
      continue;
    }

    const regex = compileRegex(getPatternValue(patternEntry));
    if (regex) {
      compiled.push(regex);
    }
  }

  if (compiled.length === 0) {
    return;
  }

  for (const element of queryAllSafe(document, 'script[src]')) {
    const src = element.getAttribute('src') || '';
    if (compiled.some((regex) => regex.test(src))) {
      element.remove();
    }
  }

  for (const element of queryAllSafe(document, 'link[href]')) {
    const href = element.getAttribute('href') || '';
    if (compiled.some((regex) => regex.test(href))) {
      element.remove();
    }
  }
}

function applyBlockJsInline(document, pattern, pageURL) {
  const regex = compileRegex(pattern);
  if (!regex || !regex.test(pageURL)) {
    return;
  }

  for (const element of queryAllSafe(document, 'script:not([src])')) {
    element.remove();
  }
}

function applyCsCodeOperation(document, op, scope = document) {
  if (!op || typeof op !== 'object') {
    return;
  }

  if (typeof op.hide_elem === 'string' && op.hide_elem.length > 0) {
    for (const element of queryAllSafe(scope, op.hide_elem)) {
      const existingStyle = element.getAttribute('style') || '';
      const nextStyle = existingStyle
        ? `${existingStyle};display:none!important`
        : 'display:none!important';
      element.setAttribute('style', nextStyle);
    }
  }

  let condMatches = [];
  if (typeof op.cond === 'string' && op.cond.length > 0) {
    condMatches = queryAllSafe(scope, op.cond);

    if (op.rm_elem) {
      for (const element of condMatches) {
        element.remove();
      }
    }

    if (typeof op.rm_class === 'string' && op.rm_class.length > 0) {
      const classes = op.rm_class.split(/\s+/).filter(Boolean);
      for (const element of condMatches) {
        for (const className of classes) {
          element.classList.remove(className);
        }
      }
    }

    if (typeof op.rm_attrib === 'string' && op.rm_attrib.length > 0) {
      for (const element of condMatches) {
        element.removeAttribute(op.rm_attrib);
      }
    }

    if (typeof op.set_attrib === 'string' && op.set_attrib.length > 0) {
      const separatorIndex = op.set_attrib.indexOf('|');
      if (separatorIndex > -1) {
        const attr = op.set_attrib.slice(0, separatorIndex);
        const value = op.set_attrib.slice(separatorIndex + 1);
        for (const element of condMatches) {
          element.setAttribute(attr, value);
        }
      }
    }
  }

  if (Array.isArray(op.elems) && op.elems.length > 0) {
    const childScopes = condMatches.length > 0 ? condMatches : [scope];
    for (const childScope of childScopes) {
      for (const childOp of op.elems) {
        applyCsCodeOperation(document, childOp, childScope);
      }
    }
  }

  if (typeof op.add_style === 'string' && op.add_style.length > 0) {
    const head = document.querySelector('head');
    if (head) {
      head.insertAdjacentHTML('beforeend', `<style>${op.add_style}</style>`);
    }
  }
}

function applyCsCode(document, operations) {
  if (!Array.isArray(operations) || operations.length === 0) {
    return;
  }

  for (const op of operations) {
    applyCsCodeOperation(document, op);
  }
}

function applyAmpUnhide(document) {
  for (const element of queryAllSafe(document, '[subscriptions-section="content-not-granted"]')) {
    element.remove();
  }

  for (const element of queryAllSafe(document, '[subscriptions-section]')) {
    element.removeAttribute('subscriptions-section');
  }

  for (const element of queryAllSafe(document, '[amp-access-hide]')) {
    element.removeAttribute('amp-access-hide');
  }
}

function rewriteSelectionAttr(element, attr, originalHost) {
  const value = element.getAttribute(attr);
  if (!value) {
    return;
  }

  const rewritten = rewriteProxyURLRef(value, originalHost);
  if (rewritten !== value) {
    element.setAttribute(attr, rewritten);
  }
}

function rewriteHTMLDocument(document, originalHost) {
  const rewrites = [
    ['img[src]', 'src'],
    ['script[src]', 'src'],
    ['a[href]', 'href'],
    ['link[href]', 'href'],
    ['form[action]', 'action'],
  ];

  for (const [selector, attr] of rewrites) {
    for (const element of queryAllSafe(document, selector)) {
      rewriteSelectionAttr(element, attr, originalHost);
    }
  }
}

function pickInjectionContent(injection) {
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

function resolveInjectionSelector(position) {
  if (position === 'body') {
    return 'body';
  }

  if (position === 'html') {
    return 'html';
  }

  if (position === 'head' || !position) {
    return 'head';
  }

  if (position.includes('.') || position.includes('#') || position.includes('[')) {
    return position;
  }

  return 'head';
}

function applyInjectionsToDocument(document, injections) {
  if (!Array.isArray(injections) || injections.length === 0) {
    return;
  }

  for (const injection of injections) {
    if (!injection || typeof injection !== 'object') {
      continue;
    }

    const content = pickInjectionContent(injection);
    if (!content) {
      continue;
    }

    const selector = resolveInjectionSelector(injection.position || 'head');
    const targets = queryAllSafe(document, selector);

    if (targets.length > 0) {
      for (const target of targets) {
        if (typeof injection.replace === 'string' && injection.replace.length > 0) {
          target.innerHTML = content;
        } else if (typeof injection.prepend === 'string' && injection.prepend.length > 0) {
          target.insertAdjacentHTML('afterbegin', content);
        } else {
          target.insertAdjacentHTML('beforeend', content);
        }
      }
      continue;
    }

    const fallbackHead = document.querySelector('head');
    if (fallbackHead) {
      fallbackHead.insertAdjacentHTML('beforeend', content);
    }
  }
}

function applyContentInjectionsStringFallback(content, injections) {
  if (!Array.isArray(injections) || injections.length === 0) {
    return content;
  }

  let output = content;

  for (const injection of injections) {
    if (!injection || typeof injection !== 'object') {
      continue;
    }

    const injectionContent = pickInjectionContent(injection);
    if (!injectionContent) {
      continue;
    }

    const position = injection.position || 'head';
    if (position === 'body') {
      output = output.replace(/<\/body>/i, `${injectionContent}\n</body>`);
    } else {
      output = output.replace(/<\/head>/i, `${injectionContent}\n</head>`);
    }
  }

  return output;
}

function getRuleCSP(rule) {
  if (!rule || !rule.headers || typeof rule.headers !== 'object') {
    return '';
  }

  const csp = rule.headers['content-security-policy'];
  return typeof csp === 'string' ? csp : '';
}

export function processContent(content, targetURL, rule, globalBlockPatterns = [], options = {}) {
  const normalizedContent = String(content || '');
  const currentRule = rule && typeof rule === 'object' ? rule : {};
  const csp = getRuleCSP(currentRule);

  let originalHost = '';
  let originalHostname = '';
  try {
    const parsedURL = new URL(targetURL);
    originalHost = parsedURL.host;
    originalHostname = parsedURL.hostname;
  } catch {
    // Leave host empty; URL rewrites will no-op.
  }

  const withRegexRules = applyRegexRules(normalizedContent, currentRule.regexRules);

  let document;
  try {
    ({ document } = parseHTML(withRegexRules));
  } catch {
    const fallbackContent = applyContentInjectionsStringFallback(
      rewriteHTMLFallback(withRegexRules, originalHost),
      currentRule.injections,
    );

    return csp ? { content: fallbackContent, csp } : { content: fallbackContent };
  }

  const blockPatterns = [];

  if (Array.isArray(currentRule.blockScripts)) {
    blockPatterns.push(...currentRule.blockScripts);
  }

  if (Array.isArray(currentRule.blockScriptsGeneral)) {
    blockPatterns.push(...currentRule.blockScriptsGeneral);
  }

  if (Array.isArray(globalBlockPatterns)) {
    blockPatterns.push(...globalBlockPatterns);
  }

  applyBlockScripts(document, blockPatterns, originalHostname || originalHost);

  if (typeof currentRule.blockJsInline === 'string' && currentRule.blockJsInline.length > 0) {
    applyBlockJsInline(document, currentRule.blockJsInline, targetURL);
  }

  applyJSONContentExtraction(document, currentRule.contentExtraction);
  applyArchiveFallback(document, targetURL, currentRule.archiveFallback, options.archiveHTML, options.archiveURL);

  applyCsCode(document, currentRule.csCode);

  if (currentRule.ampUnhide) {
    applyAmpUnhide(document);
  }

  rewriteHTMLDocument(document, originalHost);

  applyInjectionsToDocument(document, currentRule.injections);
  applyExternalLink(document, targetURL, currentRule.externalLink);

  if (currentRule.clearStorage) {
    const head = document.querySelector('head');
    if (head) {
      head.insertAdjacentHTML('afterbegin', '<script>localStorage.clear();sessionStorage.clear()</script>');
    }
  }

  let serialized;
  try {
    serialized = document.toString();
  } catch {
    serialized = withRegexRules;
  }

  const rewritten = rewriteCSSURLRefs(serialized, originalHost);
  return csp ? { content: rewritten, csp } : { content: rewritten };
}
