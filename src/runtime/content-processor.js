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

function parseContentExtractionSpec(spec) {
  const parts = String(spec || '').split('|');
  return {
    paywallSelector: parts[0] || '',
    articleSelector: parts[1] || '',
    append: Boolean(parts[2]),
    hold: Boolean(parts[3]),
    articleIdSelector: parts[4] || '',
    key: parts[5] || '',
    restRoute: Boolean(parts[6]),
  };
}

function normalizeArticleContent(value) {
  if (Array.isArray(value)) {
    return value
      .map((item) => {
        if (typeof item === 'string') return item;
        if (!item || typeof item !== 'object') return '';
        if (Array.isArray(item.children)) {
          return item.children.map((child) => child?.text || child?.innerHTML || '').join('');
        }
        return item.text || item.innerHTML || '';
      })
      .filter(Boolean)
      .join('<br><br>');
  }

  return typeof value === 'string' ? value.trim() : '';
}

function findArticleContentInJSON(value, preferredKeys, seen = new Set()) {
  if (!value || typeof value !== 'object' || seen.has(value)) {
    return '';
  }

  seen.add(value);
  for (const key of preferredKeys) {
    const direct = normalizeArticleContent(value[key]);
    if (direct) return direct;
  }

  for (const child of Object.values(value)) {
    if (child && typeof child === 'object') {
      const found = findArticleContentInJSON(child, preferredKeys, seen);
      if (found) return found;
    }
  }

  return '';
}

function getNestedValue(value, path) {
  if (!value || typeof value !== 'object' || !path) return undefined;
  if (Object.prototype.hasOwnProperty.call(value, path)) return value[path];
  return path.split('.').reduce((current, key) => current?.[key], value);
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
      const text =
        mode === 'next'
          ? findArticleContentInJSON(parsed, [
              'blocks',
              'body',
              'BodyPlainText',
              'content',
              'contentHtml',
              'description',
              'html',
            ])
          : findArticleContentInJSON(parsed, ['articleBody', 'text', 'description']);
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

function sanitizeExtractedHTML(value) {
  const raw = String(value || '');
  if (!raw.includes('<')) {
    return articleTextToHTML(raw.replace(/(?:\\r)?\\n/g, '\n'));
  }

  let document;
  try {
    ({ document } = parseHTML(`<html><body><div id="bpc-extracted">${raw}</div></body></html>`));
  } catch {
    return articleTextToHTML(raw);
  }

  const root = document.querySelector('#bpc-extracted');
  if (!root) return articleTextToHTML(raw);

  for (const element of queryAllSafe(root, 'script,style,object,base,meta,link')) {
    element.remove();
  }

  for (const element of queryAllSafe(root, '*')) {
    for (const attribute of Array.from(element.attributes || [])) {
      const name = String(attribute.name || '').toLowerCase();
      const valueText = String(attribute.value || '').trim().toLowerCase();
      if (
        name.startsWith('on') ||
        name === 'srcdoc' ||
        (['href', 'src', 'xlink:href', 'action'].includes(name) &&
          (valueText.startsWith('javascript:') || valueText.startsWith('data:text/html')))
      ) {
        element.removeAttribute(attribute.name);
      }
    }
  }

  return root.innerHTML;
}

function applyExtractedContent(document, spec, content, mode = '') {
  const parsed = parseContentExtractionSpec(spec);
  const sourceParts = String(spec || '').split('|');
  const paywallSelector = parsed.paywallSelector;
  const articleSelector = parsed.articleSelector;
  const append = mode === 'ldJsonSource' ? Boolean(sourceParts[4]) : parsed.append;
  const hold = mode === 'ldJsonSource' ? Boolean(sourceParts[5]) : parsed.hold;
  if (!paywallSelector || !articleSelector || !content) return false;

  const paywalls = queryAllSafe(document, paywallSelector);
  const article = document.querySelector(articleSelector);
  if (paywalls.length === 0 || !article) return false;

  for (const paywall of paywalls) paywall.remove();
  const safeHTML = sanitizeExtractedHTML(content);
  if (!safeHTML) return false;

  if (append || !article.parentNode) {
    if (!hold) article.innerHTML = '';
    article.insertAdjacentHTML('beforeend', `<div>${safeHTML}</div>`);
  } else {
    article.outerHTML = `<div style="margin:25px 0px">${safeHTML}</div>`;
  }
  return true;
}

function extractBalancedJSON(text, startIndex) {
  const source = String(text || '');
  let start = -1;
  for (let index = Math.max(0, startIndex); index < source.length; index += 1) {
    if (source[index] === '{' || source[index] === '[') {
      start = index;
      break;
    }
  }
  if (start < 0) return '';

  const stack = [];
  let quote = '';
  let escaped = false;
  for (let index = start; index < source.length; index += 1) {
    const char = source[index];
    if (quote) {
      if (escaped) escaped = false;
      else if (char === '\\') escaped = true;
      else if (char === quote) quote = '';
      continue;
    }
    if (char === '"' || char === "'") {
      quote = char;
      continue;
    }
    if (char === '{' || char === '[') stack.push(char);
    else if (char === '}' || char === ']') {
      stack.pop();
      if (stack.length === 0) return source.slice(start, index + 1);
    }
  }
  return '';
}

function extractSourceJSONContent(document, spec) {
  const parts = String(spec || '').split('|');
  const filter = parts[2] || '';
  const key = parts[3] || '';
  if (!filter || !key) return '';

  const normalizedFilter = filter.replace(/\s+/g, '');
  for (const script of queryAllSafe(document, 'script:not([src])')) {
    const text = String(script.textContent || '');
    const normalizedText = text.replace(/\s+/g, '');
    const normalizedIndex = normalizedText.indexOf(normalizedFilter);
    if (normalizedIndex < 0) continue;

    const filterStart = text.search(new RegExp(filter.replace(/[.*+?^${}()|[\]\\]/g, '\\$&').replace('=', '\\s*=\\s*')));
    const jsonText = extractBalancedJSON(text, filterStart < 0 ? 0 : filterStart + filter.length);
    if (!jsonText) continue;
    try {
      return normalizeArticleContent(getNestedValue(JSON.parse(jsonText), key));
    } catch {
      // Try the next matching script.
    }
  }
  return '';
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

function parseExternalJSONContent(payload, key) {
  if (typeof payload !== 'string' || !payload.trim()) return '';
  try {
    const json = JSON.parse(payload.replace(/<script>[\s\S]+<\/script>/g, ''));
    const value = key ? getNestedValue(json, key) : getNestedValue(json, 'content.rendered');
    return normalizeArticleContent(value);
  } catch {
    return '';
  }
}

function applyJSONContentExtraction(document, extraction, options = {}) {
  if (!extraction || typeof extraction !== 'object') {
    return;
  }

  const candidates = ['ldJsonNext', 'ldJson', 'ldJsonSource', 'ldJsonUrl'];

  for (const key of candidates) {
    if (typeof extraction[key] !== 'string' || extraction[key].length === 0) {
      continue;
    }

    let content = '';
    if (key === 'ldJsonNext') content = extractArticleTextFromDocument(document, 'next');
    else if (key === 'ldJson') content = extractArticleTextFromDocument(document, 'ld');
    else if (key === 'ldJsonSource') content = extractSourceJSONContent(document, extraction[key]);
    else if (key === 'ldJsonUrl') {
      const { key: nestedKey } = parseContentExtractionSpec(extraction[key]);
      content = parseExternalJSONContent(options.jsonURLPayload, nestedKey);
    }

    if (applyExtractedContent(document, extraction[key], content, key)) return;
  }
}

export function findAmpRedirectURL(content, targetURL, ampRedirect) {
  if (typeof ampRedirect !== 'string' || !ampRedirect) return '';

  let document;
  try {
    ({ document } = parseHTML(String(content || '')));
  } catch {
    return '';
  }

  const [paywallSelector, configuredAmpURL = ''] = ampRedirect.split('|');
  if (!paywallSelector || queryAllSafe(document, paywallSelector).length === 0) return '';

  const ampScript = document.querySelector('script[src^="https://cdn.ampproject.org/"]');
  const ampLink = document.querySelector('head > link[rel="amphtml"][href]');
  if (ampScript && !ampLink && !configuredAmpURL) return '';

  let ampURL = configuredAmpURL || ampLink?.getAttribute('href') || '';
  if (!ampURL) return '';

  try {
    const current = new URL(targetURL);
    ampURL = ampURL.replaceAll('{path}', current.pathname);
    if (ampURL.includes('{host}')) {
      ampURL = ampURL.replaceAll('{host}', current.hostname.replace(/^www\./, ''));
      if (!/^https?:\/\//i.test(ampURL)) ampURL = `https://${ampURL}`;
    }
    const resolved = new URL(ampURL, current);
    return ['http:', 'https:'].includes(resolved.protocol) ? resolved.toString() : '';
  } catch {
    return '';
  }
}

export function getJSONExtractionRequest(content, targetURL, extraction) {
  const spec = extraction?.ldJsonUrl;
  if (typeof spec !== 'string' || !spec) return null;

  let document;
  try {
    ({ document } = parseHTML(String(content || '')));
  } catch {
    return null;
  }

  const parsedSpec = parseContentExtractionSpec(spec);
  if (
    !parsedSpec.paywallSelector ||
    !parsedSpec.articleSelector ||
    queryAllSafe(document, parsedSpec.paywallSelector).length === 0 ||
    !document.querySelector(parsedSpec.articleSelector)
  ) {
    return null;
  }

  let jsonURL = document
    .querySelector('head > link[rel="alternate"][type="application/json"][href]')
    ?.getAttribute('href');

  if (!jsonURL && parsedSpec.articleIdSelector) {
    const articleID = document
      .querySelector(`${parsedSpec.articleIdSelector}[content]`)
      ?.getAttribute('content');
    if (articleID) {
      try {
        jsonURL = new URL(`/wp-json/wp/v2/posts/${encodeURIComponent(articleID)}`, targetURL).toString();
      } catch {
        return null;
      }
    }
  }

  if (!jsonURL) return null;
  try {
    const target = new URL(targetURL);
    const resolved = new URL(jsonURL, targetURL);
    if (/^www\.autohebdo(?:f1)?\.\w{2,3}$/.test(resolved.hostname) && resolved.hostname !== target.hostname) {
      resolved.hostname = target.hostname;
    }
    if (!['http:', 'https:'].includes(resolved.protocol) || resolved.hostname !== target.hostname) return null;
    if (parsedSpec.restRoute) resolved.href = resolved.href.replace('/wp-json/', '/?rest_route=/');
    return { url: resolved.toString() };
  } catch {
    return null;
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
      const classes = op.rm_class.split(/[,|\s]+/).filter(Boolean);
      for (const element of condMatches) {
        for (const className of classes) {
          element.classList.remove(className);
        }
      }
    }

    if (typeof op.rm_attrib === 'string' && op.rm_attrib.length > 0) {
      const attributes = op.rm_attrib.split('|').map((value) => value.trim()).filter(Boolean);
      for (const element of condMatches) {
        for (const attribute of attributes) element.removeAttribute(attribute);
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
    // BPC treats `elems` as follow-up document-wide operations once the
    // parent condition matched; it is not a nested selector scope.
    if (condMatches.length > 0 || !op.cond) {
      for (const childOp of op.elems) {
        applyCsCodeOperation(document, childOp, document);
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

  for (const element of queryAllSafe(document, 'amp-img[src]')) {
    const image = document.createElement('img');
    for (const attribute of Array.from(element.attributes || [])) {
      image.setAttribute(attribute.name, attribute.value);
    }
    element.replaceWith(image);
  }

  for (const element of queryAllSafe(document, 'amp-iframe[src]')) {
    const iframe = document.createElement('iframe');
    for (const attribute of Array.from(element.attributes || [])) {
      iframe.setAttribute(attribute.name, attribute.value);
    }
    iframe.setAttribute('width', iframe.getAttribute('width') || '100%');
    element.replaceWith(iframe);
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
    ['iframe[src]', 'src'],
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

  applyJSONContentExtraction(document, currentRule.contentExtraction, options);
  applyArchiveFallback(document, targetURL, currentRule.archiveFallback, options.archiveHTML, options.archiveURL);

  applyCsCode(document, currentRule.csCode);

  if (currentRule.ampUnhide) {
    applyAmpUnhide(document);
  }

  rewriteHTMLDocument(document, originalHost);

  applyInjectionsToDocument(document, currentRule.injections);
  applyExternalLink(document, targetURL, currentRule.externalLink);

  let serialized;
  try {
    serialized = document.toString();
  } catch {
    serialized = withRegexRules;
  }

  const rewritten = rewriteCSSURLRefs(serialized, originalHost);
  return csp ? { content: rewritten, csp } : { content: rewritten };
}
