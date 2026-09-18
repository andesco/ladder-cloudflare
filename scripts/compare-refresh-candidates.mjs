#!/usr/bin/env node

import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import { parseHTML } from 'linkedom';

const DEFAULT_WORKER_URL = 'https://ladderflare.example.workers.dev';
const DEFAULT_AUDIT_PATH = new URL('../documentation/bpc-kitesurf-compatibility-gap-audit.md', import.meta.url);
const DEFAULT_RULESET_URL = `${DEFAULT_WORKER_URL}/ruleset`;
const MAX_BODY_BYTES = 8 * 1024 * 1024;
const REQUEST_TIMEOUT_MS = 20_000;
const USER_AGENT = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/131.0 Safari/537.36';

function parseArgs(argv) {
  const options = {
    workerURL: process.env.WORKER_URL || DEFAULT_WORKER_URL,
    auditPath: process.env.AUDIT_PATH || DEFAULT_AUDIT_PATH,
    rulesetURL: process.env.RULESET_URL || DEFAULT_RULESET_URL,
    concurrency: Number(process.env.CONCURRENCY || 2),
  };

  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === '--worker') options.workerURL = argv[++index];
    else if (arg === '--audit') options.auditPath = argv[++index];
    else if (arg === '--ruleset') options.rulesetURL = argv[++index];
    else if (arg === '--concurrency') options.concurrency = Number(argv[++index]);
    else if (arg === '--help') {
      console.log('Usage: node scripts/compare-refresh-candidates.mjs [--worker URL] [--audit PATH] [--ruleset URL] [--concurrency N]');
      process.exit(0);
    }
  }

  options.concurrency = Number.isFinite(options.concurrency) && options.concurrency > 0
    ? Math.min(Math.floor(options.concurrency), 4)
    : 2;
  options.workerURL = options.workerURL.replace(/\/$/, '');
  return options;
}

function normalizeDomain(value) {
  return String(value || '').toLowerCase().replace(/^www\./, '').replace(/\.$/, '');
}

function isSameDomain(hostname, domain) {
  const host = normalizeDomain(hostname);
  const target = normalizeDomain(domain);
  return host === target || host.endsWith(`.${target}`) || target.endsWith(`.${host}`);
}

async function readAuditDomains(auditPath) {
  const text = await fs.readFile(auditPath, 'utf8');
  const match = text.match(/The 42 candidates are:\s*```text\s*([\s\S]*?)```/i);
  if (!match) throw new Error(`Could not find the 42-domain code block in ${auditPath}`);

  const domains = match[1]
    .split(/\s+/)
    .map((value) => value.trim().toLowerCase())
    .filter((value) => /^[a-z0-9][a-z0-9.-]+\.[a-z]{2,}$/i.test(value));

  return [...new Set(domains)];
}

async function fetchWithTimeout(url, init = {}, timeoutMs = REQUEST_TIMEOUT_MS) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, {
      ...init,
      signal: controller.signal,
    });
  } finally {
    clearTimeout(timer);
  }
}

async function readBody(response) {
  if (!response.body) return '';
  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > MAX_BODY_BYTES) {
      await reader.cancel('comparison body limit');
      throw new Error(`body exceeds ${MAX_BODY_BYTES} bytes`);
    }
    chunks.push(value);
  }

  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder().decode(bytes);
}

function hash(value) {
  return crypto.createHash('sha256').update(value).digest('hex').slice(0, 16);
}

function parseBody(body, contentType) {
  const base = {
    bytes: Buffer.byteLength(body),
    bodyHash: hash(body),
    title: '',
    textLength: 0,
    articleTextLength: 0,
    articleHash: '',
    paywallSignals: [],
  };

  if (!contentType.includes('html') && !/<html[\s>]/i.test(body)) return base;

  try {
    const { document } = parseHTML(body);
    const article = document.querySelector('article, [itemprop="articleBody"], main');
    const text = document.body?.textContent?.replace(/\s+/g, ' ').trim() || '';
    const articleText = article?.textContent?.replace(/\s+/g, ' ').trim() || '';
    const selectors = [
      '[class*="paywall" i]',
      '[id*="paywall" i]',
      '[class*="subscribe" i]',
      '[id*="subscribe" i]',
      '[class*="premium" i]',
      '[id*="premium" i]',
      '[data-paywall]',
      '[class*="regwall" i]',
      '[class*="gate" i]',
    ];

    const paywallSignals = [];
    for (const selector of selectors) {
      let count = 0;
      try {
        count = document.querySelectorAll(selector).length;
      } catch {
        count = 0;
      }
      if (count) paywallSignals.push(`${selector}:${count}`);
    }

    return {
      ...base,
      title: document.querySelector('title')?.textContent?.replace(/\s+/g, ' ').trim() || '',
      textLength: text.length,
      articleTextLength: articleText.length,
      articleHash: hash(articleText),
      paywallSignals,
    };
  } catch {
    return base;
  }
}

async function fetchSnapshot(url, label) {
  const startedAt = Date.now();
  try {
    const response = await fetchWithTimeout(url, {
      redirect: 'follow',
      headers: {
        Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'User-Agent': USER_AGENT,
        DNT: '1',
      },
    });
    const contentType = response.headers.get('content-type') || '';
    const body = await readBody(response);
    return {
      label,
      ok: response.ok,
      status: response.status,
      finalURL: response.url,
      contentType,
      elapsedMs: Date.now() - startedAt,
      error: '',
      ...parseBody(body, contentType),
    };
  } catch (error) {
    return {
      label,
      ok: false,
      status: 0,
      finalURL: '',
      contentType: '',
      elapsedMs: Date.now() - startedAt,
      error: error?.name === 'AbortError' ? `timeout after ${REQUEST_TIMEOUT_MS}ms` : String(error?.message || error),
      bytes: 0,
      bodyHash: '',
      title: '',
      textLength: 0,
      articleTextLength: 0,
      articleHash: '',
      paywallSignals: [],
    };
  }
}

function candidateScore(url) {
  const path = url.pathname.toLowerCase();
  let score = Math.min(path.length, 100);
  if (/\/20\d{2}\//.test(path)) score += 80;
  if (/article|story|news|opinion|politics|business|culture|sport|world|magazine/.test(path)) score += 30;
  if (/\d/.test(path)) score += 15;
  if (/\/(tag|tags|category|categories|author|authors|search|login|subscribe|subscription|about|contact|privacy|terms)(\/|$)/.test(path)) score -= 100;
  if (/\.(css|js|jpg|jpeg|png|gif|svg|webp|xml|json|pdf)(\?|$)/.test(path)) score -= 200;
  return score;
}

function discoverArticleFromHTML(baseURL, html, domain) {
  try {
    const { document } = parseHTML(html);
    const candidates = [];
    for (const anchor of document.querySelectorAll('a[href]')) {
      const raw = anchor.getAttribute('href');
      if (!raw || raw.startsWith('#') || raw.startsWith('javascript:') || raw.startsWith('mailto:')) continue;
      try {
        const url = new URL(raw, baseURL);
        if (!/^https?:$/.test(url.protocol) || !isSameDomain(url.hostname, domain)) continue;
        url.hash = '';
        if (url.pathname === '/' || url.pathname.length < 8) continue;
        candidates.push({ url: url.toString(), score: candidateScore(url) });
      } catch {
        // Ignore malformed links from the source page.
      }
    }

    candidates.sort((left, right) => right.score - left.score);
    return candidates[0]?.url || '';
  } catch {
    return '';
  }
}

async function discoverURL(domain, rules) {
  for (const rule of rules) {
    const ruleDomains = [rule.domain, ...(Array.isArray(rule.domains) ? rule.domains : [])]
      .filter(Boolean);
    if (!ruleDomains.some((ruleDomain) => isSameDomain(ruleDomain, domain))) continue;
    for (const test of Array.isArray(rule.tests) ? rule.tests : []) {
      if (!test?.url) continue;
      try {
        const testURL = new URL(test.url);
        if (isSameDomain(testURL.hostname, domain)) {
          return { url: testURL.toString(), source: 'ruleset-test' };
        }
      } catch {
        // Continue to homepage discovery.
      }
    }
  }

  const roots = [`https://${domain}/`, `https://www.${domain}/`];
  for (const root of [...new Set(roots)]) {
    const snapshot = await fetchSnapshot(root, 'discovery');
    if (snapshot.status === 0 || !snapshot.contentType.includes('html')) continue;
    const articleURL = discoverArticleFromHTML(root, await fetchTextForDiscovery(root), domain);
    if (articleURL) return { url: articleURL, source: 'homepage-link' };
  }

  return { url: roots[0], source: 'homepage-fallback' };
}

async function fetchTextForDiscovery(url) {
  try {
    const response = await fetchWithTimeout(url, {
      redirect: 'follow',
      headers: {
        Accept: 'text/html,application/xhtml+xml',
        'User-Agent': USER_AGENT,
      },
    });
    if (!response.ok) return '';
    return await readBody(response);
  } catch {
    return '';
  }
}

async function loadRuleset(url) {
  try {
    const response = await fetchWithTimeout(url, { headers: { Accept: 'application/json' } });
    if (response.ok) {
      const parsed = JSON.parse(await readBody(response));
      if (Array.isArray(parsed)) return parsed;
    }
  } catch (error) {
    console.warn(`Ruleset fetch failed (${error?.message || error}); using local artifact if available.`);
  }

  try {
    return JSON.parse(await fs.readFile('ruleset-embedded.json', 'utf8'));
  } catch (error) {
    throw new Error(`Unable to load a ruleset from ${url} or ruleset-embedded.json: ${error.message}`);
  }
}

function compareSnapshots(origin, browser) {
  return {
    bothHTML: origin.contentType.includes('html') && browser.contentType.includes('html'),
    statusChanged: origin.status !== browser.status,
    bodyChanged: Boolean(origin.bodyHash && browser.bodyHash && origin.bodyHash !== browser.bodyHash),
    articleChanged: Boolean(origin.articleHash && browser.articleHash && origin.articleHash !== browser.articleHash),
    titleChanged: origin.title !== browser.title,
    articleTextDelta: browser.articleTextLength - origin.articleTextLength,
    paywallSignalsRemoved: origin.paywallSignals.length > browser.paywallSignals.length,
  };
}

async function mapWithConcurrency(values, concurrency, callback) {
  const results = new Array(values.length);
  let nextIndex = 0;

  async function worker() {
    while (true) {
      const index = nextIndex;
      nextIndex += 1;
      if (index >= values.length) return;
      results[index] = await callback(values[index], index);
    }
  }

  await Promise.all(Array.from({ length: Math.min(concurrency, values.length) }, () => worker()));
  return results;
}

function compact(value, maxLength = 32) {
  const text = String(value || '-').replace(/\s+/g, ' ');
  return text.length > maxLength ? `${text.slice(0, maxLength - 1)}…` : text;
}

function printRecord(record) {
  const origin = record.origin;
  const browser = record.browser;
  const comparison = record.comparison;
  const flags = [];
  if (comparison?.articleChanged) flags.push('article');
  if (comparison?.paywallSignalsRemoved) flags.push('paywall↓');
  if (comparison?.statusChanged) flags.push('status');
  if (record.discovery.source !== 'ruleset-test') flags.push(record.discovery.source === 'homepage-link' ? 'discovered' : 'home');
  if (origin.error || browser.error) flags.push('error');
  console.log(
    `${record.domain.padEnd(25)} ` +
    `${String(origin.status || '-').padStart(3)}→${String(browser.status || '-').padEnd(3)} ` +
    `${String(origin.articleTextLength).padStart(6)}→${String(browser.articleTextLength).padEnd(6)} ` +
    `${flags.join(',') || 'same'} ` +
    `${compact(record.targetURL, 76)}`,
  );
  if (origin.error || browser.error) {
    console.log(`  origin: ${origin.error || 'ok'}; browser: ${browser.error || 'ok'}`);
  }
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  const domains = await readAuditDomains(options.auditPath);
  const rules = await loadRuleset(options.rulesetURL);

  console.log(`Comparing ${domains.length} refresh candidates`);
  console.log(`Worker: ${options.workerURL}`);
  console.log(`Concurrency: ${options.concurrency}; timeout: ${REQUEST_TIMEOUT_MS}ms`);
  console.log('domain                    HTTP→BPC article chars  result target');
  console.log('-'.repeat(150));

  const records = await mapWithConcurrency(domains, options.concurrency, async (domain) => {
    const discovery = await discoverURL(domain, rules);
    const targetURL = discovery.url;
    const browserURL = `${options.workerURL}/browser/${targetURL}`;
    const [origin, browser] = await Promise.all([
      fetchSnapshot(targetURL, 'origin'),
      fetchSnapshot(browserURL, 'browser'),
    ]);
    const record = {
      domain,
      targetURL,
      discovery,
      origin,
      browser,
      comparison: compareSnapshots(origin, browser),
    };
    printRecord(record);
    return record;
  });

  const usable = records.filter((record) => record.origin.status > 0 || record.browser.status > 0);
  const changed = records.filter((record) => record.comparison?.articleChanged || record.comparison?.paywallSignalsRemoved);
  const browserSuccess = records.filter((record) => record.browser.ok);
  const originSuccess = records.filter((record) => record.origin.ok);
  const errors = records.filter((record) => record.origin.error || record.browser.error);

  console.log('\nSummary');
  console.log(`- candidates: ${records.length}`);
  console.log(`- usable responses (either side): ${usable.length}`);
  console.log(`- regular fetch 2xx: ${originSuccess.length}`);
  console.log(`- Kitesurf 2xx: ${browserSuccess.length}`);
  console.log(`- Kitesurf changed article/paywall signals: ${changed.length}`);
  console.log(`- requests with errors/timeouts: ${errors.length}`);
  console.log('\nNote: a changed DOM is evidence that the rules altered the response; it is not by itself proof that every paywall was fully removed.');
}

main().catch((error) => {
  console.error(error.stack || error);
  process.exitCode = 1;
});
