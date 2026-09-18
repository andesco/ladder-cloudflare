import assert from 'node:assert/strict';
import test from 'node:test';

import {
  findAmpRedirectURL,
  getJSONExtractionRequest,
  processContent,
} from '../src/runtime/content-processor.js';

test('applies nested BPC cs_code operations', () => {
  const html = '<html><head></head><body><article id="locked"><div class="body gated">Text</div></article></body></html>';
  const result = processContent(
    html,
    'https://example.com/story',
    {
      csCode: [
        {
          cond: 'article#locked',
          elems: [{ cond: 'div.body', rm_class: 'gated' }],
        },
      ],
    },
    [],
  );

  assert.match(result.content, /class="body"/);
  assert.doesNotMatch(result.content, /gated/);
});

test('applies nested cs_code operations document-wide and splits attributes', () => {
  const html = '<html class="locked" style="overflow:hidden"><body><div class="paywall"></div><article class="gated dim">Text</article></body></html>';
  const result = processContent(
    html,
    'https://example.com/story',
    {
      csCode: [
        {
          cond: '.paywall',
          rm_elem: true,
          elems: [
            { cond: 'article', rm_class: 'gated|dim' },
            { cond: 'html', rm_attrib: 'class|style' },
          ],
        },
      ],
    },
    [],
  );

  assert.doesNotMatch(result.content, /paywall|gated|dim|overflow:hidden/);
});

test('resolves an AMP redirect only when its paywall is present', () => {
  const html = '<html><head><link rel="amphtml" href="/story/amp"></head><body><div class="paywall"></div></body></html>';
  assert.equal(
    findAmpRedirectURL(html, 'https://example.com/story', '.paywall'),
    'https://example.com/story/amp',
  );
  assert.equal(findAmpRedirectURL(html, 'https://example.com/story', '.missing'), '');
});

test('rebuilds article content from page-source JSON', () => {
  const html = `<html><head><script>var article = {"content":"<p>Recovered <b>article</b></p>"};</script></head><body><div class="paywall"></div><article>Preview</article></body></html>`;
  const result = processContent(
    html,
    'https://example.com/story',
    { contentExtraction: { ldJsonSource: '.paywall|article|var article=|content' } },
    [],
  );

  assert.match(result.content, /Recovered <b>article<\/b>/);
  assert.doesNotMatch(result.content, /Preview|paywall/);
});

test('discovers and applies a same-origin JSON article endpoint', () => {
  const html = '<html><head><link rel="alternate" type="application/json" href="/wp-json/wp/v2/posts/12"></head><body><div class="paywall"></div><article>Preview</article></body></html>';
  const extraction = { ldJsonUrl: '.paywall|article' };
  assert.deepEqual(getJSONExtractionRequest(html, 'https://example.com/story', extraction), {
    url: 'https://example.com/wp-json/wp/v2/posts/12',
  });

  const result = processContent(html, 'https://example.com/story', { contentExtraction: extraction }, [], {
    jsonURLPayload: JSON.stringify({
      content: { rendered: '<p onclick="steal()">Full text</p><script>steal()</script>' },
    }),
  });
  assert.match(result.content, /Full text/);
  assert.doesNotMatch(result.content, /Preview|onclick|steal\(\)|paywall/);
});

test('unhides generic AMP content and converts AMP media elements', () => {
  const html = '<html><body><div subscriptions-section="content-not-granted">Preview</div><article subscriptions-section="content"><p amp-access-hide>Full</p><amp-img src="/image.jpg"></amp-img><amp-iframe src="/video"></amp-iframe></article></body></html>';
  const result = processContent(html, 'https://example.com/story/amp', { ampUnhide: true }, []);

  assert.doesNotMatch(result.content, /Preview|amp-access-hide|subscriptions-section|<amp-/);
  assert.match(result.content, /<img src="\/https:\/\/example.com\/image.jpg">/);
  assert.match(result.content, /<iframe[^>]+src="\/https:\/\/example.com\/video"/);
});

test('honors excluded domains for global block script rules', () => {
  const html = '<html><head><script src="https://cdn.piano.io/xbuilder/experience/execute"></script></head></html>';
  const rule = {};
  const globalBlocks = [
    {
      pattern: '\\/xbuilder\\/experience\\/execute',
      excludedDomains: ['example.com'],
    },
  ];

  const excluded = processContent(html, 'https://example.com/story', rule, globalBlocks);
  const included = processContent(html, 'https://other.example/story', rule, globalBlocks);

  assert.match(excluded.content, /xbuilder\/experience\/execute/);
  assert.doesNotMatch(included.content, /xbuilder\/experience\/execute/);
});

test('rebuilds article body from JSON-LD when content extraction is configured', () => {
  const html = `
    <html>
      <head>
        <script type="application/ld+json">{"@type":"NewsArticle","articleBody":"First paragraph.\\n\\nSecond paragraph."}</script>
      </head>
      <body>
        <article><div class="paywall"></div><div class="content">Locked</div></article>
      </body>
    </html>`;

  const result = processContent(
    html,
    'https://example.com/story',
    {
      contentExtraction: {
        ldJson: '.paywall|.content',
      },
    },
    [],
  );

  assert.match(result.content, /First paragraph/);
  assert.match(result.content, /Second paragraph/);
  assert.doesNotMatch(result.content, /Locked/);
});

test('injects external article link when BPC add_ext_link paywall selector matches', () => {
  const html = '<html><body><article><div class="paywall">Subscribe</div><p>Intro</p></article></body></html>';
  const result = processContent(
    html,
    'https://example.com/story?utm=1',
    {
      externalLink: {
        selector: '.paywall|article',
        type: 'google_search_tool',
      },
    },
    [],
  );

  assert.doesNotMatch(result.content, /Subscribe/);
  assert.match(result.content, /search\.google\.com\/test\/rich-results/);
  assert.match(result.content, /Try Google rich results/);
});

test('replaces article from archive fallback HTML when available', () => {
  const html = '<html><body><article><div class="paywall">Subscribe</div><div class="content">Locked</div></article></body></html>';
  const archiveHTML = '<html><body><article><div class="content"><p>Archived article text</p></div></article></body></html>';
  const result = processContent(
    html,
    'https://example.com/story',
    {
      archiveFallback: {
        selector: '.paywall|.content',
      },
    },
    [],
    {
      archiveURL: 'https://archive.is/https://example.com/story',
      archiveHTML,
    },
  );

  assert.match(result.content, /Archived article text/);
  assert.match(result.content, /Full article text fetched from external archive/);
  assert.doesNotMatch(result.content, /Locked/);
});
