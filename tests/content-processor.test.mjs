import assert from 'node:assert/strict';
import test from 'node:test';

import { processContent } from '../src/runtime/content-processor.js';

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
