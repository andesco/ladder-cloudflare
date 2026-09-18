import assert from 'node:assert/strict';
import test from 'node:test';

import {
  BROWSER_GAP_DOMAIN_COUNT,
  BROWSER_GAP_RULES,
  getBrowserGapForURL,
} from '../src/runtime/browser-gaps.js';

test('recognizes a normalized refresh-gap hostname', () => {
  const gap = getBrowserGapForURL('https://www.afr.com/news/example');

  assert.deepEqual(gap.reasons, ['refresh']);
  assert.equal(gap.host, 'afr.com');
});

test('reports all known gaps when a domain overlaps audit categories', () => {
  const lastampa = getBrowserGapForURL('https://lastampa.it/news/example');
  const historyToday = getBrowserGapForURL('https://www.historytoday.com/example');

  assert.deepEqual(lastampa.reasons, ['refresh', 'cookie-clear']);
  assert.deepEqual(historyToday.reasons, ['refresh', 'all-frames']);
});

test('does not gate a domain outside the compatibility audit', () => {
  assert.equal(getBrowserGapForURL('https://example.com/story'), null);
});

test('the audit lists 54 unique gated domains', () => {
  assert.equal(BROWSER_GAP_DOMAIN_COUNT, 54);
  assert.equal(BROWSER_GAP_RULES.length, 4);
});
