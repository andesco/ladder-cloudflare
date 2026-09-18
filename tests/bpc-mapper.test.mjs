import assert from 'node:assert/strict';
import test from 'node:test';

import { mapBPCEntry, validateBPCData } from '../scripts/bpc-mapper.mjs';

test('maps AMP redirects without inventing a query parameter', () => {
  const rule = mapBPCEntry({ domain: 'example.com', amp_redirect: '.paywall|/amp{path}' });
  assert.equal(rule.ampRedirect, '.paywall|/amp{path}');
  assert.equal(rule.urlMods, undefined);
});

test('does not leak content-script parameters into origin request headers', () => {
  const rule = mapBPCEntry({
    domain: 'example.com',
    cs_param: { 'x-access-token': 'content-script-only' },
  });
  assert.equal(rule.extraHeaders, undefined);
});

test('does not clear shared proxy storage for publisher storage rules', () => {
  const rule = mapBPCEntry({ domain: 'example.com', cs_clear_lclstrg: 1 });
  assert.equal(rule.clearStorage, undefined);
  assert.equal(rule.csClearLocalStorage, true);
});

test('keeps browser-only BPC content-script inputs for the Kitesurf adapter', () => {
  const rule = mapBPCEntry({
    domain: 'example.com',
    allow_cookies: 1,
    cs_all_frames: 1,
    cs_block: 1,
    cs_param: { article_sel: 'article' },
  });
  assert.equal(rule.bpc, true);
  assert.equal(rule.allowCookies, true);
  assert.equal(rule.csAllFrames, true);
  assert.equal(rule.csBlock, true);
  assert.deepEqual(rule.csParam, { article_sel: 'article' });
});

test('rejects newly introduced BPC and cs_code fields instead of silently dropping them', () => {
  assert.throws(
    () => validateBPCData([{ domain: 'example.com', future_rule: 1 }]),
    /Unknown BPC fields: future_rule/,
  );
  assert.throws(
    () => validateBPCData([{ domain: 'example.com', cs_code: [{ cond: 'article', future_op: 1 }] }]),
    /Unknown BPC fields: cs_code\.future_op/,
  );
});

test('keeps pseudo-domain general block rules as global rules', () => {
  assert.deepEqual(
    mapBPCEntry({
      domain: '###_arcxp.com',
      block_regex_general: '\\/arc\\/subs\\/p\\.min\\.js',
      excluded_domains: ['example.com'],
    }),
    {
      global: true,
      blockScriptsGeneral: [
        { pattern: '\\/arc\\/subs\\/p\\.min\\.js', excludedDomains: ['example.com'] },
      ],
    },
  );
});
