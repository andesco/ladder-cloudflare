import assert from 'node:assert/strict';
import test from 'node:test';

import { buildFetchInstructions } from '../src/runtime/fetch-instructions.js';
import { findRuleForURL } from '../src/runtime/rule-matcher.js';

test('matches the most specific host and path rule', () => {
  const rules = [
    { domain: 'example.com', headers: { referer: 'https://broad.example/' } },
    { domain: 'sub.example.com', paths: ['/news'], headers: { referer: 'https://specific.example/' } },
  ];

  const rule = findRuleForURL('https://sub.example.com/news/story', rules);
  assert.equal(rule.headers.referer, 'https://specific.example/');
});

test('keeps mapped cookie policy in fetch instructions', () => {
  const instructions = buildFetchInstructions(
    'https://example.com/story',
    [
      {
        domain: 'example.com',
        cookiePolicy: { drop: ['xbc'] },
      },
    ],
    {},
  );

  assert.deepEqual(instructions.cookiePolicy, { drop: ['xbc'] });
});
