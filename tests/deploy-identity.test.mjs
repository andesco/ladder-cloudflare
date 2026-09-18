import assert from 'node:assert/strict';
import test from 'node:test';

import {
  applyDeployIdentity,
  getDeployIdentity,
} from '../src/runtime/deploy-identity.js';

test('getDeployIdentity reads Cloudflare version metadata and optional git SHA', () => {
  const deploy = getDeployIdentity({
    CF_VERSION_METADATA: {
      id: '3115be89-7da1-4b03-8d96-748e0ac5f1d8',
      tag: 'production',
      timestamp: '2026-08-07T00:11:16.030Z',
    },
    GIT_SHA: '1454254',
  });

  assert.deepEqual(deploy, {
    id: '3115be89-7da1-4b03-8d96-748e0ac5f1d8',
    tag: 'production',
    timestamp: '2026-08-07T00:11:16.030Z',
    git: '1454254',
  });
});

test('getDeployIdentity leaves missing metadata and blank git as null', () => {
  assert.deepEqual(getDeployIdentity({}), {
    id: null,
    tag: null,
    timestamp: null,
    git: null,
  });

  assert.equal(getDeployIdentity({ GIT_SHA: '   ' }).git, null);
});

test('applyDeployIdentity sets version and git headers without replacing the body', async () => {
  const response = applyDeployIdentity(
    new Response('ok', {
      status: 200,
      headers: { 'Content-Type': 'text/plain' },
    }),
    {
      CF_VERSION_METADATA: { id: 'abc-123' },
      GIT_SHA: 'deadbeef',
    },
  );

  assert.equal(response.status, 200);
  assert.equal(response.headers.get('Content-Type'), 'text/plain');
  assert.equal(response.headers.get('X-Ladderflare-Version'), 'abc-123');
  assert.equal(response.headers.get('X-Ladderflare-Git'), 'deadbeef');
  assert.equal(await response.text(), 'ok');
});

test('applyDeployIdentity omits headers when identity fields are absent', () => {
  const response = applyDeployIdentity(new Response('ok'), {});

  assert.equal(response.headers.get('X-Ladderflare-Version'), null);
  assert.equal(response.headers.get('X-Ladderflare-Git'), null);
});
