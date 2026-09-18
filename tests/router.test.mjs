import assert from 'node:assert/strict';
import test from 'node:test';

import { routeRequest } from '../src/runtime/router.js';

test('routes root target URLs to the browser renderer by default', () => {
  const result = routeRequest('GET', '/https://example.com/story', {});

  assert.equal(result.type, 'proxy');
  assert.equal(result.responseType, 'browser');
  assert.equal(result.targetURL, 'https://example.com/story');
});

test('routes /browser URLs to the explicit browser renderer alias', () => {
  const result = routeRequest(
    'GET',
    '/browser/https://example.com/story',
    {},
  );

  assert.equal(result.type, 'proxy');
  assert.equal(result.responseType, 'browser');
  assert.equal(result.targetURL, 'https://example.com/story');
});

test('routes /api URLs to the Kitesurf API renderer', () => {
  const result = routeRequest('GET', '/api/https://example.com/story', {});

  assert.equal(result.type, 'proxy');
  assert.equal(result.responseType, 'browser-api');
  assert.equal(result.targetURL, 'https://example.com/story');
});

test('routes /raw URLs to the Kitesurf raw renderer', () => {
  const result = routeRequest('GET', '/raw/https://example.com/story', {});

  assert.equal(result.type, 'proxy');
  assert.equal(result.responseType, 'browser-raw');
  assert.equal(result.targetURL, 'https://example.com/story');
});

test('routes /fast URLs to the explicit FastHTTP renderer', () => {
  const result = routeRequest('GET', '/fast/https://example.com/story', {});

  assert.equal(result.type, 'proxy');
  assert.equal(result.responseType, 'fast');
  assert.equal(result.targetURL, 'https://example.com/story');
});

test('routes /fast/api URLs to the explicit FastHTTP API renderer', () => {
  const result = routeRequest('GET', '/fast/api/https://example.com/story', {});

  assert.equal(result.type, 'proxy');
  assert.equal(result.responseType, 'fast-api');
  assert.equal(result.targetURL, 'https://example.com/story');
});

test('routes /fast/raw URLs to the explicit FastHTTP raw renderer', () => {
  const result = routeRequest('GET', '/fast/raw/https://example.com/story', {});

  assert.equal(result.type, 'proxy');
  assert.equal(result.responseType, 'fast-raw');
  assert.equal(result.targetURL, 'https://example.com/story');
});
