import { test } from 'node:test';
import assert from 'node:assert/strict';
import { outcome } from '../src/lib/submit.ts';

const page = { Page: 'account', Data: { Error: 'Enter a valid email address.' }, Branding: { SiteName: 'Test' } };
const parse = html => ({ querySelector: () => (html === 'page' ? { textContent: JSON.stringify(page) } : null) });
const response = (status, headers = {}, extra = {}) => ({
  ok: status >= 200 && status < 300, status, redirected: false, url: '', headers: new Headers(headers), ...extra,
});

test('enhanced forms follow server redirects as real navigations', () => {
  assert.deepEqual(outcome(response(204, { 'X-ObjectShare-Redirect': '/account' }), '', parse), { kind: 'navigate', location: '/account' });
  // fetch followed a plain 303 itself: load the destination so the address bar is right.
  assert.deepEqual(outcome(response(200, { 'Content-Type': 'text/html' }, { redirected: true, url: 'http://host/files' }), 'page', parse), { kind: 'navigate', location: 'http://host/files' });
});

test('a page answer renders whatever its status, so validation errors show in place', () => {
  for (const status of [200, 400, 403, 429]) {
    assert.deepEqual(outcome(response(status, { 'Content-Type': 'text/html; charset=utf-8' }), 'page', parse), { kind: 'page', boot: page });
  }
});

test('other answers finish quietly, report the persisted theme, or carry a short message', () => {
  assert.deepEqual(outcome(response(204), '', parse), { kind: 'done', theme: undefined });
  assert.deepEqual(outcome(response(204, { 'X-ObjectShare-Theme': 'dark' }), '', parse), { kind: 'done', theme: 'dark' });
  assert.deepEqual(outcome(response(403, { 'Content-Type': 'text/plain' }), 'Invalid CSRF token.\n', parse), { kind: 'failed', message: 'Invalid CSRF token.' });
  assert.equal(outcome(response(500, { 'Content-Type': 'text/plain' }), 'x'.repeat(500), parse).message.length, 300);
  // HTML that is not an ObjectShare page (a proxy error page) is never shown raw.
  assert.deepEqual(outcome(response(502, { 'Content-Type': 'text/html' }), '<h1>Bad gateway</h1>', parse), { kind: 'failed', message: 'The request failed (HTTP 502). Try again.' });
});
