import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { readBootstrap } from '../src/lib/bootstrap.ts';
import { bytes, date, amount } from '../src/lib/format.ts';

const root = value => ({ querySelector: () => ({ textContent: JSON.stringify(value) }) });

test('bootstrap is inert page data, not executable source', () => {
  const data = { Page: 'file_view', Data: { FileName: '</script><img src=x onerror=alert(1)>' }, Branding: { SiteName: 'Test' } };
  assert.deepEqual(readBootstrap(root(data)), data);
  assert.equal(readBootstrap({ querySelector: () => null }), null);
  for (const invalid of [null, 'source', {}, { Page: 'index', Data: null }, { Page: 'index', Data: {} }]) {
    assert.throws(() => readBootstrap(root(invalid)), /Invalid page data/);
  }
});

test('sizes and money retain units without rounding whole account values', () => {
  assert.equal(bytes(0), '0 B');
  assert.equal(bytes(1024), '1 KiB');
  assert.equal(bytes(1024 ** 3 * 1.5), '1.5 GiB');
  assert.equal(amount(1234, 'USD'), '$12.34');
});

test('displayed timestamps are UTC, independent of the browser time zone', () => {
  const value = date('2026-10-04T20:00:00+08:00', true);
  assert.match(value, /Oct 4, 2026/);
  assert.match(value, /12:00/);
  assert.match(value, / UTC$/);
  assert.equal(date(null), '—');
  assert.equal(date('Already formatted'), 'Already formatted');
});

test('the footer keeps the version and the "Made with heart by Cat" credit', async () => {
  const app = await readFile(new URL('../src/App.svelte', import.meta.url), 'utf8');
  const footer = app.slice(app.indexOf('<footer'), app.indexOf('</footer>'));
  assert.match(footer, /ObjectShare \{data\.Version\}/);
  assert.match(footer, /Made with <span role="img" aria-label="love"><Icon name="heart"[^>]*\/><\/span> by Cat/);
});
