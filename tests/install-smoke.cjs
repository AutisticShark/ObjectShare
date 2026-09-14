// Destructive fixture creation for a NEW, disposable, loopback-only installation.
// This is invoked explicitly by CI, not by the ordinary JavaScript unit suite.
const assert = require('node:assert/strict');
const {randomBytes} = require('node:crypto');
const {execFileSync} = require('node:child_process');
require('../template/client-encryption.js');

function localOrigin(value) {
  const url = new URL(value);
  assert.equal(url.protocol, 'http:', 'Use the isolated local HTTP fixture');
  assert.ok(['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname), 'Refusing a non-loopback target');
  assert.ok(!url.username && !url.password && !url.search && !url.hash && url.pathname === '/', 'Use an origin without credentials or a path');
  return url.origin;
}

async function runSmoke({origin, restart}) {
  origin = localOrigin(origin);
  assert.equal(typeof restart, 'function', 'A fixture restart callback is required');
  const cookies = new Map();
  const request = async (route, options = {}, authenticated = true) => {
    assert.ok(route.startsWith('/') && !route.startsWith('//'), 'Expected a local route');
    const response = await fetch(origin + route, {
      ...options, redirect: 'manual', signal: AbortSignal.timeout(15000),
      headers: {...options.headers, Origin: origin,
        ...(authenticated ? {Cookie: [...cookies].map(([key, value]) => `${key}=${value}`).join('; ')} : {})},
    });
    if (authenticated) for (const cookie of response.headers.getSetCookie()) {
      const [key, ...value] = cookie.split(';')[0].split('=');
      cookies.set(key, value.join('='));
    }
    return response;
  };
  const page = async route => {
    const response = await request(route);
    assert.equal(response.status, 200, `${route} should render successfully`);
    return response.text();
  };
  const csrfFrom = html => {
    const match = html.match(/name="csrf_token" value="([^"]+)"/);
    assert.ok(match, 'Expected a CSRF-protected form');
    return match[1];
  };

  assert.equal((await request('/health/ready')).status, 200, 'Database readiness');
  // Refuse to reuse credentials, users, or files from an existing installation.
  const setup = await page('/setup');
  assert.match(setup, /action="\/setup"/);
  const password = randomBytes(24).toString('hex');
  const created = await request('/setup', {method: 'POST', body: new URLSearchParams({
    csrf_token: csrfFrom(setup), email: `install-${randomBytes(8).toString('hex')}@example.test`,
    display_name: 'Installation smoke fixture', password, password_confirm: password,
  })});
  assert.equal(created.status, 303, 'First administrator setup');
  assert.equal((await request('/setup')).status, 303, 'Setup must close after bootstrap');
  for (const route of ['/admin', '/admin/users', '/admin/settings', '/admin/plans', '/admin/invoices', '/files', '/billing', '/invoices']) {
    await page(route);
  }
  const csrf = csrfFrom(await page('/'));
  const stateResponse = await request('/account/encryption');
  assert.equal(stateResponse.status, 200);
  const state = await stateResponse.json();
  assert.equal(state.vault, null);
  const passphrase = randomBytes(24).toString('hex');
  const crypto = globalThis.ObjectShareCrypto;
  const {raw, vault} = await crypto.createVault(state.user_id, passphrase);
  let fileKey;
  try {
    const saved = await request('/account/encryption', {method: 'POST',
      headers: {'Content-Type': 'application/json', 'X-CSRF-Token': csrf}, body: JSON.stringify(vault)});
    assert.equal(saved.status, 201, 'Persist encryption vault');
    const content = 'ObjectShare fresh-install encrypted storage fixture.\n';
    const encrypted = await crypto.encryptFile(new File([content], 'install-smoke.txt'), raw);
    fileKey = await crypto.fileKey(raw, encrypted.metadata);
    raw.fill(0);
    const form = new FormData();
    form.set('csrf_token', csrf); form.set('share_mode', 'private'); form.set('upload_mode', 'single');
    form.set('client_encryption', encrypted.metadata); form.set('file', encrypted.file, 'install-smoke.txt');
    const uploaded = await request('/api/v1/upload', {method: 'POST', body: form});
    assert.equal(uploaded.status, 303, 'Encrypted filesystem upload');
    const filePage = uploaded.headers.get('location');
    assert.match(filePage, /^\/file\/[0-9a-f-]{36}$/);
    const downloadRoute = '/api/v1/download/' + filePage.split('/').pop();
    const verifyFile = async () => {
      const html = await page(filePage);
      assert.match(html, /install-smoke\.txt/);
      const token = html.match(/name="download_token" value="([^"]+)"/);
      assert.ok(token, 'Expected scoped download authorization');
      const downloaded = await request(downloadRoute, {method: 'POST', body: new URLSearchParams({download_token: token[1]})});
      assert.equal(downloaded.status, 200, 'Owner download');
      assert.equal(downloaded.headers.get('location'), null, 'Private download must stream through ObjectShare');
      const plaintext = await crypto.decryptFile(await downloaded.blob(), encrypted.metadata, fileKey);
      assert.equal(await plaintext.text(), content, 'Authenticated plaintext round trip');
      assert.equal((await request(filePage, {}, false)).status, 404, 'Guest private-file denial');
      assert.equal((await request(downloadRoute, {method: 'POST'}, false)).status, 404, 'Guest private-download denial');
    };
    await verifyFile();
    await restart();
    let ready = false;
    for (let attempt = 0; attempt < 30; attempt++) {
      try { if ((await request('/health/ready')).status === 200) { ready = true; break; } } catch {}
      await new Promise(resolve => setTimeout(resolve, 1000));
    }
    assert.ok(ready, 'Application did not become ready after restart');
    assert.equal((await request('/setup')).status, 303, 'Administrator persists after restart');
    const restoredState = await request('/account/encryption');
    assert.equal(restoredState.status, 200, 'JWT remains valid across restart');
    assert.deepEqual((await restoredState.json()).vault, vault, 'Vault persists after restart');
    await page('/admin');
    await verifyFile();
    console.log('PASS: fresh setup, admin/workspace pages, encrypted private storage, restart persistence, and guest denial');
  } finally { raw.fill(0); fileKey?.fill(0); }
}

if (require.main === module) {
  const project = process.env.COMPOSE_PROJECT_NAME || '';
  assert.match(project, /^objectshare-ci-[0-9]+-[0-9]+$/, 'Use a dedicated CI Compose project');
  assert.equal(process.env.OBJECTSHARE_SMOKE_ALLOW_SETUP, '1', 'Explicit disposable-install opt-in required');
  runSmoke({origin: process.env.OBJECTSHARE_SMOKE_BASE_URL || 'http://127.0.0.1:8080',
    restart: async () => execFileSync('docker', ['compose', '--project-name', project, 'restart', 'app'], {stdio: 'pipe', timeout: 60000}),
  }).catch(error => { console.error(error.message); process.exitCode = 1; });
}
module.exports = {runSmoke, localOrigin};
