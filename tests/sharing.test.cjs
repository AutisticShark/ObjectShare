const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
require('../template/client-encryption.js');
const crypto = globalThis.ObjectShareCrypto;
const source = fs.readFileSync(require('node:path').join(__dirname, '../template/sharing.js'), 'utf8');

function page({encrypted = false, api = crypto, clipboardFails = false, invalid = false} = {}) {
  function element(extra = {}) {
    return {value: '', hidden: false, disabled: false, isConnected: true, dataset: {}, events: {},
      addEventListener(name, fn) { (this.events[name] ||= []).push(fn); },
      async fire(name) { for (const fn of this.events[name] || []) await fn({preventDefault() {}}); },
      focus() { this.focused = true; }, select() { this.selected = true; }, ...extra};
  }
  const nodes = {
    'share-url': element({value: encrypted ? '' : '/file/example'}),
    'copy-share-link': element(), 'copy-status': element(),
    'sharing-permissions': element({dataset: {unsaved: String(invalid)}}),
    'share-mode': element({value: 'private'}), 'recipients': element(),
    'sharing-recipients': element(), 'unsaved-sharing': element(),
  };
  if (encrypted) Object.assign(nodes, {
    'encrypted-sharing': element({dataset: {shareUrl: '/file/example', metadata: ''}}),
    'create-encrypted-link': element(), 'encrypted-link-result': element({hidden: true}),
    'share-passphrase': element(), 'share-key-backup': element({files: []}),
  });
  const documentEvents = {}, windowEvents = {}, copied = [];
  const context = {URL, Error, ObjectShareCrypto: api,
    document: {getElementById: id => nodes[id] || null, addEventListener: (name, fn) => { documentEvents[name] = fn; }},
    window: {location: {origin: 'https://share.example'}, addEventListener: (name, fn) => { windowEvents[name] = fn; }},
    navigator: {clipboard: {async writeText(value) { if (clipboardFails) throw new Error('denied'); copied.push(value); }}},
  };
  vm.runInNewContext(source, context);
  return {nodes, copied, documentEvents, windowEvents};
}

test('copy uses an absolute link, respects unsaved permissions, and offers clipboard fallback', async () => {
  for (const clipboardFails of [false, true]) {
    const {nodes: n, copied, documentEvents} = page({clipboardFails});
    assert.equal(n['share-url'].value, 'https://share.example/file/example');
    assert.equal(n['sharing-recipients'].hidden, true);
    n['share-mode'].value = 'selected'; await n['sharing-permissions'].fire('change');
    assert.equal(n['recipients'].disabled, false);
    assert.equal(n['sharing-recipients'].hidden, false);
    assert.equal(n['unsaved-sharing'].hidden, false);
    await n['copy-share-link'].fire('click'); assert.equal(copied.length, 0);
    n['share-mode'].value = 'private'; await n['sharing-permissions'].fire('change');
    assert.equal(n['unsaved-sharing'].hidden, true);
    documentEvents['htmx:afterSwap'](); // Reinitialization must not bind twice.
    await n['copy-share-link'].fire('click');
    if (clipboardFails) {
      assert.equal(n['share-url'].selected, true);
      assert.match(n['copy-status'].textContent, /keyboard/);
    } else assert.deepEqual(copied, ['https://share.example/file/example']);
  }
  const invalid = page({invalid: true}).nodes;
  assert.equal(invalid['copy-share-link'].disabled, true);
});

test('sharing page creates a decryptable per-file link and clears working keys and passphrase', async () => {
  const passphrase = 'separate encryption passphrase';
  const account = await crypto.createVault('owner', passphrase);
  const encrypted = await crypto.encryptFile(new File(['recipient content'], 'secret.txt'), account.raw);
  for (const backup of [false, true]) {
    let raw, key;
    const api = {...crypto,
      accountKey: async supplied => { assert.equal(supplied, passphrase); return raw = account.raw.slice(); },
      unlockVault: async (...args) => raw = await crypto.unlockVault(...args),
      fileKey: async (...args) => key = await crypto.fileKey(...args),
    };
    const {nodes: n, copied, windowEvents} = page({encrypted: true, api});
    n['encrypted-sharing'].dataset.metadata = encrypted.metadata;
    n['share-passphrase'].value = passphrase;
    if (backup) n['share-key-backup'].files = [new File([JSON.stringify(account.vault)], 'backup.json')];
    await n['encrypted-sharing'].fire('submit');
    assert.equal(n['encrypted-link-result'].hidden, false);
    const link = new URL(n['share-url'].value);
    assert.equal(link.pathname, '/file/example');
    assert.equal(link.search, '');
    const recipientKey = crypto.unb64(link.hash.slice(5), 32);
    assert.notDeepEqual(recipientKey, account.raw);
    assert.equal(await (await crypto.decryptFile(encrypted.file, encrypted.metadata, recipientKey)).text(), 'recipient content');
    assert.ok(raw.every(byte => byte === 0)); assert.ok(key.every(byte => byte === 0));
    assert.equal(n['share-passphrase'].value, '');
    await n['copy-share-link'].fire('click'); assert.equal(copied[0], link.href);
    windowEvents.pagehide();
    assert.equal(n['share-url'].value, '');
    assert.equal(n['encrypted-link-result'].hidden, true);
  }
});

test('failed unlock, changed permissions, and navigation never publish a stale file key', async () => {
  const failure = page({encrypted: true, api: {...crypto, accountKey: async () => { throw new Error('Wrong passphrase'); }}}).nodes;
  failure['share-passphrase'].value = 'wrong';
  await failure['encrypted-sharing'].fire('submit');
  assert.equal(failure['share-passphrase'].value, '');
  assert.equal(failure['share-url'].value, '');
  assert.match(failure['copy-status'].textContent, /Wrong passphrase/);

  for (const action of ['edit', 'navigate', 'back']) {
    let unlock;
    const raw = new Uint8Array(32).fill(1), key = new Uint8Array(32).fill(2);
    const api = {...crypto, accountKey: () => new Promise(resolve => { unlock = resolve; }), fileKey: async () => key};
    const {nodes: n, documentEvents, windowEvents} = page({encrypted: true, api});
    const pending = n['encrypted-sharing'].fire('submit');
    assert.equal(n['create-encrypted-link'].disabled, true);
    if (action === 'edit') {
      n['share-mode'].value = 'link'; await n['sharing-permissions'].fire('change');
    } else if (action === 'back') {
      windowEvents.pagehide(); windowEvents.pageshow();
    } else documentEvents['htmx:beforeSwap']({detail: {target: {contains: () => true}}});
    unlock(raw); await pending;
    assert.equal(n['share-url'].value, ''); assert.equal(n['encrypted-link-result'].hidden, true);
    assert.ok(raw.every(byte => byte === 0)); assert.ok(key.every(byte => byte === 0));
  }
});
