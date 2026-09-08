const {test} = require('node:test');
const assert = require('node:assert/strict');
require('../template/client-encryption.js');
const c = globalThis.ObjectShareCrypto;
const passphrase = 'a separate long test passphrase';
const vm = require('node:vm');
const fs = require('node:fs');
const path = require('node:path');

test('random per-user keys, passphrase wrapping, wrong passphrase and account binding', async () => {
  const a = await c.createVault('alice', passphrase);
  const b = await c.createVault('bob', passphrase);
  assert.notEqual(a.vault.key_id, b.vault.key_id);
  assert.deepEqual(await c.unlockVault(a.vault, 'alice', passphrase), a.raw);
  await assert.rejects(c.unlockVault(a.vault, 'alice', 'incorrect passphrase'), /Unable to unlock/);
  await assert.rejects(c.unlockVault(a.vault, 'bob', passphrase), /different account/);
  const tampered = {...a.vault, wrapped_key: b.vault.wrapped_key};
  await assert.rejects(c.unlockVault(tampered, 'alice', passphrase));
  await assert.rejects(c.unlockVault({...a.vault, version: 2}, 'alice', passphrase));
});

test('empty, boundary and multi-chunk files round trip; each file has an independent key', async () => {
  const account = await c.createVault('alice', passphrase);
  for (const size of [0, 1, 1048576, 1048577, 2097153]) {
    const original = Uint8Array.from({length: size}, (_, i) => i % 251);
    const file = new File([original], 'original.bin');
    const encrypted = await c.encryptFile(file, account.raw);
    const key = await c.fileKey(account.raw, encrypted.metadata);
    assert.equal(encrypted.file.size, size + 16 * Math.max(1, Math.ceil(size / 1048576)));
    const decrypted = await c.decryptFile(encrypted.file, encrypted.metadata, key);
    assert.deepEqual(new Uint8Array(await decrypted.arrayBuffer()), original);
    const second = await c.encryptFile(file, account.raw);
    assert.notEqual(encrypted.metadata, second.metadata);
    await assert.rejects(c.decryptFile(second.file, second.metadata, key), /authentication failed/);
  }
});

test('tamper, truncation, append, wrong key, metadata substitution and reordered chunks fail closed', async () => {
  const a = await c.createVault('alice', passphrase), b = await c.createVault('bob', passphrase);
  const encrypted = await c.encryptFile(new File([new Uint8Array(2097152)], 'secret.bin'), a.raw);
  const key = await c.fileKey(a.raw, encrypted.metadata);
  await assert.rejects(c.fileKey(b.raw, encrypted.metadata), /different encryption key/);
  await assert.rejects(c.decryptFile(encrypted.file, encrypted.metadata, b.raw), /authentication failed/);
  const bytes = new Uint8Array(await encrypted.file.arrayBuffer()); bytes[0] ^= 1;
  await assert.rejects(c.decryptFile(new Blob([bytes]), encrypted.metadata, key), /authentication failed/);
  await assert.rejects(c.decryptFile(encrypted.file.slice(0, -1), encrypted.metadata, key), /truncated/);
  await assert.rejects(c.decryptFile(new Blob([encrypted.file, new Uint8Array(1)]), encrypted.metadata, key), /invalid size/);
  const swapped = new Blob([encrypted.file.slice(1048592), encrypted.file.slice(0, 1048592)]);
  await assert.rejects(c.decryptFile(swapped, encrypted.metadata, key), /authentication failed/);
  const meta = JSON.parse(encrypted.metadata); meta.salt = b.vault.key_id;
  await assert.rejects(c.decryptFile(encrypted.file, JSON.stringify(meta), key), /authentication failed/);
  meta.version = 999;
  await assert.rejects(c.decryptFile(encrypted.file, JSON.stringify(meta), key), /Unsupported/);
});

test('uploader sends ciphertext through proxied/direct single/batch flows and never falls back on unlock failure', async () => {
  const account = await c.createVault('upload-user', passphrase);
  for (const direct of [false, true]) for (const count of [1, 2]) for (const fail of [false, true]) {
    const original = 'never send this plaintext';
    const files = Array.from({length:count}, (_, i) => new File([original], `file-${i}.txt`));
    let submit;
    let destination;
    const transfers = [], requests = [], metadata = [];
    const element = () => ({value:'', textContent:'', disabled:true, style:{}, classList:{remove(){},add(){}},setAttribute(){}});
    const status = element(), button = element(), input = {...element(),files};
    const fields = {'#file':input,'#upload-button':button,'#upload-status':status,'#upload-progress-wrap':element(),'#upload-progress':element(),'#encryption-passphrase':element(),"input[name='upload_mode']:checked":{value:count === 1 ? 'single':'multiple'}};
    const form = {dataset:{directUpload:String(direct),clientEncryption:'true',maxFiles:'10',maxFileMib:'10'},action:'/api/v1/upload', elements:{share_mode:{value:'private'}},querySelector:selector=>fields[selector] || null,querySelectorAll:()=>[],addEventListener:(_event,callback)=>{submit=callback;}};
    class TestFormData extends FormData { constructor() { super(); this.append('share_mode','private'); } }
    class XHR {
      constructor() {this.events={};this.upload={addEventListener(){}};this.status=200;}
      open(_method,url){this.url=url;}
      setRequestHeader(){}
      addEventListener(event,callback){this.events[event]=callback;}
      send(file){transfers.push(file);this.events.load();}
    }
    const fetchMock = async (url, options) => {
      requests.push(url);
      if (url === '/api/v1/upload') {
        transfers.push(...options.body.getAll('file')); metadata.push(...options.body.getAll('client_encryption'));
        return new Response(null,{status:204,headers:{'HX-Redirect':'/file/result'}});
      }
      if (url.endsWith('/batch')) {
        const payload=JSON.parse(options.body); metadata.push(...payload.files.map(file=>file.client_encryption));
        assert.ok(payload.files.every(file=>file.content_type === 'application/octet-stream' && file.file_size === original.length+16));
        return Response.json({uploads:files.map((_file,i)=>({file_id:String(i),token:'token',upload_url:`https://storage.test/${i}`,complete_url:`/complete/${i}`,abort_url:`/abort/${i}`}))});
      }
      return Response.json({location:'/file/result'});
    };
    const sandbox = {document:{querySelector:()=>form},crypto:globalThis.crypto,ObjectShareCrypto:{...c,accountKey:async()=>{if(fail)throw new Error('unlock failed');return account.raw.slice();}},XMLHttpRequest:XHR,FormData:TestFormData,fetch:fetchMock,window:{location:{assign:url=>{destination=url;}}}};
    vm.runInNewContext(fs.readFileSync(path.join(__dirname,'../template/upload.js'),'utf8'),sandbox);
    assert.equal(button.disabled,false);
    await submit({preventDefault(){}});
    if (fail) {
      assert.equal(requests.length,0); assert.equal(transfers.length,0); assert.equal(destination,undefined); assert.equal(status.textContent,'Upload failed.');
    } else {
      assert.equal(transfers.length,count); assert.ok(destination);
      for (let i=0;i<count;i++) {
        assert.equal((await transfers[i].text()).includes(original),false);
        const key=await c.fileKey(account.raw,metadata[i]);
        assert.equal(await (await c.decryptFile(transfers[i],metadata[i],key)).text(),original);
      }
    }
  }
});
