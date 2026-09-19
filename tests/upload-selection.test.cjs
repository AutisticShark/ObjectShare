const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const source = fs.readFileSync(path.join(__dirname, '../template/upload.js'), 'utf8');
function uploader(encrypted, cryptoAvailable = true) {
  const element = () => ({value:'', textContent:'', disabled:false, children:[], events:{}, classList:{add(){},remove(){}},
    addEventListener(name, fn){this.events[name]=fn;}, setCustomValidity(value){this.validationMessage=value;}, reportValidity(){return !this.validationMessage;},
    replaceChildren(){this.children=[];}, append(child){this.children.push(child);}});
  const input=element(), selected=element(), single=element(), multiple=element(), button=element(), zone=element(), access=element(), explanation=element();
  input.files=[];
  Object.defineProperty(input,'value',{set(value){if(value==='')this.files=[];},get(){return '';}});
  selected.value='single';
  const list=element();
  const fields={'#file':input,'#file-selection':list,'#upload-button':button,'#upload-dropzone':zone,'#share-mode':access,'#sharing-explanation':explanation,'#upload-status':element(),"input[name='upload_mode']:checked":selected};
  const choice = {...element(),checked:encrypted}, pass = element(), encryptionFields = element();
  Object.assign(fields,{'#encrypt-files':choice,'#encryption-passphrase':pass,'#encryption-fields':encryptionFields});
  const form={dataset:{maxFiles:'2',maxFileMib:'1'},querySelector:s=>fields[s]||null,querySelectorAll:()=>[single,multiple],addEventListener(){}};
  vm.runInNewContext(source,{document:{querySelector:()=>form,createElement:element},crypto:cryptoAvailable ? globalThis.crypto : undefined,ObjectShareCrypto:cryptoAvailable ? {} : undefined});
  return {input,selected,multiple,button,zone,access,explanation,list,choice,pass,encryptionFields};
}

test('selection enforces single/batch limits and treats names as text', () => {
  const ui=uploader(false);
  ui.input.files=[{name:'<img src=x onerror=alert(1)>',size:10}];ui.input.events.change();
  assert.equal(ui.input.validationMessage,'');assert.equal(ui.list.children.length,1);
  assert.match(ui.list.children[0].textContent,/^<img src=x onerror=alert\(1\)>/);
  ui.input.files.push({name:'second',size:10});ui.input.events.change();
  assert.match(ui.input.validationMessage,/Multiple files/);
  ui.selected.value='multiple';ui.multiple.events.change();
  assert.equal(ui.input.files.length,0);assert.equal(ui.input.validationMessage,'');
  ui.input.files=[1,2,3].map(n=>({name:String(n),size:10}));ui.input.events.change();
  assert.match(ui.input.validationMessage,/up to 2/);
  ui.input.files=[{name:'large',size:1024*1024+1}];ui.input.events.change();
  assert.match(ui.input.validationMessage,/within 1 MiB/);
});

test('drop selection and sharing guidance preserve the selected permission', () => {
  const ui=uploader(false);let prevented=false;
  ui.zone.events.drop({preventDefault(){prevented=true;},dataTransfer:{files:[{name:'dropped',size:10}]}});
  assert.equal(prevented,true);assert.match(ui.list.children[0].textContent,/dropped/);
  ui.access.value='private';ui.access.events.change();assert.match(ui.explanation.textContent,/Only you/);
  ui.access.value='signed_in';ui.access.events.change();assert.match(ui.explanation.textContent,/must log in/);
  ui.button.disabled=true;
  ui.zone.events.drop({preventDefault(){},dataTransfer:{files:[{name:'replacement',size:10}]}});
  assert.equal(ui.input.files[0].name,'dropped');
});

test('selection includes encryption overhead at the size boundary', () => {
  const ui=uploader(true);
  ui.input.files=[{name:'boundary',size:1024*1024}];ui.input.events.change();
  assert.match(ui.input.validationMessage,/encryption overhead/);
  assert.equal(ui.pass.required,true);assert.equal(ui.pass.disabled,false);assert.equal(ui.encryptionFields.hidden,false);
  ui.pass.value='do not retain this';ui.choice.checked=false;ui.choice.events.change();
  assert.equal(ui.input.validationMessage,'');assert.equal(ui.pass.value,'');
  assert.equal(ui.pass.required,false);assert.equal(ui.pass.disabled,true);assert.equal(ui.encryptionFields.hidden,true);
  ui.choice.checked=true;ui.choice.events.change();assert.match(ui.input.validationMessage,/encryption overhead/);
  ui.input.files=[{name:'fits',size:1024*1024-16}];ui.input.events.change();
  assert.equal(ui.input.validationMessage,'');
});
test('without Web Crypto only the encryption option is disabled', () => {
  const ui=uploader(false,false);
  assert.equal(ui.choice.disabled,true);assert.equal(ui.button.disabled,false);
  assert.equal(ui.pass.required,false);assert.equal(ui.pass.disabled,true);
});
function retryHarness(failure) {
  const element = () => ({value:'',textContent:'',disabled:false,files:[],style:{},children:[],events:{},classList:{remove(){},add(){}},
    addEventListener(name,fn){this.events[name]=fn;},setCustomValidity(){},setAttribute(){},replaceChildren(){this.children=[];},append(child){this.children.push(child);}});
  const input=element(), button=element(), retry=element(), completed=element(), status=element(), pass=element(), access=element();
  access.value='private'; pass.value='page-only passphrase';
  const fields={'#file':input,'#upload-button':button,'#retry-upload':retry,'#completed-uploads':completed,'#upload-status':status,'#upload-progress-wrap':element(),'#upload-progress':element(),'#upload-recovery':element(),'#encryption-passphrase':pass,'#share-mode':access,"input[name='upload_mode']:checked":{value:'multiple'}};
  const choice = {...element(),checked:true};fields['#encrypt-files']=choice;
  let submit, destination, reservations=0, encryptions=0, lost=false;
  const puts=[0,0,0], completions=[0,0,0];
  const form={dataset:{directUpload:'true',maxFiles:'3',maxFileMib:'1'},elements:{share_mode:access},querySelector:s=>fields[s]||null,querySelectorAll:()=>[],addEventListener(_name,fn){submit=fn;}};
  const key=new Uint8Array(32).fill(7);
  class XHR {
    constructor(){this.events={};this.upload={addEventListener(){}};this.status=200;}
    open(_method,url){this.index=Number(url.split('/').pop());}
    setRequestHeader(){}
    addEventListener(name,fn){this.events[name]=fn;}
    send(file){
      assert.equal(file.name,`file-${this.index}.txt`);assert.equal(file.type,'application/octet-stream');puts[this.index]++;
      if(failure==='put' && this.index===1 && !lost){lost=true;this.events.error();} else this.events.load();
    }
  }
  const fetch=async(url,options)=>{
    if(url.endsWith('/batch')){
      reservations++;
      assert.ok(JSON.parse(options.body).files.every(file=>file.share_mode==='private'));
      return Response.json({uploads:[0,1,2].map(i=>({file_id:`id-${i}`,upload_url:`https://store.test/${i}`,complete_url:`/complete/${i}`,abort_url:`/abort/${i}`,token:'same-reservation'}))});
    }
    assert.ok(url.startsWith('/complete/'),'retry must not abort or create another reservation');
    const index=Number(url.split('/').pop());completions[index]++;
    assert.equal(JSON.parse(options.body).token,'same-reservation');
    if(index===1 && failure==='completion' && !lost){lost=true;throw new Error('completion response lost');}
    return Response.json({location:`/file/id-${index}`});
  };
  vm.runInNewContext(source,{document:{querySelector:()=>form,createElement:element},crypto:globalThis.crypto,ObjectShareCrypto:{
    accountKey:async()=>key,
    encryptFile:async(file)=>{encryptions++;return {file:new File(['ciphertext'],file.name,{type:'application/octet-stream'}),metadata:'encrypted-metadata'};}
  },XMLHttpRequest:XHR,fetch,window:{location:{assign(url){destination=url;}}}});
  input.files=[0,1,2].map(i=>new File(['plaintext'],`file-${i}.txt`));
  return {submit:()=>submit({preventDefault(){}}),retry:()=>retry.events.click(),input,button,completed,pass,access,choice,key,puts,completions,
    stats:()=>({reservations,encryptions,destination})};
}

for (const failure of ['put','completion']) test(`direct retry after ${failure} failure preserves completed files and ciphertext`, async () => {
  const ui=retryHarness(failure);
  await ui.submit();
  assert.equal(ui.stats().destination,undefined);
  assert.equal(ui.button.disabled,true);assert.equal(ui.input.disabled,true);assert.equal(ui.access.disabled,true);
  assert.equal(ui.choice.disabled,true,'encryption selection must stay fixed for retries');
  assert.equal(ui.pass.value,'');assert.ok(ui.key.every(byte=>byte===0),'account key must be cleared before network uploads');
  assert.equal(ui.completed.children.length,1);assert.equal(ui.completed.children[0].children[0].href,'/file/id-0');
  await ui.submit();assert.equal(ui.stats().reservations,1,'submitting again cannot duplicate a partial batch');
  await ui.retry();
  assert.equal(ui.stats().reservations,1);assert.equal(ui.stats().encryptions,3);
  assert.deepEqual(ui.puts,failure==='put'?[1,2,1]:[1,1,1]);
  assert.deepEqual(ui.completions,failure==='completion'?[1,2,1]:[1,1,1]);
  assert.equal(ui.stats().destination,'/uploads/complete?ids=id-0,id-1,id-2');
});
