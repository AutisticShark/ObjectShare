const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const source = fs.readFileSync(require('node:path').join(__dirname, '../template/theme.js'), 'utf8');

test('account theme changes only on a confirmed preference event and survives navigation replacement', () => {
  const events = {}, root = {dataset: {bsTheme: 'light'}};
  function toggle() {
    const input = {value: 'dark'}, button = {setAttribute(name,value) { this[name] = value; }}, status = {textContent:''};
    const icons = ['light','dark'].map(themeIcon => ({dataset:{themeIcon}}));
    return {input,button,status,icons,
      querySelector: selector => selector === 'button' ? button : selector === '[data-theme-status]' ? status : input,
      querySelectorAll: () => icons,
    };
  }
  let form = toggle();
  const selection = {value: 'light'};
  const document = {documentElement:root, currentScript:{hasAttribute:()=>true},
    querySelectorAll:()=>[form], querySelector:()=>selection,
    addEventListener(name,listener) { assert.equal(events[name],undefined,'duplicate document listener'); events[name]=listener; },
  };
  const context = {document,window:{matchMedia() { throw new Error('account preference must not follow OS'); }}};
  vm.runInNewContext(source,context);
  assert.equal(root.dataset.bsTheme,'light');
  events['htmx:sendError']({detail:{elt:{closest:()=>form}}});
  assert.equal(root.dataset.bsTheme,'light'); assert.match(form.status.textContent,/could not be saved/);
  events['objectshare:theme']({detail:{theme:'dark'}});
  assert.equal(root.dataset.bsTheme,'dark'); assert.equal(selection.value,'dark');
  assert.equal(form.input.value,'light'); assert.equal(form.button['aria-label'],'Switch to light theme');
  assert.equal(form.icons[0].hidden,false); assert.equal(form.icons[1].hidden,true); assert.equal(form.status.textContent,'');
  form = toggle(); // A new navigation fragment must use the existing listener.
  vm.runInNewContext(source,context);
  events['objectshare:theme']({detail:{theme:'light'}});
  assert.equal(form.input.value,'dark'); assert.equal(form.button.title,'Switch to dark theme');
  events['objectshare:theme']({detail:{theme:'invalid'}});
  assert.equal(root.dataset.bsTheme,'light');
});

test('guest themes continue to follow OS changes with both media-query APIs', () => {
  for (const legacy of [false,true]) {
    let changed;
    const root = {dataset:{}}, preference = {matches:true};
    if (legacy) preference.addListener = callback => { changed=callback; };
    else preference.addEventListener = (name,callback) => { assert.equal(name,'change'); changed=callback; };
    vm.runInNewContext(source, {document:{documentElement:root,currentScript:{hasAttribute:()=>false}},window:{matchMedia:()=>preference}});
    assert.equal(root.dataset.themePreference,'system'); assert.equal(root.dataset.bsTheme,'dark');
    preference.matches=false; changed(); assert.equal(root.dataset.bsTheme,'light');
  }
});
