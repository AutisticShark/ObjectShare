const {test} = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const fs = require('node:fs');

test('management dialogs reopen for correction but stay closed after successful updates', () => {
  for (const failed of [false,true]) {
    const events = {};
    class Element {
      closest() { return this; }
      getAttribute() { return 'user-actions-fixture'; }
    }
    let opened = 0;
    const dialog = {tagName:'DIALOG',open:false,showModal(){opened++;},
      querySelector: selector => selector === '[role="alert"]' && failed ? {} : null};
    const document = {getElementById: id => id === 'user-actions-fixture' ? dialog : null,
      addEventListener: (name, callback) => {events[name]=callback;}};
    vm.runInNewContext(fs.readFileSync(require('node:path').join(__dirname,'../template/admin_users.js'),'utf8'),{document,Element});
    events['htmx:beforeRequest']({target:new Element()});
    events['htmx:afterSwap']();
    assert.equal(opened,failed ? 1 : 0);
    events['htmx:afterSwap'](); // A later unrelated swap must not reopen it again.
    assert.equal(opened,failed ? 1 : 0);
  }
});
