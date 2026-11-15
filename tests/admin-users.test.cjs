const {test} = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const fs = require('node:fs');

test('management dialogs open from their button, focus the first field, and close', () => {
  let click;
  class Element {
    constructor(attributes = {}, parent = null) { this.attributes = attributes; this.parent = parent; }
    closest(selector) {
      for (let node = this; node; node = node.parent) {
        const name = selector.match(/^\[([a-z-]+)\]$/)?.[1];
        if (name ? name in node.attributes : node.tagName === 'DIALOG') return node;
      }
      return null;
    }
    getAttribute(name) { return this.attributes[name]; }
  }
  const field = {focused: false, focus() { this.focused = true; }};
  const dialog = Object.assign(new Element(), {tagName: 'DIALOG', open: false,
    showModal() { this.open = true; }, close() { this.open = false; }, querySelector: () => field});
  const opener = new Element({'data-user-dialog-open': 'user-actions-fixture'});
  const closer = new Element({'data-user-dialog-close': ''}, dialog);
  const document = {getElementById: id => id === 'user-actions-fixture' ? dialog : null,
    addEventListener: (name, callback) => { if (name === 'click') click = callback; }};
  vm.runInNewContext(fs.readFileSync(require('node:path').join(__dirname, '../frontend/src/controllers/admin-users.js'), 'utf8'), {document, Element});
  click({target: opener});
  assert.equal(dialog.open, true);
  assert.equal(field.focused, true);
  click({target: closer});
  assert.equal(dialog.open, false);
  click({target: opener});
  click({target: dialog}); // the backdrop
  assert.equal(dialog.open, false);
});
