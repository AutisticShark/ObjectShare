const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const source = fs.readFileSync(require('node:path').join(__dirname, '../template/htmx-errors.js'), 'utf8');

function setup() {
  const listeners = {};
  const body = {children: [], prepend(child) { this.children.unshift(child); child.parent = this; }};
  const form = {
    querySelector(selector) {
      if (selector === '.card-body') return body;
      if (selector === '[data-htmx-error]') return body.children.find(child => child.attributes['data-htmx-error'] !== undefined) || null;
      return null;
    },
  };
  const element = (select) => ({
    closest(selector) {
      if (selector === 'form') return form;
      if (selector === '[hx-select]') return select ? {getAttribute: () => select} : null;
      return null;
    },
  });
  const document = {
    documentElement: {dataset: {}},
    addEventListener(name, listener) { assert.equal(listeners[name], undefined, `duplicate ${name} listener`); listeners[name] = listener; },
    createElement() {
      return {attributes: {}, setAttribute(name, value) { this.attributes[name] = value; }, remove() { body.children = body.children.filter(child => child !== this); }};
    },
  };
  class DOMParser {
    parseFromString(html) { return {querySelector: selector => selector === '.page' && html.includes('class="page') ? {} : null}; }
  }
  const context = {document, DOMParser};
  vm.runInNewContext(source, context);
  vm.runInNewContext(source, context); // A second copy must not add listeners.
  const swap = (elt, status, type, response) => {
    const detail = {shouldSwap: status < 400, isError: status >= 400, serverResponse: response, requestConfig: {elt},
      xhr: {status, getResponseHeader: name => name === 'Content-Type' ? type : null}};
    listeners['htmx:beforeSwap']({detail});
    return detail;
  };
  return {listeners, body, element, swap};
}

test('an error page that contains the page target is swapped in', () => {
  const {body, element, swap} = setup();
  const detail = swap(element('.page'), 403, 'text/html; charset=utf-8', '<div class="page page-center">The setup token is incorrect.</div>');
  assert.equal(detail.shouldSwap, true);
  assert.equal(detail.isError, true, 'responseError listeners must still run');
  assert.equal(body.children.length, 0);
});

test('a plain-text rejection is shown inside the form instead of being dropped', () => {
  const {listeners, body, element, swap} = setup();
  const form = element('.page');
  const detail = swap(form, 429, 'text/plain; charset=utf-8', 'Too many requests. Try again later.\n');
  assert.equal(detail.shouldSwap, false);
  assert.equal(body.children.length, 1);
  assert.equal(body.children[0].textContent, 'Too many requests. Try again later.');
  assert.equal(body.children[0].attributes.role, 'alert');
  swap(form, 403, 'text/plain; charset=utf-8', 'Invalid CSRF token.\n');
  assert.equal(body.children.length, 1, 'a second failure must reuse the alert');
  assert.equal(body.children[0].textContent, 'Invalid CSRF token.');
  listeners['htmx:beforeRequest']({detail: {elt: form}});
  assert.equal(body.children.length, 0, 'a new submission clears the previous error');
});

test('an HTML response without the page target is not swapped over the page', () => {
  const {body, element, swap} = setup();
  const detail = swap(element('.page'), 502, 'text/html', '<html><body>Bad gateway</body></html>');
  assert.equal(detail.shouldSwap, false);
  assert.match(body.children[0].textContent, /HTTP 502/);
});

test('successful responses and elements that do not replace the page are untouched', () => {
  const {body, element, swap} = setup();
  assert.equal(swap(element('.page'), 200, 'text/html', '<div class="page"></div>').shouldSwap, true);
  const toggle = swap(element(''), 403, 'text/plain', 'Invalid CSRF token.');
  assert.equal(toggle.shouldSwap, false);
  assert.equal(body.children.length, 0);
});

test('a network failure is reported in the form', () => {
  const {listeners, body, element} = setup();
  listeners['htmx:sendError']({detail: {elt: element('.page'), requestConfig: {elt: element('.page')}}});
  assert.match(body.children[0].textContent, /could not be reached/);
});
