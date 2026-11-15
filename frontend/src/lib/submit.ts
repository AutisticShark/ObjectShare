import { readBootstrap, type Bootstrap } from './bootstrap.ts';

// Forms marked data-enhance submit with fetch so a rejected submission keeps
// the page (and an open dialog) instead of reloading it. Every other form,
// and any submitter with its own formaction, posts natively.

export const fetchHeader = 'X-ObjectShare-Fetch';
export const redirectHeader = 'X-ObjectShare-Redirect';
export const themeHeader = 'X-ObjectShare-Theme';

export type Outcome =
  | { kind: 'navigate'; location: string }
  | { kind: 'page'; boot: Bootstrap }
  | { kind: 'done'; theme?: string }
  | { kind: 'failed'; message: string };

/** Decides what a response to an enhanced form means for the page. */
export function outcome(
  response: Pick<Response, 'ok' | 'status' | 'redirected' | 'url' | 'headers'>, body: string,
  parse: (html: string) => ParentNode = html => new DOMParser().parseFromString(html, 'text/html'),
): Outcome {
  const location = response.headers.get(redirectHeader);
  if (location) return { kind: 'navigate', location };
  // fetch followed a plain redirect itself; load the destination for real.
  if (response.redirected) return { kind: 'navigate', location: response.url };
  const html = (response.headers.get('Content-Type') || '').toLowerCase().startsWith('text/html');
  if (html) {
    const boot = readBootstrap(parse(body));
    if (boot) return { kind: 'page', boot };
  }
  if (response.ok) return { kind: 'done', theme: response.headers.get(themeHeader) || undefined };
  const message = html ? '' : body.trim().slice(0, 300);
  return { kind: 'failed', message: message || `The request failed (HTTP ${response.status}). Try again.` };
}

/** Shows a failure inside the form unless a listener of objectshare:submit-failed handles it. */
function fail(form: HTMLFormElement, message: string) {
  const event = new CustomEvent('objectshare:submit-failed', { bubbles: true, cancelable: true, detail: { message } });
  if (!form.dispatchEvent(event) || !form.isConnected) return;
  let alert = form.querySelector<HTMLElement>('[data-submit-error]');
  if (!alert) {
    alert = document.createElement('div');
    alert.className = 'alert alert-danger';
    alert.setAttribute('role', 'alert');
    alert.dataset.submitError = '';
    (form.querySelector('.card-body') || form).prepend(alert);
  }
  alert.textContent = message;
}

export function enhanceForms(show: (boot: Bootstrap, form: HTMLFormElement) => void) {
  const pending = new WeakSet<HTMLFormElement>();
  // Confirmation applies to every form, enhanced or not, and runs first.
  document.addEventListener('submit', event => {
    const form = event.target;
    if (form instanceof HTMLFormElement && form.dataset.confirm && !confirm(form.dataset.confirm)) event.preventDefault();
  }, true);
  // Window listeners run after the page's own submit handlers, which may take over.
  window.addEventListener('submit', async event => {
    const form = event.target;
    const submitter = event.submitter;
    if (event.defaultPrevented || !(form instanceof HTMLFormElement) || !('enhance' in form.dataset)) return;
    if (submitter?.hasAttribute('formaction') || submitter?.hasAttribute('formmethod')) return;
    event.preventDefault();
    if (pending.has(form)) return;
    pending.add(form);
    // Read attributes, not form.action/form.enctype: a control named "action"
    // (the MFA forms have one) shadows those properties.
    const target = new URL(form.getAttribute('action') || '', location.href);
    const values = new FormData(form, submitter);
    const body = form.getAttribute('enctype') === 'multipart/form-data' ? values : new URLSearchParams(values as unknown as Record<string, string>);
    const buttons = [...form.querySelectorAll<HTMLButtonElement>('button[type="submit"], button:not([type])')].filter(button => !button.disabled);
    buttons.forEach(button => { button.disabled = true; });
    form.querySelector('[data-submit-error]')?.remove();
    try {
      let response: Response, text: string;
      try {
        response = await fetch(target, { method: 'POST', body, headers: { [fetchHeader]: 'true' } });
        text = await response.text();
      } catch {
        fail(form, 'The server could not be reached. Check your connection and try again.');
        return;
      }
      const result = outcome(response, text);
      if (result.kind === 'navigate') location.assign(result.location);
      else if (result.kind === 'page') show(result.boot, form);
      else if (result.kind === 'failed') fail(form, result.message);
      else if (result.theme) document.dispatchEvent(new CustomEvent('objectshare:theme', { detail: { theme: result.theme } }));
    } catch (error) {
      console.error('ObjectShare could not show the response.', error);
      fail(form, 'The response could not be shown. Reload the page and try again.');
    } finally {
      pending.delete(form);
      buttons.forEach(button => { button.disabled = false; });
    }
  });
}
