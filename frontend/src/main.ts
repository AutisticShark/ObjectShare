import 'vite/modulepreload-polyfill';
import { flushSync, mount, unmount } from 'svelte';
import App from './App.svelte';
import './app.css';
import { readBootstrap, type Bootstrap } from './lib/bootstrap';
import { initializeControllers } from './lib/controllers';
import { enhanceForms } from './lib/submit';

let application: ReturnType<typeof mount> | undefined;
let container: HTMLElement | undefined;
let disposeControllers: (() => void) | undefined;

function render(boot: Bootstrap) {
  const previous = container || document.getElementById('objectshare-app');
  if (!previous) return;
  const next = document.createElement('div');
  next.id = 'objectshare-app';
  const mounted = mount(App, { target: next, props: { boot } });
  flushSync();
  disposeControllers?.();
  if (application) void unmount(application);
  previous.replaceWith(next);
  container = next;
  application = mounted;
  disposeControllers = initializeControllers();
}

const initial = readBootstrap(document);
if (initial) {
  try {
    render(initial);
    document.getElementById('objectshare-page')?.remove();
  } catch (error) {
    console.error('ObjectShare frontend could not start.', error);
  }
}

// An enhanced form answered with a page: show it in place, reopen the dialog
// the form came from when the page reports an error, and focus the error.
enhanceForms((boot, form) => {
  const dialogID = form.closest('dialog')?.id;
  render(boot);
  if (boot.Data.Error && dialogID) document.getElementById(dialogID)?.querySelector('[role="alert"]')?.closest('dialog')?.showModal();
  const alert = container?.querySelector<HTMLElement>('dialog[open] [role="alert"], main > [role="alert"]');
  if (alert) {
    alert.tabIndex = -1;
    alert.focus();
  }
});
