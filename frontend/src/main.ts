import 'vite/modulepreload-polyfill';
import { flushSync, mount, unmount } from 'svelte';
import htmx from 'htmx.org';
import App from './App.svelte';
import './app.css';
import 'virtual:objectshare-errors';
import { readBootstrap, type Bootstrap } from './lib/bootstrap';
import { initializeControllers } from './lib/controllers';

htmx.config.allowEval = false;
htmx.config.allowScriptTags = false;
htmx.config.includeIndicatorStyles = false;

let application: ReturnType<typeof mount> | undefined;
let container: HTMLElement | undefined;
let disposeControllers: (() => void) | undefined;

function render(boot: Bootstrap) {
  const previous = container || document.querySelector<HTMLElement>('.page');
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
  htmx.process(next);
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

document.addEventListener('htmx:beforeSwap', (event: Event) => {
  const detail = (event as CustomEvent).detail as {
    shouldSwap: boolean; serverResponse?: string; xhr?: XMLHttpRequest;
  };
  if (!detail?.serverResponse || !detail.xhr?.getResponseHeader('Content-Type')?.startsWith('text/html')) return;
  const page = new DOMParser().parseFromString(detail.serverResponse, 'text/html');
  const boot = readBootstrap(page);
  if (!boot) return;
  detail.shouldSwap = false;
  const dialogID = document.querySelector<HTMLDialogElement>('dialog[open]')?.id;
  queueMicrotask(() => {
    render(boot);
    if (boot.Data.Error && dialogID) document.getElementById(dialogID)?.querySelector('[role="alert"]')?.closest('dialog')?.showModal();
    const alert = container?.querySelector<HTMLElement>('dialog[open] [role="alert"], main > [role="alert"]');
    if (alert) {
      alert.tabIndex = -1;
      alert.focus();
    }
  });
});
