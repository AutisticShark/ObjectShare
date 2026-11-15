import { controllers } from 'virtual:objectshare-controllers';

type Listener = { target: EventTarget; type: string; callback: EventListenerOrEventListenerObject; options?: boolean | AddEventListenerOptions };

function scopedTarget<T extends Document | Window>(target: T, listeners: Listener[]): T {
  return new Proxy(target, {
    get(object, key) {
      if (key === 'addEventListener') {
        return (type: string, callback: EventListenerOrEventListenerObject, options?: boolean | AddEventListenerOptions) => {
          object.addEventListener(type, callback, options);
          listeners.push({ target: object, type, callback, options });
        };
      }
      const value: unknown = Reflect.get(object, key, object);
      return typeof value === 'function' ? value.bind(object) : value;
    },
    set(object, key, value) { return Reflect.set(object, key, value, object); },
  });
}

export function initializeControllers(): () => void {
  const listeners: Listener[] = [];
  const scopedDocument = scopedTarget(document, listeners);
  const scopedWindow = scopedTarget(window, listeners);
  for (const initialize of Object.values(controllers)) initialize(scopedDocument, scopedWindow);
  if (document.querySelector('.objectshare-turnstile')) {
    const api = window as Window & { turnstile?: { remove(id: string): void }; objectShareTurnstileReady?: () => void };
    if (api.turnstile) api.objectShareTurnstileReady?.();
    else if (!document.getElementById('objectshare-turnstile-api')) {
      const script = document.createElement('script');
      script.id = 'objectshare-turnstile-api';
      script.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit&onload=objectShareTurnstileReady';
      script.async = true;
      document.head.append(script);
    }
  }
  return () => {
    const api = window as Window & { turnstile?: { remove(id: string): void } };
    document.querySelectorAll<HTMLElement>('.objectshare-turnstile[data-widget-id]').forEach(element => {
      if (element.dataset.widgetId) api.turnstile?.remove(element.dataset.widgetId);
    });
    for (const listener of listeners) {
      if (listener.type === 'pagehide' && typeof listener.callback === 'function') listener.callback(new Event('pagehide'));
      listener.target.removeEventListener(listener.type, listener.callback, listener.options);
    }
  };
}
