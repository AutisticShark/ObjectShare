import 'svelte/elements';

declare module 'svelte/elements' {
  interface HTMLAttributes<T extends EventTarget> {
    'hx-post'?: string;
    'hx-select'?: string;
    'hx-target'?: string;
    'hx-swap'?: string;
    'hx-disabled-elt'?: string;
    'hx-confirm'?: string;
    'hx-encoding'?: string;
  }
}
