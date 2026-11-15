/// <reference types="svelte" />
/// <reference types="vite/client" />

declare module 'virtual:objectshare-controllers' {
  export const controllers: Record<string, (document: Document, window: Window) => void>;
}

declare module 'virtual:objectshare-errors';

declare module 'htmx.org' {
  interface HTMX { process(element: Element): void; config: { allowEval: boolean; allowScriptTags: boolean; includeIndicatorStyles: boolean }; }
  const htmx: HTMX;
  export default htmx;
}
