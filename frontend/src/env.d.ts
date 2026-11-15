/// <reference types="svelte" />
/// <reference types="vite/client" />

declare module 'virtual:objectshare-controllers' {
  export const controllers: Record<string, (document: Document, window: Window) => void>;
}
