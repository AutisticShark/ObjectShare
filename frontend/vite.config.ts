import { defineConfig, type Plugin } from 'vite';
import { svelte } from '@sveltejs/vite-plugin-svelte';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

const controllers = ['client-encryption', 'upload', 'sharing', 'captcha', 'admin-users'] as const;

function existingControllers(): Plugin {
  const virtualID = 'virtual:objectshare-controllers';
  return {
    name: 'objectshare-controllers',
    resolveId(id) { if (id === virtualID || id === 'virtual:objectshare-errors') return '\0' + id; },
    async load(id) {
      if (id === '\0virtual:objectshare-errors') {
        const file = fileURLToPath(new URL('../template/htmx-errors.js', import.meta.url));
        this.addWatchFile(file);
        return readFile(file, 'utf8');
      }
      if (id !== '\0' + virtualID) return;
      const sources = await Promise.all(controllers.map(async name => {
        const filename = name === 'admin-users' ? 'admin_users' : name;
        const file = fileURLToPath(new URL(`../template/${filename}.js`, import.meta.url));
        this.addWatchFile(file);
        const source = await readFile(file, 'utf8');
        return `${JSON.stringify(name)}: function(document, window) { ${source} }`;
      }));
      return `export const controllers = {${sources.join(',\n')}};`;
    },
  };
}

export default defineConfig({
  base: '/assets/frontend/',
  plugins: [svelte(), existingControllers()],
  build: {
    outDir: '../template/frontend',
    emptyOutDir: true,
    manifest: 'manifest.json',
    cssCodeSplit: true,
    sourcemap: false,
    rolldownOptions: { input: 'src/main.ts' },
  },
});
