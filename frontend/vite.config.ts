import { defineConfig, type Plugin } from 'vite';
import { svelte } from '@sveltejs/vite-plugin-svelte';
import { readFile, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

const controllers = ['client-encryption', 'upload', 'sharing', 'captcha', 'admin-users'] as const;

function existingControllers(): Plugin {
  const virtualID = 'virtual:objectshare-controllers';
  return {
    name: 'objectshare-controllers',
    resolveId(id) { if (id === virtualID) return '\0' + id; },
    async load(id) {
      if (id !== '\0' + virtualID) return;
      const sources = await Promise.all(controllers.map(async name => {
        const file = fileURLToPath(new URL(`./src/controllers/${name}.js`, import.meta.url));
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
  plugins: [svelte(), existingControllers(), {
    // The Go embed of frontend/dist needs a file there even in unbuilt checkouts.
    name: 'objectshare-keep-dist',
    async closeBundle() { await writeFile(fileURLToPath(new URL('./dist/.gitkeep', import.meta.url)), ''); },
  }],
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    manifest: 'manifest.json',
    cssCodeSplit: true,
    sourcemap: false,
    rolldownOptions: { input: 'src/main.ts' },
  },
});
