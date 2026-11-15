import { mkdir, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { resolve, relative, dirname, join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { compile } from 'svelte/compiler';
import { svelte2tsx } from '../tools/svelte-types/index.mjs';

const root = resolve(import.meta.dirname, '..');
const output = resolve(root, '.check');
const require = createRequire(import.meta.url);
const shim = require.resolve('svelte2tsx/svelte-shims-v4.d.ts', { paths: [resolve(root, 'tools/svelte-types')] });
let warnings = 0;

async function copy(directory) {
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const file = join(directory, entry.name);
    if (entry.isDirectory()) { await copy(file); continue; }
    if (!/\.(svelte|ts)$/.test(entry.name)) continue;
    let source = await readFile(file, 'utf8');
    const destination = join(output, relative(root, file) + (entry.name.endsWith('.svelte') ? '.tsx' : ''));
    if (entry.name.endsWith('.svelte')) {
      const result = compile(source, { filename: file, generate: false });
      for (const warning of result.warnings) {
        console.error(`${relative(root, file)}:${warning.start?.line || 1}: ${warning.code}: ${warning.message}`);
        warnings++;
      }
      source = svelte2tsx(source, { filename: file, isTsFile: true, mode: 'ts' }).code;
    }
    source = source.replace(/(['"])([^'"\n]+\.svelte)\1/g, '$1$2.tsx$1');
    await mkdir(dirname(destination), { recursive: true });
    await writeFile(destination, source);
  }
}

try {
  await mkdir(output, { recursive: true });
  await copy(resolve(root, 'src'));
  const config = JSON.parse(await readFile(join(root, 'tsconfig.json'), 'utf8'));
  config.compilerOptions.jsx = 'preserve';
  config.include = ['src/**/*.ts', 'src/**/*.tsx', shim, shim.replace('svelte-shims-v4.d.ts', 'svelte-jsx-v4.d.ts')];
  await writeFile(join(output, 'tsconfig.json'), JSON.stringify(config));
  const result = spawnSync(process.execPath, [join(root, 'node_modules/typescript/bin/tsc'), '--project', join(output, 'tsconfig.json')], { stdio: 'inherit' });
  if (result.error) throw result.error;
  process.exitCode = result.status || (warnings ? 1 : 0);
} finally {
  await rm(output, { recursive: true, force: true });
}
