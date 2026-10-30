import path from 'node:path';
import fs from 'node:fs/promises';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

const root = path.dirname(fileURLToPath(import.meta.url));
const source = 'client/src/pages/secureshop/components/AgentLane/SearchEcho.jsx';
const entry = 'client/src/pages/secureshop/searchEchoClientRenderer.jsx';
const sha = bytes => crypto.createHash('sha256').update(bytes).digest('hex');

export default defineConfig(({ command }) => {
  if (command !== 'build') throw new Error('SearchEcho renderer supports build only');
  const outDir = process.env.SECURESHOP_SEARCH_ECHO_RENDERER_OUT_DIR
    ? path.resolve(process.env.SECURESHOP_SEARCH_ECHO_RENDERER_OUT_DIR)
    : path.join(root, 'build/secureshop-search-echo-renderer');
  let sourceBytes, entryBytes;
  return { plugins: [react(), { name: 'search-echo-source-manifest',
    async buildStart() {
      [sourceBytes, entryBytes] = await Promise.all([fs.readFile(path.join(root, '..', source)),
        fs.readFile(path.join(root, '..', entry))]);
    },
    async closeBundle() {
      if (!sourceBytes.equals(await fs.readFile(path.join(root, '..', source)))
          || !entryBytes.equals(await fs.readFile(path.join(root, '..', entry))))
        throw new Error('SearchEcho sources changed during build');
      const artifact = 'renderer.js';
      await fs.writeFile(path.join(outDir, 'manifest.json'), JSON.stringify({ version: 1,
        component: 'SecureShop.SearchEcho', source, sourceSha256: sha(sourceBytes),
        entry, entrySha256: sha(entryBytes), artifact,
        artifactSha256: sha(await fs.readFile(path.join(outDir, artifact))) }) + '\n');
    } }], define: { 'process.env.NODE_ENV': JSON.stringify('production') },
    build: { copyPublicDir: false, target: 'es2022', outDir, emptyOutDir: true,
      lib: { entry: path.join(root, '..', entry), name: 'OwaspAiGoatSearchEchoRenderer',
        formats: ['iife'], fileName: () => 'renderer.js' } } };
});
