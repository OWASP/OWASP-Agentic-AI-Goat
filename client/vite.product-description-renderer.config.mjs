import path from 'node:path';
import fs from 'node:fs/promises';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

const root = path.dirname(fileURLToPath(import.meta.url));
const source = path.join(root, 'src/pages/secureshop/components/ProductDescription.jsx');
const defaultOutDir = path.join(root, 'build/secureshop-product-description-renderer');
const artifact = 'renderer.cjs';
const sha256 = value => crypto.createHash('sha256').update(value).digest('hex');

function manifest(outDir) {
  return {
    name: 'owasp-ai-goat-secureshop-product-description-renderer-manifest',
    async closeBundle() {
      const [sourceBytes, artifactBytes] = await Promise.all([
        fs.readFile(source), fs.readFile(path.join(outDir, artifact)),
      ]);
      await fs.writeFile(path.join(outDir, 'manifest.json'), `${JSON.stringify({
        version: 1,
        component: 'SecureShop.Product.Description',
        source: 'client/src/pages/secureshop/components/ProductDescription.jsx',
        sourceSha256: sha256(sourceBytes), artifact,
        artifactSha256: sha256(artifactBytes),
      })}\n`, { mode: 0o644 });
    },
  };
}

export default defineConfig(({ command }) => {
  if (command !== 'build') throw new Error('ProductDescription renderer supports build only');
  // Qualification builds need writable output outside the immutable source tree.
  // Keep the normal application build location unless the caller explicitly
  // supplies an absolute or relative output root for this renderer only.
  const outDir = process.env.SECURESHOP_PRODUCT_DESCRIPTION_RENDERER_OUT_DIR
    ? path.resolve(process.env.SECURESHOP_PRODUCT_DESCRIPTION_RENDERER_OUT_DIR)
    : defaultOutDir;
  process.env.NODE_ENV = 'production';
  process.env.VITE_USER_NODE_ENV = '';
  return { plugins: [react(), manifest(outDir)],
    define: { 'process.env.NODE_ENV': JSON.stringify('production'),
      'process.env': JSON.stringify({ NODE_ENV: 'production' }) },
    build: {
    // This server-side library has no public assets; keep its manifest bundle exact.
    copyPublicDir: false,
    target: 'node18', outDir, emptyOutDir: true, minify: false,
    lib: { entry: path.join(root,
      'src/pages/secureshop/components/productDescriptionServerRenderer.jsx'),
    formats: ['cjs'], fileName: () => artifact },
    rollupOptions: { external: ['node:worker_threads'] },
    },
  };
});
