'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { Worker, getEnvironmentData } = require('node:worker_threads');

const SHA256 = /^[0-9a-f]{64}$/;
const QUALIFICATION_PRELOAD_KEY = 'owasp-ai-goat.secureshop.product-description-renderer-worker-token';
const ARTIFACT_ROOT = path.resolve(__dirname, '../../client/build/secureshop-product-description-renderer');
const RENDERER_ROOT_ENV = 'SECURESHOP_PRODUCT_DESCRIPTION_RENDERER_ROOT';
function unavailable() {
  return Object.assign(new Error('SecureShop ProductDescription renderer is unavailable'), {
    code: 'SECURESHOP_PRODUCT_DESCRIPTION_RENDERER_UNAVAILABLE',
  });
}
function sha256(value) { return crypto.createHash('sha256').update(value).digest('hex'); }
function safeName(value) {
  return typeof value === 'string' && /^[a-zA-Z0-9._-]+$/.test(value) && value !== '.' && value !== '..';
}

function configuredRendererRoot() {
  const configured = process.env[RENDERER_ROOT_ENV];
  if (configured === undefined || configured === '') return ARTIFACT_ROOT;
  if (!path.isAbsolute(configured)) throw unavailable();
  return path.resolve(configured);
}

function loadSecureShopProductDescriptionRenderer({ root, timeoutMs = 5000 } = {}) {
  try {
    if (!Number.isInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 15000) throw unavailable();
    root = root === undefined ? configuredRendererRoot() : root;
    if (typeof root !== 'string' || !path.isAbsolute(root)) throw unavailable();
    root = path.resolve(root);
    const manifestPath = path.join(root, 'manifest.json');
    const bytes = fs.readFileSync(manifestPath);
    if (bytes.length > 8192) throw unavailable();
    const manifest = JSON.parse(bytes.toString('utf8'));
    if (!manifest || Object.keys(manifest).sort().join(',')
        !== 'artifact,artifactSha256,component,source,sourceSha256,version'
        || manifest.version !== 1 || manifest.component !== 'SecureShop.Product.Description'
        || manifest.source !== 'client/src/pages/secureshop/components/ProductDescription.jsx'
        || !safeName(manifest.artifact) || !SHA256.test(manifest.sourceSha256)
        || !SHA256.test(manifest.artifactSha256)) throw unavailable();
    const artifactPath = path.join(root, manifest.artifact);
    const artifact = fs.readFileSync(artifactPath);
    if (artifact.length < 1 || artifact.length > 4 * 1024 * 1024
        || sha256(artifact) !== manifest.artifactSha256) throw unavailable();
    return Object.freeze({ componentId: manifest.component,
      sourceSha256: manifest.sourceSha256, artifactSha256: manifest.artifactSha256,
      async renderProductDescription(product, { signal } = {}) {
        signal?.throwIfAborted();
        // Execute the bytes that were hashed above. Reopening artifactPath in
        // the worker would leave a verify/use race if deployment files changed.
        // The isolated full-application qualification preload runs in Worker
        // threads as well as the server process. Carry its server-minted token
        // only when that preload is active, so it can admit this exact renderer
        // worker while retaining a deny-all network policy inside the worker.
        const qualificationToken = getEnvironmentData(QUALIFICATION_PRELOAD_KEY);
        const workerData = typeof qualificationToken === 'string' && /^[a-f0-9]{64}$/.test(qualificationToken)
          ? { product, qualificationPreload: Object.freeze({ version: 1,
            purpose: 'secureshop_product_description_renderer', token: qualificationToken }) }
          : { product };
        const worker = new Worker(artifact.toString('utf8'), { eval: true, workerData });
        let timer;
        let abortReject;
        const abort = () => {
          abortReject?.(signal.reason || Object.assign(new Error('Aborted'), { name: 'AbortError' }));
          worker.terminate().catch(() => {});
        };
        try {
          const result = await new Promise((resolve, reject) => {
            abortReject = reject;
            let received = false;
            worker.once('message', value => { received = true; resolve(value); });
            worker.once('error', reject);
            worker.once('exit', () => {
              if (!received) reject(unavailable());
            });
            timer = setTimeout(() => reject(unavailable()), timeoutMs);
            signal?.addEventListener('abort', abort, { once: true });
          });
          signal?.throwIfAborted();
          if (!result || result.ok !== true || Object.keys(result).sort().join(',') !== 'markup,ok'
              || typeof result.markup !== 'string'
              || Buffer.byteLength(result.markup, 'utf8') > 128 * 1024) throw unavailable();
          return result.markup;
        } finally {
          clearTimeout(timer);
          signal?.removeEventListener('abort', abort);
          await worker.terminate().catch(() => {});
        }
      } });
  } catch (error) {
    if (error?.code === 'SECURESHOP_PRODUCT_DESCRIPTION_RENDERER_UNAVAILABLE') throw error;
    throw unavailable();
  }
}

module.exports = { loadSecureShopProductDescriptionRenderer, ARTIFACT_ROOT, RENDERER_ROOT_ENV };
