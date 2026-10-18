'use strict';

// This worker is only launched inside the dedicated policy-render bwrap
// namespace. The unsafe process global is intentional teaching behavior; do
// not import or execute this worker in the application process.

const crypto = require('node:crypto');
const nunjucks = require('/opt/policy-render/nunjucks-3.2.4.js');

const ISOLATION = 'bwrap-policy-template-v1';
const VERSION = 1;
const MAX_RENDERED_BYTES = 64 * 1024;

function fail(message) {
  const error = new Error(message);
  error.code = 'POLICY_RENDER_WORKER_INVALID';
  throw error;
}

function readRequest(encoded) {
  let value;
  try { value = JSON.parse(Buffer.from(String(encoded || ''), 'base64').toString('utf8')); }
  catch { fail('Invalid policy render request'); }
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || Object.keys(value).sort().join(',') !== 'markdown,name,operationId,requestSha256,targets'
      || typeof value.operationId !== 'string' || typeof value.name !== 'string'
      || typeof value.markdown !== 'string' || !Array.isArray(value.targets)
      || typeof value.requestSha256 !== 'string' || !/^[0-9a-f]{64}$/.test(value.requestSha256)) {
    fail('Invalid policy render request');
  }
  return value;
}

function emit(marker, value) {
  process.stdout.write(`${marker}${Buffer.from(JSON.stringify(value)).toString('base64')}`);
}

function main() {
  const request = readRequest(process.argv[2]);
  const marker = process.argv[3];
  if (typeof marker !== 'string' || !/^__POLICY_RENDER_[0-9a-f]{64}__$/.test(marker)) fail('Invalid result marker');
  const environment = new nunjucks.Environment(null, { autoescape: false, throwOnUndefined: false });
  // Modern Node no longer initializes process.mainModule. Restore that legacy
  // property inside this disposable namespace so the documented teaching
  // payload reaches the real module loader here, never in the backend.
  if (!process.mainModule) Object.defineProperty(process, 'mainModule', { value: module, configurable: false });
  environment.addGlobal('process', process);
  environment.addGlobal('global', global);
  const rendered = environment.renderString(request.markdown, {
    store_name: 'SecureShop', current_year: new Date().getUTCFullYear(),
    policy_name: request.name, targets: [...request.targets],
  });
  const renderedBytes = Buffer.from(rendered, 'utf8');
  if (renderedBytes.length > MAX_RENDERED_BYTES) fail('Policy render output exceeds 65536 UTF-8 bytes');
  emit(marker, {
    version: VERSION, operationId: request.operationId,
    requestSha256: request.requestSha256, isolation: ISOLATION,
    renderedBase64: renderedBytes.toString('base64'),
    renderedSha256: crypto.createHash('sha256').update(renderedBytes).digest('hex'),
  });
}

try { main(); }
catch (error) {
  process.stderr.write(String(error?.message || 'Policy render failed').slice(0, 4096));
  process.exitCode = 70;
}
