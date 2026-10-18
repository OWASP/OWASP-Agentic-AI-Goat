'use strict';

// This process runs only behind policy-init inside the per-call bwrap namespace.
// The process global is the intentional Listings teaching sink.
const crypto = require('node:crypto');
const nunjucks = require('/opt/listing-template/nunjucks-3.2.4.js');
const { normalizeListingTemplateExecution, listingTemplateExecutionDigest, ISOLATION, VERSION }
  = require('/server/services/secureshopListingTemplateExecutorContract.js');

function main() {
  const encoded = process.argv[2];
  const marker = process.argv[3];
  if (typeof encoded !== 'string' || !/^[A-Za-z0-9+/=]{4,131072}$/.test(encoded)
      || typeof marker !== 'string' || !/^__LISTING_TEMPLATE_[0-9a-f]{64}__$/.test(marker)) throw new Error('Invalid template worker arguments');
  const payload = JSON.parse(Buffer.from(encoded, 'base64').toString('utf8'));
  if (!payload || typeof payload !== 'object' || Object.keys(payload).sort().join(',')
      !== 'description,operationId,price,productId,requestSha256,sourceSha256,templateSource,title,version') throw new Error('Invalid template worker request');
  const { requestSha256, ...raw } = payload;
  const request = normalizeListingTemplateExecution(raw);
  if (requestSha256 !== listingTemplateExecutionDigest(request)) throw new Error('Template request digest mismatch');
  const env = new nunjucks.Environment(null, { autoescape: false, throwOnUndefined: false });
  if (!process.mainModule) Object.defineProperty(process, 'mainModule', { value: module, configurable: false });
  env.addGlobal('process', process);
  env.addGlobal('global', global);
  // @intentional-vulnerability ssti-listing-template
  const rendered = env.renderString(request.templateSource, {
    title: request.title, description: request.description, price: request.price,
  });
  const bytes = Buffer.from(rendered, 'utf8');
  if (bytes.length > 65536) throw new Error('Template result too large');
  process.stdout.write(marker + Buffer.from(JSON.stringify({
    version: VERSION, operationId: request.operationId, productId: request.productId,
    requestSha256, sourceSha256: request.sourceSha256, isolation: ISOLATION,
    renderedBase64: bytes.toString('base64'),
    renderedSha256: crypto.createHash('sha256').update(bytes).digest('hex'),
  })).toString('base64'));
}

try { main(); }
catch { process.stderr.write('Listing template worker failed'); process.exitCode = 70; }
