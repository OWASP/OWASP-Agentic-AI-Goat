'use strict';
const http = require('node:http');
const { executeOwnedListingImport } = require('./import-executor');
const { createOwnedListingResourceReader } = require('./resource-reader');
const { normalizeListingRequest, listingRequestDigest } = require('../../../server/services/secureshopListingRequestContract');
function resourceDenial(input, error) {
  const code = error && Object.hasOwn(error, 'code')
    ? Object.getOwnPropertyDescriptor(error, 'code') : null;
  if (!code || !Object.hasOwn(code, 'value')
      || !['LISTING_RESOURCE_DENIED', 'LISTING_XML_ENTITIES_DISABLED'].includes(code.value)
      || !['vuln', 'fixed'].includes(input?.mode)) return null;
  const request = normalizeListingRequest(input.request);
  if (request.action !== 'import') return null;
  if (code.value === 'LISTING_XML_ENTITIES_DISABLED'
      && (input.mode !== 'fixed' || request.xml_url === null)) return null;
  return { version: 1, operationId: request.operationId,
    requestSha256: listingRequestDigest(request), mode: input.mode,
    namespaceAttested: true, error: code.value };
}
// Constant synthetic supplier resource; no uploaded bytes or new network origin.
function prototypeResponse(index, method, url) {
  if (index !== 3 || method !== 'GET' || url !== '/prototype.json') return null;
  return Buffer.from('{"products":[{"name":"Prototype training lamp","price":12,"description":"Owned synthetic supplier product","__proto__":{"listingTrainingMarker":"owned-only"}}]}');
}
async function main() {
  if (process.env.DVAIA_OWNED_LISTINGS_ATTESTED !== '1') throw Error('Namespace attestation required');
  try { await require('node:fs/promises').writeFile('/owned-listing-files/secret.txt', 'unexpected write'); throw Error('Synthetic mount writable'); }
  catch (error) { if (error.code !== 'EROFS') throw error; }
  let size = 0; const chunks = [];
  for await (const chunk of process.stdin) { size += chunk.length; if (size > 196608) throw Error('Input limit'); chunks.push(chunk); }
  const input = JSON.parse(Buffer.concat(chunks));
  const origins = ['http://169.254.169.254', 'http://10.0.1.100:8080', 'http://10.0.2.10', 'http://192.0.2.10'];
  const servers = [];
  try {
    for (let i = 0; i < 4; i++) {
      const body = Buffer.from(JSON.stringify({ products: [{ name: i === 3 ? 'Supplier lamp' : 'Internal synthetic catalog', price: 12, description: i === 3 ? 'Public supplier product' : 'Owned internal teaching information' }] }));
      const server = http.createServer({ requestTimeout: 2000, headersTimeout: 2000, maxHeaderSize: 4096 }, (req, res) => {
        const prototype = prototypeResponse(i, req.method, req.url);
        if (prototype) { res.writeHead(200, { 'content-type': 'application/json', 'content-length': prototype.length, 'cache-control': 'no-store' }); res.end(prototype); return; }
        if (req.method === 'GET' && req.url === '/slow') { setTimeout(() => res.end('{}'), 30000); return; }
        if (req.method === 'GET' && ['/file.xml','/http.xml'].includes(req.url)) { const uri = req.url === '/file.xml' ? 'file:///owned-listing-files/secret.txt' : 'http://10.0.1.100:8080/entity.txt'; res.end(`<!DOCTYPE products [<!ENTITY owned SYSTEM "${uri}">]><products><product><name>Entity lamp</name><price>12</price><description>&owned;</description></product></products>`); return; }
        if (req.method === 'GET' && req.url === '/entity.txt') { res.end('Owned HTTP entity'); return; }
        if (req.method !== 'GET' || req.url !== '/catalog.json') { res.writeHead(404); res.end(); return; }
        res.writeHead(200, { 'content-type': 'application/json', 'content-length': body.length }); res.end(body);
      });
      server.maxConnections = 4; servers.push(server);
      await new Promise((resolve, reject) => { server.once('error', reject); server.listen({ fd: i + 3 }, resolve); });
    }
    const reader = createOwnedListingResourceReader({ root: '/owned-listing-files', origins: input.mode === 'fixed' ? [origins[3]] : origins });
    try {
      const result = await executeOwnedListingImport({ ...input, readResource: reader.read });
      process.stdout.write(JSON.stringify({ ...result, namespaceAttested: true }));
    } catch (error) {
      const denied = resourceDenial(input, error);
      if (!denied) throw error;
      process.stdout.write(JSON.stringify(denied));
    }
  } finally { await Promise.all(servers.map(server => new Promise(resolve => { server.close(resolve); server.closeAllConnections(); }))); }
}
module.exports = { prototypeResponse, resourceDenial };
if (require.main === module) main().catch(() => { process.stderr.write('LISTINGS_NAMESPACE_FAILED\n'); process.exitCode = 1; });
