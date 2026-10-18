'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { pathToFileURL } = require('node:url');
const { createOwnedListingResourceReader } = require('../sidecars/sandbox-runner/owned-listings/resource-reader');
const { parseOwnedListingXml } = require('../sidecars/sandbox-runner/owned-listings/xml-parser');

test('actual HTTP entities resolve owned bytes; redirect, status, limits and stalls fail', { timeout: 4000 }, async () => {
  const server = http.createServer((req, res) => {
    if (req.url === '/stall') { res.writeHead(200); res.write('incomplete'); return; }
    if (req.url === '/escape') { res.writeHead(302, { location: 'http://127.0.0.1:1/not-owned' }); res.end(); return; }
    if (req.url === '/missing') { res.writeHead(404); res.end('not evidence'); return; }
    res.end('OWNED_HTTP_ENTITY');
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    const origin = `http://127.0.0.1:${server.address().port}`;
    const reader = createOwnedListingResourceReader({ root: os.tmpdir(), origins: [origin], timeoutMs: 150 });
    const xml = `<!DOCTYPE products [<!ENTITY lesson SYSTEM "${origin}/entity">]><products><product><name>Example</name><description>&lesson;</description></product></products>`;
    const result = await parseOwnedListingXml(xml, { mode: 'vuln', resolveEntity: reader.read });
    assert.equal(result.products[0].description, 'OWNED_HTTP_ENTITY');
    assert.equal(result.entityReads[0].byteCount, 17);
    await assert.rejects(reader.read(origin + '/escape'), { code: 'LISTING_RESOURCE_DENIED' });
    await assert.rejects(reader.read(origin + '/missing'), { code: 'LISTING_RESOURCE_HTTP_ERROR' });
    await assert.rejects(reader.read(origin + '/entity', { maxBytes: 2 }), { code: 'LISTING_RESOURCE_LIMIT' });
    await assert.rejects(reader.read(origin + '/stall'));
    const controller = new AbortController(); controller.abort();
    await assert.rejects(reader.read(origin + '/entity', { signal: controller.signal }));
  } finally { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); }
});

test('file reader accepts owned synthetic files and denies sibling paths and symlinks', async () => {
  const temporary = await fs.mkdtemp(path.join(os.tmpdir(), 'dvaia-listing-resources-'));
  try {
    const root = path.join(temporary, 'owned'); await fs.mkdir(root);
    const file = path.join(root, 'synthetic.txt'), sibling = path.join(temporary, 'sibling.txt');
    await fs.writeFile(file, 'owned'); await fs.writeFile(sibling, 'sibling');
    await fs.symlink(sibling, path.join(root, 'escape'));
    const reader = createOwnedListingResourceReader({ root, origins: [] });
    assert.equal((await reader.read(pathToFileURL(file).href)).toString(), 'owned');
    for (const target of [sibling, path.join(root, 'escape')]) {
      await assert.rejects(reader.read(pathToFileURL(target).href), { code: 'LISTING_RESOURCE_DENIED' });
    }
    await assert.rejects(reader.read(pathToFileURL(file).href, { maxBytes: 1 }), { code: 'LISTING_RESOURCE_LIMIT' });
  } finally { await fs.rm(temporary, { recursive: true, force: true }); }
});
test('owned named pipes are rejected without blocking on open', {timeout:2000}, async()=>{
 const temporary=await fs.mkdtemp(path.join(os.tmpdir(),'dvaia-listing-fifo-'));
 try{
  const fifo=path.join(temporary,'synthetic-pipe');
  require('node:child_process').execFileSync('mkfifo',[fifo]);
  const reader=createOwnedListingResourceReader({root:temporary,origins:[],timeoutMs:100});
  await assert.rejects(reader.read(pathToFileURL(fifo).href),{code:'LISTING_RESOURCE_LIMIT'});
 }finally{await fs.rm(temporary,{recursive:true,force:true});}
});
