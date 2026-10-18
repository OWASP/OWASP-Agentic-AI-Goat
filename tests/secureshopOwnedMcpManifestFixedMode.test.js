'use strict';
// Controlled parser policy only. No attested worker/network/native execution or objective credit.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');
const { createHash } = require('node:crypto');
const xml2js = require('xml2js');
const worker = require('../sidecars/sandbox-runner/owned-mcp-registry/worker');

test('fixed manifest rejects external declarations before entity file IO or XML parsing', async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'owned-manifest-policy-'));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const file = path.join(root, 'synthetic.txt');
  await fs.writeFile(file, 'Owned synthetic entity');
  const originalRead = fs.readFile, originalParse = xml2js.parseStringPromise;
  let reads = 0, parses = 0;
  fs.readFile = function (...args) { reads++; return originalRead.apply(this, args); };
  xml2js.parseStringPromise = function (...args) { parses++; return originalParse.apply(this, args); };
  t.after(() => { fs.readFile = originalRead; xml2js.parseStringPromise = originalParse; });
  for (const declaration of [
    `<!DOCTYPE manifest [<!ENTITY secret SYSTEM "file://${file}">]>`,
    `<!DOCTYPE manifest [<!ENTITY % secret SYSTEM "file://${file}">]>`,
    '<!DOCTYPE manifest [<!ENTITY secret PUBLIC "owned-id" "http://owned.invalid/entity">]>',
    '<!DOCTYPE manifest SYSTEM "http://owned.invalid/dtd">',
  ]) {
    await assert.rejects(worker.parseManifest(`${declaration}<manifest/>`, { root, mode: 'fixed' }),
      error => error.code === 'MCP_REGISTRY_FIXED_ENTITY_DENIED' && error.effectNotStarted === true);
  }
  await assert.rejects(worker.parseManifest('<manifest/>', { root, mode: 'caller-selected' }),
    error => error.code === 'MCP_REGISTRY_EXECUTOR_INVALID' && error.effectNotStarted === true);
  assert.equal(reads, 0); assert.equal(parses, 0);
});

test('vulnerable manifest preserves exact bounded owned-file expansion and original read observation', async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'owned-manifest-vuln-'));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const file = path.join(root, 'synthetic.txt'), text = 'Owned synthetic <entity> & UTF-8 Ω';
  await fs.writeFile(file, text);
  const xml = `<!DOCTYPE manifest [<!ENTITY secret SYSTEM "file://${file}">]><manifest><label>&secret;</label></manifest>`;
  const result = await worker.parseManifest(xml, { root, mode: 'vuln' });
  assert.equal(result.parsed.manifest.label, text);
  assert.deepEqual(result.reads, [{ path: file, sha256: createHash('sha256').update(text).digest('hex'),
    bytes: Buffer.byteLength(text), value: text }]);
  await assert.rejects(worker.parseManifest(xml.replace(file, path.join(path.dirname(root), 'foreign-synthetic.txt')),
    { root, mode: 'vuln' }), { code: 'MCP_REGISTRY_ENTITY_OUTSIDE_NAMESPACE' });
  await fs.writeFile(file, 'a'.repeat(16385));
  await assert.rejects(worker.parseManifest(xml, { root, mode: 'vuln' }), { code: 'MCP_REGISTRY_ENTITY_LIMIT' });
});

test('fixed entity-free manifest parses ordinary server definitions with no entity reads', async () => {
  const xml = '<manifest><server><name>owned</name><transport>sse</transport><url>http://owned.invalid/mcp</url></server></manifest>';
  const result = await worker.parseManifest(xml, { mode: 'fixed' });
  assert.deepEqual(result.reads, []);
  assert.equal(worker.manifestServers(result.parsed)[0].name, 'owned');
  assert.equal(worker.manifestServers(result.parsed)[0].url, 'http://owned.invalid/mcp');
});

test('attested import threads only its validated trusted mode into the parser', async () => {
  const source = await fs.readFile(path.resolve(__dirname, '../sidecars/sandbox-runner/owned-mcp-registry/worker.js'), 'utf8');
  assert.ok(/parseManifest\(xml,\{root,mode:input\.mode\}\)/.test(source),
    'Import must pass its already validated trusted mode to the parser');
  await assert.rejects(worker.operation({ request: {}, activeEntries: [], mode: 'fixed' }),
    error => error.code === 'MCP_REGISTRY_EXECUTOR_UNATTESTED' && error.effectNotStarted === true);
});
