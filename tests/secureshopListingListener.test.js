'use strict';
const test = require('node:test'), assert = require('node:assert/strict');
const fs = require('node:fs/promises'), os = require('node:os'), path = require('node:path');
const { createListingListener } = require('../sidecars/sandbox-runner/owned-listings/http-listener');
test('authenticated operation HTTP retains exact receipt for GET and repeated POST', async t => {
 const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'listing-listener-')); await fs.chmod(directory, 0o700);
 const token = 'a'.repeat(43); let calls = 0;
 const namespace = { checkReadiness: async () => ({ ready: true, runtimeDigest: 'b'.repeat(64) }), execute: async () => { calls++; return { products: [] }; } };
 const listener = await createListingListener({ directory, token, mode: 'vuln', identity: 'c'.repeat(64), namespace });
 t.after(async () => { await listener.close(); await fs.rm(directory, { recursive: true, force: true }); });
 const { port } = await listener.start(), url = `http://127.0.0.1:${port}/operations`;
 const request = { version: 1, action: 'import', operationId: '12345678-1234-4234-8234-123456789abc', json_url: 'http://supplier.training/catalog', xml_url: null };
 assert.equal((await fetch(url)).status, 401);
 const options = { method: 'POST', headers: { authorization: 'Bearer ' + token }, body: JSON.stringify(request) };
 const first = await (await fetch(url, options)).json(); assert.equal(first.status, 'completed');
 assert.deepEqual(await (await fetch(url + '/' + request.operationId, { headers: options.headers })).json(), first);
 assert.deepEqual(await (await fetch(url, options)).json(), first); assert.equal(calls, 1);
});
