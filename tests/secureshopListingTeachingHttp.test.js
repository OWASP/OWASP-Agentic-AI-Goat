'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const os = require('node:os');
const { createListingTeachingHttp } = require('../sidecars/sandbox-runner/owned-listings/teaching-http');
const { createOwnedListingResourceReader } = require('../sidecars/sandbox-runner/owned-listings/resource-reader');
test('actual internal HTTP bytes reachable only through vulnerable owned origin policy', async t => {
 const bytes = Buffer.from('{"products":[{"name":"Internal synthetic catalog","price":1}]}');
 const service = await createListingTeachingHttp({ supplierRoutes: [{ path: '/catalog', type: 'application/json', bytes: Buffer.from('{"products":[]}') }], internalRoutes: [{ path: '/catalog', type: 'application/json', bytes }] });
 t.after(service.close);
 bytes.fill(0); // bootstrap input must not mutate served evidence.
 const vuln = createOwnedListingResourceReader({ root: os.tmpdir(), origins: service.originsForMode('vuln') });
 const fixed = createOwnedListingResourceReader({ root: os.tmpdir(), origins: service.originsForMode('fixed') });
 const result = await vuln.read(service.internalOrigin + '/catalog');
 assert.equal(JSON.parse(result).products[0].name, 'Internal synthetic catalog');
 await assert.rejects(fixed.read(service.internalOrigin + '/catalog'), { code: 'LISTING_RESOURCE_DENIED' });
 assert.equal((await fetch(service.supplierOrigin + '/missing')).status, 404);
 assert.equal((await fetch(service.supplierOrigin + '/catalog', { method: 'POST' })).status, 405);
 await assert.rejects(vuln.read('http://127.0.0.1:1/catalog'), { code: 'LISTING_RESOURCE_DENIED' });
});
test('rejects ambiguous or oversized synthetic bootstrap routes before listening', async () => {
 const row = { path: '/catalog', type: 'application/json', bytes: Buffer.from('{}') };
 await assert.rejects(createListingTeachingHttp({ supplierRoutes: [row, row], internalRoutes: [row] }), /Invalid synthetic route/);
 await assert.rejects(createListingTeachingHttp({ supplierRoutes: [{ ...row, bytes: Buffer.alloc(1024 * 1024 + 1) }], internalRoutes: [row] }), /budget/);
});
