'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { createListingOperationExecutor } = require('../sidecars/sandbox-runner/owned-listings/operation-executor');
const request = { version: 1, action: 'import', operationId: '12345678-1234-4234-8234-123456789abc', json_url: 'http://supplier.local/products', xml_url: null };
async function fixture(t, readResource) {
 const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'listing-journal-'));
 await fs.chmod(directory, 0o700);
 t.after(() => fs.rm(directory, { recursive: true, force: true }));
 const options = { directory, identity: 'a'.repeat(64), mode: 'vuln', readResource };
 return { directory, options, executor: await createListingOperationExecutor(options) };
}
test('actual disposable parser result has immutable receipt and restart replay does not fetch again', async t => {
 let calls = 0;
 const f = await fixture(t, async () => { calls++; return Buffer.from(JSON.stringify({ products: [{ name: 'Lamp', price: 12 }] })); });
 const first = await f.executor.execute(request);
 assert.equal(first.status, 'completed'); assert.equal(first.result.products[0].name, 'Lamp');
 const restarted = await createListingOperationExecutor(f.options);
 assert.deepEqual(await restarted.execute(request), first); assert.equal(calls, 1);
 await assert.rejects(restarted.execute({ ...request, json_url: 'http://supplier.local/changed' }), { code: 'LISTING_OPERATION_CONFLICT' });
});
test('failure is durably truthful, sanitized, and never re-dispatches', async t => {
 let calls = 0;
 const f = await fixture(t, async () => { calls++; throw new Error('/private/secret'); });
 const receipt = await f.executor.execute(request);
 assert.equal(receipt.status, 'failed'); assert.equal(receipt.error, 'LISTING_EXECUTION_FAILED');
 assert.deepEqual(await f.executor.execute(request), receipt); assert.equal(calls, 1);
 assert.ok(!JSON.stringify(receipt).includes('/private/'));
});
test('admission without receipt is unknown after restart and never executed again', async t => {
 let calls = 0;
 const f = await fixture(t, async () => { calls++; return Buffer.from('{}'); });
 await f.executor.execute(request);
 await fs.unlink(path.join(f.directory, request.operationId + '.receipt.json'));
 const restarted = await createListingOperationExecutor(f.options);
 assert.equal((await restarted.execute(request)).status, 'unknown'); assert.equal(calls, 1);
});
test('receipt corruption and wrong namespace identity fail closed', async t => {
 const f = await fixture(t, async () => Buffer.from('{}'));
 await f.executor.execute(request);
 const other = await createListingOperationExecutor({ ...f.options, identity: 'b'.repeat(64) });
 await assert.rejects(other.get(request.operationId), { code: 'LISTING_JOURNAL_IDENTITY' });
 const file = path.join(f.directory, request.operationId + '.receipt.json');
 const value = JSON.parse(await fs.readFile(file)); value.status = 'completed'; value.result = { products: [] };
 await fs.writeFile(file, JSON.stringify(value));
 await assert.rejects(f.executor.get(request.operationId), { code: 'LISTING_RECEIPT_INTEGRITY' });
});
test('retirement drains execution, retains hashes, removes raw data and preserves sibling receipts', async t => {
 let started; const entered = new Promise(resolve => { started = resolve; });
 let release; const blocked = new Promise(resolve => { release = resolve; });
 const f = await fixture(t, async () => { started(); await blocked; return Buffer.from('{"products":[{"name":"Private synthetic","price":1}]}'); });
 const running = f.executor.execute(request);
 await entered;
 const retirement = f.executor.retire(request.operationId);
 release();
 // Retirement may fence admission before execution starts; either outcome must
 // not permit raw GET data or future dispatch after an admitted operation.
 await running.catch(() => {});
 const retired = await retirement;
 assert.ok(retired);
 assert.equal(retired.status,'retired'); assert.ok(retired.tombstoneSha256);
 assert.equal(Object.hasOwn(retired,'result'),false);
 assert.deepEqual(await f.executor.get(request.operationId),retired);
 await assert.rejects(fs.access(path.join(f.directory,request.operationId+'.receipt.json')));
 const restarted = await createListingOperationExecutor(f.options);
 assert.deepEqual(await restarted.execute(request),retired);
 const sibling = await restarted.execute({...request,operationId:'12345678-1234-4234-8234-123456789abd'});
 assert.equal(sibling.status,'completed');
});
test('completed retirement is idempotent and survives a new executor', async t => {
 const f = await fixture(t,async()=>Buffer.from('{"products":[]}'));
 const original=await f.executor.execute(request);
 const retired=await f.executor.retire(request.operationId);
 assert.equal(retired.receiptSha256,original.receiptSha256);
 assert.deepEqual(await f.executor.retire(request.operationId),retired);
 assert.deepEqual(await (await createListingOperationExecutor(f.options)).get(request.operationId),retired);
});
