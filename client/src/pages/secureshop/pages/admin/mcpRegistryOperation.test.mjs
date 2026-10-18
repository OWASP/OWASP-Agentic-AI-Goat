import { attachShopStorage, SHOP_MCP_REGISTRY_KEY } from '../../utils/shopStorage.mjs';
import { administration as decodeAdministration, createOperation, readAnyPending, savePending, clearPending,
  assertPendingCurrent, verifiedImportEntityReads } from './mcpRegistryOperation.mjs';

const { webcrypto, createHash } = require('node:crypto');
const administration = { ready: true, version: '0', scopeKey: 'a'.repeat(64) };
let values, flush, release;

beforeEach(() => {
  Object.defineProperty(globalThis.crypto, 'subtle', { configurable: true, value: webcrypto.subtle });
  values = new Map(); flush = async () => {};
  release = attachShopStorage({ getItem: key => values.get(key) ?? null,
    setItem: (key, value) => values.set(key, value), removeItem: key => values.delete(key),
    flush: () => flush() });
});
afterEach(() => release());

const operation = (name = 'owned-server', scopeKey = administration.scopeKey) =>
  createOperation({ ...administration, scopeKey }, 'register',
    { name, transport: 'sse', url: 'http://owned.invalid/mcp', stdio_cmd: '' });

test('foreign saved registry operation remains visible and cannot be overwritten', async () => {
  const foreign = await operation('foreign-server', 'b'.repeat(64));
  await savePending(foreign);
  expect(await readAnyPending()).toEqual(foreign);
  await expect(savePending(await operation())).rejects.toThrow('Check the saved registry operation');
  expect(await readAnyPending()).toEqual(foreign);
});

test('replacement during parent save ACK blocks the new operation', async () => {
  const original = await operation();
  const replacement = await operation('replacement');
  flush = async () => { values.set(SHOP_MCP_REGISTRY_KEY, JSON.stringify(replacement)); };
  await expect(savePending(original)).rejects.toThrow('Registry recovery authority changed');
  expect(await readAnyPending()).toEqual(replacement);
});

test('failed clear ACK restores only the original absent reference', async () => {
  const original = await operation();
  await savePending(original);
  flush = async () => { throw Error('parent refused removal'); };
  await expect(clearPending(original)).rejects.toThrow('parent refused removal');
  expect(await readAnyPending()).toEqual(original);
  expect(assertPendingCurrent(original)).toEqual(original);
});

test('failed clear ACK does not replace a concurrent saved operation', async () => {
  const original = await operation();
  const replacement = await operation('replacement');
  await savePending(original);
  flush = async () => {
    values.set(SHOP_MCP_REGISTRY_KEY, JSON.stringify(replacement));
    throw Error('parent refused removal');
  };
  await expect(clearPending(original)).rejects.toThrow('parent refused removal');
  expect(await readAnyPending()).toEqual(replacement);
});

test('terminal maximum version remains readable for saved recovery but rejects a new write', async () => {
  const terminal = { ...administration, version: '9007199254740991' };
  expect(decodeAdministration(terminal)).toEqual(terminal);
  await expect(createOperation(terminal, 'register', { name: 'new-server',
    transport: 'sse', url: 'http://owned.invalid/mcp', stdio_cmd: '' }))
    .rejects.toThrow('Invalid saved registry operation');
});

test('completed import displays each exact owned entity read once with verified bytes', async () => {
  const value = '<img src=x onerror=alert(1)>\n';
  const read = { path: '/owned-mcp-files/admin-token.txt', value,
    bytes: new TextEncoder().encode(value).length,
    sha256: createHash('sha256').update(value).digest('hex') };
  const effect = { isolation: 'owned-mcp-registry-v1', mode: 'vuln', entityReads: [read] };
  const receipt = { state: 'completed', action: 'import', changes: [
    { name: 'first', effect }, { name: 'second', effect: JSON.parse(JSON.stringify(effect)) }] };
  expect(await verifiedImportEntityReads(receipt)).toEqual([read]);
  for (const bad of [
    { ...read, path: '/owned-mcp-files/../private.txt' },
    { ...read, path: '/owned-mcp-files//admin-token.txt' },
    { ...read, bytes: read.bytes - 1 },
    { ...read, sha256: '0'.repeat(64) },
    { ...read, value: value + 'changed' },
  ]) {
    const altered = JSON.parse(JSON.stringify(receipt));
    altered.changes[1].effect.entityReads = [bad];
    await expect(verifiedImportEntityReads(altered)).rejects.toThrow('could not be verified');
  }
  const fixed = JSON.parse(JSON.stringify(receipt));
  fixed.changes = [{ name: 'first', effect: { ...effect, mode: 'fixed', entityReads: [] } }];
  expect(await verifiedImportEntityReads(fixed)).toEqual([]);
  fixed.changes[0].effect.entityReads = [read];
  await expect(verifiedImportEntityReads(fixed)).rejects.toThrow('could not be verified');
  const mixed = JSON.parse(JSON.stringify(receipt));
  mixed.changes[1].effect.mode = 'fixed';
  await expect(verifiedImportEntityReads(mixed)).rejects.toThrow('could not be verified');
});
