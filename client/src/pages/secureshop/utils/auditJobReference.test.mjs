import { decodeAuditJobReference, readAuditJobReference, saveAuditJobReference,
  assertAuditJobReference, clearAuditJobReference } from './auditJobReference.mjs';
import { shopStorage, flushShopStorage } from './shopStorage.mjs';

jest.mock('./shopStorage.mjs', () => ({ SHOP_AUDIT_JOB_KEY: 'audit-job',
  shopStorage: { getItem: jest.fn(), setItem: jest.fn(), removeItem: jest.fn() },
  flushShopStorage: jest.fn() }));

const reference = { version: 1, scopeKey: 'a'.repeat(64),
  sourceSessionId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
  sourceRequestId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
  proposalId: 'cccccccc-cccc-5ccc-8ccc-cccccccccccc',
  jobSessionId: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd',
  jobRequestId: 'cccccccc-cccc-5ccc-8ccc-cccccccccccc', requestSha256: 'b'.repeat(64) };
let raw;
beforeEach(() => { raw = null;
  shopStorage.getItem.mockImplementation(() => raw);
  shopStorage.setItem.mockImplementation((key, value) => { raw = value; });
  shopStorage.removeItem.mockImplementation(() => { raw = null; });
  flushShopStorage.mockResolvedValue();
});
afterEach(() => jest.clearAllMocks());

test('opaque source/job identity is parent-ACKed and no input is persisted', async () => {
  let release;
  flushShopStorage.mockImplementationOnce(() => new Promise(resolve => { release = resolve; }));
  const saving = saveAuditJobReference(reference);
  expect(raw).not.toContain('Inspect owned audit');
  expect(readAuditJobReference()).toEqual(reference);
  release();
  await expect(saving).resolves.toEqual(reference);
});

test('occupied or malformed slot fails closed and replacement fails exact pre-dispatch check', async () => {
  raw = JSON.stringify(reference);
  await expect(saveAuditJobReference(reference)).rejects.toThrow(/Check the saved/);
  raw = JSON.stringify({ ...reference, requestSha256: 'c'.repeat(64) });
  expect(() => assertAuditJobReference(reference)).toThrow(/changed/);
  expect(() => decodeAuditJobReference(JSON.stringify({ ...reference, input: 'secret' })))
    .toThrow(/invalid/);
});

test('failed clear ACK restores only absent own slot, preserving replacement and epoch change', async () => {
  raw = JSON.stringify(reference);
  flushShopStorage.mockRejectedValueOnce(Error('Parent ACK unavailable'));
  await expect(clearAuditJobReference(reference)).rejects.toThrow('Parent ACK unavailable');
  expect(readAuditJobReference()).toEqual(reference);
  const replacement = { ...reference, proposalId: 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee',
    jobRequestId: 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee' };
  shopStorage.removeItem.mockImplementationOnce(() => { raw = JSON.stringify(replacement); });
  flushShopStorage.mockRejectedValueOnce(Error('Parent ACK unavailable'));
  await expect(clearAuditJobReference(reference)).rejects.toThrow('Parent ACK unavailable');
  expect(readAuditJobReference()).toEqual(replacement);
  raw = JSON.stringify(reference);
  let live = true;
  flushShopStorage.mockImplementationOnce(async () => { live = false; throw Error('Parent ACK unavailable'); });
  await expect(clearAuditJobReference(reference, () => live)).rejects.toThrow('Parent ACK unavailable');
  expect(raw).toBeNull();
});
