import { shopStorage, flushShopStorage, SHOP_ACL_KEY } from '../../utils/shopStorage.mjs';
function parseAclPending(raw) {
  if (raw.length > 8192) throw new Error('Saved ACL change is invalid');
  let value;
  try { value = JSON.parse(raw); } catch { throw new Error('Saved ACL change is invalid'); }
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Saved ACL change is invalid');
  if (typeof value.scopeKey !== 'string' || !value.scopeKey
    || !['permission','enforcement'].includes(value.kind) || typeof value.body?.operationId !== 'string'
    || !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value.body.operationId) || typeof value.body.expectedVersion !== 'string' || !/^[1-9]\d{0,18}$/.test(value.body.expectedVersion)
    || !/^[0-9a-f]{64}$/.test(value.registrySha256)) throw new Error('Saved ACL change is invalid');
  const keys = value.kind === 'permission' ? ['allowed','expectedVersion','operationId','role','tool_name'] : ['enabled','expectedVersion','operationId'];
  if (Object.keys(value).sort().join(',') !== 'body,kind,registrySha256,scopeKey'
    || Object.keys(value.body).sort().join(',') !== keys.sort().join(',')
    || (value.kind === 'permission' && (typeof value.body.tool_name !== 'string' || value.body.tool_name.length > 160
      || !['customer','merchant','admin'].includes(value.body.role) || typeof value.body.allowed !== 'boolean'))
    || (value.kind === 'enforcement' && typeof value.body.enabled !== 'boolean')) throw new Error('Saved ACL change is invalid');
  return value;
}
export function readAclPending(scopeKey) {
  const raw = shopStorage.getItem(SHOP_ACL_KEY);
  if (raw === null) return null;
  const value = parseAclPending(raw);
  if (value.scopeKey !== scopeKey) throw new Error('Saved ACL change belongs to another scope');
  return value;
}
export async function saveAclPending(value) {
  const serialized = JSON.stringify(value);
  parseAclPending(serialized);
  if (shopStorage.getItem(SHOP_ACL_KEY) !== null) throw new Error('A saved ACL change already needs recovery');
  shopStorage.setItem(SHOP_ACL_KEY, serialized);
  await flushShopStorage();
  if (shopStorage.getItem(SHOP_ACL_KEY) !== serialized) throw new Error('Saved ACL change was replaced');
}
export async function clearAclPending(expected, isCurrent = () => true) {
  const serialized = JSON.stringify(expected);
  parseAclPending(serialized);
  if (!isCurrent()) throw new Error('ACL recovery authority changed');
  if (shopStorage.getItem(SHOP_ACL_KEY) !== serialized) throw new Error('Saved ACL change does not match');
  shopStorage.removeItem(SHOP_ACL_KEY);
  try {
    await flushShopStorage();
    if (!isCurrent()) throw new Error('ACL recovery authority changed');
    if (shopStorage.getItem(SHOP_ACL_KEY) !== null) throw new Error('Saved ACL change was replaced');
  } catch (error) {
    // A failed parent acknowledgement is not permission to forget recovery.
    // Restore only our absent slot, never a replacement or renewed authority.
    if (isCurrent() && shopStorage.getItem(SHOP_ACL_KEY) === null) {
      shopStorage.setItem(SHOP_ACL_KEY, serialized);
      try { await flushShopStorage(); } catch { /* Retain local GET-only recovery. */ }
    }
    throw error;
  }
}
export function assertAclReceipt(receipt, pending) {
  const body = pending.body;
  const expected = pending.kind === 'permission'
    ? { kind: 'permission', toolKey: body.tool_name, role: body.role, allowed: body.allowed }
    : { kind: 'enforcement', enabled: body.enabled };
  if (!receipt || receipt.operationId !== body.operationId || receipt.expectedVersion !== body.expectedVersion
    || receipt.version !== String(BigInt(body.expectedVersion) + 1n) || receipt.registrySha256 !== pending.registrySha256
    || !receipt.change || Object.keys(receipt.change).length !== Object.keys(expected).length
    || Object.keys(expected).some(key => receipt.change[key] !== expected[key])
    || typeof receipt.enforcement !== 'boolean'
    || (pending.kind === 'enforcement' && receipt.enforcement !== body.enabled)) throw new Error('ACL receipt could not be verified');
  return receipt;
}
