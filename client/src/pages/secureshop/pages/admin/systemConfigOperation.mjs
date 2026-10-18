// Recovery references only. Paths, file contents and credentials must never be
// persisted here. Integrating callers persist/flush before the first dispatch.
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const HASH = /^[a-f0-9]{64}$/;
const fail = () => { throw new Error('Invalid saved System operation'); };
function reference(value) {
  if (!value || Array.isArray(value) || Object.keys(value).sort().join(',') !== 'operationId,scopeKey,state'
      || typeof value.scopeKey !== 'string' || !HASH.test(value.scopeKey)
      || typeof value.operationId !== 'string' || !UUID.test(value.operationId)
      || !['pending', 'unknown', 'completed'].includes(value.state)) fail();
  return { scopeKey: value.scopeKey, operationId: value.operationId, state: value.state };
}
function validated(values) {
  if (!Array.isArray(values) || values.length > 8) fail();
  const rows = Array.from(values, reference);
  if (new Set(rows.map(row => `${row.scopeKey}:${row.operationId}`)).size !== rows.length) fail();
  return rows;
}
export function decodeSystemConfigReferences(raw) {
  if (raw === null) return [];
  if (typeof raw !== 'string' || new TextEncoder().encode(raw).length > 4096) fail();
  let value;
  try { value = JSON.parse(raw); } catch { fail(); }
  if (!value || Array.isArray(value) || Object.keys(value).sort().join(',') !== 'references,version' || value.version !== 1) fail();
  return validated(value.references);
}
export function encodeSystemConfigReferences(values) {
  return JSON.stringify({ version: 1, references: validated(values) });
}
export function rememberSystemConfigReference(values, raw) {
  const rows = validated(values), next = reference(raw);
  const index = rows.findIndex(row => row.scopeKey === next.scopeKey && row.operationId === next.operationId);
  if (index < 0) {
    if (rows.length === 8) throw new Error('Verify or explicitly forget an earlier System operation first');
    rows.push(next);
  } else {
    // Do not regress an uncertain or completed operation to pending, and do
    // not discard a durable completed state during a racing persistence write.
    if (rows[index].state === 'unknown' && next.state === 'pending'
        || rows[index].state === 'completed' && next.state !== 'completed') {
      throw new Error('Saved System operation changed');
    }
    rows[index] = next;
  }
  return rows;
}
export function forgetSystemConfigReference(values, raw) {
  const rows = validated(values), expected = reference(raw);
  const index = rows.findIndex(row => row.scopeKey === expected.scopeKey && row.operationId === expected.operationId);
  if (index < 0 || rows[index].state !== expected.state) throw new Error('Saved System operation changed');
  return rows.filter((_, position) => position !== index);
}
