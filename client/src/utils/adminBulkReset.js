// Keep retries bound to the original server cohort, including a lost success response.
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const active = new Set();
function newId() {
  const bytes = globalThis.crypto.getRandomValues(new Uint8Array(16));
  bytes[6] = (bytes[6] & 15) | 64; bytes[8] = (bytes[8] & 63) | 128;
  const h = Array.from(bytes, n => n.toString(16).padStart(2, '0')).join('');
  return `${h.slice(0,8)}-${h.slice(8,12)}-${h.slice(12,16)}-${h.slice(16,20)}-${h.slice(20)}`;
}
export async function runAdminBulkReset({api, actorId, token, workshopKey, confirmPassword, isCurrent, onCommit,
  storage = sessionStorage}) {
  if (!actorId || !token || !isCurrent()) throw new Error('Current administrator session required');
  const scope = workshopKey ? `workshop:${workshopKey}` : 'all';
  const key = `dvaia:admin-reset:${actorId}:${scope}`;
  if (active.has(String(actorId))) throw new Error('An administrative reset is already running');
  active.add(String(actorId));
  try {
    const headers = {Authorization: `Bearer ${token}`};
    const pending = await api.get('/api/admin/workshops/reset-operations', {headers,params:workshopKey?{requestKind:'workshop',workshopKey}:{requestKind:'all'}});
    if (!isCurrent()) throw new Error('Administrator session changed');
    if (pending.data?.success !== true || !Array.isArray(pending.data.operations)) throw new Error('Reset recovery state is unavailable');
    const matches = pending.data.operations.filter(op => workshopKey
      ? op.requestKind === 'workshop' && op.workshopKeys?.length === 1 && op.workshopKeys[0] === workshopKey
      : op.requestKind === 'all');
    let operationId = storage.getItem(key);
    if (operationId && !UUID.test(operationId)) throw new Error('Saved reset recovery identifier is invalid');
    // Resume the oldest matching operation; the server retains its immutable cohort.
    operationId ||= matches[0]?.operationId || newId();
    if (!UUID.test(operationId)) throw new Error('Server reset recovery identifier is invalid');
    storage.setItem(key, operationId); // Fail before effects if recovery cannot survive a reload.
    if (storage.getItem(key) !== operationId) throw new Error('Reset recovery could not be saved');
    if (!isCurrent()) throw new Error('Administrator session changed');
    const response = await api.post(workshopKey
      ? `/api/admin/workshops/${encodeURIComponent(workshopKey)}/reset-all-students`
      : '/api/admin/database/reset', workshopKey ? {} : {resetType: 'challenges', confirmPassword},
    {headers: {...headers, 'x-reset-operation-id': operationId}});
    if (!isCurrent()) throw new Error('Administrator session changed');
    if (response.data?.success !== true) throw new Error(response.data?.error || 'Reset did not complete');
    await onCommit?.(response);
    if (!isCurrent()) throw new Error('Administrator session changed');
    storage.removeItem(key);
    return response;
  } finally { active.delete(String(actorId)); }
}
