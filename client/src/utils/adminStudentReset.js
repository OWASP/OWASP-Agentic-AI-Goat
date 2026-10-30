// Persist only a session partition and operation UUID, never the bearer token.
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
async function fingerprint(token) {
  if (!globalThis.crypto?.subtle) {
    // HTTP origins lack SubtleCrypto. Canonical JWT jti is a random session ID,
    // used only as a storage partition; the server still authenticates the token.
    let claims;
    try {
      const payload = token.split('.')[1];
      claims = JSON.parse(atob(payload.replace(/-/g, '+').replace(/_/g, '/')));
    } catch (_) { throw new Error('Current session recovery identity is unavailable'); }
    if (!Number.isSafeInteger(claims.userId) || claims.userId < 1 || !UUID.test(claims.jti)) {
      throw new Error('Current session recovery identity is unavailable');
    }
    return `session-${claims.userId}-${claims.jti}`;
  }
  const bytes = new TextEncoder().encode(token);
  const digest = await globalThis.crypto.subtle.digest('SHA-256', bytes);
  return Array.from(new Uint8Array(digest), b => b.toString(16).padStart(2, '0')).join('');
}
function newId() {
  const b = globalThis.crypto.getRandomValues(new Uint8Array(16));
  b[6] = (b[6] & 15) | 64; b[8] = (b[8] & 63) | 128;
  const h = Array.from(b, v => v.toString(16).padStart(2, '0')).join('');
  return `${h.slice(0,8)}-${h.slice(8,12)}-${h.slice(12,16)}-${h.slice(16,20)}-${h.slice(20)}`;
}
export async function runAdminStudentReset({ api, studentId, token, isCurrent,
  storage = sessionStorage, digest = fingerprint, createId = newId }) {
  if (!token || !/^[1-9]\d*$/.test(String(studentId))) throw new Error('Current reset scope is required');
  const scope = await digest(token);
  if (!isCurrent()) throw new Error('Administrator session or selection changed');
  const key = `owasp-ai-goat:admin-student-reset:${scope}:${studentId}:sensitive_info_disclosure`;
  {
    let operationId = storage.getItem(key);
    if (operationId && !UUID.test(operationId)) throw new Error('Saved reset identifier is invalid');
    operationId ||= createId();
    if (!UUID.test(operationId)) throw new Error('Reset identifier is invalid');
    storage.setItem(key, operationId);
    if (storage.getItem(key) !== operationId) throw new Error('Reset recovery could not be saved');
    if (!isCurrent()) throw new Error('Administrator session or selection changed');
    const response = await api.post(`/api/admin/students/${studentId}/workshops/sensitive_info_disclosure/reset`, {},
      { headers: { Authorization: `Bearer ${token}`, 'x-reset-operation-id': operationId } });
    if (!isCurrent()) throw new Error('Administrator session or selection changed');
    if (response.data?.success !== true) throw new Error('Reset completion was not acknowledged');
    if (storage.getItem(key) === operationId) storage.removeItem(key);
    return response;
  }
}
