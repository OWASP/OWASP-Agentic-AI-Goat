// Recovery follows server references only. It never resubmits an original mutation.
const UUID = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/;
export const recoveryCancelled = () => Object.assign(new Error('CTF recovery cancelled'), { name: 'AbortError', code: 'CTF_RECOVERY_CANCELLED' });
export const isCtfRecoveryCancelled = error => error?.code === 'CTF_RECOVERY_CANCELLED' || error?.name === 'AbortError' || error?.code === 'ERR_CANCELED';
export function recoveryNeeded(state, message = 'Outcome pending or unknown. Do not resubmit automatically.') {
  return Object.assign(new Error(message), { code: 'CTF_RECOVERY_NEEDED', recovery: state, response: { data: { error: message } } });
}
export function createCtfRecoveryState(kind, response) {
  const body = response?.data || {};
  const valid = value => typeof value === 'string' && UUID.test(value) ? value : null;
  return { kind, operationId: kind === 'operation' ? valid(body.operationId) : null,
    runId: kind === 'attempt' ? valid(body.runId) : null,
    admissionId: kind === 'attempt' ? valid(body.admissionId) : null,
    decisionId: kind === 'attempt' ? valid(body.decisionId) : null, authorizationSent: false };
}
export const canCheckCtfRecovery = state => Boolean(state && (state.operationId || state.admissionId || state.decisionId || state.runId));
export async function resolveCtfRecovery({ client, state, headers, signal, isCurrent = () => true, maxRequests = 12, windowMs = 30000, explicitResume = false }) {
  headers = Object.freeze({ ...headers });
  const started = Date.now(); let requests = 0, resumeSent = false;
  const assertCurrent = () => { if (signal?.aborted || !isCurrent()) throw recoveryCancelled(); };
  async function pause(ms) {
    assertCurrent();
    await new Promise((resolve, reject) => {
      const abort = () => { clearTimeout(timer); reject(recoveryCancelled()); };
      const timer = setTimeout(() => { signal?.removeEventListener('abort', abort); resolve(); }, ms);
      signal?.addEventListener('abort', abort, { once: true });
    });
    assertCurrent();
  }
  async function call(method, url) {
    assertCurrent();
    if (++requests > maxRequests || Date.now() - started >= windowMs) throw recoveryNeeded(state);
    let timer, abort;
    const request = new AbortController();
    const parentAbort = () => request.abort();
    signal?.addEventListener('abort', parentAbort, { once: true });
    try {
      return await Promise.race([
        (method === 'post' ? client.post(url, {}, { headers, signal: request.signal }) : client.get(url, { headers, signal: request.signal })),
        new Promise((_, reject) => {
          timer = setTimeout(() => { reject(recoveryNeeded(state)); request.abort(); }, Math.max(1, windowMs - (Date.now() - started)));
          abort = () => reject(recoveryCancelled()); signal?.addEventListener('abort', abort, { once: true });
        }),
      ]);
    } finally { clearTimeout(timer); signal?.removeEventListener('abort', abort); signal?.removeEventListener('abort', parentAbort); request.abort(); assertCurrent(); }
  }
  if (!canCheckCtfRecovery(state)) throw recoveryNeeded(state, 'Recovery is needed, but this attempt has no supported result reference. Do not resubmit automatically.');
  for (;;) {
    let response;
    try {
      if (state.kind === 'operation') response = await call('get', `/api/ctf/operations/${state.operationId}`);
      else if (state.decisionId) response = await call('get', `/api/ctf/publications/${state.decisionId}`);
      else if (!state.admissionId && state.runId) {
        const read = await call('get', `/api/ctf/predefense/${state.runId}`);
        const value = read?.data;
        const keys = ['version','state','runId','admissionId','blockedOperationId','decisionId','currentCompletion'];
        const known = ['not_found','in_progress','outcome_indeterminate','outcome_stored','admission_pending','blocked_ready_to_enqueue','blocked_pending','blocked_publishable','guardian_not_started_or_unknown','proposal_staged','decision_available','recovery_required'];
        if (read.status !== 200 || !value || Object.keys(value).length !== keys.length || Object.keys(value).some(k => !keys.includes(k))
          || value.version !== 1 || value.runId !== state.runId || value.currentCompletion !== false || !known.includes(value.state)
          || !['admissionId','blockedOperationId','decisionId'].every(k => value[k] === null || typeof value[k] === 'string' && UUID.test(value[k]))
          || (value.state === 'not_found' ? value.admissionId !== null || value.blockedOperationId !== null : !value.admissionId || !value.blockedOperationId)
          || (value.state === 'decision_available' ? !value.decisionId : value.decisionId !== null)) throw recoveryNeeded(null, 'Recovery reference changed; no result was accepted.');
        if (value.state === 'decision_available') { state.decisionId = value.decisionId; continue; }
        if (value.state === 'proposal_staged') { state.admissionId = value.admissionId; continue; }
        if (value.state === 'blocked_publishable') {
          response = await call('get', `/api/ctf/blocked-publications/${state.runId}`);
          if (response?.status !== 200 || response.data?.blocked !== true || response.data?.success !== false
            || !Number.isInteger(response.data?.attemptNumber) || response.data.attemptNumber < 1
            || typeof response.data?.reason !== 'string') throw recoveryNeeded(state, 'Current blocked result is not available. Check status later; no new attempt was sent.');
        } else if (['outcome_stored','admission_pending','blocked_ready_to_enqueue','blocked_pending'].includes(value.state)) {
          if (explicitResume !== true || resumeSent) throw recoveryNeeded(state, 'Deterministic recovery is pending. Check status to resume stored work; no model request will be repeated.');
          resumeSent = true;
          try {
            const resumed = await call('post', `/api/ctf/predefense/${state.runId}/resume`);
            // A resume response is never a published attempt. Re-read its bound
            // state before selecting the separately authorized publication route.
            if (![200,202].includes(resumed?.status)) throw recoveryNeeded(state);
          } catch (error) {
            if (isCtfRecoveryCancelled(error) || [401,403,404,423].includes(error?.response?.status)) throw error;
            throw recoveryNeeded(state, 'Deterministic recovery outcome is unknown. Check status again; the original attempt was not repeated.');
          }
          continue;
        } else throw recoveryNeeded(state, 'This attempt needs server recovery. No model request will be repeated.');
      } else {
        response = await call('get', `/api/ctf/decisions/${state.admissionId}`);
        const body = response?.data || {};
        if (body.admissionId !== state.admissionId) throw recoveryNeeded(null, 'Recovery reference changed; no result was accepted.');
        if (UUID.test(body.decisionId || '') && ['historical_receipt', 'authorized_receipt'].includes(body.state)) {
          state.decisionId = body.decisionId; continue;
        }
        if (body.state === 'proposal_staged' && !state.authorizationSent) {
          state.authorizationSent = true; // Also retained across an uncertain POST response or a later explicit check.
          try { await call('post', `/api/ctf/decisions/${state.admissionId}/authorize`); }
          catch (error) {
            if (isCtfRecoveryCancelled(error) || [401, 403, 404, 409, 423].includes(error?.response?.status)) throw error;
            throw recoveryNeeded(state, 'Proposal authorization outcome is unknown. Check status; the original attempt will not be repeated.');
          }
          continue; // Even an authorization receipt is not current publication.
        }
        if (!['proposal_staged', 'authorization_uncertain'].includes(body.state)) throw recoveryNeeded(null, 'This attempt needs server recovery. No model request will be repeated.');
        response = { status: 202 };
      }
    } catch (error) {
      if (error?.code === 'CTF_RECOVERY_NEEDED' || isCtfRecoveryCancelled(error)) throw error;
      if ([401, 403, 404, 423].includes(error?.response?.status)) throw error;
      if (error?.response?.status === 503 && state.decisionId && error.response.data?.judgment?.verdict === 'unavailable') throw error;
      throw recoveryNeeded(state, 'Current result is unavailable. Check status later; no new attempt was sent.');
    }
    assertCurrent();
    if (response?.status !== 202) {
      if (response?.data?.pending === true || response?.data?.currentCompletion === false) throw recoveryNeeded(state);
      return response;
    }
    await pause(Math.min(3000, requests * 1000, Math.max(1, windowMs - (Date.now() - started))));
  }
}
