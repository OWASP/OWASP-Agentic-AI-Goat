import { createCtfRecoveryState, resolveCtfRecovery } from './ctfRecovery';
const operationId = '11111111-1111-4111-8111-111111111111';
const admissionId = '22222222-2222-4222-8222-222222222222';
const decisionId = '33333333-3333-4333-8333-333333333333';
const headers = { Authorization: 'Bearer original-session' };
const state = (kind, data) => createCtfRecoveryState(kind, { data });
const predefense = (runId, stateName = 'blocked_publishable') => ({ status: 200, data: { version: 1, state: stateName, runId, admissionId, blockedOperationId: operationId, decisionId: null, currentCompletion: false } });
const recover = (client, value, options = {}) => resolveCtfRecovery({ client, state: value, headers, ...options });
beforeEach(() => jest.useFakeTimers());
afterEach(() => jest.useRealTimers());
test('lifecycle202 polls current result, no mutation replay', async () => {
 const client = { get: jest.fn().mockResolvedValueOnce({ status: 202 }).mockResolvedValueOnce({ status: 200, data: { success: true } }), post: jest.fn() };
 const pending = recover(client, state('operation', { operationId }));
 await jest.advanceTimersByTimeAsync(1000);
 await expect(pending).resolves.toMatchObject({ data: { success: true } });
 expect(client.post).not.toHaveBeenCalled(); expect(client.get).toHaveBeenCalledTimes(2);
});
test('proposal authorization then historical receipt needs current publication', async () => {
 const client = { get: jest.fn().mockResolvedValueOnce({ data: { admissionId, state: 'proposal_staged' } }).mockResolvedValueOnce({ data: { admissionId, state: 'historical_receipt', decisionId, currentCompletion: false } }).mockResolvedValueOnce({ status: 200, data: { success: true, aiResponse: 'current' } }), post: jest.fn().mockResolvedValue({ data: { state: 'authorized_receipt', decisionId } }) };
 expect((await recover(client, state('attempt', { admissionId }))).data.aiResponse).toBe('current');
 expect(client.post).toHaveBeenCalledTimes(1); expect(client.post).toHaveBeenCalledWith(`/api/ctf/decisions/${admissionId}/authorize`, {}, expect.objectContaining({ headers }));
 expect(client.get.mock.calls.at(-1)[0]).toBe(`/api/ctf/publications/${decisionId}`);
});
test('uncertain authorization retains sent marker across explicit later check', async () => {
 const value = state('attempt', { admissionId });
 const client = { get: jest.fn().mockResolvedValue({ data: { admissionId, state: 'proposal_staged' } }), post: jest.fn().mockRejectedValue(new Error('lost')) };
 await expect(recover(client, value)).rejects.toMatchObject({ code: 'CTF_RECOVERY_NEEDED' });
 const pending = recover(client, value, { maxRequests: 1 });
 const rejected = expect(pending).rejects.toMatchObject({ code: 'CTF_RECOVERY_NEEDED' });
 await jest.advanceTimersByTimeAsync(1000); await rejected;
 expect(client.post).toHaveBeenCalledTimes(1);
});
test.each([401,403,404,423])('denial%s terminates without retry', async status => {
 const error = { response: { status } }, client = { get: jest.fn().mockRejectedValue(error) };
 await expect(recover(client, state('attempt', { decisionId }))).rejects.toBe(error); expect(client.get).toHaveBeenCalledTimes(1);
});
test('final guardian503 retained; generic503 not polled', async () => {
 const final = { response: { status: 503, data: { attemptNumber: 2, judgment: { verdict: 'unavailable' } } } };
 const client = { get: jest.fn().mockRejectedValueOnce(final).mockRejectedValueOnce({ response: { status: 503 } }) };
 await expect(recover(client, state('attempt', { decisionId }))).rejects.toBe(final);
 await expect(recover(client, state('attempt', { decisionId }))).rejects.toMatchObject({ code: 'CTF_RECOVERY_NEEDED' }); expect(client.get).toHaveBeenCalledTimes(2);
});
test('unsupported predefense operation reference cannot yield attempt completion', async () => {
 const client = { get: jest.fn() };
 await expect(recover(client, state('attempt', { operationId }))).rejects.toMatchObject({ code: 'CTF_RECOVERY_NEEDED' }); expect(client.get).not.toHaveBeenCalled();
});
test('navigation abort and wrong session stop late requests', async () => {
 const controller = new AbortController(), client = { get: jest.fn(() => new Promise(() => {})) };
 const pending = recover(client, state('operation', { operationId }), { signal: controller.signal }); controller.abort();
 await expect(pending).rejects.toMatchObject({ name: 'AbortError' }); expect(client.get.mock.calls[0][1].signal.aborted).toBe(true);
 await expect(recover(client, state('operation', { operationId }), { isCurrent: () => false })).rejects.toMatchObject({ name: 'AbortError' }); expect(client.get).toHaveBeenCalledTimes(1);
});
test('deadline aborts actual request, snapshots header and ignores late success', async () => {
 let finish; const original = { Authorization: 'Bearer original' };
 const client = { get: jest.fn(() => new Promise(resolve => { finish = resolve; })) };
 const pending = recover(client, state('operation', { operationId }), { windowMs: 50, headers: original });
 original.Authorization = 'Bearer changed';
 const rejected = expect(pending).rejects.toMatchObject({ code: 'CTF_RECOVERY_NEEDED' });
 await jest.advanceTimersByTimeAsync(50); await rejected;
 expect(client.get.mock.calls[0][1].signal.aborted).toBe(true); expect(client.get.mock.calls[0][1].headers.Authorization).toBe('Bearer original');
 finish({ status: 200, data: { success: true } }); await Promise.resolve();
 expect(client.get).toHaveBeenCalledTimes(1);
});

test('run-only recovery accepts only current200 blocked response and never POSTs', async () => {
 const runId = '44444444-4444-4444-8444-444444444444';
 const value = state('attempt', { runId, operationId });
 const response = { status: 200, data: { blocked: true, success: false, reason: 'Input blocked', attemptNumber: 2 } };
 const client = { get: jest.fn().mockResolvedValueOnce(predefense(runId)).mockResolvedValue(response), post: jest.fn() };
 await expect(recover(client, value)).resolves.toBe(response);
 expect(value.operationId).toBeNull(); expect(value.runId).toBe(runId);
 expect(client.get).toHaveBeenCalledWith(`/api/ctf/blocked-publications/${runId}`, expect.objectContaining({ headers }));
 expect(client.post).not.toHaveBeenCalled();
});
test.each([409,503])('blocked publication%s stays explicit recovery-needed without polling or POST', async status => {
 const runId = '44444444-4444-4444-8444-444444444444';
 const client = { get: jest.fn().mockRejectedValue({ response: { status } }), post: jest.fn() };
 await expect(recover(client, state('attempt', { runId }))).rejects.toMatchObject({ code: 'CTF_RECOVERY_NEEDED', recovery: { runId } });
 expect(client.get).toHaveBeenCalledTimes(1); expect(client.post).not.toHaveBeenCalled();
});
test.each([401,403,404])('blocked publication denial%s terminates original-session recovery', async status => {
 const error = { response: { status } }, client = { get: jest.fn().mockRejectedValue(error), post: jest.fn() };
 await expect(recover(client, state('attempt', { runId: decisionId }))).rejects.toBe(error);
 expect(client.get).toHaveBeenCalledTimes(1); expect(client.post).not.toHaveBeenCalled();
});
test.each([{ status: 202, data: { blocked: true, success: false, reason: 'pending', attemptNumber: 1 } }, { status: 200, data: { success: true } }, { status: 200, data: { blocked: true, success: false, reason: 'bad', attemptNumber: 0 } }])('blocked recovery rejects acceptance or malformed completion', async response => {
 const client = { get: jest.fn().mockResolvedValueOnce(predefense(decisionId)).mockResolvedValue(response), post: jest.fn() };
 await expect(recover(client, state('attempt', { runId: decisionId }))).rejects.toMatchObject({ code: 'CTF_RECOVERY_NEEDED' });
 expect(client.post).not.toHaveBeenCalled();
});
test('admission and decision references retain precedence over run ID; invalid run is not queryable', async () => {
 const client = { get: jest.fn().mockResolvedValue({ status: 200, data: { success: false } }), post: jest.fn() };
 await recover(client, state('attempt', { runId: operationId, admissionId, decisionId }));
 expect(client.get.mock.calls[0][0]).toBe(`/api/ctf/publications/${decisionId}`);
 client.get.mockResolvedValue({ status: 200, data: { admissionId, state: 'claimed_without_proposal' } });
 await expect(recover(client, state('attempt', { runId: operationId, admissionId }))).rejects.toMatchObject({ code: 'CTF_RECOVERY_NEEDED' });
 expect(client.get.mock.calls[1][0]).toBe(`/api/ctf/decisions/${admissionId}`);
 await expect(recover(client, state('attempt', { runId: '../forged', operationId }))).rejects.toMatchObject({ code: 'CTF_RECOVERY_NEEDED' });
 expect(client.get).toHaveBeenCalledTimes(2); expect(client.post).not.toHaveBeenCalled();
});

test('automatic predefense read cannot resume, explicit check posts once then requires current publication', async () => {
 const value=state('attempt',{runId:operationId});const client={get:jest.fn().mockResolvedValue(predefense(operationId,'outcome_stored')),post:jest.fn().mockResolvedValue({status:202})};
 await expect(recover(client,value)).rejects.toMatchObject({code:'CTF_RECOVERY_NEEDED'});expect(client.post).not.toHaveBeenCalled();
 client.get.mockReset().mockResolvedValueOnce(predefense(operationId,'outcome_stored')).mockResolvedValueOnce(predefense(operationId)).mockResolvedValueOnce({status:200,data:{blocked:true,success:false,reason:'blocked',attemptNumber:1}});
 await expect(recover(client,value,{explicitResume:true})).resolves.toMatchObject({data:{blocked:true}});expect(client.post).toHaveBeenCalledTimes(1);expect(client.post).toHaveBeenCalledWith(`/api/ctf/predefense/${operationId}/resume`,{},expect.objectContaining({headers}));
});
test('uncertain resume is not retried implicitly and wrong current references never publish', async () => {
 const value=state('attempt',{runId:operationId}),client={get:jest.fn().mockResolvedValue(predefense(operationId,'outcome_stored')),post:jest.fn().mockRejectedValue(Error('lost response'))};
 await expect(recover(client,value,{explicitResume:true})).rejects.toMatchObject({code:'CTF_RECOVERY_NEEDED'});expect(client.post).toHaveBeenCalledTimes(1);
 await expect(recover(client,value)).rejects.toMatchObject({code:'CTF_RECOVERY_NEEDED'});expect(client.post).toHaveBeenCalledTimes(1);
 client.get.mockResolvedValue(predefense(decisionId));await expect(recover(client,value,{explicitResume:true})).rejects.toMatchObject({code:'CTF_RECOVERY_NEEDED',recovery:null});expect(client.post).toHaveBeenCalledTimes(1);
});
test.each(['outcome_indeterminate','guardian_not_started_or_unknown','in_progress','recovery_required'])('state %s cannot trigger a resume or infer a result', async name=>{
 const client={get:jest.fn().mockResolvedValue(predefense(operationId,name)),post:jest.fn()};await expect(recover(client,state('attempt',{runId:operationId}),{explicitResume:true})).rejects.toMatchObject({code:'CTF_RECOVERY_NEEDED'});expect(client.post).not.toHaveBeenCalled();
});
