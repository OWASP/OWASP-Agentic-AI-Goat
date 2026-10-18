import { compileOperation, matchOperationRequest } from './operations.mjs';
import { validateShopSnapshot } from './stateStore.mjs';
import { SHOP_AUDIT_JOB_KEY, SHOP_TOKEN_KEY, SHOP_CART_KEY } from '../utils/shopStorage.mjs';

const id = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';

test('audit and System full-result bridge reads require the saved turn and operation IDs', () => {
  for (const [name, leaf] of [
    ['agent.admin.assistant.auditOperation', 'audit'],
    ['agent.admin.assistant.systemConfigOperation', 'system/config'],
  ]) {
    const params = { sessionId: id, requestId: id, operationId: id };
    const path = `/api/secureshop/agents/admin/assistant/${leaf}/operations/${id}/${id}/${id}`;
    expect(compileOperation(name, { params })).toEqual(expect.objectContaining({ path, method: 'GET' }));
    expect(matchOperationRequest({ pathname: path, method: 'GET' }).name).toBe(name);
    expect(() => compileOperation(name, { params: { operationId: id } })).toThrow();
    expect(() => compileOperation(name, { params, body: { message: 'rerun' } })).toThrow();
  }
});

test('saved System assessment check is an exact admin-only POST with source IDs', () => {
  const body = { sessionId: id, requestId: id };
  const path = '/api/secureshop/agents/admin/assistant/system/config/assessment-retry';
  expect(compileOperation('agent.admin.assistant.systemConfigAssessmentRetry', { body }))
    .toEqual(expect.objectContaining({ method: 'POST', path, body }));
  expect(matchOperationRequest({ pathname: path, method: 'POST', body }).name)
    .toBe('agent.admin.assistant.systemConfigAssessmentRetry');
  expect(() => compileOperation('agent.admin.assistant.systemConfigAssessmentRetry',
    { body: { ...body, operationId: id } })).toThrow();
  expect(() => compileOperation('agent.admin.assistant.systemConfigAssessmentRetry',
    { body: { sessionId: id } })).toThrow();
  expect(() => matchOperationRequest({ pathname: path, method: 'GET' })).toThrow();
  expect(() => compileOperation('agent.merchant.assistant.systemConfigAssessmentRetry', { body })).toThrow();
});

test('saved policy instruction assessment check is an exact admin-only POST with source IDs', () => {
  const body = { sessionId: id, requestId: id };
  const path = '/api/secureshop/agents/admin/assistant/policy/instruction/assessment-retry';
  expect(compileOperation('agent.admin.assistant.policyInstructionAssessmentRetry', { body }))
    .toEqual(expect.objectContaining({ method: 'POST', path, body }));
  expect(matchOperationRequest({ pathname: path, method: 'POST', body }).name)
    .toBe('agent.admin.assistant.policyInstructionAssessmentRetry');
  expect(() => compileOperation('agent.admin.assistant.policyInstructionAssessmentRetry',
    { body: { ...body, objectiveId: 'ss_policy_instruction' } })).toThrow();
  expect(() => compileOperation('agent.admin.assistant.policyInstructionAssessmentRetry',
    { body: { sessionId: id } })).toThrow();
  expect(() => matchOperationRequest({ pathname: path, method: 'GET' })).toThrow();
  expect(() => compileOperation('agent.merchant.assistant.policyInstructionAssessmentRetry', { body })).toThrow();
});

test('audit job Run and exact protected read use closed source IDs, with no content in saved parent state', () => {
  const body = { sessionId: id, requestId: id, proposalId: id };
  const run = compileOperation('agent.admin.assistant.auditJobRun', { body });
  expect(run.path).toBe('/api/secureshop/agents/admin/assistant/audit/job/run');
  expect(run.body).toEqual(body);
  expect(() => compileOperation('agent.admin.assistant.auditJobRun',
    { body: { ...body, message: 'untrusted SQL' } })).toThrow();
  const params = body;
  const read = compileOperation('agent.admin.assistant.auditJobOperation', { params });
  expect(read).toEqual(expect.objectContaining({ method: 'GET', path:
    `/api/secureshop/agents/admin/assistant/audit/job/operations/${id}/${id}/${id}` }));
  expect(() => compileOperation('agent.admin.assistant.auditJobOperation',
    { params: { sessionId: id, requestId: id } })).toThrow();
  const reference = { version: 1, scopeKey: 'a'.repeat(64), sourceSessionId: id,
    sourceRequestId: id, proposalId: id, jobSessionId: id, jobRequestId: id,
    requestSha256: 'b'.repeat(64) };
  expect(validateShopSnapshot({ [SHOP_TOKEN_KEY]: null, [SHOP_CART_KEY]: null,
    [SHOP_AUDIT_JOB_KEY]: JSON.stringify(reference) })[SHOP_AUDIT_JOB_KEY])
    .toBe(JSON.stringify(reference));
  expect(() => validateShopSnapshot({ [SHOP_TOKEN_KEY]: null, [SHOP_CART_KEY]: null,
    [SHOP_AUDIT_JOB_KEY]: JSON.stringify({ ...reference, input: 'untrusted SQL' }) })).toThrow();
});

test('admin ACL choice intents and confirmation are closed while merchant intent is denied', () => {
  for (const intent of ['acl_allow', 'acl_deny']) {
    const body = { sessionId: id, requestId: id, message: 'Review permission',
      selection: { choiceId: id, intent } };
    expect(compileOperation('agent.admin.assistant.chat', { body }).body).toEqual(body);
    expect(() => compileOperation('agent.merchant.assistant.chat', { body })).toThrow();
  }
  expect(() => compileOperation('agent.admin.assistant.chat', { body: {
    sessionId: id, requestId: id, message: 'Review permission',
    selection: { choiceId: id, intent: 'acl_allow', enabled: true },
  } })).toThrow();
  const confirm = compileOperation('agent.admin.assistant.aclConfirm',
    { body: { sessionId: id, requestId: id, proposalId: id } });
  expect(confirm.path).toBe('/api/secureshop/agents/admin/assistant/acl/confirm');
  expect(() => compileOperation('agent.admin.assistant.aclConfirm', { body: {
    sessionId: id, requestId: id, proposalId: id, allowed: true,
  } })).toThrow();
});


test('audit timing and unbounded workflows compile only their server-selected request shapes', () => {
  const sessionPath = '/api/secureshop/admin/audit/unbounded-session';
  expect(compileOperation('admin.audit.unboundedSession', { body: {} }))
    .toEqual(expect.objectContaining({ method: 'POST', path: sessionPath, body: {} }));
  expect(matchOperationRequest({ pathname: sessionPath, method: 'POST', body: {} }).name)
    .toBe('admin.audit.unboundedSession');
  const summary = { session_id: id, request_id: id, limit: 5000 };
  expect(compileOperation('admin.audit.unboundedSummary', { body: summary }).body).toEqual(summary);
  expect(() => compileOperation('admin.audit.unboundedSummary', { body: { ...summary, objectiveId: 'V36' } })).toThrow();
  const timingPath = '/api/secureshop/admin/audit/timing-run';
  const timing = { sessionId: id, requestId: id, message: 'Inspect the owned timing target.' };
  expect(compileOperation('admin.audit.timingSession', { body: {} }).path)
    .toBe('/api/secureshop/admin/audit/timing-session');
  expect(compileOperation('admin.audit.timingRun', { body: timing }))
    .toEqual(expect.objectContaining({ method: 'POST', path: timingPath, body: timing }));
  expect(matchOperationRequest({ pathname: timingPath, method: 'POST', body: timing }).name)
    .toBe('admin.audit.timingRun');
  expect(() => compileOperation('admin.audit.timingRun', { body: { ...timing, objectiveId: 'V52' } })).toThrow();
});
