import { compileOperation, matchOperationRequest } from './operations.mjs';

const sessionId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const requestId = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const proposalId = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
const ids = { sessionId, requestId, proposalId };
const post = '/api/secureshop/agents/admin/assistant/system/diagnostic/confirm';
const get = `${post}/${sessionId}/${requestId}/${proposalId}`;

test('role diagnostic confirmation bridge accepts only saved IDs and protected GET', () => {
  expect(matchOperationRequest({ pathname: post, method: 'POST', body: ids }).name)
    .toBe('agent.admin.assistant.systemDiagnosticConfirm');
  expect(compileOperation('agent.admin.assistant.systemDiagnosticOperation', { params: ids }))
    .toMatchObject({ path: get, method: 'GET' });
  expect(matchOperationRequest({ pathname: get, method: 'GET' }).name)
    .toBe('agent.admin.assistant.systemDiagnosticOperation');
  for (const extra of [{ cmd_template: 'echo' }, { args: 'payload' }, { mode: 'vuln' },
    { operationId: proposalId }, { scopeKey: 'a'.repeat(64) }]) {
    expect(() => matchOperationRequest({ pathname: post, method: 'POST', body: { ...ids, ...extra } }))
      .toThrow();
  }
  expect(() => matchOperationRequest({ pathname: get, method: 'GET', query: { mode: 'vuln' } }))
    .toThrow();
  expect(() => matchOperationRequest({ pathname: get, method: 'GET', body: ids })).toThrow();
});

test('diagnostic assessment bridge admits only three saved IDs and GET recovery', () => {
  const assess = '/api/secureshop/agents/admin/assistant/system/diagnostic/assess';
  const savedAssessment = `${assess}/${sessionId}/${requestId}/${proposalId}`;
  expect(compileOperation('agent.admin.assistant.systemDiagnosticAssess', { body: ids }))
    .toMatchObject({ path: assess, method: 'POST', body: ids });
  expect(matchOperationRequest({ pathname: assess, method: 'POST', body: ids }).name)
    .toBe('agent.admin.assistant.systemDiagnosticAssess');
  expect(compileOperation('agent.admin.assistant.systemDiagnosticAssessment', { params: ids }))
    .toMatchObject({ path: savedAssessment, method: 'GET' });
  expect(matchOperationRequest({ pathname: savedAssessment, method: 'GET' }).name)
    .toBe('agent.admin.assistant.systemDiagnosticAssessment');
  for (const value of [undefined, null, {}, { sessionId, requestId },
    { ...ids, cmd_template: 'uname' }, { ...ids, operationId: proposalId },
    { ...ids, proposalId: 'not-a-uuid' }]) {
    expect(() => compileOperation('agent.admin.assistant.systemDiagnosticAssess', { body: value }))
      .toThrow();
    expect(() => matchOperationRequest({ pathname: assess, method: 'POST', body: value }))
      .toThrow();
  }
  expect(() => compileOperation('agent.admin.assistant.systemDiagnosticAssessment', {
    params: { ...ids, requestId: 'not-a-uuid' } })).toThrow();
  expect(() => matchOperationRequest({ pathname: savedAssessment, method: 'GET',
    query: { mode: 'vuln' } })).toThrow();
});
