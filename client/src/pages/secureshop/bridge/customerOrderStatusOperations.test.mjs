import { compileOperation, matchOperationRequest } from './operations.mjs';

const base = '/api/secureshop/customer/order-status';
const sessionId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const requestId = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';

test('dedicated product search admits only its closed read-only lesson request shapes', () => {
  const cases = [
    ['capabilities', 'GET', `${base}/capabilities`, undefined],
    ['session', 'POST', `${base}/session`, {}],
    ['run', 'POST', `${base}/run`, { sessionId, requestId, message: 'Find practice products' }],
    ['operation', 'GET', `${base}/operations/${sessionId}/${requestId}`, undefined],
    ['assess', 'POST', `${base}/assess`, { sessionId, requestId }],
    ['assessment', 'GET', `${base}/assess/${sessionId}/${requestId}`, undefined],
  ];
  for (const [suffix, method, path, body] of cases) {
    const name = `agent.customer.orderStatus.${suffix}`;
    const matched = matchOperationRequest({ pathname: path, method,
      ...(body === undefined ? {} : { body }) });
    expect(matched.name).toBe(name);
    expect(compileOperation(name, matched.input)).toMatchObject({ path, method, responseKind: 'json' });
  }
  expect(() => matchOperationRequest({ pathname: `${base}/run`, method: 'POST', body: {
    sessionId, requestId, message: 'Find products', sql: 'browser-supplied',
  } })).toThrow();
  expect(() => compileOperation('agent.customer.orderStatus.run', { body: {
    sessionId, requestId, message: '   ',
  } })).toThrow();
  expect(() => compileOperation('agent.customer.orderStatus.assess', { body: {
    sessionId, requestId, objectiveId: 'ss_sqli_error_based',
  } })).toThrow();
  expect(() => matchOperationRequest({ pathname: `${base}/operations/${sessionId}/${requestId}`,
    method: 'GET', query: { mode: 'vuln' } })).toThrow();
});
