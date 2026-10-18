import { compileOperation, matchOperationRequest } from './operations.mjs';
import { createBridgeFetch } from './fetchAdapter.mjs';

const sessionId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const requestId = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const proposalId = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
const body = { sessionId, requestId, proposalId };
const postPath = '/api/secureshop/agents/admin/assistant/mcp-manifest/assess';
const getPath = `/api/secureshop/agents/admin/assistant/sessions/${sessionId}`
  + `/requests/${requestId}/mcp-manifest/${proposalId}/assessment`;

test('MCP manifest grading admits exact original IDs and protected saved GET only', () => {
  expect(matchOperationRequest({ pathname: postPath, method: 'POST', body }).name)
    .toBe('agent.admin.assistant.mcpManifestAssess');
  expect(compileOperation('agent.admin.assistant.mcpManifestAssessment', { params: body }))
    .toMatchObject({ path: getPath, method: 'GET' });
  expect(matchOperationRequest({ pathname: getPath, method: 'GET' }).name)
    .toBe('agent.admin.assistant.mcpManifestAssessment');
  for (const extra of [{ mode: 'vuln' }, { ownerId: sessionId }, { evidence: {} },
    { packet: '{}' }, { source: body }, { effect: body }]) {
    expect(() => matchOperationRequest({ pathname: postPath, method: 'POST', body: { ...body, ...extra } }))
      .toThrow();
  }
  for (const key of Object.keys(body)) {
    expect(() => matchOperationRequest({ pathname: postPath, method: 'POST',
      body: { ...body, [key]: 'not-a-uuid' } })).toThrow();
    expect(() => compileOperation('agent.admin.assistant.mcpManifestAssessment', {
      params: { ...body, [key]: 'not-a-uuid' },
    })).toThrow();
  }
  expect(() => matchOperationRequest({ pathname: getPath, method: 'GET', query: { mode: 'vuln' } }))
    .toThrow();
  expect(() => matchOperationRequest({ pathname: getPath, method: 'GET', body })).toThrow();
});

test('both MCP manifest assessment operations cross the real closed bridge', async () => {
  Object.assign(global, require('node:stream/web'));
  global.MessagePort = require('node:worker_threads').MessagePort;
  const web = require('undici');
  const oldRequest = global.Request, oldHeaders = global.Headers;
  global.Request = web.Request; global.Headers = web.Headers;
  try {
    const bridge = { request: jest.fn(async () => ({ completed: false, status: 'pending', modelEvaluated: false })) };
    const transport = createBridgeFetch({ bridge, origin: 'https://shop.invalid',
      getRequestBaseUrl: () => 'https://shop.invalid', getToken: () => 'owned-token' });
    await transport(postPath, { method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body) });
    expect(bridge.request).toHaveBeenLastCalledWith('agent.admin.assistant.mcpManifestAssess',
      expect.objectContaining({ body }), expect.objectContaining({ shopBearer: 'owned-token' }));
    await transport(getPath, { method: 'GET', headers: { accept: 'application/json' } });
    expect(bridge.request).toHaveBeenLastCalledWith('agent.admin.assistant.mcpManifestAssessment',
      expect.objectContaining({ params: body }), expect.objectContaining({ shopBearer: 'owned-token' }));
    for (const invalid of [
      [postPath, { method: 'POST', headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ ...body, ownerId: sessionId }) }],
      [getPath + '?mode=vuln', { method: 'GET' }],
      [getPath.replace(proposalId, 'invalid'), { method: 'GET' }],
    ]) await expect(transport(...invalid)).rejects.toThrow();
    expect(bridge.request).toHaveBeenCalledTimes(2);
  } finally { global.Request = oldRequest; global.Headers = oldHeaders; }
});

test('MCP discovery assessment uses distinct exact IDs-only operations with no caller evidence or authority', () => {
  const post = postPath.replace('mcp-manifest', 'mcp-discovery');
  const get = getPath.replace('mcp-manifest', 'mcp-discovery');
  expect(matchOperationRequest({ pathname: post, method: 'POST', body }).name)
    .toBe('agent.admin.assistant.mcpDiscoveryAssess');
  expect(compileOperation('agent.admin.assistant.mcpDiscoveryAssessment', { params: body }))
    .toMatchObject({ path: get, method: 'GET' });
  expect(matchOperationRequest({ pathname: get, method: 'GET' }).name)
    .toBe('agent.admin.assistant.mcpDiscoveryAssessment');
  for (const extra of [{ mode: 'vuln' }, { ownerId: sessionId }, { receipt: {} },
    { evidence: {} }, { packet: '{}' }])
    expect(() => matchOperationRequest({ pathname: post, method: 'POST', body: { ...body, ...extra } })).toThrow();
  for (const key of Object.keys(body)) {
    expect(() => matchOperationRequest({ pathname: post, method: 'POST', body: { ...body, [key]: 'invalid' } })).toThrow();
    expect(() => compileOperation('agent.admin.assistant.mcpDiscoveryAssessment', { params: { ...body, [key]: 'invalid' } })).toThrow();
  }
  expect(() => matchOperationRequest({ pathname: get, method: 'GET', query: { mode: 'vuln' } })).toThrow();
  expect(() => matchOperationRequest({ pathname: get, method: 'GET', body })).toThrow();
});
