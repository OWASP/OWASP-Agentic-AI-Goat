import { compileOperation } from './operations.mjs';

const sessionId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const requestId = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const choiceId = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';

test('merchant product details selection is closed and unavailable to admin chat', () => {
  const body = { sessionId, requestId, message: 'Show my selected product details.',
    selection: { choiceId, intent: 'product_details' } };
  expect(compileOperation('agent.merchant.assistant.chat', { body }).body).toEqual(body);
  expect(() => compileOperation('agent.admin.assistant.chat', { body })).toThrow();
  for (const selection of [
    { choiceId, intent: 'product_details', productId: 7 },
    { choiceId, intent: 'product_details', quantity: 1 },
    { choiceId, intent: 'product_detail' },
  ]) expect(() => compileOperation('agent.merchant.assistant.chat', {
    body: { ...body, selection },
  })).toThrow();
});

test('merchant manual search selection carries only its current opaque product choice', () => {
  const body = { sessionId, requestId, message: 'How do I replace the battery?',
    selection: { choiceId, intent: 'manual_search' } };
  expect(compileOperation('agent.merchant.assistant.chat', { body }).body).toEqual(body);
  expect(() => compileOperation('agent.admin.assistant.chat', { body })).toThrow();
  for (const selection of [
    { choiceId, intent: 'manual_search', productId: 7 },
    { choiceId, intent: 'manual_search', query: body.message },
    { choiceId, intent: 'manual_search', manualId: 1 },
  ]) expect(() => compileOperation('agent.merchant.assistant.chat', {
    body: { ...body, selection },
  })).toThrow();
  for (const message of [' ', 'a'.repeat(4097), 'read\0manual'])
    expect(() => compileOperation('agent.merchant.assistant.chat', {
      body: { ...body, message },
    })).toThrow();
});

test('merchant mailbox and message selections carry only an opaque choice', () => {
  for (const intent of ['mail_list', 'mail_detail', 'mail_send', 'mail_reply']) {
    const body = { sessionId, requestId, message: 'Show saved mail.',
      selection: { choiceId, intent } };
    expect(compileOperation('agent.merchant.assistant.chat', { body }).body).toEqual(body);
    expect(() => compileOperation('agent.admin.assistant.chat', { body })).toThrow();
    for (const selection of [
      { choiceId, intent, userId: 7 },
      { choiceId, intent, messageId: 9 },
      { choiceId, intent, recipient: 'merchant@example.test' },
    ]) expect(() => compileOperation('agent.merchant.assistant.chat', {
      body: { ...body, selection },
    })).toThrow();
  }
  expect(compileOperation('agent.merchant.assistant.mailConfirm', { body: {
    sessionId, requestId, proposalId: choiceId,
  } }).body).toEqual({ sessionId, requestId, proposalId: choiceId });
  expect(compileOperation('agent.merchant.assistant.mailOperation', { params: {
    sessionId, requestId, operationId: choiceId,
  } }).path).toBe(`/api/secureshop/agents/merchant/assistant/mail/operations/${sessionId}/${requestId}/${choiceId}`);
  expect(() => compileOperation('agent.merchant.assistant.mailConfirm', { body: {
    sessionId, requestId, proposalId: choiceId, to: 'victim@example.test',
  } })).toThrow();
});

test('merchant older mail continues only the saved source request without a mailbox id or offset', () => {
  const body = { sessionId, requestId, message: 'Show older mail',
    mailContinuation: { intent: 'mail_next', sourceRequestId: choiceId } };
  expect(compileOperation('agent.merchant.assistant.chat', { body }).body).toEqual(body);
  for (const changed of [
    { ...body, selection: { choiceId, intent: 'mail_list' } },
    { ...body, orderContinuation: { intent: 'orders_next', sourceRequestId: choiceId } },
    { ...body, mailContinuation: { ...body.mailContinuation, offset: 5 } },
    { ...body, mailContinuation: { intent: 'mail_next', sourceRequestId: 9 } },
  ]) expect(() => compileOperation('agent.merchant.assistant.chat', { body: changed })).toThrow();
  expect(() => compileOperation('agent.admin.assistant.chat', { body })).toThrow();
});

test('merchant pricing comparison selection and v3 request carry only the exact supported URL', () => {
  const competitorUrl='http://competitor.example/product?name=Practice%20laptop';
  const chat={sessionId,requestId,message:'Compare my selected product with this competitor URL.',
    selection:{choiceId,intent:'pricing_compare',competitorUrl}};
  expect(compileOperation('agent.merchant.assistant.chat',{body:chat}).body).toEqual(chat);
  for(const selection of [{...chat.selection,productId:7},
    {...chat.selection,competitorUrl:'https://competitor.example/product'},
    {...chat.selection,competitorUrl:'http://name:password@competitor.example/'},
    {...chat.selection,competitorUrl:'http://competitor.example/#fragment'},
    {choiceId,intent:'pricing_compare'}])
    expect(()=>compileOperation('agent.merchant.assistant.chat',{body:{...chat,selection}})).toThrow();
  expect(()=>compileOperation('agent.admin.assistant.chat',{body:chat})).toThrow();
  const run={operationId:requestId,productId:7,message:'Compare my product with this URL.',competitorUrl};
  expect(compileOperation('merchant.pricing.run',{body:run}).body).toEqual(run);
  expect(()=>compileOperation('merchant.pricing.run',{body:{...run,
    experiment:{strategy:'premium',durationDays:7}}})).toThrow();
});

test('merchant older orders continuation is a closed source turn reference', () => {
  const body = { sessionId, requestId, message: 'Show older orders',
    orderContinuation: { intent: 'orders_next', sourceRequestId: choiceId } };
  expect(compileOperation('agent.merchant.assistant.chat', { body }).body).toEqual(body);
  for (const invalid of [
    { ...body, selection: { choiceId } },
    { ...body, orderContinuation: { ...body.orderContinuation, cursor: 'forged' } },
    { ...body, orderContinuation: { intent: 'orders_next', sourceRequestId: 7 } },
    { ...body, orderContinuation: { intent: 'orders_next', sourceRequestId: [choiceId] } },
    { ...body, message: 'Find orders' },
  ]) expect(() => compileOperation('agent.merchant.assistant.chat', { body: invalid })).toThrow();
  expect(() => compileOperation('agent.admin.assistant.chat', { body })).toThrow();
});

test('admin MCP read and retire choices have a closed selection envelope', () => {
  for (const intent of ['mcp_detail', 'mcp_retire']) {
    const operation = compileOperation('agent.admin.assistant.chat', { body: {
      sessionId, requestId, message: 'Review this registered server.',
      selection: { choiceId, intent },
    } });
    expect(operation.body.selection).toEqual({ choiceId, intent });
  }
  for (const selection of [{ choiceId, intent: 'mcp_retire', name: 'forged' },
    { choiceId, intent: 'mcp_register' }, { choiceId, intent: 'mcp_detail', quantity: 1 }]) {
    expect(() => compileOperation('agent.admin.assistant.chat', { body: {
      sessionId, requestId, message: 'Review this registered server.', selection,
    } })).toThrow();
  }
  expect(() => compileOperation('agent.merchant.assistant.chat', { body: {
    sessionId, requestId, message: 'Review', selection: { choiceId, intent: 'mcp_detail' },
  } })).toThrow();
});

test('registry confirmation and registered-runtime recovery use separate exact operations', () => {
  expect(compileOperation('agent.admin.session', { body: {} })).toMatchObject({
    path: '/api/secureshop/agents/admin/session', method: 'POST', body: {},
  });
  expect(compileOperation('agent.admin.assistant.mcpConfirm', { body: {
    sessionId, requestId, proposalId: choiceId,
  } })).toMatchObject({ path: '/api/secureshop/agents/admin/assistant/mcp/confirm', method: 'POST' });
  expect(() => compileOperation('agent.admin.assistant.mcpConfirm', { body: {
    sessionId, requestId, proposalId: choiceId, name: 'forged',
  } })).toThrow();
  expect(compileOperation('agent.admin.chat', { body: {
    sessionId, requestId, message: 'Use my registered tools',
  } })).toMatchObject({ path: '/api/secureshop/agents/admin/chat', method: 'POST' });
  expect(compileOperation('agent.admin.chat.request', { params: { sessionId, requestId } }))
    .toMatchObject({ path: `/api/secureshop/agents/admin/chat/requests/${sessionId}/${requestId}`,
      method: 'GET' });
  expect(compileOperation('agent.admin.chat.assessment', { params: { sessionId, requestId } }))
    .toMatchObject({ path: `/api/secureshop/agents/admin/chat/assessment/${sessionId}/${requestId}`,
      method: 'GET' });
  expect(compileOperation('agent.admin.chat.assessmentRetry', { body: { sessionId, requestId } }))
    .toMatchObject({ path: '/api/secureshop/agents/admin/chat/assessment-retry', method: 'POST',
      body: { sessionId, requestId } });
  expect(() => compileOperation('agent.admin.chat.assessmentRetry', { body: {
    sessionId, requestId, choiceId,
  } })).toThrow();
  expect(compileOperation('agent.admin.assistant.systemRestartAssess', { body: { sessionId, requestId } }))
    .toMatchObject({ path: '/api/secureshop/agents/admin/assistant/system/restart/assess', method: 'POST',
      body: { sessionId, requestId } });
  expect(compileOperation('agent.admin.assistant.systemRestartAssessment', { params: { sessionId, requestId } }))
    .toMatchObject({ path: `/api/secureshop/agents/admin/assistant/system/restart/assessment/${sessionId}/${requestId}`, method: 'GET' });
  expect(() => compileOperation('agent.admin.assistant.systemRestartAssess', { body: { sessionId, requestId, proposalId: choiceId } })).toThrow();
  expect(compileOperation('agent.admin.chat.descriptionAssessment', { params: { sessionId, requestId } }))
    .toMatchObject({ path: `/api/secureshop/agents/admin/chat/description-assessment/${sessionId}/${requestId}`, method: 'GET' });
  expect(compileOperation('agent.admin.chat.descriptionAssess', { body: { sessionId, requestId } }))
    .toMatchObject({ path: '/api/secureshop/agents/admin/chat/description-assessment', method: 'POST',
      body: { sessionId, requestId } });
  expect(() => compileOperation('agent.admin.chat.descriptionAssess', { body: {
    sessionId, requestId, objectiveId: 'ss_mcp_description_instruction_adoption',
  } })).toThrow();
});


test('user lookup grading and recovery carry only the original role request IDs', () => {
  expect(compileOperation('agent.admin.assistant.userLookupAssess', { body: { sessionId, requestId } }))
    .toMatchObject({ method: 'POST', path: '/api/secureshop/agents/admin/assistant/user-lookup/assess', body: { sessionId, requestId } });
  expect(compileOperation('agent.admin.assistant.userLookupAssessment', { params: { sessionId, requestId } }))
    .toMatchObject({ method: 'GET', path: `/api/secureshop/agents/admin/assistant/sessions/${sessionId}/requests/${requestId}/user-lookup/assessment` });
  for (const extra of [{ username: 'student_customer' }, { response: 'forged' }, { objectiveId: 'forged' }])
    expect(() => compileOperation('agent.admin.assistant.userLookupAssess', { body: { sessionId, requestId, ...extra } })).toThrow();
});
