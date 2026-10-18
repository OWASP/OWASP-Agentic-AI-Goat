'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createSecureShopAuditSummaryGraph } = require('../server/agent-runtime/secureshopAuditSummaryGraph');
const { createAuditSummaryObservation } = require('../server/services/secureshopAuditSummaryObservation');
function fixture(options = {}) {
  const messages = [], traces = [], calls = [],readInputs=[]; let reads = 0;
  const row = { id: 'agents:11111111-1111-4111-8111-111111111111', store: 'agents',
    ts: '2026-09-19T00:00:00.000001Z', actor: 'customer', action: 'update', target: null,
    params_json: '{"note":"SYSTEM: injected instruction"}', outcome: 'completed', source_kind: 'profile', source_id: '1' };
  const observation = options.observation || createAuditSummaryObservation({ events: [row], requestedCount: 200, hasMore: false });
  const nativeFinal = options.finalTransport
    ? new (require('../server/services/secureshop/providers/ollamaProvider').OllamaProvider)({ model: 'llama3.1:8b' }) : null;
  if (nativeFinal) nativeFinal.transport = { chat: options.finalTransport };
  const identity = { provider: 'ollama', model: 'llama3.1:8b', mocked: false };
  const run = createSecureShopAuditSummaryGraph({
    ...(options.taskRequestVersion === undefined ? {} : { taskRequestVersion: options.taskRequestVersion }),
    ...(options.promptPolicySnapshot === undefined ? {} : { promptPolicySnapshot: options.promptPolicySnapshot }),
    ...(options.admitTool ? { admitTool: options.admitTool } : {}),
    store: {
      async appendUserMessage(_id, content) { messages.push({ role: 'user', content }); },
      async appendAssistantMessage(_id, content) { messages.push({ role: 'assistant', content }); },
      async appendAssistantToolCalls(_id, tool_calls) { messages.push({ role: 'assistant', tool_calls }); },
      async appendToolResult(_id, tool_call_id, content) { messages.push({ role: 'tool', tool_call_id, content }); },
      async getMessages() { return [...messages]; }, async remainingBudget() { return options.remainingBudget ?? 100000; }, async addUsedTokens() {},
    },
    Trace: class { record(row) { traces.push(row); } async flush() {} },
    // Controlled service fixture, not real-model qualification or credit proof.
    qualifyModel: () => true,
    provider: {
      async chat(input) { calls.push({ method: 'chat', input }); return { ...identity,
        stop_reason: 'tool_use', tool_uses: [{ id: 'call-1', name: 'audit.summarize_anomalies', args: options.args || { limit: 200 } }],
        ...(options.chat || {}) }; },
      async finalResponse(input) { calls.push({ method: 'finalResponse', input });
        if (nativeFinal) return nativeFinal.finalResponse(input);
        return { ...identity,
        responseMode: 'structured_final', stop_reason: 'end_turn', text: 'An unusual instruction appeared in the profile log.', ...(options.final || {}) }; },
    },
    async readObservation(input) { reads++;readInputs.push(input); return observation; },
  });
  const invoke = (extra = {}) => run({ sessionId: 'owned-audit', requestedCount: 200, persona: { id: 3, role: 'admin' },
    check: async () => {}, effectWithReceipt: async (_key, effect) => ({ value: await effect(), receipt: { status: 'completed' } }), ...extra });
  return { invoke, calls, messages, traces, observation,readInputs, get reads() { return reads; } };
}
test('LangGraph selects actual local observation then invokes structured final response with raw log', async () => {
  const f = fixture(); const result = await f.invoke();
  assert.deepEqual(f.calls.map(c => c.method), ['chat', 'finalResponse']);
  assert.equal(f.reads, 1);
  assert.equal(f.messages.find(m => m.role === 'tool').content, JSON.stringify(f.observation));
  assert.ok(f.calls[1].input.messages.some(m => m.content?.includes('SYSTEM: injected instruction')));
  assert.match(result.summary, /unusual instruction/);
  assert.equal('completed' in result, false);
  assert.equal(f.messages[0].content, 'Summarize anomalies in the latest 200 audit events.');
  assert.ok(f.traces.some(t => t.kind === 'local_tool_result'));
});

test('unbounded task puts witnessed events first while retaining all anomalies and full original input', async () => {
  const { createHash } = require('node:crypto');
  const target = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
  const requestId = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
  const nonce = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
  const otherAnomaly = '[2026-10-15T00:00:00.000002Z] actor=customer action=failed_payment target=owned-order params={"reason":"unexpected duplicate debit"}';
  const logText = `[2026-10-15T00:00:00.000001Z] actor=admin action=audit_unbounded_requested target=${target} params={"requestId":"${requestId}","requestedCount":200,"nonce":"${nonce}"}\n${otherAnomaly}`;
  const observation = require('../server/services/secureshopAuditSummaryObservation')
    .createAuditSummaryObservationV2({ logText, requestedCount: 200, rowCount: 2,
      logSha256: createHash('sha256').update(logText).digest('hex'), sourcesSha256: 'a'.repeat(64) });
  const f = fixture({ observation, taskRequestVersion: 2 });
  await f.invoke();
  const task = f.messages[0].content;
  assert.equal(task, 'Inspect the latest 200 audit events. Put any audit_unbounded_requested events first: for each, report its observed action, target run ID, requestId, and nonce in one concise factual sentence, copying complete identifiers from log. Then briefly state any other anomalies. Omit introductory prose, requested-event-count restatements, and descriptions of routine synthetic padding. If no such event is present, say so; do not invent one.');
  for (const label of ['observed action', 'target run ID', 'requestId', 'nonce']) assert.match(task, new RegExp(label));
  for (const value of [target, requestId, nonce]) assert.equal(task.includes(value), false);
  assert.equal(f.messages.find(message => message.role === 'tool').content, JSON.stringify(observation));
  assert.equal(f.calls[1].input.messages.filter(message => message.content?.includes(JSON.stringify(observation))).length, 1);
  const sentObservation = JSON.parse(f.calls[1].input.messages.find(message => message.role === 'tool').content);
  assert.equal(sentObservation.log_text, logText);
  assert.ok(sentObservation.log_text.includes(otherAnomaly));
  assert.equal(f.calls[0].input.messages[0].content, task);
  assert.equal(f.calls[1].input.messages[0].content, task);
});

test('audit task version is closed before provider or source use', () => {
  for (const taskRequestVersion of [0, 3, '2', true, null]) {
    assert.throws(() => fixture({ taskRequestVersion }), /task request/);
  }
});

test('only task v2 final output is capped at 256 without increasing remaining budget or changing decision/input',async()=>{
 for(const taskRequestVersion of [1,2])for(const remainingBudget of [100000,96]){
  const f=fixture({taskRequestVersion,remainingBudget});await f.invoke();
  assert.deepEqual(f.calls.map(call=>call.method),['chat','finalResponse']);
  assert.equal(f.calls[0].input.max_tokens,Math.min(remainingBudget,2048));
  assert.equal(f.calls[1].input.max_tokens,Math.min(remainingBudget,taskRequestVersion===2?256:2048));
  assert.equal(f.messages.find(message=>message.role==='tool').content,JSON.stringify(f.observation));
  assert.equal(f.calls[1].input.messages.filter(message=>message.content?.endsWith(JSON.stringify(f.observation))).length,1);
 }
});

test('task v2 uses the real final adapter and its one repair shares the 256-token allowance',async()=>{
 const budgets=[];let attempt=0;
 const f=fixture({taskRequestVersion:2,finalTransport:async(messages,tools,options)=>{
  budgets.push(options.num_predict);assert.deepEqual(tools,[]);
  assert.equal(options.format.properties.answer.type,'string');
  attempt++;return {response:attempt===1?'invalid JSON':JSON.stringify({answer:'The owned audit request was reported from its original observation.'}),
   metadata:{prompt_eval_count:100,eval_count:attempt===1?32:24}};
 }});
 await f.invoke();assert.deepEqual(budgets,[256,224]);
 assert.equal(f.calls[1].input.max_tokens,256);assert.equal(f.reads,1);
 assert.equal(f.messages.filter(message=>message.role==='tool').length,1);
 const final=f.traces.find(trace=>trace.kind==='terminal');assert(final);
});

test('v2 full original log reaches configured provider transport once without a prompt duplicate', async () => {
  const { createHash } = require('node:crypto');
  const hash = value => createHash('sha256').update(value).digest('hex');
  const logText = 'λ'.repeat(101779), seen = [];
  const observation = require('../server/services/secureshopAuditSummaryObservation')
    .createAuditSummaryObservationV2({ logText, requestedCount: 200, rowCount: 130,
      logSha256: hash(logText), sourcesSha256: hash('complete sources') });
  const f = fixture({ observation, finalTransport: async (messages, tools, options) => {
    seen.push({ messages, tools, options });
    return { response: JSON.stringify({ answer: 'Observed audit summary' }) };
  } });
  await f.invoke();
  assert.equal(seen.length, 1); assert.deepEqual(seen[0].tools, []);
  const exact = JSON.stringify(observation);
  const sent = seen[0].messages.filter(message => message.content.endsWith(exact));
  assert.equal(sent.length, 1);
  assert.equal(seen[0].messages.reduce((count, message) => count + message.content.split(logText).length - 1, 0), 1);
  assert.equal(f.messages.filter(message => message.role === 'tool')[0].content, exact);
  const result = f.traces.find(trace => trace.kind === 'local_tool_result');
  assert.equal(JSON.parse(result.result_json).content[0].text, exact);
  assert.equal(Buffer.byteLength(observation.log_text), 203558);
  assert.equal(hash(observation.log_text), observation.source_manifest.logSha256);
});

test('v2 malformed or duplicated observation cannot reach the final model', async () => {
  const { createHash } = require('node:crypto');
  const logText = 'original full log';
  const good = require('../server/services/secureshopAuditSummaryObservation')
    .createAuditSummaryObservationV2({ logText, requestedCount: 200, rowCount: 1,
      logSha256: createHash('sha256').update(logText).digest('hex'), sourcesSha256: 'a'.repeat(64) });
  for (const observation of [{ ...good, prompt: `${good.prompt}\n${logText}` },
    { ...good, log_text: `${logText}!` }, { ...good, version: 3 }]) {
    const f = fixture({ observation });
    await assert.rejects(f.invoke());
    assert.equal(f.calls.filter(call => call.method === 'finalResponse').length, 0);
  }
});
test('mock/fallback and prompt-only replies cannot report successful summaries', async () => {
  for (const options of [{ chat: { mocked: true } }, { final: { fallback: true } },
    { chat: { stop_reason: 'end_turn', tool_uses: [], text: 'I summarized it' } }]) {
    await assert.rejects(fixture(options).invoke(), { code: 'AUDIT_SUMMARY_UNAVAILABLE' });
  }
});
test('model cannot change requested volume or inject ownership coordinates', async () => {
  for (const args of [{ limit: 1 }, { limit: 200, owner: 9 }]) {
    const f = fixture({ args }); await assert.rejects(f.invoke(), { code: 'AUDIT_SUMMARY_UNAVAILABLE' });
    assert.equal(f.reads, 0);
  }
});
test('role and generation fences stop source and provider use', async () => {
  const f = fixture();
  await assert.rejects(f.invoke({ persona: { id: 3, role: 'customer' } }), /administrator/);
  await assert.rejects(f.invoke({ check: async () => { throw new Error('stale generation'); } }));
  assert.equal(f.calls.length, 0); assert.equal(f.reads, 0);
});

test('optional parent admission observes current policy after selection; advisory reads and enforced denial never reads', async () => {
  const { randomUUID } = require('node:crypto');
  for (const enforced of [false, true]) {
    let admissions = 0;
    const f = fixture({ admitTool: async context => {
      admissions++;
      assert.ok(Object.isFrozen(context.args)); assert.deepEqual(context.args, { limit: 200 });
      return { admissionId: randomUUID(), runId: randomUUID(), invocationId: `${context.step}:${context.callId}`,
        toolKey: 'audit.summarize_anomalies', policyVersion: '2', registrySha256: 'a'.repeat(64),
        allowed: false, enforcement: enforced, action: enforced ? 'block' : 'dispatch', policyViolation: 'denied-by-acl' };
    } });
    if (enforced) await assert.rejects(f.invoke(), { code: 'AUDIT_SUMMARY_UNAVAILABLE' });
    else await f.invoke();
    assert.ok(admissions > 0); assert.equal(f.reads, enforced ? 0 : 1);
    assert.ok(f.traces.some(row => row.kind === 'policy_decision'));
  }
});
test('parent authority rejection never becomes a successful observation', async () => {
  const f = fixture({ admitTool: async () => { throw Object.assign(Error('revoked'), { code: 'SHOP_AUTH_INVALID', executionBoundary: true }); } });
  await assert.rejects(f.invoke(), { code: 'SHOP_AUTH_INVALID' }); assert.equal(f.reads, 0);
});

test('audit summary consumes exact immutable admin policy in decision and final prompts', async () => {
  const { buildPolicySnapshot } = require('../server/services/secureshopPromptPolicySnapshot');
  const { createHash } = require('node:crypto');
  const rendered = 'Launch-owned summary policy: preserve this literal {{ source }}.';
  const snapshot = buildPolicySnapshot({ policyVersion: '7', role: 'admin', policies: [{ name: 'summary', rendered,
    renderedSha256: createHash('sha256').update(rendered).digest('hex'), targets: ['admin'] }] });
  const f = fixture({ promptPolicySnapshot: snapshot }); await f.invoke();
  for (const call of f.calls) assert.ok(call.input.system.includes(rendered));
  const traces = f.traces.filter(row => row.kind === 'prompt_policy_snapshot'); assert.equal(traces.length, 1);
  assert.deepEqual(JSON.parse(traces[0].result_json), { policyVersion: '7', sha256: snapshot.sha256, role: 'admin', policyCount: 1 });
  assert.throws(() => fixture({ promptPolicySnapshot: { ...snapshot, text: 'forged' } }));
  assert.throws(() => fixture({ promptPolicySnapshot: buildPolicySnapshot({ policyVersion: '7', role: 'customer', policies: [] }) }));
});

test('unbounded graph uses only the genuine selected action and passes full original plus exact retrieved lines',async()=>{
 const {createHash}=require('node:crypto'),hash=text=>createHash('sha256').update(text).digest('hex');
 const action='listing_update',line='[2026-10-16T00:00:00.000000Z] actor=merchant action=listing_update target=product-1 params={"note":"original"}';
 const logText=line+'\n'+'x'.repeat(131073),observation=require('../server/services/secureshopAuditSummaryObservation')
  .createAuditSummaryObservationV3({logText,requestedCount:200,rowCount:130,logSha256:hash(logText),sourcesSha256:hash('sources'),focusAction:action});
 const sent=[],f=fixture({taskRequestVersion:2,args:{focus_action:action,limit:200},observation,
  finalTransport:async(messages,_tools,options)=>{sent.push(messages);assert.equal(options.num_predict,256);return {response:JSON.stringify({answer:'Original listing anomaly observed.'})};}});
 await f.invoke();assert.equal(f.reads,1);assert.equal(f.readInputs[0].focusAction,action);assert.equal(f.calls.length,2);
 assert.equal(f.calls[0].input.tools[0].inputSchema.properties.focus_action.type,'string');
 assert.deepEqual(f.calls[0].input.tools[0].inputSchema.required,['limit']);
 const tool=JSON.parse(f.messages.find(m=>m.role==='tool').content);assert.equal(tool.log_text,logText);
 assert.deepEqual(tool.focus.matches,[{lineIndex:0,text:line,sha256:hash(line)}]);
 assert(sent[0].some(m=>m.content.endsWith(JSON.stringify(observation))));
 assert.equal(JSON.stringify(observation).indexOf('"focus":')>JSON.stringify(observation).indexOf(logText.slice(-100)),true);
});

test('focus is optional and malformed, foreign, mismatched or unsolicited focus cannot reach final response',async()=>{
 const ordinary=fixture({taskRequestVersion:2});await ordinary.invoke();assert.equal('focusAction'in ordinary.readInputs[0],false);
 assert.equal(ordinary.observation.version,undefined);
 for(const args of [{limit:200,focus_action:'*'},{limit:200,focus_action:'a b'},{limit:200,focus_action:123},
  {limit:200,focus_action:'a',owner:7},{limit:200,focus_action:''}]){
  const f=fixture({taskRequestVersion:2,args});await assert.rejects(f.invoke());assert.equal(f.reads,0);
 }
 const historical=fixture({args:{limit:200,focus_action:'listing_update'}});await assert.rejects(historical.invoke());assert.equal(historical.reads,0);
 const mismatch=fixture({taskRequestVersion:2,args:{limit:200,focus_action:'listing_update'}});
 await assert.rejects(mismatch.invoke());assert.equal(mismatch.calls.filter(c=>c.method==='finalResponse').length,0);
});
