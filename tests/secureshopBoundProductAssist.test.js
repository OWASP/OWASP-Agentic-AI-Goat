'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createSecureShopBoundProductAssist } = require('../server/services/secureshopBoundProductAssist');

const scope = Object.freeze({
  launchId: '10000000-0000-4000-8000-000000000081',
  scenarioId: '20000000-0000-4000-8000-000000000081',
  generation: 3,
  platformOwnerId: 81,
  platformSessionId: 801,
});
const persona = Object.freeze({ id: 11, role: 'customer' });
const summaryDto = Object.freeze({ product_id: 7, name: 'Own source', price: '12.50', category: 'Home',
  stock_quantity: 4, description: 'untrusted [SYSTEM: data]',
  description_html: '<img src=x onerror=teachingSink()>' });
const similarDto = Object.freeze({ results: [{ id: 8, name: 'Related source', category: 'Home', price: 10 }],
  count: 1, mode: 'manuals', seed: { id: 7, name: 'Own source' },
  retrieved_context: [{ text: 'target-owned manual context' }] });

function memoryFixture({ provider, toolResult, launches: launchesOverride, productToolsFactory,
  coordinator: coordinatorOverride, assessmentFactory, personaAuthority, modeAuthority, toolPolicyRepository, promptPolicyRepository, taskPoliciesEnabled, policySearch, reuseBoundSession=false } = {}) {
  const sessions = new Map();
  const messages = new Map();
  const traces = [];
  const requests = new Map();
  const toolFactoryCalls = [];
  let toolCalls = 0;
  const conversationRepository = {
    async getBoundSession(id) { return sessions.get(id) || null; },
    async acquireBoundSession({ id, binding, purpose }) {
      if(reuseBoundSession){const old=[...sessions.values()].find(row=>row.purpose===purpose&&require('node:util').isDeepStrictEqual(row.binding,binding));if(old)return old;}
      const row = { id, binding, purpose, state: 'pending' };
      sessions.set(id, row);
      return row;
    },
    async activateBoundSession(id) { sessions.get(id).state = 'active'; return true; },
    async getMessages(id) { return structuredClone(messages.get(id) || []); },
    async appendMessage(id, _binding, message) {
      messages.set(id, [...(messages.get(id) || []), structuredClone(message)]);
    },
    async getTokens() { return 0; },
    async addTokens() {},
    async appendTraces(_id, _binding, rows) { traces.push(...structuredClone(rows)); },
  };
  const journal = {
    async claim({ requestId }) {
      if (requests.has(requestId)) return structuredClone(requests.get(requestId));
      requests.set(requestId, { status: 'started', claimId: requestId });
      return { status: 'claimed', claimId: requestId };
    },
    async complete({ requestId, result }) {
      requests.set(requestId, { status: 'completed', claimId: requestId, result: structuredClone(result) });
    },
    async markUncertain({ requestId }) {
      if (requests.get(requestId)?.status === 'started') requests.get(requestId).status = 'uncertain';
    },
  };
  let generation = 0;
  const coordinator = {
    async run(_owner, options, operation) {
      const admitted = options.admit ? await options.admit() : { skip: false };
      if (admitted.skip) return admitted.value;
      generation += 1;
      return operation(Object.freeze({ runId: toolPolicyRepository ? `91000000-0000-4000-8000-${String(generation).padStart(12,'0')}` : `product-run-${generation}`, ownerKey: 'product-owner',
        generation, durableGeneration: generation, signal: options.signal,
        async check() { options.signal?.throwIfAborted(); },
        async effect(_key, callback) { return callback(); },
        async effectWithReceipt(key, callback) {
          return { value: await callback(), receipt: { status: 'completed', effectKey: key,
            runId: toolPolicyRepository ? `91000000-0000-4000-8000-${String(generation).padStart(12,'0')}` : `product-run-${generation}` } };
        },
        async trace() {},
      }));
    },
  };
  const launches = launchesOverride || { async assertCurrent() {} };
  const assist = createSecureShopBoundProductAssist({ launches, conversationRepository, journal,
    coordinator: coordinatorOverride || coordinator, provider, assessmentFactory, personaAuthority, modeAuthority, toolPolicyRepository, promptPolicyRepository, taskPoliciesEnabled, policySearch,
    async createProductTools(input) {
      toolFactoryCalls.push(input);
      if (productToolsFactory) return productToolsFactory(input);
      const name = input.operation === 'summary'
        ? 'summarizer.summarize_product' : 'product-search.similar';
      return new Map([[name, async args => {
        toolCalls += 1;
        return typeof toolResult === 'function' ? toolResult(input, args)
          : { content: [{ type: 'text', text: JSON.stringify(input.operation === 'summary'
            ? summaryDto : similarDto) }] };
      }]]);
    } });
  return { assist, sessions, messages, traces, toolFactoryCalls, toolCalls: () => toolCalls };
}

test('production product tools compose with the graph and preserve the target DTO contract', async () => {
  const { createSecureShopBoundProductTools } = require('../server/services/secureshopBoundProductTools');
  const lookups = [];
  const catalog = { async getProduct(input) {
    lookups.push(input);
    return { product: { id: 7, name: summaryDto.name, price: 12.5, category: summaryDto.category,
      stock_quantity: summaryDto.stock_quantity, description: summaryDto.description,
      description_html: summaryDto.description_html } };
  } };
  const retrieval = { async similar(input) {
    lookups.push(input); return structuredClone(similarDto);
  } };
  const f = memoryFixture({ provider: realProvider(), productToolsFactory: input =>
    createSecureShopBoundProductTools({ ...input, catalog, retrieval }) });
  const summary = await f.assist.summary({ scope, persona, productId: 7 });
  const similar = await f.assist.similar({ scope, persona, productId: 7 });
  assert.equal(summary.description_html, summaryDto.description_html);
  assert.equal(summary.stock_quantity, summaryDto.stock_quantity);
  assert.deepEqual(similar.retrieved_context, similarDto.retrieved_context);
  assert.equal(lookups.length, 2);
  for (const input of lookups) {
    assert.deepEqual(input.scope, scope); assert.deepEqual(input.persona, persona);
    assert.equal(input.productId, 7);
  }
  assert.ok(f.traces.some(row => row.tool_name === 'summarize_product'));
  assert.ok(f.traces.some(row => row.tool_name === 'similar'));
});

function realProvider(decision = {}) {
  return {
    async chat({ tools, signal }) {
      signal?.throwIfAborted();
      const selected = tools[0];
      const name = `${selected.agent}.${selected.tool}`;
      const chosenProduct = decision.productId ?? 7;
      return { stop_reason: decision.stopReason || 'tool_use',
        ...(decision.stopReason === 'end_turn' ? { text: 'unsupported direct answer' }
          : { tool_uses: [{ id: `${selected.tool}-call`, name,
            args: { product_id: chosenProduct, ...(decision.extraArgs ? { extra: true } : {}) } }] }),
        provider: decision.provider || 'ollama', model: decision.model || 'llama3.1:8b',
        mocked: decision.mocked ?? false, fallback: decision.fallback ?? false };
    },
    async finalResponse({ messages, signal }) {
      signal?.throwIfAborted();
      const observed = JSON.parse(messages.at(-1).content);
      return { stop_reason: 'end_turn', responseMode: 'structured_final',
        text: observed.product_id ? 'Actual graph summary.' : 'Actual graph recommendations.',
        provider: decision.finalProvider || 'ollama', model: decision.finalModel || 'llama3.1:8b',
        mocked: decision.finalMocked ?? false, fallback: decision.finalFallback ?? false };
    },
  };
}

test('product questions reuse owned conversation context and echo exact request identity',async()=>{
 const {randomUUID}=require('node:crypto'),seen=[],provider=realProvider(),chat=provider.chat;
 provider.chat=async args=>{seen.push(structuredClone(args.messages));return chat(args);};
 const f=memoryFixture({provider}),requestId=randomUUID();
 const first=await f.assist.question({scope,persona,productId:7,message:'Does this product include a lid?',requestId});
 assert.equal(first.requestId,requestId);assert.equal(first.product_id,7);assert.equal(first.answer,'Actual graph summary.');
 const second=await f.assist.question({scope,persona,productId:7,message:'What was my previous question?',sessionId:first.sessionId,requestId:randomUUID()});
 assert.equal(second.sessionId,first.sessionId);assert.equal(f.sessions.size,1);assert.ok(JSON.stringify(seen[1]).includes('include a lid'));
 const calls=f.toolCalls();await assert.rejects(f.assist.question({scope,persona:{id:12,role:'customer'},productId:7,message:'foreign',sessionId:first.sessionId}),{code:'CONVERSATION_UNAVAILABLE'});
 await assert.rejects(f.assist.question({scope,persona,productId:7,message:'',requestId:randomUUID()}),{code:'INVALID_ARGUMENT'});assert.equal(f.toolCalls(),calls);
});

test('product model decisions use the closed task catalog for summary, similar, and questions',async()=>{
 const seen=[],provider=realProvider(),chat=provider.chat;
 provider.chat=async args=>{seen.push({closedToolCatalog:args.closedToolCatalog,maxToolCalls:args.maxToolCalls,requireToolCall:args.requireToolCall,
   names:args.tools.map(tool=>`${tool.agent}.${tool.tool}`)});return chat(args);};
 const f=memoryFixture({provider});
 await f.assist.summary({scope,persona,productId:7});
 await f.assist.similar({scope,persona,productId:7});
 await f.assist.question({scope,persona,productId:7,message:'What is the current price and stock?'});
 assert.deepEqual(seen,[
  {closedToolCatalog:true,maxToolCalls:1,requireToolCall:true,names:['summarizer.summarize_product']},
  {closedToolCatalog:true,maxToolCalls:1,requireToolCall:true,names:['product-search.similar']},
  {closedToolCatalog:true,maxToolCalls:1,requireToolCall:true,names:['summarizer.summarize_product']},
 ]);
});

test('product question cannot publish a direct model answer without an observed tool result',async()=>{
 const f=memoryFixture({provider:realProvider({stopReason:'end_turn'})});
 await assert.rejects(f.assist.question({scope,persona,productId:7,message:'What is the current price and stock?'}),
  {code:'PRODUCT_MODEL_UNAVAILABLE'});
 assert.equal(f.toolCalls(),0);
 assert.equal(f.traces.some(row=>row.kind==='local_tool_result'),false);
});

test('summary runs the real bound graph and returns raw HTML only from its trusted observation', async () => {
  const f = memoryFixture({ provider: realProvider() });
  const result = await f.assist.summary({ scope, persona, productId: 7 });
  assert.deepEqual(result, { ...summaryDto, summary: 'Actual graph summary.',
    provider: 'ollama', model: 'llama3.1:8b' });
  assert.equal(f.toolCalls(), 1);
  assert.equal(f.toolFactoryCalls.length, 1);
  const factory = f.toolFactoryCalls[0];
  assert.deepEqual(factory.scope, scope);
  assert.deepEqual(factory.persona, persona);
  assert.equal(factory.productId, 7);
  assert.equal(factory.operation, 'summary');
  assert.equal(typeof factory.checkCurrent, 'function');
  assert.ok(f.traces.some(row => row.kind === 'local_tool_result'));
  assert.ok(f.traces.some(row => row.kind === 'terminal'));
  const stored = [...f.messages.values()][0];
  assert.deepEqual(stored.map(row => row.role), ['user', 'assistant', 'tool', 'assistant']);
  assert.equal(stored[2].content, JSON.stringify(summaryDto));
});

test('similar uses its closed operation tool and preserves target-owned retrieval DTO', async () => {
  const f = memoryFixture({ provider: realProvider() });
  const result = await f.assist.similar({ scope, persona, productId: 7 });
  assert.deepEqual(result, { ...similarDto, recommendation: 'Actual graph recommendations.', provider: 'ollama', model: 'llama3.1:8b' });
  assert.equal(f.toolCalls(), 1);
  assert.equal(f.toolFactoryCalls[0].operation, 'similar');
});

function promptPolicyFixture() {
  const { buildPolicySnapshot } = require('../server/services/secureshopPromptPolicySnapshot');
  const { createHash } = require('node:crypto');
  const credential = { sessionId: '93000000-0000-4000-8000-000000000001', authorityVersion: '7' };
  const rendered = 'PRODUCT_ASSIST_BOUND_POLICY';
  const snapshot = buildPolicySnapshot({ policyVersion: '4', role: 'customer', policies: [{ name: 'owned', rendered,
    renderedSha256: createHash('sha256').update(rendered).digest('hex'), targets: ['customer'] }] });
  const admissions = [];
  const personaAuthority = { capture: ({ scope: s, personaId, role, sessionId, authorityVersion }) => ({
    binding: { ...s, personaId, role, sessionId, authorityVersion },
    async assertRemoteAdmission() {}, async withPersonaEffect(work) { return work({}); },
    async withCrossStoreEffect(work) { return work(); },
  }) };
  const promptPolicyRepository = { async admitRunSnapshot(input) {
    admissions.push(structuredClone(input));
    assert.equal(input.persona.id, persona.id); assert.equal(input.persona.role, 'customer');
    assert.deepEqual(input.personaSession, credential);
    return snapshot;
  } };
  return { credential, rendered, admissions, personaAuthority, promptPolicyRepository };
}

test('summary provider input contains the exact admitted customer policy snapshot', async () => {
  const fixture = promptPolicyFixture();
  const provider = realProvider(); const chat = provider.chat;
  const providerInputs = [];
  provider.chat = async input => { providerInputs.push(structuredClone(input)); return chat(input); };
  const f = memoryFixture({ provider, personaAuthority: fixture.personaAuthority, promptPolicyRepository: fixture.promptPolicyRepository });
  await f.assist.summary({ scope, persona, personaSession: fixture.credential, productId: 7 });
  assert.equal(fixture.admissions.length, 1);
  assert.equal(fixture.admissions[0].runId, 'product-run-1');
  assert.ok(providerInputs.some(input => input.system.includes(fixture.rendered)));
  assert.ok(f.traces.some(row => row.kind === 'prompt_policy_snapshot' && row.result_json.includes('"policyVersion":"4"')));
});

test('similar provider input contains the exact admitted customer policy snapshot', async () => {
  const fixture = promptPolicyFixture();
  const provider = realProvider(); const chat = provider.chat;
  const providerInputs = [];
  provider.chat = async input => { providerInputs.push(structuredClone(input)); return chat(input); };
  const f = memoryFixture({ provider, personaAuthority: fixture.personaAuthority, promptPolicyRepository: fixture.promptPolicyRepository });
  await f.assist.similar({ scope, persona, personaSession: fixture.credential, productId: 7 });
  assert.equal(fixture.admissions.length, 1);
  assert.ok(providerInputs.some(input => input.system.includes(fixture.rendered)));
  assert.ok(f.traces.some(row => row.kind === 'prompt_policy_snapshot' && row.result_json.includes('"sha256":"')));
});

for (const [operation, recipient] of [['summary', 'summarizer'], ['similar', null]]) test(`task policy opt-in gives product ${operation} its trusted v2 recipient`, async () => {
  const { buildTaskPolicySnapshot } = require('../server/services/secureshopPromptPolicyTaskSnapshot');
  const { createHash } = require('node:crypto');
  const credential = { sessionId: '93000000-0000-4000-8000-000000000001', authorityVersion: '7' };
  const rendered = `TASK_POLICY_${operation}`; const admissions = [];
  const personaAuthority = { capture: ({ scope: s, personaId, role, sessionId, authorityVersion }) => ({
    binding: { ...s, personaId, role, sessionId, authorityVersion }, async assertRemoteAdmission() {},
    async withPersonaEffect(work) { return work({}); }, async withCrossStoreEffect(work) { return work(); },
  }) };
  const targets = recipient === null ? ['customer'] : [recipient];
  const snapshot = buildTaskPolicySnapshot({ policyVersion: '8', role: 'customer', recipient, policies: [{ name: 'task', rendered,
    renderedSha256: createHash('sha256').update(rendered).digest('hex'), targets }] });
  const promptPolicyRepository = { async admitRunSnapshot(input) { admissions.push(structuredClone(input)); return snapshot; } };
  const provider = realProvider(); const chat = provider.chat; const systems = [];
  provider.chat = async input => { systems.push(input.system); return chat(input); };
  const fixture = memoryFixture({ provider, personaAuthority, promptPolicyRepository, taskPoliciesEnabled: true });
  await fixture.assist[operation]({ scope, persona, personaSession: credential, productId: 7 });
  assert.equal(admissions.length, 1);
  assert.equal(admissions[0].policyContractVersion, 2); assert.equal(admissions[0].recipient, recipient);
  assert.ok(systems.some(system => system.includes(rendered)));
  assert.ok(fixture.traces.some(row => row.kind === 'prompt_policy_snapshot'
    && row.result_json.includes('"policyContractVersion":2')));
});

test('product task policy opt-in is an explicit boolean', () => {
  assert.throws(() => memoryFixture({ taskPoliciesEnabled: 'true' }), /task policy configuration required/);
});

test('policy-enabled summary retrieves the exact admitted revision before accepting the product observation',async()=>{
 const {buildTaskPolicySnapshot}=require('../server/services/secureshopPromptPolicyTaskSnapshot'),{createHash}=require('node:crypto');
 const credential={sessionId:'93000000-0000-4000-8000-000000000001',authorityVersion:'7'},rendered='POLICY_RETRIEVAL_POISON',renderedSha256=createHash('sha256').update(rendered).digest('hex');
 const snapshot=buildTaskPolicySnapshot({policyVersion:'12',role:'customer',recipient:'summarizer',policies:[{name:'retrieval',rendered,renderedSha256,targets:['summarizer']}]});
 const personaAuthority={capture:({scope:s,personaId,role,sessionId,authorityVersion})=>({binding:{...s,personaId,role,sessionId,authorityVersion},async assertRemoteAdmission(){},async withPersonaEffect(work){return work({});},async withCrossStoreEffect(work){return work();}})};
 const promptPolicyRepository={async admitRunSnapshot(){return snapshot;}},searchCalls=[];
 const policySearch={async search(value){searchCalls.push(structuredClone(value));return{revisionId:'95000000-0000-4000-8000-000000000001',policyVersion:snapshot.policyVersion,policySnapshotSha256:snapshot.sha256,results:[{name:'retrieval',text:rendered,sourceSha256:'a'.repeat(64),score:1}]};}};
 let decisions=0;const provider={async chat({tools}){decisions++;const name=decisions===1?'summarizer.search_policy':'summarizer.summarize_product';assert.ok(tools.some(tool=>`${tool.agent}.${tool.tool}`===name));return{stop_reason:'tool_use',tool_uses:[{id:`call-${decisions}`,name,args:decisions===1?{query:'return policy'}:{product_id:7}}],provider:'ollama',model:'llama3.1:8b',mocked:false,fallback:false};},async finalResponse(){return{stop_reason:'end_turn',responseMode:'structured_final',text:'Policy-aware actual summary.',provider:'ollama',model:'llama3.1:8b',mocked:false,fallback:false};}};
 const f=memoryFixture({provider,personaAuthority,promptPolicyRepository,taskPoliciesEnabled:true,policySearch});
 const result=await f.assist.summary({scope,persona,personaSession:credential,productId:7});assert.equal(result.summary,'Policy-aware actual summary.');assert.equal(searchCalls.length,1);assert.equal(searchCalls[0].policySnapshot.sha256,snapshot.sha256);assert.equal(f.toolCalls(),1);assert.ok(f.traces.some(row=>row.tool_name==='search_policy'&&row.kind==='local_tool_result'));
});

test('optional assessment is admitted only for the similar operation', async () => {
  const events = [];
  const assessmentFactory = context => {
    events.push(['factory', context]);
    return {
      async begin() { events.push(['begin']); return { attempt: 'owned' }; },
      async observe(_execution, packet) { events.push(['observe', packet.observation.tool]); },
      async finalize(_execution, packet) { events.push(['finalize', packet.result.stopReason]); },
    };
  };
  const f = memoryFixture({ provider: realProvider(), assessmentFactory });
  const summary = await f.assist.summary({ scope, persona, productId: 7 });
  assert.equal(summary.summary, 'Actual graph summary.');
  assert.deepEqual(events, []);
  const similar = await f.assist.similar({ scope, persona, productId: 7 });
  assert.equal(similar.recommendation, 'Actual graph recommendations.');
  assert.deepEqual(events.map(([name]) => name), ['factory', 'begin', 'observe', 'finalize']);
  assert.deepEqual(events[0][1].binding, { ...scope, shopUserId: persona.id, role: persona.role });
});

test('assessment failures remain bounded to the assessed similar operation', async () => {
  const f = memoryFixture({ provider: realProvider(), assessmentFactory: () => ({
    async begin() { throw Object.assign(new Error('assessment unavailable'), { code: 'ASSESSMENT_UNAVAILABLE' }); },
    async observe() {}, async finalize() {},
  }) });
  await assert.rejects(f.assist.similar({ scope, persona, productId: 7 }), { code: 'ASSESSMENT_UNAVAILABLE' });
  const summary = await memoryFixture({ provider: realProvider() }).assist.summary({ scope, persona, productId: 7 });
  assert.equal(summary.product_id, 7);
});

test('invalid optional assessment factories are rejected at construction', () => {
  assert.throws(() => memoryFixture({ provider: realProvider(), assessmentFactory: true }),
    /Bound product assessment factory required/);
});

test('concurrent product requests keep operation observations and final metadata private', async () => {
  const f = memoryFixture({ provider: realProvider() });
  const [summary, similar] = await Promise.all([
    f.assist.summary({ scope, persona, productId: 7 }),
    f.assist.similar({ scope, persona, productId: 7 }),
  ]);
  assert.equal(summary.product_id, 7);
  assert.equal(summary.summary, 'Actual graph summary.');
  assert.deepEqual(similar.results.map(row => row.id), [8]);
  assert.equal(Object.hasOwn(similar, 'product_id'), false);
  assert.deepEqual(f.toolFactoryCalls.map(call => call.operation).sort(), ['similar', 'summary']);
});

test('provider decisions cannot change the server-bound product or bypass the tool observation', async () => {
  for (const decision of [{ productId: 8 }, { productId: 7, extraArgs: true }]) {
    const f = memoryFixture({ provider: realProvider(decision) });
    await assert.rejects(f.assist.summary({ scope, persona, productId: 7 }),
      { code: 'PRODUCT_MODEL_UNAVAILABLE' });
    assert.equal(f.toolCalls(), 0);
  }
  const direct = memoryFixture({ provider: realProvider({ stopReason: 'end_turn' }) });
  await assert.rejects(direct.assist.summary({ scope, persona, productId: 7 }),
    { code: 'PRODUCT_MODEL_UNAVAILABLE' });
  assert.equal(direct.toolCalls(), 0);
});

test('graph can correct a rejected tool decision within its finite budget', async () => {
  const provider = realProvider(); let decisions = 0;
  const correct = provider.chat;
  provider.chat = async args => {
    decisions += 1;
    return decisions === 1 ? realProvider({ productId: 8 }).chat(args) : correct(args);
  };
  const f = memoryFixture({ provider });
  const result = await f.assist.summary({ scope, persona, productId: 7 });
  assert.equal(decisions, 2);
  assert.equal(f.toolCalls(), 1);
  assert.equal(result.product_id, 7);
  assert.equal(result.summary, 'Actual graph summary.');
});

test('mock, fallback and unavailable model identities cannot qualify either graph phase', async () => {
  for (const decision of [
    { provider: 'mock', model: 'deterministic-mock', mocked: true },
    { provider: 'ollama', model: 'llama3.1:8b', fallback: true },
    { finalProvider: 'mock', finalModel: 'deterministic-mock', finalMocked: true },
    { finalProvider: 'ollama', finalModel: 'fallback', finalFallback: true },
  ]) {
    const f = memoryFixture({ provider: realProvider(decision) });
    await assert.rejects(f.assist.summary({ scope, persona, productId: 7 }),
      { code: 'PRODUCT_MODEL_UNAVAILABLE' });
  }
});

test('failed, malformed and foreign product observations never reach a final response', async () => {
  const cases = [
    () => ({ isError: true, content: [{ type: 'text', text: JSON.stringify(summaryDto) }] }),
    () => ({ content: [{ type: 'text', text: '{' }] }),
    () => ({ content: [{ type: 'text', text: JSON.stringify({ ...summaryDto, product_id: 8 }) }] }),
  ];
  for (const toolResult of cases) {
    let finalCalls = 0;
    const provider = realProvider();
    const original = provider.finalResponse;
    provider.finalResponse = async input => { finalCalls += 1; return original(input); };
    const f = memoryFixture({ provider, toolResult });
    await assert.rejects(f.assist.summary({ scope, persona, productId: 7 }),
      { code: 'PRODUCT_MODEL_UNAVAILABLE' });
    assert.equal(finalCalls, 0);
  }
});

test('abort and stale launch authority propagate without publishing a product result', async () => {
  const controller = new AbortController();
  controller.abort(new DOMException('cancelled', 'AbortError'));
  const aborted = memoryFixture({ provider: realProvider() });
  await assert.rejects(aborted.assist.summary({ scope, persona, productId: 7,
    signal: controller.signal }), { name: 'AbortError' });
  assert.equal(aborted.toolCalls(), 0);

  const providerAbort = memoryFixture({ provider: {
    async chat() { throw new DOMException('provider cancelled', 'AbortError'); },
    async finalResponse() { throw new Error('must not reach final response'); },
  } });
  await assert.rejects(providerAbort.assist.summary({ scope, persona, productId: 7 }),
    { name: 'AbortError' });

  let staleNow = false;
  const staleProvider = realProvider();
  const finalResponse = staleProvider.finalResponse;
  staleProvider.finalResponse = async input => {
    const result = await finalResponse(input);
    staleNow = true;
    return result;
  };
  const stale = memoryFixture({ provider: staleProvider, launches: { async assertCurrent() {
    if (staleNow) throw Object.assign(new Error('stale launch'), { code: 'STALE_LAUNCH' });
  } } });
  await assert.rejects(stale.assist.summary({ scope, persona, productId: 7 }),
    { code: 'STALE_LAUNCH' });
});

test('customer identity and product IDs are strict trusted inputs', async () => {
  const f = memoryFixture({ provider: realProvider() });
  await assert.rejects(f.assist.summary({ scope, persona: { id: 11, role: 'merchant' }, productId: 7 }),
    { code: 'INVALID_ARGUMENT' });
  await assert.rejects(f.assist.similar({ scope, persona, productId: '7' }),
    { code: 'INVALID_ARGUMENT' });
});


test('retained coordinator drains an in-flight product tool before reset cleanup', { timeout: 5000 }, async () => {
  const { createRunCoordinator } = require('../server/agent-runtime/runCoordinator');
  const coordinator = createRunCoordinator({ family: 'ProductResetQualification', ledger: null });
  let signalEntered;
  const entered = new Promise(resolve => { signalEntered = resolve; });
  let releaseTool;
  const toolBarrier = new Promise(resolve => { releaseTool = resolve; });
  const order = [];
  const fixture = memoryFixture({ coordinator, provider: realProvider(),
    async toolResult() {
      order.push('tool-start');
      signalEntered();
      await toolBarrier;
      order.push('tool-settled');
      return { content: [{ type: 'text', text: JSON.stringify(summaryDto) }] };
    },
  });
  const running = fixture.assist.summary({ scope, persona, productId: 7 });
  const rejected = assert.rejects(running);
  await entered;
  const [sessionId] = fixture.sessions.keys();
  assert.ok(sessionId);
  const reset = coordinator.reset(sessionId, async () => { order.push('cleanup'); });
  await new Promise(resolve => setImmediate(resolve));
  assert.deepEqual(order, ['tool-start']);
  releaseTool();
  await rejected;
  await reset;
  assert.deepEqual(order, ['tool-start', 'tool-settled', 'cleanup']);
});

test('candidate ProductAssist fences selected tool and final projection after persona changes',async()=>{
 for(const stage of ['decision','observation']){
  let revoked=false;const check=async()=>{if(revoked)throw Object.assign(Error('revoked'),{code:'SHOP_AUTH_INVALID',executionBoundary:true});};
  const personaAuthority={capture:({scope:s,personaId,role,sessionId,authorityVersion})=>Object.freeze({binding:Object.freeze({...s,personaId,role,sessionId,authorityVersion}),assertRemoteAdmission:check,withPersonaEffect:async work=>{await check();return work();},withCrossStoreEffect:async work=>{await check();return work();}})};
  const provider=realProvider(),chat=provider.chat;provider.chat=async input=>{const result=await chat(input);if(stage==='decision')revoked=true;return result;};
  const f=memoryFixture({provider,personaAuthority,toolResult:()=>{revoked=true;return{content:[{type:'text',text:JSON.stringify(summaryDto)}]};}});
  await assert.rejects(f.assist.summary({scope,persona,productId:7,personaSession:{sessionId:'owned-session',authorityVersion:'1'}}),{code:'SHOP_AUTH_INVALID'});
  assert.equal(f.toolCalls(),stage==='decision'?0:1);
 }
});

for (const operation of ['summary','similar']) for (const enforced of [false,true]) test(`product ${operation} factory policy ${enforced?'blocks':'advisory dispatches'} with original credential`, async () => {
  const credential={sessionId:'93000000-0000-4000-8000-000000000001',authorityVersion:'1'}, original={...credential};
  const admissions=[];
  const personaAuthority={capture:({scope:s,...identity})=>({binding:{...s,...identity},async assertRemoteAdmission(){await Promise.resolve();credential.sessionId="94000000-0000-4000-8000-000000000001";},async withPersonaEffect(work){return work();},async withCrossStoreEffect(work){return work();}})};
  const selected=operation==='summary'?'summarizer.summarize_product':'product-search.similar';let calls=0;
  const f=memoryFixture({personaAuthority,toolPolicyRepository:{async admitTool(input){
    admissions.push(input);assert.deepEqual(input.personaSession,original);assert.deepEqual(input.scope,scope);assert.deepEqual(input.persona,persona);
    assert.equal(input.workflow,`product-${operation}`);assert.deepEqual(input.declaredTools.map(t=>`${t.agent}.${t.tool}`),[selected]);
    return{admissionId:require('node:crypto').randomUUID(),runId:input.runId,invocationId:input.invocationId,toolKey:selected,registrySha256:require('../server/services/secureshopBoundAclRegistry').REGISTRY_SHA256,policyVersion:'2',allowed:false,enforcement:enforced,action:enforced?'block':'dispatch',policyViolation:'denied-by-acl'};
  }},provider:{async chat(){calls++;credential.sessionId='94000000-0000-4000-8000-000000000001';return{provider:'ollama',model:'llama3.1:8b',mocked:false,stop_reason:'tool_use',tool_uses:[{id:`call-${calls}`,name:selected,args:{product_id:7}}]};},async finalResponse(){return{provider:'ollama',model:'llama3.1:8b',mocked:false,responseMode:'structured_final',stop_reason:'end_turn',text:'Controlled fixture'};}}});
  const pending=f.assist[operation]({scope,persona,personaSession:credential,productId:7});
  if(enforced)await assert.rejects(pending);else await pending;
  assert.ok(admissions.length);assert.equal(f.toolCalls(),enforced?0:1);
});
test('product policy constructor rejects invalid repository or absent authority before any allocation',()=>{
  for(const options of [{toolPolicyRepository:{}},{toolPolicyRepository:{admitTool(){}}}])assert.throws(()=>memoryFixture(options),/Policy repository and persona authority required/);
});

test('fixed product graph preserves descriptive questions and rejects changed product authority before lookup',async()=>{
 const {createFeatureModeAuthority}=require('../server/services/secureshopFeatureModeAuthority'),{createSecureShopBoundProductTools}=require('../server/services/secureshopBoundProductTools');let stamp='one',lookups=0;
 const modeAuthority=createFeatureModeAuthority({progress:{getEvaluationScope:async()=>({mode:'fixed',generation:0,modeStamp:stamp})},launches:{assertCurrent:async()=>{}}});
 const personaAuthority={capture:({scope:s,...identity})=>({binding:{...s,...identity},async assertRemoteAdmission(){},async withPersonaEffect(work){return work({});},async withCrossStoreEffect(work){return work();}})};
 const catalog={getProduct:async()=>{lookups++;return{product:{id:7,name:'Ceramic mug',price:12.5,stock_quantity:4,category:'Home',description:'A glazed ceramic mug keeps tea warm.'}};}};
 const make=(provider)=>memoryFixture({provider,personaAuthority,modeAuthority,reuseBoundSession:true,taskPoliciesEnabled:true,policySearch:{search:async()=>{throw Error('fixed must not retrieve policy text');}},productToolsFactory:input=>createSecureShopBoundProductTools({...input,catalog})});
 const base=realProvider(),provider={...base,async finalResponse(args){assert.match(args.messages.at(-1).content,/glazed ceramic mug keeps tea warm/);assert.match(args.messages.at(-1).content,/untrusted_catalog_text/);return base.finalResponse(args);}};
 const input={scope,persona,personaSession:{sessionId:'91000000-0000-4000-8000-000000000001',authorityVersion:'1'},productId:7};
 const f=make(provider),question={...input,message:'What material is this mug?',requestId:require('node:crypto').randomUUID()},result=await f.assist.question(question);assert.equal(result.modeCapability.effectiveMode,'fixed');assert.equal(result.modeCapability.policyVersion,'bounded-product-data-and-catalog-neighbors-v1');assert.equal(result.answer,'Actual graph summary.');
 const questionLookups=lookups;assert.deepEqual(await f.assist.question({...question,sessionId:result.sessionId}),result);assert.equal(lookups,questionLookups,'Existing descriptive question replay performs no new tool effect');
 const summaryProvider={...base,async finalResponse(args){assert.doesNotMatch(JSON.stringify(args.messages),/glazed ceramic mug|Ceramic mug|untrusted_catalog_text/);assert.match(args.messages.at(-1).content,/fixed_summary_numeric_facts_v1/);return base.finalResponse(args);}};
 provider.finalResponse=summaryProvider.finalResponse;
 provider.chat=async args=>{assert.doesNotMatch(JSON.stringify(args.messages),/glazed ceramic mug|What material|Actual graph summary/);return base.chat(args);};
 const summary=await f.assist.summary({...input,sessionId:result.sessionId});assert.equal(summary.modeCapability.policyVersion,'fixed-summary-numeric-facts-v1');assert.equal(summary.description,null);assert.equal(summary.price,12.5);assert.equal(summary.stock_quantity,4);assert.equal(summary.summary,'Actual graph summary.');
 assert.equal(f.sessions.size,1,'Real bound-session reuse does not import prior descriptive history into turn-local Summary');
 assert.deepEqual(await f.assist.question({...question,sessionId:result.sessionId}),result,'Summary specialization leaves original question replay valid');
 const before=lookups;await assert.rejects(make(realProvider({productId:8})).assist.summary(input));assert.equal(lookups,before);
 await assert.rejects(make({...base,async chat(args){assert.deepEqual(args.tools.map(row=>row.agent+'.'+row.tool),['summarizer.summarize_product']);return{...(await base.chat(args)),tool_uses:[{id:'forbidden',name:'system.run_diagnostics',args:{command:'arbitrary'}}]};}}).assist.summary(input));assert.equal(lookups,before);
 const stale=make({...base,async chat(args){const result=await base.chat(args);stamp='two';return result;}});await assert.rejects(stale.assist.summary(input),{code:'ANALYTICS_MODE_STALE'});assert.equal(lookups,before);
});
