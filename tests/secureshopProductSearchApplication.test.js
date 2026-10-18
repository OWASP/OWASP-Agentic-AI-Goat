'use strict';
// The source-reader suite imports only this inert production-graph fixture.
const test = require.main === module ? require('node:test') : () => {};
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const { createProductSearchApplication } = require('../server/services/secureshopProductSearchApplication');
const { createTurnRequest } = require('../server/services/secureshopTurnRequest');
const { createSceneBinding } = require('../server/services/secureshopSceneBinding');
const { POLICIES } = require('../server/services/secureshopFeatureModeAuthority');
const { OllamaProvider } = require('../server/services/secureshop/providers/ollamaProvider');
const Protocol = require('../server/services/secureshopProductSearchSqlContract');

function fixture({ codes = ['Laptop'], mode = 'vuln', queryError = false,
  incompleteEffect = false, tamperReceipt = false, foreignTarget = false, driftDuringModel = false,
  driftDuringLookup = false, mock = false, policy = false, policyDenied = false,
  decisionTransform, abortDuringModel, searchResult, finalText = 'The observations are complete.', filters } = {}) {
  const scope = { launchId: randomUUID(), scenarioId: randomUUID(), generation: 1, platformOwnerId: 1, platformSessionId: 2 };
  const persona = { id: 3, role: 'customer' }, personaSession = { sessionId: randomUUID(), authorityVersion: '1' };
  const context = { scope, persona, personaSession }, sessions = new Map(), rows = new Map(), messages = [], traces = [];
  const formats = [], prompts = [], queries = [], requests = [], admissions = [], bank = [{ id: 1, code: 'SAVE10', discount_percent: 10, active: 1 }];
  let stale = false, calls = 0, finalCalls = 0, provisions = 0;
  const check = async () => { if (stale) throw Object.assign(Error('stale'), { code: 'SHOP_SCENE_STALE' }); };
  const target = createSceneBinding({ ...scope, targetId: randomUUID() }, { sceneId: randomUUID(),
    sceneGeneration: 1, grantId: randomUUID(), execution: scope, withLease: work => work() });
  const tokens = ['customer_chat', 'product_search'].map(featureId => ({ snapshot: { version: 1, featureId,
    policyVersion: POLICIES[featureId], mode, generation: 1, modeStamp: 'mode-1', scope },
  assertCurrent: check, assertCurrentAtEffect: check }));
  const personaAuthority = { capture(input) { return { binding: { ...input.scope, personaId: input.personaId,
    role: input.role, sessionId: input.sessionId, authorityVersion: input.authorityVersion },
  assertRemoteAdmission: check, withPersonaEffect: work => work({}), withCrossStoreEffect: work => work() }; } };
  const repository = {
    async acquireBoundSession({ id, binding, purpose }) { const row = { id, binding, purpose, state: 'pending' };
      sessions.set(id, row); return row; },
    async activateBoundSession(id) { sessions.get(id).state = 'active'; return true; },
    async getBoundSession(id) { return sessions.get(id); },
    async getMessages() { return []; }, async appendMessage(_id, _owner, value) { messages.push(structuredClone(value)); },
    async getTokens() { return 0; }, async addTokens() {},
    async appendTraces(_id, _owner, value) { traces.push(...structuredClone(value)); },
  };
  const journal = {
    async claim(input) {
      const request = createTurnRequest(input), prior = rows.get(input.requestId);
      if (prior) { if (prior.request_hash !== request.hash) throw Object.assign(Error('conflict'), { code: 'TURN_CONFLICT' });
        return { status: prior.status, result: prior.result_json, claimId: input.requestId }; }
      rows.set(input.requestId, { session_id: input.sessionId, request_id: input.requestId,
        request_hash: request.hash, request_version: 1, status: 'started' });
      return { status: 'claimed', claimId: input.requestId };
    },
    async complete(input) { Object.assign(rows.get(input.requestId), { status: 'completed', result_json: structuredClone(input.result) }); },
    async markUncertain(input) { const row = rows.get(input.requestId); if (row && row.status !== 'completed') row.status = 'uncertain'; },
  };
  const coordinator = { async run(sessionId, options, work) {
    const admitted = await options.admit(); if (admitted.skip) return admitted.value;
    const runId = randomUUID(), ownerKey = JSON.stringify(['SecureShopBoundConversation', sessionId]);
    return work({ runId, ownerKey, generation: 1, durableGeneration: 0, signal: options.signal, check,
      async effect(_key, execute) { return execute(); },
      async effectWithReceipt(key, execute) { return { value: await execute(), receipt: { version: 1,
        status: incompleteEffect ? 'pending' : 'completed', runId, ownerKey, generation: '0',
        effectKey: `${options.idempotencyKey}:${key}` } }; }, async trace() {} });
  } };
  const provider = new OllamaProvider({ model: 'llama3.1:8b' });
  provider.transport = { async chat(prompt, _tools, options) {
    formats.push(structuredClone(options.format)); prompts.push(structuredClone(prompt));
    if (driftDuringModel) stale = true;
    abortDuringModel?.abort();
    if (options.format?.properties?.answer) { finalCalls++; return { response: JSON.stringify({ answer: finalText }) }; }
    const code = codes[calls++];
    return { response: JSON.stringify(code === undefined ? { reply: finalText }
      : { tool_calls: [{ agent: 'product-search', tool: 'search', args: { query: code, ...(filters ? {filters} : {}) } }] }) };
  } };
  if (decisionTransform) { const original = provider.chat.bind(provider); provider.chat = async args => decisionTransform(await original(args)); }
  if (mock) provider.chat = async () => ({ provider: 'mock', model: 'fixture', mocked: true, stop_reason: 'end_turn', text: 'fake' });
  const sqlTarget = { targetId: randomUUID(), scope, sourceManifestSha256: 'a'.repeat(64) };
  const searchService = { async provision() { provisions++; return sqlTarget; },
    async searchProducts(input) {
      requests.push(structuredClone(input)); if (driftDuringLookup) stale = true;
      if (queryError) throw Error('SQL error containing PRIVATE_REFERENCE');
      const receipt = Protocol.buildReceipt({ target: foreignTarget ? { ...sqlTarget, scope: { ...scope, platformOwnerId: 99 } } : sqlTarget,
        request: input, result: { rows: searchResult ? searchResult(input) : [], row_count: searchResult ? searchResult(input).length : 0 } });
      return tamperReceipt ? { ...receipt, resultSha256: 'f'.repeat(64) } : receipt;
    } };
  const args = { captureCurrent: async () => ({ ...context, target, mode: tokens[0], searchMode: tokens[1], check }),
    personaAuthority, modeAuthority: { assertToken(token) { assert(tokens.includes(token)); return token; } },
    launches: { assertCurrent: check }, conversationRepository: repository, journal, coordinator, provider,
    ...(policy ? { toolPolicyRepository: { async admitTool(input) {
      admissions.push(input); const resolver = require('../server/services/secureshopBoundAclRegistry')
        .createBoundAclResolver({ workflow: input.workflow, declaredTools: input.declaredTools });
      assert.equal(input.workflow, 'product-search-union'); assert(resolver.resolve(input.agent, input.tool));
      return { admissionId: randomUUID(), runId: input.runId, invocationId: input.invocationId,
        toolKey: 'product-search.search', policyVersion: '1', enforcement: true,
        allowed: !policyDenied, action: policyDenied ? 'block' : 'dispatch', policyViolation: null,
        registrySha256: resolver.registrySha256 };
    } } } : {}),
    searchService, agentsPool: { async query(sql, params) {
      queries.push({ sql, params }); const row = rows.get(params[1]); return { rows: row ? [structuredClone(row)] : [] }; } } };
  const app = createProductSearchApplication(args);
  return { app, args, context, rows, sessions, formats, prompts, messages, traces, requests, tokens, queries, admissions,
    stale() { stale = true; }, get calls() { return calls; }, get finalCalls() { return finalCalls; },
    get provisions() { return provisions; } };
}
async function start(f) { const { sessionId } = await f.app.createSession(f.context);
  return { ...f.context, sessionId, requestId: randomUUID(), message: 'Search this practice catalog.' }; }

test('real graph preserves selected query, original rows and saved GET/replay without another effect',async()=>{
 const row={id:1,name:'Laptop',description:null,price:20,category:'electronics',image_url:null,stock_quantity:4,retailer_id:1,status:'active',created_at:null,updated_at:null};
 const f=fixture({searchResult:()=>[row]}),input=await start(f);const first=await f.app.run(input);
 assert.equal(first.searches[0].results[0].name,'Laptop');assert.equal(f.calls,2);assert.equal(f.requests.length,1);
 const saved=await f.app.read(input);assert.equal(saved.replayed,true);await f.app.run(input);
 assert.equal(f.requests.length,1);assert.equal(f.calls,2);
 const source=await f.app.readSavedSource(f.context,input);assert.equal(source.turn.taskMetadata.productSearch.searches[0].args.query,'Laptop');
});
test('post-query filters affect only public rows and never alter saved SQL receipt',async()=>{
 const row={id:1,name:'Hidden',description:null,price:20,category:'other',image_url:null,stock_quantity:4,retailer_id:1,status:'active',created_at:null,updated_at:null};
 const f=fixture({filters:{category:'electronics'},searchResult:()=>[row]}),input=await start(f);const result=await f.app.run(input);
 assert.deepEqual(result.searches[0].results,[]);const source=await f.app.readSavedSource(f.context,input);
 assert.equal(source.turn.taskMetadata.productSearch.searches[0].receipt.result.rows.length,1);
});
for(const option of ['queryError','incompleteEffect','tamperReceipt','foreignTarget','driftDuringModel','driftDuringLookup','mock'])test(option+' fails closed',async()=>{
 const f=fixture({[option]:true}),input=await start(f);await assert.rejects(f.app.run(input));
});
test('eight searches are bounded and final response is real provider continuation',async()=>{
 const f=fixture({codes:Array.from({length:8},(_,i)=>'query'+i)}),input=await start(f);const result=await f.app.run(input);
 assert.equal(result.searches.length,8);assert.equal(f.requests.length,8);assert.equal(f.finalCalls,1);
});
test('model may reply without searching; reset denies saved read before any dispatch',async()=>{
 const f=fixture({codes:[]}),input=await start(f);assert.deepEqual((await f.app.run(input)).searches,[]);
 assert.equal(f.provisions,0);f.stale();await assert.rejects(f.app.read(input));assert.equal(f.requests.length,0);
});
module.exports={fixture,start};

test('production ACL admits only dedicated search key and denial prevents target work',async()=>{
 const allowed=fixture({policy:true}),input=await start(allowed);await allowed.app.run(input);
 assert.equal(allowed.admissions.length,1);assert.equal(allowed.admissions[0].workflow,'product-search-union');
 const denied=fixture({policy:true,policyDenied:true}),other=await start(denied);
 await assert.rejects(denied.app.run(other));assert.equal(denied.provisions,0);assert.equal(denied.requests.length,0);
});
