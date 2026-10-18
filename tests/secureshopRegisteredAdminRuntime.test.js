'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createRegisteredAdminRuntime } = require('../server/services/secureshopRegisteredAdminRuntime');
const { createTurnRequest } = require('../server/services/secureshopTurnRequest');

const SCOPE = Object.freeze({
  launchId: '81000000-0000-4000-8000-000000000001',
  scenarioId: '82000000-0000-4000-8000-000000000001',
  generation: 1,
  platformOwnerId: 7,
  platformSessionId: 8,
});
const PERSONA = Object.freeze({ id: 3, role: 'admin' });
const CREDENTIAL = Object.freeze({
  sessionId: '83000000-0000-4000-8000-000000000001',
  authorityVersion: '1',
});
const SESSION_ID = '84000000-0000-4000-8000-000000000001';

function fixture({ provider, onCapture, onCreate, onRead, modeAuthority, readApproval = async () => true,dispatch,health,impersonationAssessment,descriptionAssessment } = {}) {
  const messages = [];
  const persistedTraces = [];
  const journalRows = new Map();
  const fences = [];
  let currentCredential=CREDENTIAL;
  const conversations = {
    async assertOwned(id,binding) {if(id!==SESSION_ID||Object.keys(SCOPE).some(k=>binding[k]!==SCOPE[k])
      ||binding.shopUserId!==PERSONA.id||binding.role!=='admin')throw Object.assign(Error('foreign'),{code:'CONVERSATION_UNAVAILABLE'});},
    async getMessages() { return messages.map(value => structuredClone(value)); },
    async create(binding, persona, purpose) {
      onCreate?.(binding, persona, purpose);
      return { id: SESSION_ID };
    },
  };
  const repository = {
    async appendMessage(_id, _binding, message) { messages.push(structuredClone(message)); },
    async getTokens() { return 0; },
    async addTokens() {},
    async appendTraces(_id, _binding, rows) { persistedTraces.push(...structuredClone(rows)); },
  };
  const turns = {
    async run(_id, _binding, _persona, options, operation) {
      const boundary = Object.freeze({
        identity: Object.freeze({ runId: 'run-1', ownerKey: 'owner-1', durableGeneration: '1' }),
        signal: undefined,
        async check() {},
        async effect() {},
        async effectWithReceipt(key, callback) { return { value: await require('../server/agent-runtime/effectAdmissionContext').withEffectAdmission(
          {runId:'run-1',ownerKey:'owner-1',durableGeneration:'1'},key,callback), receipt: { status: 'completed' } }; },
      });
      assert.equal(options.idempotencyKey.length > 0, true);
      return operation(boundary);
    },
  };
  const journal = {
    async claim(input) {
      const {requestId}=input;
      const request=createTurnRequest(input);
      if(journalRows.has(requestId)&&journalRows.get(requestId).request_hash!==request.hash)
        throw Object.assign(Error('changed'),{code:'TURN_REQUEST_CONFLICT'});
      if (journalRows.has(requestId)) {const row=journalRows.get(requestId);
        return {...row,status:row.status==='claimed'?'started':row.status};}
      const row = { status: 'claimed', claimId: requestId,session_id:input.sessionId,
        request_id:requestId,request_hash:request.hash,request_version:request.version };
      journalRows.set(requestId, row);
      return row;
    },
    async complete({ requestId, result }) {
      if(journalRows.get(requestId)?.status!=='claimed')throw Object.assign(Error('claim unavailable'),{code:'TURN_CLAIM_UNAVAILABLE'});
      journalRows.set(requestId, { ...journalRows.get(requestId),status: 'completed', claimId: requestId, result });
    },
    async markUncertain({requestId}) {const row=journalRows.get(requestId);if(row&&row.status!=='completed')row.status='uncertain';},
    async readRegisteredAdminRequest({sessionId,requestId}){
      const row=journalRows.get(requestId);
      return row?.session_id===sessionId?{...structuredClone(row),status:row.status==='claimed'?'started':row.status,result_json:structuredClone(row.result)}:null;
    },
  };
  const personaAuthority = {
    capture(input) {
      onCapture?.(input);
      if (input.role !== 'admin' || input.personaId !== PERSONA.id
          || input.sessionId !== currentCredential.sessionId || input.authorityVersion !== currentCredential.authorityVersion
          ||Object.keys(SCOPE).some(k=>input.scope[k]!==SCOPE[k])) {
        return {
          binding: { ...input.scope, personaId: input.personaId, role: input.role,
            sessionId: input.sessionId, authorityVersion: input.authorityVersion },
          async assertRemoteAdmission() {
            throw Object.assign(new Error('invalid persona session'), { code: 'SHOP_AUTH_INVALID' });
          },
        };
      }
      const fence = {
        binding: { ...SCOPE, personaId: PERSONA.id, role: 'admin', ...currentCredential },
        async assertRemoteAdmission() {},
        async withPersonaEffect(callback) { return callback({}, { sessionId: CREDENTIAL.sessionId }); },
      };
      fences.push(fence);
      return fence;
    },
  };
  let snapshotNumber = 0;
  const snapshots = {
    capture(binding, fence) {
      assert.equal(binding.role, 'admin');
      assert.ok(fence);
      snapshotNumber += 1;
      const tools=[{ name: 'read_status', description: 'read status', inputSchema: { type: 'object',properties:{},additionalProperties:false } }];
      const entry = { entryId: `91000000-0000-4000-8000-00000000000${snapshotNumber}`, name: `owned-entry-${snapshotNumber}`,
        registryVersion:'1',transport:'streamable-http',endpoint:'http://owned.example/mcp',
        schemaSha256:require('../server/services/secureshopMcpSchemaDigest').mcpSchemaDigest(tools),tools };
      return {
        async read() { onRead?.(entry); return [entry]; },
        async withCurrentEntry(_entry, callback) { return callback(); },
      };
    },
  };
  const executor = { async invocationHealth() {health?.();return { instanceId: '91000000-0000-4000-8000-000000000099', runtimeDigest: 'digest-1' }; } };
  return {
    runtime: createRegisteredAdminRuntime({ turns, conversations, conversationRepository: repository, journal,
      personaAuthority, provider: provider || { async chat() { return { stop_reason: 'end_turn', text: 'ok' }; } },
      snapshots, executor, modeAuthority, impersonationAssessment, descriptionAssessment, dispatch: dispatch|| (async () => ({ result: {} })), observeInvocation: async () => ({ observed: true }), mode: 'fixed', readApproval }),
    fences, messages, journalRows, persistedTraces,changeCredential(value){currentCredential=value;},
  };
}

test('admin createSession rejects missing and wrong persona credentials before persistence', async () => {
  let created = 0;
  const { runtime } = fixture({ onCreate: () => { created++; } });
  await assert.rejects(runtime.createSession(SCOPE, PERSONA), { code: 'SHOP_AUTH_INVALID' });
  await assert.rejects(runtime.createSession(SCOPE, PERSONA, { ...CREDENTIAL, authorityVersion: 'wrong' }), { code: 'SHOP_AUTH_INVALID' });
  await assert.rejects(runtime.createSession(SCOPE, { id: PERSONA.id, role: 'customer' }, CREDENTIAL), { code: 'SHOP_AUTH_INVALID' });
  assert.equal(created, 0);
});

test('admin createSession captures the canonical persona session and rechecks admission', async () => {
  const captures = [];
  const { runtime } = fixture({ onCapture: input => captures.push(input) });
  assert.deepEqual(await runtime.createSession(SCOPE, PERSONA, CREDENTIAL), { id: SESSION_ID });
  assert.deepEqual(captures[0], { scope: { ...SCOPE, shopUserId: PERSONA.id, role: PERSONA.role }, personaId: PERSONA.id,
    role: 'admin', sessionId: CREDENTIAL.sessionId, authorityVersion: CREDENTIAL.authorityVersion });
});

test('each run builds its manifest from its own registered tool pool', async () => {
  const providerInputs = [];
  const reads = [];
  const { runtime } = fixture({
    provider: { async chat(input) { providerInputs.push(input); return { stop_reason: 'end_turn', text: 'controlled' }; } },
    onRead: entry => reads.push(entry),
  });
  await runtime.runner.run({ sessionId: SESSION_ID, requestId: '85000000-0000-4000-8000-000000000001',
    scope: SCOPE, persona: PERSONA, personaSession: CREDENTIAL, message: 'status' });
  await runtime.runner.run({ sessionId: SESSION_ID, requestId: '85000000-0000-4000-8000-000000000002',
    scope: SCOPE, persona: PERSONA, personaSession: CREDENTIAL, message: 'status again' });
  assert.equal(providerInputs.length, 2);
  assert.equal(reads.length, 2);
  assert.notEqual(reads[0], reads[1]);
  assert.equal(providerInputs[0].tools.length, 2);
  assert.equal(providerInputs[1].tools.length, 2);
  assert.notEqual(providerInputs[0].tools[0].agent, providerInputs[1].tools[0].agent);
  assert.equal(providerInputs[0].tools[0].tool, 'tool_0');
  assert.equal(providerInputs[1].tools[0].tool, 'tool_0');
});

test('canonical registered-tool mode stamp change during model call prevents result publication',async()=>{
 let stamp='first';const modeAuthority=require('../server/services/secureshopFeatureModeAuthority').createFeatureModeAuthority({progress:{getEvaluationScope:async()=>({mode:'fixed',generation:0,modeStamp:stamp})},launches:{assertCurrent:async()=>{}}});
 const {runtime}=fixture({modeAuthority,provider:{async chat(){stamp='second';return {stop_reason:'end_turn',text:'stale answer'};}}});
 await assert.rejects(runtime.runner.run({sessionId:SESSION_ID,requestId:'85000000-0000-4000-8000-000000000003',scope:SCOPE,persona:PERSONA,personaSession:CREDENTIAL,message:'status'}),{code:'ANALYTICS_MODE_STALE'});
});


test('fixed admin can inspect grounded registry status without receiving poisoned descriptions or executing remote tools', async () => {
  let modelCalls = 0; const events = [];
 const { runtime, journalRows, persistedTraces } = fixture({ readApproval: async () => false,
    onRead: entry => { entry.tools[0].description = 'POISONED_DESCRIPTION'; },
    provider: { async chat(input) {
      modelCalls++;
      assert.doesNotMatch(JSON.stringify(input), /POISONED_DESCRIPTION/);
      assert.deepEqual(input.tools.map(tool => `${tool.agent}.${tool.tool}`), ['registry.status']);
      if (modelCalls === 1) return { stop_reason: 'tool_use', tool_uses: [
        { id: 'status-1', name: 'registry.status', args: {} }] };
      const observation = input.messages.find(row => row.role === 'tool');
      assert.ok(observation);
      assert.match(observation.content, /"registrationCount":1/);
      assert.match(observation.content, /"availableExternalToolCount":0/);
      return { stop_reason: 'end_turn', text: 'One registration; no approved external tools are available.' };
    } } });
  const requestId = '85000000-0000-4000-8000-000000000004';
  const input = { sessionId: SESSION_ID, requestId, scope: SCOPE, persona: PERSONA,
    personaSession: CREDENTIAL, message: 'How many tools are registered and approved?',
    stream: { send: (name, data) => events.push({ name, data }) } };
  const result = await runtime.runner.run(input);
  assert.equal(modelCalls, 2);
  assert.equal(result.text, 'One registration; no approved external tools are available.');
  assert.equal(result.modeCapability.effectiveMode, 'fixed');
  assert.equal(result.modeCapability.featureId, 'registered_mcp');
  assert.deepEqual(journalRows.get(requestId).result.modeCapability, result.modeCapability);
  assert.equal(result.taskMetadata.registeredAdmin.version,3);
  assert.deepEqual(result.taskMetadata.registeredAdmin.traceEventIds,persistedTraces.map(row=>row.event_id));
  assert.ok(result.taskMetadata.registeredAdmin.traceEventIds.length>=3);
  for (const event of events.filter(row => ['assistant_message', 'done'].includes(row.name))) {
    assert.deepEqual(event.data.modeCapability, result.modeCapability);
  }
  assert.equal(events.filter(row => row.name === 'done').length, 1);
  const replay = await runtime.runner.run(input);
  assert.deepEqual(replay.modeCapability, result.modeCapability);
  assert.equal(modelCalls, 2);
});

test('lost terminal GET and exact POST replay retain one admitted registered dispatch without model or snapshot rerun',async()=>{
 let calls=0,effects=0,reads=0,health=0;
 const protocol=require('../sidecars/sandbox-runner/owned-mcp-registry/invoke-protocol');
 const f=fixture({onRead:()=>reads++,health:()=>health++,provider:{async chat(input){
  calls++;const user=JSON.parse(input.messages.find(x=>x.role==='user').content);
  assert.equal(user.message,'read current tool');assert.match(user.personaSessionSha256,/^[a-f0-9]{64}$/);
  assert.doesNotMatch(JSON.stringify(input.messages),new RegExp(CREDENTIAL.sessionId));
  if(calls===1){const tool=input.tools.find(x=>x.isExternalMcp);return {stop_reason:'tool_use',tool_uses:[{id:'owned-call',name:`${tool.agent}.${tool.tool}`,args:{}}]};}
  return {stop_reason:'end_turn',text:'Actual controlled tool result.'};
 }},dispatch:async({request:q})=>{
  effects++;const result={content:[{type:'text',text:'controlled registered result'}]};
  return protocol.receipt({version:1,instanceId:q.instanceId,operationId:q.operationId,entryId:q.entry.entryId,
   registryVersion:q.entry.registryVersion,requestSha256:protocol.digest(q),schemaSha256:q.entry.schemaSha256,
   endpointSha256:protocol.digest(q.entry.endpoint),argumentsSha256:protocol.digest(q.args),
   resultSha256:protocol.digest(result),result,isolation:'owned-mcp-registry-v1'},q);
 }});
 const requestId='85000000-0000-4000-8000-000000000010';
 const input={sessionId:SESSION_ID,requestId,scope:SCOPE,persona:PERSONA,personaSession:CREDENTIAL,message:'read current tool'};
 const committed=await f.runtime.runner.run(input);
 assert.equal(committed.stopReason,'end_turn');assert.equal(committed.hops.length,1);assert.equal(effects,1);
 const saved=await f.runtime.readRequest(SCOPE,PERSONA,CREDENTIAL,SESSION_ID,requestId);
 assert.equal(saved.status,'completed');assert.equal(saved.replayed,true);
 const {taskMetadata,replayed,...projection}=committed;assert.deepEqual(saved.result,projection);
 assert.equal(Object.hasOwn(saved.result,'taskMetadata'),false);
 assert.deepEqual(await f.runtime.runner.run(input),{...committed,replayed:true});
 assert.deepEqual([calls,effects,reads,health],[2,1,1,1]);
 await assert.rejects(f.runtime.runner.run({...input,message:'changed message'}),{code:'TURN_REQUEST_CONFLICT'});
 const next={...CREDENTIAL,sessionId:'83000000-0000-4000-8000-000000000002'};f.changeCredential(next);
 await assert.rejects(f.runtime.runner.run({...input,personaSession:next}),{code:'TURN_REQUEST_CONFLICT'});
 await assert.rejects(f.runtime.readRequest(SCOPE,PERSONA,next,SESSION_ID,requestId),{code:'TURN_REQUEST_CONFLICT'});
 assert.deepEqual([calls,effects,reads,health],[2,1,1,1]);
});

test('saved GET rechecks exact reconstructed hash, current mode and ownership; legacy and uncertain rows remain unconfirmed',async()=>{
 const f=fixture(),requestId='85000000-0000-4000-8000-000000000011';
 const input={sessionId:SESSION_ID,requestId,scope:SCOPE,persona:PERSONA,personaSession:CREDENTIAL,message:'status'};
 assert.equal((await f.runtime.readRequest(SCOPE,PERSONA,CREDENTIAL,SESSION_ID,requestId)).status,'unconfirmed');
 await f.runtime.runner.run(input);const original=structuredClone(f.journalRows.get(requestId));
 assert.equal(original.result.taskMetadata.registeredAdmin.version,3);
 assert.deepEqual(original.result.taskMetadata.registeredAdmin.traceEventIds,
   f.persistedTraces.map(row=>row.event_id));
 const jsonb=v=>Array.isArray(v)?v.map(jsonb):v&&typeof v==='object'?Object.fromEntries(Object.keys(v).sort().reverse().map(k=>[k,jsonb(v[k])])):v;
 f.journalRows.set(requestId,jsonb(original));assert.equal((await f.runtime.readRequest(SCOPE,PERSONA,CREDENTIAL,SESSION_ID,requestId)).status,'completed');
 const historical=structuredClone(original);
 historical.result.taskMetadata.registeredAdmin.version=1;
 delete historical.result.taskMetadata.registeredAdmin.traceEventIds;
 delete historical.result.taskMetadata.registeredAdmin.execution;
 f.journalRows.set(requestId,historical);
 assert.equal((await f.runtime.readRequest(SCOPE,PERSONA,CREDENTIAL,SESSION_ID,requestId)).status,'completed');
 for(const alter of [row=>row.result.taskMetadata.registeredAdmin.message='forged',row=>row.request_hash='a'.repeat(64),
  row=>row.result.taskMetadata.registeredAdmin.extra=true,row=>row.result.modeCapability.effectiveMode='vuln',row=>row.request_version=2,
  row=>{row.result.taskMetadata.registeredAdmin.traceEventIds=undefined;},
  row=>{row.result.taskMetadata.registeredAdmin.traceEventIds[0]='not-an-event-id';},
  row=>{row.result.taskMetadata.registeredAdmin.traceEventIds.push(row.result.taskMetadata.registeredAdmin.traceEventIds[0]);},
  row=>{row.result.taskMetadata.registeredAdmin.version=1;},
  row=>{row.result.taskMetadata.registeredAdmin.version=4;}]){
  const row=structuredClone(original);alter(row);f.journalRows.set(requestId,row);
  await assert.rejects(f.runtime.readRequest(SCOPE,PERSONA,CREDENTIAL,SESSION_ID,requestId),{code:'TURN_REQUEST_CONFLICT'});
 }
 for(const row of [{...original,status:'uncertain'}, {...original,result:{...original.result,taskMetadata:undefined}}]){
  f.journalRows.set(requestId,row);assert.equal((await f.runtime.readRequest(SCOPE,PERSONA,CREDENTIAL,SESSION_ID,requestId)).status,'unconfirmed');
 }
 f.journalRows.set(requestId,{...original,status:'uncertain'});
 await assert.rejects(f.runtime.runner.run(input),{code:'TURN_RECOVERY_REQUIRED'});
 for(const [scope,persona,session,id] of [[{...SCOPE,generation:2},PERSONA,CREDENTIAL,SESSION_ID],
  [SCOPE,{id:4,role:'admin'},CREDENTIAL,SESSION_ID],[SCOPE,PERSONA,CREDENTIAL,'84000000-0000-4000-8000-000000000002']])
  await assert.rejects(f.runtime.readRequest(scope,persona,session,id,requestId));
});

test('in-flight and uncertain requests never authorize another model or tool admission',async()=>{
 let release,entered,calls=0;const enteredPromise=new Promise(resolve=>{entered=resolve;});
 const f=fixture({provider:{async chat(){calls++;entered();await new Promise(resolve=>{release=resolve;});return {stop_reason:'end_turn',text:'settled'};}}});
 const requestId='85000000-0000-4000-8000-000000000012';
 const input={sessionId:SESSION_ID,requestId,scope:SCOPE,persona:PERSONA,personaSession:CREDENTIAL,message:'one request'};
 const work=f.runtime.runner.run(input);await enteredPromise;
 assert.equal((await f.runtime.readRequest(SCOPE,PERSONA,CREDENTIAL,SESSION_ID,requestId)).status,'unconfirmed');
 await assert.rejects(f.runtime.runner.run(input),{code:'TURN_RECOVERY_REQUIRED'});
 assert.equal(calls,1);release();await assert.rejects(work,{code:'TURN_CLAIM_UNAVAILABLE'});
 assert.equal((await f.runtime.readRequest(SCOPE,PERSONA,CREDENTIAL,SESSION_ID,requestId)).status,'unconfirmed');
 assert.equal(calls,1);
});

test('changed registered mode on completed replay suppresses all terminal events',async()=>{
 let current='fixed',calls=0;
 const modeAuthority=require('../server/services/secureshopFeatureModeAuthority').createFeatureModeAuthority({
  progress:{getEvaluationScope:async()=>({mode:current,generation:0,modeStamp:current})},launches:{assertCurrent:async()=>{}}});
 const f=fixture({modeAuthority,provider:{async chat(){calls++;return {stop_reason:'end_turn',text:'saved fixed answer'};}}});
 const input={sessionId:SESSION_ID,requestId:'85000000-0000-4000-8000-000000000013',scope:SCOPE,
  persona:PERSONA,personaSession:CREDENTIAL,message:'status'};
 await f.runtime.runner.run(input);current='vuln';const events=[];
 await assert.rejects(f.runtime.runner.run({...input,stream:{send:(name,data)=>events.push({name,data})}}),{code:'TURN_REQUEST_CONFLICT'});
 assert.deepEqual(events,[]);assert.equal(calls,1);
 await assert.rejects(f.runtime.readRequest(SCOPE,PERSONA,CREDENTIAL,SESSION_ID,input.requestId),{code:'TURN_REQUEST_CONFLICT'});
});

test('V43 grades only a committed original turn before done; GET/replay never repeat grading or tools',async()=>{
 let attempts=0,reads=0,actors=0,release,started;
 const gate=new Promise(resolve=>{release=resolve;}),begin=new Promise(resolve=>{started=resolve;});
 const events=[];let f;
 const assessment={async runAttempt(input){
  attempts++;assert.equal(f.journalRows.get(input.requestId).status,'completed');
  assert.equal((await input.verifyOriginal()).status,'completed');
  started();await gate;return {completed:false,status:'ineligible',modelEvaluated:false};
 },async readOutcome(input){reads++;assert.equal((await input.verifyOriginal()).status,'completed');
  return {completed:false,status:'unconfirmed',modelEvaluated:false};}};
 f=fixture({impersonationAssessment:assessment,provider:{async chat(){actors++;return {stop_reason:'end_turn',text:'saved'};}}});
 const requestId='85000000-0000-4000-8000-000000000050';
 const input={scope:SCOPE,persona:PERSONA,personaSession:CREDENTIAL,sessionId:SESSION_ID,requestId,message:'status',stream:{send:(name)=>events.push(name)}};
 const pending=f.runtime.runner.run(input);await begin;
 assert.equal(events.includes('done'),false);release();await pending;assert.equal(events.filter(x=>x==='done').length,1);
 await f.runtime.readRequest(SCOPE,PERSONA,CREDENTIAL,SESSION_ID,requestId);
 await f.runtime.runner.run(input);assert.equal(attempts,1);assert.equal(actors,1);
 assert.deepEqual(await f.runtime.readMcpImpersonationAssessment(input),{completed:false,status:'unconfirmed',modelEvaluated:false});
 assert.equal(reads,1);assert.equal(attempts,1);
 await f.runtime.retryMcpImpersonationAssessment(input);assert.equal(attempts,2);assert.equal(actors,1);
});

test('V43 prepacket outage preserves committed chat and explicit assessment retry never runs the model',async()=>{
 let attempts=0,actors=0;
 const assessment={async runAttempt(){attempts++;if(attempts===1)throw Error('private source outage');return {completed:false,status:'ineligible',modelEvaluated:false};},
  async readOutcome(){return {completed:false,status:'unconfirmed',modelEvaluated:false};}};
 const f=fixture({impersonationAssessment:assessment,provider:{async chat(){actors++;return {stop_reason:'end_turn',text:'saved'};}}});
 const input={scope:SCOPE,persona:PERSONA,personaSession:CREDENTIAL,sessionId:SESSION_ID,requestId:'85000000-0000-4000-8000-000000000051',message:'status'};
 assert.equal((await f.runtime.runner.run(input)).text,'saved');
 assert.equal((await f.runtime.readRequest(SCOPE,PERSONA,CREDENTIAL,SESSION_ID,input.requestId)).status,'completed');
 assert.equal((await f.runtime.readMcpImpersonationAssessment(input)).status,'unconfirmed');
 await f.runtime.retryMcpImpersonationAssessment(input);assert.equal(actors,1);assert.equal(attempts,2);
 f.changeCredential({...CREDENTIAL,authorityVersion:'2'});
 await assert.rejects(f.runtime.retryMcpImpersonationAssessment(input),{code:'SHOP_AUTH_INVALID'});
 await assert.rejects(f.runtime.readMcpImpersonationAssessment(input),{code:'SHOP_AUTH_INVALID'});assert.equal(attempts,2);
});

test('registered v3 read rejects changed private epoch while historical v2 remains readable',async()=>{
 const f=fixture();const requestId='85000000-0000-4000-8000-000000000052';
 await f.runtime.runner.run({scope:SCOPE,persona:PERSONA,personaSession:CREDENTIAL,sessionId:SESSION_ID,requestId,message:'status'});
 const row=f.journalRows.get(requestId),original=structuredClone(row.result.taskMetadata.registeredAdmin);
 row.result.taskMetadata.registeredAdmin.execution.modeStamp='changed';
 await assert.rejects(f.runtime.readRequest(SCOPE,PERSONA,CREDENTIAL,SESSION_ID,requestId),{code:'TURN_REQUEST_CONFLICT'});
 row.result.taskMetadata.registeredAdmin=original;row.result.taskMetadata.registeredAdmin.version=2;delete row.result.taskMetadata.registeredAdmin.execution;
 assert.equal((await f.runtime.readRequest(SCOPE,PERSONA,CREDENTIAL,SESSION_ID,requestId)).status,'completed');
});


test('description capture remains execution-local across interleaved runs and private on saved GET', async () => {
  const C = require('../server/services/secureshopOwnedMcpInvocationContract');
  let release, entered;
  const blocked = new Promise(resolve => { entered = resolve; });
  const inputs = [];
  const f = fixture({provider:{async chat(input){
    inputs.push(input);
    if(inputs.length===1){entered();await new Promise(resolve=>{release=resolve;});}
    return {stop_reason:'end_turn',text:'controlled catalog'};
  }}});
  const base={scope:SCOPE,persona:PERSONA,personaSession:CREDENTIAL,sessionId:SESSION_ID,message:'status'};
  const first={...base,requestId:'85000000-0000-4000-8000-000000000060'};
  const second={...base,requestId:'85000000-0000-4000-8000-000000000061'};
  const pending=f.runtime.runner.run(first);await blocked;
  const b=await f.runtime.runner.run(second);release();const a=await pending;
  assert.equal(a.taskMetadata.registeredDescription.manifestSha256,C.digest(inputs[0].tools));
  assert.equal(b.taskMetadata.registeredDescription.manifestSha256,C.digest(inputs[1].tools));
  assert.notEqual(a.taskMetadata.registeredDescription.entries[0].entryId,b.taskMetadata.registeredDescription.entries[0].entryId);
  assert.deepEqual(Object.keys(a.taskMetadata.registeredAdmin).sort(),
    ['version','message','personaSessionSha256','traceEventIds','execution'].sort());
  assert.equal(a.taskMetadata.registeredAdmin.version,3);
  const saved=await f.runtime.readRequest(SCOPE,PERSONA,CREDENTIAL,SESSION_ID,first.requestId);
  assert.equal(Object.hasOwn(saved.result,'taskMetadata'),false);
  assert.deepEqual((await f.runtime.runner.run(first)).taskMetadata,a.taskMetadata);
  assert.equal(inputs.length,2);
});

test('optional manifest capture cannot overflow ordinary registered-turn metadata admission', async () => {
  const f=fixture();
  const base={scope:SCOPE,persona:PERSONA,personaSession:CREDENTIAL,sessionId:SESSION_ID,message:'status'};
  const first=await f.runtime.runner.run({...base,requestId:'85000000-0000-4000-8000-000000000062'});
  assert.ok(first.taskMetadata.registeredDescription);
  const onlyBase={registeredAdmin:first.taskMetadata.registeredAdmin};
  const length=65536-Buffer.byteLength(JSON.stringify(onlyBase))+base.message.length-10;
  const input={...base,requestId:'85000000-0000-4000-8000-000000000063',message:'x'.repeat(length)};
  const result=await f.runtime.runner.run(input);
  assert.equal(result.stopReason,'end_turn');
  assert.equal(result.taskMetadata.registeredAdmin.message,input.message);
  assert.equal(Object.hasOwn(result.taskMetadata,'registeredDescription'),false);
  assert.ok(Buffer.byteLength(JSON.stringify(result.taskMetadata))<=65536);
  assert.equal((await f.runtime.readRequest(SCOPE,PERSONA,CREDENTIAL,SESSION_ID,input.requestId)).status,'completed');
});

test('explicit description assessment dispatch preserves original turn and never reexecutes model or tools', async () => {
  let calls=0,reads=0,attempts=0;
  const result={completed:false,status:'ineligible',modelEvaluated:false};
  const descriptionAssessment={async runAttempt(input){attempts++;assert.equal((await input.verifyOriginal()).status,'completed');return result;},
    async readOutcome(input){reads++;assert.equal((await input.verifyOriginal()).status,'completed');return result;}};
  const f=fixture({descriptionAssessment,provider:{async chat(){calls++;return {stop_reason:'end_turn',text:'controlled'};}}});
  const input={scope:SCOPE,persona:PERSONA,personaSession:CREDENTIAL,sessionId:SESSION_ID,
    requestId:'85000000-0000-4000-8000-000000000064',message:'status'};
  await f.runtime.runner.run(input);assert.deepEqual([calls,reads,attempts],[1,0,0]);
  assert.equal(await f.runtime.readMcpDescriptionAssessment(input),result);
  assert.equal(await f.runtime.assessMcpDescription(input),result);
  assert.deepEqual([calls,reads,attempts],[1,1,1]);
  f.changeCredential({...CREDENTIAL,authorityVersion:'2'});
  await assert.rejects(f.runtime.assessMcpDescription(input),{code:'SHOP_AUTH_INVALID'});
  assert.deepEqual([calls,reads,attempts],[1,1,1]);
  const missing=fixture();
  assert.throws(()=>missing.runtime.assessMcpDescription(input),{code:'MCP_DESCRIPTION_EVIDENCE_UNAVAILABLE'});
});
