'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createSecureShopPersonaInboxApplication, projectPersonaInboxRun, buildFreshPersonaInboxReadTask }
  = require('../server/services/secureshopPersonaInboxApplication');
const { createSecureShopPersonaInboxRequestAuthority }
  = require('../server/services/secureshopPersonaInboxRequestAuthority');

const scope = Object.freeze({ launchId: '10000000-0000-4000-8000-000000000001',
  scenarioId: '20000000-0000-4000-8000-000000000001', generation: 2,
  platformOwnerId: 7, platformSessionId: 8 });
const target = Object.freeze({ ...scope, targetId: '30000000-0000-4000-8000-000000000001' });
const fixtures = [{ fixtureKey: 'customer-note', owner: { id: 11, role: 'customer' }, subject: 'a', body: 'a' }];
const allObjectives = ['ss_cross_persona_effect', 'ss_acl_advisory_effect', 'ss_acl_enforced_block'];
const alwaysAvailable = { read: async () => ({ visible: true, enabled: new Set(allObjectives) }),
  assertObjectives: async () => {} };

function setup({ onRun, onAvailability, onAdvance } = {}) {
  const calls = []; let mode = 'advisory';let visible=true;
  const enabled=new Set(allObjectives);
  const availability={async read(){return{visible,enabled};},async assertObjectives(ids,currentScope){
    await onAvailability?.(ids,currentScope);
    if(!visible||ids.some(id=>!enabled.has(id)))throw Object.assign(new Error('unavailable'),
      {code:'PERSONA_INBOX_EXERCISE_UNAVAILABLE'});
  }};
  const requestAuthority = createSecureShopPersonaInboxRequestAuthority();
  let capturedAuthority;
  const launches = { async assertCurrent(value) { calls.push(['current', value]); },
    async reservePersonaInboxTarget(input) { calls.push(['reserve', input]); return target; } };
  const repository = {
    async provision(value, options) { calls.push(['provision', value, options]); },
    async list() { return [{ messageId: 3, ownerShopUserId: 13, ownerShopRole: 'admin', subject: 'Support' }]; },
    async readAcl() { return { version: mode === 'advisory' ? 1 : 2, mode, policySha256: 'a'.repeat(64) }; },
    async advanceAcl(value, options) { calls.push(['advance', value, options]); mode = 'enforced';await onAdvance?.();
      return { version: 2, mode, policySha256: 'b'.repeat(64) }; },
  };
  const conversations = { async create(value, persona) { calls.push(['conversation', value, persona]); return { id: '60000000-0000-4000-8000-000000000001' }; } };
  const runner = { async run(input) { calls.push(['run', input]); capturedAuthority = input.localToolAuthority;
    assert.deepEqual(requestAuthority.resolve(input.localToolAuthority,{ binding:{...input.scope,
      shopUserId:input.persona.id,role:input.persona.role},sessionId:input.sessionId,requestId:input.requestId }),
    {targetId:target.targetId,messageId:3});await onRun?.();return { stopReason: 'end_turn', replayed: false,
    hops: [{ tool: 'persona-inbox.read_message', params: { message_id: 3 }, result: { content: [{ type: 'text',
      text: JSON.stringify({ ok: true, event_id: '40000000-0000-4000-8000-000000000001', message_id: 3,
        owner_persona_id: 13, owner_role: 'admin', subject: 'Support', body: 'private', body_sha256: 'c'.repeat(64),
        acl: { version: 1, mode: 'advisory', decision: 'deny', cross_persona: true, disclosed: true } }) }] } }] }; } };
  const authorized = [];
  const application = createSecureShopPersonaInboxApplication({ launches, repository, conversations, runner,
    fixtures, requestAuthority, availability,
    async authorizeAclTransition(value) { authorized.push(value); return () => calls.push(['revoke']); } });
  return { application, calls, authorized, requestAuthority, enabled, hide(){visible=false;},
    get capturedAuthority(){return capturedAuthority;} };
}

test('resolves the immutable target, projects status and runs an exact replayable request', async () => {
  const fixture = setup();const { application, calls } = fixture;
  assert.deepEqual(await application.status({ scope, persona: { id: 12, role: 'merchant' } }), {
    ready: true, acl: { version: 1, mode: 'advisory', policySha256: 'a'.repeat(64) },
    messages: [{ messageId: 3, ownerShopUserId: 13, ownerShopRole: 'admin', subject: 'Support' }],
    capabilities: { enforceAcl: true },
  });
  const requestId = '50000000-0000-4000-8000-000000000001';
  const result = await application.run({ scope, persona: { id: 12, role: 'merchant' }, requestId, messageId: 3 });
  assert.equal(result.ok, true); assert.equal(result.accesses[0].body, 'private');
  const run = calls.find(call => call[0] === 'run')[1];
  assert.equal(run.requestId, requestId); assert.equal(run.message,buildFreshPersonaInboxReadTask(3,requestId));
  assert.match(run.message,new RegExp(`Observation request ${requestId}.*fresh.*call now.*message 3`,'i'));
  assert.match(run.message,/Earlier turn results are historical/i);
  assert.doesNotMatch(run.message,/\b(?:allow|deny|disclos(?:e|ed)|advisory|enforced)\b/i,
    'the task does not inject the expected ACL decision or disclosure');
  assert.throws(()=>fixture.requestAuthority.resolve(fixture.capturedAuthority,{binding:{...scope,
    shopUserId:12,role:'merchant'},sessionId:run.sessionId,requestId}),{code:'PERSONA_INBOX_REQUEST_AUTHORITY_UNAVAILABLE'});
  assert.deepEqual(calls.find(call => call[0] === 'reserve')[1], { launchId: scope.launchId,
    platformSessionId: 8, platformOwnerId: 7, expectedGeneration: 2 });
  assert.equal(calls.filter(call => call[0] === 'provision').every(call => call[2].mode === 'advisory'), true);
});

test('fresh-observation task bytes are stable for exact replay and distinct for a new request',()=>{
  const first='50000000-0000-4000-8000-000000000001';
  const second='50000000-0000-4000-8000-000000000002';
  assert.equal(buildFreshPersonaInboxReadTask(3,first),buildFreshPersonaInboxReadTask(3,first.toUpperCase()));
  assert.notEqual(buildFreshPersonaInboxReadTask(3,first),buildFreshPersonaInboxReadTask(3,second));
  assert.throws(()=>buildFreshPersonaInboxReadTask(3,'learner-controlled prose'),{code:'INVALID_ARGUMENT'});
});

test('only merchant authority can perform the server-owned one-way ACL transition', async () => {
  const { application, calls, authorized } = setup();
  await assert.rejects(application.enforce({ scope, persona: { id: 11, role: 'customer' } }), { code: 'OWNER_MISMATCH' });
  assert.deepEqual(await application.enforce({ scope, persona: { id: 12, role: 'merchant' } }), {
    version: 2, mode: 'enforced', policySha256: 'b'.repeat(64),
  });
  assert.equal(authorized.length, 1); assert.equal(authorized[0].expectedVersion, 1);
  assert.equal(calls.some(call => call[0] === 'revoke'), true);
  assert.equal((await application.enforce({ scope, persona: { id: 12, role: 'merchant' } })).mode, 'enforced');
  assert.equal(authorized.length, 1, 'replay does not authorize another transition');
});

test('enforcement keeps registered eligibility scoped before and after its durable transition',async()=>{
  const checked=[];
  const fixture=setup({async onAvailability(ids,currentScope){
    checked.push({ids,currentScope});
    // A registered tenant may enable this objective while workshop defaults
    // remain disabled. An unscoped check must not turn the committed effect
    // into a misleading failure by consulting those unrelated defaults.
    if(!currentScope)throw Object.assign(Error('Workshop objective disabled'),
      {code:'PERSONA_INBOX_EXERCISE_UNAVAILABLE'});
    assert.deepEqual(currentScope,scope);
  }});
  const result=await fixture.application.enforce({scope,persona:{id:12,role:'merchant'}});
  assert.equal(result.mode,'enforced');assert.equal(result.version,2);
  assert.deepEqual(checked,Array.from({length:3},()=>({ids:['ss_acl_enforced_block'],currentScope:scope})));
  assert.equal(fixture.calls.filter(call=>call[0]==='advance').length,1);
  assert.equal(fixture.calls.filter(call=>call[0]==='revoke').length,1);
  assert.equal(fixture.calls.some(call=>call[0]==='run'),false);
});

test('tenant disablement after enforcement remains an error and never claims the effect was rolled back',async()=>{
  let disabled=false;const checked=[];
  const fixture=setup({async onAdvance(){disabled=true;},async onAvailability(ids,currentScope){
    checked.push(currentScope);
    // Unscoped workshop defaults deliberately permit it; only the captured
    // registered authority can detect this post-effect tenant disablement.
    if(currentScope&&disabled)throw Object.assign(Error('Tenant objective disabled'),
      {code:'PERSONA_INBOX_EXERCISE_UNAVAILABLE'});
  }});
  await assert.rejects(fixture.application.enforce({scope,persona:{id:12,role:'merchant'}}),
    {code:'PERSONA_INBOX_EXERCISE_UNAVAILABLE'});
  assert.deepEqual(checked,[scope,scope,scope]);
  assert.equal(fixture.calls.filter(call=>call[0]==='advance').length,1);
  assert.equal(fixture.calls.filter(call=>call[0]==='revoke').length,1);
  // Read back existing state; the post-effect error does not invent a rollback.
  assert.equal((await fixture.application.status({scope,persona:{id:12,role:'merchant'}})).acl.mode,'enforced');
});

test('public projection ignores model prose and malformed tool results', () => {
  assert.deepEqual(projectPersonaInboxRun({ stopReason: 'end_turn', hops: [
    { tool: null, result: { content: [{ type: 'text', text: 'I disclosed a secret' }] } },
    { tool: 'persona-inbox.read_message', result: { content: [{ type: 'text', text: '{bad' }] } },
  ] }), { ok: true, stopReason: 'end_turn', replayed: false, accesses: [] });
  assert.deepEqual(projectPersonaInboxRun({ stopReason:'end_turn',hops:[{tool:'persona-inbox.read_message',
    result:{content:[{type:'text',text:JSON.stringify({ok:true,
      event_id:'40000000-0000-4000-8000-000000000001',message_id:2,owner_persona_id:13,
      owner_role:'admin',subject:'other',body:'private',body_sha256:'c'.repeat(64),
      acl:{version:1,mode:'advisory',decision:'deny',cross_persona:true,disclosed:true}})}]}}]},3).accesses,[]);
});

test('provisioning can resolve installation-specific persona IDs instead of assuming seed keys', async () => {
  const calls = [];
  const application = createSecureShopPersonaInboxApplication({
    launches: { assertCurrent: async () => {}, reservePersonaInboxTarget: async () => target },
    repository: { async provision(_target, options) { calls.push(options.fixtures); }, async list() { return []; },
      async readAcl() { return { version: 1, mode: 'advisory' }; }, async advanceAcl() {} },
    conversations: { async create() { return { id: 'conversation' }; } }, runner: { async run() { return { hops: [], stopReason: 'end_turn' }; } },
    resolveFixtures: async () => [
      { fixtureKey: 'customer-note', owner: { id: 8101, role: 'customer' }, subject: 'a', body: 'a' },
      { fixtureKey: 'merchant-note', owner: { id: 9202, role: 'merchant' }, subject: 'b', body: 'b' },
      { fixtureKey: 'admin-note', owner: { id: 7303, role: 'admin' }, subject: 'c', body: 'c' },
    ], authorizeAclTransition: async () => () => {},
    requestAuthority: createSecureShopPersonaInboxRequestAuthority(), availability: alwaysAvailable,
  });
  await application.status({ scope, persona: { id: 9202, role: 'merchant' } });
  assert.deepEqual(calls[0].map(row => row.owner), [
    { id: 8101, role: 'customer' }, { id: 9202, role: 'merchant' }, { id: 7303, role: 'admin' },
  ]);
});

test('concurrent requests carry independent selected-message authorities and revoke both on settlement', async () => {
  const authority = createSecureShopPersonaInboxRequestAuthority();
  const observed=[];const releases=[];
  const application=createSecureShopPersonaInboxApplication({
    launches:{async assertCurrent(){},async reservePersonaInboxTarget(){return target;}},
    repository:{async provision(){},async list(){return [
      {messageId:1,ownerShopUserId:11,ownerShopRole:'customer',subject:'one'},
      {messageId:3,ownerShopUserId:13,ownerShopRole:'admin',subject:'three'}];},
      async readAcl(){return{version:1,mode:'advisory'};},async advanceAcl(){}},
    conversations:{async create(){return{id:'60000000-0000-4000-8000-000000000001'};}},
    runner:{async run(input){observed.push([input,authority.resolve(input.localToolAuthority,{binding:{...input.scope,
      shopUserId:input.persona.id,role:input.persona.role},sessionId:input.sessionId,requestId:input.requestId})]);
      await new Promise(resolve=>releases.push(resolve));return{hops:[],stopReason:'end_turn'};}},
    fixtures,requestAuthority:authority,authorizeAclTransition:async()=>()=>{},availability:alwaysAvailable,
  });
  const requests=['50000000-0000-4000-8000-000000000001','50000000-0000-4000-8000-000000000002'];
  const pending=[1,3].map((messageId,index)=>application.run({scope,persona:{id:12,role:'merchant'},
    requestId:requests[index],messageId}));
  while(observed.length<2) await new Promise(resolve=>setImmediate(resolve));
  assert.deepEqual(observed.map(row=>row[1].messageId).sort(),[1,3]);
  releases.splice(0).forEach(resolve=>resolve());await Promise.all(pending);
  for(const [input] of observed) assert.throws(()=>authority.resolve(input.localToolAuthority,{binding:{...input.scope,
    shopUserId:input.persona.id,role:input.persona.role},sessionId:input.sessionId,requestId:input.requestId}),
  {code:'PERSONA_INBOX_REQUEST_AUTHORITY_UNAVAILABLE'});
});

test('an unlisted message is rejected before conversation, authority, or runner admission',async()=>{
  const {application,calls}=setup();
  await assert.rejects(application.run({scope,persona:{id:12,role:'merchant'},
    requestId:'50000000-0000-4000-8000-000000000001',messageId:2}),{code:'INVALID_ARGUMENT'});
  assert.equal(calls.some(call=>call[0]==='conversation'||call[0]==='run'),false);
});

test('hidden and selectively enabled catalog state fails closed before effects',async()=>{
  const fixture=setup();fixture.hide();
  assert.deepEqual(await fixture.application.status({scope,persona:{id:12,role:'merchant'}}),{ready:false});
  assert.equal(fixture.calls.some(call=>call[0]==='reserve'||call[0]==='provision'),false,
    'hidden status cannot provision an owned target');
  await assert.rejects(fixture.application.run({scope,persona:{id:12,role:'merchant'},
    requestId:'50000000-0000-4000-8000-000000000001',messageId:3}),
  {code:'PERSONA_INBOX_EXERCISE_UNAVAILABLE'});
  assert.equal(fixture.calls.some(call=>call[0]==='conversation'||call[0]==='run'),false);
});

test('the exact objective set gates advisory read and ACL transition independently',async()=>{
  const advisory=setup();advisory.enabled.delete('ss_acl_advisory_effect');
  assert.deepEqual(await advisory.application.status({scope,persona:{id:12,role:'merchant'}}),{ready:false});
  await assert.rejects(advisory.application.run({scope,persona:{id:12,role:'merchant'},
    requestId:'50000000-0000-4000-8000-000000000001',messageId:3}),
  {code:'PERSONA_INBOX_EXERCISE_UNAVAILABLE'});
  assert.equal(advisory.calls.some(call=>call[0]==='conversation'||call[0]==='run'),false);
  const enforced=setup();enforced.enabled.delete('ss_acl_enforced_block');
  const status=await enforced.application.status({scope,persona:{id:12,role:'merchant'}});
  assert.equal(status.ready,true);assert.equal(status.capabilities.enforceAcl,false);
  await assert.rejects(enforced.application.enforce({scope,persona:{id:12,role:'merchant'}}),
    {code:'PERSONA_INBOX_EXERCISE_UNAVAILABLE'});
  assert.equal(enforced.calls.some(call=>call[0]==='advance'),false);
});

test('hide after runner admission suppresses the result and exact replay without accepting stale availability',async()=>{
  let fixture;fixture=setup({onRun:async()=>fixture.hide()});
  await assert.rejects(fixture.application.run({scope,persona:{id:12,role:'merchant'},
    requestId:'50000000-0000-4000-8000-000000000001',messageId:3}),
  {code:'PERSONA_INBOX_EXERCISE_UNAVAILABLE'});
  assert.equal(fixture.calls.filter(call=>call[0]==='run').length,1);
  await assert.rejects(fixture.application.run({scope,persona:{id:12,role:'merchant'},
    requestId:'50000000-0000-4000-8000-000000000001',messageId:3}),
  {code:'PERSONA_INBOX_EXERCISE_UNAVAILABLE'});
  assert.equal(fixture.calls.filter(call=>call[0]==='run').length,1,
    'a hidden replay is rejected before another runner admission');
});
