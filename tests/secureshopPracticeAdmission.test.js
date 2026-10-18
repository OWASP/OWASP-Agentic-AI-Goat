'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createSecureShopStandaloneAuthService } = require('../server/services/secureshopStandaloneAuth');
const { createSecureShopPracticeAdmissionRepository, assertPracticeAdmission } = require('../server/database/postgres/secureshopPracticeAdmissionRepository');
const { createSecureShopPracticeAdmission } = require('../server/services/secureshopPracticeAdmission');
const id = '00000000-0000-4000-8000-000000000001';
const principalId = '00000000-0000-4000-8000-000000000002';
const tenantId = '00000000-0000-4000-8000-000000000003';
const sourceScene = '00000000-0000-4000-8000-000000000004';
async function base(sessionId = 10) {
  const methods = ['registerWithSession','findCredential','recordFailedLogin','createSession','rotateSession',
    'revokeSession','readCredentialForSession','changePassword','revokeAll','readOrCreateDefaultExecutionSession'];
  const repository = Object.fromEntries(methods.map(name => [name, async () => { throw Error('unexpected auth effect'); }]));
  repository.readCurrentSession = async () => ({ principalId,ownerId:9,sessionId,shopUserId:1000000001,
    username:'customer',email:'customer@shop.invalid',role:'customer',credentialVersion:'1',authorityVersion:'1',
    expiresAt:'2099-01-01T00:00:00.000Z' });
  return createSecureShopStandaloneAuthService({ repository }).authenticate('x'.repeat(43));
}
function database() {
  const calls = [];
  const state = { operation:null, published:null, active:true, resumable:true, selection:true, capacity:false, failCommit:false, preferenceRevision:'1' };
  let before;
  async function query(sql, args = []) {
    calls.push({ sql, args });
    if (sql === 'BEGIN') { before = { operation:state.operation,published:state.published }; return { rows:[] }; }
    if (sql === 'ROLLBACK') { Object.assign(state,before); return { rows:[] }; }
    if (sql === 'COMMIT') { if (state.failCommit) throw Error('commit response lost'); return { rows:[] }; }
    if (sql.includes('SELECT s.session_id,t.tenant_id')) return { rows:state.active ? [{ session_id:args[0],
      tenant_id:tenantId,owner_id:91,seed_merchant_id:1000000002,membership_version:'1',principal_id:principalId,
      expires_at:'2099-01-01T00:00:00.000Z' }] : [] };
    if (sql.includes('SELECT o.*,p.scene_id')) return { rows:state.operation?.operation_id === args[0]
      ? [{ ...state.operation,published_scene_id:state.published }] : [] };
    if (sql.includes('SELECT x.*,l.launch_id')) return { rows:state.selection ? [{ auth_session_id:10,
      tenant_id:tenantId,principal_id:principalId,execution_session_id:20,scene_id:sourceScene,revision:'1',preference_revision:'1',
      launch_id:'00000000-0000-4000-8000-000000000005',generation:'1' }] : [] };
    if (sql.startsWith('SELECT 1 FROM secureshop_auth.practice_operations')) return { rows:[],rowCount:state.operation ? 1 : 0 };
    if (sql.includes('AS launches,')) return { rows:[{ launches:state.capacity ? 256 : 1,products:1 }] };
    if (sql.startsWith('INSERT INTO secureshop_auth.execution_sessions')) return { rows:[{ session_id:21 }],rowCount:1 };
    if (sql.startsWith('INSERT INTO secureshop_auth.practice_operations')) {
      const keys = ['operation_id','tenant_id','principal_id','auth_session_id','membership_version',
        'source_execution_id','source_launch_id','source_generation','source_scene_id','source_selection_revision',
        'execution_session_id','launch_id','scenario_id','owner_id','target_id','scene_id','source_preference_revision'];
      state.operation = { ...Object.fromEntries(keys.map((key,index) => [key,args[index]])),generation:1 };
    }
    if (sql.includes('SELECT x.auth_session_id FROM')) return { rows:[],rowCount:state.resumable && String(args[13]) === state.preferenceRevision ? 1 : 0 };
    if (sql.startsWith('INSERT INTO secureshop_auth.practice_publications')) state.published = args[1];
    return { rows:[],rowCount:1 };
  }
  return { state,calls,pool:{ query,connect:async () => ({ query,release() {} }) } };
}
test('unbranded caller cannot admit or read practice operations', async () => {
  const f = database(), repo = createSecureShopPracticeAdmissionRepository({ pool:f.pool });
  await assert.rejects(repo.admit({}, id), { code:'SHOP_AUTH_INVALID' });
  assert.ok(!f.calls.some(call => call.sql.startsWith('INSERT')));
});
test('capacity is checked before any resource or operation insertion and rolls back', async () => {
  const f = database(); f.state.capacity = true;
  const repo = createSecureShopPracticeAdmissionRepository({ pool:f.pool });
  await assert.rejects(repo.admit(await base(), id), { code:'SHOP_PRACTICE_CAPACITY' });
  assert.ok(!f.calls.some(call => call.sql.startsWith('INSERT')));
  assert.ok(f.calls.some(call => call.sql === 'ROLLBACK'));
});
test('admission is immutable and replay never allocates a second execution or target', async () => {
  const f = database(), repo = createSecureShopPracticeAdmissionRepository({ pool:f.pool }), actor = await base();
  assert.deepEqual(await repo.admit(actor, id), { operationId:id,status:'pending',sceneId:null,canResume:true });
  const original = { ...f.state.operation };
  assert.equal((await repo.admit(actor, id)).status,'pending');
  assert.deepEqual(f.state.operation, original);
  assert.equal(f.calls.filter(call => call.sql.startsWith('INSERT INTO secureshop_auth.execution_sessions')).length,1);
  assert.equal(f.calls.filter(call => call.sql.startsWith('INSERT INTO identity.secureshop_target_reservations')).length,1);
});
test('renewed cookie reads retained unfinished admission without provisioning or reparenting', async () => {
  const f = database(), repo = createSecureShopPracticeAdmissionRepository({ pool:f.pool });
  await repo.admit(await base(), id);
  let effects = 0;
  assert.deepEqual(await repo.publish(await base(11), id, async () => { effects += 1; }),
    { operationId:id,status:'retained_unfinished',sceneId:null,canResume:false });
  assert.equal((await repo.read(await base(11), id)).status,'retained_unfinished');
  assert.equal(effects,0); assert.equal(f.state.operation.auth_session_id,10);
});
test('changed selection denies publication but preserves admitted resource identity', async () => {
  const f = database(), repo = createSecureShopPracticeAdmissionRepository({ pool:f.pool }), actor = await base();
  await repo.admit(actor,id); f.state.resumable = false;
  let effects = 0;
  assert.equal((await repo.publish(actor,id,async () => { effects += 1; })).status,'retained_unfinished');
  assert.equal(effects,0); assert.equal(f.state.published,null);
});
test('real provision failure leaves the claimed target recoverable and publishes no scene', async () => {
  const f = database(), repo = createSecureShopPracticeAdmissionRepository({ pool:f.pool }), actor = await base();
  await repo.admit(actor,id);
  const target = f.state.operation.target_id;
  await assert.rejects(repo.publish(actor,id,async claim => {
    assert.equal(assertPracticeAdmission(claim).binding.targetId,target);
    throw Error('target response unavailable');
  }), /target response unavailable/);
  assert.equal(f.state.operation.target_id,target);
  assert.equal((await repo.read(actor,id)).status,'pending');
  assert.ok(!f.calls.some(call => call.sql.startsWith('INSERT INTO identity.secureshop_scenes')));
});
test('publication binds exact target evidence, revokes private claim, and replay is effect-free', async () => {
  const f = database(), repo = createSecureShopPracticeAdmissionRepository({ pool:f.pool }), actor = await base();
  let effects = 0, captured;
  const service = createSecureShopPracticeAdmission({ repository:repo,catalog:{ provisionPracticeTarget:async claim => {
    effects += 1; captured = claim; assertPracticeAdmission(claim);
    return { targetId:claim.binding.targetId,sourceSha256:'a'.repeat(64) };
  } } });
  const result = await service.create(actor,id);
  assert.equal(result.status,'published'); assert.equal(result.sceneId,f.state.operation.scene_id);
  assert.throws(() => assertPracticeAdmission(captured), { code:'SHOP_PRACTICE_CONFLICT' });
  // Replay after selection changed is still the original committed result.
  f.state.resumable = false;
  assert.deepEqual(await service.create(actor,id),result);
  assert.deepEqual(await service.read(await base(11),id),result);
  assert.equal(effects,1);
  const sceneInsert = f.calls.findIndex(call => call.sql.startsWith('INSERT INTO identity.secureshop_scenes'));
  const publishInsert = f.calls.findIndex(call => call.sql.startsWith('INSERT INTO secureshop_auth.practice_publications'));
  assert.ok(sceneInsert > 0 && publishInsert > sceneInsert);
  assert.ok(f.calls.slice(sceneInsert,publishInsert).every(call => call.sql !== 'COMMIT'));
});
test('mismatched target receipt rolls publication back without clearing admission', async () => {
  const f = database(), repo = createSecureShopPracticeAdmissionRepository({ pool:f.pool }), actor = await base();
  await repo.admit(actor,id);
  await assert.rejects(repo.publish(actor,id,async () => ({ targetId:id,sourceSha256:'a'.repeat(64) })),
    { code:'SHOP_PRACTICE_CONFLICT' });
  assert.equal(f.state.published,null); assert.ok(f.state.operation);
});
test('different principal or tenant cannot adopt an existing UUID', async () => {
  const f = database(), repo = createSecureShopPracticeAdmissionRepository({ pool:f.pool }), actor = await base();
  await repo.admit(actor,id); f.state.operation.principal_id = '00000000-0000-4000-8000-000000000099';
  await assert.rejects(repo.read(actor,id), { code:'SHOP_PRACTICE_CONFLICT' });
  await assert.rejects(repo.admit(actor,id), { code:'SHOP_PRACTICE_CONFLICT' });
});


test('different UUID cannot allocate competing debt from the same selected execution', async () => {
  const f=database(),repo=createSecureShopPracticeAdmissionRepository({pool:f.pool}),actor=await base();
  await repo.admit(actor,id);
  await assert.rejects(repo.admit(actor,'00000000-0000-4000-8000-000000000099'),{code:'SHOP_PRACTICE_CONFLICT'});
  assert.equal(f.calls.filter(call=>call.sql.startsWith('INSERT INTO secureshop_auth.execution_sessions')).length,1);
});
test('another session changing preferred scene prevents side effect and publication', async () => {
  const f=database(),repo=createSecureShopPracticeAdmissionRepository({pool:f.pool}),actor=await base();
  await repo.admit(actor,id);f.state.preferenceRevision='2';
  let effects=0;
  assert.equal((await repo.publish(actor,id,async()=>{effects+=1;})).status,'retained_unfinished');
  assert.equal(effects,0);assert.equal(f.state.operation.source_preference_revision,'1');
  assert.equal(f.state.published,null);
});
test('authority expiry during provision never publishes or replaces the retained admission', async () => {
  const f=database(),repo=createSecureShopPracticeAdmissionRepository({pool:f.pool}),actor=await base();
  await repo.admit(actor,id);const target=f.state.operation.target_id;
  await assert.rejects(repo.publish(actor,id,async claim=>{
    f.state.active=false;return{targetId:claim.binding.targetId,sourceSha256:'a'.repeat(64)};
  }),{code:'SHOP_AUTH_INVALID'});
  assert.equal(f.state.operation.target_id,target);assert.equal(f.state.published,null);
  assert.equal(f.calls.some(call=>call.sql.startsWith('INSERT INTO identity.secureshop_scenes')),false);
});
test('unknown publication commit is not reported as success and original admission is retained', async () => {
  const f=database(),repo=createSecureShopPracticeAdmissionRepository({pool:f.pool}),actor=await base();
  await repo.admit(actor,id);const target=f.state.operation.target_id;f.state.failCommit=true;
  await assert.rejects(repo.publish(actor,id,async claim=>({targetId:claim.binding.targetId,sourceSha256:'a'.repeat(64)})),/commit response lost/);
  assert.equal(f.state.operation.target_id,target);
});
test('practice service refuses missing real provisioning and journal dependencies',()=>{
  assert.throws(()=>createSecureShopPracticeAdmission({repository:{read(){},admit(){},publish(){}},catalog:{}}),TypeError);
  assert.throws(()=>createSecureShopPracticeAdmission({repository:{read(){},admit(){}},catalog:{provisionPracticeTarget(){}}}),TypeError);
});
