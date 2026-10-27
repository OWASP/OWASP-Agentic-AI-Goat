'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {createExternalMailAuthority}=require('../server/database/postgres/secureshopExternalMailAuthority');
const {createSecureShopStandaloneAuthService}=require('../server/services/secureshopStandaloneAuth');
const {createSecureShopBoundPersonaAuthority}=require('../server/database/postgres/secureshopBoundPersonaAuthority');
const scope={launchId:'11111111-1111-4111-8111-111111111111',scenarioId:'22222222-2222-4222-8222-222222222222',
  generation:1,platformOwnerId:7,platformSessionId:8};
async function fixture() {
  const calls=[];let live=true,personaLive=true,onLock;
  const future=new Date(Date.now()+60000).toISOString();
  const source={principalId:'33333333-3333-4333-8333-333333333333',ownerId:11,sessionId:12,shopUserId:13,
    role:'merchant',username:'merchant',email:'merchant@test',credentialVersion:'1',authorityVersion:'1',expiresAt:future};
  const repository=Object.fromEntries(['registerWithSession','findCredential','recordFailedLogin',
    'createSession','rotateSession','revokeSession','readCredentialForSession','changePassword','revokeAll',
    'readOrCreateDefaultExecutionSession'].map(name=>[name,async()=>assert.fail(`Unexpected ${name}`)]));
  repository.readCurrentSession=async()=>source;
  const authService=createSecureShopStandaloneAuthService({repository});
  const principal=await authService.authenticate('a'.repeat(43));
  const row={tenant_id:'44444444-4444-4444-8444-444444444444',membership_version:'1',
    credential_version:'1',authority_version:'1',selection_revision:'1',
    scene_id:'55555555-5555-4555-8555-555555555555',scene_generation:'1',
    grant_id:'66666666-6666-4666-8666-666666666666',mode:'vuln',mode_revision:'1',
    launch_credential_version:'1',expires_at:future};
  const identity={query:async(sql,args)=>{
    calls.push({store:'identity',sql,args});
    if(onLock&&sql.includes('FOR UPDATE')){const action=onLock;onLock=null;action();}
    return {rows:sql.startsWith('SELECT e.tenant_id')?(live?[{...row}]:[]):[],rowCount:1};
  },release:()=>calls.push({store:'identity',sql:'release'})};
  const agents={query:async(sql,args)=>{
    calls.push({store:'agents',sql,args});
    if(sql.startsWith('SELECT 1 FROM'))return{rowCount:personaLive?1:0};
    return {rows:[{id:13,role:'merchant',authority_version:'1',banned_at:null}]};
  },release:()=>calls.push({store:'agents',sql:'release'})};
  const personaAuthority=createSecureShopBoundPersonaAuthority({pool:{connect:async()=>agents},checkCurrent:async()=>{}});
  const authority=createExternalMailAuthority({pool:{query:identity.query,connect:async()=>identity},
    personaAuthority,sender:'sender@gmail.com'});
  const context={principal,scope,persona:{id:13,role:'merchant'},
    personaSession:{sessionId:'77777777-7777-4777-8777-777777777777',authorityVersion:'1',expiresAt:future}};
  return {authority,context,calls,row,set live(v){live=v;},set personaLive(v){personaLive=v;},set onLock(v){onLock=v;}};
}
test('authority rejects forged cookie principal, mismatched persona and nonmerchant',async()=>{
  const f=await fixture();
  for(const context of [{...f.context,principal:{...f.context.principal}},
    {...f.context,persona:{id:99,role:'merchant'}},{...f.context,persona:{id:13,role:'admin'}}])
    await assert.rejects(f.authority.capture(context),{code:'SHOP_AUTH_INVALID'});
});
test('read-only capture binds exact retained mode/scene/selection/auth identity without writes',async()=>{
  const f=await fixture(),a=await f.authority.capture(f.context);
  assert.match(a.scopeKey,/^[a-f0-9]{64}$/);assert.equal(a.binding.authSessionId,12);
  assert.equal(a.binding.platformSessionId,8);assert.equal(a.binding.sceneId,f.row.scene_id);
  assert.equal(f.calls.some(x=>/\b(?:INSERT|UPDATE|DELETE)\b/.test(x.sql)),false);
  const sql=f.calls.find(x=>x.sql.startsWith('SELECT e.tenant_id')).sql;
  assert.match(sql,/m.role='merchant'/);assert.match(sql,/e\.session_id=\$5/);
  assert.match(sql,/p.principal_id=\$6 AND s.session_id=\$7/);
  assert.match(sql,/sc.status='active'/);assert.match(sql,/g.scene_generation=sc.scene_generation/);
});
for(const key of ['mode_revision','selection_revision','scene_id','grant_id','membership_version','credential_version','launch_credential_version'])
 test(`changed ${key} invalidates captured send authority`,async()=>{
  const f=await fixture(),a=await f.authority.capture(f.context);
  f.row[key]='changed';await assert.rejects(f.authority.assertCurrent(a),{code:'EXTERNAL_MAIL_SCOPE_STALE'});
 });
test('dispatch uses actual persona locks before identity lifecycle locks and no source-row locks',async()=>{
  const f=await fixture(),a=await f.authority.capture(f.context);f.calls.length=0;
  await f.authority.withDispatch(a,async()=>{
    f.calls.push({store:'effect',sql:'SMTP'});
  },{deadlineAt:Date.now()+10000});
  const relevant=f.calls.filter(x=>/advisory|FOR UPDATE|FOR SHARE|lock_external|SMTP/.test(x.sql));
  assert.equal(relevant[0].args[0],'secureshop-bound-audit-owner:7');
  assert.equal(relevant[1].args[0],`secureshop-conversation-admission:${scope.launchId}`);
  assert.match(relevant[2].sql,/authority_owners/);assert.match(relevant[3].sql,/authority_sessions/);
  assert.match(relevant[4].sql,/secureshop_launches/);assert.match(relevant[5].sql,/secureshop_scenes/);
  assert.match(relevant[6].sql,/practice_selections/);assert.match(relevant[7].sql,/lock_external_mail_mode/);
  assert.equal(relevant[8].sql,'SMTP');
  assert.equal(f.calls.some(x=>/secureshop_auth\.(principals|sessions).*FOR (UPDATE|SHARE)/.test(x.sql)),false);
  assert.equal(f.calls.filter(x=>x.sql==="SET LOCAL lock_timeout='3000ms'").length,2);
  assert.equal(f.calls.at(-1).store,'agents');assert.equal(f.calls.at(-1).sql,'release');
});
test('identity revocation while waiting for lease prevents effect and releases both stores',async()=>{
  const f=await fixture(),a=await f.authority.capture(f.context);f.calls.length=0;f.onLock=()=>{f.live=false;};
  let sends=0;
  await assert.rejects(f.authority.withDispatch(a,async()=>{sends++;},{deadlineAt:Date.now()+10000}),
    {code:'EXTERNAL_MAIL_SCOPE_STALE'});
  assert.equal(sends,0);assert.equal(f.calls.filter(x=>x.sql==='ROLLBACK').length,2);
});
test('persona revoke before external lease prevents identity locks and effect',async()=>{
  const f=await fixture(),a=await f.authority.capture(f.context);f.calls.length=0;f.personaLive=false;
  await assert.rejects(f.authority.withDispatch(a,()=>assert.fail('no SMTP'),{deadlineAt:Date.now()+10000}),
    {code:'SHOP_AUTH_INVALID'});
  assert.equal(f.calls.some(x=>x.store==='identity'),false);
});
test('external persona lease rejects missing/expired/oversized absolute deadline',async()=>{
  const f=await fixture(),a=await f.authority.capture(f.context);
  for(const deadlineAt of [undefined,NaN,Date.now()-1,Date.now()+30000])
    await assert.rejects(f.authority.withDispatch(a,()=>assert.fail('no SMTP'),{deadlineAt}));
});
