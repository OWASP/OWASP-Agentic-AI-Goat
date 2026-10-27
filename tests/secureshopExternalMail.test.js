'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const C = require('../server/services/secureshopExternalMailContract');
const {createExternalMailApplication,projectExternalMailOperation} = require('../server/services/secureshopExternalMail');
const {createExternalMailRepository} = require('../server/database/postgres/secureshopExternalMailRepository');
const ID = '11111111-1111-4111-8111-111111111111', SCOPE = 'a'.repeat(64);
function setup() {
  let row, sends=0, available=true, revoked=false, failSend=false, failSettle=false, block;
  const a = {principalId:ID,authSessionId:7,scopeKey:SCOPE,expiresAt:Date.now()+60000,binding:{}};
  const current = async()=>{if(revoked)throw C.error('EXTERNAL_MAIL_SCOPE_STALE');return a;};
  const repository = {
    assertReady:async()=>{},read:async()=>row||null,
    prepare:async(_a,p,sha)=> row ||= {operation_id:p.operationId,preview:p,scope_key:SCOPE,
      request_sha256:sha,state:'prepared',expires_at:new Date(Date.now()+60000),smtp:null},
    claim:async()=>{if(row.state!=='prepared')return{claimed:false,row};
      row={...row,state:'dispatching'};return{claimed:true,row};},
    cancel:async()=>{if(row.state!=='prepared')throw C.error('EXTERNAL_MAIL_RECOVERY_REQUIRED');
      return row={...row,state:'cancelled'};},
    settle:async(_id,state,smtp)=>{if(failSettle)throw Error('controlled settlement failure');
      return row={...row,state,smtp};},
  };
  const authority = {capture:current,assertCurrent:current,
    withDispatch:async(_a,work,options)=>{await current();return work(options);}};
  const transport = {isAvailable:()=>available,send:async(p,{signal,deadlineAt})=>{
    sends++;assert.ok(deadlineAt<=Date.now()+C.DISPATCH_MS);assert.equal(signal.aborted,false);
    if(block)await block;if(failSend)throw Error('provider private detail');
    return{smtpAccepted:true,deliveryConfirmed:false,messageId:'<synthetic@test>',accepted:[p.recipient],rejected:[]};
  }};
  const app = createExternalMailApplication({repository,authority,transport,sender:'sender@gmail.com'});
  const prepare = ()=>app.prepare({}, {version:1,operationId:ID,recipient:'receiver@sharklasers.com',scopeKey:SCOPE});
  const confirm = ()=>app.confirm({}, {version:1,operationId:ID,requestSha256:row.request_sha256});
  return{app,prepare,confirm,repository,authority,transport,get row(){return row;},get sends(){return sends;},
    set available(v){available=v;},set revoked(v){revoked=v;},set failSend(v){failSend=v;},
    set failSettle(v){failSettle=v;},set block(v){block=v;}};
}
test('disabled readiness never captures/provisions authority or contacts SMTP',async()=>{
  const f=setup();f.available=false;f.authority.capture=()=>{throw Error('must not capture');};
  assert.deepEqual(await f.app.readiness({}),{version:1,available:false,reason:'not_configured'});
  assert.equal(f.sends,0);
});
test('prepare/read/cancel have no SMTP effect; cancel is not a send instruction',async()=>{
  const f=setup(),draft=await f.prepare();assert.equal(draft.state,'prepared');
  assert.equal((await f.app.read({},ID)).requestSha256,draft.requestSha256);
  assert.equal((await f.app.cancel({},{version:1,operationId:ID,requestSha256:draft.requestSha256})).state,'cancelled');
  assert.equal((await f.confirm()).state,'cancelled');assert.equal(f.sends,0);
});
test('accepted SMTP is explicitly not delivered; duplicate same operation never resends',async()=>{
  const f=setup();await f.prepare();const receipt=await f.confirm();
  assert.equal(receipt.state,'smtp_accepted');assert.equal(receipt.smtp.deliveryConfirmed,false);
  assert.deepEqual(await f.confirm(),receipt);assert.equal(f.sends,1);
});
test('concurrent same-ID confirm performs at most one dispatch, other reads durable dispatching',async()=>{
  const f=setup();let finish;f.block=new Promise(r=>{finish=r;});await f.prepare();
  const pending=f.confirm();await new Promise(setImmediate);
  assert.equal((await f.confirm()).state,'dispatching');assert.equal(f.sends,1);
  finish();await pending;assert.equal(f.sends,1);
});
test('revocation after durable claim and before lease has zero SMTP and known pre-dispatch denial',async()=>{
  const f=setup();await f.prepare();const old=f.repository.claim;
  f.repository.claim=async(...args)=>{const claim=await old(...args);f.revoked=true;return claim;};
  assert.equal((await f.confirm()).state,'rejected_before_dispatch');assert.equal(f.sends,0);
});
test('expired dispatch deadline has zero SMTP',async()=>{
  const f=setup();await f.prepare();
  f.authority.withDispatch=async(_a,work)=>work({deadlineAt:Date.now()-1});
  assert.equal((await f.confirm()).state,'rejected_before_dispatch');assert.equal(f.sends,0);
});
test('post-entry failure is unknown and no retry occurs',async()=>{
  const f=setup();await f.prepare();f.failSend=true;
  const result=await f.confirm();assert.equal(result.state,'unknown');assert.equal(result.smtp,null);
  assert.equal(JSON.stringify(result).includes('provider private detail'),false);
  assert.equal((await f.confirm()).state,'unknown');assert.equal(f.sends,1);
});
test('lost local settlement keeps dispatching and does not resend',async()=>{
  const f=setup();await f.prepare();f.failSettle=true;await assert.rejects(f.confirm(),/settlement/);
  assert.equal(f.row.state,'dispatching');assert.equal((await f.confirm()).state,'dispatching');assert.equal(f.sends,1);
});
test('retained null read is still followed by current-authority validation',async()=>{
  const f=setup();f.repository.read=async()=>{f.revoked=true;return null;};
  await assert.rejects(f.app.read({},ID),{code:'EXTERNAL_MAIL_SCOPE_STALE'});assert.equal(f.sends,0);
});
test('immutable receipt projection rejects changed body or fabricated delivery',async()=>{
  const f=setup();await f.prepare();
  assert.throws(()=>projectExternalMailOperation({...f.row,preview:{...f.row.preview,text:'secret'}}));
  const result=await f.confirm();assert.equal(result.smtp.deliveryConfirmed,false);
  assert.throws(()=>projectExternalMailOperation({...f.row,smtp:{...f.row.smtp,deliveryConfirmed:true}}));
});
function sqlRepository(value,{now=new Date(),afterLock}={}) {
  const calls=[];const c={query:async(sql,args)=>{
    calls.push({sql,args});
    if(sql.startsWith('SELECT *')){
      if(afterLock)value=await afterLock(value);
      return{rows:value?[value]:[]};
    }
    if(sql==='SELECT clock_timestamp() AS now')return{rows:[{now}]};
    if(sql.startsWith('UPDATE'))return{rows:[{...value,state:args[1]}]};
    return{rows:[]};
  },release:()=>calls.push({sql:'release'})};
  return{calls,repo:createExternalMailRepository({pool:{query:c.query,connect:async()=>c}})};
}
test('repository retained GET survives session/scope change only for original principal',async()=>{
  const f=sqlRepository({principal_id:ID,auth_session_id:1,scope_key:'b'.repeat(64),expires_at:new Date(Date.now()+60000)});
  assert.ok(await f.repo.read({principalId:ID,authSessionId:99,scopeKey:SCOPE},ID));
  await assert.rejects(f.repo.read({principalId:'other'},ID),{code:'EXTERNAL_MAIL_NOT_FOUND'});
  assert.equal(f.calls.some(x=>/^(?:UPDATE|INSERT|DELETE)\b/.test(x.sql)),false);
  assert.ok(f.calls.some(x=>x.sql.endsWith('FOR UPDATE')));
});
test('GET expiry uses locked persisted state and fresh database clock without state/quota mutation',async()=>{
  const past=new Date('2020-01-01T00:00:00Z'),now=new Date('2020-01-01T00:01:00Z');
  for(const state of ['prepared','dispatching','unknown','cancelled','smtp_accepted','rejected_before_dispatch']){
    const value={principal_id:ID,state,expires_at:past};
    const f=sqlRepository(value,{now}),read=await f.repo.read({principalId:ID},ID);
    assert.equal(read.state,state);assert.equal(read.derivedExpired,state==='prepared');
    assert.equal(value.derivedExpired,undefined);assert.equal(value.state,state);
    const lock=f.calls.findIndex(x=>x.sql.startsWith('SELECT *'));
    const clock=f.calls.findIndex(x=>x.sql==='SELECT clock_timestamp() AS now');
    assert.match(f.calls[lock].sql,/FOR UPDATE$/);assert.ok(clock>lock);
    assert.equal(f.calls.some(x=>/^(?:UPDATE|INSERT|DELETE)\b|advisory/.test(x.sql)),false);
  }
});
test('GET read after a concurrent claim lock returns dispatching, never stale expired draft',async()=>{
  const f=sqlRepository({principal_id:ID,state:'prepared',expires_at:new Date('2020-01-01')},{
    now:new Date('2020-01-02'),afterLock:async value=>({...value,state:'dispatching'})});
  const result=await f.repo.read({principalId:ID},ID);
  assert.equal(result.state,'dispatching');assert.equal(result.derivedExpired,false);
});
test('unexpired GET does not use application clock or authorize retry',async()=>{
  const f=sqlRepository({principal_id:ID,state:'prepared',expires_at:new Date('2020-01-02')},
    {now:new Date('2020-01-01')});
  const value=await f.repo.read({principalId:ID},ID);assert.equal(value.derivedExpired,false);
  assert.equal(value.state,'prepared'); // Both timestamps are in the host's past.
});
test('only GET exposes authoritative expired projection; unknown/dispatching cannot be made expired',async()=>{
  const f=setup();await f.prepare();
  f.repository.read=async()=>({...f.row,derivedExpired:true});
  const result=await f.app.read({},ID);assert.equal(result.state,'expired');assert.equal(result.smtp,null);
  assert.equal(f.row.state,'prepared');assert.equal(f.sends,0);
  assert.equal(projectExternalMailOperation({...f.row,derivedExpired:true}).state,'prepared');
  for(const state of ['unknown','dispatching']){
    f.repository.read=async()=>({...f.row,state,derivedExpired:true});
    await assert.rejects(f.app.read({},ID),{code:'EXTERNAL_MAIL_UNAVAILABLE'});
    assert.equal(projectExternalMailOperation({...f.row,state,derivedExpired:true}).state,state);
  }
});
test('repository mutation still rejects changed auth session and scope',async()=>{
  for(const authority of [{principalId:ID,authSessionId:2,scopeKey:SCOPE},
    {principalId:ID,authSessionId:1,scopeKey:'b'.repeat(64)}]){
    const f=sqlRepository({principal_id:ID,auth_session_id:1,scope_key:SCOPE});
    await assert.rejects(f.repo.cancel(authority,{operationId:ID,requestSha256:SCOPE}),
      {code:'EXTERNAL_MAIL_SCOPE_STALE'});
    assert.ok(f.calls.some(x=>x.sql==='ROLLBACK'));
  }
});
test('settlement uses bounded separate transaction and cannot update terminal receipt',async()=>{
  const f=sqlRepository({state:'dispatching'});
  await f.repo.settle(ID,'unknown');
  assert.deepEqual(f.calls.slice(0,3).map(x=>x.sql),['BEGIN',
    "SET LOCAL statement_timeout='3000ms'","SET LOCAL lock_timeout='3000ms'"]);
  assert.match(f.calls[3].sql,/state='dispatching'/);
  assert.equal(f.calls.at(-2).sql,'COMMIT');assert.equal(f.calls.at(-1).sql,'release');
});
