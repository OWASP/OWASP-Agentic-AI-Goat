'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {randomUUID}=require('node:crypto');
const {createBoundMailRepository,prepareSend}=require('../server/database/postgres/secureshopBoundMailRepository');
const {withMailCleanup}=require('../server/services/secureshopMailCleanup');
function binding(){return {scope:{launchId:randomUUID(),scenarioId:randomUUID(),generation:1,platformOwnerId:7,platformSessionId:8},targetId:randomUUID(),persona:{id:2,role:'merchant'},personaSession:{sessionId:randomUUID(),authorityVersion:'1'},mode:'vuln',operationId:randomUUID()};}
const message={from:'merchant@lab',to:'customer@lab',subject:'Hello',body_markdown:'<img src=x onerror="owned()">'};
function fixture({result,authorityError,afterError,postCommitError,cleanup,wrongBinding=false}={}){
 const queries=[];let effects=0;
 const pool={async query(sql,args){queries.push({sql,args});return {rows:[{result:cleanup}]};}};
 const personaAuthority={capture(raw){return {binding:{...raw.scope,personaId:wrongBinding?99:raw.personaId,role:raw.role,sessionId:raw.sessionId,authorityVersion:raw.authorityVersion},
  async assertRemoteAdmission(){if(postCommitError)throw postCommitError;},
  async withPersonaEffect(work){if(authorityError)throw authorityError;effects++;const value=await work({async query(sql,args){queries.push({sql,args});return {rows:[{result:typeof result==='function'?(args?result(args):undefined):result}]};}});if(afterError)throw afterError;return value;}};}};
 let cleanupAllowed=true;
 const repository=createBoundMailRepository({pool,personaAuthority,checkCleanup:async()=>{if(!cleanupAllowed)throw Error('canonical cleanup denied');}});
 return {repository,queries,get effects(){return effects;},denyCleanup(){cleanupAllowed=false;}};
}
function sendResult(args){return {ok:true,operationId:args[11],replayed:false,email_id:12,thread_id:12,receipt:{email_id:12,thread_id:12}};}
test('send stays inside exact persona transaction with SQL deadlines and bound parameters',async()=>{
 const b=binding(),f=fixture({result:sendResult});const r=await f.repository.send(b,message);
 assert.equal(r.email_id,12);assert.equal(f.effects,1);assert.match(f.queries[0].sql,/statement_timeout='3000ms'/);assert.match(f.queries[1].sql,/lock_timeout='3000ms'/);
 const args=f.queries[2].args;assert.deepEqual(args.slice(0,13),[b.targetId,b.scope.launchId,b.scope.scenarioId,1,7,8,2,b.personaSession.sessionId,'merchant','1','vuln',b.operationId,'send']);
 assert.equal(JSON.parse(args[13]).body_html,message.body_markdown);assert(!f.queries[2].sql.includes(message.body_markdown));
});
test('expected reply source is checked under the send transaction lock before first effect',async()=>{
 const b=binding(),seen=[],expectedSource={threadId:5,messageId:9,sha256:'a'.repeat(64)};
 const f=fixture({result:args=>{seen.push(args[12]);
  if(args[12]==='recover')return {found:false};
  if(args[12]==='browse')return {ok:true,operationId:args[11],replayed:false,
   receipt:{userId:2,messages:[{id:9,sha256:expectedSource.sha256}]},
   emails:[{id:9,thread_id:5}]};
  return sendResult(args);
 }});
 await f.repository.send(b,{...message,threadId:5},{expectedSource});
 assert.deepEqual(seen,['recover','browse','send']);assert.equal(f.effects,1);
 assert.equal(f.queries.filter(q=>q.sql.includes('bound_lab_mail(')).length,3);
 const wrong=fixture({result:args=>args[12]==='recover'?{found:false}:{ok:true,
  operationId:args[11],replayed:false,receipt:{userId:2,messages:[{id:10,sha256:'b'.repeat(64)}]},
  emails:[{id:10,thread_id:5}]}});
 await assert.rejects(wrong.repository.send(b,{...message,threadId:5},{expectedSource}),
  {code:'MAIL_SOURCE_STALE',executionBoundary:true});
 assert.equal(wrong.queries.some(q=>q.args?.[12]==='send'),false);
 const noThread=fixture({result:sendResult});
 await assert.rejects(noThread.repository.send(b,message,{expectedSource}),{code:'INVALID_ARGUMENT'});
 assert.equal(noThread.effects,0);
});
test('committed send replay bypasses fresh-source check but still uses SQL request hash',async()=>{
 const b=binding(),seen=[],expectedSource={threadId:5,messageId:9,sha256:'a'.repeat(64)};
 const f=fixture({result:args=>{seen.push(args[12]);return args[12]==='recover'
  ?{found:true,operationId:b.operationId,action:'send',receipt:{email_id:12,thread_id:5},requestSha256:'b'.repeat(64)}
  :sendResult(args);}});
 await f.repository.send(b,{...message,threadId:5},{expectedSource});
 assert.deepEqual(seen,['recover','send']);
 assert.equal(f.queries.some(q=>q.args?.[12]==='browse'),false);
});
test('teaching HTML and CRLF remain stored data; arbitrary derived HTML and headers rejected',()=>{
 // @intentional-vulnerability xss-stored-email
 // @intentional-vulnerability html-injection
 // @intentional-vulnerability email-header-injection
 const p=prepareSend({...message,subject:'Hi\r\nBcc: admin@lab'});assert.match(p.headers_raw,/\r\nBcc:/);assert.equal(p.body_html,message.body_markdown);
 assert.throws(()=>prepareSend({...message,body_html:'fabricated'}),{code:'INVALID_ARGUMENT'});
 assert.throws(()=>prepareSend({...message,headers_raw:'fabricated'}),{code:'INVALID_ARGUMENT'});
});
test('oversized or foreign authority inputs fail before any effect',async()=>{
 const f=fixture({result:sendResult});await assert.rejects(f.repository.send({...binding(),persona:{id:0,role:'merchant'}},message));
 assert.throws(()=>f.repository.send(binding(),{...message,body_markdown:'x'.repeat(32769)}));assert.equal(f.effects,0);
 const wrong=fixture({wrongBinding:true});await assert.rejects(wrong.repository.send(binding(),message),{code:'SHOP_AUTH_INVALID'});assert.equal(wrong.effects,0);
});
test('revoked authority cannot execute or return a stale committed-looking response',async()=>{
 const before=fixture({authorityError:Error('revoked')});await assert.rejects(before.repository.send(binding(),message),/revoked/);assert.equal(before.queries.length,0);
 const after=fixture({afterError:Error('retired'),result:sendResult});await assert.rejects(after.repository.send(binding(),message),/retired/);
});
test('recovery uses only operation binding, no second send or source body',async()=>{
 const b=binding(),f=fixture({result:{found:false}});assert.deepEqual(await f.repository.recover(b),{found:false});
 assert.equal(f.queries[2].args[12],'recover');assert.equal(f.queries[2].args[13],'{}');
});
test('malformed success, foreign operation and missing persisted IDs fail closed',async()=>{
 for(const result of [{ok:true},{ok:true,operationId:randomUUID(),replayed:true,receipt:{}},sendResult(Array(12).fill(randomUUID()))]){
  await assert.rejects(fixture({result}).repository.send(binding(),message),{code:'MAIL_RECEIPT_INVALID'});
 }
});
test('within-target IDOR knob reaches parameterized read without being rewritten to caller',async()=>{
 // @intentional-vulnerability idor-inbox
 const b=binding(),f=fixture({result:args=>({ok:true,operationId:args[11],replayed:false,receipt:{userId:3,messages:[]},emails:[]})});
 await f.repository.read(b,3);assert.equal(JSON.parse(f.queries[2].args[13]).userId,3);assert.equal(f.queries[2].args[6],2);
});
test('canonical cleanup authorization required even for unprovisioned mail',async()=>{
 const f=fixture({cleanup:{provisioned:false}}),b=binding();f.denyCleanup();await assert.rejects(f.repository.verifyCleanup({...b.scope,targetId:b.targetId},randomUUID()),/denied/);assert.equal(f.queries.length,0);
});
test('cleanup receipt requires exact target and operation',async()=>{
 const b=binding(),operationId=randomUUID();const good={provisioned:true,targetId:b.targetId,operationId,deletedMessageCount:1,retainedOperationCount:2,evidenceSha256:'a'.repeat(64),receiptSha256:'b'.repeat(64)};
 assert.deepEqual(await fixture({cleanup:good}).repository.verifyCleanup({...b.scope,targetId:b.targetId},operationId),good);
 await assert.rejects(fixture({cleanup:{...good,targetId:randomUUID()}}).repository.verifyCleanup({...b.scope,targetId:b.targetId},operationId),{code:'MAIL_CLEANUP_MISMATCH'});
});
test('both cleanup and reconciliation verify mail after canonical receipt without changing original receipt',async()=>{
 const calls=[],receipt=Object.freeze({version:1,deletedMessageCount:3,receiptSha256:'original'}),scope={},options={operationId:randomUUID()};
 let blocked=false;
 const wrapped=withMailCleanup({cleanup:async()=>{calls.push('cleanup');return receipt;},readCleanupReceipt:async()=>{calls.push('reconcile');return receipt;},list:()=>12},
  {verifyCleanup:async(s,id)=>{assert.equal(s,scope);assert.equal(id,options.operationId);calls.push('mail');if(blocked)throw Error('mail mismatch');}});
 assert.equal(await wrapped.cleanup(scope,options),receipt);assert.equal(await wrapped.readCleanupReceipt(scope,options),receipt);assert.equal(wrapped.list(),12);
 assert.deepEqual(calls,['cleanup','mail','reconcile','mail']);blocked=true;await assert.rejects(wrapped.cleanup(scope,options),/mail mismatch/);await assert.rejects(wrapped.readCleanupReceipt(scope,options),/mail mismatch/);
});
const {createDurableMailCleanupVerifier}=require('../server/services/secureshopMailCleanup');
function lifecyclePool({table=null,provisioned=false,result,failQuery}={}){
 const calls=[];let releases=0;
 return {calls,get releases(){return releases;},async connect(){return {release(){releases++;},async query(sql,args){calls.push(sql);
  if(failQuery&&sql.includes(failQuery))throw Error('missing verifier');
  if(sql.includes('to_regclass'))return {rows:[{table_name:table}]};
  if(sql.startsWith('SELECT EXISTS'))return {rows:[{provisioned}]};
  if(sql.includes('verify_bound_lab_mail_cleanup'))return {rows:[{result}]};return {rows:[]};}};}};
}
test('durable lifecycle check permits pre-mail schema and unprovisioned historical targets',async()=>{
 for(const p of [lifecyclePool(),lifecyclePool({table:'secureshop_agents.lab_mail_targets'})]){
  await createDurableMailCleanupVerifier(p).verifyCleanup({targetId:randomUUID()},randomUUID());assert.equal(p.releases,1);assert.equal(p.calls.at(-1),'COMMIT');
 }
});
test('disabled serving config cannot bypass a historical provisioned mailbox verifier',async()=>{
 const targetId=randomUUID(),operationId=randomUUID();
 const p=lifecyclePool({table:'secureshop_agents.lab_mail_targets',provisioned:true,result:{provisioned:true,targetId,operationId}});
 // No serving composition or injected optional mail repository is needed.
 await createDurableMailCleanupVerifier(p).verifyCleanup({targetId},operationId);assert(p.calls.some(sql=>sql.includes('verify_bound_lab_mail_cleanup')));
});
test('missing SQL verifier or bad durable receipt blocks lifecycle acknowledgement and releases client',async()=>{
 for(const options of [{failQuery:'verify_bound_lab_mail_cleanup'},{result:{provisioned:false}},{result:{provisioned:true,targetId:randomUUID(),operationId:randomUUID()}}]){
  const p=lifecyclePool({table:'secureshop_agents.lab_mail_targets',provisioned:true,...options});
  await assert.rejects(createDurableMailCleanupVerifier(p).verifyCleanup({targetId:randomUUID()},randomUUID()));
  assert.equal(p.calls.at(-1),'ROLLBACK');assert.equal(p.releases,1);
 }
});

test('identity reset after SQL commit prevents a stale saved-looking response',async()=>{const f=fixture({result:sendResult,postCommitError:Object.assign(Error('reset after commit'),{code:'STALE_LAUNCH'})});await assert.rejects(f.repository.send(binding(),message),{code:'STALE_LAUNCH'});assert.equal(f.effects,1);});
