'use strict';
// Controlled storage contract, not command execution or objective qualification.
const test=require('node:test'),assert=require('node:assert/strict');
const {createHash,randomUUID}=require('node:crypto');
const {createSecureShopSystemRestartRepository}=require('../server/database/postgres/secureshopSystemRestartRepository');
const Wire=require('../sidecars/sandbox-runner/owned-system/restart-wire');
const {restartRequestDigest}=require('../server/services/secureshopSystemRestartContract');
const {createSceneBinding}=require('../server/services/secureshopSceneBinding');
const hash=s=>createHash('sha256').update(s,'utf8').digest('hex');
function fixture(){
 const scope={launchId:randomUUID(),scenarioId:randomUUID(),generation:1,platformOwnerId:41,platformSessionId:51};
 const targetId=randomUUID(),operationId=randomUUID(),sessionId=randomUUID(),workerToken=randomUUID();
 const raw={scope,persona:{id:77,role:'admin'},personaSession:{sessionId,authorityVersion:'1'},operationId,name:'nginx; hostname'};
 const request={version:1,operationId,name:raw.name},wire={targetId,request};
 const witness=Wire.restartWitness(wire,'restart-'+'b'.repeat(32)),stdoutText=witness.hostname+'\n',stderrText='';
 const receipt={version:Wire.WITNESS_VERSION,targetId,operationId,requestSha256:restartRequestDigest(request),
  beforeInstanceId:randomUUID(),afterInstanceId:randomUUID(),beforeGeneration:1,afterGeneration:2,
  effectSha256:'a'.repeat(64),outputText:stdoutText,outputSha256:hash(stdoutText),outputBytes:Buffer.byteLength(stdoutText),
  ownedCommandEffectSha256:'c'.repeat(64),ownedCommandEffectFiles:1,ownedCommandEffectBytes:4,
  command:'systemctl restart '+raw.name,status:'completed',isolation:'owned-restart-namespace-v1',
  witness,stdoutText,stderrText,stdoutSha256:hash(stdoutText),stderrSha256:hash(stderrText),
  stdoutBytes:Buffer.byteLength(stdoutText),stderrBytes:0,drained:true,exitCode:0};
 Wire.validateRestartReceipt(wire,receipt);
 const row={operation_id:operationId,target_id:targetId,launch_id:scope.launchId,scenario_id:scope.scenarioId,
  generation:1,original_platform_owner_id:41,original_platform_session_id:51,shop_user_id:77,
  persona_session_id:sessionId,authority_version:'1',service_name:raw.name,state:'completed',worker_token:workerToken,
  request_sha256:Buffer.from(receipt.requestSha256,'hex'),before_instance_id:receipt.beforeInstanceId,
  after_instance_id:receipt.afterInstanceId,before_generation:1,after_generation:2,
  effect_sha256:Buffer.from(receipt.effectSha256,'hex'),output_sha256:Buffer.from(receipt.outputSha256,'hex'),
  output_bytes:receipt.outputBytes,output_text:receipt.outputText};
 let stored={receipt_text:JSON.stringify(receipt),receipt_sha256:hash(JSON.stringify(receipt))};
 let active=true,grant=true,duplicate=false,commitError=null;const calls=[];
 const client={async query(sql,args=[]){calls.push({sql,args});
  if(sql==='COMMIT'&&commitError)throw commitError;
  if(['BEGIN','COMMIT','ROLLBACK'].includes(sql)||sql.startsWith('SELECT set_config')||sql.startsWith('SELECT pg_advisory_xact_lock'))return{rows:[]};
  if(sql.includes('assert_scene_execution_grant')){if(!grant)throw Object.assign(Error('stale'),{code:'SHOP_SCENE_STALE'});return{rows:[{allowed:true}]};}
  if(sql.startsWith('SELECT 1 FROM secureshop_review.scene_restart_admissions'))return{rows:[{allowed:true}]};
  if(sql.startsWith('SELECT * FROM secureshop_review.bound_system_restart_operations'))return{rows:[row]};
  if(sql.includes('FROM secureshop_review.bound_system_restart_full_receipts'))return{rows:stored?(duplicate?[stored,stored]:[stored]):[]};
  if(sql.includes('complete_bound_system_restart'))return{rows:[{...row,state:'completed'}]};
  if(sql.includes('record_scene_restart_effect'))return{rows:[{allowed:true}]};
  throw Error('Unexpected storage query');
 },release(){calls.push({sql:'release'});}};
 const personaAuthority={async capture(){return{binding:{...scope,personaId:77,role:'admin',sessionId,authorityVersion:'1'},
  assertRemoteAdmission:async()=>{},async withCrossStoreEffect(work){if(!active)throw Object.assign(Error('revoked'),{code:'SHOP_AUTH_INVALID'});return work();}};}};
 const repository=createSecureShopSystemRestartRepository({pool:{query(){},connect:async()=>client},personaAuthority,
  audit:{async append(clientValue){assert.equal(clientValue,client);calls.push({sql:'audit'});}}});
 return{repository,raw,row,receipt,workerToken,targetId,calls,scope,
  get stored(){return stored;},set stored(value){stored=value;},duplicate:()=>{duplicate=true;},
  revoke:()=>{active=false;},staleGrant:()=>{grant=false;},failCommit:error=>{commitError=error;}};
}
test('private v3 receipt round-trips original complete TEXT and raw digest while public Q63 projection stays unchanged',async()=>{
 const f=fixture(),original=f.stored.receipt_text;
 const got=await f.repository.readEvidenceReceipt(f.raw);
 assert.equal(got.receiptText,original);assert.equal(got.receiptSha256,hash(original));assert.deepEqual(got.receipt,f.receipt);
 assert(f.calls.every(c=>!/^INSERT|^UPDATE|^DELETE/.test(c.sql)));
 const publicResult=await f.repository.operation(f.raw);
 assert.deepEqual(Object.keys(publicResult.receipt).sort(),['afterGeneration','afterInstanceId','beforeGeneration','beforeInstanceId','effectSha256','outputBytes','outputSha256','outputText'].sort());
 assert.equal(Object.hasOwn(publicResult.receipt,'witness'),false);
 // TEXT order remains authoritative; no JSONB stringify hash is substituted.
 const reversed=Object.fromEntries(Object.entries(f.receipt).reverse());
 const text=JSON.stringify(reversed,null,1);f.stored={receipt_text:text,receipt_sha256:hash(text)};
 assert.equal((await f.repository.readEvidenceReceipt(f.raw)).receiptText,text);
});
test('v3 completion atomically sends full validated receipt to protected function, preserving v2 SQL path',async()=>{
 const f=fixture();f.row.state='running';
 const value=await f.repository.complete(f.raw,{targetId:f.targetId,workerToken:f.workerToken,receipt:f.receipt});
 const saved=f.calls.find(c=>c.sql.includes('complete_bound_system_restart_with_receipt'));
 assert.deepEqual(saved.args,[f.raw.operationId,f.workerToken,JSON.stringify(f.receipt)]);
 assert.equal(value.state,'completed');assert.equal(Object.hasOwn(value.receipt,'witness'),false);
 assert(f.calls.findIndex(c=>c.sql==='audit')<f.calls.findIndex(c=>c.sql==='COMMIT'));
 const legacy=fixture();legacy.row.state='running';const receipt=structuredClone(legacy.receipt);
 receipt.version=Wire.VERSION;for(const key of ['witness','stdoutText','stderrText','stdoutSha256','stderrSha256','stdoutBytes','stderrBytes','drained','exitCode'])delete receipt[key];
 await legacy.repository.complete(legacy.raw,{targetId:legacy.targetId,workerToken:legacy.workerToken,receipt});
 assert(!legacy.calls.some(c=>c.sql.includes('complete_bound_system_restart_with_receipt')));
 assert.equal(legacy.calls.find(c=>c.sql.includes('complete_bound_system_restart(')).args.length,10);
});
test('old missing receipt is unavailable without reconstruction and malformed full proof is rejected',async()=>{
 const missing=fixture();missing.stored=null;assert.equal(await missing.repository.readEvidenceReceipt(missing.raw),null);
 for(const mutate of [f=>{f.stored.receipt_sha256='0'.repeat(64);},f=>{f.duplicate();},
  f=>{const r=JSON.parse(f.stored.receipt_text);r.witness.hostname='restart-'+'0'.repeat(32);const text=JSON.stringify(r);f.stored={receipt_text:text,receipt_sha256:hash(text)};},
  f=>{f.row.effect_sha256=Buffer.alloc(32);},f=>{f.row.output_text='changed';},
  f=>{f.row.persona_session_id=randomUUID();}]){const f=fixture();mutate(f);await assert.rejects(f.repository.readEvidenceReceipt(f.raw),{code:'OPERATION_CONFLICT'});}
});
test('private receipt read retains original persona and current scene grant fences; commit failures are not success',async()=>{
 const revoked=fixture();revoked.revoke();await assert.rejects(revoked.repository.readEvidenceReceipt(revoked.raw),{code:'SHOP_AUTH_INVALID'});assert.equal(revoked.calls.length,0);
 const scene=fixture();let leases=0;const storage=createSceneBinding({targetId:scene.targetId,...scene.scope},
  {sceneId:randomUUID(),sceneGeneration:1,grantId:randomUUID(),execution:scene.scope,async withLease(work){leases++;return work();}});
 await scene.repository.readEvidenceReceipt(scene.raw,storage);assert.equal(leases,1);
 scene.staleGrant();await assert.rejects(scene.repository.readEvidenceReceipt(scene.raw,storage),{code:'SHOP_SCENE_STALE'});
 const fail=fixture(),original=Error('commit failed');fail.row.state='running';fail.failCommit(original);
 await assert.rejects(fail.repository.complete(fail.raw,{targetId:fail.targetId,workerToken:fail.workerToken,receipt:fail.receipt}),error=>error===original);
 assert(fail.calls.some(c=>c.sql==='ROLLBACK'));
});
