'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {createSecureShopSystemRestartRepository}=require('../server/database/postgres/secureshopSystemRestartRepository');
const {createSceneBinding}=require('../server/services/secureshopSceneBinding');

function fencedRestartFixture({denyAuthority=false}={}) {
 const scope={launchId:'40000000-0000-4000-8000-000000000004',scenarioId:'50000000-0000-4000-8000-000000000005',generation:1,platformOwnerId:41,platformSessionId:51};
 const sessionId='30000000-0000-4000-8000-000000000003',targetId='20000000-0000-4000-8000-000000000002',instanceId='60000000-0000-4000-8000-000000000006';
 const raw={scope,persona:{id:77,role:'admin'},personaSession:{sessionId,authorityVersion:'1'},operationId:'10000000-0000-4000-8000-000000000001'};
 const events=[];let held=false,connections=0;
 const client={async query(sql){
  assert.equal(held,true,'every review query must remain inside the persona fence');
  if(['BEGIN','COMMIT','ROLLBACK'].includes(sql)){events.push(sql);return{rows:[]};}
  if(sql.startsWith('SELECT set_config')||sql.startsWith('SELECT pg_advisory_xact_lock'))return{rows:[]};
  if(sql.includes('FROM secureshop_review.product_targets'))return{rows:[{target_id:targetId,lifecycle:'active',launch_id:scope.launchId,scenario_id:scope.scenarioId,generation:'1'}]};
  if(sql.startsWith('INSERT INTO secureshop_review.bound_system_restart_targets'))return{rows:[],rowCount:0};
  if(sql.includes('FROM secureshop_review.bound_system_restart_targets'))return{rows:[{target_id:targetId,instance_id:instanceId,restart_generation:'1'}]};
  if(sql.includes('FROM secureshop_review.bound_system_restart_operations'))return{rows:[]};
  throw Error('unexpected query '+sql);
 },release(){assert.equal(held,true);events.push('release');}};
 const personaAuthority={async capture(){return{
  binding:{...scope,personaId:77,role:'admin',sessionId,authorityVersion:'1'},
  async assertRemoteAdmission(){assert.equal(held,false,'persona admission must not re-enter a held transaction');throw Error('separate admission is unnecessary');},
  async withCrossStoreEffect(work){
   assert.equal(held,false);events.push('authority-before');
   if(denyAuthority)throw Object.assign(Error('authority revoked'),{code:'SHOP_AUTH_INVALID'});
   held=true;
   try{const result=await work();events.push('authority-after');return result;}
   finally{held=false;}
  },
 };}};
 const repo=createSecureShopSystemRestartRepository({pool:{query(){},async connect(){connections++;return client;}},personaAuthority,audit:{append(){}}});
 return{repo,raw,target:{targetId,instanceId,generation:1},events,connections:()=>connections};
}

test('restart administration and readback keep one persona fence through review commit without re-entry',async()=>{
 const fixture=fencedRestartFixture();
 assert.deepEqual(await fixture.repo.ensureTarget(fixture.raw,fixture.target),fixture.target);
 assert.deepEqual(await fixture.repo.operation(fixture.raw),{state:'not_found',operationId:fixture.raw.operationId});
 assert.equal(fixture.connections(),2);
 assert.deepEqual(fixture.events,[...Array(2)].flatMap(()=>['authority-before','BEGIN','COMMIT','release','authority-after']));
});

test('restart authority denial prevents target writes and operation readback before opening review transactions',async()=>{
 const fixture=fencedRestartFixture({denyAuthority:true});
 await assert.rejects(fixture.repo.ensureTarget(fixture.raw,fixture.target),{code:'SHOP_AUTH_INVALID'});
 await assert.rejects(fixture.repo.operation(fixture.raw),{code:'SHOP_AUTH_INVALID'});
 assert.equal(fixture.connections(),0);
 assert.deepEqual(fixture.events,['authority-before','authority-before']);
});

function repository({excessColumn,publicFunction,missingInsert}={}){
 const pool={async query(sql,args=[]){
  if(sql==='SELECT current_user AS role')return{rows:[{role:'dvaia_secureshop_review_runtime'}]};
  if(sql.startsWith('SELECT to_regclass'))return{rows:[{ready:true}]};
  if(sql.includes('aclexplode')&&sql.includes('pg_class'))return{rows:[{private:true}]};
  if(sql.includes('has_table_privilege')&&sql.includes('column_write')){const deletion=String(args[0]).endsWith('owner_deletion_receipts')||String(args[0]).endsWith('full_receipts');return{rows:[{read:true,append:deletion?false:missingInsert!==args[0],broad_write:false,column_write:excessColumn===args[0]}]};}
  if(sql.includes('FROM pg_trigger'))return{rows:[{ready:true}]};
  if(sql.includes('has_function_privilege')&&sql.includes('AS private'))return{rows:[{allowed:true,private:!publicFunction}]};
  throw new Error('unexpected readiness query: '+sql);
 }};
 pool.connect=async()=>({query:pool.query.bind(pool),release(){}});
 return createSecureShopSystemRestartRepository({pool,personaAuthority:{capture(){}},audit:{append(){}}});
}
test('restart readiness accepts only exact append/read grants and private canonical functions',async()=>{assert.deepEqual(await repository().checkReadiness(),{ready:true});for(const options of [{excessColumn:'secureshop_review.bound_system_restart_targets'},{excessColumn:'secureshop_review.bound_system_restart_operations'},{missingInsert:'secureshop_review.bound_system_restart_operations'},{publicFunction:true}])await assert.rejects(repository(options).checkReadiness(),{code:'SYSTEM_RESTART_NOT_READY'});});
test('restart journal projects the canonical shopUserId and writes only through the review-store client',async()=>{const operationId='10000000-0000-4000-8000-000000000001',targetId='20000000-0000-4000-8000-000000000002',sessionId='30000000-0000-4000-8000-000000000003',scope={launchId:'40000000-0000-4000-8000-000000000004',scenarioId:'50000000-0000-4000-8000-000000000005',generation:1,platformOwnerId:41,platformSessionId:51};let captured,inserted,released=0;const client={async query(sql,args){if(['BEGIN','COMMIT'].includes(sql)||sql.startsWith('SELECT set_config')||sql.startsWith('SELECT pg_advisory_xact_lock'))return{rows:[]};if(sql.startsWith('SELECT * FROM secureshop_review.bound_system_restart_operations'))return{rows:[]};if(sql.startsWith('INSERT INTO secureshop_review.bound_system_restart_operations')){inserted=args;return{rows:[],rowCount:1};}if(sql.startsWith('SELECT * FROM secureshop_review.begin_bound_system_restart'))return{rows:[{state:'running',operation_id:operationId,request_sha256:Buffer.alloc(32),target_id:targetId,worker_token:args[1]}]};throw Error('unexpected '+sql);},release(error){assert.equal(error,undefined);released++;}};const personaAuthority={async capture(input){captured=input;const binding={...scope,personaId:77,role:'admin',sessionId,authorityVersion:'1'};return{binding,assertRemoteAdmission:async()=>{},withCrossStoreEffect:work=>work(),withPersonaEffect:()=>assert.fail('agents client must not receive review queries')};}};const repo=createSecureShopSystemRestartRepository({pool:{query(){},connect:async()=>client},personaAuthority,audit:{append(){}}});const result=await repo.begin({scope,persona:{id:77,role:'admin'},personaSession:{sessionId,authorityVersion:'1'},version:1,operationId,name:'nginx'},{targetId});assert.equal(captured.personaId,77);assert.equal(inserted[7],77);assert.equal(result.state,'running');assert.equal(released,1);});
test('restart target readiness accepts the exact persisted post-restart generation',async()=>{const targetId='20000000-0000-4000-8000-000000000002',instanceId='60000000-0000-4000-8000-000000000006',scope={launchId:'40000000-0000-4000-8000-000000000004',scenarioId:'50000000-0000-4000-8000-000000000005',generation:1,platformOwnerId:41,platformSessionId:51},sessionId='30000000-0000-4000-8000-000000000003';const client={async query(sql){if(['BEGIN','COMMIT'].includes(sql)||sql.startsWith('SELECT set_config')||sql.startsWith('SELECT pg_advisory_xact_lock'))return{rows:[]};if(sql.includes('FROM secureshop_review.product_targets'))return{rows:[{target_id:targetId,lifecycle:'active',launch_id:scope.launchId,scenario_id:scope.scenarioId,generation:'1'}]};if(sql.startsWith('INSERT INTO secureshop_review.bound_system_restart_targets'))return{rows:[],rowCount:0};if(sql.includes('FROM secureshop_review.bound_system_restart_targets'))return{rows:[{target_id:targetId,instance_id:instanceId,restart_generation:'2'}]};throw Error('unexpected '+sql);},release(){}};const personaAuthority={async capture(){return{binding:{...scope,personaId:77,role:'admin',sessionId,authorityVersion:'1'},assertRemoteAdmission:async()=>{},withCrossStoreEffect:work=>work()};}};const repo=createSecureShopSystemRestartRepository({pool:{query(){},connect:async()=>client},personaAuthority,audit:{append(){}}}),raw={scope,persona:{id:77,role:'admin'},personaSession:{sessionId,authorityVersion:'1'},operationId:'10000000-0000-4000-8000-000000000001'};assert.deepEqual(await repo.ensureTarget(raw,{targetId,instanceId,generation:2}),{targetId,instanceId,generation:2});await assert.rejects(repo.ensureTarget(raw,{targetId,instanceId,generation:0}),{code:'INVALID_ARGUMENT'});});
test('restart review transaction destroys a connection when rollback fails',async()=>{const scope={launchId:'40000000-0000-4000-8000-000000000004',scenarioId:'50000000-0000-4000-8000-000000000005',generation:1,platformOwnerId:41,platformSessionId:51},sessionId='30000000-0000-4000-8000-000000000003',failure=Error('review query failed'),rollback=Error('rollback failed');let released;const client={async query(sql){if(sql==='BEGIN'||sql.startsWith('SELECT set_config')||sql.startsWith('SELECT pg_advisory_xact_lock'))return{rows:[]};if(sql==='ROLLBACK')throw rollback;throw failure;},release(error){released=error;}};const personaAuthority={async capture(){return{binding:{...scope,personaId:77,role:'admin',sessionId,authorityVersion:'1'},assertRemoteAdmission:async()=>{},withCrossStoreEffect:work=>work()};}};const repo=createSecureShopSystemRestartRepository({pool:{query(){},connect:async()=>client},personaAuthority,audit:{append(){}}}),raw={scope,persona:{id:77,role:'admin'},personaSession:{sessionId,authorityVersion:'1'},operationId:'10000000-0000-4000-8000-000000000001'};await assert.rejects(repo.operation(raw),failure);assert.equal(released,rollback);});

test('restart admission binds old storage to the current scene grant and rejects another scene on replay',async()=>{
 const operationId='10000000-0000-4000-8000-000000000001',targetId='20000000-0000-4000-8000-000000000002',sessionId='30000000-0000-4000-8000-000000000003';
 const current={launchId:'40000000-0000-4000-8000-000000000004',scenarioId:'50000000-0000-4000-8000-000000000005',generation:2,platformOwnerId:41,platformSessionId:52};
 const storage={targetId,launchId:'60000000-0000-4000-8000-000000000006',scenarioId:'70000000-0000-4000-8000-000000000007',generation:1,platformOwnerId:41,platformSessionId:51};
 let leased=false,operation=null,admissionGrant=null,inserted=null,grants=0;
 const makeScene=grantId=>createSceneBinding(storage,{sceneId:'80000000-0000-4000-8000-000000000008',sceneGeneration:1,grantId,execution:current,async withLease(work){leased=true;try{return await work();}finally{leased=false;}}});
 const scene=makeScene('90000000-0000-4000-8000-000000000009');
 const client={async query(sql,args=[]){
  assert.equal(leased,true);
  if(['BEGIN','COMMIT','ROLLBACK'].includes(sql)||sql.startsWith('SELECT set_config')||sql.startsWith('SELECT pg_advisory_xact_lock'))return{rows:[]};
  if(sql.includes('assert_scene_execution_grant')){grants++;return{rows:[{allowed:true}]};}
  if(sql.startsWith('SELECT * FROM secureshop_review.bound_system_restart_operations'))return{rows:operation?[operation]:[]};
  if(sql.startsWith('SELECT 1 FROM secureshop_review.scene_restart_admissions'))return{rows:admissionGrant===args[2]?[{ '?column?':1 }]:[]};
  if(sql.startsWith('INSERT INTO secureshop_review.bound_system_restart_operations')){inserted=args;return{rowCount:1,rows:[]};}
  if(sql.includes('begin_bound_system_restart')){operation={operation_id:operationId,target_id:targetId,launch_id:storage.launchId,scenario_id:storage.scenarioId,generation:1,original_platform_owner_id:41,original_platform_session_id:51,shop_user_id:77,persona_session_id:sessionId,authority_version:'1',state:'running',worker_token:args[1],request_sha256:Buffer.alloc(32)};return{rows:[operation]};}
  if(sql.includes('record_scene_restart_admission')){admissionGrant=args[2];return{rows:[{record_scene_restart_admission:true}]};}
  throw Error('unexpected scene restart query '+sql);
 },release(){}};
 const personaAuthority={async capture(){return{binding:{...current,personaId:77,role:'admin',sessionId,authorityVersion:'1'},assertRemoteAdmission:async()=>{},withCrossStoreEffect:work=>work()};}};
 const repo=createSecureShopSystemRestartRepository({pool:{query(){},connect:async()=>client},personaAuthority,audit:{append(){}}});
 const raw={scope:current,persona:{id:77,role:'admin'},personaSession:{sessionId,authorityVersion:'1'},operationId,name:'nginx'};
 await repo.begin(raw,{targetId,binding:scene});
 assert.deepEqual(inserted.slice(1,7),[targetId,storage.launchId,storage.scenarioId,storage.generation,storage.platformOwnerId,storage.platformSessionId]);
 assert.equal(admissionGrant,scene.scene.grantId);
 assert.equal((await repo.operation(raw,scene)).state,'running');
 const other=makeScene('a0000000-0000-4000-8000-00000000000a');
 await assert.rejects(repo.operation(raw,other),{code:'OPERATION_CONFLICT'});
 assert.equal(leased,false);assert(grants>=4);
});
