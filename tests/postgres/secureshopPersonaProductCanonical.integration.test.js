'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),os=require('node:os'),{randomUUID,createHash}=require('node:crypto'),{Pool}=require('pg');
test('canonical ProductAssist graph denies held decisions and observation after actual persona role changes',{skip:process.env.PERSONA_REVIEW_CANONICAL_NATIVE!=='1',timeout:90000},async t=>{
 assert.equal(process.env.PG_TEST_DISPOSABLE,'yes');assert.equal(fs.realpathSync(process.cwd()),fs.realpathSync(process.env.OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE));
 const families={IDENTITY:'identity',FRESH:'secureshop_agents',COMMERCE:'secureshop',REVIEW:'secureshop_review'};let nonce,port;
 const pool=(store,role)=>{const u=new URL(process.env[`PERSONA_${store}_${role}_URL`]);assert.equal(u.protocol,'postgresql:');assert.equal(u.hostname,'127.0.0.1');assert.equal(u.username,`dvaia_${families[store]}_${role.toLowerCase()}`);assert.equal(u.password,'');assert.equal(u.search,'');assert.equal(u.hash,'');assert.match(u.port,/^[1-9]\d{0,4}$/);assert.ok(Number(u.port)<=65535);const match=/^\/owasp_ai_goat_test_persona_([a-f0-9]{12})_(commerce|fresh|review|identity)$/.exec(u.pathname);assert.ok(match);assert.equal(match[2],store.toLowerCase());nonce??=match[1];port??=u.port;assert.equal(match[1],nonce);assert.equal(u.port,port);const p=new Pool({connectionString:u.href,max:6,statement_timeout:8000});t.after(()=>p.end());return p;};
 const identity=pool('IDENTITY','RUNTIME'),im=pool('IDENTITY','MIGRATION'),leases=pool('IDENTITY','RUNTIME'),agents=pool('FRESH','RUNTIME'),am=pool('FRESH','MIGRATION'),commerce=pool('COMMERCE','RUNTIME'),cm=pool('COMMERCE','MIGRATION'),review=pool('REVIEW','RUNTIME'),rm=pool('REVIEW','MIGRATION');const {migrate}=require('../../db/postgres/migrate');await migrate(im,'db/postgres/identity-migrations');await migrate(cm,'db/postgres/workshop-migrations/secureshop');await require('../../server/database/postgres/secureshopSeed').seedSecureShop(cm);await migrate(rm,'db/postgres/workshop-migrations/secureshop_review');
 // Keep the real pre-0113 store populated before applying the successor.
 const migrationRoot=path.resolve('db/postgres/workshop-migrations/secureshop_agents');
 const migrationView=fs.mkdtempSync(path.join(os.tmpdir(),'owasp-ai-goat-agency-role-migrations-'));
 t.after(()=>fs.rmSync(migrationView,{recursive:true,force:true}));
 const migrationNames=fs.readdirSync(migrationRoot).filter(n=>/^\d{4}_.*\.sql$/.test(n)).sort();
 for(const name of migrationNames.filter(n=>Number(n.slice(0,4))<=112))fs.symlinkSync(path.join(migrationRoot,name),path.join(migrationView,name));
 await migrate(am,migrationView);
 const agencyMigration='0113_owned_agency_role_state.sql',agencySql=fs.readFileSync(path.join(migrationRoot,agencyMigration),'utf8');
 await previewAgencyMigration(am,agencySql);

 const users=require('../../server/database/postgres/identityRepository').createIdentityRepository(identity),launches=require('../../server/database/postgres/secureshopLaunchRepository').createSecureShopLaunchRepository(identity),checkCurrent=s=>launches.assertCurrent(s),auditFactory=require('../../server/database/postgres/secureshopBoundAuditRepository').createBoundAuditStore;
 const authority=require('../../server/database/postgres/secureshopBoundPersonaAuthority').createSecureShopBoundPersonaAuthority({pool:agents,checkCurrent});const personas=require('../../server/database/postgres/secureshopBoundPersonaRepository').createSecureShopBoundPersonaRepository({commercePool:commerce,agentsPool:agents,personaAuthority:authority,auditStore:auditFactory({store:'agents',pool:agents})});await personas.ensureTemplates();const auth=require('../../server/services/secureshopBoundPersonaAuth').createSecureShopBoundPersonaAuth({repository:personas,personaAuthority:authority,launches,jwtSecret:'owned-canonical-review-native-only-secret'});
 const conversationRepository=require('../../server/database/postgres/secureshopBoundConversationsRepository').createBoundConversationsRepository({pool:agents,queue:async(_id,work)=>work()}),journal=require('../../server/database/postgres/secureshopTurnRequestsRepository').createTurnRequestsRepository({pool:agents}),ledger=require('../../server/agent-runtime/postgresRunLedger').createPostgresRunLedger(identity,{leasePool:leases}),coordinator=require('../../server/agent-runtime/runCoordinator').createRunCoordinator({family:'SecureShopBoundConversation',ledger});
 const createOwner=async name=>{const passwordHash=await require('bcryptjs').hash('owned-only',4),user=await users.createUser({username:name,email:name+'@example.invalid',passwordHash}),token=randomUUID(),expiresAt=new Date(Date.now()+600000).toISOString(),session=await users.createSession({userId:user.id,token,expiresAt,expectedPasswordHash:passwordHash}),issued=await launches.issueOrRenew({platformOwnerId:user.id,platformSessionId:session.id,expiresAt}),scope=require('../../server/services/secureshopConversationBinding').createLaunchScope(issued.binding),logged=await auth.login({scope,username:'student_customer',password:'student123'}),verified=await auth.authenticateBoundToken({scope,token:logged.token});return{user,token,scope,bearer:issued.bearer,personaToken:logged.token,persona:logged.user,personaSession:{sessionId:verified.sessionId,authorityVersion:verified.authorityVersion}};};



 const admins=require('../../server/database/postgres/secureshopBoundUserAdministrationRepository').createSecureShopBoundUserAdministrationRepository({pool:agents,checkCurrent,auditStore:auditFactory({store:'agents',pool:agents})});
 const productRepository=require('../../server/database/postgres/secureshopBoundProductRepository').createSecureShopBoundProductRepository(review,{checkCurrent,checkCleanup:async()=>{throw Error('Outside cohort');}});
 const scenes=require('../../server/services/secureshopScenes').createSecureShopScenes({repository:require('../../server/database/postgres/secureshopSceneRepository').createSecureShopSceneRepository({pool:identity,launches}),reviewPool:review,launches});
 const product={id:7,sourceRetailerId:1,retailerId:12,name:'Owned source',description:'Untrusted source retained',descriptionHtml:'<p>original</p>',price:12.5,category:'demo',imageUrl:null,images:[],stockQuantity:4,status:'active',templateSource:'{{source}}',createdAt:null,updatedAt:null};

 await qualifyAgencyRoleState({t,agents,am,im,cm,migrate,migrationRoot,migrationView,migrationNames,agencyMigration,agencySql,
  createOwner,authority,auth,launches,scenes,productRepository,product});

 for(const mode of ['decision','observation','live']){
  const o=await createOwner('assist-'+mode),reserved=await launches.reserveProductsTarget({...o.scope,expectedGeneration:o.scope.generation}),binding={...o.scope,targetId:reserved.targetId};await productRepository.provision(binding,{ownMerchantId:12,products:[product]});
  const logged=await auth.login({scope:o.scope,username:'student_admin',password:'student123'}),admin=await auth.authenticateBoundToken({scope:o.scope,token:logged.token});let changed=false;
  const change=async()=>{if(changed)return;changed=true;await admins.mutate({scope:o.scope,actorId:admin.user.id,actorSessionId:admin.sessionId,targetId:o.persona.id,operationId:randomUUID(),expectedVersion:'1',action:'set_role',role:'merchant'});};
  const catalog=require('../../server/services/secureshopBoundCatalog').createSecureShopBoundCatalog({sourcePool:commerce,repository:productRepository,checkCurrent,scenes,resolveTarget:s=>launches.reserveProductsTarget({...s,expectedGeneration:s.generation})});let observations=0;
  const observedCatalog={...catalog,getProduct:async input=>{const result=await catalog.getProduct(input);observations++;if(mode==='observation')await change();return result;}};
  let reached,release;const ready=new Promise(r=>reached=r),gate=new Promise(r=>release=r);let calls=0,finalCalls=0,assessmentCallbacks=0;
  const provider={chat:async()=>{calls++;reached();await gate;return{stop_reason:'tool_use',tool_uses:[{id:'owned-product-summary',name:'summarizer.summarize_product',args:{product_id:7}}],provider:'ollama',model:'controlled-fixture',mocked:false,fallback:false};},finalResponse:async()=>{finalCalls++;return {stop_reason:'end_turn',responseMode:'structured_final',text:'Controlled source summary',provider:'ollama',model:'controlled-fixture',mocked:false,fallback:false};}};
  const assist=require('../../server/services/secureshopBoundProductAssist').createSecureShopBoundProductAssist({launches,conversationRepository,journal,coordinator,provider,personaAuthority:authority,catalog,scenes,afterSummaryCommit:async()=>{assessmentCallbacks++;},createProductTools:input=>require('../../server/services/secureshopBoundProductTools').createSecureShopBoundProductTools({...input,catalog:observedCatalog})});
  const base={scope:o.scope,persona:{id:o.persona.id,role:o.persona.role},personaSession:o.personaSession,productId:7};
  const input={...base,...await assist.createSummarySession(base),requestId:randomUUID()};
  assert.deepEqual(await assist.readSummary(input),{status:'not_found',sessionId:input.sessionId,requestId:input.requestId});
  assert.equal(calls,0);assert.equal(observations,0);
  const running=assist.runSummary(input);running.catch(()=>{});await Promise.race([ready,running.then(()=>{throw Error('Held decision missing');})]);if(mode==='decision')await change();release();
  if(mode==='live'){
   const result=await running;assert.equal(result.summary,'Controlled source summary');assert.equal(result.description,'Untrusted source retained');assert.equal(result.sessionId,input.sessionId);assert.equal(result.requestId,input.requestId);
   assert.deepEqual(await assist.readSummary(input),{status:'completed',result});assert.deepEqual(await assist.runSummary(input),result);
   assert.equal(finalCalls,1);assert.equal(assessmentCallbacks,1);
   const original=(await agents.query('SELECT result_json FROM secureshop_agents.turn_requests WHERE session_id=$1 AND request_id=$2',[input.sessionId,input.requestId])).rows[0].result_json;
   assert.equal(original.taskMetadata.productAssist.version,2);assert.equal(original.taskMetadata.productSummaryOrigin.source.requestId,input.requestId);
   const ownerKey=JSON.stringify(['SecureShopBoundConversation',input.sessionId]);
   const run=(await identity.query('SELECT owner_key,status FROM graph_runtime.runs WHERE run_id=$1',[original.taskMetadata.productSummaryOrigin.runId])).rows[0];
   assert.deepEqual(run,{owner_key:ownerKey,status:'completed'});
   const effectKey=`${input.requestId}:${JSON.stringify([original.hops[0].step,'owned-product-summary','summarizer.summarize_product'])}`;
   const effects=(await identity.query('SELECT owner_key,effect_key,status FROM graph_runtime.effects WHERE run_id=$1',[original.taskMetadata.productSummaryOrigin.runId])).rows;
   assert.deepEqual(effects,[{owner_key:ownerKey,effect_key:effectKey,status:'completed'}]);
   const sourceReader=require('../../server/services/secureshopProductSummarySourceReader').createProductSummarySourceReader({identityPool:identity,agentsPool:agents,reviewPool:review,
    current:async()=>({binding:require('../../server/services/secureshopConversationBinding').createConversationBinding(o.scope,base.persona),persona:base.persona,personaSession:o.personaSession,target:await scenes.readRetained(o.scope),execution:original.taskMetadata.productSummaryOrigin.execution,check:()=>launches.assertCurrent(o.scope)}),
    qualifyModel:model=>model.provider==='ollama'&&model.model==='controlled-fixture'&&!model.mocked&&!model.fallback});
   const captured=await sourceReader(null,{sessionId:input.sessionId,requestId:input.requestId});
   assert.equal(captured.lineage.consumer.original.requestId,input.requestId);
   await change();await assert.rejects(assist.readSummary(input),{code:'SHOP_AUTH_INVALID'});
  }else {await assert.rejects(running,{code:'SHOP_AUTH_INVALID'});await assert.rejects(assist.readSummary(input),{code:'SHOP_AUTH_INVALID'});assert.equal(finalCalls,0);assert.equal(assessmentCallbacks,0);} 
  assert.equal(observations,mode==='decision'?0:1);assert.equal(calls,1);
  const records=(await agents.query('SELECT tr.status FROM secureshop_agents.turn_requests tr JOIN secureshop_agents.agent_sessions s ON s.id=tr.session_id WHERE s.original_platform_owner_id=$1',[o.user.id])).rows;assert.equal(records.length,1);assert.equal(records[0].status,mode==='live'?'completed':'uncertain');
  assert.equal((await identity.query('SELECT count(*)::int n FROM workshop_platform.objective_judgments WHERE user_id=$1',[o.user.id])).rows[0].n,0);
 }
 const runs=(await identity.query('SELECT status FROM graph_runtime.runs')).rows;assert.equal(runs.length,3);assert.equal(runs.filter(r=>r.status==='completed').length,1);
 t.diagnostic('Real canonical ProductAssist graph/turn/catalog/scenes and real persona role changes; durable summary GET/replay and original SQL source custody add no model/tool/assessment work; controlled provider protocol fixture is not actual Ollama evidence, no Judge or objective credit.');
});


// V29 state qualification uses real PG authority and scene leases, but controlled
// request/mode/ACL receipts. It is not model, ACL-admission or objective-credit proof.
async function snapshotSchema(pool,schema,names){
 const tables=names||((await pool.query("SELECT tablename FROM pg_tables WHERE schemaname=$1 ORDER BY tablename",[schema])).rows.map(r=>r.tablename));
 const result={};
 for(const table of tables){assert.match(table,/^[a-z_][a-z0-9_]*$/);result[table]=(await pool.query(`SELECT to_jsonb(t) AS row FROM "${schema}"."${table}" t ORDER BY to_jsonb(t)::text`)).rows.map(r=>r.row);}
 return result;
}
async function agencyPrivileges(client){
 const role='dvaia_secureshop_agents_runtime';
 for(const table of ['owned_agency_role_targets','owned_agency_role_effects']){
  for(const privilege of ['SELECT','INSERT'])assert.equal((await client.query('SELECT has_table_privilege($1,$2,$3) AS ok',[role,'secureshop_agents.'+table,privilege])).rows[0].ok,true);
  for(const privilege of ['UPDATE','DELETE','TRUNCATE','REFERENCES','TRIGGER'])assert.equal((await client.query('SELECT has_table_privilege($1,$2,$3) AS ok',[role,'secureshop_agents.'+table,privilege])).rows[0].ok,false);
 }
 for(const column of ['teaching_role','revision','lifecycle'])assert.equal((await client.query("SELECT has_column_privilege($1,'secureshop_agents.owned_agency_role_targets',$2,'UPDATE') AS ok",[role,column])).rows[0].ok,true);
 assert.equal((await client.query("SELECT has_column_privilege($1,'secureshop_agents.owned_agency_role_targets','customer_id','UPDATE') AS ok",[role])).rows[0].ok,false);
 for(const name of ['guard_owned_agency_role_target','retire_owned_agency_roles'])assert.equal((await client.query("SELECT has_function_privilege($1,$2,'EXECUTE') AS ok",[role,'secureshop_agents.'+name+'()'])).rows[0].ok,false);
 const triggers=(await client.query("SELECT tgname FROM pg_trigger WHERE tgname=ANY($1::text[]) AND NOT tgisinternal ORDER BY tgname",[['owned_agency_role_target_guard','owned_agency_role_target_admission','owned_agency_role_effect_immutable','owned_agency_role_retirement','owned_agency_role_owner_retirement']])).rows.map(r=>r.tgname);
 assert.equal(triggers.length,5);
}
async function previewAgencyMigration(pool,sql){
 const c=await pool.connect();
 try{await c.query('BEGIN');await c.query('SAVEPOINT fresh_0113');await c.query(sql);await agencyPrivileges(c);
  for(const table of ['owned_agency_role_targets','owned_agency_role_effects'])assert.equal((await c.query(`SELECT count(*)::int n FROM secureshop_agents.${table}`)).rows[0].n,0);
  await c.query('ROLLBACK TO SAVEPOINT fresh_0113');assert.equal((await c.query("SELECT to_regclass('secureshop_agents.owned_agency_role_targets') AS table_name")).rows[0].table_name,null);
  await c.query('COMMIT');
 }catch(e){await c.query('ROLLBACK');throw e;}finally{c.release();}
}
async function qualifyAgencyRoleState(o){
 const {t,agents,am,im,cm,migrate,migrationRoot,migrationView,migrationNames,agencyMigration,agencySql,createOwner,authority,auth,launches,scenes,productRepository,product}=o;
 const {withSceneLease}=require('../../server/services/secureshopSceneBinding');
 const repo=require('../../server/database/postgres/secureshopOwnedAgencyRoleRepository').createSecureShopOwnedAgencyRoleRepository();
 const owners=[];
 for(const name of ['agency-primary','agency-sibling','agency-rollback']){
  const owner=await createOwner(name),reserved=await launches.reserveProductsTarget({...owner.scope,expectedGeneration:owner.scope.generation});
  await productRepository.provision({...owner.scope,targetId:reserved.targetId},{ownMerchantId:12,products:[product]});
  const target=await scenes.resolve(owner.scope);assert.ok(target?.scene);
  const context={scope:owner.scope,scene:{targetId:target.targetId,sceneId:target.scene.sceneId,sceneGeneration:target.scene.sceneGeneration,grantId:target.scene.grantId},persona:{id:owner.persona.id,role:'customer'},personaSession:owner.personaSession};
  const fence=authority.capture({scope:owner.scope,personaId:owner.persona.id,sessionId:owner.personaSession.sessionId,role:'customer',authorityVersion:owner.personaSession.authorityVersion});
  owners.push({...owner,target,context,fence,work:fn=>withSceneLease(target,()=>fence.withPersonaEffect(fn))});
 }
 const before=await snapshotSchema(am,'secureshop_agents');
 assert.ok(before.bound_persona_sessions.length>=3);assert.ok(before.bound_actor_identities.length>=3);
 const ledgerBefore=(await am.query('SELECT * FROM dvaia_migrations.ledger ORDER BY name')).rows;
 fs.symlinkSync(path.join(migrationRoot,agencyMigration),path.join(migrationView,agencyMigration));
 assert.deepEqual(await migrate(am,migrationView),[agencyMigration]);await agencyPrivileges(am);
 assert.deepEqual(await snapshotSchema(am,'secureshop_agents',Object.keys(before)),before);
 const ledger=(await am.query('SELECT * FROM dvaia_migrations.ledger ORDER BY name')).rows;
 assert.deepEqual(ledger.slice(0,-1),ledgerBefore);assert.equal(ledger.at(-1).name,agencyMigration);
 assert.equal(ledger.at(-1).checksum,createHash('sha256').update(agencySql).digest('hex'));
 assert.deepEqual(await migrate(am,migrationView),[]);assert.deepEqual((await am.query('SELECT * FROM dvaia_migrations.ledger ORDER BY name')).rows,ledger);
 // Current producer dependencies may include the independently owned ACL successor.
 for(const name of migrationNames.filter(n=>Number(n.slice(0,4))>113))fs.symlinkSync(path.join(migrationRoot,name),path.join(migrationView,name));
 await migrate(am,migrationView);assert.deepEqual(await migrate(am,migrationView),[]);
 const protectedState=async()=>({agents:await snapshotSchema(am,'secureshop_agents',Object.keys(before)),identity:await snapshotSchema(im,'identity'),shopAuth:await snapshotSchema(im,'secureshop_auth'),progress:await snapshotSchema(im,'workshop_platform'),commerce:await snapshotSchema(cm,'secureshop')});
 const protectedBefore=await protectedState();assert.ok(Object.keys(protectedBefore.identity).length>0);
 for(const owner of owners){assert.equal(await owner.work(c=>repo.readWithClient(c,owner.context)),null);const initial=await owner.work(c=>repo.ensureWithClient(c,owner.context));assert.equal(initial.teachingRole,'customer');assert.equal(initial.revision,'1');}
 function request(owner){
  const runId=randomUUID(),requestId=randomUUID(),callId='controlled-agency-role',step=1;
  return {...owner.context,requestId,runId,callId,step,effectKey:JSON.stringify([step,callId,'user-management.set_role']),args:{user_id:owner.persona.id,role:'admin'},
   modeExecution:{version:1,featureId:'customer_chat',policyVersion:'owned-catalog-and-cart-read-v1',mode:'vuln',generation:0,modeStamp:'native-controlled-v29',scope:owner.scope},
   policyAdmission:{admissionId:randomUUID(),runId,invocationId:`${step}:${callId}`,toolKey:'user-management.set_role',policyVersion:'1',registrySha256:'a'.repeat(64),enforcement:false,allowed:false,action:'dispatch',policyViolation:'denied-by-acl'}};
 }
 const [primary,sibling,rollback]=owners,q=request(primary),siblingRequest=request(sibling),rollbackRequest=request(rollback);
 const fixed={...rollbackRequest,modeExecution:{...rollbackRequest.modeExecution,mode:'fixed'}};
 await assert.rejects(rollback.work(c=>repo.applyWithClient(c,fixed)),{code:'AGENCY_ROLE_DENIED'});
 await assert.rejects(rollback.work(async c=>{await repo.applyWithClient(c,rollbackRequest);throw Object.assign(Error('transaction rollback control'),{code:'CONTROLLED_ROLLBACK'});}),{code:'CONTROLLED_ROLLBACK'});
 assert.equal((await rollback.work(c=>repo.readWithClient(c,rollback.context))).teachingRole,'customer');
 assert.equal((await agents.query('SELECT count(*)::int n FROM secureshop_agents.owned_agency_role_effects')).rows[0].n,0);
 // Two concurrent callers serialize on the real persona/target locks.
 const applied=await Promise.all([primary.work(c=>repo.applyWithClient(c,q)),primary.work(c=>repo.applyWithClient(c,q))]);
 assert.deepEqual(applied.map(r=>r.replayed).sort(),[false,true]);assert.deepEqual(applied[0].receipt,applied[1].receipt);
 const receipt=applied[0].receipt;assert.equal(receipt.changed,true);assert.deepEqual(receipt.before,{role:'customer',revision:'1'});assert.deepEqual(receipt.after,{role:'admin',revision:'2'});
 const ref=Object.fromEntries(['requestId','runId','callId','effectKey'].map(k=>[k,q[k]]));
 assert.deepEqual(await primary.work(c=>repo.readEffectWithClient(c,primary.context,ref)),receipt);
 await assert.rejects(primary.work(c=>repo.applyWithClient(c,{...q,modeExecution:{...q.modeExecution,modeStamp:'different-epoch'}})),{code:'AGENCY_ROLE_CONFLICT'});
 await assert.rejects(primary.work(c=>repo.readEffectWithClient(c,{...primary.context,personaSession:{...primary.personaSession,sessionId:randomUUID()}},ref)),{code:'AGENCY_ROLE_CONFLICT'});
 assert.equal(await sibling.work(c=>repo.readEffectWithClient(c,sibling.context,ref)),null);
 const noop=await primary.work(c=>repo.applyWithClient(c,request(primary)));assert.equal(noop.receipt.changed,false);assert.deepEqual(noop.receipt.before,noop.receipt.after);
 const siblingReceipt=(await sibling.work(c=>repo.applyWithClient(c,siblingRequest))).receipt;
 const forgedFence=authority.capture({scope:primary.scope,personaId:primary.persona.id,sessionId:randomUUID(),role:'customer',authorityVersion:primary.personaSession.authorityVersion});let entered=false;
 await assert.rejects(withSceneLease(primary.target,()=>forgedFence.withPersonaEffect(()=>{entered=true;})),{code:'SHOP_AUTH_INVALID'});assert.equal(entered,false);
 assert.equal((await authority.read(primary.scope,primary.persona.id,{role:'customer',version:primary.personaSession.authorityVersion})).role,'customer');
 assert.deepEqual(await protectedState(),protectedBefore);
 const effectsBefore=(await am.query('SELECT to_jsonb(e) row FROM secureshop_agents.owned_agency_role_effects e ORDER BY target_key,request_id,call_id')).rows;
 const targetsBefore=(await am.query('SELECT to_jsonb(t) row FROM secureshop_agents.owned_agency_role_targets t ORDER BY target_key')).rows;
 // Runtime grants and privileged trigger defenses are separate checks.
 for(const sql of ["DELETE FROM secureshop_agents.owned_agency_role_targets","UPDATE secureshop_agents.owned_agency_role_effects SET receipt_json=receipt_json","TRUNCATE secureshop_agents.owned_agency_role_effects"]){await assert.rejects(agents.query(sql),{code:'42501'});}
 await assert.rejects(am.query('UPDATE secureshop_agents.owned_agency_role_effects SET receipt_json=receipt_json'),{code:'55000'});
 await assert.rejects(am.query('DELETE FROM secureshop_agents.owned_agency_role_targets'),{code:'55000'});
 await assert.rejects(agents.query("UPDATE secureshop_agents.owned_agency_role_targets SET teaching_role='customer',revision=1 WHERE teaching_role='admin'"),{code:'55000'});
 assert.deepEqual(await migrate(am,migrationView),[]);
 assert.deepEqual((await am.query('SELECT to_jsonb(e) row FROM secureshop_agents.owned_agency_role_effects e ORDER BY target_key,request_id,call_id')).rows,effectsBefore);
 assert.deepEqual((await am.query('SELECT to_jsonb(t) row FROM secureshop_agents.owned_agency_role_targets t ORDER BY target_key')).rows,targetsBefore);
 // Exercise owner-deletion trigger semantics in a rolled-back migration-role
 // transaction; this synthetic trigger probe is never a persisted cleanup claim.
 const deletionProbe=await am.connect();
 try{await deletionProbe.query('BEGIN');
  await deletionProbe.query(`INSERT INTO secureshop_agents.bound_audit_owner_deletion_receipts
   (deletion_job_id,original_platform_owner_id,deleted_event_count,receipt_sha256) VALUES($1,$2,0,decode($3,'hex'))`,[randomUUID(),rollback.scope.platformOwnerId,'b'.repeat(64)]);
  assert.equal((await deletionProbe.query('SELECT lifecycle FROM secureshop_agents.owned_agency_role_targets WHERE original_platform_owner_id=$1',[rollback.scope.platformOwnerId])).rows[0].lifecycle,'retired');
  assert.equal((await deletionProbe.query('SELECT lifecycle FROM secureshop_agents.owned_agency_role_targets WHERE original_platform_owner_id=$1',[sibling.scope.platformOwnerId])).rows[0].lifecycle,'active');
  assert.deepEqual((await deletionProbe.query('SELECT to_jsonb(e) row FROM secureshop_agents.owned_agency_role_effects e ORDER BY target_key,request_id,call_id')).rows,effectsBefore);
 }finally{await deletionProbe.query('ROLLBACK');deletionProbe.release();}
 assert.deepEqual((await am.query('SELECT to_jsonb(t) row FROM secureshop_agents.owned_agency_role_targets t ORDER BY target_key')).rows,targetsBefore);
 const lifecycle=require('../../server/database/postgres/secureshopConversationLifecycleRepository').createSecureShopConversationLifecycleRepository({pool:agents});
 const retirement={resetId:randomUUID(),binding:primary.scope};await lifecycle.beginRetirement(retirement);await lifecycle.beginRetirement(retirement);
 assert.equal((await agents.query('SELECT lifecycle FROM secureshop_agents.owned_agency_role_targets WHERE original_platform_owner_id=$1',[primary.scope.platformOwnerId])).rows[0].lifecycle,'retired');
 await assert.rejects(primary.work(c=>repo.readWithClient(c,primary.context)),{code:'SHOP_AUTH_INVALID'});
 for(const read of [c=>repo.readWithClient(c,primary.context),c=>repo.readEffectWithClient(c,primary.context,ref),c=>repo.applyWithClient(c,q)])await assert.rejects(read(agents),{code:'AGENCY_ROLE_RETIRED'});
 await assert.rejects(repo.ensureWithClient(agents,primary.context),{code:'55000'});
 assert.deepEqual(await sibling.work(c=>repo.readEffectWithClient(c,sibling.context,Object.fromEntries(['requestId','runId','callId','effectKey'].map(k=>[k,siblingRequest[k]])))),siblingReceipt);
 assert.deepEqual((await am.query('SELECT to_jsonb(e) row FROM secureshop_agents.owned_agency_role_effects e ORDER BY target_key,request_id,call_id')).rows,effectsBefore);
 t.diagnostic('V29: real 0113 fresh DDL rollback, populated upgrade and nonempty second/no-op; runtime grants/triggers, real scene→persona transaction, exact replay/conflict/no-op, fixed no-effect, retirement and sibling/history. Controlled mode/ACL receipts are not model or canonical Judge proof; retirement component is not authenticated full-reset qualification.');
}
