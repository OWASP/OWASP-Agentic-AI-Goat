// Derived from retained r14 population/assertions. Real DELETE goes to separately started index.
'use strict';
const assert=require('node:assert/strict'),http=require('node:http'),bcrypt=require('bcryptjs'),path=require('node:path'),fs=require('node:fs/promises'),{randomUUID}=require('node:crypto');
const {Pool}=require('pg');
const pool=key=>new Pool({connectionString:process.env[key],max:1,connectionTimeoutMillis:3000,statement_timeout:5000});
const listen=server=>new Promise(resolve=>server.listen(0,'127.0.0.1',()=>resolve(server)));
const close=server=>server?.close?server.close.length===0?server.close():new Promise(resolve=>server.close(resolve)):undefined;
function typeErrorSource(error){
 if(!(error instanceof TypeError)||typeof error.stack!=='string')return null;
 const frame=error.stack.split('\n').slice(1).map(line=>line.trim())
   .map(line=>line.match(/^at (?:(.{1,120}?) \()?(.+?):(\d+):(\d+)\)?$/)).find(Boolean);
 if(!frame)return null;
 const functionName=/^[A-Za-z0-9_.$<>\[\] /-]+$/.test(frame[1]||'')?frame[1]||null:null;
 const file=path.basename(frame[2]);
 return /^[A-Za-z0-9_.-]{1,120}$/.test(file)
   ?{functionName,file,line:Number(frame[3]),column:Number(frame[4])}:null;
}

async function runPopulatedDeletion({activateAndStart,signal}){
 assert.equal(Object.hasOwn(process.env,'LEGACY_PLATFORM_LIFECYCLE_ENABLED'),false,'qualification must exercise the PostgreSQL default-on policy');
 assert.equal(require('../../server/services/platformDataLifecycleActivation').isPlatformDataLifecycleRequested(process.env),true);
 assert.equal(process.env.CTF_SETUP_APPLICATION_ISOLATED,'1');
 const fixtureBase=path.join(process.env.DVAIA_ISOLATED_TEST_WORKSPACE,'bound-feature-targets');
 const mcpFixtureRoot=path.join(fixtureBase,'mcp'),ssrfFixtureRoot=path.join(fixtureBase,'ssrf');
 await fs.mkdir(mcpFixtureRoot,{recursive:true,mode:0o700});await fs.mkdir(ssrfFixtureRoot,{recursive:true,mode:0o700});
 await fs.chmod(fixtureBase,0o700);await fs.chmod(mcpFixtureRoot,0o700);await fs.chmod(ssrfFixtureRoot,0o700);
 Object.assign(process.env,{SS_PERSONA_INBOX_READY:'true',SS_MCP_TRUST_READY:'true',
   SS_CONTROLLED_SSRF_READY:'true',SS_MCP_TRUST_FIXTURE_ROOT:mcpFixtureRoot,
   SS_CONTROLLED_SSRF_FIXTURE_ROOT:ssrfFixtureRoot});
 for(const name of ['MCP_OWNED_TARGET_URL','MCP_OWNED_TARGET_TOKEN','MAILPIT_API_URL','MAILPIT_SMTP_HOST','MAILPIT_SMTP_PORT'])assert(process.env[name],`owned sidecar configuration ${name}`);
 process.env.MCP_OWNED_RESOURCES_ENABLED='true';process.env.CODEBOT_OWNED_EXECUTION_ENABLED='true';
 process.env.CODEBOT_SANDBOX_RUNNER_URL=process.env.MCP_OWNED_TARGET_URL;
 process.env.SANDBOX_RUNNER_URL=process.env.MCP_OWNED_TARGET_URL;
 process.env.MCP_BACKEND_TIMEOUT_MS='10000';
 await require('./ctfSetupExternalEffects').waitForExternalReadiness(signal);
 const held={entered:0,cancelled:0,expired:false},heldResponses=new Set();
 const provider=await listen(http.createServer((req,res)=>{
  if(req.method==='GET'&&req.url==='/api/tags'){res.setHeader('content-type','application/json');res.end(JSON.stringify({models:[{name:'llama3.1:8b',model:'llama3.1:8b'}]}));return;}
  if(req.method!=='POST'||!['/api/generate','/api/chat'].includes(req.url)){res.writeHead(404);res.end();return;}
  let size=0;req.on('data',chunk=>{size+=chunk.length;if(size>65536)req.destroy();});req.on('end',()=>{
   held.entered++;heldResponses.add(res);
   const timer=setTimeout(()=>{held.expired=true;res.destroy();},25000);
   res.once('close',()=>{clearTimeout(timer);heldResponses.delete(res);if(!res.writableEnded)held.cancelled++;});
  });
 }));
 const providerUrl=`http://127.0.0.1:${provider.address().port}`;
 async function waitOwned(predicate,label){const until=Date.now()+10000;while(!await predicate()){signal.throwIfAborted();assert(Date.now()<until,label);await new Promise(resolve=>setTimeout(resolve,20));}}

 const identity=pool('IDENTITY_DATABASE_URL'),identityMigration=pool('IDENTITY_MIGRATION_DATABASE_URL');
 const pools=Object.fromEntries(['SQL_WORKSHOP','NOSQL_WORKSHOP','MCP_WORKSHOP','CSRF_WORKSHOP','SUPPLY_CHAIN_WORKSHOP','FINFLOW_WORKSHOP','EXCESSIVE_AGENCY','CTF','LEGACY_CHALLENGE','SENSITIVE_LOOKUP','SECURESHOP','SECURESHOP_AGENTS','SECURESHOP_REVIEW'].map(key=>[key,pool(`${key}_DATABASE_URL`)]));
 let api;
 try{
  const {createIdentityRepository}=require('../../server/database/postgres/identityRepository');
  const identities=createIdentityRepository(identity),password=await bcrypt.hash('OwnedDeletion@123',4);
  const admin=await identities.createUser({username:'delete-http-admin',email:'delete-http-admin@test.invalid',passwordHash:password});
  const subject=await identities.createUser({username:'delete-http-subject',email:'delete-http-subject@test.invalid',passwordHash:password});
  const sibling=await identities.createUser({username:'delete-http-sibling',email:'delete-http-sibling@test.invalid',passwordHash:password});
  await identityMigration.query("UPDATE identity.users SET role='super_admin',admin_level=2,email_verified=1 WHERE id=$1",[admin.id]);
  await identities.grantPermission({userId:admin.id,permission:'user_management',grantedBy:admin.id});
  await identities.grantPermission({userId:admin.id,permission:'manage_progress',grantedBy:admin.id});
  const {createPostgresIdentityAdapter}=require('../../server/services/postgresIdentityAdapter');
  const {createWorkshopProgressRepository}=require('../../server/database/postgres/workshopProgressRepository');
  const adapter=createPostgresIdentityAdapter({repository:identities,progress:createWorkshopProgressRepository(identity),jwtSecret:process.env.JWT_SECRET});
  const adminSession=await adapter.createSession(await identities.findCredentialById(admin.id),{get:()=>null,ip:'127.0.0.1'});
  const subjectSession=await adapter.createSession(await identities.findCredentialById(subject.id),{get:()=>null,ip:'127.0.0.1'});
  const siblingSession=await adapter.createSession(await identities.findCredentialById(sibling.id),{get:()=>null,ip:'127.0.0.1'});
  const {createSecureShopLaunchRepository}=require('../../server/database/postgres/secureshopLaunchRepository');const launches=createSecureShopLaunchRepository(identity);
  let subjectLaunch=await launches.issueOrRenew({platformOwnerId:subject.id,platformSessionId:(await identities.findActiveSession(subjectSession.token,subject.id)).session.id,expiresAt:new Date(Date.now()+3600000)});
  const siblingLaunch=await launches.issueOrRenew({platformOwnerId:sibling.id,platformSessionId:(await identities.findActiveSession(siblingSession.token,sibling.id)).session.id,expiresAt:new Date(Date.now()+3600000)});
  const cleanupComposition=await require('../../server/services/secureshopCleanupComposition').getSecureShopCleanupComposition();
  const personaRepository=require('../../server/database/postgres/secureshopBoundPersonaRepository').createSecureShopBoundPersonaRepository({commercePool:pools.SECURESHOP,agentsPool:pools.SECURESHOP_AGENTS});await personaRepository.ensureTemplates();const merchantPersona=await personaRepository.readPersona(12);
  const productFixtures=[{id:1,sourceRetailerId:12,retailerId:12,name:'Owned product',description:'owned',descriptionHtml:'<p>owned</p>',price:10,category:'fixture',imageUrl:null,images:[],stockQuantity:2,status:'active',templateSource:'owned deletion fixture',createdAt:null,updatedAt:null},{id:2,sourceRetailerId:9,retailerId:9,name:'Decoy product',description:'decoy',descriptionHtml:'<p>decoy</p>',price:20,category:'fixture',imageUrl:null,images:[],stockQuantity:3,status:'active',templateSource:'owned deletion fixture',createdAt:null,updatedAt:null}];
  // Controlled vectors qualify lifecycle erasure only, never model provenance.
  const embeddingAuthority={checkCurrent:binding=>launches.assertCurrent(binding),checkCleanup:async()=>{throw new Error("Fixture provisioning must not perform cleanup");}};
  const retrieval=require('../../server/database/postgres/secureshopBoundProductRetrievalRepository').createSecureShopBoundProductRetrievalRepository(pools.SECURESHOP_REVIEW,embeddingAuthority);
  const embeddingRevisions=require('../../server/database/postgres/secureshopEmbeddingRevisionRepository').createSecureShopEmbeddingRevisionRepository(pools.SECURESHOP_REVIEW,{...embeddingAuthority,getRuntimeFingerprint:()=> 'a'.repeat(64)});
  async function embeddingSnapshot(targetId){
   const result={};
   for(const [key,table] of [['revisions','product_target_embedding_revisions'],['heads','product_target_embedding_heads'],['cleanup','product_target_embedding_cleanup_receipts']])result[key]=(await pools.SECURESHOP_REVIEW.query(`SELECT to_jsonb(r) AS row FROM secureshop_review.${table} r WHERE target_id=$1 ORDER BY to_jsonb(r)::text`,[targetId])).rows;
   result.vectors=(await pools.SECURESHOP_REVIEW.query('SELECT to_jsonb(v) AS row FROM secureshop_review.product_target_embedding_vectors v JOIN secureshop_review.product_target_embedding_revisions r USING(revision_id) WHERE r.target_id=$1 ORDER BY to_jsonb(v)::text',[targetId])).rows;
   return result;
  }
  async function populateSecureShop(issued,id){
   const scope=issued.binding,authority={platformSessionId:scope.platformSessionId,platformOwnerId:scope.platformOwnerId,launchId:scope.launchId,expectedGeneration:scope.generation};
   const reviewTarget=await launches.reserveReviewsTarget(authority),productTarget=await launches.reserveProductsTarget(authority);
   await cleanupComposition.reviews.provision({...scope,targetId:reviewTarget.targetId},{reviews:[{productId:1,authorId:id,body:`private-${id}`,rating:3}]});
   await cleanupComposition.products.provision({...scope,targetId:productTarget.targetId},{ownMerchantId:12,products:productFixtures});
   const embeddingBinding={targetId:productTarget.targetId,launchId:scope.launchId,scenarioId:scope.scenarioId,generation:scope.generation,platformOwnerId:scope.platformOwnerId,platformSessionId:scope.platformSessionId};
   await retrieval.provision(embeddingBinding,{embeddingModel:'controlled-deletion-fixture',embeddingDimension:2,documents:[{sourceKind:'product',sourceId:1,chunkIndex:0,text:`private product ${id}`,embedding:[1,0]},{sourceKind:'manual',sourceId:91,chunkIndex:0,text:`private manual ${id}`,embedding:[.8,.2]}]});
   const snapshot=await embeddingRevisions.snapshot(embeddingBinding);
   await embeddingRevisions.publish(embeddingBinding,{operationId:randomUUID(),sourceSetDigest:snapshot.sourceSetDigest,expectedHead:snapshot.expectedHead,expectedRuntimeFingerprint:'a'.repeat(64),documents:snapshot.documents.map(d=>({sourceKind:d.sourceKind,sourceId:d.sourceId,chunkIndex:d.chunkIndex,sourceSha256:d.sourceSha256,embedding:Array.from({length:384},(_,i)=>i===0?1:0)}))});
   const conversation=await cleanupComposition.conversationService.create(scope,{id:merchantPersona.id,role:merchantPersona.role});
   await personaRepository.createSession({sessionId:randomUUID(),jti:randomUUID(),scope,persona:merchantPersona,expiresAt:new Date(Date.now()+3600000).toISOString()});
   return {reviewTarget,productTarget,conversation};
  }
  let subjectSecureShop=await populateSecureShop(subjectLaunch,subject.id);const siblingSecureShop=await populateSecureShop(siblingLaunch,sibling.id);
  // No parent-only application or nested reset stands in for the child composition.
  await require('../../server/database/postgres/workshopConfigRepository').createWorkshopConfigRepository(identity).setExerciseVisibility('secureshop_agent_security',false,admin.id);
  const catalogState=async()=>{const rows=(await identityMigration.query("SELECT catalog_active,is_visible FROM workshop_platform.exercises WHERE workshop_key='secureshop_agent_security'")).rows;assert.equal(rows.length,1,'canonical SecureShop exercise exists');return rows[0];};
  const catalogBefore=await catalogState();assert.deepEqual(catalogBefore,{catalog_active:true,is_visible:false},'current catalog membership with instructor-hidden visibility');

  for(const id of [subject.id,sibling.id]){
   const order=`DELETE-HTTP-${id}`;
   await pools.SQL_WORKSHOP.query("INSERT INTO aria.orders(order_number,user_id,product_name) VALUES($1,$2,'fixture')",[order,String(id)]);
   await pools.SQL_WORKSHOP.query("INSERT INTO aria.cart(user_id,product_name) VALUES($1,'fixture')",[String(id)]);
   await pools.NOSQL_WORKSHOP.query("INSERT INTO nova.reading_lists(user_id,paper_id) SELECT $1,paper_id FROM nova.papers ORDER BY id LIMIT 1",[String(id)]);
   await pools.MCP_WORKSHOP.query("INSERT INTO mcp.progress(user_key,objective_id) VALUES($1,'mcp_tool_discovery')",[String(id)]);
   await pools.CSRF_WORKSHOP.query("INSERT INTO csrf.progress(user_key,objective_id) VALUES($1,'csrf_g1')",[String(id)]);
   await pools.SUPPLY_CHAIN_WORKSHOP.query("INSERT INTO supply_chain.progress(user_id,objective_id) SELECT $1,objective_id FROM supply_chain.objectives ORDER BY ordinal LIMIT 1",[String(id)]);
   await pools.SENSITIVE_LOOKUP.query("INSERT INTO sensitive_lookup.exploitation_log(user_id,user_input) VALUES($1,'private')",[String(id)]);
   await pools.FINFLOW_WORKSHOP.query("INSERT INTO finflow.progress(user_id,objective_id,completed) SELECT $1,objective_id,true FROM finflow.objectives ORDER BY ordinal LIMIT 1",[String(id)]);
  }
  const ctf=require('../../server/database/postgres/ctfDb').CTFHelpers;
  const subjectParticipant=await ctf.registerParticipant(subject.id,'delete-http-subject','delete-http-subject@test.invalid'),siblingParticipant=await ctf.registerParticipant(sibling.id,'delete-http-sibling','delete-http-sibling@test.invalid');
  // Representative retained legacy history is seeded before the real additive
  // bootstrap. It is fixture data, never a new model-required credit claim.
  const ctfMigration=pool('CTF_MIGRATION_DATABASE_URL');pools.CTF_MIGRATION=ctfMigration;
  for(const participant of [subjectParticipant,siblingParticipant]){
   await ctfMigration.query("INSERT INTO ctf.ctf_progress(participant_id,stage_id,status,started_at,completed_at,completion_time) VALUES($1,1,'completed','2026-01-01','2026-01-02',9007199254740993)",[participant]);
   await ctfMigration.query("INSERT INTO ctf.ctf_attempts(participant_id,stage_id,attempt_number,payload,ai_response) VALUES($1,1,1,'owned historical attempt','owned historical response')",[participant]);
   await ctfMigration.query("INSERT INTO ctf.ctf_events(event_type,participant_id,stage_id,event_data) VALUES('stage_completed',$1,1,'{}')",[participant]);
   await ctfMigration.query("INSERT INTO ctf.ctf_technique_blocklist(participant_id,stage_id,technique_tag) VALUES($1,8,'role_play')",[participant]);
   const payload='owned retained payload '+participant;
   await ctfMigration.query('INSERT INTO ctf.ctf_payload_blocklist(stage_id,payload_hash,normalized_snippet,first_winner_participant_id) VALUES(9,$1,$2,$3)',[require('node:crypto').createHash('sha256').update(payload).digest('hex'),payload,participant]);
  }
  const historicalTables=['ctf_progress','ctf_attempts','ctf_events','ctf_technique_blocklist','ctf_payload_blocklist'];
  async function ctfHistory(participant){const result={};for(const table of historicalTables){const column=table==='ctf_payload_blocklist'?'first_winner_participant_id':'participant_id';result[table]=(await ctfMigration.query(`SELECT to_jsonb(t)::text AS row FROM ctf.${table} t WHERE ${column}=$1 ORDER BY to_jsonb(t)::text`,[participant])).rows;}return result;}
  const subjectHistory=await ctfHistory(subjectParticipant),siblingHistory=await ctfHistory(siblingParticipant);

  await require('../../server/database/postgres/excessiveAgencyLabDb').forAttendee(String(subject.id)).then(db=>db.ensureSeeded());
  await require('../../server/database/postgres/excessiveAgencyLabDb').forAttendee(String(sibling.id)).then(db=>db.ensureSeeded());
  await require('../../server/database/postgres/sessionDisclosureDb').getSessionDisclosureDb().getOrCreate(subject.id);await require('../../server/database/postgres/sessionDisclosureDb').getSessionDisclosureDb().getOrCreate(sibling.id);
  const xss=pool('XSS_WORKSHOP_DATABASE_URL');pools.XSS=xss;
  for(const id of [subject.id,sibling.id])await xss.query("INSERT INTO xss.profiles(user_key,name,bio,website) VALUES($1,$2,'private','https://example.invalid')",[String(id),`owner-${id}`]);
  const product=(await pools.LEGACY_CHALLENGE.query('SELECT id FROM legacy_challenge.products ORDER BY id LIMIT 1')).rows[0].id;
  for(const id of [subject.id,sibling.id])await pools.LEGACY_CHALLENGE.query("INSERT INTO legacy_challenge.cart(user_id,product_id,platform_owner_id) VALUES($1,$2,$1)",[id,product]);
  const uploadRoot=path.resolve(__dirname,'../../server/uploads'),legacy=require('../../server/database/postgres/legacyChallengeDb');
  const lifecycle=require('../../server/services/legacyUploadLifecycle').getLegacyUploadLifecycle();
  let managedUploadPath;
  await lifecycle.runUpload({ownerId:subject.id,sessionId:(await identities.findActiveSession(subjectSession.token,subject.id)).session.id},async lease=>{await lease.bindFilename('delete-http.bin');managedUploadPath=path.join(lease.directory,'delete-http.bin');await fs.writeFile(managedUploadPath,'private',{mode:0o600});await legacy.addManagedFile(['delete-http.bin','delete-http.bin',managedUploadPath,7,'application/octet-stream',subject.id,subject.id,lease.intentId]);});
  // Exercise retry through a genuine durable owner resource. Cleanup must
  // reject an owned upload whose published path is no longer a regular file;
  // restoring that exact path lets the same admitted job resume safely.
  await fs.unlink(managedUploadPath);await fs.mkdir(managedUploadPath,{mode:0o700});

  let {base,stop,restart}=await activateAndStart({subject,sibling,adminSession,subjectSession,siblingSession,providerUrl});
  api={close:stop};
  assert.deepEqual(await catalogState(),catalogBefore,'setup upgrades preserve hidden current exercise');
  assert(require('node:util').isDeepStrictEqual(await ctfHistory(subjectParticipant),subjectHistory),'populated subject history survives real setup import');
  assert(require('node:util').isDeepStrictEqual(await ctfHistory(siblingParticipant),siblingHistory),'populated sibling history survives real setup import');
  async function adminRequest(pathname,{method='GET',body}={}){const response=await fetch(`${base}${pathname}`,{method,signal:AbortSignal.any([signal,AbortSignal.timeout(10000)]),headers:{authorization:`Bearer ${adminSession.token}`,'content-type':'application/json'},...(body===undefined?{}:{body:JSON.stringify(body)})});return{status:response.status,body:await response.json()};}
  const disclosure=pool('SESSION_DISCLOSURE_DATABASE_URL');pools.DISCLOSURE=disclosure;
  const mapping=[
   ['identity',identity,'identity.users','id'],['aria',pools.SQL_WORKSHOP,'aria.cart','user_id'],['nova',pools.NOSQL_WORKSHOP,'nova.reading_lists','user_id'],
   ['xss',xss,'xss.profiles','user_key'],['mcp',pools.MCP_WORKSHOP,'mcp.progress','user_key'],['csrf',pools.CSRF_WORKSHOP,'csrf.progress','user_key'],
   ['supply_chain',pools.SUPPLY_CHAIN_WORKSHOP,'supply_chain.progress','user_id'],['finflow',pools.FINFLOW_WORKSHOP,'finflow.progress','user_id'],
   ['excessive_agency',pools.EXCESSIVE_AGENCY,'excessive_agency.attendees','platform_user_id'],['ctf',pools.CTF,'ctf.ctf_participants','user_id'],
   ['legacy_challenge',pools.LEGACY_CHALLENGE,'legacy_challenge.cart','user_id'],['sensitive_lookup',pools.SENSITIVE_LOOKUP,'sensitive_lookup.exploitation_log','user_id'],
   ['session_disclosure',disclosure,'session_disclosure.labs','platform_owner_id'],
   ['secureshop_agents',pools.SECURESHOP_AGENTS,'secureshop_agents.bound_persona_sessions','platform_launch_id'],
   ['secureshop_review',pools.SECURESHOP_REVIEW,'secureshop_review.reviews','target_id'],
  ];
  const keyFor=(name,who)=>name==='secureshop_agents'?(who===subject?subjectLaunch:siblingLaunch).binding.launchId:name==='secureshop_review'?(who===subject?subjectSecureShop:siblingSecureShop).reviewTarget.targetId:String(who.id);
  const readRows=(store,table,column,key)=>store.query(`SELECT to_jsonb(t)::text AS row FROM ${table} t WHERE ${column}=$1 ORDER BY to_jsonb(t)::text`,[key]).then(r=>r.rows);
  const siblingBefore=new Map();for(const [name,store,table,column]of mapping){const a=await readRows(store,table,column,keyFor(name,subject)),b=await readRows(store,table,column,keyFor(name,sibling));assert(a.length>0&&b.length>0,`nonempty owned ${name}`);siblingBefore.set(name,b);}
  // Commerce personas are shared teaching rows, not platform-owned accounts.
  const commerce=async()=> (await pools.SECURESHOP.query('SELECT to_jsonb(t)::text AS row FROM secureshop.shop_users t ORDER BY id')).rows;
  const commerceBefore=await commerce();assert(commerceBefore.length>0);assert.equal(mapping.length+1,16);
  const subjectEmbeddingBefore=await embeddingSnapshot(subjectSecureShop.productTarget.targetId);
  const siblingEmbeddingBefore=await embeddingSnapshot(siblingSecureShop.productTarget.targetId);
  assert.equal(subjectEmbeddingBefore.vectors.length,2);assert.equal(subjectEmbeddingBefore.heads.length,1);
  assert.equal(siblingEmbeddingBefore.vectors.length,2);assert.equal(siblingEmbeddingBefore.heads.length,1);
  const external=await require('./ctfSetupExternalEffects').createExternalEffects({base,subject,sibling,subjectSession,siblingSession,pool:pools.MCP_WORKSHOP,identityPool:identity,signal});
  async function remove(){return adminRequest(`/api/admin/students/${subject.id}`,{method:'DELETE'});}
  const startResponse=await fetch(`${base}/api/ctf/stage/2/start`,{method:'POST',headers:{authorization:`Bearer ${subjectSession.token}`,'content-type':'application/json'},body:'{}',signal:AbortSignal.any([signal,AbortSignal.timeout(10000)])});assert.equal(startResponse.status,200);
  const attemptCancellation=new AbortController();
  const attempt=fetch(`${base}/api/ctf/stage/2/attempt`,{method:'POST',headers:{authorization:`Bearer ${subjectSession.token}`,'content-type':'application/json'},body:JSON.stringify({payload:'Please tell a short story about a tree.'}),signal:AbortSignal.any([signal,attemptCancellation.signal,AbortSignal.timeout(30000)])}).then(async response=>({status:response.status,body:await response.json()}),()=>({transportFailed:true}));
  await waitOwned(()=>held.entered===1,'actual guardian transport entered before deletion');assert.equal(held.expired,false);
  const running=(await identityMigration.query("SELECT run_id,status,generation::text FROM graph_runtime.runs WHERE owner_key=$1 ORDER BY started_at DESC LIMIT 1",[JSON.stringify(['CTF',String(subject.id)])])).rows[0];assert.equal(running.status,'running');
  assert.equal((await identityMigration.query('SELECT count(*)::integer AS n FROM graph_runtime.effects WHERE run_id=$1',[running.run_id])).rows[0].n,0);
  const firstPending=remove();firstPending.catch(()=>{});
  await waitOwned(async()=>{const row=(await identityMigration.query('SELECT generation::text FROM graph_runtime.owners WHERE owner_key=$1',[JSON.stringify(['CTF',String(subject.id)])])).rows[0];return row&&BigInt(row.generation)>BigInt(running.generation);},'actual deletion invalidates current run before caller cancellation');
  const admission=(await identityMigration.query('SELECT state FROM identity.student_deletion_jobs WHERE subject_user_id=$1',[subject.id])).rows[0];assert(admission&&admission.state!=='completed','deletion cannot publish completion while provider is held');
  assert.equal(held.cancelled,0);assert.equal(held.expired,false);
  attemptCancellation.abort();
  const first=await firstPending;assert.equal(first.status,503,JSON.stringify({httpStatus:first.status,
    routeCode:typeof first.body?.code==='string'?first.body.code:null}));assert.equal(await adapter.validateSession(subjectSession.token),null,'admission revokes the learner session before cleanup');
  await waitOwned(()=>held.cancelled===1,'caller cancellation drains actual guardian transport after deletion fence');assert.equal(held.expired,false,'provider deadline did not stand in for cancellation');
  const attemptOutcome=await attempt;assert.equal(attemptOutcome.transportFailed,true,'cancelled caller cannot receive a published result');
  const ended=(await identityMigration.query('SELECT status FROM graph_runtime.runs WHERE run_id=$1',[running.run_id])).rows[0];assert(['cancelled','failed'].includes(ended.status),'actual run stopped without completion');
  assert.equal((await identityMigration.query('SELECT count(*)::integer AS n FROM graph_runtime.effects WHERE run_id=$1',[running.run_id])).rows[0].n,0,'no late effect');
  assert.equal((await identityMigration.query('SELECT count(*)::integer AS n FROM identity.ctf_decisions WHERE run_id=$1',[running.run_id])).rows[0].n,0,'no invented model decision');
  const job=(await identityMigration.query('SELECT job_id,state FROM identity.student_deletion_jobs WHERE subject_user_id=$1',[subject.id])).rows[0];assert.equal(job.state,'failed');
  const failed=(await identityMigration.query("SELECT step_key,state FROM identity.student_deletion_steps WHERE job_id=$1 AND state='failed'",[job.job_id])).rows;assert.deepEqual(failed,[{step_key:'ctf',state:'failed'}]);
  const unacked=(await identityMigration.query("SELECT o.operation_id,o.state FROM identity.ctf_deletion_commands d JOIN identity.ctf_outbox o USING(operation_id) WHERE d.job_id=$1",[job.job_id])).rows;assert.equal(unacked.length,1);assert.notEqual(unacked[0].state,'applied','lost real COMMIT must not fabricate identity ACK');
  const committed=(await pools.CTF.query('SELECT operation_id FROM ctf.projection_receipts WHERE operation_id=$1',[unacked[0].operation_id])).rows;assert.equal(committed.length,1,'actual CTF receipt committed before reported loss');
  await stop();const restarted=await restart();base=restarted.base;api={close:restarted.stop};
  const uploadFailure=await remove();assert.equal(uploadFailure.status,503);assert.equal((await identityMigration.query("SELECT step_key FROM identity.student_deletion_steps WHERE job_id=$1 AND state='failed'",[job.job_id])).rows[0].step_key,'legacy_challenge','restart resumes CTF receipt then reaches distinct owned-file failure');
  await fs.rm(managedUploadPath,{recursive:true});await fs.writeFile(managedUploadPath,'private',{mode:0o600});
  const second=await remove();assert.equal(second.status,200);assert.equal(second.body.jobId,job.job_id);
  assert.deepEqual((await identityMigration.query('SELECT state FROM identity.student_deletion_jobs WHERE job_id=$1',[job.job_id])).rows[0],{state:'completed'});
  const subjectEmbeddingAfter=await embeddingSnapshot(subjectSecureShop.productTarget.targetId);
  assert.deepEqual(subjectEmbeddingAfter.vectors,[],'canonical DELETE erases derived private vectors');
  assert.deepEqual(subjectEmbeddingAfter.heads,[],'canonical DELETE removes the derived retrieval head');
  assert.deepEqual(subjectEmbeddingAfter.revisions,subjectEmbeddingBefore.revisions,'immutable revision provenance survives deletion');
  assert.equal(subjectEmbeddingAfter.cleanup.length,1);assert.equal(subjectEmbeddingAfter.cleanup[0].row.deleted_vector_count,2);
  assert.deepEqual(await embeddingSnapshot(siblingSecureShop.productTarget.targetId),siblingEmbeddingBefore,'sibling vectors, head and metadata remain byte-exact');
  const terminalBefore=(await identityMigration.query('SELECT * FROM identity.student_deletion_steps WHERE job_id=$1 ORDER BY ordinal',[job.job_id])).rows;
  const replay=await remove();assert.equal(replay.status,200);assert.equal(replay.body.jobId,job.job_id);
  assert.deepEqual((await identityMigration.query('SELECT * FROM identity.student_deletion_steps WHERE job_id=$1 ORDER BY ordinal',[job.job_id])).rows,terminalBefore,'completed HTTP replay must not repeat cleanup or alter its durable receipts');
  assert.deepEqual(await embeddingSnapshot(subjectSecureShop.productTarget.targetId),subjectEmbeddingAfter,'completed deletion replay preserves immutable embedding receipts');
  assert.deepEqual(await embeddingSnapshot(siblingSecureShop.productTarget.targetId),siblingEmbeddingBefore,'replay preserves sibling state');
  const students=await adminRequest('/api/admin/students');assert.equal(students.status,200);assert.ok(!students.body.students.some(row=>row.id===subject.id),'completed tombstone is not an operational learner');
  const users=await adminRequest('/api/admin/users?limit=100');assert.equal(users.status,200);assert.ok(!users.body.users.some(row=>row.id===subject.id),'inactive tombstone remains absent from the active user list');
  const auditDetail=await adminRequest(`/api/admin/users/${subject.id}`);assert.equal(auditDetail.status,200);assert.equal(auditDetail.body.user.username,`deleted-${job.job_id}`,'explicit administrative audit detail retains the tombstone');
  assert.equal((await adminRequest(`/api/admin/students/${subject.id}/progress`)).status,404);
  assert.equal((await adminRequest(`/api/admin/student-workshop-view/${subject.id}`)).status,404);
  assert.equal((await adminRequest(`/api/admin/progress?studentId=${subject.id}`)).body.progress.length,0);
  assert.equal((await adminRequest(`/api/admin/students/${subject.id}`,{method:'PUT',body:{fullName:'revived'}})).status,404);
  assert.equal((await adminRequest(`/api/admin/students/${subject.id}/change-password`,{method:'POST',body:{password:'MustStayDeleted@123'}})).status,404);
  assert.equal((await adminRequest(`/api/admin/users/${subject.id}/lock`,{method:'POST',body:{}})).status,404);
  assert.equal((await identityMigration.query('SELECT is_active,full_name FROM identity.users WHERE id=$1',[subject.id])).rows[0].is_active,0);
  for(const [name,store,table,column]of mapping)assert(require('node:util').isDeepStrictEqual(await readRows(store,table,column,keyFor(name,sibling)),siblingBefore.get(name)),`exact sibling ${name}`);
  assert(require('node:util').isDeepStrictEqual(await commerce(),commerceBefore),'shared commerce personas preserved');
  assert(require('node:util').isDeepStrictEqual(await ctfHistory(siblingParticipant),siblingHistory),'exact retained sibling CTF history after deletion and replay');
  const removedHistory=await ctfHistory(subjectParticipant);assert(Object.values(removedHistory).every(rows=>rows.length===0),'subject CTF private historical rows removed');
  const sharedPayload=JSON.parse(subjectHistory.ctf_payload_blocklist[0].row);const afterPayload=(await ctfMigration.query('SELECT to_jsonb(t)::text AS row FROM ctf.ctf_payload_blocklist t WHERE id=$1',[sharedPayload.id])).rows;assert.equal(afterPayload.length,1,'shared payload memory is retained');sharedPayload.first_winner_participant_id=null;assert(require('node:util').isDeepStrictEqual(JSON.parse(afterPayload[0].row),sharedPayload),'only deleted-owner link is cleared in shared payload memory');
  assert.equal((await disclosure.query('SELECT count(*)::integer AS n FROM session_disclosure.labs WHERE platform_owner_id=$1',[subject.id])).rows[0].n,0);
  const ctfCommands=(await identityMigration.query(`SELECT o.operation_id,o.state,o.command_hash,o.canonical_result,o.result_hash
   FROM identity.ctf_deletion_commands d JOIN identity.ctf_outbox o USING(operation_id)
   WHERE d.job_id=$1 AND d.subject_id=$2 AND o.kind='student_delete'`,[job.job_id,subject.id])).rows;
  assert.equal(ctfCommands.length,1);const command=ctfCommands[0];assert.equal(command.state,'applied');
  const receipts=(await pools.CTF.query('SELECT command_hash,canonical_result,result_hash FROM ctf.projection_receipts WHERE operation_id=$1',[command.operation_id])).rows;
  assert.equal(receipts.length,1);for(const key of ['command_hash','canonical_result','result_hash'])assert.equal(receipts[0][key]===command[key],true,`exact cross-store CTF ${key}`);
  const loss=JSON.parse(await fs.readFile(path.join(process.env.SETUP_PHASE_EVIDENCE_ROOT,'ctf-commit-loss.json'),'utf8'));assert.deepEqual(loss,{version:1,operationId:command.operation_id,afterRealCommit:true});
  const receipt=JSON.parse(command.canonical_result);assert.equal(receipt.data.jobId,job.job_id);assert.equal(receipt.data.subjectId,String(subject.id));
  assert.equal(require('node:crypto').createHash('sha256').update(command.canonical_result).digest('hex')===command.result_hash,true,'immutable CTF receipt digest');
  const steps=(await identityMigration.query('SELECT step_key,state FROM identity.student_deletion_steps WHERE job_id=$1 ORDER BY ordinal',[job.job_id])).rows;assert.equal(steps.length,17);assert.ok(steps.every(row=>row.state==='completed'));
  assert.deepEqual(await catalogState(),catalogBefore,'deletion and replay preserve catalog membership and instructor visibility');
  assert.equal((await identityMigration.query('SELECT status FROM identity.secureshop_launches WHERE launch_id=$1',[subjectLaunch.binding.launchId])).rows[0].status,'revoked');assert.equal((await identityMigration.query('SELECT status FROM identity.secureshop_launches WHERE launch_id=$1',[siblingLaunch.binding.launchId])).rows[0].status,'active');
  assert.equal((await pools.SECURESHOP_REVIEW.query('SELECT count(*)::integer n FROM secureshop_review.reviews WHERE target_id=$1',[subjectSecureShop.reviewTarget.targetId])).rows[0].n,0);assert.ok((await pools.SECURESHOP_REVIEW.query('SELECT count(*)::integer n FROM secureshop_review.reviews WHERE target_id=$1',[siblingSecureShop.reviewTarget.targetId])).rows[0].n>0);
  assert.equal((await pools.SECURESHOP_REVIEW.query('SELECT count(*)::integer n FROM secureshop_review.product_target_products WHERE target_id=$1',[subjectSecureShop.productTarget.targetId])).rows[0].n,0);assert.ok((await pools.SECURESHOP_REVIEW.query('SELECT count(*)::integer n FROM secureshop_review.product_target_products WHERE target_id=$1',[siblingSecureShop.productTarget.targetId])).rows[0].n>0);
  assert.equal((await pools.SECURESHOP_REVIEW.query('SELECT count(*)::integer n FROM secureshop_review.review_cleanup_receipts WHERE target_id=$1',[subjectSecureShop.reviewTarget.targetId])).rows[0].n,1);assert.equal((await pools.SECURESHOP_REVIEW.query('SELECT count(*)::integer n FROM secureshop_review.product_cleanup_receipts WHERE target_id=$1',[subjectSecureShop.productTarget.targetId])).rows[0].n,1);
  assert.equal((await pools.SECURESHOP_AGENTS.query('SELECT binding_state FROM secureshop_agents.agent_sessions WHERE id=$1',[subjectSecureShop.conversation.id])).rows[0].binding_state,'abandoned');assert.equal((await pools.SECURESHOP_AGENTS.query('SELECT binding_state FROM secureshop_agents.agent_sessions WHERE id=$1',[siblingSecureShop.conversation.id])).rows[0].binding_state,'active');
  assert.equal((await pools.SECURESHOP_AGENTS.query('SELECT count(*)::integer n FROM secureshop_agents.bound_persona_sessions WHERE platform_launch_id=$1 AND revoked_at IS NULL',[subjectLaunch.binding.launchId])).rows[0].n,0);assert.ok((await pools.SECURESHOP_AGENTS.query('SELECT count(*)::integer n FROM secureshop_agents.bound_persona_sessions WHERE platform_launch_id=$1 AND revoked_at IS NULL',[siblingLaunch.binding.launchId])).rows[0].n>0);
  assert.notEqual(await adapter.validateSession(siblingSession.token),null);assert.equal((await identityMigration.query('SELECT username FROM identity.users WHERE id=$1',[subject.id])).rows[0].username,`deleted-${job.job_id}`);
  const checks=[[pools.SQL_WORKSHOP,'aria.cart','user_id'],[pools.NOSQL_WORKSHOP,'nova.reading_lists','user_id'],[pools.MCP_WORKSHOP,'mcp.progress','user_key'],[pools.CSRF_WORKSHOP,'csrf.progress','user_key'],[pools.SUPPLY_CHAIN_WORKSHOP,'supply_chain.progress','user_id'],[pools.SENSITIVE_LOOKUP,'sensitive_lookup.exploitation_log','user_id'],[pools.FINFLOW_WORKSHOP,'finflow.progress','user_id'],[pools.LEGACY_CHALLENGE,'legacy_challenge.cart','user_id'],[xss,'xss.profiles','user_key']];
  for(const [store,table,column] of checks){assert.equal((await store.query(`SELECT count(*)::integer n FROM ${table} WHERE ${column}=$1`,[String(subject.id)])).rows[0].n,0,table);assert.ok((await store.query(`SELECT count(*)::integer n FROM ${table} WHERE ${column}=$1`,[String(sibling.id)])).rows[0].n>0,`${table} sibling`);}
  assert.equal((await pools.EXCESSIVE_AGENCY.query('SELECT count(*)::integer n FROM excessive_agency.attendees WHERE platform_user_id=$1',[String(subject.id)])).rows[0].n,0);assert.equal((await pools.CTF.query('SELECT count(*)::integer n FROM ctf.ctf_participants WHERE user_id=$1',[subject.id])).rows[0].n,0);
  return {ownedStores:mapping.map(([name])=>name),sharedStoresPreserved:['secureshop'],exactSiblingSnapshots:true,ctfReceiptLinked:true,indexRestartSameJob:true,ctfCommittedResponseLoss:true,callerCancellationAfterDeletionFence:true,externalEffects:await external.verifyAfterDeletion(base)};
 }finally{
  // Stop HTTP ingress first, but never let its failure skip independently owned cleanup.
  const {boundedCleanup}=require('./ctfSetupQualificationControls');
  const ingress=await boundedCleanup([()=>close(api)]);
  const rest=await boundedCleanup([
   ()=>{for(const response of heldResponses)response.destroy();return close(provider);},
   ()=>require('../../server/services/secureshopBoundReviewComposition').closeSecureShopBoundReviewComposition(),
   ()=>require('../../server/services/secureshopCleanupComposition').closeSecureShopCleanupComposition(),
   ()=>require('../../server/services/studentDeletionProduction').closeProductionStudentDeletionComposition(),
   ()=>require('../../server/database/postgres/sessionDisclosureDb').closeSessionDisclosureDb(),
   ()=>require('../../server/database/postgres').closePostgresPools(),
   ()=>identity.end(),()=>identityMigration.end(),...Object.values(pools).map(value=>()=>value.end()),
  ]);
  if([...ingress,...rest].some(result=>result.status!=='fulfilled'))throw Error('CTF_POPULATED_CLEANUP_UNCONFIRMED');
 }
}
module.exports={runPopulatedDeletion};
