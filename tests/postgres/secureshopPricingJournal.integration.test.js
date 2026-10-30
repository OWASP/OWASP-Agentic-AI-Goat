'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),{randomUUID,createHash}=require('node:crypto'),{Pool}=require('pg');
test('pricing candidate native original authority, journal and controlled graph',{skip:process.env.PERSONA_PRICING_NATIVE!=='1',timeout:process.env.PERSONA_PRICING_ACTUAL==='1'?840000:180000},async t=>{
 assert.equal(process.env.PG_TEST_DISPOSABLE,'yes');assert.equal(fs.realpathSync(process.cwd()),fs.realpathSync(process.env.OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE));
 const outputRoot=require('../fixtures/pricingOwnedOutput').pricingOwnedOutputRoot();
 const pools=[];const pool=(store,role)=>{const u=new URL(process.env[`PERSONA_${store}_${role}_URL`]);assert.equal(u.hostname,'127.0.0.1');assert.match(u.pathname,/^\/owasp_ai_goat_test_persona_[a-f0-9]+_(identity|fresh|commerce|aclfresh|review)$/);const p=new Pool({connectionString:u.href,max:2,statement_timeout:8000});pools.push(p);return p;};
 t.after(async()=>{const results=await Promise.allSettled(pools.map(p=>p.end()));assert.ok(results.every(r=>r.status==='fulfilled'));});
 const identity=pool('IDENTITY','RUNTIME'),im=pool('IDENTITY','MIGRATION'),agents=pool('FRESH','RUNTIME'),am=pool('FRESH','MIGRATION'),commerce=pool('COMMERCE','RUNTIME'),cm=pool('COMMERCE','MIGRATION'),fresh=pool('ACLFRESH','RUNTIME'),fm=pool('ACLFRESH','MIGRATION'),review=pool('REVIEW','RUNTIME'),rm=pool('REVIEW','MIGRATION');
 if(process.env.PERSONA_PRICING_BLOCKED_NATIVE==='1'){
  await verifyBlockedPricingSuccessor({identity,im,agents,am,commerce,cm,fresh,fm,review,rm,outputRoot});
  return;
 }
 const {migrate}=require('../../db/postgres/migrate');const base='db/postgres/workshop-migrations/secureshop_agents';
 const canonical=process.env.PERSONA_PRICING_CANONICAL==='1';
 const migrationName=canonical?'0033_bound_pricing.sql':'0033_bound_pricing_candidate.sql';
 const candidate=canonical?'db/postgres/workshop-migrations/secureshop_agents/0033_bound_pricing.sql':'docs/modernization/drafts/secureshop-bound-pricing/0033_bound_pricing.candidate.sql';
 const previous=fs.mkdtempSync(path.join(outputRoot,'pricing-previous-')),combined=fs.mkdtempSync(path.join(outputRoot,'pricing-candidate-'));
 t.after(()=>fs.rmSync(previous,{recursive:true,force:true}));
 t.after(()=>fs.rmSync(combined,{recursive:true,force:true}));
 for(const name of fs.readdirSync(base).filter(name=>name.endsWith('.sql')&&name<'0033')){fs.copyFileSync(path.join(base,name),path.join(previous,name));fs.copyFileSync(path.join(base,name),path.join(combined,name));}
 fs.copyFileSync(candidate,path.join(combined,migrationName));
 await migrate(im,'db/postgres/identity-migrations');await migrate(cm,'db/postgres/workshop-migrations/secureshop');await require('../../server/database/postgres/secureshopSeed').seedSecureShop(cm);await migrate(am,previous);await migrate(rm,'db/postgres/workshop-migrations/secureshop_review');

 const users=require('../../server/database/postgres/identityRepository').createIdentityRepository(identity),launches=require('../../server/database/postgres/secureshopLaunchRepository').createSecureShopLaunchRepository(identity);
 const authority=require('../../server/database/postgres/secureshopBoundPersonaAuthority').createSecureShopBoundPersonaAuthority({pool:agents,checkCurrent:s=>launches.assertCurrent(s)});
 const personas=require('../../server/database/postgres/secureshopBoundPersonaRepository').createSecureShopBoundPersonaRepository({commercePool:commerce,agentsPool:agents,personaAuthority:authority,auditStore:require('../../server/database/postgres/secureshopBoundAuditRepository').createBoundAuditStore({store:'agents',pool:agents})});await personas.ensureTemplates();
 const auth=require('../../server/services/secureshopBoundPersonaAuth').createSecureShopBoundPersonaAuth({repository:personas,personaAuthority:authority,launches,jwtSecret:'owned-acl-foundation-secret-at-least-32-bytes'});
 const ownerScope=async()=>{const id=randomUUID(),passwordHash=await require('bcryptjs').hash('owned-only',4),u=await users.createUser({username:'acl-'+id.slice(0,8),email:id+'@example.invalid',passwordHash}),expiresAt=new Date(Date.now()+(process.env.PERSONA_PRICING_ACTUAL==='1'?1200000:600000)).toISOString(),s=await users.createSession({userId:u.id,token:randomUUID(),expiresAt,expectedPasswordHash:passwordHash}),issued=await launches.issueOrRenew({platformOwnerId:u.id,platformSessionId:s.id,expiresAt});return{scope:require('../../server/services/secureshopConversationBinding').createLaunchScope(issued.binding)};};
 let runSetup;const owner=async(options={})=>{const {scope}=await ownerScope(),login=await auth.login({scope,username:'student_merchant',password:'student123'}),verified=await auth.authenticateBoundToken({scope,token:login.token});const result={scope,token:login.token,persona:login.user,sessionId:verified.sessionId,version:verified.authorityVersion};if(runSetup)await runSetup(result,options);return result;};
 const coords=o=>[o.scope.launchId,o.scope.scenarioId,o.scope.generation,o.scope.platformOwnerId,o.scope.platformSessionId];
 // Historical rows are migration data under the real 0032 guard, not current
 // authentication authority. Current login requires the later actor schema.
 const historicalOwners=[];
 for(let index=0;index<3;index++){
  const historical=await ownerScope();historicalOwners.push(historical);
  const inserted=await agents.query(`INSERT INTO secureshop_agents.bound_persona_sessions
   (session_id,jti_sha256,platform_launch_id,platform_scenario_id,platform_launch_generation,
    original_platform_owner_id,original_platform_session_id,shop_user_id,username,role,email,full_name,phone,expires_at)
   SELECT $1,$2,$3,$4,$5,$6,$7,shop_user_id,username,role,email,full_name,phone,clock_timestamp()+interval '20 minutes'
    FROM secureshop_agents.bound_persona_templates WHERE username='student_merchant'`,
   [randomUUID(),createHash('sha256').update(randomUUID()).digest(),...coords(historical)]);
  assert.equal(inserted.rowCount,1);
 }
 const old=historicalOwners[2];
 const retire=o=>agents.query('INSERT INTO secureshop_agents.conversation_generation_retirements(reset_id,platform_launch_id,platform_scenario_id,from_generation,original_platform_owner_id,original_platform_session_id) VALUES($1,$2,$3,$4,$5,$6)',[randomUUID(),...coords(o)]);
 await retire(old);const before=(await agents.query('SELECT * FROM secureshop_agents.bound_persona_sessions ORDER BY session_id')).rows;assert.equal(before.length,3);const ledgerBefore=(await am.query('SELECT * FROM dvaia_migrations.ledger ORDER BY name')).rows;
 assert.deepEqual(await migrate(am,combined),[migrationName]);
 assert.deepEqual(await migrate(am,combined),[]);
 assert.deepEqual((await agents.query('SELECT * FROM secureshop_agents.bound_persona_sessions ORDER BY session_id')).rows,before);
 const after=(await am.query('SELECT * FROM dvaia_migrations.ledger ORDER BY name')).rows;assert.deepEqual(after.slice(0,-1),ledgerBefore);
 assert.equal(after.at(-1).checksum,createHash('sha256').update(fs.readFileSync(candidate)).digest('hex'));
 const freshApplied=await migrate(fm,combined);assert.equal(freshApplied.at(-1),migrationName);assert.deepEqual(await migrate(fm,combined),[]);
 // Preserve the exact populated/fresh 0033 proof above, then extend the same
 // migration view to the complete current head before current auth/repositories.
 // The retained candidate name has identical 0033 bytes; never apply it twice.
 assert.deepEqual(fs.readFileSync(candidate),fs.readFileSync(path.join(base,'0033_bound_pricing.sql')));
 for(const name of fs.readdirSync(base).filter(name=>/^\d{4}_[a-z0-9_]+\.sql$/.test(name)&&Number(name.slice(0,4))>33))fs.copyFileSync(path.join(base,name),path.join(combined,name));
 await migrate(am,combined);assert.deepEqual(await migrate(am,combined),[]);
 await migrate(fm,combined);assert.deepEqual(await migrate(fm,combined),[]);
 const a=await owner(),b=await owner();

 const {createPricingRepository:createRepo}=require('../../server/database/postgres/secureshopPricingRepository');
 const audit=require('../../server/database/postgres/secureshopBoundAuditRepository').createBoundAuditStore({store:'agents',pool:agents});
 const products=require('../../server/database/postgres/secureshopBoundProductRepository').createSecureShopBoundProductRepository(review,{checkCurrent:s=>launches.assertCurrent(s),checkCleanup:async()=>{throw Error('cleanup not used');}});
 const catalog=require('../../server/services/secureshopBoundCatalog').createSecureShopBoundCatalog({sourcePool:commerce,repository:products,personaAuthority:authority,resolveTarget:s=>launches.reserveProductsTarget({launchId:s.launchId,platformSessionId:s.platformSessionId,platformOwnerId:s.platformOwnerId,expectedGeneration:s.generation}),checkCurrent:s=>launches.assertCurrent(s)});
 const targetSource=require('../../server/services/secureshopPricingTargetSource').createPricingTargetSource({catalog,productRepository:products,reviewPool:review,launches,personaAuthority:authority});
 const checkRunBinding=require('../../server/services/secureshopPricingRunBinding').createPricingRunBinding({identityPool:identity});
 const conversationRepository=require('../../server/database/postgres/secureshopBoundConversationsRepository').createBoundConversationsRepository({pool:agents,queue:async(_id,work)=>work()});
 const conversations=require('../../server/services/secureshopBoundConversation').createBoundConversationService({conversations:conversationRepository,launches});
 const preparedTargets=new Map();
 const nativeContext=o=>({scope:o.scope,persona:o.persona,personaSession:{sessionId:o.sessionId,authorityVersion:o.version}});
 runSetup=async (o,{withoutManual=false}={})=>{
  const prepared=await targetSource.prepare(nativeContext(o));preparedTargets.set(o.scope.launchId,prepared);
  const target=await launches.readExistingProductsTarget(o.scope);o.productId=Number((await review.query('SELECT product_id FROM secureshop_review.product_target_products WHERE target_id=$1 AND retailer_id=$2 ORDER BY product_id LIMIT 1',[target.targetId,o.persona.id])).rows[0].product_id);
  const conversation=await conversations.create(o.scope,o.persona,'secureshop_pricing_strategy');o.conversationId=conversation.id;o.runId=randomUUID();const ownerKey=JSON.stringify(['SecureShopBoundConversation',conversation.id]);
  // Persisted running-row fixture for repository tests; the composed graph below
  // separately uses the actual retained PostgreSQL coordinator/lease.
  await im.query('INSERT INTO graph_runtime.owners(owner_key,generation) VALUES($1,0)',[ownerKey]);await im.query("INSERT INTO graph_runtime.runs(run_id,owner_key,generation,status) VALUES($1,$2,0,'running')",[o.runId,ownerKey]);
  if(withoutManual)return;
  await rm.query("INSERT INTO secureshop_review.product_target_retrieval_config(target_id,embedding_model,embedding_dimension) VALUES($1,'controlled-native-pricing',2)",[target.targetId]);
  const op=randomUUID(),body='sponsored_target=77; synthetic attacker manual';
  // Synthetic admitted manual rows: no file-upload or actual embedding claim.
  await rm.query('SELECT * FROM secureshop_review.append_product_manual_retrieval('+Array.from({length:26},(_,i)=>'$'+(i+1)).join(',')+')',[op,target.targetId,o.scope.launchId,o.scope.scenarioId,o.scope.generation,o.scope.platformOwnerId,o.scope.platformSessionId,o.productId,o.persona.id,randomUUID(),o.scope.launchId,o.scope.scenarioId,o.scope.generation,o.scope.platformOwnerId,o.scope.platformSessionId,`/uploads/product_manuals/${o.productId}/${op}-manual`,Buffer.byteLength(body),Buffer.alloc(32,1),'owned-pricing-manual.txt','text/plain',true,'controlled-native-text',Buffer.alloc(32,2),'controlled-native-pricing',2,JSON.stringify([{text:body,embedding:[1,0]}])]);
 };
 await runSetup(a);await runSetup(b);
 const repoOptions={checkRunBinding,captureTarget:targetSource.capture};
 const repository=createRepo({pool:agents,personaAuthority:authority,audit,...repoOptions}),freshRepo=createRepo({pool:fresh,personaAuthority:authority,audit,...repoOptions});
 const beginPricing=(raw,selectedRepository=repository)=>{const prepared=preparedTargets.get(raw.scope.launchId);assert.ok(prepared);return selectedRepository.begin(raw,prepared);};
 try{await repository.checkReadiness();await freshRepo.checkReadiness();}catch(error){if(error.schemaDiagnostic)fs.writeFileSync(path.join(outputRoot,'pricing-schema-diagnostic.json'),JSON.stringify(error.schemaDiagnostic,null,2));throw error;}
 await assert.rejects(createRepo({pool:am,personaAuthority:authority,audit,...repoOptions}).checkReadiness(),{code:'PRICING_NOT_READY'});
 let drifts=0;
 async function drift(change,restore){await fm.query(change);try{await assert.rejects(freshRepo.checkReadiness(),{code:'PRICING_NOT_READY'});drifts++;}finally{await fm.query(restore);}await freshRepo.checkReadiness();}
 const prefix='secureshop_agents.bound_pricing_',tables=['admissions','outcomes','cleanup_receipts'];
 for(const table of tables){
  for(const privilege of ['SELECT',...(table==='cleanup_receipts'?[]:['INSERT'])])await drift(`REVOKE ${privilege} ON ${prefix+table} FROM dvaia_secureshop_agents_runtime`,`GRANT ${privilege} ON ${prefix+table} TO dvaia_secureshop_agents_runtime`);
  for(const privilege of ['UPDATE','DELETE','TRUNCATE','REFERENCES','TRIGGER',...(table==='cleanup_receipts'?['INSERT']:[])])await drift(`GRANT ${privilege} ON ${prefix+table} TO dvaia_secureshop_agents_runtime`,`REVOKE ${privilege} ON ${prefix+table} FROM dvaia_secureshop_agents_runtime`);
  await drift(`GRANT UPDATE(${table==='cleanup_receipts'?'receipt_sha256':'request_sha256'}) ON ${prefix+table} TO dvaia_secureshop_agents_runtime`,`REVOKE UPDATE(${table==='cleanup_receipts'?'receipt_sha256':'request_sha256'}) ON ${prefix+table} FROM dvaia_secureshop_agents_runtime`);
 }
 for(const table of tables)await drift(`GRANT SELECT ON ${prefix+table} TO PUBLIC`,`REVOKE SELECT ON ${prefix+table} FROM PUBLIC`);
 for(const fn of ['guard_pricing_record','guard_pricing_actor','cleanup_pricing_records'])for(const role of ['PUBLIC','dvaia_secureshop_agents_runtime'])await drift(`GRANT EXECUTE ON FUNCTION secureshop_agents.${fn}() TO ${role}`,`REVOKE EXECUTE ON FUNCTION secureshop_agents.${fn}() FROM ${role}`);
 for(const name of ['guard_pricing_record','guard_pricing_actor','cleanup_pricing_records']){
  const definition=(await fm.query('SELECT pg_get_functiondef($1::regprocedure) AS definition',[`secureshop_agents.${name}()`])).rows[0].definition;
  await drift(`CREATE OR REPLACE FUNCTION secureshop_agents.${name}() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$ BEGIN RETURN NEW; END $$`,definition);
 }
 const triggers=(await fm.query("SELECT tgrelid::regclass::text AS rel,tgname FROM pg_trigger WHERE NOT tgisinternal AND (tgname LIKE 'pricing_%' OR tgname LIKE 'a_pricing_%' OR tgname LIKE 'b_pricing_%')")).rows;
 assert.equal(triggers.length,9);
 for(const row of triggers)await drift(`ALTER TABLE ${row.rel} DISABLE TRIGGER ${row.tgname}`,`ALTER TABLE ${row.rel} ENABLE TRIGGER ${row.tgname}`);
 const checks=(await fm.query("SELECT conrelid::regclass::text AS rel,conname,pg_get_constraintdef(oid,false) AS def FROM pg_constraint WHERE conrelid::regclass::text LIKE 'secureshop_agents.bound_pricing_%' AND contype='c'")).rows;
 for(const row of checks){const drop=`ALTER TABLE ${row.rel} DROP CONSTRAINT ${row.conname}`,restore=`ALTER TABLE ${row.rel} ADD CONSTRAINT ${row.conname} ${row.def}`;await drift(drop,restore);await fm.query(drop);try{await fm.query(`ALTER TABLE ${row.rel} ADD CONSTRAINT ${row.conname} CHECK(true)`);await assert.rejects(freshRepo.checkReadiness(),{code:'PRICING_NOT_READY'});drifts++;}finally{await fm.query(drop);await fm.query(restore);}await freshRepo.checkReadiness();}
 const foreignKey=(await fm.query("SELECT conname,pg_get_constraintdef(oid,false) AS def FROM pg_constraint WHERE conrelid='secureshop_agents.bound_pricing_outcomes'::regclass AND contype='f'")).rows[0];
 await drift(`ALTER TABLE ${prefix}outcomes DROP CONSTRAINT ${foreignKey.conname}`,`ALTER TABLE ${prefix}outcomes ADD CONSTRAINT ${foreignKey.conname} ${foreignKey.def}`);
 await drift(`ALTER TABLE ${prefix}admissions ALTER COLUMN persona_session_id DROP NOT NULL`,`ALTER TABLE ${prefix}admissions ALTER COLUMN persona_session_id SET NOT NULL`);
 const uniqueTarget=(await fm.query("SELECT conname,pg_get_constraintdef(oid,false) AS def FROM pg_constraint WHERE conrelid='secureshop_agents.bound_pricing_admissions'::regclass AND contype='u'")).rows[0];
 await drift(`ALTER TABLE ${prefix}admissions DROP CONSTRAINT ${uniqueTarget.conname}`,`ALTER TABLE ${prefix}admissions ADD CONSTRAINT ${uniqueTarget.conname} ${uniqueTarget.def}`);
 const context=o=>({scope:o.scope,persona:o.persona,personaSession:{sessionId:o.sessionId,authorityVersion:o.version}});
 const administrationBefore=(await agents.query(`SELECT count(*) AS n FROM ${prefix}admissions`)).rows[0].n;
 const originalAdministration=await repository.administration(context(a));assert.deepEqual(Object.keys(originalAdministration),['scopeKey']);assert.match(originalAdministration.scopeKey,/^[a-f0-9]{64}$/);
 assert.deepEqual(await repository.administration(context(a)),originalAdministration);assert.notEqual((await repository.administration(context(b))).scopeKey,originalAdministration.scopeKey);
 assert.equal((await agents.query(`SELECT count(*) AS n FROM ${prefix}admissions`)).rows[0].n,administrationBefore);
 const input=o=>({...context(o),operationId:randomUUID(),runId:o.runId,task:'pricing-strategy',productId:o.productId,message:'Recommend an owned price.'});
 const contract=require('../../server/services/secureshopPricingContract');
 const targets=new Map();
 const admit=async x=>{const value=await beginPricing(x);targets.set(x.operationId,value.targetId);return value;};
 const receipt=x=>({version:'secureshop-pricing-execution.v1',targetId:targets.get(x.operationId),operationId:x.operationId,runId:x.runId,requestSha256:contract.requestDigest({operationId:x.operationId,task:x.task,productId:x.productId,message:x.message}),response:'Controlled native receipt only',observations:[]});
 const negative=input(a);
 await assert.rejects(beginPricing({...negative,runId:randomUUID()}),{code:'PRICING_RUN_AUTHORITY_UNAVAILABLE'});
 await assert.rejects(beginPricing({...negative,runId:b.runId}),{code:'PRICING_RUN_AUTHORITY_UNAVAILABLE'});
 const ownerKey=JSON.stringify(['SecureShopBoundConversation',a.conversationId]),staleRun=randomUUID();
 await im.query("INSERT INTO graph_runtime.runs(run_id,owner_key,generation,status) SELECT $1,owner_key,generation+1,'running' FROM graph_runtime.owners WHERE owner_key=$2",[staleRun,ownerKey]);
 await assert.rejects(beginPricing({...negative,runId:staleRun}),{code:'PRICING_RUN_AUTHORITY_UNAVAILABLE'});
 const first=input(a),concurrent=await Promise.all([admit(first),admit(first)]);
 assert.deepEqual(concurrent.map(x=>x.state).sort(),['admitted','pending']);
 await assert.rejects(beginPricing({...first,message:'other'}),{code:'OPERATION_CONFLICT'});
 await repository.assertCurrent(first,targets.get(first.operationId));await repository.complete({...first,receipt:receipt(first)});
 assert.equal((await beginPricing(first)).state,'completed');assert.deepEqual((await repository.operation(first)).receipt,receipt(first));
 const assessmentRead=await repository.readAssessment(first);assert.deepEqual(assessmentRead.receipt,receipt(first));assert.equal(assessmentRead.request.message,first.message);assert.match(assessmentRead.targetSnapshot.canary,/^[a-f0-9]{64}$/);
 await assert.rejects(repository.readAssessment({...first,runId:b.runId}),{code:'PRICING_RUN_UNAVAILABLE'});
 await assert.rejects(repository.assertCurrent(first,targets.get(first.operationId)),{code:'PRICING_OPERATION_TERMINAL'});
 for(const method of ['markUnknown','markNotExecuted']){const x=input(a);await admit(x);const terminal=await repository[method](x);assert.equal((await beginPricing(x)).state,terminal.state);assert.equal((await repository.operation(x)).state,terminal.state);await assert.rejects(repository.assertCurrent(x,targets.get(x.operationId)),{code:'PRICING_OPERATION_TERMINAL'});await assert.rejects(repository.complete({...x,receipt:receipt(x)}),{code:'PRICING_OUTCOME_UNCERTAIN'});}
 const sibling=input(b);await admit(sibling);await repository.complete({...sibling,receipt:receipt(sibling)});
 assert.equal((await repository.operation({...context(b),operationId:first.operationId})).state,'not_found');
 const laterLogin=await auth.login({scope:a.scope,username:'student_merchant',password:'student123'}),later=await auth.authenticateBoundToken({scope:a.scope,token:laterLogin.token});
 assert.notEqual((await repository.administration({...context(a),personaSession:{sessionId:later.sessionId,authorityVersion:later.authorityVersion}})).scopeKey,originalAdministration.scopeKey);
 await assert.rejects(repository.operation({...first,personaSession:{sessionId:later.sessionId,authorityVersion:later.authorityVersion}}),{code:'OPERATION_CONFLICT'});
 await assert.rejects(repository.readAssessment({...first,personaSession:{sessionId:later.sessionId,authorityVersion:later.authorityVersion}}),{code:'OPERATION_CONFLICT'});
 assert.equal((await repository.operation(first)).state,'completed');
 const lost=input(a);let drop=true;
 const lostAuthority={async capture(x){const fence=await authority.capture(x);return {...fence,async withPersonaEffect(work){const value=await fence.withPersonaEffect(work);if(drop)throw Error('controlled lost commit acknowledgement');return value;}};}};
 const lostRepo=createRepo({pool:agents,personaAuthority:lostAuthority,audit,...repoOptions});
 await assert.rejects(beginPricing(lost,lostRepo),{code:'PRICING_OUTCOME_UNCERTAIN'});drop=false;assert.equal((await admit(lost)).state,'pending');
 drop=true;await assert.rejects(lostRepo.complete({...lost,receipt:receipt(lost)}),{code:'PRICING_OUTCOME_UNCERTAIN'});drop=false;assert.equal((await repository.operation(lost)).state,'completed');
 const revokedOwner=await owner(),revoked=input(revokedOwner);await admit(revoked);await personas.revokeOwnedSession({scope:revokedOwner.scope,shopUserId:revokedOwner.persona.id,sessionId:revokedOwner.sessionId});
 await assert.rejects(repository.administration(context(revokedOwner)),{code:'SHOP_AUTH_INVALID'});
 await assert.rejects(repository.complete({...revoked,receipt:receipt(revoked)}),{code:'SHOP_AUTH_INVALID'});await assert.rejects(repository.operation(revoked),{code:'SHOP_AUTH_INVALID'});
 const quotaOwner=await owner();const quotaRows=await Promise.allSettled(Array.from({length:12},()=>beginPricing(input(quotaOwner))));assert.equal(quotaRows.filter(x=>x.status==='fulfilled').length,8);await assert.rejects(beginPricing(input(quotaOwner)),{code:'PRICING_QUOTA_EXCEEDED'});
 const retainedOwner=await owner();for(let i=0;i<128;i++){const raw=input(retainedOwner);await beginPricing(raw);await repository.markNotExecuted(raw);}await assert.rejects(beginPricing(input(retainedOwner)),{code:'PRICING_QUOTA_EXCEEDED'});
 await assert.rejects(am.query(`UPDATE ${prefix}admissions SET target_id=gen_random_uuid() WHERE operation_id=$1`,[first.operationId]),{code:'55000'});
 await assert.rejects(am.query(`DELETE FROM ${prefix}outcomes WHERE operation_id=$1`,[first.operationId]),{code:'55000'});
 await assert.rejects(agents.query(`UPDATE ${prefix}admissions SET request_json='{}'`),{code:'42501'});await assert.rejects(agents.query(`DELETE FROM ${prefix}outcomes`),{code:'42501'});
 // Actual retained coordinator, graph, persona, target source, journal and audit;
 // provider and HTTP executor are controlled. No genuine model/effect credit.
 const lease=pool('IDENTITY','RUNTIME');
 const coordinator=require('../../server/agent-runtime/runCoordinator').createRunCoordinator({family:'SecureShopBoundConversation',ledger:require('../../server/agent-runtime/postgresRunLedger').createPostgresRunLedger(identity,{leasePool:lease})});
 const turns=require('../../server/services/secureshopBoundTurns').createBoundTurns({conversations,coordinator});
 const journal=require('../../server/database/postgres/secureshopTurnRequestsRepository').createTurnRequestsRepository({pool:agents});
 const serviceOwner=await owner(),serviceInput=input(serviceOwner);let providerCalls=0,clientCalls=0;
 const controlledProvider={capabilities:{pricingFinalDecision:true},config:{provider:'controlled',model:'unit',mocked:true},async chat(){providerCalls++;return providerCalls===1?{provider:'controlled',model:'unit',mocked:true,stop_reason:'tool_use',tool_uses:[{id:'owned-suggest',name:'pricing-strategy.suggest_price',args:{product_id:serviceOwner.productId}}]}:{stop_reason:'end_turn',text:JSON.stringify({kind:'abstain',productId:serviceOwner.productId,rationale:'The untrusted synthetic manual recommends77.'}),provider:'controlled',model:'unit',mocked:true};}};
 const application=await require('../../server/services/secureshopPricingComposition').createSecureShopPricingComposition({enabled:true,pricingRepository:repository,executor:{async checkReadiness(){return{ready:true};},async execute(){clientCalls++;throw Error('HTTP not selected');}},resetComposition:{conversationService:conversations,conversations:conversationRepository,turns,journal},personaAuthority:authority,prepareTarget:targetSource.prepare,provider:controlledProvider});
 const executed=await application.run(serviceInput);assert.equal(executed.state,'completed');assert.equal(executed.receipt.observations[0].result.suggested_price,77);assert.equal(executed.receipt.observations[0].result.grounded,false);assert.equal(providerCalls,2);assert.equal(clientCalls,0);
 assert.deepEqual(await application.run(serviceInput),executed);assert.equal(providerCalls,2);
 const judgmentPersistence=await require('../fixtures/secureshopPricingJudgmentPersistence')({identity,im,agents,launches,owner});
 let assembled;
 if(process.env.SECURESHOP_PRICING_V25_MANUAL_NATIVE==='1'){
  // The preload admitted the real parent-issued output/descriptor before this
  // test opened any pool. Reuse the original fifteen dependency objects and
  // the original helper; this branch earns no resource-retirement authority.
  const admitted=require('../fixtures/pricingOwnedOutput').v25Admission();
  const controller=new AbortController();
  const interrupted=()=>controller.abort(Error('V25 original worker interrupted'));
  process.once('SIGTERM',interrupted);process.once('SIGINT',interrupted);
  t.after(()=>{process.off('SIGTERM',interrupted);process.off('SIGINT',interrupted);});
  const result=await require('./ownedPricingManualConsumer')._consume({
   ...admitted,admitted,signal:controller.signal,
   dependencies:{identity,im,agents,review,launches,conversations,
    conversationRepository,turns,journal,coordinator,catalog,products,authority,owner,auth}});
  assembled={actual:result.observation,manualConsumer:result.receipt};
 }else if(process.env.PERSONA_PRICING_HTTP_NATIVE==='1')assembled=await require('../fixtures/secureshopPricingAssembled')({identity,im,agents,review,launches,conversations,conversationRepository,turns,journal,coordinator,catalog,products,authority,auth,owner});
 const rows=async(table,o)=>(await agents.query(`SELECT * FROM ${prefix+table} WHERE platform_launch_id=$1 ORDER BY operation_id`,[o.scope.launchId])).rows;
 const siblingRows={admissions:await rows('admissions',b),outcomes:await rows('outcomes',b)};
 const preserved=(await rows('admissions',a)).map(r=>[r.operation_id,r.request_sha256.toString('hex'),r.binding_sha256.toString('hex')]);
 await retire(a);for(const row of await rows('admissions',a)){assert.equal(row.request_json,null);assert.equal(row.target_id,null);assert.equal(row.target_snapshot_json,null);}for(const row of await rows('outcomes',a))assert.equal(row.receipt_json,null);
 assert.deepEqual((await rows('admissions',a)).map(r=>[r.operation_id,r.request_sha256.toString('hex'),r.binding_sha256.toString('hex')]),preserved);
 await assert.rejects(beginPricing(input(a)));
 const stored=siblingRows.admissions[0];
 await assert.rejects(agents.query(`INSERT INTO ${prefix}admissions (platform_launch_id,platform_scenario_id,platform_launch_generation,original_platform_owner_id,original_platform_session_id,operation_id,persona_id,persona_session_id,persona_role,authority_version,request_sha256,binding_sha256,request_json,target_id,run_id,target_snapshot_json) SELECT $1,$2,$3,$4,$5,$6,persona_id,persona_session_id,persona_role,authority_version,request_sha256,binding_sha256,request_json,gen_random_uuid(),run_id,target_snapshot_json FROM ${prefix}admissions WHERE operation_id=$7`,[...coords(a),randomUUID(),stored.operation_id]),{code:'55000'});
 await agents.query('SELECT * FROM secureshop_agents.destroy_bound_audit_owner($1,$2)',[a.scope.platformOwnerId,randomUUID()]);for(const table of ['admissions','outcomes'])assert.equal((await rows(table,a)).length,0);
 for(const table of ['admissions','outcomes'])assert.deepEqual(await rows(table,b),siblingRows[table]);
 await retire(b);for(const row of await rows('admissions',b))assert.equal(row.request_json,null);for(const row of await rows('outcomes',b))assert.equal(row.receipt_json,null);
 const auditRows=(await agents.query("SELECT outcome,params_json FROM secureshop_agents.bound_audit_events WHERE action='pricing_execution'")).rows;assert.ok(auditRows.length);assert.ok(auditRows.every(r=>['completed','failed'].includes(r.outcome)));assert.ok(!JSON.stringify(auditRows).includes('TRAINING_PRICING_ONLY'));
 fs.writeFileSync(path.join(outputRoot,'pricing-journal-result.json'),JSON.stringify({status:'passed',assembled,judgmentPersistence,candidateOnly:!canonical,registered:canonical,fresh:true,populated:true,noop:true,readinessDrifts:drifts,realPersonaAuthority:true,actualAuditAdapter:true,controlledClientCalls:clientCalls,controlledProviderCalls:providerCalls,actualCoordinator:true,actualOwnedProductManualRead:true,manualIngestProvenance:'synthetic migration-role fixture, not file upload or embedding proof',originalSessionReadback:true,privateAssessmentReadback:true,laterSessionDenied:true,terminalNoReadmission:true,lostCommitAcknowledgementReadback:true,retirementRedaction:true,ownerDeletion:true,siblingPreserved:true,receiptProvenance:'controlled provider/receipt only; no native executor/model',actualModelCalls:assembled?.actual?.actualActorCalls??0,actualJudgeCalls:assembled?.actual?.actualJudgeCalls??0},null,2));
});

async function verifyBlockedPricingSuccessor({identity,im,agents,am,commerce,cm,fresh,fm,review,rm,outputRoot}){
 const {migrate}=require('../../db/postgres/migrate');
 const {createAgentsMigrationView}=require('../helpers/secureshopAgentsMigrationView');
 const previous=createAgentsMigrationView(80),current=createAgentsMigrationView(81);
 await migrate(im,'db/postgres/identity-migrations');
 await migrate(cm,'db/postgres/workshop-migrations/secureshop');
 await require('../../server/database/postgres/secureshopSeed').seedSecureShop(cm);
 await migrate(rm,'db/postgres/workshop-migrations/secureshop_review');
 await previous.migrate(am,previous.directory);
 await previous.migrate(fm,previous.directory);
 const users=require('../../server/database/postgres/identityRepository').createIdentityRepository(identity);
 const launches=require('../../server/database/postgres/secureshopLaunchRepository').createSecureShopLaunchRepository(identity);
 const authority=require('../../server/database/postgres/secureshopBoundPersonaAuthority').createSecureShopBoundPersonaAuthority({pool:agents,checkCurrent:s=>launches.assertCurrent(s)});
 const audit=require('../../server/database/postgres/secureshopBoundAuditRepository').createBoundAuditStore({store:'agents',pool:agents});
 const personas=require('../../server/database/postgres/secureshopBoundPersonaRepository').createSecureShopBoundPersonaRepository({commercePool:commerce,agentsPool:agents,personaAuthority:authority,auditStore:audit});
 await personas.ensureTemplates();
 const auth=require('../../server/services/secureshopBoundPersonaAuth').createSecureShopBoundPersonaAuth({repository:personas,personaAuthority:authority,launches,jwtSecret:'owned-pricing-blocked-only-at-least-32-bytes'});
 const products=require('../../server/database/postgres/secureshopBoundProductRepository').createSecureShopBoundProductRepository(review,{checkCurrent:s=>launches.assertCurrent(s),checkCleanup:async()=>{throw Error('cleanup not used');}});
 const catalog=require('../../server/services/secureshopBoundCatalog').createSecureShopBoundCatalog({sourcePool:commerce,repository:products,personaAuthority:authority,resolveTarget:s=>launches.reserveProductsTarget({launchId:s.launchId,platformSessionId:s.platformSessionId,platformOwnerId:s.platformOwnerId,expectedGeneration:s.generation}),checkCurrent:s=>launches.assertCurrent(s)});
 const targetSource=require('../../server/services/secureshopPricingTargetSource').createPricingTargetSource({catalog,productRepository:products,reviewPool:review,launches,personaAuthority:authority});
 const checkRunBinding=require('../../server/services/secureshopPricingRunBinding').createPricingRunBinding({identityPool:identity});
 const conversationRepository=require('../../server/database/postgres/secureshopBoundConversationsRepository').createBoundConversationsRepository({pool:agents,queue:async(_id,work)=>work()});
 const conversations=require('../../server/services/secureshopBoundConversation').createBoundConversationService({conversations:conversationRepository,launches});
 const {createPricingRepository}=require('../../server/database/postgres/secureshopPricingRepository');
 const repository=createPricingRepository({pool:agents,personaAuthority:authority,audit,checkRunBinding,captureTarget:targetSource.capture});
 const siblingRepository=createPricingRepository({pool:fresh,personaAuthority:authority,audit,checkRunBinding,captureTarget:targetSource.capture});
 const context=o=>({scope:o.scope,persona:o.persona,personaSession:{sessionId:o.sessionId,authorityVersion:o.version}});
 const owner=async()=>{
  const id=randomUUID(),passwordHash=await require('bcryptjs').hash('owned-only',4);
  const user=await users.createUser({username:'pricing-'+id.slice(0,8),email:id+'@example.invalid',passwordHash});
  const expiresAt=new Date(Date.now()+600000).toISOString();
  const session=await users.createSession({userId:user.id,token:randomUUID(),expiresAt,expectedPasswordHash:passwordHash});
  const issued=await launches.issueOrRenew({platformOwnerId:user.id,platformSessionId:session.id,expiresAt});
  const scope=require('../../server/services/secureshopConversationBinding').createLaunchScope(issued.binding);
  const login=await auth.login({scope,username:'student_merchant',password:'student123'});
  const verified=await auth.authenticateBoundToken({scope,token:login.token});
  const value={scope,persona:login.user,sessionId:verified.sessionId,version:verified.authorityVersion};
  value.preparedTarget=await targetSource.prepare(context(value));
  const target=await launches.readExistingProductsTarget(scope);
  value.productId=Number((await review.query('SELECT product_id FROM secureshop_review.product_target_products WHERE target_id=$1 AND retailer_id=$2 ORDER BY product_id LIMIT 1',[target.targetId,value.persona.id])).rows[0].product_id);
  const conversation=await conversations.create(scope,value.persona,'secureshop_pricing_strategy');
  value.conversationId=conversation.id;
  value.runId=randomUUID();
  const ownerKey=JSON.stringify(['SecureShopBoundConversation',conversation.id]);
  await im.query('INSERT INTO graph_runtime.owners(owner_key,generation) VALUES($1,0)',[ownerKey]);
  await im.query("INSERT INTO graph_runtime.runs(run_id,owner_key,generation,status) VALUES($1,$2,0,'running')",[value.runId,ownerKey]);
  return value;
 };
 const first=await owner(),sibling=await owner();
 const request=(o,competitorUrl)=>({...context(o),operationId:randomUUID(),runId:o.runId,task:'pricing-strategy',productId:o.productId,message:'Compare this exact owned product.',...(competitorUrl?{competitorUrl}:{})});
 const contract=require('../../server/services/secureshopPricingContract');
 const legacy=request(first),unknown=request(first),notExecuted=request(first),other=request(sibling);
 const admitted=new Map();
 const begin=raw=>repository.begin(raw,raw.scope.launchId===first.scope.launchId?first.preparedTarget:sibling.preparedTarget);
 for(const raw of [legacy,unknown,notExecuted,other])admitted.set(raw.operationId,await begin(raw));
 const requestHash=raw=>contract.requestDigest({operationId:raw.operationId,task:raw.task,productId:raw.productId,message:raw.message,...(raw.competitorUrl?{competitorUrl:raw.competitorUrl}:{}),...(raw.experiment?{experiment:raw.experiment}:{})});
 const legacyReceipt=raw=>({version:'secureshop-pricing-execution.v1',targetId:admitted.get(raw.operationId).targetId,operationId:raw.operationId,runId:raw.runId,requestSha256:requestHash(raw),response:'Controlled pre-upgrade receipt',observations:[]});
 await repository.complete({...legacy,receipt:legacyReceipt(legacy)});
 await repository.markUnknown(unknown);await repository.markNotExecuted(notExecuted);
 await repository.complete({...other,receipt:legacyReceipt(other)});
 const rows=async pool=>(await pool.query('SELECT operation_id,state,receipt_json,receipt_sha256 FROM secureshop_agents.bound_pricing_outcomes ORDER BY operation_id')).rows;
 const before=await rows(agents),siblingBefore=await rows(fresh);
 const ledgerBefore=(await am.query('SELECT name,checksum FROM dvaia_migrations.ledger ORDER BY name')).rows;
 assert.equal((await repository.operation(legacy)).state,'completed');
 await assert.rejects(repository.checkReadiness(),{code:'PRICING_NOT_READY'});
 assert.deepEqual(await current.migrate(am,current.directory),['0081_pricing_blocked_denial_outcome.sql']);
 assert.deepEqual(await current.migrate(am,current.directory),[]);
 assert.deepEqual(await current.migrate(fm,current.directory),['0081_pricing_blocked_denial_outcome.sql']);
 assert.deepEqual(await current.migrate(fm,current.directory),[]);
 assert.deepEqual(await rows(agents),before);
 assert.deepEqual(await rows(fresh),siblingBefore);
 const ledgerAfter=(await am.query('SELECT name,checksum FROM dvaia_migrations.ledger ORDER BY name')).rows;
 assert.deepEqual(ledgerAfter.slice(0,-1),ledgerBefore);
 assert.equal(ledgerAfter.at(-1).checksum,createHash('sha256').update(fs.readFileSync('db/postgres/workshop-migrations/secureshop_agents/0081_pricing_blocked_denial_outcome.sql')).digest('hex'));
 await repository.checkReadiness();await siblingRepository.checkReadiness();
 for(const [raw,state] of [[legacy,'completed'],[unknown,'unknown'],[notExecuted,'not_executed'],[other,'completed']])assert.equal((await repository.operation(raw)).state,state);
 const url='http://owned.training/pricing-policy-denied?item=Camera%202';
 const blocked=request(first,url),pending=await begin(blocked);
 const {DENIAL_ATTESTATION}=require('../../server/services/secureshopPricingReceipt');
 const attestation=Object.fromEntries(DENIAL_ATTESTATION.map(key=>[key,true]));
 const receipt={version:'secureshop-pricing-denial.v1',targetId:pending.targetId,operationId:blocked.operationId,runId:blocked.runId,requestSha256:requestHash(blocked),productId:blocked.productId,sourceCallId:'owned-compare',competitorUrl:url,mode:'fixed',reason:'policy_denied',modelDecision:{provider:'ollama',model:'llama3.1:8b',mocked:false,fallback:false},proof:{drained:true,result:{version:1,isolationAttestation:attestation,originalUrlSha256:createHash('sha256').update(url).digest('hex'),originalUrlBytes:Buffer.byteLength(url),mode:'fixed',status:'failed',category:'policy_denied',hops:[],hits:[]}}};
 assert.equal((await repository.block({...blocked,receipt})).state,'blocked');
 const modeCapability={version:1,featureId:'pricing',policyVersion:'owned-network-and-catalog-facts-v1',effectiveMode:'fixed',scope:{kind:'launch_feature',id:'pricing'}};
 const journal=require('../../server/database/postgres/secureshopTurnRequestsRepository').createTurnRequestsRepository({pool:agents});
 const binding=require('../../server/services/secureshopConversationBinding').createConversationBinding(blocked.scope,blocked.persona);
 const claim=await journal.claim({sessionId:first.conversationId,requestId:blocked.operationId,binding,message:blocked.message});
 assert.equal(claim.status,'claimed');
 await journal.complete({sessionId:first.conversationId,requestId:blocked.operationId,binding,claimId:claim.claimId,result:{
  source:'server',stopReason:'tool_denied',text:'Comparison blocked by fixed-mode policy. No competitor request was made.',
  taskMetadata:{operationId:blocked.operationId,requestSha256:receipt.requestSha256,state:'blocked',receiptSha256:require('../../server/services/mcp/protocolContext').canonicalDigest(receipt)},modeCapability
 }});
 const blockedRead=await repository.operation(blocked);
 assert.deepEqual(blockedRead.receipt,receipt);assert.deepEqual(blockedRead.modeCapability,modeCapability);
 assert.equal((await repository.begin(blocked)).state,'blocked');
 assert.equal((await repository.block({...blocked,receipt})).state,'blocked');
 const assessmentRead=await repository.readAssessment(blocked);
 assert.equal(assessmentRead.state,'blocked');assert.deepEqual(assessmentRead.modeCapability,modeCapability);
 const legacyBlocked=request(first),legacyPending=await begin(legacyBlocked);
 const legacyDenial={...receipt,targetId:legacyPending.targetId,operationId:legacyBlocked.operationId,requestSha256:requestHash(legacyBlocked)};
 assert.equal((await repository.block({...legacyBlocked,receipt:legacyDenial})).state,'blocked');
 assert.deepEqual((await repository.operation(legacyBlocked)).receipt,legacyDenial);
 const experimentBlocked={...request(first),experiment:{strategy:'premium',durationDays:14}},experimentPending=await begin(experimentBlocked);
 const experimentDenial={...receipt,targetId:experimentPending.targetId,operationId:experimentBlocked.operationId,requestSha256:requestHash(experimentBlocked)};
 assert.equal((await repository.block({...experimentBlocked,receipt:experimentDenial})).state,'blocked');
 assert.deepEqual((await repository.operation(experimentBlocked)).receipt,experimentDenial);
 await assert.rejects(repository.assertCurrent(blocked,pending.targetId),{code:'PRICING_OPERATION_TERMINAL'});
 await assert.rejects(repository.block({...blocked,receipt:{...receipt,sourceCallId:'changed'}}),{code:'OPERATION_CONFLICT'});
 await assert.rejects(repository.block({...legacy,receipt}),{code:'PRICING_DENIAL_INVALID'});
 for(const method of ['markUnknown','markNotExecuted']){
  const terminal=request(first,url),admission=await begin(terminal);
  await repository[method](terminal);
  const denied={...receipt,targetId:admission.targetId,operationId:terminal.operationId,requestSha256:requestHash(terminal)};
  await assert.rejects(repository.block({...terminal,receipt:denied}),{code:'PRICING_OUTCOME_UNCERTAIN'});
  assert.equal((await repository.operation(terminal)).state,method==='markUnknown'?'unknown':'not_executed');
 }
 assert.equal((await repository.operation({...context(sibling),operationId:blocked.operationId})).state,'not_found');
 const laterLogin=await auth.login({scope:first.scope,username:'student_merchant',password:'student123'});
 const later=await auth.authenticateBoundToken({scope:first.scope,token:laterLogin.token});
 await assert.rejects(repository.operation({...blocked,personaSession:{sessionId:later.sessionId,authorityVersion:later.authorityVersion}}),{code:'OPERATION_CONFLICT'});
 assert.deepEqual(await rows(fresh),siblingBefore);
 const siblingOwned=(await agents.query('SELECT * FROM secureshop_agents.bound_pricing_outcomes WHERE operation_id=$1',[other.operationId])).rows;
 const blockedHash=(await agents.query('SELECT receipt_sha256 FROM secureshop_agents.bound_pricing_outcomes WHERE operation_id=$1',[blocked.operationId])).rows[0].receipt_sha256;
 await agents.query('INSERT INTO secureshop_agents.conversation_generation_retirements(reset_id,platform_launch_id,platform_scenario_id,from_generation,original_platform_owner_id,original_platform_session_id) VALUES($1,$2,$3,$4,$5,$6)',[randomUUID(),first.scope.launchId,first.scope.scenarioId,first.scope.generation,first.scope.platformOwnerId,first.scope.platformSessionId]);
 const retired=(await agents.query('SELECT request_json,target_id,target_snapshot_json FROM secureshop_agents.bound_pricing_admissions WHERE operation_id=$1',[blocked.operationId])).rows[0];
 assert.equal(retired.request_json,null);assert.equal(retired.target_id,null);assert.equal(retired.target_snapshot_json,null);
 const redactedOutcome=(await agents.query('SELECT receipt_json,receipt_sha256 FROM secureshop_agents.bound_pricing_outcomes WHERE operation_id=$1',[blocked.operationId])).rows[0];
 assert.equal(redactedOutcome.receipt_json,null);assert.deepEqual(redactedOutcome.receipt_sha256,blockedHash);
 assert.deepEqual((await agents.query('SELECT * FROM secureshop_agents.bound_pricing_outcomes WHERE operation_id=$1',[other.operationId])).rows,siblingOwned);
 await assert.rejects(repository.operation(blocked));
 fs.writeFileSync(path.join(outputRoot,'pricing-journal-blocked-result.json'),JSON.stringify({status:'passed',scope:'V54 durable fixed-policy pricing denial; controlled receipt and disposable PostgreSQL only',fresh:true,populated:true,noop:true,priorStatesPreserved:true,oldLedgerPreserved:true,readiness:true,blockedDurable:true,legacyV1V2DeniedWithoutRequestRewrite:true,blockedReplay:true,blockedAssessmentRead:true,blockedTerminal:true,retirementRedaction:true,siblingPreserved:true,otherSessionDenied:true,actualModelCalls:0,actualExecutorCalls:0},null,2),{mode:0o600});
}
