'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),{randomUUID}=require('node:crypto'),{Pool}=require('pg');
const {migrate,readMigrations}=require('../../db/postgres/migrate');
const agentsDirectory=path.resolve(__dirname,'../../db/postgres/workshop-migrations/secureshop_agents');
const authorityMigration='0023_secureshop_persona_authority_state.sql';
function prefixLoader(){
 const fsp=require('node:fs/promises'),{Module,createRequire}=require('node:module');
 const filename=require.resolve('../../db/postgres/migrate'),localRequire=createRequire(filename),loaded=new Module(filename,module);
 loaded.filename=filename;
 loaded.require=name=>name==='node:fs/promises'?{
  async readdir(directory,...args){assert.equal(path.resolve(directory),agentsDirectory);return(await fsp.readdir(directory,...args)).filter(name=>name<authorityMigration);},
  readFile:(...args)=>fsp.readFile(...args),
 }:localRequire(name);
 loaded._compile(fs.readFileSync(filename,'utf8'),filename);return loaded.exports;
}
test('persona migration prefix retains canonical SQL and checksums without staging',async()=>{
 const fsp=require('node:fs/promises'),original=fsp.readdir,full=await readMigrations(agentsDirectory);
 assert.ok(full.some(row=>row.name===authorityMigration));
 assert.deepEqual(await prefixLoader().readMigrations(agentsDirectory),full.filter(row=>row.name<authorityMigration));
 assert.equal(fsp.readdir,original);assert.deepEqual(await readMigrations(agentsDirectory),full);
});
test('owned persona admin candidate: native transactional state, audit, replay and privileges',{skip:process.env.PERSONA_ADMIN_NATIVE!=='1',timeout:90000},async()=>{
 assert.equal(process.env.PG_TEST_DISPOSABLE,'yes');assert.equal(fs.realpathSync(process.cwd()),fs.realpathSync(process.env.OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE));
 const servers=[];const pools=[];const pool=(store,role)=>{const u=new URL(process.env[`PERSONA_${store}_${role}_URL`]);assert.equal(u.hostname,'127.0.0.1');assert.match(u.pathname,/^\/owasp_ai_goat_test_persona_[a-f0-9]+_(commerce|fresh|populated)$/);assert.equal(u.username,`dvaia_${store==='COMMERCE'?'secureshop':'secureshop_agents'}_${role.toLowerCase()}`);const p=new Pool({connectionString:u.href,max:4,statement_timeout:15000});pools.push(p);return p;};
 const cm=pool('COMMERCE','MIGRATION'),cr=pool('COMMERCE','RUNTIME');
 try{
 await migrate(cm,'db/postgres/workshop-migrations/secureshop');await require('../../server/database/postgres/secureshopSeed').seedSecureShop(cm);
 const canonical=await readMigrations(agentsDirectory),prefix=canonical.filter(row=>row.name<authorityMigration);
 assert.ok(canonical.some(row=>row.name===authorityMigration));
 const proofs=[];
 for(const mode of ['POPULATED','FRESH']){
 const m=pool(mode,'MIGRATION'),r=pool(mode,'RUNTIME');
 const initial=mode==='POPULATED'?prefix:canonical;
 assert.deepEqual(await (mode==='POPULATED'?prefixLoader().migrate:migrate)(m,agentsDirectory),initial.map(row=>row.name));
 const ledger=async()=>(await m.query('SELECT name,checksum FROM dvaia_migrations.ledger ORDER BY name')).rows;
 assert.deepEqual(await ledger(),initial.map(({name,checksum})=>({name,checksum})));
 const repo=require('../../server/database/postgres/secureshopBoundPersonaRepository').createSecureShopBoundPersonaRepository({commercePool:cr,agentsPool:r});
 await repo.ensureTemplates();const templates=await repo.listPersonas();
 const scope={launchId:randomUUID(),scenarioId:randomUUID(),generation:1,platformOwnerId:17,platformSessionId:27};
 const sibling={...scope,launchId:randomUUID(),platformOwnerId:18,platformSessionId:28};
 const create=async(s,role)=>{const p=templates.find(t=>t.role===role),sessionId=randomUUID(),jti=randomUUID();await repo.createSession({scope:s,sessionId,jti,persona:p,expiresAt:new Date(Date.now()+600000).toISOString()});return{p,sessionId,jti};};
 const admin=await create(scope,'admin'),target=await create(scope,'customer'),other=await create(sibling,'customer');
 await repo.rotateApiKey({scope,shopUserId:target.p.id,nextKey:'sk_ss_live_'+'a'.repeat(32)});
 await repo.rotateApiKey({scope:sibling,shopUserId:other.p.id,nextKey:'sk_ss_live_'+'b'.repeat(32)});
 const before=JSON.stringify((await r.query('SELECT * FROM secureshop_agents.bound_persona_templates ORDER BY shop_user_id')).rows);
 if(mode==='POPULATED')assert.deepEqual(await migrate(m,agentsDirectory),canonical.filter(row=>row.name>=authorityMigration).map(row=>row.name));
 assert.deepEqual(await ledger(),canonical.map(({name,checksum})=>({name,checksum})));
 assert.deepEqual(await migrate(m,agentsDirectory),[]);
 const audit=require('../../server/database/postgres/secureshopBoundAuditRepository').createBoundAuditStore({store:'agents',pool:r});
 const service=require('../../server/database/postgres/secureshopBoundUserAdministrationRepository').createSecureShopBoundUserAdministrationRepository({pool:r,auditStore:audit,checkCurrent:async s=>assert.equal(s.launchId,scope.launchId)});
 const candidateAuthority=require('../../server/database/postgres/secureshopBoundPersonaAuthority').createSecureShopBoundPersonaAuthority({pool:r,checkCurrent:async()=>{}});
 const boundRepo=require('../../server/database/postgres/secureshopBoundPersonaRepository').createSecureShopBoundPersonaRepository({commercePool:cr,agentsPool:r,personaAuthority:candidateAuthority,auditStore:audit});
 const auth=require('../../server/services/secureshopBoundPersonaAuth').createSecureShopBoundPersonaAuth({repository:boundRepo,personaAuthority:candidateAuthority,launches:{assertCurrent:async()=>({expiresAt:new Date(Date.now()+3600000).toISOString()})},jwtSecret:'candidate-test-secret-more-than-thirty-two-bytes'});
 const authScope={...scope,launchId:randomUUID(),platformOwnerId:19,platformSessionId:29};
 const authAdmin=await auth.login({scope:authScope,username:'student_admin',password:'student123'});
 const oldCustomer=await auth.login({scope:authScope,username:'student_customer',password:'student123'});
 const verifiedAdmin=await auth.authenticateBoundToken({scope:authScope,token:authAdmin.token});
 const authService=require('../../server/database/postgres/secureshopBoundUserAdministrationRepository').createSecureShopBoundUserAdministrationRepository({pool:r,auditStore:audit,checkCurrent:async()=>{}});
 const express=require('express'),app=express();app.use(express.json());
 const candidateComposition=require('../../server/services/secureshopUserAdministrationCandidateComposition').createUserAdministrationCandidateComposition({agentsPool:r,commercePool:cr,launches:{assertCurrent:async()=>({expiresAt:new Date(Date.now()+3600000).toISOString()})},jwtSecret:'candidate-test-secret-more-than-thirty-two-bytes',auditStore:audit,account:{profile:async({persona})=>templates.find(t=>t.id===persona.id)}});
 assert.deepEqual(await candidateComposition.assertStorageReady(),{storageReady:true,productionReady:false});const userAdmin=candidateComposition.users;
 app.use('/api/secureshop',(req,_res,next)=>{req.ssLaunch=authScope;next();},require('../../server/routes/secureshop/boundUserAdministration').createBoundUserAdministrationRouter({service:userAdmin,authenticatePersona:candidateComposition.auth.authenticatePersona}));
 const server=app.listen(0,'127.0.0.1');servers.push(server);await new Promise(resolve=>server.once('listening',resolve));const origin='http://127.0.0.1:'+server.address().port;
 const request=async(path,body,token=authAdmin.token)=>fetch(origin+'/api/secureshop'+path,{method:body?'POST':'GET',headers:{authorization:'Bearer '+token,...(body?{'content-type':'application/json'}:{})},...(body?{body:JSON.stringify(body)}:{})});
 assert.equal((await request('/admin/users',null,oldCustomer.token)).status,403);
 const directory=await request('/admin/users');assert.equal(directory.status,200);assert.equal((await directory.json()).users.length,3);
 assert.equal((await request('/admin/users/'+oldCustomer.user.id+'/role',{role:'banned'})).status,400);
 const roleChange={scope:authScope,actorId:authAdmin.user.id,actorSessionId:verifiedAdmin.sessionId,targetId:oldCustomer.user.id,operationId:randomUUID(),expectedVersion:'1',action:'set_role',role:'merchant'};
 const oldVerified=await auth.authenticateBoundToken({scope:authScope,token:oldCustomer.token});
 const fence=candidateAuthority.capture({scope:authScope,personaId:oldCustomer.user.id,sessionId:oldVerified.sessionId,role:oldCustomer.user.role,authorityVersion:oldVerified.authorityVersion});
 let effectCalls=0;const {startHeldPersonaGraph}=require('../fixtures/secureshopHeldPersonaGraph');
 const heldGraph=startHeldPersonaGraph({scope:authScope,persona:oldCustomer.user,fence,onEffect:async()=>{effectCalls++;}});await heldGraph.ready;
 const admission=await fence.assertRemoteAdmission();assert.equal(admission.pointInTimeOnly,true);
 const changedRole=await request('/admin/users/'+oldCustomer.user.id+'/role',{role:'merchant',operationId:roleChange.operationId,expectedVersion:'1'});assert.equal(changedRole.status,200);assert.equal((await changedRole.json()).receipt.role,'merchant'); // actual HTTP mutation completes while provider held
 const receiptRead=await request('/admin/users/operations/'+roleChange.operationId);assert.equal(receiptRead.status,200);assert.equal((await receiptRead.json()).receipt.operationId,roleChange.operationId);
 const replayRole=await request('/admin/users/'+oldCustomer.user.id+'/role',{role:'merchant',operationId:roleChange.operationId,expectedVersion:'1'});assert.equal((await replayRole.json()).replayed,true);
 heldGraph.release();await assert.rejects(heldGraph.running,{code:'SHOP_AUTH_INVALID'});assert.equal(heldGraph.effectCalls(),0);assert.equal(effectCalls,0);
 await assert.rejects(fence.assertRemoteAdmission(),{code:'SHOP_AUTH_INVALID'});
 await assert.rejects(auth.authenticateBoundToken({scope:authScope,token:oldCustomer.token}),{code:'SHOP_AUTH_INVALID'});
 const promoted=await auth.login({scope:authScope,username:'student_customer',password:'student123'});assert.equal(promoted.user.role,'merchant');
 const promotedSession=await auth.authenticateBoundToken({scope:authScope,token:promoted.token});
 const renewed=await auth.renew({scope:authScope,token:promoted.token});assert.equal(renewed.user.role,'merchant');
 const extraToken=await auth.login({scope:authScope,username:'student_customer',password:'student123'});
 const extraVerified=await auth.authenticateBoundToken({scope:authScope,token:extraToken.token});
 const passwordFence=candidateAuthority.capture({scope:authScope,personaId:extraToken.user.id,sessionId:extraVerified.sessionId,role:extraToken.user.role,authorityVersion:extraVerified.authorityVersion});
 const passwordGraph=startHeldPersonaGraph({scope:authScope,persona:extraToken.user,fence:passwordFence});await passwordGraph.ready;
 await auth.changePassword({scope:authScope,shopPersona:promoted.user,currentSessionId:promotedSession.sessionId,currentPassword:'student123',newPassword:'changed-owned-pass'});
 passwordGraph.release();await assert.rejects(passwordGraph.running,{code:'SHOP_AUTH_INVALID'});assert.equal(passwordGraph.effectCalls(),0);
 await assert.rejects(passwordFence.withPersonaEffect(async()=>{effectCalls++;}),{code:'SHOP_AUTH_INVALID'});assert.equal(effectCalls,0);
 const passwordAudit=(await r.query("SELECT shop_role FROM secureshop_agents.bound_audit_events WHERE launch_id=$1 AND action='password_change'",[authScope.launchId])).rows;assert.equal(passwordAudit.length,1);assert.equal(passwordAudit[0].shop_role,'merchant');
 const changed=await auth.login({scope:authScope,username:'student_customer',password:'changed-owned-pass'});assert.equal(changed.user.role,'merchant');
 const changedSession=await auth.authenticateBoundToken({scope:authScope,token:changed.token});
 const key=await auth.rotateApiKey({scope:authScope,shopPersona:changed.user,currentSessionId:changedSession.sessionId});assert.equal((await auth.authenticateApiKey({scope:authScope,presentedKey:key.api_key})).user.role,'merchant');
 const banFence=candidateAuthority.capture({scope:authScope,personaId:changed.user.id,sessionId:changedSession.sessionId,role:changed.user.role,authorityVersion:changedSession.authorityVersion});
 const effectEvent=randomUUID();const positiveGraph=startHeldPersonaGraph({scope:authScope,persona:changed.user,fence:banFence,onEffect:async c=>{await audit.append(c,{eventId:effectEvent,scope:authScope,persona:changed.user,actor:changed.user.role,action:'owned_local_effect',target:'fixture',paramsJson:'{}',outcome:'completed',sourceKind:'native_test',sourceId:effectEvent});return {content:[{type:'text',text:'Owned local observation'}]};}});await positiveGraph.ready;positiveGraph.release();await positiveGraph.running;assert.equal(positiveGraph.effectCalls(),1);
 assert.equal((await r.query('SELECT count(*)::int AS n FROM secureshop_agents.bound_audit_events WHERE event_id=$1',[effectEvent])).rows[0].n,1);
 const banGraph=startHeldPersonaGraph({scope:authScope,persona:changed.user,fence:banFence});await banGraph.ready;
 const bannedResponse=await request('/admin/users/'+changed.user.id+'/ban',{operationId:randomUUID(),expectedVersion:'2',reason:'owned fixture'});assert.equal(bannedResponse.status,200);
 const bannedDirectory=await request('/admin/users?banned=true');const listed=await bannedDirectory.json();assert.equal(listed.users.length,1);assert.equal(listed.users[0].authority_version,'3');
 banGraph.release();await assert.rejects(banGraph.running,{code:'SHOP_AUTH_INVALID'});assert.equal(banGraph.effectCalls(),0);
 await assert.rejects(banFence.withPersonaEffect(async()=>{effectCalls++;}),{code:'SHOP_AUTH_INVALID'});assert.equal(effectCalls,0);
 await assert.rejects(auth.login({scope:authScope,username:'student_customer',password:'changed-owned-pass'}));
 await assert.rejects(auth.renew({scope:authScope,token:changed.token}));
 await assert.rejects(auth.rotateApiKey({scope:authScope,shopPersona:changed.user,currentSessionId:changedSession.sessionId}));
 await assert.rejects(auth.authenticateApiKey({scope:authScope,presentedKey:key.api_key}));
 const input={scope,actorId:admin.p.id,actorSessionId:admin.sessionId,targetId:target.p.id,operationId:randomUUID(),expectedVersion:'1',action:'set_role',role:'merchant'};
 const result=await service.mutate(input);assert.equal(result.receipt.revokedSessions,1);assert.equal(result.receipt.revokedApiKeys,1);assert.equal(result.receipt.version,'2');
 assert.equal(await repo.readSession({scope,jti:target.jti}),null);assert.equal(await repo.readApiKey({scope,shopUserId:target.p.id}),null);
 assert.ok(await repo.readSession({scope:sibling,jti:other.jti}));assert.ok(await repo.readApiKey({scope:sibling,shopUserId:other.p.id}));
 const event=(await r.query('SELECT * FROM secureshop_agents.bound_audit_events WHERE event_id=$1',[input.operationId])).rows[0];assert.equal(event.shop_user_id,admin.p.id);assert.equal(event.target,String(target.p.id));assert.equal(event.shop_role,'admin');
 const replay=await service.mutate(input);assert.equal(replay.replayed,true);assert.deepEqual(replay.receipt,result.receipt);
 await assert.rejects(service.mutate({...input,scope:{...scope,launchId:randomUUID()},operationId:randomUUID()}),/./);
 await assert.rejects(service.mutate({...input,role:'admin'}),{code:'OPERATION_CONFLICT'});
 await assert.rejects(service.mutate({...input,operationId:randomUUID()}),{code:'REVISION_CONFLICT'});
 const ban=await service.mutate({...input,operationId:randomUUID(),expectedVersion:'2',action:'ban',role:undefined,reason:'owned test'});assert.ok(ban.receipt.bannedAt);assert.equal(ban.receipt.role,'merchant');
 assert.equal(JSON.stringify((await r.query('SELECT * FROM secureshop_agents.bound_persona_templates ORDER BY shop_user_id')).rows),before);
 await assert.rejects(r.query('DELETE FROM secureshop_agents.bound_persona_state'),{code:'42501'});
 await assert.rejects(r.query('UPDATE secureshop_agents.bound_persona_admin_operations SET target_id=target_id'),{code:'42501'});
 const fn=(await m.query("SELECT prosecdef,proconfig,has_function_privilege('public',oid,'EXECUTE') AS public_exec FROM pg_proc WHERE oid='secureshop_agents.revoke_admin_target_api_keys(uuid,uuid,bigint,integer,integer,integer,uuid,integer)'::regprocedure")).rows[0];assert.equal(fn.prosecdef,true);assert.equal(fn.public_exec,false);assert.ok(fn.proconfig.includes('search_path=pg_catalog, secureshop_agents'));
 await assert.rejects(r.query('SELECT secureshop_agents.revoke_admin_target_api_keys($1,$2,$3,$4,$5,$6,$7,$8)',[scope.launchId,scope.scenarioId,1,17,27,target.p.id,target.sessionId,admin.p.id]),{code:'42501'});
 const lifecycle=require('../../server/database/postgres/secureshopConversationLifecycleRepository').createSecureShopConversationLifecycleRepository({pool:r});
 const reset={binding:scope,resetId:randomUUID()};await lifecycle.beginRetirement(reset);await lifecycle.beginRetirement(reset);
 assert.equal((await r.query('SELECT count(*)::int AS n FROM secureshop_agents.bound_persona_state WHERE platform_launch_id=$1',[scope.launchId])).rows[0].n,0);
 const cleanup=(await r.query("SELECT * FROM secureshop_agents.bound_persona_admin_cleanup_receipts WHERE cleanup_id=$1 AND cleanup_kind='retirement'",[reset.resetId])).rows[0];assert.equal(Number(cleanup.deleted_state_count),1);assert.equal(Number(cleanup.deleted_operation_count),0);
 assert.equal((await r.query('SELECT count(*)::int AS n FROM secureshop_agents.bound_persona_admin_operations WHERE platform_launch_id=$1',[scope.launchId])).rows[0].n,2);
 await assert.rejects(service.mutate(input),{code:'STALE_AUTHORITY'});
 const freshScope={...scope,launchId:randomUUID()};const freshAdmin=await create(freshScope,'admin');
 const freshService=require('../../server/database/postgres/secureshopBoundUserAdministrationRepository').createSecureShopBoundUserAdministrationRepository({pool:r,auditStore:audit,checkCurrent:async()=>{}});
 await freshService.mutate({...input,scope:freshScope,actorSessionId:freshAdmin.sessionId,operationId:randomUUID()});
 const job=randomUUID();const destroyed=await r.query('SELECT * FROM secureshop_agents.destroy_bound_audit_owner($1,$2)',[scope.platformOwnerId,job]);assert.equal(destroyed.rowCount,1);
 const firstDeletion=(await r.query("SELECT * FROM secureshop_agents.bound_persona_admin_cleanup_receipts WHERE cleanup_id=$1 AND cleanup_kind='owner_deletion'",[job])).rows[0];assert.equal(Number(firstDeletion.deleted_operation_count),3);assert.equal(Number(firstDeletion.deleted_state_count),1);
 await r.query('SELECT * FROM secureshop_agents.destroy_bound_audit_owner($1,$2)',[scope.platformOwnerId,job]);assert.deepEqual((await r.query("SELECT * FROM secureshop_agents.bound_persona_admin_cleanup_receipts WHERE cleanup_id=$1 AND cleanup_kind='owner_deletion'",[job])).rows[0],firstDeletion);
 await assert.rejects(freshService.mutate({...input,scope:freshScope,actorSessionId:freshAdmin.sessionId,operationId:randomUUID()}),{code:'STALE_AUTHORITY'});
 await assert.rejects(r.query(`INSERT INTO secureshop_agents.bound_persona_state
 (platform_launch_id,platform_scenario_id,platform_launch_generation,original_platform_owner_id,original_platform_session_id,shop_user_id,effective_role,authority_version)
 VALUES($1,$2,1,17,27,$3,'admin',1)`,[freshScope.launchId,freshScope.scenarioId,target.p.id]),{code:'55000'});
 await assert.rejects(r.query(`INSERT INTO secureshop_agents.bound_persona_admin_operations
 (platform_launch_id,platform_scenario_id,platform_launch_generation,original_platform_owner_id,original_platform_session_id,operation_id,actor_id,original_actor_session_id,target_id,request_sha256,result_json)
 VALUES($1,$2,1,17,27,$3,$4,$5,$6,$7,'{}'::jsonb)`,[freshScope.launchId,freshScope.scenarioId,randomUUID(),admin.p.id,freshAdmin.sessionId,target.p.id,Buffer.alloc(32)]),{code:'55000'});
 assert.ok(await repo.readSession({scope:sibling,jti:other.jti}));assert.ok(await repo.readApiKey({scope:sibling,shopUserId:other.p.id}));
 await assert.rejects(r.query('DELETE FROM secureshop_agents.bound_persona_admin_cleanup_receipts'),{code:'42501'});
 proofs.push({mode,actualSessionAndKeyRevocation:true,actorTargetAudit:true,replayConflict:true,templatesAndSiblingPreserved:true,minimumTestedPrivileges:true,retirementAndOwnerDeletionReplay:true,heldDecisionRoleBanCredentialEffectFences:true});
 }
 fs.writeFileSync(process.env.WORKSHOP_RAG_EVIDENCE_PATH,JSON.stringify({scope:'Native repository foundation only; no auth overlay/effect/lifecycle availability claim',proofs},null,2));
 }finally{await Promise.all(servers.map(s=>new Promise(resolve=>s.close(resolve))));await Promise.all(pools.map(p=>p.end()));}
});
