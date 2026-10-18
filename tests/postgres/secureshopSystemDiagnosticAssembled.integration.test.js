'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),{randomUUID,createHash}=require('node:crypto'),{Pool}=require('pg');
test('canonical System diagnostic admission native authority and lifecycle',{skip:process.env.PERSONA_SYSTEM_DIAGNOSTIC_NATIVE!=='1',timeout:180000},async t=>{
 assert.equal(process.env.PG_TEST_DISPOSABLE,'yes');assert.equal(fs.realpathSync(process.cwd()),fs.realpathSync(process.env.DVAIA_ISOLATED_TEST_WORKSPACE));
 const pools=[];const pool=(store,role)=>{const u=new URL(process.env[`PERSONA_${store}_${role}_URL`]);assert.equal(u.hostname,'127.0.0.1');assert.match(u.pathname,/^\/dvaia_test_persona_[a-f0-9]+_(identity|fresh|commerce|aclfresh)$/);const p=new Pool({connectionString:u.href,max:2,statement_timeout:8000});pools.push(p);return p;};
 t.after(async()=>{const results=await Promise.allSettled(pools.map(p=>p.end()));assert.ok(results.every(r=>r.status==='fulfilled'));});
 const identity=pool('IDENTITY','RUNTIME'),im=pool('IDENTITY','MIGRATION'),agents=pool('FRESH','RUNTIME'),am=pool('FRESH','MIGRATION'),commerce=pool('COMMERCE','RUNTIME'),cm=pool('COMMERCE','MIGRATION'),fresh=pool('ACLFRESH','RUNTIME'),fm=pool('ACLFRESH','MIGRATION');
 const {migrate}=require('../../db/postgres/migrate');const base='db/postgres/workshop-migrations/secureshop_agents';
 const migrationName='9999_system_diagnostic_candidate.sql';
 const candidate='docs/modernization/drafts/secureshop-bound-system-diagnostic/schema.candidate.sql';
 const previous=fs.mkdtempSync(path.join(process.cwd(),'system-diagnostic-previous-')),combined=fs.mkdtempSync(path.join(process.cwd(),'system-diagnostic-candidate-'));
 t.after(()=>fs.rmSync(previous,{recursive:true,force:true}));
 t.after(()=>fs.rmSync(combined,{recursive:true,force:true}));
 for(const name of fs.readdirSync(base).filter(name=>name.endsWith('.sql')&&name<'0030_bound_system_diagnostics.sql')){fs.copyFileSync(path.join(base,name),path.join(previous,name));fs.copyFileSync(path.join(base,name),path.join(combined,name));}
 fs.copyFileSync(candidate,path.join(combined,migrationName));
 await migrate(im,'db/postgres/identity-migrations');await migrate(cm,'db/postgres/workshop-migrations/secureshop');await require('../../server/database/postgres/secureshopSeed').seedSecureShop(cm);await migrate(am,previous);

 const users=require('../../server/database/postgres/identityRepository').createIdentityRepository(identity),launches=require('../../server/database/postgres/secureshopLaunchRepository').createSecureShopLaunchRepository(identity);
 const authority=require('../../server/database/postgres/secureshopBoundPersonaAuthority').createSecureShopBoundPersonaAuthority({pool:agents,checkCurrent:s=>launches.assertCurrent(s)});
 const personas=require('../../server/database/postgres/secureshopBoundPersonaRepository').createSecureShopBoundPersonaRepository({commercePool:commerce,agentsPool:agents,personaAuthority:authority,auditStore:require('../../server/database/postgres/secureshopBoundAuditRepository').createBoundAuditStore({store:'agents',pool:agents})});await personas.ensureTemplates();
 const auth=require('../../server/services/secureshopBoundPersonaAuth').createSecureShopBoundPersonaAuth({repository:personas,personaAuthority:authority,launches,jwtSecret:'owned-acl-foundation-secret-at-least-32-bytes'});
 const owner=async()=>{const id=randomUUID(),passwordHash=await require('bcryptjs').hash('owned-only',4),u=await users.createUser({username:'acl-'+id.slice(0,8),email:id+'@example.invalid',passwordHash}),expiresAt=new Date(Date.now()+600000).toISOString(),s=await users.createSession({userId:u.id,token:randomUUID(),expiresAt,expectedPasswordHash:passwordHash}),issued=await launches.issueOrRenew({platformOwnerId:u.id,platformSessionId:s.id,expiresAt}),scope=require('../../server/services/secureshopConversationBinding').createLaunchScope(issued.binding),login=await auth.login({scope,username:'student_admin',password:'student123'}),verified=await auth.authenticateBoundToken({scope,token:login.token});return{scope,token:login.token,persona:login.user,sessionId:verified.sessionId,version:verified.authorityVersion};};
 const a=await owner(),b=await owner(),old=await owner();const coords=o=>[o.scope.launchId,o.scope.scenarioId,o.scope.generation,o.scope.platformOwnerId,o.scope.platformSessionId];
 const retire=o=>agents.query('INSERT INTO secureshop_agents.conversation_generation_retirements(reset_id,platform_launch_id,platform_scenario_id,from_generation,original_platform_owner_id,original_platform_session_id) VALUES($1,$2,$3,$4,$5,$6)',[randomUUID(),...coords(o)]);
 await retire(old);const before=(await agents.query('SELECT * FROM secureshop_agents.bound_persona_sessions ORDER BY session_id')).rows;const ledgerBefore=(await am.query('SELECT * FROM dvaia_migrations.ledger ORDER BY name')).rows;
 assert.deepEqual(await migrate(am,combined),[migrationName]);
 assert.deepEqual(await migrate(am,combined),[]);

 const {createSystemDiagnosticRepository:createRepo}=require('../../server/database/postgres/secureshopSystemDiagnosticRepository');
 const audit=require('../../server/database/postgres/secureshopBoundAuditRepository').createBoundAuditStore({store:'agents',pool:agents});
 const repository=createRepo({pool:agents,personaAuthority:authority,audit}),freshRepo=createRepo({pool:fresh,personaAuthority:authority,audit});
 assert.deepEqual((await agents.query('SELECT * FROM secureshop_agents.bound_persona_sessions ORDER BY session_id')).rows,before);
 const after=(await am.query('SELECT * FROM dvaia_migrations.ledger ORDER BY name')).rows;assert.deepEqual(after.slice(0,-1),ledgerBefore);
 assert.equal(after.at(-1).checksum,createHash('sha256').update(fs.readFileSync(candidate)).digest('hex'));
 const freshApplied=await migrate(fm,combined);assert.equal(freshApplied.at(-1),migrationName);assert.deepEqual(await migrate(fm,combined),[]);
 try{await repository.checkReadiness();await freshRepo.checkReadiness();}catch(error){if(error.schemaDiagnostic)fs.writeFileSync('system-diagnostic-schema-diagnostic.json',JSON.stringify(error.schemaDiagnostic,null,2));throw error;}
 await assert.rejects(createRepo({pool:am,personaAuthority:authority,audit}).checkReadiness(),{code:'SYSTEM_DIAGNOSTIC_NOT_READY'});
 let drifts=0;
 async function drift(change,restore){await fm.query(change);try{await assert.rejects(freshRepo.checkReadiness(),{code:'SYSTEM_DIAGNOSTIC_NOT_READY'});drifts++;}finally{await fm.query(restore);}await freshRepo.checkReadiness();}
 const prefix='secureshop_agents.bound_system_diagnostic_',tables=['admissions','outcomes','cleanup_receipts'];
 for(const table of tables){
  for(const privilege of ['SELECT',...(table==='cleanup_receipts'?[]:['INSERT'])])await drift(`REVOKE ${privilege} ON ${prefix+table} FROM dvaia_secureshop_agents_runtime`,`GRANT ${privilege} ON ${prefix+table} TO dvaia_secureshop_agents_runtime`);
  for(const privilege of ['UPDATE','DELETE','TRUNCATE','REFERENCES','TRIGGER',...(table==='cleanup_receipts'?['INSERT']:[])])await drift(`GRANT ${privilege} ON ${prefix+table} TO dvaia_secureshop_agents_runtime`,`REVOKE ${privilege} ON ${prefix+table} FROM dvaia_secureshop_agents_runtime`);
  await drift(`GRANT UPDATE(${table==='cleanup_receipts'?'receipt_sha256':'request_sha256'}) ON ${prefix+table} TO dvaia_secureshop_agents_runtime`,`REVOKE UPDATE(${table==='cleanup_receipts'?'receipt_sha256':'request_sha256'}) ON ${prefix+table} FROM dvaia_secureshop_agents_runtime`);
 }
 for(const table of tables)await drift(`GRANT SELECT ON ${prefix+table} TO PUBLIC`,`REVOKE SELECT ON ${prefix+table} FROM PUBLIC`);
 for(const fn of ['guard_system_diagnostic_record','guard_system_diagnostic_actor','cleanup_system_diagnostic_records'])for(const role of ['PUBLIC','dvaia_secureshop_agents_runtime'])await drift(`GRANT EXECUTE ON FUNCTION secureshop_agents.${fn}() TO ${role}`,`REVOKE EXECUTE ON FUNCTION secureshop_agents.${fn}() FROM ${role}`);
 const triggers=(await fm.query("SELECT tgrelid::regclass::text AS rel,tgname FROM pg_trigger WHERE NOT tgisinternal AND (tgname LIKE 'system_diagnostic_%' OR tgname LIKE 'a_system_diagnostic_%' OR tgname LIKE 'b_system_diagnostic_%')")).rows;
 assert.equal(triggers.length,9);
 for(const row of triggers)await drift(`ALTER TABLE ${row.rel} DISABLE TRIGGER ${row.tgname}`,`ALTER TABLE ${row.rel} ENABLE TRIGGER ${row.tgname}`);
 const checks=(await fm.query("SELECT conrelid::regclass::text AS rel,conname,pg_get_constraintdef(oid,false) AS def FROM pg_constraint WHERE conrelid::regclass::text LIKE 'secureshop_agents.bound_system_diagnostic_%' AND contype='c'")).rows;
 for(const row of checks){const drop=`ALTER TABLE ${row.rel} DROP CONSTRAINT ${row.conname}`,restore=`ALTER TABLE ${row.rel} ADD CONSTRAINT ${row.conname} ${row.def}`;await drift(drop,restore);await fm.query(drop);try{await fm.query(`ALTER TABLE ${row.rel} ADD CONSTRAINT ${row.conname} CHECK(true)`);await assert.rejects(freshRepo.checkReadiness(),{code:'SYSTEM_DIAGNOSTIC_NOT_READY'});drifts++;}finally{await fm.query(drop);await fm.query(restore);}await freshRepo.checkReadiness();}
 const foreignKey=(await fm.query("SELECT conname,pg_get_constraintdef(oid,false) AS def FROM pg_constraint WHERE conrelid='secureshop_agents.bound_system_diagnostic_outcomes'::regclass AND contype='f'")).rows[0];
 await drift(`ALTER TABLE ${prefix}outcomes DROP CONSTRAINT ${foreignKey.conname}`,`ALTER TABLE ${prefix}outcomes ADD CONSTRAINT ${foreignKey.conname} ${foreignKey.def}`);
 await drift(`ALTER TABLE ${prefix}admissions ALTER COLUMN persona_session_id DROP NOT NULL`,`ALTER TABLE ${prefix}admissions ALTER COLUMN persona_session_id SET NOT NULL`);
 const uniqueTarget=(await fm.query("SELECT conname,pg_get_constraintdef(oid,false) AS def FROM pg_constraint WHERE conrelid='secureshop_agents.bound_system_diagnostic_admissions'::regclass AND contype='u'")).rows[0];
 await drift(`ALTER TABLE ${prefix}admissions DROP CONSTRAINT ${uniqueTarget.conname}`,`ALTER TABLE ${prefix}admissions ADD CONSTRAINT ${uniqueTarget.conname} ${uniqueTarget.def}`);
 const context=o=>({scope:o.scope,persona:o.persona,personaSession:{sessionId:o.sessionId,authorityVersion:o.version}});
 const administrationBefore=(await agents.query(`SELECT count(*) AS n FROM ${prefix}admissions`)).rows[0].n;
 const originalAdministration=await repository.administration(context(a));assert.deepEqual(Object.keys(originalAdministration),['scopeKey']);assert.match(originalAdministration.scopeKey,/^[a-f0-9]{64}$/);
 assert.deepEqual(await repository.administration(context(a)),originalAdministration);assert.notEqual((await repository.administration(context(b))).scopeKey,originalAdministration.scopeKey);
 assert.equal((await agents.query(`SELECT count(*) AS n FROM ${prefix}admissions`)).rows[0].n,administrationBefore);
 const input=o=>({...context(o),operationId:randomUUID(),cmd_template:'printf',args:'TRAINING_DIAGNOSTIC_ONLY'});
 const contract=require('../../sidecars/sandbox-runner/owned-system/diagnostic-contract');
 const {bindDiagnosticResult}=require('../../sidecars/sandbox-runner/owned-system/diagnostic-wire');
 // Controlled receipt only: no executor or actual filesystem effect claimed.
 const targets=new Map();
 const admit=async x=>{const value=await repository.begin(x);targets.set(x.operationId,value.targetId);return value;};
 const receipt=x=>{const request={operationId:x.operationId,cmd_template:x.cmd_template,args:x.args},empty=createHash('sha256').update('').digest('hex');return bindDiagnosticResult({targetId:targets.get(x.operationId),request},{version:contract.VERSION,isolation:'bwrap-system-diagnostic-v1',operationId:x.operationId,requestSha256:contract.diagnosticRequestDigest(request),command:contract.diagnosticCommand(request),executed:true,exitCode:0,signal:null,timedOut:false,truncated:false,drained:true,stdout:'',stderr:'',encoding:'base64',stdoutBytes:0,stderrBytes:0,stdoutSha256:empty,stderrSha256:empty});};
 const first=input(a),concurrent=await Promise.all([admit(first),admit(first)]);
 assert.deepEqual(concurrent.map(x=>x.state).sort(),['admitted','pending']);
 await assert.rejects(repository.begin({...first,args:'other'}),{code:'OPERATION_CONFLICT'});
 await repository.assertCurrent(first,targets.get(first.operationId));await repository.complete({...first,receipt:receipt(first)});
 assert.equal((await repository.begin(first)).state,'completed');assert.deepEqual((await repository.operation(first)).receipt,receipt(first));
 await assert.rejects(repository.assertCurrent(first,targets.get(first.operationId)),{code:'SYSTEM_DIAGNOSTIC_OPERATION_TERMINAL'});
 for(const method of ['markUnknown','markNotExecuted']){const x=input(a);await admit(x);const terminal=await repository[method](x);assert.equal((await repository.begin(x)).state,terminal.state);assert.equal((await repository.operation(x)).state,terminal.state);await assert.rejects(repository.assertCurrent(x,targets.get(x.operationId)),{code:'SYSTEM_DIAGNOSTIC_OPERATION_TERMINAL'});await assert.rejects(repository.complete({...x,receipt:receipt(x)}),{code:'SYSTEM_DIAGNOSTIC_OUTCOME_UNCERTAIN'});}
 const sibling=input(b);await admit(sibling);await repository.complete({...sibling,receipt:receipt(sibling)});
 assert.equal((await repository.operation({...context(b),operationId:first.operationId})).state,'not_found');
 const laterLogin=await auth.login({scope:a.scope,username:'student_admin',password:'student123'}),later=await auth.authenticateBoundToken({scope:a.scope,token:laterLogin.token});
 assert.notEqual((await repository.administration({...context(a),personaSession:{sessionId:later.sessionId,authorityVersion:later.authorityVersion}})).scopeKey,originalAdministration.scopeKey);
 await assert.rejects(repository.operation({...first,personaSession:{sessionId:later.sessionId,authorityVersion:later.authorityVersion}}),{code:'OPERATION_CONFLICT'});
 assert.equal((await repository.operation(first)).state,'completed');
 const lost=input(a);let drop=true;
 const lostAuthority={async capture(x){const fence=await authority.capture(x);return {...fence,async withPersonaEffect(work){const value=await fence.withPersonaEffect(work);if(drop)throw Error('controlled lost commit acknowledgement');return value;}};}};
 const lostRepo=createRepo({pool:agents,personaAuthority:lostAuthority,audit});
 await assert.rejects(lostRepo.begin(lost),{code:'SYSTEM_DIAGNOSTIC_OUTCOME_UNCERTAIN'});drop=false;assert.equal((await admit(lost)).state,'pending');
 drop=true;await assert.rejects(lostRepo.complete({...lost,receipt:receipt(lost)}),{code:'SYSTEM_DIAGNOSTIC_OUTCOME_UNCERTAIN'});drop=false;assert.equal((await repository.operation(lost)).state,'completed');
 const revokedOwner=await owner(),revoked=input(revokedOwner);await admit(revoked);await personas.revokeOwnedSession({scope:revokedOwner.scope,shopUserId:revokedOwner.persona.id,sessionId:revokedOwner.sessionId});
 await assert.rejects(repository.administration(context(revokedOwner)),{code:'SHOP_AUTH_INVALID'});
 await assert.rejects(repository.complete({...revoked,receipt:receipt(revoked)}),{code:'SHOP_AUTH_INVALID'});await assert.rejects(repository.operation(revoked),{code:'SHOP_AUTH_INVALID'});
 const quotaOwner=await owner();const quotaRows=await Promise.allSettled(Array.from({length:12},()=>repository.begin(input(quotaOwner))));assert.equal(quotaRows.filter(x=>x.status==='fulfilled').length,8);await assert.rejects(repository.begin(input(quotaOwner)),{code:'SYSTEM_DIAGNOSTIC_QUOTA_EXCEEDED'});
 const retainedOwner=await owner();for(let i=0;i<128;i++){const raw=input(retainedOwner);await repository.begin(raw);await repository.markNotExecuted(raw);}await assert.rejects(repository.begin(input(retainedOwner)),{code:'SYSTEM_DIAGNOSTIC_QUOTA_EXCEEDED'});
 await assert.rejects(am.query(`UPDATE ${prefix}admissions SET target_id=gen_random_uuid() WHERE operation_id=$1`,[first.operationId]),{code:'55000'});
 await assert.rejects(am.query(`DELETE FROM ${prefix}outcomes WHERE operation_id=$1`,[first.operationId]),{code:'55000'});
 await assert.rejects(agents.query(`UPDATE ${prefix}admissions SET request_json='{}'`),{code:'42501'});await assert.rejects(agents.query(`DELETE FROM ${prefix}outcomes`),{code:'42501'});
 // Actual service+repository+authority; controlled client only, no HTTP/executor claim.
 let clientCalls=0;
 const service=require('../../server/services/secureshopBoundSystemDiagnosticService').createBoundSystemDiagnosticService({repository,client:{async execute(wire,options){await options.assertCurrent();clientCalls++;targets.set(wire.request.operationId,wire.targetId);return receipt(wire.request);}}});
 const serviceOwner=await owner(),serviceInput=input(serviceOwner);
 assert.equal((await service.execute(serviceInput)).state,'completed');assert.equal((await service.execute(serviceInput)).state,'completed');assert.equal(clientCalls,1);

 // Actual authenticated router + native private executor. Launch attachment uses
 // a real issued scope but is fixture middleware, not the production gateway.
 const httpOwner=await owner(),httpSibling=await owner();
 const endpoint=new URL(process.env.PERSONA_DIAGNOSTIC_EXECUTOR_URL);assert.equal(endpoint.hostname,'127.0.0.1');assert.equal(endpoint.protocol,'http:');
 const privateToken=process.env.PERSONA_DIAGNOSTIC_EXECUTOR_TOKEN;let actualPosts=0,notifyDispatch;
 const realClient=require('../../server/services/secureshopSystemDiagnosticClient').createSecureShopSystemDiagnosticClient({baseURL:endpoint.href,token:privateToken,fetchImpl:async(url,options)=>{if(options.method==='POST'){actualPosts++;notifyDispatch?.();}return fetch(url,options);}});
 const assembled=await require('../../server/services/secureshopSystemDiagnosticComposition').createSecureShopSystemDiagnosticComposition({agentsPool:agents,personaAuthority:authority,audit,client:realClient,authenticatePersona:auth.authenticatePersona});assert.equal(assembled.ready,true);const realService=assembled.service;
 const express=require('express'),app=express();app.use(express.json({limit:'128kb'}));
 let dropOperation=null;
 app.use((req,res,next)=>{req.ssLaunch=httpOwner.scope;const json=res.json.bind(res);res.json=value=>{if(value.operationId===dropOperation&&value.state==='completed'){dropOperation=null;res.destroy();return res;}return json(value);};next();});
 app.use(assembled.router);
 const server=app.listen(0,'127.0.0.1');await new Promise(resolve=>server.once('listening',resolve));
 t.after(()=>new Promise(resolve=>{server.closeAllConnections();server.close(resolve);}));
 const origin='http://127.0.0.1:'+server.address().port;
 const publicRequest={operationId:randomUUID(),cmd_template:'/usr/bin/uname',args:'-n'};
 const post=(body,token=httpOwner.token,signal)=>fetch(origin+'/admin/system/diagnostic',{method:'POST',headers:{authorization:'Bearer '+token,'content-type':'application/json'},body:JSON.stringify(body),signal:signal||AbortSignal.timeout(20000)});
 const get=(operationId,token=httpOwner.token)=>fetch(origin+'/admin/system/diagnostic-operations/'+operationId,{headers:{authorization:'Bearer '+token},signal:AbortSignal.timeout(10000)});
 const available=await fetch(origin+'/admin/system/diagnostic',{headers:{authorization:'Bearer '+httpOwner.token}});assert.equal(available.status,200);assert.match((await available.json()).administration.scopeKey,/^[a-f0-9]{64}$/);
 dropOperation=publicRequest.operationId;await assert.rejects(post(publicRequest));assert.equal(actualPosts,1);
 const readback=await get(publicRequest.operationId);assert.equal(readback.status,200);const observed=await readback.json();assert.equal(observed.state,'completed');assert.equal(observed.stdout,observed.hostname+'\n');assert.equal(observed.hostname,'system-diag-'+observed.targetId.replaceAll('-',''));assert.equal(observed.drained,true);
 const actualStored=await repository.operation({...context(httpOwner),operationId:publicRequest.operationId});assert.deepEqual(actualStored.receipt,observed.receipt);
 const replay=await post(publicRequest);assert.equal(replay.status,200);await replay.arrayBuffer();assert.equal(actualPosts,1);
 const laterHttpLogin=await auth.login({scope:httpOwner.scope,username:'student_admin',password:'student123'});
 const foreign=await get(publicRequest.operationId,laterHttpLogin.token);assert.equal(foreign.status,409);await foreign.arrayBuffer();assert.equal(actualPosts,1);
 const siblingActual={...context(httpSibling),operationId:randomUUID(),cmd_template:'/usr/bin/uname',args:'-n'};assert.equal((await realService.execute(siblingActual)).state,'completed');assert.equal(actualPosts,2);
 const siblingActualBefore=await repository.operation(siblingActual);
 const abortRequest={operationId:randomUUID(),cmd_template:'sleep',args:'30'},controller=new AbortController();
 const dispatched=new Promise(resolve=>notifyDispatch=resolve);const aborted=post(abortRequest,httpOwner.token,controller.signal).catch(error=>error);await dispatched;
 // Wait for actual remote admission occupancy, without inventing an effect witness.
 const busyDeadline=Date.now()+3000;let busy=false;while(Date.now()<busyDeadline){const health=await fetch(new URL('/secureshop/system/diagnostic-health',endpoint),{headers:{authorization:'Bearer '+privateToken},signal:AbortSignal.timeout(1000)});const status=health.status;await health.arrayBuffer();if(status===503){busy=true;break;}await new Promise(resolve=>setTimeout(resolve,20));}
 assert.equal(busy,true);controller.abort();await aborted;notifyDispatch=null;
 const terminalDeadline=Date.now()+10000;let abortedState;while(Date.now()<terminalDeadline){abortedState=await repository.operation({...context(httpOwner),operationId:abortRequest.operationId});if(abortedState.state==='unknown')break;await new Promise(resolve=>setTimeout(resolve,25));}assert.equal(abortedState.state,'unknown');assert.equal(actualPosts,3);
 assert.equal((await realService.execute({...context(httpOwner),...abortRequest})).state,'unknown');assert.equal(actualPosts,3);
 await retire(httpOwner);await assert.rejects(repository.operation({...context(httpOwner),operationId:publicRequest.operationId}));assert.deepEqual(await repository.operation(siblingActual),siblingActualBefore);
 const rows=async(table,o)=>(await agents.query(`SELECT * FROM ${prefix+table} WHERE platform_launch_id=$1 ORDER BY operation_id`,[o.scope.launchId])).rows;
 const siblingRows={admissions:await rows('admissions',b),outcomes:await rows('outcomes',b)};
 const preserved=(await rows('admissions',a)).map(r=>[r.operation_id,r.request_sha256.toString('hex'),r.binding_sha256.toString('hex')]);
 await retire(a);for(const row of await rows('admissions',a)){assert.equal(row.request_json,null);assert.equal(row.target_id,null);}for(const row of await rows('outcomes',a))assert.equal(row.receipt_json,null);
 assert.deepEqual((await rows('admissions',a)).map(r=>[r.operation_id,r.request_sha256.toString('hex'),r.binding_sha256.toString('hex')]),preserved);
 await assert.rejects(repository.begin(input(a)));
 const stored=siblingRows.admissions[0];
 await assert.rejects(agents.query(`INSERT INTO ${prefix}admissions (platform_launch_id,platform_scenario_id,platform_launch_generation,original_platform_owner_id,original_platform_session_id,operation_id,persona_id,persona_session_id,persona_role,authority_version,request_sha256,binding_sha256,request_json,target_id) SELECT $1,$2,$3,$4,$5,$6,persona_id,persona_session_id,persona_role,authority_version,request_sha256,binding_sha256,request_json,gen_random_uuid() FROM ${prefix}admissions WHERE operation_id=$7`,[...coords(a),randomUUID(),stored.operation_id]),{code:'55000'});
 await agents.query('SELECT * FROM secureshop_agents.destroy_bound_audit_owner($1,$2)',[a.scope.platformOwnerId,randomUUID()]);for(const table of ['admissions','outcomes'])assert.equal((await rows(table,a)).length,0);
 for(const table of ['admissions','outcomes'])assert.deepEqual(await rows(table,b),siblingRows[table]);
 await retire(b);for(const row of await rows('admissions',b))assert.equal(row.request_json,null);for(const row of await rows('outcomes',b))assert.equal(row.receipt_json,null);
 const auditRows=(await agents.query("SELECT outcome,params_json FROM secureshop_agents.bound_audit_events WHERE action='system_diagnostic'")).rows;assert.ok(auditRows.length);assert.ok(auditRows.every(r=>['completed','failed'].includes(r.outcome)));assert.ok(!JSON.stringify(auditRows).includes('TRAINING_SYSTEM_DIAGNOSTIC_ONLY'));
 fs.writeFileSync('system-diagnostic-assembled-result.json',JSON.stringify({status:'passed',candidateOnly:true,registered:false,fresh:true,populated:true,noop:true,readinessDrifts:drifts,realPersonaAuthority:true,actualAuditAdapter:true,controlledClientCalls:clientCalls,originalSessionReadback:true,laterSessionDenied:true,terminalNoReadmission:true,lostCommitAcknowledgementReadback:true,retirementRedaction:true,ownerDeletion:true,siblingPreserved:true,actualPrivateExecutorDispatches:actualPosts,committedResponseLossReadback:true,actualHostnameBinding:true,disconnectOutcome:'unknown; remote occupancy observed, no effect claim',routerAuth:true,productionGateway:false,receiptProvenance:'3 actual private executor POST dispatches; other journal lifecycle tests use controlled receipts',actualModelCalls:0},null,2));
});
