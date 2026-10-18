'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),{randomUUID,createHash}=require('node:crypto'),{Pool}=require('pg');
const agentsDirectory=path.resolve(__dirname,'../../db/postgres/workshop-migrations/secureshop_agents');
function migrationView(before){
 assert.ok(['0028_','0029_','0030_'].includes(before));
 const fsp=require('node:fs/promises'),{Module,createRequire}=require('node:module');
 const filename=require.resolve('../../db/postgres/migrate'),localRequire=createRequire(filename),loaded=new Module(filename,module);
 loaded.filename=filename;
 loaded.require=name=>name==='node:fs/promises'?{
  async readdir(directory,...args){assert.equal(path.resolve(directory),agentsDirectory);return(await fsp.readdir(directory,...args)).filter(name=>name<before);},
  readFile:(...args)=>fsp.readFile(...args),
 }:localRequire(name);
 loaded._compile(fs.readFileSync(filename,'utf8'),filename);return loaded.exports;
}
test('canonical System config admission native authority and lifecycle',{skip:process.env.PERSONA_SYSTEM_CONFIG_NATIVE!=='1',timeout:180000},async t=>{
 assert.equal(process.env.PG_TEST_DISPOSABLE,'yes');assert.equal(fs.realpathSync(process.cwd()),fs.realpathSync(process.env.DVAIA_ISOLATED_TEST_WORKSPACE));
 const output=process.env.SYSTEM_CONFIG_TEST_OUTPUT_DIR;assert.ok(output&&path.isAbsolute(output),'Explicit absolute owned output directory required');
 const outputStat=fs.lstatSync(output);assert.ok(outputStat.isDirectory()&&!outputStat.isSymbolicLink());assert.equal(outputStat.uid,process.getuid());assert.equal(outputStat.mode&0o077,0);assert.equal(fs.realpathSync(output),output);assert.notEqual(output,fs.realpathSync(process.cwd()));
 const save=(name,value)=>fs.writeFileSync(path.join(output,name),JSON.stringify(value,null,2),{flag:'wx',mode:0o600});
 const pools=[];const pool=(store,role)=>{const u=new URL(process.env[`PERSONA_${store}_${role}_URL`]);assert.equal(u.hostname,'127.0.0.1');assert.match(u.pathname,/^\/dvaia_test_persona_[a-f0-9]+_(identity|fresh|commerce|aclfresh)$/);const p=new Pool({connectionString:u.href,max:2,statement_timeout:8000});pools.push(p);return p;};
 t.after(async()=>{const results=await Promise.allSettled(pools.map(p=>p.end()));assert.ok(results.every(r=>r.status==='fulfilled'));});
 const identity=pool('IDENTITY','RUNTIME'),im=pool('IDENTITY','MIGRATION'),agents=pool('FRESH','RUNTIME'),am=pool('FRESH','MIGRATION'),commerce=pool('COMMERCE','RUNTIME'),cm=pool('COMMERCE','MIGRATION'),fresh=pool('ACLFRESH','RUNTIME'),fm=pool('ACLFRESH','MIGRATION');
 const {migrate,readMigrations}=require('../../db/postgres/migrate');const base=agentsDirectory;
 const canonical=await readMigrations(base),canonicalNames=canonical.map(row=>row.name);
 const migrationName='0028_system_config_candidate.sql',correctionName='0029_system_config_retirement_guard.sql';
 const candidate=path.join(base,migrationName),correction=path.join(base,correctionName);
 assert.deepEqual(fs.readFileSync(candidate),fs.readFileSync('docs/modernization/drafts/secureshop-bound-system-config/schema.candidate.sql'));
 assert.deepEqual(fs.readFileSync(correction),fs.readFileSync('docs/modernization/drafts/secureshop-bound-system-config/retirement-guard.correction.sql'));
 await migrate(im,'db/postgres/identity-migrations');await migrate(cm,'db/postgres/workshop-migrations/secureshop');await require('../../server/database/postgres/secureshopSeed').seedSecureShop(cm);
 assert.deepEqual(await migrationView('0028_').migrate(am,base),canonicalNames.filter(name=>name<'0028_'));

 const users=require('../../server/database/postgres/identityRepository').createIdentityRepository(identity),launches=require('../../server/database/postgres/secureshopLaunchRepository').createSecureShopLaunchRepository(identity);
 const authority=require('../../server/database/postgres/secureshopBoundPersonaAuthority').createSecureShopBoundPersonaAuthority({pool:agents,checkCurrent:s=>launches.assertCurrent(s)});
 const personas=require('../../server/database/postgres/secureshopBoundPersonaRepository').createSecureShopBoundPersonaRepository({commercePool:commerce,agentsPool:agents,personaAuthority:authority,auditStore:require('../../server/database/postgres/secureshopBoundAuditRepository').createBoundAuditStore({store:'agents',pool:agents})});await personas.ensureTemplates();
 const auth=require('../../server/services/secureshopBoundPersonaAuth').createSecureShopBoundPersonaAuth({repository:personas,personaAuthority:authority,launches,jwtSecret:'owned-acl-foundation-secret-at-least-32-bytes'});
 const owner=async()=>{const id=randomUUID(),passwordHash=await require('bcryptjs').hash('owned-only',4),u=await users.createUser({username:'acl-'+id.slice(0,8),email:id+'@example.invalid',passwordHash}),expiresAt=new Date(Date.now()+600000).toISOString(),s=await users.createSession({userId:u.id,token:randomUUID(),expiresAt,expectedPasswordHash:passwordHash}),issued=await launches.issueOrRenew({platformOwnerId:u.id,platformSessionId:s.id,expiresAt}),scope=require('../../server/services/secureshopConversationBinding').createLaunchScope(issued.binding),login=await auth.login({scope,username:'student_admin',password:'student123'}),verified=await auth.authenticateBoundToken({scope,token:login.token});return{scope,token:login.token,persona:login.user,sessionId:verified.sessionId,version:verified.authorityVersion};};
 const a=await owner(),b=await owner(),old=await owner();const coords=o=>[o.scope.launchId,o.scope.scenarioId,o.scope.generation,o.scope.platformOwnerId,o.scope.platformSessionId];
 const retire=o=>agents.query('INSERT INTO secureshop_agents.conversation_generation_retirements(reset_id,platform_launch_id,platform_scenario_id,from_generation,original_platform_owner_id,original_platform_session_id) VALUES($1,$2,$3,$4,$5,$6)',[randomUUID(),...coords(o)]);
 await retire(old);const before=(await agents.query('SELECT * FROM secureshop_agents.bound_persona_sessions ORDER BY session_id')).rows;const ledgerBefore=(await am.query('SELECT * FROM dvaia_migrations.ledger ORDER BY name')).rows;
 assert.deepEqual(await migrationView('0029_').migrate(am,base),[migrationName]);

 const {createSystemConfigReadRepository:createRepo}=require('../../server/database/postgres/secureshopSystemConfigReadRepository');
 const audit=require('../../server/database/postgres/secureshopBoundAuditRepository').createBoundAuditStore({store:'agents',pool:agents});
 const repository=createRepo({pool:agents,personaAuthority:authority,audit}),freshRepo=createRepo({pool:fresh,personaAuthority:authority,audit});
 // Populate the registered0028 foundation before its0029 forward correction.
 const upgradeRequest={scope:a.scope,persona:a.persona,personaSession:{sessionId:a.sessionId,authorityVersion:a.version},operationId:randomUUID(),path:'missing'};
 await repository.begin(upgradeRequest);await repository.markNotExecuted(upgradeRequest);
 const upgradeBefore=(await agents.query('SELECT * FROM secureshop_agents.bound_system_config_outcomes ORDER BY operation_id')).rows;
 assert.equal(upgradeBefore.length,1);assert.equal(upgradeBefore[0].state,'not_executed');
 const foundationLedger=(await am.query('SELECT * FROM dvaia_migrations.ledger ORDER BY name')).rows;
 assert.deepEqual(foundationLedger.slice(0,ledgerBefore.length),ledgerBefore);
 assert.equal(foundationLedger.at(-1).name,migrationName);
 assert.equal(foundationLedger.at(-1).checksum,createHash('sha256').update(fs.readFileSync(candidate)).digest('hex'));
 assert.deepEqual(await migrationView('0030_').migrate(am,base),[correctionName]);
 assert.deepEqual(await migrationView('0030_').migrate(am,base),[]);
 assert.deepEqual((await agents.query('SELECT * FROM secureshop_agents.bound_system_config_outcomes ORDER BY operation_id')).rows,upgradeBefore);
 const correctedLedger=(await am.query('SELECT * FROM dvaia_migrations.ledger ORDER BY name')).rows;
 assert.deepEqual(correctedLedger.slice(0,foundationLedger.length),foundationLedger);
 assert.equal(correctedLedger.at(-1).name,correctionName);
 assert.equal(correctedLedger.at(-1).checksum,createHash('sha256').update(fs.readFileSync(correction)).digest('hex'));
 // Apply the complete current tail separately; retain historical receipt bytes.
 assert.deepEqual(await migrate(am,base),canonicalNames.filter(name=>name>='0030_'));
 assert.deepEqual(await migrate(am,base),[]);
 assert.deepEqual((await agents.query('SELECT * FROM secureshop_agents.bound_system_config_outcomes ORDER BY operation_id')).rows,upgradeBefore);
 assert.deepEqual((await agents.query('SELECT * FROM secureshop_agents.bound_persona_sessions ORDER BY session_id')).rows,before);
 const after=(await am.query('SELECT * FROM dvaia_migrations.ledger ORDER BY name')).rows;
 assert.deepEqual(after.slice(0,correctedLedger.length),correctedLedger);
 assert.deepEqual(after.map(({name,checksum})=>({name,checksum})),canonical.map(({name,checksum})=>({name,checksum})));
 assert.deepEqual(await migrate(fm,base),canonicalNames);assert.deepEqual(await migrate(fm,base),[]);
 assert.deepEqual((await fm.query('SELECT name,checksum FROM dvaia_migrations.ledger ORDER BY name')).rows,canonical.map(({name,checksum})=>({name,checksum})));

 try{await repository.checkReadiness();await freshRepo.checkReadiness();}catch(error){if(error.schemaDiagnostic)save('system-config-schema-diagnostic.json',error.schemaDiagnostic);throw error;}
 await assert.rejects(createRepo({pool:am,personaAuthority:authority,audit}).checkReadiness(),{code:'SYSTEM_CONFIG_NOT_READY'});
 let drifts=0;
 async function drift(change,restore){await fm.query(change);try{await assert.rejects(freshRepo.checkReadiness(),{code:'SYSTEM_CONFIG_NOT_READY'});drifts++;}finally{await fm.query(restore);}await freshRepo.checkReadiness();}
 const prefix='secureshop_agents.bound_system_config_',tables=['admissions','outcomes','cleanup_receipts'];
 for(const table of tables){
  for(const privilege of ['SELECT',...(table==='cleanup_receipts'?[]:['INSERT'])])await drift(`REVOKE ${privilege} ON ${prefix+table} FROM dvaia_secureshop_agents_runtime`,`GRANT ${privilege} ON ${prefix+table} TO dvaia_secureshop_agents_runtime`);
  for(const privilege of ['UPDATE','DELETE','TRUNCATE','REFERENCES','TRIGGER',...(table==='cleanup_receipts'?['INSERT']:[])])await drift(`GRANT ${privilege} ON ${prefix+table} TO dvaia_secureshop_agents_runtime`,`REVOKE ${privilege} ON ${prefix+table} FROM dvaia_secureshop_agents_runtime`);
  await drift(`GRANT UPDATE(${table==='cleanup_receipts'?'receipt_sha256':'request_sha256'}) ON ${prefix+table} TO dvaia_secureshop_agents_runtime`,`REVOKE UPDATE(${table==='cleanup_receipts'?'receipt_sha256':'request_sha256'}) ON ${prefix+table} FROM dvaia_secureshop_agents_runtime`);
 }
 for(const fn of ['guard_system_config_record','guard_system_config_actor','cleanup_system_config_records'])for(const role of ['PUBLIC','dvaia_secureshop_agents_runtime'])await drift(`GRANT EXECUTE ON FUNCTION secureshop_agents.${fn}() TO ${role}`,`REVOKE EXECUTE ON FUNCTION secureshop_agents.${fn}() FROM ${role}`);
 const oldGuard=fs.readFileSync(candidate,'utf8').split('CREATE FUNCTION secureshop_agents.guard_system_config_record()')[1].split('CREATE FUNCTION secureshop_agents.guard_system_config_actor()')[0];
 await drift('CREATE OR REPLACE FUNCTION secureshop_agents.guard_system_config_record()'+oldGuard,fs.readFileSync(correction,'utf8'));
 const triggers=(await fm.query("SELECT tgrelid::regclass::text AS rel,tgname FROM pg_trigger WHERE NOT tgisinternal AND (tgname LIKE 'system_config_%' OR tgname LIKE 'a_system_config_%' OR tgname LIKE 'b_system_config_%')")).rows;
 assert.equal(triggers.length,9);
 for(const row of triggers)await drift(`ALTER TABLE ${row.rel} DISABLE TRIGGER ${row.tgname}`,`ALTER TABLE ${row.rel} ENABLE TRIGGER ${row.tgname}`);
 const checks=(await fm.query("SELECT conrelid::regclass::text AS rel,conname,pg_get_constraintdef(oid,false) AS def FROM pg_constraint WHERE conrelid::regclass::text LIKE 'secureshop_agents.bound_system_config_%' AND contype='c'")).rows;
 for(const row of checks){const drop=`ALTER TABLE ${row.rel} DROP CONSTRAINT ${row.conname}`,restore=`ALTER TABLE ${row.rel} ADD CONSTRAINT ${row.conname} ${row.def}`;await drift(drop,restore);await fm.query(drop);try{await fm.query(`ALTER TABLE ${row.rel} ADD CONSTRAINT ${row.conname} CHECK(true)`);await assert.rejects(freshRepo.checkReadiness(),{code:'SYSTEM_CONFIG_NOT_READY'});drifts++;}finally{await fm.query(drop);await fm.query(restore);}await freshRepo.checkReadiness();}
 const foreignKey=(await fm.query("SELECT conname,pg_get_constraintdef(oid,false) AS def FROM pg_constraint WHERE conrelid='secureshop_agents.bound_system_config_outcomes'::regclass AND contype='f'")).rows[0];
 await drift(`ALTER TABLE ${prefix}outcomes DROP CONSTRAINT ${foreignKey.conname}`,`ALTER TABLE ${prefix}outcomes ADD CONSTRAINT ${foreignKey.conname} ${foreignKey.def}`);
 await drift(`ALTER TABLE ${prefix}admissions ALTER COLUMN persona_session_id DROP NOT NULL`,`ALTER TABLE ${prefix}admissions ALTER COLUMN persona_session_id SET NOT NULL`);
 const context=o=>({scope:o.scope,persona:o.persona,personaSession:{sessionId:o.sessionId,authorityVersion:o.version}});
 const administrationBefore=(await agents.query(`SELECT count(*) AS n FROM ${prefix}admissions`)).rows[0].n;
 const originalAdministration=await repository.administration(context(a));assert.deepEqual(Object.keys(originalAdministration),['scopeKey']);assert.match(originalAdministration.scopeKey,/^[a-f0-9]{64}$/);
 assert.deepEqual(await repository.administration(context(a)),originalAdministration);assert.notEqual((await repository.administration(context(b))).scopeKey,originalAdministration.scopeKey);
 assert.equal((await agents.query(`SELECT count(*) AS n FROM ${prefix}admissions`)).rows[0].n,administrationBefore);
 const input=o=>({...context(o),operationId:randomUUID(),path:'....//.env'});
 const contract=require('../../sidecars/sandbox-runner/owned-system/contract');
 // Controlled receipt only: no executor, renderer or actual filesystem effect claimed.
 const receipt=request=>{const content='TRAINING_SYSTEM_CONFIG_ONLY';return{version:contract.VERSION,isolation:contract.ISOLATION,operationId:request.operationId,requestSha256:contract.requestDigest({operationId:request.operationId,path:request.path}),status:'completed',exitCode:0,timedOut:false,truncated:false,drained:true,readResult:{ok:true,input:request.path,sanitized:'../.env',targetPath:'/app/.env',size:Buffer.byteLength(content),content,contentSha256:contract.hash(content)}};};
 const first=input(a),concurrent=await Promise.all([repository.begin(first),repository.begin(first)]);
 assert.deepEqual(concurrent.map(x=>x.state).sort(),['admitted','pending']);
 await assert.rejects(repository.begin({...first,path:'other'}),{code:'OPERATION_CONFLICT'});
 await repository.assertCurrent(first);await repository.complete({...first,receipt:receipt(first)});
 assert.equal((await repository.begin(first)).state,'completed');assert.deepEqual((await repository.operation(first)).receipt,receipt(first));
 await assert.rejects(repository.assertCurrent(first),{code:'SYSTEM_CONFIG_OPERATION_TERMINAL'});
 for(const method of ['markUnknown','markNotExecuted']){const x=input(a);await repository.begin(x);const terminal=await repository[method](x);assert.equal((await repository.begin(x)).state,terminal.state);assert.equal((await repository.operation(x)).state,terminal.state);await assert.rejects(repository.assertCurrent(x),{code:'SYSTEM_CONFIG_OPERATION_TERMINAL'});await assert.rejects(repository.complete({...x,receipt:receipt(x)}),{code:'SYSTEM_CONFIG_OUTCOME_UNCERTAIN'});}
 const sibling=input(b);await repository.begin(sibling);await repository.complete({...sibling,receipt:receipt(sibling)});
 assert.equal((await repository.operation({...context(b),operationId:first.operationId})).state,'not_found');
 const laterLogin=await auth.login({scope:a.scope,username:'student_admin',password:'student123'}),later=await auth.authenticateBoundToken({scope:a.scope,token:laterLogin.token});
 assert.notEqual((await repository.administration({...context(a),personaSession:{sessionId:later.sessionId,authorityVersion:later.authorityVersion}})).scopeKey,originalAdministration.scopeKey);
 await assert.rejects(repository.operation({...first,personaSession:{sessionId:later.sessionId,authorityVersion:later.authorityVersion}}),{code:'OPERATION_CONFLICT'});
 assert.equal((await repository.operation(first)).state,'completed');
 const lost=input(a);let drop=true;
 const lostAuthority={async capture(x){const fence=await authority.capture(x);return {...fence,async withPersonaEffect(work){const value=await fence.withPersonaEffect(work);if(drop)throw Error('controlled lost commit acknowledgement');return value;}};}};
 const lostRepo=createRepo({pool:agents,personaAuthority:lostAuthority,audit});
 await assert.rejects(lostRepo.begin(lost),{code:'SYSTEM_CONFIG_OUTCOME_UNCERTAIN'});drop=false;assert.equal((await repository.begin(lost)).state,'pending');
 drop=true;await assert.rejects(lostRepo.complete({...lost,receipt:receipt(lost)}),{code:'SYSTEM_CONFIG_OUTCOME_UNCERTAIN'});drop=false;assert.equal((await repository.operation(lost)).state,'completed');
 const revokedOwner=await owner(),revoked=input(revokedOwner);await repository.begin(revoked);await personas.revokeOwnedSession({scope:revokedOwner.scope,shopUserId:revokedOwner.persona.id,sessionId:revokedOwner.sessionId});
 await assert.rejects(repository.administration(context(revokedOwner)),{code:'SHOP_AUTH_INVALID'});
 await assert.rejects(repository.complete({...revoked,receipt:receipt(revoked)}),{code:'SHOP_AUTH_INVALID'});await assert.rejects(repository.operation(revoked),{code:'SHOP_AUTH_INVALID'});
 const quotaOwner=await owner();for(let i=0;i<32;i++)await repository.begin(input(quotaOwner));await assert.rejects(repository.begin(input(quotaOwner)),{code:'SYSTEM_CONFIG_QUOTA_EXCEEDED'});
 await assert.rejects(agents.query(`UPDATE ${prefix}admissions SET request_json='{}'`),{code:'42501'});await assert.rejects(agents.query(`DELETE FROM ${prefix}outcomes`),{code:'42501'});
 // Real router/service/repository/auth composition; the launch attachment is an
 // owned fixture seam, not the production gateway or platform launch middleware.
 const httpOwner=await owner();let clientCalls=0;
 // Opt-in actual executor composition; the isolated launcher must own the loopback listener.
 const actualExecutor=process.env.PERSONA_SYSTEM_CONFIG_EXECUTOR_NATIVE==='1';
 let remote;
 if(actualExecutor){
  const endpoint=new URL(process.env.PERSONA_SYSTEM_CONFIG_EXECUTOR_URL);
  assert.equal(endpoint.protocol,'http:');assert.equal(endpoint.hostname,'127.0.0.1');
  assert.equal(endpoint.pathname,'/');assert.equal(endpoint.username+endpoint.password+endpoint.search+endpoint.hash,'');
  assert.ok(Number(endpoint.port)>0);
  remote=require('../../server/services/secureshopSystemConfigClient').createSecureShopSystemConfigClient({baseURL:endpoint.href,token:process.env.PERSONA_SYSTEM_CONFIG_EXECUTOR_TOKEN,timeoutMs:5000});
  assert.equal(await remote.assertReady(),true);
 }
 const service=require('../../server/services/secureshopBoundSystemConfigReadService').createBoundSystemConfigReadService({repository,client:{async read(request,options){await options.assertCurrent();clientCalls++;return actualExecutor?remote.read(request,options):receipt(request);}}});
 const express=require('express'),app=express();app.use(express.json({limit:'32kb'}));app.use((req,res,next)=>{req.ssLaunch=httpOwner.scope;next();});
 app.use(require('../../server/routes/secureshop/boundSystemConfig').createBoundSystemConfigRouter({service,authenticatePersona:auth.authenticatePersona}));
 const server=await new Promise(resolve=>{const value=app.listen(0,'127.0.0.1',()=>resolve(value));});
 t.after(()=>new Promise(resolve=>{server.closeAllConnections();server.close(resolve);}));
 const baseURL=`http://127.0.0.1:${server.address().port}`,httpRequest={operationId:randomUUID(),path:'....//.env'};
 const availability=await fetch(baseURL+'/admin/system/config-read',{headers:{authorization:'Bearer '+httpOwner.token},signal:AbortSignal.timeout(5000)});assert.equal(availability.status,200);
 const availabilityBody=await availability.json();assert.deepEqual(availabilityBody,{ok:true,administration:{configReadCapability:require('../../server/services/secureshopSystemConfigClient').CAPABILITY,scopeKey:(await repository.administration(context(httpOwner))).scopeKey}});
 assert.equal(clientCalls,0);
 const post=()=>fetch(baseURL+'/admin/system/config-read',{method:'POST',headers:{authorization:'Bearer '+httpOwner.token,'content-type':'application/json'},body:JSON.stringify(httpRequest),signal:AbortSignal.timeout(5000)});
 const firstHTTP=await post();assert.equal(firstHTTP.status,200);const firstBody=await firstHTTP.json();
 const expectedContent=actualExecutor?require('../../sidecars/sandbox-runner/owned-system/executor').FIXTURES['/app/.env']:'TRAINING_SYSTEM_CONFIG_ONLY';
 assert.equal(firstBody.content,expectedContent);assert.equal(firstBody.size,Buffer.byteLength(expectedContent));
 assert.equal(firstBody.contentSha256,contract.hash(expectedContent));assert.equal(firstBody.operationId,httpRequest.operationId);
 const storedHTTP=await repository.operation({...context(httpOwner),operationId:httpRequest.operationId});
 assert.equal(storedHTTP.receipt.readResult.content,expectedContent);assert.equal(storedHTTP.receipt.drained,true);
 assert.equal((await post()).status,200);assert.equal(clientCalls,1);
 const readURL=baseURL+'/admin/system/config-operations/'+httpRequest.operationId;
 const readback=await fetch(readURL,{headers:{authorization:'Bearer '+httpOwner.token},signal:AbortSignal.timeout(5000)});assert.equal(readback.status,200);assert.equal((await readback.json()).state,'completed');
 const newLogin=await auth.login({scope:httpOwner.scope,username:'student_admin',password:'student123'});
 const foreignRead=await fetch(readURL,{headers:{authorization:'Bearer '+newLogin.token},signal:AbortSignal.timeout(5000)});assert.equal(foreignRead.status,409);await foreignRead.arrayBuffer();
 await personas.revokeOwnedSession({scope:httpOwner.scope,shopUserId:httpOwner.persona.id,sessionId:httpOwner.sessionId});
 const revokedRead=await fetch(readURL,{headers:{authorization:'Bearer '+httpOwner.token},signal:AbortSignal.timeout(5000)});assert.equal(revokedRead.status,401);await revokedRead.arrayBuffer();assert.equal(clientCalls,1);
 const rows=async(table,o)=>(await agents.query(`SELECT * FROM ${prefix+table} WHERE platform_launch_id=$1 ORDER BY operation_id`,[o.scope.launchId])).rows;
 const siblingRows={admissions:await rows('admissions',b),outcomes:await rows('outcomes',b)};
 const preserved=(await rows('admissions',a)).map(r=>[r.operation_id,r.request_sha256.toString('hex'),r.binding_sha256.toString('hex')]);
 await retire(a);for(const row of await rows('admissions',a))assert.equal(row.request_json,null);for(const row of await rows('outcomes',a))assert.equal(row.receipt_json,null);
 assert.deepEqual((await rows('admissions',a)).map(r=>[r.operation_id,r.request_sha256.toString('hex'),r.binding_sha256.toString('hex')]),preserved);
 await assert.rejects(repository.begin(input(a)));
 const stored=siblingRows.admissions[0];
 await assert.rejects(agents.query(`INSERT INTO ${prefix}admissions SELECT $1,$2,$3,$4,$5,$6,persona_id,persona_session_id,persona_role,authority_version,request_sha256,binding_sha256,request_json FROM ${prefix}admissions WHERE operation_id=$7`,[...coords(a),randomUUID(),stored.operation_id]),{code:'55000'});
 await agents.query('SELECT * FROM secureshop_agents.destroy_bound_audit_owner($1,$2)',[a.scope.platformOwnerId,randomUUID()]);for(const table of ['admissions','outcomes'])assert.equal((await rows(table,a)).length,0);
 for(const table of ['admissions','outcomes'])assert.deepEqual(await rows(table,b),siblingRows[table]);
 await retire(b);for(const row of await rows('admissions',b))assert.equal(row.request_json,null);for(const row of await rows('outcomes',b))assert.equal(row.receipt_json,null);
 const auditRows=(await agents.query("SELECT outcome,params_json FROM secureshop_agents.bound_audit_events WHERE action='system_config_read'")).rows;assert.ok(auditRows.length);assert.ok(auditRows.every(r=>['completed','failed'].includes(r.outcome)));assert.ok(!JSON.stringify(auditRows).includes('TRAINING_SYSTEM_CONFIG_ONLY'));
 save('system-config-repository-result.json',{status:'passed',canonicalRegisteredMigration:true,populatedFrom:'0027',populatedTo:canonicalNames.at(-1),populated0028ReceiptPreservedThrough0029:true,fresh:true,populated:true,noop:true,readinessDrifts:drifts,realPersonaAuthority:true,actualAuditAdapter:true,mountedRouterServiceWithRealPersonaAuth:true,productionGateway:false,controlledClientCalls:actualExecutor?0:clientCalls,actualExecutorClientCalls:actualExecutor?clientCalls:0,administrationOpaqueOriginalSessionScope:true,originalSessionReadback:true,laterSessionDenied:true,terminalNoReadmission:true,lostCommitAcknowledgementReadback:true,retirementRedaction:true,ownerDeletion:true,siblingPreserved:true,receiptProvenance:actualExecutor?'HTTP scenario uses actual private client and owned executor; other lifecycle cases use controlled receipts':'controlled fixture; no executor call',actualModelCalls:0});
});
