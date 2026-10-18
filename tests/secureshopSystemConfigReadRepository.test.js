'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),{randomUUID}=require('node:crypto'),fs=require('node:fs');
const {createSystemConfigReadRepository}=require('../server/database/postgres/secureshopSystemConfigReadRepository');
const {VERSION,ISOLATION,requestDigest,hash}=require('../sidecars/sandbox-runner/owned-system/contract');
function fixture({realAudit=false,modeAuthority}={}){
 const raw={scope:{launchId:randomUUID(),scenarioId:randomUUID(),generation:1,platformOwnerId:1,platformSessionId:2},persona:{id:3,role:'admin'},personaSession:{sessionId:randomUUID(),authorityVersion:'1'},operationId:randomUUID(),path:'....//.env'};
 const admissions=new Map(),outcomes=new Map(),audits=[],queries=[];let revoked=false,drop=false,foreign=false,queue=Promise.resolve();const key=v=>JSON.stringify(v.slice(0,6));
 const client={async query(sql,v=[]){queries.push(sql);let rows=[];
 if(sql.startsWith('INSERT INTO secureshop_agents.bound_audit_events')){audits.push(v);return {rows:[],rowCount:1};}
 if(sql.startsWith('SET ')||sql.includes('pg_advisory_xact_lock'))return {rows};
 if(sql.startsWith('SELECT * FROM')){const table=sql.includes('_admissions')?admissions:outcomes;rows=table.has(key(v))?[table.get(key(v))]:[];}
 else if(sql.startsWith('SELECT count'))rows=[{n:[...admissions.keys()].filter(k=>k.startsWith(JSON.stringify(v).slice(0,-1)+',')).length}];
 else if(sql.startsWith('INSERT INTO')){const record={operation_id:v[5],persona_id:v[6],persona_session_id:v[7],persona_role:v[8],authority_version:v[9],request_sha256:Buffer.from(v[10],'hex'),binding_sha256:Buffer.from(v[11],'hex')};
 if(sql.includes('_admissions')){record.request_json=JSON.parse(v[12]);admissions.set(key(v),record);}else{record.state=v[12];record.receipt_json=v[13]?JSON.parse(v[13]):null;record.receipt_sha256=v[14]?Buffer.from(v[14],'hex'):null;outcomes.set(key(v),record);}}
 else throw Error('Unexpected query: '+sql);return {rows};}};
 const personaAuthority={async capture(x){if(revoked)throw Object.assign(Error('revoked'),{code:'SHOP_AUTH_REVOKED'});const binding={...x.scope,personaId:x.personaId,role:x.role,sessionId:foreign?randomUUID():x.sessionId,authorityVersion:x.authorityVersion};return {binding,withPersonaEffect(work){const turn=queue.then(()=>work(client));queue=turn.catch(()=>{});return turn.then(value=>{if(drop)throw Error('commit acknowledgement lost');return value;});},async assertRemoteAdmission(){if(revoked)throw Error('revoked');}};}};
 const repo=createSystemConfigReadRepository({pool:{query:client.query},personaAuthority,modeAuthority,audit:realAudit?require('../server/database/postgres/secureshopBoundAuditRepository').createBoundAuditStore({store:'agents',pool:client}):{async append(c,row){assert.equal(c,client);audits.push(row);}}});
 return {raw,repo,admissions,outcomes,audits,queries,setRevoked:v=>revoked=v,setDrop:v=>drop=v,setForeign:v=>foreign=v};
}
function receipt(x){const content='synthetic';return {version:VERSION,isolation:ISOLATION,operationId:x.operationId,requestSha256:requestDigest({operationId:x.operationId,path:x.path}),status:'completed',exitCode:0,timedOut:false,truncated:false,drained:true,readResult:{ok:true,input:x.path,sanitized:'../.env',targetPath:'/app/.env',size:content.length,content,contentSha256:hash(content)}};}
test('only first concurrent admission can execute; exact repeat is pending and changed request conflicts',async()=>{const f=fixture();const rows=await Promise.all([f.repo.begin(f.raw),f.repo.begin(f.raw)]);assert.deepEqual(rows.map(x=>x.state),['admitted','pending']);await assert.rejects(f.repo.begin({...f.raw,path:'different'}),e=>e.code==='OPERATION_CONFLICT');await f.repo.assertCurrent(f.raw);assert.equal(f.admissions.size,1);});
test('completed immutable receipt replay and readback use original actor and sameclient secret-free audit',async()=>{const f=fixture();await f.repo.begin(f.raw);const value=receipt(f.raw);const first=await f.repo.complete({...f.raw,receipt:value});assert.equal(first.state,'completed');assert.deepEqual((await f.repo.begin(f.raw)).receipt,value);assert.deepEqual((await f.repo.operation(f.raw)).receipt,value);assert.equal((await f.repo.markUnknown(f.raw)).state,'completed');assert.equal((await f.repo.markNotExecuted(f.raw)).state,'completed');assert.equal(f.audits.length,1);assert.equal(f.audits[0].paramsJson.includes('synthetic'),false);assert.equal(f.audits[0].paramsJson.includes('....//'),false);await assert.rejects(f.repo.complete({...f.raw,receipt:{...value,readResult:{...value.readResult,content:'forged'}}}));});
test('unknown and not_executed are terminal without re-admission or outcome replacement',async()=>{for(const method of ['markUnknown','markNotExecuted']){const f=fixture();await f.repo.begin(f.raw);const terminal=await f.repo[method](f.raw);assert.equal((await f.repo.begin(f.raw)).state,terminal.state);assert.equal((await f.repo.markUnknown(f.raw)).state,terminal.state);await assert.rejects(f.repo.complete({...f.raw,receipt:receipt(f.raw)}),e=>e.code==='SYSTEM_CONFIG_OUTCOME_UNCERTAIN');assert.equal(f.outcomes.size,1);}});
test('original persona/session/version mismatch, revoked authority and foreign capture deny reads and publication',async()=>{const f=fixture();await f.repo.begin(f.raw);for(const patch of [{persona:{id:4,role:'admin'}},{personaSession:{...f.raw.personaSession,sessionId:randomUUID()}},{personaSession:{...f.raw.personaSession,authorityVersion:'2'}}])await assert.rejects(f.repo.operation({...f.raw,...patch}),e=>e.code==='OPERATION_CONFLICT');f.setForeign(true);await assert.rejects(f.repo.assertCurrent(f.raw),e=>e.code==='SHOP_AUTH_INVALID');f.setForeign(false);f.setRevoked(true);await assert.rejects(f.repo.complete({...f.raw,receipt:receipt(f.raw)}),e=>e.code==='SHOP_AUTH_REVOKED');assert.equal(f.outcomes.size,0);});
test('lost admission or completed commit acknowledgement never authorizes redispatch',async()=>{const f=fixture();f.setDrop(true);await assert.rejects(f.repo.begin(f.raw),e=>e.code==='SYSTEM_CONFIG_OUTCOME_UNCERTAIN');f.setDrop(false);assert.equal((await f.repo.begin(f.raw)).state,'pending');f.setDrop(true);await assert.rejects(f.repo.complete({...f.raw,receipt:receipt(f.raw)}),e=>e.code==='SYSTEM_CONFIG_OUTCOME_UNCERTAIN');f.setDrop(false);assert.equal((await f.repo.operation(f.raw)).state,'completed');});
test('quota checks after replay; sibling scopes and notfound remain distinct',async()=>{const f=fixture();for(let i=0;i<32;i++)await f.repo.begin({...f.raw,operationId:i?randomUUID():f.raw.operationId});assert.equal((await f.repo.begin(f.raw)).state,'pending');await assert.rejects(f.repo.begin({...f.raw,operationId:randomUUID()}),e=>e.code==='SYSTEM_CONFIG_QUOTA_EXCEEDED');assert.equal((await f.repo.begin({...f.raw,scope:{...f.raw.scope,launchId:randomUUID()}})).state,'admitted');assert.deepEqual(await f.repo.operation({...f.raw,operationId:'22222222-2222-4222-8222-222222222222'}),{state:'not_found',operationId:'22222222-2222-4222-8222-222222222222'});});
test('stored receipt or admission corruption fails closed',async()=>{const f=fixture();await f.repo.begin(f.raw);await f.repo.complete({...f.raw,receipt:receipt(f.raw)});[...f.outcomes.values()][0].receipt_json.readResult.content='changed';await assert.rejects(f.repo.operation(f.raw),e=>e.code==='SYSTEM_CONFIG_INTEGRITY_UNAVAILABLE');[...f.admissions.values()][0].request_json.path='changed';await assert.rejects(f.repo.begin(f.raw),e=>e.code==='SYSTEM_CONFIG_INTEGRITY_UNAVAILABLE');});
test('unregistered SQL preserves least privilege, full lifecycle scope and terminal append-only state',()=>{const sql=fs.readFileSync('docs/modernization/drafts/secureshop-bound-system-config/schema.candidate.sql','utf8');assert.match(sql,/REVOKE ALL ON .*bound_system_config_admissions.*FROM PUBLIC,dvaia_secureshop_agents_runtime/s);assert.match(sql,/GRANT SELECT,INSERT ON/);assert.doesNotMatch(sql,/GRANT (?:UPDATE|DELETE|TRUNCATE)/);assert.match(sql,/state IN \('completed','unknown','not_executed'\)/);assert.match(sql,/NEW.original_platform_session_id/);assert.match(sql,/s.revoked_at IS NULL AND s.expires_at>clock_timestamp\(\)/);assert.match(sql,/s.credential_version=/);assert.match(sql,/request_json=NULL/);assert.match(sql,/receipt_json=NULL/);assert.match(sql,/BEFORE UPDATE OR DELETE/);assert.match(sql,/>=32/);});
test('caller mutation after admission starts cannot change original request or actor binding',async()=>{const f=fixture(),original=structuredClone(f.raw);const pending=f.repo.begin(f.raw);f.raw.path='changed';f.raw.personaSession.authorityVersion='2';f.raw.persona.id=4;assert.equal((await pending).state,'admitted');assert.equal((await f.repo.begin(original)).state,'pending');assert.deepEqual([...f.admissions.values()][0].request_json,{operationId:original.operationId,path:original.path});});

test('actual audit append contract accepts terminal categories and keeps protocol state as metadata',async()=>{
 for(const state of ['completed','unknown','not_executed','unavailable']){
  const f=fixture({realAudit:true});await f.repo.begin(f.raw);
  if(state==='unknown')await f.repo.markUnknown(f.raw);
  else if(state==='not_executed')await f.repo.markNotExecuted(f.raw);
  else {const r=receipt(f.raw);if(state==='unavailable'){r.status='unavailable';r.exitCode=1;delete r.readResult;}await f.repo.complete({...f.raw,receipt:r});}
  assert.equal(f.audits.length,1);assert.equal(f.audits[0][12],state==='completed'?'completed':'failed');
  assert.equal(JSON.parse(f.audits[0][11]).state,state==='unavailable'?'completed':state);
  assert.equal(f.audits[0][9],'system_config_read');assert.equal(f.audits[0][13],'system_config_read');
 }
});
test('dispatch authority check rejects every recorded terminal outcome',async()=>{
 for(const method of ['complete','markUnknown','markNotExecuted']){
  const f=fixture();await f.repo.begin(f.raw);await f.repo.assertCurrent(f.raw);
  await f.repo[method]({...f.raw,receipt:receipt(f.raw)});
  await assert.rejects(f.repo.assertCurrent(f.raw),e=>e.code==='SYSTEM_CONFIG_OPERATION_TERMINAL');
 }
});

test('administration captures original authority without inventing admission or exposing coordinates',async()=>{
 const f=fixture();const {operationId,path,...context}=f.raw;
 const value=await f.repo.administration(context);assert.deepEqual(Object.keys(value),['scopeKey']);assert.match(value.scopeKey,/^[a-f0-9]{64}$/);
 assert.deepEqual(await f.repo.administration(context),value);assert.equal(f.admissions.size,0);assert.equal(f.outcomes.size,0);assert.equal(f.audits.length,0);
 assert.ok(f.queries.every(q=>q.startsWith('SET ')||q.includes('pg_advisory_xact_lock')));
 assert.notEqual((await f.repo.administration({...context,personaSession:{...context.personaSession,sessionId:randomUUID()}})).scopeKey,value.scopeKey);
 f.setRevoked(true);await assert.rejects(f.repo.administration(context),{code:'SHOP_AUTH_REVOKED'});
});

function modeFixture() {
 let mode='vuln', revision=1;
 const modeAuthority=require('../server/services/secureshopFeatureModeAuthority').createFeatureModeAuthority({
  launches:{async assertCurrent(){}},progress:{async getEvaluationScope(){return {mode,generation:1,modeStamp:String(revision)};}}
 });
 const f=fixture({modeAuthority});let calls=0,beforeRemote;
 const client={async read(request,{assertCurrent}){await beforeRemote?.();await assertCurrent();calls++;
  if(request.path==='....//.env')return receipt({...f.raw,...request});
  const content='{}';return {...receipt({...f.raw,...request}),readResult:{ok:true,input:request.path,sanitized:request.path,
   targetPath:'/app/config/application.json',size:2,content,contentSha256:hash(content)}};
 }};
 const service=require('../server/services/secureshopBoundSystemConfigReadService').createBoundSystemConfigReadService({repository:f.repo,client,modeAuthority});
 return {...f,modeAuthority,service,calls:()=>calls,setMode(value){mode=value;revision++;},beforeRemote(fn){beforeRemote=fn;}};
}

test('fixed containment rejects both separator spellings without remote reads and persists original mode',async()=>{
 const f=modeFixture();f.setMode('fixed');
 for(const path of ['....//.env','....//platform_secrets.json','../.env','..\\.env','....\\\\.env','/app/.env','\\app\\.env','C:\\secret','C:secret','\\\\server\\share','sub/../../.env','sub\\..\\..\\.env','..','']){
  const raw={...f.raw,operationId:randomUUID(),path};
  const first=await f.service.read(raw);
  assert.equal(first.state,'not_executed',path);assert.equal(first.execution.mode,'fixed');
  assert.equal(Object.hasOwn(first,'receipt'),false);
  assert.deepEqual(await f.service.read(raw),first);assert.deepEqual(await f.service.operation(raw),first);
 }
 assert.equal(f.calls(),0);assert.equal(f.admissions.size,14);assert.equal(f.outcomes.size,14);
 assert.ok([...f.admissions.values()].every(row=>row.request_json.version===2&&row.request_json.execution.featureId==='system_config'));
});

test('vulnerable traversal and ordinary fixed reads retain original isolated receipt protocol',async()=>{
 const f=modeFixture();
 const vuln=await f.service.read(f.raw);assert.equal(vuln.receipt.version,1);assert.equal(vuln.receipt.readResult.targetPath,'/app/.env');
 assert.equal(vuln.execution.mode,'vuln');assert.equal(vuln.requestSha256,requestDigest({operationId:f.raw.operationId,path:f.raw.path}));
 f.setMode('fixed');
 const fixed=await f.service.read({...f.raw,operationId:randomUUID(),path:'application.json'});
 assert.equal(fixed.receipt.readResult.targetPath,'/app/config/application.json');assert.equal(fixed.execution.mode,'fixed');assert.equal(f.calls(),2);
 // Exact historical GET remains readable; a POST never substitutes a fresh mode
 // for the immutable original execution epoch, including an ABA mode change.
 assert.deepEqual(await f.service.operation(f.raw),vuln);
 await assert.rejects(f.service.read(f.raw),{code:'SECURESHOP_FEATURE_MODE_STALE'});
 f.setMode('vuln');await assert.rejects(f.service.read(f.raw),{code:'SECURESHOP_FEATURE_MODE_STALE'});
 assert.equal(f.calls(),2);
});

test('mode change before actual remote read blocks dispatch and does not invent a terminal receipt',async()=>{
 const f=modeFixture();f.beforeRemote(()=>f.setMode('fixed'));
 await assert.rejects(f.service.read(f.raw),{code:'ANALYTICS_MODE_STALE'});
 assert.equal(f.calls(),0);const saved=await f.service.operation(f.raw);
 assert.equal(saved.state,'pending');assert.equal(saved.execution.mode,'vuln');assert.equal(f.outcomes.size,0);
});

test('trusted mode token and original execution binding cannot be supplied or replaced by caller JSON',async()=>{
 const f=modeFixture(),token=await f.modeAuthority.capture(f.raw.scope,'system_config');
 await assert.rejects(f.repo.begin(f.raw,{modeToken:{snapshot:token.snapshot}}));
 await assert.rejects(f.service.read({...f.raw,execution:token.snapshot}),{code:'SYSTEM_CONFIG_MODE_INVALID'});
 await f.service.read(f.raw);const row=[...f.admissions.values()][0];
 row.request_json.execution.mode='fixed';await assert.rejects(f.repo.operation(f.raw),{code:'SYSTEM_CONFIG_INTEGRITY_UNAVAILABLE'});
});

test('registered execution receipts retain original persona/session and reset scope fences',async()=>{
 const f=modeFixture();await f.service.read(f.raw);
 await assert.rejects(f.service.operation({...f.raw,personaSession:{...f.raw.personaSession,sessionId:randomUUID()}}),{code:'OPERATION_CONFLICT'});
 assert.equal((await f.service.operation({...f.raw,scope:{...f.raw.scope,generation:2}})).state,'not_found');
 f.setRevoked(true);await assert.rejects(f.service.operation(f.raw),{code:'SHOP_AUTH_REVOKED'});
 assert.equal(f.calls(),1);assert.equal(f.outcomes.size,1);
});

test('fixed admission cannot publish a forged successful traversal receipt through the repository',async()=>{
 const f=modeFixture();f.setMode('fixed');const modeToken=await f.modeAuthority.capture(f.raw.scope,'system_config');
 await f.repo.begin(f.raw,{modeToken});
 await assert.rejects(f.repo.complete({...f.raw,receipt:receipt(f.raw)},{modeToken}),{code:'SYSTEM_CONFIG_MODE_INVALID'});
 assert.equal(f.outcomes.size,0);
});

test('historical v1 completed records remain readable without inventing a trusted execution snapshot',async()=>{
 const old=fixture();await old.repo.begin(old.raw);const original=await old.repo.complete({...old.raw,receipt:receipt(old.raw)});
 const upgraded=modeFixture();upgraded.setMode('fixed');
 for(const [key,row] of old.admissions)upgraded.admissions.set(key,structuredClone(row));
 for(const [key,row] of old.outcomes)upgraded.outcomes.set(key,{...row,
  request_sha256:Buffer.from(row.request_sha256),binding_sha256:Buffer.from(row.binding_sha256),receipt_sha256:Buffer.from(row.receipt_sha256)});
 // Preserve PostgreSQL bytea Buffer representation in the controlled rows.
 for(const row of upgraded.admissions.values()){
  row.request_sha256=Buffer.from(row.request_sha256);row.binding_sha256=Buffer.from(row.binding_sha256);
 }
 assert.deepEqual(await upgraded.service.operation(old.raw),original);
 assert.deepEqual(await upgraded.service.read(old.raw),original);
 assert.equal(upgraded.calls(),0);assert.equal(Object.hasOwn(original,'execution'),false);
});
