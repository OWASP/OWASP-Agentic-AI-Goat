'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict'),crypto=require('node:crypto'),fs=require('node:fs/promises'),path=require('node:path');
const {Pool}=require('pg');const {canonicalDigest}=require('../../sidecars/sandbox-runner/owned-http/canonical');
const {createMcpProtectedReceiptRepository}=require('../../server/database/postgres/mcpProtectedReceiptRepository');
const {protectedReceipt}=require('../../server/services/mcp/ownedTargetClient')._internals;
const directory=path.resolve(__dirname,'../../db/postgres/identity-migrations');
function migrationView(before){
 assert.ok(['0097_','0098_'].includes(before));
 const {Module,createRequire}=require('node:module'),filename=require.resolve('../../db/postgres/migrate');
 const localRequire=createRequire(filename),loaded=new Module(filename,module);loaded.filename=filename;
 loaded.require=name=>name==='node:fs/promises'?{
  async readdir(folder,...args){assert.equal(path.resolve(folder),directory);return(await fs.readdir(folder,...args)).filter(name=>name<before);},
  readFile:(...args)=>fs.readFile(...args),
 }:localRequire(name);
 loaded._compile(require('node:fs').readFileSync(filename,'utf8'),filename);return loaded.exports;
}
test('unmounted protected central candidate preserves immutable admission and append-only reconciliation',{skip:process.env.PG_TEST_DISPOSABLE!=='yes'||!process.env.PG_GRAPH_TEST_RUNTIME_URL},async t=>{
 const runtime=new Pool({connectionString:process.env.PG_GRAPH_TEST_RUNTIME_URL}),migration=new Pool({connectionString:process.env.PG_GRAPH_TEST_MIGRATION_URL}),fresh=new Pool({connectionString:process.env.PG_PROTECTED_FRESH_MIGRATION_URL});t.after(()=>Promise.all([runtime.end(),migration.end(),fresh.end()]));
 for(const url of [runtime.options.connectionString,migration.options.connectionString,fresh.options.connectionString]){assert.equal(new URL(url).hostname,'127.0.0.1');assert.match(new URL(url).pathname,/^\/dvaia_test_[a-z0-9_]+$/);}
 const {migrate,readMigrations}=require('../../db/postgres/migrate');
 const canonical=await readMigrations(directory),names=canonical.map(row=>row.name);
 const candidate='0097_mcp_protected_reconciliation.sql';
 assert.deepEqual(await fs.readFile(path.join(directory,candidate)),await fs.readFile(path.resolve(__dirname,'../../docs/modernization/drafts/mcp-protected-recovery/protected_reconciliation.candidate.sql')));
 assert.deepEqual(await migrationView('0097_').migrate(migration,directory),names.filter(name=>name<'0097_'));
 const oldLedger=(await migration.query('SELECT * FROM dvaia_migrations.ledger ORDER BY name')).rows;
 const scopes=[];
 for(let i=0;i<3;i++){
  const user=await require('../../server/database/postgres/identityRepository').createIdentityRepository(runtime).createUser({username:'protected-'+i,email:'protected-'+i+'@example.invalid',passwordHash:await require('bcryptjs').hash('owned fixture',4)});
  const session=(await migration.query("INSERT INTO identity.user_sessions(user_id,session_token_hash,expires_at) VALUES($1,$2,clock_timestamp()+interval '1 hour') RETURNING id",[user.id,crypto.randomBytes(32).toString('hex')])).rows[0];
  const ownerKey=JSON.stringify(['MCP',String(user.id)]),runId=crypto.randomUUID();await migration.query('INSERT INTO graph_runtime.owners(owner_key,generation) VALUES($1,0)',[ownerKey]);await migration.query("INSERT INTO graph_runtime.runs(run_id,owner_key,generation,status) VALUES($1,$2,0,'running')",[runId,ownerKey]);
  const sdkEffectKey='mcp_tool_0_admin_rotate_keys',ledgerEffectKey='request-'+i+':'+sdkEffectKey;
  await migration.query("INSERT INTO graph_runtime.effects(owner_key,generation,effect_key,run_id,status) VALUES($1,0,$2,$3,'started')",[ownerKey,ledgerEffectKey,runId]);
  scopes.push({request:{operationId:crypto.randomUUID(),runId,operation:'rotate_keys',arguments:{labRole:'unprivileged',enforceAuthorization:false},binding:{targetId:crypto.randomUUID(),platformOwnerId:user.id,platformSessionId:Number(session.id),generation:0}},execution:{ownerKey,runId,durableGeneration:'0',check:async()=>{}},sdkEffectKey,ledgerEffectKey});
 }
 assert.deepEqual(await migrationView('0098_').migrate(migration,directory),[candidate]);
 const upgradedLedger=(await migration.query('SELECT * FROM dvaia_migrations.ledger ORDER BY name')).rows;
 assert.deepEqual(upgradedLedger.slice(0,oldLedger.length),oldLedger);
 assert.equal(upgradedLedger.at(-1).name,candidate);
 assert.equal(upgradedLedger.at(-1).checksum,canonical.find(row=>row.name===candidate).checksum);
 assert.deepEqual(await migrationView('0098_').migrate(migration,directory),[]);
 assert.deepEqual(await migrate(migration,directory),names.filter(name=>name>='0098_'));
 assert.deepEqual(await migrate(migration,directory),[]);
 assert.deepEqual((await migration.query('SELECT * FROM dvaia_migrations.ledger ORDER BY name')).rows.slice(0,upgradedLedger.length),upgradedLedger);
 const expected=canonical.map(({name,checksum})=>({name,checksum}));
 assert.deepEqual((await migration.query('SELECT name,checksum FROM dvaia_migrations.ledger ORDER BY name')).rows,expected);
 assert.deepEqual(await migrate(fresh,directory),names);assert.deepEqual(await migrate(fresh,directory),[]);
 assert.deepEqual((await fresh.query('SELECT name,checksum FROM dvaia_migrations.ledger ORDER BY name')).rows,expected);
 let reads=0,mode='normal',mutateDuringRead=null,gate=true,originReference=null,mutateOrigin=true;
 const origin=({request})=>({origin:['model','manual','controlled'][scopes.findIndex(s=>s.request.binding.platformOwnerId===request.binding.platformOwnerId)],decisionDigest:request.binding.platformOwnerId===scopes[0].request.binding.platformOwnerId?'a'.repeat(64):null});
 const repository=createMcpProtectedReceiptRepository({pool:runtime,resolveOrigin:async data=>(originReference=origin(data)),withTargetAuthority:async(binding,work)=>{await Promise.resolve();if(mutateOrigin&&originReference){originReference.origin='manual';originReference.decisionDigest=null;}assert.ok(scopes.some(s=>canonicalDigest(s.request.binding)===canonicalDigest(binding)));if(!gate)throw Error('target retired');return work();},readReceipt:async({request})=>{
  reads++;if(mutateDuringRead)await mutateDuringRead();const body={version:'mcp-owned-protected-state.v1',operation:request.operation,...request.binding,runId:request.runId,labRole:'unprivileged',policy:'vulnerable',changed:true,keyVersionBefore:mode==='conflict'?2:1,keyVersionAfter:mode==='conflict'?3:2,audited:true};const result=protectedReceipt({...body,receiptSha256:canonicalDigest(body)},request.binding,request.operation,request.runId);
  return{state:mode==='pending'?'uncertain':'completed',requestDigest:canonicalDigest(request),...(mode==='pending'?{}:{result:mode==='forged'?{...result}:result})};}});
 assert.deepEqual(await repository.checkReadiness(),{ready:true});
 for(const action of ['INSERT','UPDATE','DELETE','TRUNCATE'])assert.equal((await runtime.query('SELECT has_table_privilege(current_user,$1,$2) AS yes',['workshop_conversations.mcp_protected_intents',action])).rows[0].yes,false);
 const a=scopes[0],b=scopes[1],c=scopes[2];const admitted=await Promise.all([repository.begin(a),repository.begin(a)]);assert.deepEqual(admitted[0],admitted[1]);assert.equal(admitted[0].ledger_effect_key,a.ledgerEffectKey);assert.equal(admitted[0].sdk_effect_key,a.sdkEffectKey);assert.equal(admitted[0].origin,'model');
 mutateOrigin=false;await repository.begin(b);await repository.begin(c);assert.equal(reads,0);
 await assert.rejects(repository.begin({...a,request:{...a.request,arguments:{...a.request.arguments,labRole:'privileged'}}}),/PROTECTED_INTENT_CONFLICT/);
 await assert.rejects(repository.begin({...a,execution:b.execution}),{code:'PROTECTED_INTENT_SCOPE_INVALID'});
 await migration.query("UPDATE graph_runtime.effects SET status='uncertain';UPDATE graph_runtime.runs SET status='failed'");
 const args=s=>({operationId:s.request.operationId,ownerId:s.request.binding.platformOwnerId,platformSessionId:s.request.binding.platformSessionId});
 mode='forged';await assert.rejects(repository.reconcile(args(a)),{code:'PROTECTED_READBACK_UNTRUSTED'});mode='pending';assert.equal((await repository.reconcile(args(a))).outcome,'uncertain');mode='normal';const values=await Promise.all([repository.reconcile(args(a)),repository.reconcile(args(a))]);assert.deepEqual(values[0],values[1]);assert.equal(values[0].originalEffectStatus,'uncertain');assert.equal(values[0].creditGranted,false);assert.equal(values[0].origin,'model');
 mode='conflict';await assert.rejects(repository.reconcile(args(a)),/PROTECTED_RECONCILIATION_CONFLICT/);mode='normal';assert.equal((await repository.reconcile(args(b))).origin,'manual');assert.equal((await repository.reconcile(args(c))).origin,'controlled');
 await assert.rejects(repository.reconcile({...args(a),ownerId:b.request.binding.platformOwnerId}),{code:'PROTECTED_INTENT_UNAVAILABLE'});
 gate=false;const count=reads;await assert.rejects(repository.reconcile(args(a)),/target retired/);assert.equal(reads,count);gate=true;
 const siblingBefore=(await runtime.query('SELECT * FROM workshop_conversations.mcp_protected_reconciliations WHERE operation_id=$1',[b.request.operationId])).rows;
 mutateDuringRead=()=>migration.query('UPDATE graph_runtime.owners SET generation=1 WHERE owner_key=$1',[a.execution.ownerKey]);await assert.rejects(repository.reconcile(args(a)),/PROTECTED_GENERATION_STALE/);mutateDuringRead=null;
 await migration.query('UPDATE identity.user_sessions SET is_active=0 WHERE id=$1',[b.request.binding.platformSessionId]);const before=reads;await assert.rejects(repository.reconcile(args(b)),{code:'PROTECTED_RECONCILIATION_STALE'});assert.equal(reads,before);
 await migration.query('DELETE FROM identity.users WHERE id=$1',[c.request.binding.platformOwnerId]);await assert.rejects(repository.reconcile(args(c)),{code:'PROTECTED_RECONCILIATION_STALE'});assert.equal((await runtime.query('SELECT count(*)::int n FROM workshop_conversations.mcp_protected_intents WHERE operation_id=$1',[c.request.operationId])).rows[0].n,1);
 assert.deepEqual((await runtime.query('SELECT * FROM workshop_conversations.mcp_protected_reconciliations WHERE operation_id=$1',[b.request.operationId])).rows,siblingBefore);
 assert.deepEqual((await runtime.query('SELECT DISTINCT status FROM graph_runtime.effects')).rows,[{status:'uncertain'}]);
 await assert.rejects(runtime.query('DELETE FROM workshop_conversations.mcp_protected_reconciliations'),/permission denied/);await assert.rejects(runtime.query('UPDATE workshop_conversations.mcp_protected_intents SET origin=\'model\''),/permission denied/);
 t.diagnostic(JSON.stringify({fresh:true,populated:true,noop:true,leastPrivilege:true,concurrentExactReplay:true,requestConflict:true,origins:['model','manual','controlled'],centralEffectsUnchanged:true,resetRace:true,revokedSessionNoRead:true,deletedOwnerNoRead:true,retainedDigestHistory:true,siblingPreserved:true,actualModel:false,targetAuthority:'controlled callback; unmounted candidate only'}));
});
