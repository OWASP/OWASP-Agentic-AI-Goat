'use strict';
// Database-only storage qualification. Synthetic receipt data is never command,
// model, Judge or objective-credit proof. Only the owned launcher supplies URLs.
const test=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),fsp=require('node:fs/promises'),path=require('node:path');
const {Module,createRequire}=require('node:module');
const {randomUUID,createHash}=require('node:crypto'),{Pool}=require('pg');
const {migrate,readMigrations}=require('../../db/postgres/migrate');
const Wire=require('../../sidecars/sandbox-runner/owned-system/restart-wire');
const DIR=path.resolve(__dirname,'../../db/postgres/workshop-migrations/secureshop_review');
const TAIL='0051_bound_system_restart_full_receipts.sql',PREFIX='PG_SECURESHOP_RESTART_FULL_';
const sha=x=>createHash('sha256').update(x).digest('hex'),hex=c=>c.repeat(64);
const enabled=process.env.PG_TEST_DISPOSABLE==='yes'&&['FRESH','POPULATED'].every(s=>['MIGRATION','RUNTIME'].every(r=>process.env[`${PREFIX}${s}_${r}_URL`]));
function prefixMigrate(){const filename=require.resolve('../../db/postgres/migrate'),local=createRequire(filename);
 const visible={...fsp,async readdir(dir,...args){const names=await fsp.readdir(dir,...args);return path.resolve(dir)===DIR?names.filter(n=>!/^\d{4}_.*\.sql$/.test(n)||n<TAIL):names;}};
 const loaded=new Module(filename,module);loaded.filename=filename;loaded.require=n=>n==='node:fs/promises'?visible:local(n);loaded._compile(fs.readFileSync(filename,'utf8'),filename);return loaded.exports.migrate;}
async function open(store,t){const urls=['MIGRATION','RUNTIME'].map(role=>{const u=new URL(process.env[`${PREFIX}${store}_${role}_URL`]);
 assert.equal(u.protocol,'postgresql:');assert.equal(u.hostname,'127.0.0.1');assert.equal(u.username,`dvaia_secureshop_review_${role.toLowerCase()}`);
 assert.equal(u.password,'');assert.equal(u.search,'');assert.equal(u.hash,'');assert.match(u.pathname,new RegExp(`^/dvaia_test_persona_${store.toLowerCase()}_[a-f0-9]{12}$`));assert.ok(Number(u.port)>0&&Number(u.port)<=65535);return u;});
 const peer=new URL(process.env[`${PREFIX}${store==='FRESH'?'POPULATED':'FRESH'}_MIGRATION_URL`]);
 assert.equal(urls[0].host,urls[1].host);assert.equal(urls[0].pathname,urls[1].pathname);assert.equal(urls[0].host,peer.host);assert.notEqual(urls[0].pathname,peer.pathname);
 assert.equal(urls[0].pathname.split('_').at(-1),peer.pathname.split('_').at(-1));
 const pools=urls.map(u=>new Pool({connectionString:u.href,max:2,statement_timeout:15000,lock_timeout:3000}));
 t.after(async()=>{const ended=await Promise.allSettled(pools.map(p=>p.end()));assert.equal(ended.filter(x=>x.status==='rejected').length,0);});return{m:pools[0],r:pools[1]};}
async function snapshot(db){const out={};for(const name of ['bound_system_restart_targets','bound_system_restart_operations','bound_system_restart_full_receipts'])out[name]=(await db.query(`SELECT to_jsonb(t) AS row FROM secureshop_review.${name} t ORDER BY to_jsonb(t)::text`)).rows;return out;}
async function seed(db,owner){const t={targetId:randomUUID(),launchId:randomUUID(),scenarioId:randomUUID(),instanceId:randomUUID(),owner};
 await db.query(`INSERT INTO secureshop_review.product_targets(target_id,launch_id,scenario_id,generation,original_platform_owner_id,original_platform_session_id,own_merchant_id,source_count,source_sha256) VALUES($1,$2,$3,1,$4,51,12,1,decode($5,'hex'))`,[t.targetId,t.launchId,t.scenarioId,owner,hex('1')]);
 await db.query(`INSERT INTO secureshop_review.bound_system_restart_targets(target_id,launch_id,scenario_id,generation,original_platform_owner_id,original_platform_session_id,instance_id) VALUES($1,$2,$3,1,$4,51,$5)`,[t.targetId,t.launchId,t.scenarioId,owner,t.instanceId]);return t;}
async function running(db,t){const op=randomUUID(),worker=randomUUID();await db.query(`INSERT INTO secureshop_review.bound_system_restart_operations(operation_id,target_id,launch_id,scenario_id,generation,original_platform_owner_id,original_platform_session_id,shop_user_id,persona_session_id,authority_version,service_name,request_sha256,binding_sha256) VALUES($1,$2,$3,$4,1,$5,51,77,$6,1,'nginx',decode($7,'hex'),decode($8,'hex'))`,[op,t.targetId,t.launchId,t.scenarioId,t.owner,randomUUID(),require('../../server/services/secureshopSystemRestartContract').restartRequestDigest({version:1,operationId:op,name:'nginx'}),hex('3')]);
 await db.query('SELECT * FROM secureshop_review.begin_bound_system_restart($1,$2)',[op,worker]);return{op,worker};}
function receipt(t,run){const request={version:1,operationId:run.op,name:'nginx'},hostname='restart-'+'a'.repeat(32),stdoutText=hostname+'\n',stderrText='storage-only €\n';
 const value={version:Wire.WITNESS_VERSION,targetId:t.targetId,operationId:run.op,requestSha256:require('../../server/services/secureshopSystemRestartContract').restartRequestDigest(request),beforeInstanceId:t.instanceId,afterInstanceId:randomUUID(),beforeGeneration:1,afterGeneration:2,effectSha256:hex('4'),outputSha256:sha(stdoutText+stderrText),outputBytes:Buffer.byteLength(stdoutText+stderrText),outputText:stdoutText+stderrText,ownedCommandEffectSha256:hex('5'),ownedCommandEffectFiles:1,ownedCommandEffectBytes:1,command:'systemctl restart nginx',status:'completed',isolation:Wire.ISOLATION,witness:Wire.restartWitness({targetId:t.targetId,request},hostname),stdoutText,stderrText,stdoutSha256:sha(stdoutText),stderrSha256:sha(stderrText),stdoutBytes:Buffer.byteLength(stdoutText),stderrBytes:Buffer.byteLength(stderrText),drained:true,exitCode:0};
 return Wire.validateRestartReceipt({targetId:t.targetId,request},value);}
const complete=(db,run,text,worker=run.worker)=>db.query('SELECT * FROM secureshop_review.complete_bound_system_restart_with_receipt($1,$2,$3)',[run.op,worker,text]);
async function assertFull(db,run,text){const rows=(await db.query("SELECT receipt_text,encode(receipt_sha256,'hex') AS sha FROM secureshop_review.bound_system_restart_full_receipts WHERE operation_id=$1",[run.op])).rows;assert.deepEqual(rows,[{receipt_text:text,sha:sha(text)}]);}
async function ledger(db){return(await db.query('SELECT name,checksum FROM dvaia_migrations.ledger ORDER BY name')).rows;}
async function noOp(db){const before=await ledger(db);assert.deepEqual(await migrate(db,DIR),[]);assert.deepEqual(await ledger(db),before);}
test('0051 fresh exact private receipt privileges, atomic denial, immutable bytes and guarded owner cleanup',{skip:!enabled,timeout:120000},async t=>{
 const {m,r}=await open('FRESH',t),manifest=await readMigrations(DIR);assert.equal(manifest.at(-1).name,TAIL);assert.deepEqual(await migrate(m,DIR),manifest.map(x=>x.name));await noOp(m);
 assert.deepEqual(await ledger(m),manifest.map(({name,checksum})=>({name,checksum})));
 const privileges=(await r.query(`SELECT has_table_privilege(current_user,'secureshop_review.bound_system_restart_full_receipts','SELECT') AS read,has_table_privilege(current_user,'secureshop_review.bound_system_restart_full_receipts','INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') AS write,has_function_privilege(current_user,'secureshop_review.complete_bound_system_restart_with_receipt(uuid,uuid,text)','EXECUTE') AS complete,has_function_privilege(current_user,'secureshop_review.guard_bound_system_restart_full_receipt()','EXECUTE') AS guard`)).rows[0];assert.deepEqual(privileges,{read:true,write:false,complete:true,guard:false});
 const funcs=(await m.query(`SELECT p.proname,p.prosecdef,p.proconfig,EXISTS(SELECT 1 FROM aclexplode(p.proacl) a WHERE a.grantee=0 AND a.privilege_type='EXECUTE') AS public_execute FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='secureshop_review' AND p.proname=ANY($1::text[]) ORDER BY p.proname`,[['complete_bound_system_restart_with_receipt','guard_bound_system_restart_full_receipt']])).rows;
 assert.equal(funcs.length,2);for(const f of funcs){assert.equal(f.prosecdef,true);assert.deepEqual(f.proconfig,['search_path=pg_catalog, secureshop_review']);assert.equal(f.public_execute,false);}
 const trigger=(await m.query("SELECT tgenabled FROM pg_trigger WHERE tgrelid='secureshop_review.bound_system_restart_full_receipts'::regclass AND tgname='bound_system_restart_full_receipt_guard'")).rows;assert.deepEqual(trigger,[{tgenabled:'O'}]);
 const target=await seed(m,41),run=await running(r,target),valid=receipt(target,run),baseline=await snapshot(m);
 for(const change of [v=>v.targetId=randomUUID(),v=>v.operationId=randomUUID(),v=>v.requestSha256=hex('0'),v=>v.witness.bindingSha256=hex('0'),v=>v.witness.hostname='restart-'+'b'.repeat(32),v=>v.stdoutSha256=hex('0'),v=>v.stderrBytes++,v=>v.extra=true,v=>delete v.drained,v=>v.stdoutText=12]){const bad=structuredClone(valid);change(bad);await assert.rejects(complete(r,run,JSON.stringify(bad)),e=>['55000','22023'].includes(e.code));assert.deepEqual(await snapshot(m),baseline);}
 await assert.rejects(complete(r,run,JSON.stringify(valid),randomUUID()),e=>e.code==='55000');assert.deepEqual(await snapshot(m),baseline);
 // Deliberately retain a noncanonical key order: hash the original full TEXT,
 // never jsonb::text or a reconstructed partial public receipt.
 const text=JSON.stringify(Object.fromEntries(Object.entries(valid).reverse()));await complete(r,run,text);await assertFull(r,run,text);
 const completed=await snapshot(m);await assert.rejects(complete(r,run,text),e=>e.code==='55000');assert.deepEqual(await snapshot(m),completed);
 for(const sql of ["INSERT INTO secureshop_review.bound_system_restart_full_receipts SELECT * FROM secureshop_review.bound_system_restart_full_receipts",'UPDATE secureshop_review.bound_system_restart_full_receipts SET receipt_text=receipt_text','DELETE FROM secureshop_review.bound_system_restart_full_receipts','TRUNCATE secureshop_review.bound_system_restart_full_receipts'])await assert.rejects(r.query(sql),e=>e.code==='42501');
 for(const sql of ['UPDATE secureshop_review.bound_system_restart_full_receipts SET receipt_text=receipt_text','DELETE FROM secureshop_review.bound_system_restart_full_receipts'])await assert.rejects(m.query(sql),e=>e.code==='55000');
 assert.deepEqual(await snapshot(m),completed);
 const peer=await seed(m,42),peerRun=await running(r,peer),peerText=JSON.stringify(receipt(peer,peerRun));await complete(r,peerRun,peerText);const peerBefore=(await snapshot(m));
 await r.query('SELECT * FROM secureshop_review.destroy_bound_audit_owner($1,$2)',[41,randomUUID()]);
 assert.equal((await r.query('SELECT count(*)::int AS n FROM secureshop_review.bound_system_restart_full_receipts WHERE operation_id=$1',[run.op])).rows[0].n,0);await assertFull(r,peerRun,peerText);
 const after=await snapshot(m);for(const name of Object.keys(after))assert.deepEqual(after[name],peerBefore[name].filter(x=>x.row.original_platform_owner_id===42));
 assert.equal((await r.query('SELECT count(*)::int n FROM secureshop_review.bound_system_restart_owner_deletion_receipts WHERE original_platform_owner_id=41')).rows[0].n,1);await noOp(m);
});
test('0051 populated v2 originals and sibling rows survive exact upgrade and second-run no-op',{skip:!enabled,timeout:120000},async t=>{
 const {m,r}=await open('POPULATED',t),prefix=prefixMigrate();await prefix(m,DIR);const oldLedger=await ledger(m);assert.ok(oldLedger.length>0);assert.equal(oldLedger.at(-1).name.startsWith('0050_'),true);
 const a=await seed(m,61),old=await running(r,a),b=await seed(m,62),peer=await running(r,b);
 for(const [target,run] of [[a,old],[b,peer]])await r.query("SELECT * FROM secureshop_review.complete_bound_system_restart($1,$2,$3,$4,1,2,decode($5,'hex'),decode($6,'hex'),$7,$8)",[run.op,run.worker,target.instanceId,randomUUID(),hex('4'),sha('legacy original\n'),Buffer.byteLength('legacy original\n'),'legacy original\n']);
 const pendingTarget=await seed(m,63),pending=await running(r,pendingTarget);
 const tables=['bound_system_restart_operations','bound_system_restart_targets'],before={};for(const table of tables)before[table]=(await m.query(`SELECT to_jsonb(t) AS row FROM secureshop_review.${table} t ORDER BY to_jsonb(t)::text`)).rows;
 assert.deepEqual(await migrate(m,DIR),[TAIL]);assert.deepEqual((await ledger(m)).slice(0,oldLedger.length),oldLedger);
 for(const table of tables)assert.deepEqual((await m.query(`SELECT to_jsonb(t) AS row FROM secureshop_review.${table} t ORDER BY to_jsonb(t)::text`)).rows,before[table]);
 assert.equal((await r.query('SELECT count(*)::int AS n FROM secureshop_review.bound_system_restart_full_receipts')).rows[0].n,0);await noOp(m);
 const text=JSON.stringify(receipt(pendingTarget,pending));await complete(r,pending,text);await assertFull(r,pending,text);
 for(const run of [old,peer])assert.equal((await r.query('SELECT count(*)::int n FROM secureshop_review.bound_system_restart_full_receipts WHERE operation_id=$1',[run.op])).rows[0].n,0);
 for(const table of tables){const current=(await m.query(`SELECT to_jsonb(t) AS row FROM secureshop_review.${table} t WHERE original_platform_owner_id IN(61,62) ORDER BY to_jsonb(t)::text`)).rows;assert.deepEqual(current,before[table].filter(x=>[61,62].includes(x.row.original_platform_owner_id)));}await noOp(m);
});
