'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path'),vm=require('node:vm'),{createHash}=require('node:crypto');
const {provisioningPlan}=require('../db/postgres/provision-application');
function fixture(t,options={}){
 const root=fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(),'inspection-')));t.after(()=>fs.rmSync(root,{recursive:true,force:true}));const plan=provisioningPlan(),env={PG_ADMIN_DATABASE_URL:'postgres://admin:secret@127.0.0.1/postgres',PG_TLS:'disable'},configuration={};for(const p of plan)for(const kind of ['runtime','migration'])configuration[p[kind+'Variable']]=env[p[kind+'Variable']]=`postgres://${p[kind+'Role']}:secret@127.0.0.1/${p.database}`;
 const manifestPath=path.join(root,'manifest.json');fs.writeFileSync(manifestPath,JSON.stringify({version:1,status:'complete',plan,cluster:'123',configuration}),{mode:0o600});const controller=new AbortController(),lease={signal:controller.signal},endpointPolicySha256=createHash('sha256').update(JSON.stringify({host:'127.0.0.1',port:'5432',tls:'disable'})).digest('hex');const owner={pid:42,backendStart:'2026-01-01 00:00:00+00',databaseOid:'100',databaseName:'owasp_ai_goat_identity',role:'dvaia_identity_migration',endpointPolicySha256};let open=0,maximum=0,observations=0,budget=0,connections=0;const calls=[],sessions=new Map();
 class Client{constructor(config){this.u=new URL(config.connectionString);this.pid=1000+(++connections);this.closed=false;}on(){}async connect(){open++;maximum=Math.max(maximum,open);}async end(){if(options.closeFailure)throw Error('private secret');if(!this.closed){this.closed=true;open--;}}async query(sql,args){calls.push(sql);const name=this.u.pathname.slice(1),p=plan.find(x=>x.database===name),oid=p?String(100+plan.indexOf(p)):'99';
 if(sql.includes('SELECT ssl'))return{rows:[{ssl:!options.noTls}]};
 if(sql.includes('server_version_num'))return{rows:[{server_version_num:'180000'}]};if(sql.includes('pg_control_system'))return{rows:[{system_identifier:'123'}]};
 if(sql==='SELECT rolsuper FROM pg_roles WHERE rolname=current_user')return{rows:[{rolsuper:!options.restricted}]};
 if(sql.includes("rolname='dvaia_ctf_delivery'"))return{rows:sql.includes('pg_auth_members')?[]:options.delivery?[{rolname:'dvaia_ctf_delivery',rolcanlogin:true,rolsuper:!!options.badDelivery}]:[]};
 if(sql.includes('pg_auth_members'))return{rows:[]};
 if(sql.includes('SELECT d.datname'))return{rows:[{datname:args[0],owner:plan.find(x=>x.database===args[0]).migrationRole}]};
 if(sql.includes('rolname=ANY'))return{rows:args[0].map(rolname=>({rolname,rolsuper:false,rolcreatedb:false,rolcreaterole:false,rolreplication:false,rolbypassrls:false,rolcanlogin:true}))};
 if(sql.includes('SELECT oid::text'))return{rows:[{oid:options.wrongOid?'999':String(100+plan.findIndex(x=>x.database===args[0]))}]};
 if(sql.includes('pg_backend_pid() AS pid')){const row={pid:this.pid,backend_start:'2026-01-01 00:00:00+00',datid:oid,datname:name,usename:decodeURIComponent(this.u.username)};sessions.set(this.pid,row);return{rows:[row]};}
 if(sql.includes('pg_stat_activity WHERE pid=$1'))return{rows:options.foreignCluster?[]:[sessions.get(args[0])]};
 if(sql.includes('datid=ANY')){assert.equal(open,1,'All store clients closed before global activity snapshot');const rows=[{pid:42,backend_start:owner.backendStart,datid:'100',datname:'owasp_ai_goat_identity',usename:owner.role,backend_type:'client backend'}];if(options.activity)rows.push(options.activity);return{rows};}
 throw Error('Unhandled controlled query');}}
 let deliveryManifestPath;if(options.delivery){env.CTF_DELIVERY_DATABASE_URL='postgres://dvaia_ctf_delivery:secret@127.0.0.1/owasp_ai_goat_ctf';deliveryManifestPath=path.join(root,'delivery.json');const ctf=plan.find(x=>x.schema==='ctf');fs.writeFileSync(deliveryManifestPath,JSON.stringify({version:1,status:'complete',baseFingerprint:createHash('sha256').update(JSON.stringify({cluster:'123',ctf})).digest('hex'),cluster:'123',database:'owasp_ai_goat_ctf',role:'dvaia_ctf_delivery',configuration:{CTF_DELIVERY_DATABASE_URL:env.CTF_DELIVERY_DATABASE_URL}}),{mode:0o600});}
 const module={exports:{}};vm.runInNewContext(fs.readFileSync(require.resolve('../server/database/postgres/applicationMaintenanceStoreInspection'),'utf8'),{module,require:n=>n==='pg'?{Client}:n==='./index'?{poolConfig:require('../server/database/postgres').poolConfig,reserveDedicatedConnection:()=>{budget++;return()=>budget--;}}:n==='../../services/applicationMaintenanceLease'?{observeExclusiveMaintenanceLease:async l=>{assert.equal(l,lease);if(++observations===options.expireAt)options.expired=true;if(observations===options.hangAt)await new Promise(()=>{});if(observations===options.lossAt)throw Error('lost');return{...owner,...(options.wrongEndpoint?{endpointPolicySha256:'f'.repeat(64)}:{})};}}:n==='../../../db/postgres/provision-application'?require('../db/postgres/provision-application'):n==='node:perf_hooks'&&options.clock?{performance:{now:()=>options.expired?60001:0}}:require(n),process,Buffer,URL,Date,setTimeout:options.fastTimers?((fn,ms)=>setTimeout(fn,Math.min(ms,10))):setTimeout,clearTimeout,AggregateError});
 return{api:module.exports.createApplicationMaintenanceStoreInspection({environment:env,manifestPath,deliveryManifestPath,lease}),env,manifestPath,stats:()=>({open,maximum,budget,connections}),calls};
}
test('real manifest validator and observed sessions derive16 stores with bounded sequential clients',async t=>{const f=fixture(t),r=await f.api.inspect();assert.equal(r.stores.length,16);assert.equal(r.stores[15].databaseOid,115);assert.equal(r.recoveryAuthorized,false);assert.equal(r.recordedBackendsAbsent,true);assert.deepEqual(f.stats(),{open:0,maximum:2,budget:0,connections:33});});
test('restricted activity, wrong OID, lease endpoint and loss fail closed with cleanup',async t=>{for(const options of [{restricted:true},{wrongOid:true},{wrongEndpoint:true},{foreignCluster:true},{lossAt:4}]){const f=fixture(t,options);await assert.rejects(f.api.inspect());assert.equal(f.stats().open,0);assert.equal(f.stats().budget,0);}});
test('other idle/backend session cannot borrow lease PID or role exemption',async t=>{for(const patch of [{pid:77},{backend_start:'different'},{datid:'101'},{backend_type:null}]){const f=fixture(t,{activity:{pid:42,backend_start:'2026-01-01 00:00:00+00',datid:'100',datname:'owasp_ai_goat_identity',usename:'dvaia_identity_migration',backend_type:'client backend',...patch}});await assert.rejects(f.api.inspect());assert.equal(f.stats().open,0);}});
test('manifest symlink and environment mismatch refuse before store connections',async t=>{const f=fixture(t);const bytes=fs.readFileSync(f.manifestPath);fs.unlinkSync(f.manifestPath);const other=f.manifestPath+'.other';fs.writeFileSync(other,bytes,{mode:0o600});fs.symlinkSync(other,f.manifestPath);await assert.rejects(f.api.inspect());assert.equal(f.stats().connections,0);const g=fixture(t);const m=JSON.parse(fs.readFileSync(g.manifestPath));m.configuration.IDENTITY_DATABASE_URL=m.configuration.IDENTITY_DATABASE_URL.replace('secret','changed');fs.writeFileSync(g.manifestPath,JSON.stringify(m));await assert.rejects(g.api.inspect());assert.equal(g.stats().connections,1);});
test('unproven close retains reservation and reports only safe drain failure',async t=>{const f=fixture(t,{closeFailure:true});await assert.rejects(f.api.inspect(),e=>e instanceof AggregateError&&!JSON.stringify(e).includes('secret'));assert(f.stats().budget>0);await assert.rejects(f.api.inspect(),{code:'MAINTENANCE_INSPECTION_DRAIN_UNKNOWN'});});

test('canonical delivery extension is observed with its own private manifest and never exempted by role',async t=>{const f=fixture(t,{delivery:true}),r=await f.api.inspect();assert.equal(r.stores.find(s=>s.storeKey==='ctf').deliveryRole,'dvaia_ctf_delivery');assert.equal(f.stats().connections,34);const bad=fixture(t,{delivery:true,badDelivery:true});await assert.rejects(bad.api.inspect(),{code:'MAINTENANCE_INSPECTION_DELIVERY_MISMATCH'});assert.equal(bad.stats().open,0);});

test('final authentic lease observation cannot return late success after monotonic expiry',async t=>{
 const options={clock:true,expireAt:36},f=fixture(t,options);
 await assert.rejects(f.api.inspect(),{code:'MAINTENANCE_INSPECTION_TIMEOUT'});
 assert.equal(options.expired,true);assert.equal(f.stats().connections,33);assert.equal(f.stats().open,0);assert.equal(f.stats().budget,0);
});
test('initial and intermediate lease observations respect deadline before additional clients',async t=>{
 for(const [expireAt,connections] of [[1,0],[2,0],[3,1]]){
  const f=fixture(t,{clock:true,expireAt});await assert.rejects(f.api.inspect(),{code:'MAINTENANCE_INSPECTION_TIMEOUT'});
  assert.equal(f.stats().connections,connections);assert.equal(f.stats().open,0);assert.equal(f.stats().budget,0);
 }
});
test('unsettled authentic lease observation is timed out rather than waiting indefinitely',async t=>{
 for(const hangAt of [1,3,36]){
  const f=fixture(t,{hangAt,fastTimers:true});await assert.rejects(f.api.inspect(),{code:'MAINTENANCE_INSPECTION_TIMEOUT'});
  assert.equal(f.stats().open,0);assert.equal(f.stats().budget,0);
 }
});
test('private manifest growth after initial stat is bounded and rejected before connecting',async t=>{
 const f=fixture(t),original=fs.fstatSync;let changed=false;
 fs.fstatSync=function(fd){const s=original(fd);if(!changed){changed=true;fs.appendFileSync(f.manifestPath,'growth');}return s;};
 try{await assert.rejects(f.api.inspect(),{code:'MAINTENANCE_INSPECTION_MANIFEST_INVALID'});assert.equal(f.stats().connections,0);}finally{fs.fstatSync=original;}
});
