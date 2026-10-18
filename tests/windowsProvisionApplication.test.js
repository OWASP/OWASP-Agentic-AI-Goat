'use strict';
// Controlled provisioning/journal contracts; no native Windows or PostgreSQL.
const {test}=require('node:test'),assert=require('node:assert/strict'),crypto=require('node:crypto');
const {createApplicationProvisioner,provisioningPlan}=require('../db/postgres/provision-application');
const repositoryDirectory='C:\\Workspaces\\app',manifestPath='C:\\Users\\Synthetic\\private\\provisioning.json';
const adminUrl='postgres://synthetic:unused@127.0.0.1/postgres',plan=provisioningPlan();
const hash=bytes=>crypto.createHash('sha256').update(bytes).digest('hex');
function prior(rows=plan){return{version:1,status:'complete',cluster:'controlled-cluster',plan:rows,configuration:Object.fromEntries(rows.flatMap(row=>['runtime','migration'].map(kind=>[row[kind+'Variable'],`postgres://${row[kind+'Role']}:synthetic-existing@127.0.0.1/${row.database}`]))),created:[]};}
function fixture(previous,adapterFactory){
 const files=new Map(previous?[[manifestPath,Buffer.from(JSON.stringify(previous))]]:[]),events=[],writes=[];let inspectDenied=false,readDenied=false,ddlLost=false,writeFailure=0,afterWrite=false,collide=false;
 const missing=()=>{throw Object.assign(Error('Absent'),{code:'ENOENT'});};
 const privateJournal={inspectDestination:({filePath})=>{events.push(['inspect',filePath]);if(inspectDenied)throw Object.assign(Error('SECRET denied'),{stderr:'SECRET'});},readJournal:({filePath})=>{events.push(['read',filePath]);if(readDenied||!files.has(filePath))throw Object.assign(Error('SECRET denied'),{code:'ENOENT'});return Buffer.from(files.get(filePath));},createJournal:({filePath,bytes})=>{
  events.push(['create',filePath]);if(files.has(filePath))throw Error('collision');write({filePath,originalBytes:null,resultBytes:bytes});
 },updateJournal:options=>{events.push(['update',options.filePath]);assert(files.get(options.filePath)?.equals(options.originalBytes));write(options);}};
 function write(options){writes.push({...options,originalBytes:options.originalBytes&&Buffer.from(options.originalBytes),resultBytes:Buffer.from(options.resultBytes)});const failing=writes.length===writeFailure;if(failing&&!afterWrite)throw Object.assign(Error('SECRET publication failure'),{code:'WINDOWS_PROVISIONING_JOURNAL_DENIED'});files.set(options.filePath,Buffer.from(options.resultBytes));if(failing)throw Object.assign(Error('SECRET acknowledgement loss'),{code:'WINDOWS_PROVISIONING_JOURNAL_DENIED'});}
 const fileSystem=new Proxy({realpath:async p=>p,lstat:async p=>{events.push(['stat',p]);return files.has(p)?{isFile:()=>true,isSymbolicLink:()=>false,mode:0o666}:missing();}}, {get(target,key){if(key in target)return target[key];return()=>{throw Error('POSIX filesystem operation forbidden: '+String(key));};}});
 const client={connect:async()=>events.push(['connect']),end:async()=>events.push(['end']),query:async(sql,args)=>{
  events.push(['query',sql.split(' PASSWORD ')[0]]);
  if(sql.includes('server_version_num'))return{rows:[{server_version_num:'180000'}]};
  if(sql.includes('pg_control_system'))return{rows:[{system_identifier:'controlled-cluster'}]};
  if(sql.startsWith('SELECT d.datname'))return{rows:[{owner:plan.find(row=>row.database===args[0]).migrationRole}]};
  if(sql.startsWith('SELECT rolname,rolsuper'))return{rows:args[0].map(rolname=>({rolname,rolcanlogin:true}))};
  if(sql.includes('UNION ALL')&&collide)return{rows:[{name:'collision'}]};
  if(sql.startsWith('CREATE ROLE')&&ddlLost){ddlLost=false;throw Object.assign(Error('SECRET database acknowledgement unknown'),{code:'CONTROLLED_DDL_ACK_LOST'});}
  return{rows:[]};
 }};
 const provision=createApplicationProvisioner({platform:'win32',fileSystem,privateJournal:adapterFactory?adapterFactory({files,events}):privateJournal,repositoryDirectory}).provisionApplication;
 return{files,events,writes,invoke:options=>provision({adminUrl,manifestPath,env:{},clientFactory:()=>client,...options}),denyInspect(){inspectDenied=true;},denyRead(){readDenied=true;},loseDdlAck(){ddlLost=true;},failWrite(n,after=false){writeFailure=n;afterWrite=after;},collide(){collide=true;}};
}
const ddl=f=>f.events.filter(([op,sql])=>op==='query'&&/^(CREATE|GRANT|REVOKE) /.test(sql));
test('Windows fresh provision admits private destination before connecting and persists every acknowledged effect',async()=>{
 const f=fixture(),result=await f.invoke(),stored=JSON.parse(f.files.get(manifestPath));assert.equal(result.status,'created');assert.equal(stored.status,'complete');assert.equal(stored.created.length,48);assert.equal(f.writes.length,50);assert.equal(f.writes[0].originalBytes,null);assert.equal(JSON.parse(f.writes[0].resultBytes).status,'incomplete');assert.equal(Object.keys(result.configuration).length,32);
 assert(f.events.findIndex(([op])=>op==='inspect')<f.events.findIndex(([op])=>op==='connect'));assert(f.events.findIndex(([op])=>op==='create')<f.events.findIndex(([op,sql])=>op==='query'&&sql.startsWith('CREATE ')));
 for(let i=1;i<f.writes.length;i++)assert.deepEqual(f.writes[i].originalBytes,f.writes[i-1].resultBytes);
});
test('Windows destination ACL, containment and canonical path failures stop before database connection',async()=>{
 const denied=fixture();denied.denyInspect();await assert.rejects(denied.invoke(),{code:'MANIFEST_NOT_PRIVATE'});assert(!denied.events.some(([op])=>op==='connect'));assert.equal(denied.writes.length,0);
 for(const bad of ['c:\\workspaces\\APP\\private.json','C:\\Workspaces\\app\\private\\manifest.json','C:\\Workspaces\\app\\..\\private.json','relative.json','\\\\server\\share\\manifest.json']){
  const f=fixture();await assert.rejects(f.invoke({manifestPath:bad}));assert(!f.events.some(([op])=>op==='connect'));assert.equal(f.writes.length,0);
 }
});
test('Windows initial journal publication failure stops before any DDL and scrubs secret details',async()=>{
 const f=fixture();f.failWrite(1);await assert.rejects(f.invoke(),e=>e.code==='WINDOWS_PROVISIONING_JOURNAL_DENIED'&&!String(e.stack).includes('SECRET'));assert.equal(ddl(f).length,0);assert.equal(f.files.size,0);
});
test('Windows lost DDL acknowledgement leaves incomplete journal and forbids name adoption or replay',async()=>{
 const f=fixture();f.loseDdlAck();await assert.rejects(f.invoke(),{code:'CONTROLLED_DDL_ACK_LOST'});const retained=Buffer.from(f.files.get(manifestPath)),stored=JSON.parse(retained);assert.equal(stored.status,'incomplete');assert.deepEqual(stored.created,[]);assert.equal(ddl(f).length,1);
 await assert.rejects(f.invoke(),{code:'MANIFEST_OWNERSHIP_MISMATCH'});assert.equal(ddl(f).length,1);assert.deepEqual(f.files.get(manifestPath),retained);
});
test('Windows lost persistence acknowledgement retains latest incomplete journal and stops subsequent effects',async()=>{
 const f=fixture();f.failWrite(2,true);await assert.rejects(f.invoke(),{code:'WINDOWS_PROVISIONING_JOURNAL_DENIED'});const retained=Buffer.from(f.files.get(manifestPath)),stored=JSON.parse(retained);assert.equal(stored.status,'incomplete');assert.equal(stored.created.length,1);assert.equal(ddl(f).length,1);
 await assert.rejects(f.invoke(),{code:'MANIFEST_OWNERSHIP_MISMATCH'});assert.equal(ddl(f).length,1);assert.deepEqual(f.files.get(manifestPath),retained);
});
test('Windows existing and no-op upgrade use native reads and preserve every credential byte',async()=>{
 const f=fixture(prior()),before=f.files.get(manifestPath);assert.equal((await f.invoke()).status,'existing');assert.equal((await f.invoke({upgrade:true})).status,'existing');assert.equal(f.files.get(manifestPath),before);assert.equal(f.writes.length,0);assert.equal(ddl(f).length,0);assert.equal(f.events.filter(([op])=>op==='read').length,2);
});
test('Windows native denied or malformed existing manifests cannot become fresh creation',async()=>{
 for(const setup of [f=>f.denyRead(),f=>f.files.set(manifestPath,Buffer.from('null')),f=>f.files.set(manifestPath,Buffer.from('{partial'))]){
  const f=fixture(prior());setup(f);const before=f.files.get(manifestPath);await assert.rejects(f.invoke(),{code:'MANIFEST_NOT_PRIVATE'});assert.equal(f.files.get(manifestPath),before);assert.equal(f.writes.length,0);assert(!f.events.some(([op])=>op==='connect'));
 }
});
test('Windows additive upgrade retains scoped journal and promotes exact original only after all effects',async()=>{
 const previous=prior(plan.slice(0,-1)),f=fixture(previous),original=Buffer.from(f.files.get(manifestPath)),journal=manifestPath+'.upgrade-'+hash(original),result=await f.invoke({upgrade:true});assert.equal(result.status,'upgraded');assert.equal(ddl(f).filter(([,sql])=>sql.startsWith('CREATE ')).length,3);assert.equal(f.writes.length,6);assert.equal(f.writes[0].filePath,journal);assert.equal(f.writes.at(-1).filePath,manifestPath);assert.deepEqual(f.writes.at(-1).originalBytes,original);assert.deepEqual(f.files.get(journal),f.files.get(manifestPath));assert.equal(JSON.parse(f.files.get(journal)).status,'complete');
 for(const [key,value]of Object.entries(previous.configuration))assert.equal(result.configuration[key],value);
 const count=f.writes.length;assert.equal((await f.invoke({upgrade:true})).status,'existing');assert.equal(f.writes.length,count);assert(f.files.has(journal));
});
test('Windows interrupted additive journal preserves old manifest and blocks replay including legacy journals',async()=>{
 const f=fixture(prior(plan.slice(0,-1))),original=Buffer.from(f.files.get(manifestPath)),journal=manifestPath+'.upgrade-'+hash(original);f.loseDdlAck();await assert.rejects(f.invoke({upgrade:true}),{code:'CONTROLLED_DDL_ACK_LOST'});assert.deepEqual(f.files.get(manifestPath),original);assert.equal(JSON.parse(f.files.get(journal)).status,'incomplete');await assert.rejects(f.invoke({upgrade:true}),{code:'PROVISIONING_UPGRADE_PENDING'});assert.equal(ddl(f).length,1);
 const legacy=fixture(prior());legacy.files.set(manifestPath+'.upgrade',Buffer.from('retained legacy journal'));await assert.rejects(legacy.invoke({upgrade:true}),{code:'PROVISIONING_UPGRADE_PENDING'});assert.equal(ddl(legacy).length,0);assert.equal(legacy.writes.length,0);
});
test('Windows colliding names fail before creating a manifest or DDL',async()=>{
 const f=fixture();f.collide();await assert.rejects(f.invoke(),{code:'PROVISIONING_NAME_COLLISION'});assert.equal(f.files.size,0);assert.equal(f.writes.length,0);assert.equal(ddl(f).length,0);
});

test('Windows caller composes with real journal adapter for fifty exact native transitions',async()=>{
 const {createWindowsProvisioningJournal}=require('../scripts/lib/windows-provisioning-journal');
 const preparations=[],publications=[],intents=new Map();
 const f=fixture(undefined,({files,events})=>createWindowsProvisioningJournal({platform:'win32',privateState:{
  inspectPrivateDirectory:p=>{assert.equal(p,'C:\\Users\\Synthetic\\private');events.push(['nativeInspect',p]);return{};},
  readPrivateFile:p=>{events.push(['nativeRead',p]);assert(files.has(p));return Buffer.from(files.get(p));},
 },publication:{
  preparePrivatePublication:options=>{
   assert.deepEqual(Object.keys(options).sort(),['intentPath','operationId','originalBytes','resultBytes','targetPath']);assert.equal(options.targetPath,manifestPath);
   assert.match(options.operationId,/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/);assert.equal(options.intentPath,'C:\\Users\\Synthetic\\private\\provisioning-'+options.operationId+'.intent');
   if(options.originalBytes===null)assert(!files.has(options.targetPath));else assert.deepEqual(files.get(options.targetPath),options.originalBytes);
   const receipt={state:'prepared',intentSha256:hash(Buffer.from(options.intentPath)),size:options.resultBytes.length,identity:{volumeSerial:1,fileId:(preparations.length+1).toString(16).padStart(16,'0')}};
   preparations.push(options);intents.set(options.intentPath,{options,receipt});return receipt;
  },
  publishPrivatePublication:binding=>{
   assert.deepEqual(Object.keys(binding).sort(),['intentPath','operationId','targetPath']);const intent=intents.get(binding.intentPath);assert(intent);assert.equal(binding.operationId,intent.options.operationId);assert.equal(binding.targetPath,intent.options.targetPath);
   publications.push(binding);files.set(binding.targetPath,Buffer.from(intent.options.resultBytes));return{...intent.receipt,state:'committed'};
  },
 }}));
 const result=await f.invoke();assert.equal(result.status,'created');assert.equal(preparations.length,50);assert.equal(publications.length,50);assert.equal(JSON.parse(f.files.get(manifestPath)).status,'complete');assert.equal(preparations[0].originalBytes,null);
 for(let i=1;i<preparations.length;i++)assert.deepEqual(preparations[i].originalBytes,preparations[i-1].resultBytes);
 assert(f.events.findIndex(([op])=>op==='nativeInspect')<f.events.findIndex(([op])=>op==='connect'));assert.equal(f.events.filter(([op])=>op==='nativeRead').length,50);
});
