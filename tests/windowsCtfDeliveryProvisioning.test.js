'use strict';
// Caller -> real JavaScript native-journal adapter with controlled providers;
// no PostgreSQL, PowerShell, native NTFS, or credential output.
const {test}=require('node:test'),assert=require('node:assert/strict'),crypto=require('node:crypto');
const {createCtfDeliveryProvisioner}=require('../db/postgres/provision-ctf-delivery');
const {createWindowsProvisioningJournal}=require('../scripts/lib/windows-provisioning-journal');
const {provisioningPlan}=require('../db/postgres/provision-application');
const repositoryDirectory='C:\\Workspaces\\app',parent='C:\\Users\\Synthetic\\private',manifestPath=parent+'\\base.json',outputPath=parent+'\\delivery.json';
const hash=bytes=>crypto.createHash('sha256').update(bytes).digest('hex');
function fixture(){
 const plan=provisioningPlan(),configuration=Object.fromEntries(plan.flatMap(row=>['runtime','migration'].map(kind=>[row[kind+'Variable'],`postgres://${row[kind+'Role']}:synthetic@127.0.0.1/${row.database}`])));
 const files=new Map([[manifestPath,Buffer.from(JSON.stringify({version:1,status:'complete',cluster:'controlled-cluster',plan,configuration}))]]),events=[],intents=new Map(),publications=[];let roleExists=false,rolePrivileged=false,membership=false,loseDdl=false,authFail=false,inspectDenied=false,readDenied=null,failPublication=0;
 const native={inspectPrivateDirectory:p=>{events.push(['nativeInspect',p]);assert.equal(p,parent);if(inspectDenied)throw Error('SECRET ACL detail');return{};},readPrivateFile:p=>{events.push(['nativeRead',p]);if(readDenied===p||!files.has(p))throw Object.assign(Error('SECRET denied read'),{code:'ENOENT'});return Buffer.from(files.get(p));}};
 const receipt=intent=>({state:intent.committed?'committed':'prepared',intentSha256:hash(Buffer.from(intent.options.intentPath)),size:intent.options.resultBytes.length,identity:{volumeSerial:1,fileId:intent.fileId}});
 const publication={preparePrivatePublication:options=>{
  events.push(['prepare',options.targetPath]);assert.deepEqual(Object.keys(options).sort(),['intentPath','operationId','originalBytes','resultBytes','targetPath']);assert.equal(options.originalBytes,null);
  let intent=intents.get(options.intentPath);if(intent){assert.deepEqual(intent.options.resultBytes,options.resultBytes);}else{if(files.has(options.targetPath))throw Error('SECRET collision');intent={options:{...options,resultBytes:Buffer.from(options.resultBytes)},fileId:(intents.size+1).toString(16).padStart(16,'0'),committed:false};intents.set(options.intentPath,intent);}return receipt(intent);
 },publishPrivatePublication:binding=>{
  events.push(['publish',binding.targetPath]);publications.push(binding);if(publications.length===failPublication)throw Error('SECRET journal flush failure');const intent=intents.get(binding.intentPath);assert(intent);assert.equal(binding.targetPath,intent.options.targetPath);assert.equal(binding.operationId,intent.options.operationId);
  if(intent.committed)assert.deepEqual(files.get(binding.targetPath),intent.options.resultBytes);else if(files.has(binding.targetPath))throw Error('SECRET unexpected bytes');files.set(binding.targetPath,Buffer.from(intent.options.resultBytes));intent.committed=true;return receipt(intent);
 }};
 const privateJournal=createWindowsProvisioningJournal({platform:'win32',privateState:native,publication});
 const fileSystem=new Proxy({realpath:async p=>p,lstat:async p=>{events.push(['stat',p]);if(files.has(p))return{isFile:()=>true,isSymbolicLink:()=>false};throw Object.assign(Error('Absent'),{code:'ENOENT'});}}, {get(target,key){if(key in target)return target[key];return()=>{throw Error('POSIX filesystem forbidden: '+String(key));};}});
 const client={connect:async()=>events.push(['connect']),end:async()=>events.push(['end']),query:async(sql)=>{events.push(['query',sql.split(' PASSWORD ')[0]]);if(sql.includes('pg_control_system'))return{rows:[{cluster:'controlled-cluster',version:180000}]};if(sql.includes('pg_database d'))return{rows:[{owner:'dvaia_ctf_migration'}]};if(sql.includes('FROM pg_roles WHERE'))return{rows:roleExists?[{rolname:'dvaia_ctf_delivery',rolcanlogin:true,rolsuper:rolePrivileged}]:[]};if(sql.includes('pg_auth_members'))return{rows:membership?[{}]:[]};if(sql.startsWith('CREATE ROLE')){roleExists=true;if(loseDdl){loseDdl=false;throw Object.assign(Error('SECRET unknown acknowledgement'),{code:'CONTROLLED_ACK_LOST'});}}return{rows:[]};}};
 const delivery={connect:async()=>{events.push(['authenticate']);if(authFail)throw Object.assign(Error('SECRET auth failure'),{code:'28P01'});},query:async()=>({rows:[{login:'dvaia_ctf_delivery',effective:'dvaia_ctf_delivery',database:'owasp_ai_goat_ctf'}]}),end:async()=>events.push(['authEnd'])};
 const provision=createCtfDeliveryProvisioner({platform:'win32',fileSystem,repositoryDirectory,privateJournal}).provisionCtfDelivery;
 return{files,events,intents,publications,invoke:options=>provision({adminUrl:'postgres://synthetic:unused@127.0.0.1/postgres',manifestPath,outputPath,env:{},clientFactory:()=>client,deliveryClientFactory:()=>delivery,...options}),denyInspect(){inspectDenied=true;},denyRead:p=>{readDenied=p;},loseDdl(){loseDdl=true;},failAuth(){authFail=true;},failPublication:n=>{failPublication=n;},collide(){roleExists=true;},privilege(){rolePrivileged=true;},membership(){membership=true;}};
}
const ddl=f=>f.events.filter(([op,sql])=>op==='query'&&/^(CREATE|GRANT) /.test(sql));
test('Windows CTF fresh caller composes native pending/final create, retains immutable pending, and reauthenticates no-op',async()=>{
 const f=fixture(),base=Buffer.from(f.files.get(manifestPath));let hook=0;const result=await f.invoke({completionWriter:async complete=>{hook++;await complete();}});assert.equal(hook,1);assert.equal(result.status,'created');assert.equal(f.publications.length,2);assert.deepEqual(f.publications.map(p=>p.targetPath),[outputPath+'.pending',outputPath]);
 const pending=f.files.get(outputPath+'.pending'),complete=f.files.get(outputPath);assert.equal(JSON.parse(pending).status,'incomplete');assert.equal(JSON.parse(complete).status,'complete');assert.deepEqual(JSON.parse(pending).configuration,JSON.parse(complete).configuration);assert.deepEqual(f.files.get(manifestPath),base);
 assert(f.events.findIndex(([op])=>op==='nativeInspect')<f.events.findIndex(([op])=>op==='connect'));assert(f.events.findIndex(([op,p])=>op==='publish'&&p===outputPath+'.pending')<f.events.findIndex(([op,sql])=>op==='query'&&sql.startsWith('CREATE ')));assert(f.events.findIndex(([op])=>op==='authenticate')<f.events.findIndex(([op,p])=>op==='publish'&&p===outputPath));
 assert.equal((await f.invoke()).status,'existing');assert.equal(f.publications.length,2);assert.equal(f.files.get(outputPath+'.pending'),pending);assert.equal(f.files.get(outputPath),complete);assert.equal(ddl(f).length,2);assert.equal(f.events.filter(([op])=>op==='authenticate').length,2);
});
test('Windows CTF repository containment and base/output alias checks are case-insensitive and precede DB',async()=>{
 for(const bad of ['c:\\workspaces\\APP\\delivery.json','c:\\users\\synthetic\\PRIVATE\\BASE.JSON','C:\\Workspaces\\app\\..\\delivery.json','relative.json','\\\\host\\share\\delivery.json']){
  const f=fixture();await assert.rejects(f.invoke({outputPath:bad}),{code:'CTF_DELIVERY_PRIVATE_DESTINATION_REQUIRED'});assert(!f.events.some(([op])=>op==='connect'));assert.equal(f.publications.length,0);
 }
});
test('Windows CTF native private parent and base denial never connect or create replacement',async()=>{
 const acl=fixture();acl.denyInspect();await assert.rejects(acl.invoke(),{code:'CTF_DELIVERY_PRIVATE_PARENT_REQUIRED'});assert(!acl.events.some(([op])=>op==='connect'));assert.equal(acl.publications.length,0);
 const read=fixture();read.denyRead(manifestPath);await assert.rejects(read.invoke(),e=>e.code==='CTF_DELIVERY_MANIFEST_NOT_PRIVATE'&&!String(e.stack).includes('SECRET'));assert(!read.events.some(([op])=>op==='connect'));assert.equal(read.files.size,1);
});
test('Windows CTF initial pending publication denial stops before DDL and retains native intent',async()=>{
 const f=fixture();f.failPublication(1);await assert.rejects(f.invoke(),e=>e.code==='WINDOWS_PROVISIONING_JOURNAL_DENIED'&&!String(e.stack).includes('SECRET'));assert.equal(ddl(f).length,0);assert.equal(f.intents.size,1);assert(!f.files.has(outputPath));
});
test('Windows CTF unknown DDL acknowledgement retains incomplete private pending and forbids replay',async()=>{
 const f=fixture();f.loseDdl();await assert.rejects(f.invoke(),{code:'CONTROLLED_ACK_LOST'});const pending=f.files.get(outputPath+'.pending');assert.equal(JSON.parse(pending).status,'incomplete');assert(!f.files.has(outputPath));await assert.rejects(f.invoke(),{code:'CTF_DELIVERY_PROVISION_PENDING'});assert.equal(ddl(f).length,1);assert.equal(f.files.get(outputPath+'.pending'),pending);
});
test('Windows CTF authentication and completion hook failure preserve pending without automatic adoption',async()=>{
 for(const configure of [f=>{f.failAuth();return{};},()=>({completionWriter:async()=>{throw Object.assign(Error('controlled completion'),{code:'EIO'});}})]){
  const f=fixture(),options=configure(f);await assert.rejects(f.invoke(options));assert.equal(ddl(f).length,2);const pending=f.files.get(outputPath+'.pending');assert.equal(JSON.parse(pending).status,'incomplete');assert(!f.files.has(outputPath));await assert.rejects(f.invoke(),{code:'CTF_DELIVERY_PROVISION_PENDING'});assert.equal(ddl(f).length,2);assert.equal(f.files.get(outputPath+'.pending'),pending);
 }
});
test('Windows CTF final native publication failure retains pending and refuses blind DDL retry',async()=>{
 const f=fixture();f.failPublication(2);await assert.rejects(f.invoke(),{code:'WINDOWS_PROVISIONING_JOURNAL_DENIED'});assert.equal(f.intents.size,2);assert.equal(JSON.parse(f.files.get(outputPath+'.pending')).status,'incomplete');assert(!f.files.has(outputPath));await assert.rejects(f.invoke(),{code:'CTF_DELIVERY_PROVISION_PENDING'});assert.equal(ddl(f).length,2);
});
test('Windows CTF denied or malformed prior manifest cannot be interpreted as absence',async()=>{
 for(const configure of [f=>f.denyRead(outputPath),f=>f.files.set(outputPath,Buffer.from('{partial')),f=>f.files.set(outputPath,Buffer.from('null'))]){
  const f=fixture();await f.invoke();configure(f);const before=f.files.get(outputPath),count=f.events.filter(([op])=>op==='connect').length;await assert.rejects(f.invoke(),{code:'CTF_DELIVERY_MANIFEST_NOT_PRIVATE'});assert.equal(f.files.get(outputPath),before);assert.equal(f.publications.length,2);assert.equal(f.events.filter(([op])=>op==='connect').length,count);assert.equal(ddl(f).length,2);
 }
});
test('Windows CTF existing credentials still require login and role/membership authority checks',async()=>{
 for(const [configure,code]of [[f=>f.failAuth(),'28P01'],[f=>f.privilege(),'CTF_DELIVERY_ROLE_MISMATCH'],[f=>f.membership(),'CTF_DELIVERY_ROLE_MISMATCH']]){
  const f=fixture();await f.invoke();configure(f);await assert.rejects(f.invoke(),{code});assert.equal(f.publications.length,2);assert.equal(ddl(f).length,2);
 }
});
test('Windows CTF unowned role collision never creates journal or adopts role',async()=>{
 const f=fixture();f.collide();await assert.rejects(f.invoke(),{code:'CTF_DELIVERY_ROLE_COLLISION'});assert.equal(f.publications.length,0);assert.equal(ddl(f).length,0);assert.equal(f.files.size,1);
});
