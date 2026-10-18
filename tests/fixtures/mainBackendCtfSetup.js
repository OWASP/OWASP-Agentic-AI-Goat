'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs/promises'),path=require('node:path');
async function prepare({owned,adminUrl,environment}){
 const root=path.join(owned.appData,'installation');await fs.mkdir(root,{mode:0o700});
 const directory=path.join(root,'private');await fs.mkdir(directory,{mode:0o700});
 const resetKey=require('../../scripts/lib/setup-password-reset-key').ensurePasswordResetKey({directory});
 assert.equal(resetKey.filePath,path.join(directory,'secureshop-reset-key.json'));
 // Production provisioner writes genuine owned cluster/role manifests, never fabricated fixture receipts.
 const provisioned=await require('../../db/postgres/provision-application').provisionApplication({adminUrl,manifestPath:path.join(directory,'provisioning.json'),env:environment});
 assert.equal(provisioned.plan.length,16);
 const delivery=await require('../../scripts/install/ctf-delivery-setup').prepareCtfDelivery({directory,adminUrl,environment});
 const configuration={...provisioned.configuration,...delivery.configuration};
 Object.assign(process.env,environment,configuration);
 await require('../../scripts/lib/application-maintenance-scope').withApplicationMaintenanceScope({environment:process.env},async scope=>{
  await require('../../db/postgres/initialize-application').initializeApplication({maintenanceScope:scope});
  await require('../../scripts/install/ctf-authority-setup').prepareCtfAuthority({root,directory,environment:process.env,maintenanceScope:scope});
 });
 const journal=JSON.parse(await fs.readFile(path.join(directory,'ctf-authority.json'),'utf8'));
 assert.equal(journal.phase,'complete');assert.match(journal.checkpoint.authoritySha256,/^[a-f0-9]{64}$/);
 return {configuration,publicResult:{canonicalStores:16,ctfJournalComplete:true,passwordResetKeyReady:true,actualModel:false}};
}
async function runOwnedSetup({source,root,environment},{spawn=require('node:child_process').spawn,controls=require('./fullBackendBootControls')}={}){
 const children=controls.createOwnedChildren(spawn);
 try{const child=children.launch(process.execPath,[path.join(source,'tests/fixtures/mainBackendCtfSetup.js')],{cwd:root,env:environment,stdio:['ignore','ignore','inherit']});assert.equal(await controls.waitForChild(child,{timeoutMs:170000}),0,'genuine setup child must finish');}
 finally{await children.cleanup();}
}
function validateConfiguration(configuration,manifest,port){
 const expected=[];assert.equal(manifest.length,16);
 for(const row of manifest)for(const [key,role]of [[row.runtimeVariable,row.runtimeRole],[row.migrationVariable,'dvaia_'+row.schema+'_migration']])expected.push([key,role,'dvaia_'+row.schema]);
 expected.push(['CTF_DELIVERY_DATABASE_URL','dvaia_ctf_delivery','dvaia_ctf']);
 assert.deepEqual(Object.keys(configuration).sort(),expected.map(r=>r[0]).sort());
 for(const [key,role,database]of expected){const u=new URL(configuration[key]);assert.equal(u.protocol,'postgresql:');assert.equal(u.hostname,'127.0.0.1');assert.equal(u.port,String(port));assert.equal(u.pathname,'/'+database);assert.equal(decodeURIComponent(u.username),role);assert.ok(u.password);assert.equal(u.search,'');assert.equal(u.hash,'');}
 return configuration;
}
async function readResult(file){
 const h=await fs.open(file,require('node:fs').constants.O_RDONLY|require('node:fs').constants.O_NOFOLLOW);
 try{const before=await h.stat();assert(before.isFile());assert.equal(before.uid,process.getuid());assert.equal(before.mode&0o777,0o600);assert.equal(before.nlink,1);assert(before.size<=65536);
  const buffer=Buffer.alloc(65537);let length=0;while(length<buffer.length){const {bytesRead}=await h.read(buffer,length,buffer.length-length,length);if(!bytesRead)break;length+=bytesRead;}
  const after=await h.stat(),linked=await fs.lstat(file);assert(length<=65536);assert.equal(length,before.size);
  for(const key of ['dev','ino','size','mtimeMs','ctimeMs','uid','mode','nlink']){assert.equal(after[key],before[key]);assert.equal(linked[key],before[key]);}assert(!linked.isSymbolicLink());
  return JSON.parse(buffer.subarray(0,length).toString('utf8'));
 }finally{await h.close();}
}
module.exports={prepare,runOwnedSetup,validateConfiguration,readResult};

async function main(){
 const owned=require('./mainBackendAuthAdmission').admit(process.env,{nativePid:process.ppid});
 const admin=new URL(process.env.PG_ADMIN_DATABASE_URL);assert.equal(admin.protocol,'postgresql:');assert.equal(admin.hostname,'127.0.0.1');assert.equal(admin.port,String(owned.port));assert.equal(admin.pathname,'/postgres');assert.equal(admin.username,'postgres');assert.equal(admin.password,'');assert.equal(admin.search,'');assert.equal(admin.hash,'');
 const result=await prepare({owned,adminUrl:admin.href,environment:{PATH:process.env.PATH,HOME:owned.root,LOGS_DIR:path.join(owned.evidence,'setup-logs'),LEGACY_SENSITIVE_FILES_ROOT:path.join(owned.evidence,'setup-sensitive'),NODE_ENV:'test',PG_TLS:'disable',PLATFORM_DATABASE_ENGINE:'postgres',WORKSHOP_DATABASE_ENGINE:'postgres',DVAIA_APP_DATA_ROOT:owned.appData,MCP_SIDECARS_AUTOSTART:'false',MCP_WORKSHOP_AUTOSTART:'false',AI_PROVIDER:'mock'}});
 const handle=await fs.open(path.join(owned.appData,'setup-result.json'),'wx',0o600);try{await handle.writeFile(JSON.stringify(result));await handle.sync();}finally{await handle.close();}
}
if(require.main===module)main().catch(()=>{console.error(JSON.stringify({code:'OWNED_CTF_SETUP_FAILED'}));process.exitCode=1;});
