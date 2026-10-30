'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs/promises'),os=require('node:os'),path=require('node:path'),{createHash,randomUUID}=require('node:crypto');
const {activate}=require('../scripts/install/analytics-activate');
const {setupOwnedAnalytics}=require('../scripts/install/analytics-setup');
const {readManagedAnalyticsConfiguration}=require('../server/services/secureshopAnalyticsManagedConfiguration');
async function fixture(work){
 const homeDirectory=await fs.mkdtemp(path.join(os.tmpdir(),'owasp-ai-goat-analytics-activation-')),root=path.join(homeDirectory,'source'),workspaceId=createHash('sha256').update(root).digest('hex').slice(0,12),name='owasp-ai-goat-analytics-'+workspaceId,directory=path.join(homeDirectory,'.owasp-ai-goat',workspaceId),filename=path.join(directory,'analytics-managed.json');
 const value={version:1,enabled:false,workspaceId,dockerAuthoritySha256:'a'.repeat(64),containerName:name,containerId:'b'.repeat(64),volumeName:name+'-data',imageId:'sha256:'+'c'.repeat(64),port:18096,password:'d'.repeat(64),ownerId:randomUUID(),identity:{systemIdentifier:'1234567890123456789',controlDatabase:'owasp_ai_goat_analytics_control_'+workspaceId,clusterName:'owasp-ai-goat-owned-analytics-'+workspaceId},controlSchemaSha256:'e'.repeat(64)};
 await fs.mkdir(directory,{recursive:true,mode:0o700});await fs.writeFile(filename,JSON.stringify(value)+'\n',{mode:0o600});
 try{const record=await readManagedAnalyticsConfiguration({root,homeDirectory});await work({root,homeDirectory,filename,value,expectedSha256:record.sha256});}finally{await fs.rm(homeDirectory,{recursive:true,force:true});}
}
test('activation preserves disabled preference; explicit activation awaits readiness and preserves credentials',()=>fixture(async options=>{
 let called=0;const assertReady=async()=>{called++;};
 assert.deepEqual(await activate({...options,assertReady}),{activationEnabled:false,changed:false});assert.equal(called,0);
 assert.deepEqual(await activate({...options,assertReady,explicit:true}),{activationEnabled:true,changed:true});assert.equal(called,1);
 const record=await readManagedAnalyticsConfiguration(options);assert.deepEqual(record.config,{...options.value,enabled:true});assert.equal((await fs.stat(options.filename)).mode&0o777,0o600);
 assert.deepEqual(await activate({...options,expectedSha256:record.sha256,assertReady}),{activationEnabled:true,changed:false});assert.equal(called,2);
}));
test('failed readiness preserves exact bytes and removes activation lock',()=>fixture(async options=>{
 const bytes=await fs.readFile(options.filename);
 await assert.rejects(activate({...options,fresh:true,assertReady:async()=>{throw Object.assign(Error('not ready'),{code:'NOT_READY'});}}),{code:'NOT_READY'});
 assert.deepEqual(await fs.readFile(options.filename),bytes);await assert.rejects(fs.stat(options.filename+'.activation-lock'),{code:'ENOENT'});
}));
test('concurrent private configuration change is preserved rather than overwritten',()=>fixture(async options=>{
 const changed={...options.value,port:18097};
 await assert.rejects(activate({...options,explicit:true,assertReady:async()=>{await fs.writeFile(options.filename,JSON.stringify(changed)+'\n');}}),{code:'ANALYTICS_ACTIVATION_CONFLICT'});
 assert.deepEqual(JSON.parse(await fs.readFile(options.filename,'utf8')),changed);
 assert.deepEqual((await fs.readdir(path.dirname(options.filename))).sort(),['analytics-managed.json']);
}));
test('setup checks both private runtime and application request schema before enabling, then closes both',()=>fixture(async options=>{
 const order=[],environment={SS_ENABLE:'true',SS_BOUND_REVIEWS_ENABLED:'true',PLATFORM_DATABASE_ENGINE:'postgres',WORKSHOP_DATABASE_ENGINE:'postgres',SECURESHOP_AGENTS_DATABASE_URL:'postgresql://fixture-only'};
 const dependencies={...options,requested:true,applicationEnvironment:environment,
  provisionService:async()=>({created:true,containerId:options.value.containerId}),
  loadRuntime:async()=>({assertReady:async()=>order.push('private'),close:async()=>order.push('runtime-close')}),
  makePool:input=>{assert.equal(input.max,1);return {end:async()=>order.push('pool-close')};},checkRequests:async()=>order.push('request-schema')};
 assert.deepEqual(await setupOwnedAnalytics(dependencies),{requested:true,activationEnabled:true,changed:true});
 assert.deepEqual(order,['private','request-schema','pool-close','runtime-close']);
}));
test('setup request-schema failure leaves private feature disabled and closes resources',()=>fixture(async options=>{
 let closed=0;const bytes=await fs.readFile(options.filename);
 await assert.rejects(setupOwnedAnalytics({...options,requested:true,applicationEnvironment:{SS_ENABLE:'true',SS_BOUND_REVIEWS_ENABLED:'true',PLATFORM_DATABASE_ENGINE:'postgres',WORKSHOP_DATABASE_ENGINE:'postgres',SECURESHOP_AGENTS_DATABASE_URL:'postgresql://fixture-only'},
  provisionService:async()=>({created:true,containerId:options.value.containerId}),loadRuntime:async()=>({assertReady:async()=>{},close:async()=>{closed++;}}),makePool:()=>({end:async()=>{closed++;}}),checkRequests:async()=>{throw Object.assign(Error('schema drift'),{code:'ANALYTICS_NOT_READY'});}}),{code:'ANALYTICS_NOT_READY'});
 assert.equal(closed,2);assert.deepEqual(await fs.readFile(options.filename),bytes);
}));
test('supported setup reports required Analytics upgrade before any provisioning',()=>fixture(async options=>{
 await fs.mkdir(options.root,{recursive:true});const root=await fs.realpath(options.root),workspaceId=createHash('sha256').update(root).digest('hex').slice(0,12),name='owasp-ai-goat-analytics-'+workspaceId;
 const directory=path.join(options.homeDirectory,'.owasp-ai-goat',workspaceId),filename=path.join(directory,'analytics-managed.json');await fs.mkdir(directory,{recursive:true,mode:0o700});
 const value={...options.value,workspaceId,containerName:name,volumeName:name+'-data',identity:{...options.value.identity,controlDatabase:'owasp_ai_goat_analytics_control_'+workspaceId,clusterName:'owasp-ai-goat-owned-analytics-'+workspaceId}};await fs.writeFile(filename,JSON.stringify(value)+'\n',{mode:0o600});const before=await fs.readFile(filename);let effects=0;
 await assert.rejects(require('../scripts/setup-application').setup({root,homeDirectory:options.homeDirectory,upgrade:true,nodeVersion:'26.10.0',provision:async()=>{effects++;}}),error=>error.code==='ANALYTICS_UPGRADE_FLAG_REQUIRED'&&error.message.includes('--upgrade --owned-analytics'));
 assert.equal(effects,0);assert.deepEqual(await fs.readFile(filename),before);
}));
