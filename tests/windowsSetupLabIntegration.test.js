'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');
const setupTools = require('../scripts/setup-application');
const host = () => ({schemaVersion:1,component:'windows-hyperv-host-preflight',nonMutating:true,hostSupported:true,minimumBuild:19045,allowedSkus:[4,27,48,49,70,72,84,121,122,125,126,129,130,161,162,164,165],capabilityEvidence:'running-hypervisor',blockers:[]});
const config = {IDENTITY_DATABASE_URL:'postgresql://runtime:synthetic@localhost/identity',IDENTITY_MIGRATION_DATABASE_URL:'postgresql://migration:synthetic@localhost/identity'};
async function fixture(t) {
  const container = await fs.mkdtemp(path.join(os.tmpdir(),'owasp-ai-goat-win-setup-lab-'));
  t.after(()=>fs.rm(container,{recursive:true,force:true}));
  const root=path.join(container,'workspace'),homeDirectory=path.join(container,'home');
  await fs.mkdir(root);await fs.mkdir(homeDirectory);return {root:await fs.realpath(root),homeDirectory:await fs.realpath(homeDirectory)};
}
function parentOptions(value,order) {
  const session={},ownLabChild=async()=>{};
  return {...value,platform:'win32',nodeVersion:'26.10.0',install:false,ensureModel:false,processEnvironment:{},observeWindowsHost:host,
    admitNpm:async()=>{order.push('npm');return {};},prepareRuntime:async()=>{order.push('runtime');return {browser:{}};},
    prepareWindowsLabInstallation:async args=>{order.push(`lab:${args.mode}`);return {session,ownLabChild,close:async()=>order.push('parent-close')};},
    setupLocalPostgres:async args=>{assert.equal(args.ownedLabSession,session);assert.equal(args.ownLabChild,ownLabChild);order.push('postgres');return 'postgresql://admin:synthetic@localhost/postgres';},
    setupLocalMailpit:async args=>{assert.equal(args.ownedLabSession,session);assert.equal(args.ownLabChild,ownLabChild);order.push('mailpit');return {};},
    provision:async()=>{order.push('provision');return {configuration:config};},
    runDatabasePhase:async(request)=>{require('../scripts/install/setup-database-phase').validateRequest(request);assert.ok(!Object.hasOwn(request.context,'ownedLabSession'));assert.ok(!Object.hasOwn(request.context,'ownLabChild'));order.push('phase');assert.ok(!order.includes('parent-close'));return {done:true};},
  };
}
test('Windows fresh setup gates runtime before guest preparation and retains PG/Mailpit ownership through closed phase dispatch',async t=>{
  const value=await fixture(t),order=[];assert.deepEqual(await setupTools.setup(parentOptions(value,order)),{done:true});
  assert.deepEqual(order,['npm','runtime','lab:fresh','postgres','mailpit','provision','phase','parent-close']);
});
test('Windows setup refuses overwrite or failed runtime before preparing a guest',async t=>{
  const value=await fixture(t),order=[],options=parentOptions(value,order);
  await fs.writeFile(path.join(value.root,'.env'),'KEEP=original\n');
  await assert.rejects(setupTools.setup(options),/will not overwrite/);assert.deepEqual(order,[]);
  await fs.unlink(path.join(value.root,'.env'));
  await assert.rejects(setupTools.setup({...options,prepareRuntime:async()=>{throw Error('controlled runtime failure');}}),/controlled runtime failure/);
  assert.deepEqual(order,['npm']);
});
test('Windows parent closes owned forwards when local provisioning or phase fails',async t=>{
  for(const failure of ['postgres','phase']) {
    const value=await fixture(t),order=[],options=parentOptions(value,order);
    if(failure==='postgres')options.setupLocalPostgres=async()=>{throw Error('controlled failure');};
    else options.runDatabasePhase=async()=>{throw Error('controlled failure');};
    await assert.rejects(setupTools.setup(options),/controlled failure/);assert.equal(order.at(-1),'parent-close');
    assert.equal(order.filter(x=>x==='parent-close').length,1);
  }
});
async function phase(t,{failBase=false,failHttp=false}={}) {
  const value=await fixture(t),order=[],id=setupTools.workspaceId(value.root),directory=path.join(value.homeDirectory,'.owasp-ai-goat',id);
  await fs.mkdir(directory,{recursive:true,mode:0o700});
  const context={...value,directory,id,envPath:path.join(value.root,'.env'),platform:'win32',databaseAdminUrl:'postgresql://admin:synthetic@localhost/postgres',config,appDataRoot:directory,processEnvironment:{IPI_EMAIL_PROVIDER:'gmail'},runtime:{browser:{}},requestedEmailProvider:'gmail'};
  const request={kind:'fresh',context};
  const env=require('../scripts/install/setup-database-phase').validateRequest(request),before={...process.env};Object.assign(process.env,env);
  const postgres=require('../server/database/postgres'),bootstrap=require('../db/postgres/bootstrap-admin'),ctf=require('../scripts/install/ctf-authority-setup');
  const originals=[postgres.createPool,bootstrap.bootstrapAdmin,ctf.prepareCtfAuthority];
  postgres.createPool=()=>({end:async()=>{}});bootstrap.bootstrapAdmin=async()=>{};ctf.prepareCtfAuthority=async()=>{};
  const session={openLoopbackForwards:async(ports,{ownChild})=>{assert.equal(ownChild,ownLabChild);assert.deepEqual(ports,[8092,8093,8094].map(port=>({local:port,guest:port})));order.push('protected-forwards');}},ownLabChild=async()=>{};
  let publication;
  const dependencies={prepareWindowsLabInstallation:async args=>{assert.equal(args.mode,'existing');assert.equal(args.root,value.root);order.push('child-lab');return {session,ownLabChild,close:async()=>order.push('child-close')};},
    provisionBaseLabServices:async args=>{assert.equal(args.session,session);assert.equal(args.ownLabChild,ownLabChild);assert.equal(args.mode,'fresh');order.push('base');if(failBase)throw Object.assign(Error('controlled base failure'),{code:'BASE_FAILED'});},
    provisionDelivery:async()=>({configuration:{CTF_DELIVERY_DATABASE_URL:'postgresql://dvaia_ctf_delivery:synthetic@localhost/owasp_ai_goat_ctf'}}),
    initializeApplication:async({maintenanceScope})=>{maintenanceScope.assertHeld();order.push('initialize');},runCommand:async()=>{},
    provisionOwnedRunner:async args=>{assert.equal(args.ownedLabSession,session);order.push('runner');return {ok:true,profile:'owasp-ai-goat-mcp-sandbox',activationEnabled:true,managedPath:args.managedPath};},
    provisionOwnedHttp:async args=>{assert.equal(args.ownedLabSession,session);order.push('http');if(failHttp)throw Error('controlled HTTP failure');return {available:true,activationEnabled:true};},
    provisionOwnedShadow:async args=>{assert.equal(args.ownedLabSession,session);order.push('shadow');return {available:true,activationEnabled:true};},
    provisionAuditSql:async args=>{assert.equal(args.ownedLabSession,session);assert.equal(args.ownLabChild,ownLabChild);order.push('audit');return {candidateOnly:true};},
    prepareUploadAssetEnvironment:async()=>({configuration:{},additions:{}}),
    deferPublication:callback=>{order.push('defer');publication=callback;},
  };
  const messages=[],originalLog=console.log;
  console.log=(...args)=>{messages.push(args.map(String).join(' '));};
  try {
    const work=require('../scripts/lib/application-maintenance-scope').withApplicationMaintenanceScope({environment:env,acquire:async()=>({assertHeld(){},beginMaintenance:async()=>({epoch:'1'}),finishMaintenance:async()=>{},close:async()=>order.push('lease-close')}),drain:async()=>order.push('drain'),afterDrain:async()=>{assert.equal(order.indexOf('child-close')<order.indexOf('drain'),true);order.push('publish');await publication();}},scope=>setupTools.executeSetupDatabasePhase(request,scope,dependencies));
    if(failBase||failHttp)await assert.rejects(work,e=>e.code==='APPLICATION_INITIALIZATION_REQUIRES_EXIT');else await work;
    return {order,envPath:context.envPath,messages};
  } finally { console.log=originalLog;[postgres.createPool,bootstrap.bootstrapAdmin,ctf.prepareCtfAuthority]=originals;for(const key of Object.keys(process.env))if(!(key in before))delete process.env[key];Object.assign(process.env,before); }
}
test('owned Windows database phase reconstructs its session, stages base then protected services, and closes before drain/publication',async t=>{
  const {order,envPath,messages}=await phase(t);assert.deepEqual(order,['child-lab','base','protected-forwards','initialize','runner','http','shadow','audit','defer','child-close','drain','publish','lease-close']);assert.ok((await fs.readFile(envPath,'utf8')).includes('PLATFORM_DATABASE_ENGINE'));
  assert.ok(messages.some(message=>message.includes('Start with powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File scripts/install/Windows/start_all.ps1.')));
});
test('owned Windows database phase cleans forwards and never publishes on base or protected readiness failure',async t=>{
  for(const failure of ['base','http']){const {order,envPath}=await phase(t,{failBase:failure==='base',failHttp:failure==='http'});assert.ok(order.includes('child-close'));assert.ok(!order.includes('publish'));assert.ok(!order.includes('defer'));if(failure==='base')assert.ok(!order.includes('initialize'));await assert.rejects(fs.stat(envPath),{code:'ENOENT'});}
});
test('Windows repair and additive upgrade admit only the retained guest and preserve existing configuration',async t=>{
  for(const repair of [false,true]) {
    const value=await fixture(t),order=[],options=parentOptions(value,order);
    const plan=require('../db/postgres/provision-application').provisioningPlan();
    const configuration=Object.fromEntries(plan.flatMap(row=>[[row.runtimeVariable,`postgresql://${row.runtimeRole}:synthetic@localhost/${row.database}`],[row.migrationVariable,`postgresql://${row.migrationRole}:synthetic@localhost/${row.database}`]]));
    const directory=path.join(value.homeDirectory,'.owasp-ai-goat',setupTools.workspaceId(value.root));await fs.mkdir(directory,{recursive:true,mode:0o700});
    const original=Buffer.from(setupTools.encodeEnv({...configuration,RETAINED_VALUE:'unchanged'}));await fs.writeFile(path.join(value.root,'.env'),original,{mode:0o600});
    await fs.writeFile(path.join(directory,'provisioning.json'),JSON.stringify({version:1,status:'complete',plan,configuration,created:[]}),{mode:0o600});
    options.setupLocalPostgres=async args=>{assert.equal(args.existingOnly,true);assert.equal(args.environment.RETAINED_VALUE,'unchanged');order.push('postgres-existing');return 'postgresql://admin:synthetic@localhost/postgres';};
    await setupTools.setup({...options,upgrade:true,repair});
    assert.deepEqual(order,repair?['npm','runtime','lab:existing','postgres-existing','phase','parent-close']:['lab:existing','postgres-existing','phase','parent-close']);assert.deepEqual(await fs.readFile(path.join(value.root,'.env')),original);
    await fs.writeFile(path.join(value.root,'.env.upgrade'),'uncertain',{mode:0o600});order.length=0;
    await assert.rejects(setupTools.setup({...options,upgrade:true,repair}),{code:'UPGRADE_ENV_RECOVERY_REQUIRED'});assert.deepEqual(order,[]);
  }
});
