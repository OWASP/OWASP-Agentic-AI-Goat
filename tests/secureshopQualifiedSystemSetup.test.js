'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),os=require('node:os');
const helper=require('../scripts/install/secureshop-qualified-system-setup');
const config=require('../server/services/secureshopQualifiedManagedConfiguration');
const curriculum=require('../server/config/secureshopCurriculum');
const repo=path.resolve(__dirname,'..');
function fixture(t){const home=fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(),'qualified-system-')));t.after(()=>fs.rmSync(home,{recursive:true,force:true}));const root=path.join(home,'source');fs.mkdirSync(root);const directory=path.dirname(config.managedPath(root,home));fs.mkdirSync(directory,{recursive:true,mode:0o700});return{root,homeDirectory:home,home,directory,file:config.managedPath(root,home)};}
function ready(){return{exitCode:0,stdout:'SECURESHOP_ACTIVATION_QUALIFICATION='+JSON.stringify({ready:true,objectiveIds:curriculum.OBJECTIVES.map(r=>r.id),structuralPanels:curriculum.EXERCISES.map(r=>r.id)})+'\n'};}
test('fresh explicit combined setup stages disabled, validates captured candidate, then activates System; repeat preserves inode',async t=>{
 const f=fixture(t);let probes=0,systems=0;
 const run=async(file,args)=>{probes++;assert.deepEqual(args,['scripts/qualify-secureshop-qualified-activation.js','--candidate-readiness']);const candidate=config.load({root:f.root,home:f.home,file:path.join(f.directory,'secureshop-qualified.candidate.env')});assert.equal(candidate.SS_BOUND_REVIEWS_ENABLED,'true');if(probes===1)assert.equal(config.load(f).SS_BOUND_REVIEWS_ENABLED,'false');return ready();};
 const activateSystem=async options=>{systems++;assert.equal(config.load(f).SS_BOUND_REVIEWS_ENABLED,'true');assert.equal(options.applicationEnvironment.SS_PERSONA_INBOX_READY,'true');assert.equal(options.applicationEnvironment.SS_AUDIT_SUMMARY_ENABLED,undefined);return{activationEnabled:true};};
 await helper.prepare({...f,ensureAuthority:async()=>{},run,activateSystem,applicationEnvironment:{}});const before=fs.readFileSync(f.file),inode=fs.statSync(f.file).ino;
 await helper.prepare({...f,ensureAuthority:async()=>{},run,activateSystem,applicationEnvironment:{}});assert.equal(probes,2);assert.equal(systems,2);assert.equal(fs.statSync(f.file).ino,inode);assert.deepEqual(fs.readFileSync(f.file),before);assert.ok(!fs.existsSync(path.join(f.directory,'secureshop-qualified.candidate.env')));
});
test('candidate or real readiness failure never activates; System failure restores only newly-published flags',async t=>{
 for(const failure of ['probe','candidate','system']){const f=fixture(t);let systems=0;
  await assert.rejects(helper.prepare({...f,ensureAuthority:async()=>{},applicationEnvironment:{},run:async()=>{if(failure==='probe')return{exitCode:1,stdout:''};if(failure==='candidate')fs.appendFileSync(path.join(f.directory,'secureshop-qualified.candidate.env'),'# drift\n');return ready();},activateSystem:async()=>{systems++;throw Error('unavailable');}}));
  assert.equal(config.load(f).SS_BOUND_REVIEWS_ENABLED,'false');assert.equal(systems,failure==='system'?1:0);
 }
});
test('concurrent record drift is never overwritten on publication or recovery',async t=>{
 const f=fixture(t);const changed=Buffer.from('instructor-owned-drift\n');
 await assert.rejects(helper.prepare({...f,ensureAuthority:async()=>{},applicationEnvironment:{},run:async()=>{fs.writeFileSync(f.file,changed);return ready();},activateSystem:async()=>assert.fail('not admitted')}),{code:'SYSTEM_QUALIFIED_CONFLICT'});assert.deepEqual(fs.readFileSync(f.file),changed);
});
test('existing enabled flags survive a later System failure and malformed readiness receipt is rejected',async t=>{
 const f=fixture(t);await helper.prepare({...f,ensureAuthority:async()=>{},applicationEnvironment:{},run:async()=>ready(),activateSystem:async()=>({activationEnabled:true})});const bytes=fs.readFileSync(f.file);
 await assert.rejects(helper.prepare({...f,ensureAuthority:async()=>{},applicationEnvironment:{},run:async()=>ready(),activateSystem:async()=>{throw Error('failed');}}));assert.deepEqual(fs.readFileSync(f.file),bytes);
 await assert.rejects(helper.prepare({...f,ensureAuthority:async()=>{},applicationEnvironment:{},run:async()=>({exitCode:0,stdout:'SECURESHOP_ACTIVATION_QUALIFICATION={"ready":true}'}),activateSystem:async()=>assert.fail('not admitted')}),{code:'SYSTEM_QUALIFIED_READINESS_FAILED'});
});
test('early profile prerequisite checks are read-only and require explicit local authority and ARM64',async t=>{
 const f=fixture(t);const before=fs.readdirSync(f.directory);let checks=0,calls=0;
 const options={root:repo,home:f.home,architecture:'arm64',platform:'darwin',environment:{DOCKER_HOST:'unix:///tmp/owned.sock'},run:async()=>{calls++;return{exitCode:0,stdout:'"owned-daemon"'};},verifyProfile:async()=>{checks++;throw Object.assign(Error('missing'),{code:'SYSTEM_INSTALL_PROFILE_UNAVAILABLE'});}};
 await assert.rejects(helper.preflight(options),{code:'SYSTEM_INSTALL_PROFILE_UNAVAILABLE'});assert.equal(checks,1);assert.equal(calls,1);assert.deepEqual(fs.readdirSync(f.directory),before);
 await assert.rejects(helper.preflight({...options,architecture:'x64'}),{code:'SYSTEM_INSTALL_PLATFORM_UNQUALIFIED'});assert.equal(calls,1);
 await assert.rejects(helper.preflight({...options,environment:{}}),{code:'SYSTEM_INSTALL_AUTHORITY_REQUIRED'});
});
test('combined setup preflight failure occurs before fresh writes, dependency work or database calls',async t=>{
 const f=fixture(t);let work=0,preflights=0;const before=fs.readdirSync(f.root);
 await assert.rejects(require('../scripts/setup-application').setup({root:f.root,homeDirectory:f.home,ownedSystem:true,qualifiedSecureShop:true,preflightQualifiedSystem:async()=>{preflights++;throw Object.assign(Error('profile missing'),{code:'SYSTEM_INSTALL_PROFILE_UNAVAILABLE'});},runCommand:async()=>work++,execute:async()=>work++,provisionDelivery:async()=>({configuration:{CTF_DELIVERY_DATABASE_URL:'postgresql://dvaia_ctf_delivery:synthetic@localhost/dvaia_ctf'}}),provision:async()=>work++}),{code:'SYSTEM_INSTALL_PROFILE_UNAVAILABLE'});
 assert.equal(preflights,1);assert.equal(work,0);assert.deepEqual(fs.readdirSync(f.root),before);
 await assert.rejects(require('../scripts/setup-application').setup({root:f.root,homeDirectory:f.home,qualifiedSecureShop:true}),{code:'SYSTEM_COMBINED_OPT_IN_REQUIRED'});
});

// Controlled current database-phase dispatch: no process, socket or database.
async function controlledSetup(setupModule, options) {
 const authority=require('../scripts/install/ctf-authority-setup'),original=authority.prepareCtfAuthority;
 authority.prepareCtfAuthority=async({maintenanceScope,environment})=>{require('../scripts/lib/application-maintenance-scope').assertApplicationMaintenanceScope(maintenanceScope,environment);return {state:'active',trafficStarted:false};};
 try{return await setupModule.setup({...options,runDatabasePhase:async(request,dependencies)=>{
  const before={...process.env},environment=require('../scripts/install/setup-database-phase').validateRequest(request);Object.assign(process.env,environment);let publish;
  try{return await require('../scripts/lib/application-maintenance-scope').withApplicationMaintenanceScope({environment,acquire:async()=>({assertHeld(){},async beginMaintenance(){return Object.freeze({epoch:'1'});},async finishMaintenance(){},async close(){}}),drain:async()=>{},afterDrain:async()=>publish()},scope=>setupModule.executeSetupDatabasePhase(request,scope,{...dependencies,runCommand:options.runCommand,initializeApplication:async()=>options.runCommand(process.execPath,['controlled-scoped-initializer']),deferPublication:callback=>{publish=callback;}}));}
  finally{for(const key of Object.keys(process.env))if(!(key in before))delete process.env[key];Object.assign(process.env,before);}
 }});}finally{authority.prepareCtfAuthority=original;}
}

test('fresh setup wires combined helper after schema/seed, preserves generated private credentials on System failure',async t=>{
 const setupModule=require('../scripts/setup-application');const postgres=require('../server/database/postgres'),bootstrap=require('../db/postgres/bootstrap-admin');const originalPool=postgres.createPool,originalBootstrap=bootstrap.bootstrapAdmin;
 try{
  postgres.createPool=()=>({end:async()=>{}});bootstrap.bootstrapAdmin=async()=>{};
  for(const failure of [false,true]){
   const f=fixture(t),order=[];const dependencies=Object.fromEntries(setupModule.REQUIRED_INSTALLED_COMPONENTS.map((name,i)=>[name,`1.2.${i}`]));fs.writeFileSync(path.join(f.root,'package.json'),JSON.stringify({dependencies}));
   for(const [name,version]of Object.entries(dependencies)){const d=path.join(f.root,'node_modules',name);fs.mkdirSync(d,{recursive:true});fs.writeFileSync(path.join(d,'package.json'),JSON.stringify({name,version,main:'index.js'}));fs.writeFileSync(path.join(d,'index.js'),'module.exports={}');if(name==='@modelcontextprotocol/sdk'){fs.mkdirSync(path.join(d,'server'));fs.writeFileSync(path.join(d,'server/index.js'),'module.exports={}');}}
   const options={root:f.root,homeDirectory:f.home,install:false,ensureModel:false,ownedSystem:true,ownedAnalytics:true,qualifiedSecureShop:true,adminUrl:'postgresql://controlled.invalid/postgres',
    processEnvironment:{MCP_SIDECARS_AUTOSTART:'false',MCP_WORKSHOP_AUTOSTART:'false',IPI_EMAIL_PROVIDER:'gmail'},
    preflightQualifiedSystem:async()=>{assert.ok(!fs.existsSync(path.join(f.root,'.env')));order.push('preflight');},
    loadProductRenderer: () => ({ componentId: 'SecureShop.Product.Description', sourceSha256: 'a'.repeat(64), artifactSha256: 'b'.repeat(64), renderProductDescription: async product => `<div>${product.description_html}</div>` }), loadMailRenderer: () => ({ component: { id: 'SecureShop.MailMessageBody', sourceSha256: 'a'.repeat(64), artifactSha256: 'b'.repeat(64) } }),
      loadRenderer:()=>({sourceSha256:'source',artifactSha256:'artifact',renderReviewCard:async({body})=>`<article>${body}</article>`}),loadPuppeteer:()=>({launch:async()=>({close:async()=>{}})}),
    provisionDelivery:async()=>({configuration:{CTF_DELIVERY_DATABASE_URL:'postgresql://dvaia_ctf_delivery:synthetic@localhost/dvaia_ctf'}}),provision:async()=>({configuration:{IDENTITY_DATABASE_URL:'postgresql://controlled.invalid/identity',IDENTITY_MIGRATION_DATABASE_URL:'postgresql://controlled.invalid/identity'}}),provisionOwnedRunner:async()=>({available:false}),
    runCommand:async(_file,args)=>{if(args[0]==='controlled-scoped-initializer')order.push('schema');if(args[0]==='server/database/sensitiveInfoFiles.js')order.push('seed');},
    setupOwnedMcpRegistry:async args=>{assert.equal(args.requested,true);assert.equal(args.upgrade,false);assert.equal(args.applicationEnvironment.SS_BOUND_REVIEWS_ENABLED,'true');assert.ok(fs.existsSync(path.join(f.directory,'administrator.json')));require('../scripts/lib/application-maintenance-scope').assertApplicationMaintenanceScope(args.maintenanceScope,process.env);order.push('registry');return{requested:true,activationEnabled:true};},
    setupOwnedAnalytics:async args=>{assert.equal(args.requested,true);assert.equal(args.applicationEnvironment.SS_BOUND_REVIEWS_ENABLED,'true');assert.ok(fs.existsSync(path.join(f.directory,'administrator.json')));order.push('analytics');return{requested:true,activationEnabled:true};},
    setupOwnedCoupons:async args=>{assert.equal(args.requested,true);assert.equal(args.applicationEnvironment.SS_BOUND_REVIEWS_ENABLED,'true');order.push('coupons');return{requested:true,activationEnabled:true};},
    prepareQualifiedSystem:async args=>helper.prepare({...args,ensureAuthority:async()=>{},run:async()=>{order.push('qualified');assert.ok(!fs.existsSync(path.join(f.root,'.env')));return ready();},activateSystem:async()=>{order.push('system');if(failure)throw Object.assign(Error('controlled System failure'),{code:'CONTROLLED_SYSTEM_FAILURE'});return{activationEnabled:true};}})};
   if(failure)await assert.rejects(controlledSetup(setupModule,options),error=>error.code==='APPLICATION_INITIALIZATION_REQUIRES_EXIT'&&error.errors.some(cause=>cause.code==='CONTROLLED_SYSTEM_FAILURE'));else assert.equal((await controlledSetup(setupModule,options)).system.activationEnabled,true);
   assert.deepEqual(order,failure?['preflight','schema','seed','qualified','system']:['preflight','schema','seed','qualified','system','analytics','coupons','registry']);assert.ok(fs.existsSync(path.join(f.directory,'administrator.json')));assert.ok(fs.existsSync(path.join(f.directory,'secureshop-reset-key.json')));assert.equal(fs.existsSync(path.join(f.root,'.env')),!failure);const privateEnv=failure?'':fs.readFileSync(path.join(f.root,'.env'),'utf8');assert.ok(!privateEnv.includes('SS_SYSTEM_CONFIG_TOKEN'));assert.ok(!privateEnv.includes('SS_SYSTEM_DIAGNOSTIC_TOKEN'));assert.equal(config.load(f).SS_BOUND_REVIEWS_ENABLED,failure?'false':'true');
  }
 }finally{postgres.createPool=originalPool;bootstrap.bootstrapAdmin=originalBootstrap;}
});

test('readiness uses exact current qualified catalog identities, not stale numerical totals, without enabling objectives',()=>{
 const {assertCurriculumDefinition}=require('../scripts/qualify-secureshop-qualified-activation');assert.doesNotThrow(()=>assertCurriculumDefinition());
 assert.throws(()=>assertCurriculumDefinition({...curriculum,QUALIFIED_OBJECTIVE_IDS:curriculum.QUALIFIED_OBJECTIVE_IDS.slice(1)}));
 assert.throws(()=>assertCurriculumDefinition({...curriculum,OBJECTIVES:curriculum.OBJECTIVES.map((r,i)=>i? r:{...r,defaultEnabled:true})}));
 assert.throws(()=>assertCurriculumDefinition({...curriculum,PENDING_OBJECTIVE_IDS:['unqualified']}));
});

test('fresh helper records only explicitly selected reverified Docker authority when ordinary sidecars were skipped',async t=>{
 const f=fixture(t);let daemonReads=0;
 await helper.prepare({...f,environment:{DOCKER_HOST:'unix:///tmp/owned-combined.sock'},applicationEnvironment:{},run:async(file,args)=>{if(file==='docker'){daemonReads++;assert.deepEqual(args,['--host','unix:///tmp/owned-combined.sock','info','--format','{{json .ID}}']);return{exitCode:0,stdout:'"owned-controlled-daemon"'};}return ready();},activateSystem:async()=>({activationEnabled:true})});
 const authority=JSON.parse(fs.readFileSync(path.join(f.directory,'local-docker.json')));assert.equal(authority.host,'unix:///tmp/owned-combined.sock');assert.equal(authority.daemonId,'owned-controlled-daemon');assert.ok(daemonReads>=1);assert.equal(fs.statSync(path.join(f.directory,'local-docker.json')).mode&0o777,0o600);
});

test('post-publication concurrent instructor edit survives failed System activation',async t=>{
 const f=fixture(t),changed=Buffer.from('instructor recovery reference\n');
 await assert.rejects(helper.prepare({...f,ensureAuthority:async()=>{},applicationEnvironment:{},run:async()=>ready(),activateSystem:async()=>{fs.writeFileSync(f.file,changed);throw Error('activation failed');}}),{code:'SYSTEM_QUALIFIED_CONFLICT'});
 assert.deepEqual(fs.readFileSync(f.file),changed);
 assert.equal(fs.existsSync(f.file+'.setup-lock'),false);
});
test('fixed candidate loader rejects links and replacement during descriptor read',async t=>{
 const f=fixture(t);await helper.prepare({...f,ensureAuthority:async()=>{},applicationEnvironment:{},run:async()=>{
  assert.equal(helper.loadCandidate({root:f.root,home:f.home}).SS_ENABLE,'true');
  const candidate=path.join(f.directory,'secureshop-qualified.candidate.env'),original=fs.readSync;
  try{fs.readSync=function(fd,...args){const n=original.call(fs,fd,...args);fs.renameSync(candidate,candidate+'.old');fs.copyFileSync(candidate+'.old',candidate);fs.chmodSync(candidate,0o600);return n;};assert.throws(()=>helper.loadCandidate({root:f.root,home:f.home}),{code:'SYSTEM_QUALIFIED_UNTRUSTED'});}finally{fs.readSync=original;fs.unlinkSync(candidate);fs.renameSync(candidate+'.old',candidate);}
  return ready();},activateSystem:async()=>({activationEnabled:true})});
});
test('explicit unrelated sidecar opt-out never invokes MCP provisioning',async()=>{
 const result=await require('../scripts/setup-application').provisionOwnedRunnerForSetup({root:repo,directory:'/tmp/unused',environment:{MCP_SIDECARS_AUTOSTART:'false'},provisionFromEnvironment:async()=>assert.fail('must not provision')});
 assert.equal(result.activationEnabled,false);assert.equal(result.code,'MCP_INSTALL_EXPLICITLY_DISABLED');
});
test('actual readiness child receives the same explicit private home used by prepare',async t=>{
 const f=fixture(t);fs.mkdirSync(path.join(f.root,'scripts'));
 const output=ready().stdout;
 fs.writeFileSync(path.join(f.root,'scripts/qualify-secureshop-qualified-activation.js'),`if(process.env.HOME!==${JSON.stringify(f.home)})process.exit(9);process.stdout.write(${JSON.stringify(output)});`);
 await helper.prepare({...f,ensureAuthority:async()=>{},environment:{PATH:process.env.PATH,HOME:'/wrong-controlled-home'},applicationEnvironment:{},activateSystem:async()=>({activationEnabled:true})});
 assert.equal(config.load(f).SS_BOUND_REVIEWS_ENABLED,'true');
});


test('activation validates the complete eligibility partition without promoting pending catalog rows',()=>{
 const {assertCurriculumDefinition,assertCatalogRows}=require('../scripts/qualify-secureshop-qualified-activation');
 const rows=curriculum.OBJECTIVES.map(row=>({objective_id:row.id,is_enabled:false,is_visible:false}));
 assert.doesNotThrow(()=>assertCatalogRows(rows));
 for(const mutation of [
  c=>c.QUALIFIED_OBJECTIVE_IDS.push(c.PENDING_OBJECTIVE_IDS[0]),
  c=>c.PENDING_OBJECTIVE_IDS.push(c.PENDING_OBJECTIVE_IDS[0]),
  c=>c.PENDING_OBJECTIVE_IDS.shift(),
  c=>c.OBJECTIVES[0].qualification='unknown',
  c=>c.CHALLENGE.defaultVisible=true,
 ]){const c={...curriculum,OBJECTIVES:curriculum.OBJECTIVES.map(r=>({...r})),QUALIFIED_OBJECTIVE_IDS:[...curriculum.QUALIFIED_OBJECTIVE_IDS],PENDING_OBJECTIVE_IDS:[...curriculum.PENDING_OBJECTIVE_IDS],CHALLENGE:{...curriculum.CHALLENGE}};mutation(c);assert.throws(()=>assertCurriculumDefinition(c));}
 for(const invalid of [rows.slice(1),[...rows,{objective_id:'extra',is_enabled:false}],rows.map((r,i)=>i===1?rows[0]:r),rows.map(r=>curriculum.PENDING_OBJECTIVE_IDS.includes(r.objective_id)?{...r,is_enabled:true}:r)])assert.throws(()=>assertCatalogRows(invalid));
 const instructor=rows.map(r=>({...r,is_visible:true,is_enabled:curriculum.QUALIFIED_OBJECTIVE_IDS.includes(r.objective_id),hint_enabled:true,solution_enabled:false}));
 const before=JSON.stringify(instructor);assert.doesNotThrow(()=>assertCatalogRows(instructor));assert.equal(JSON.stringify(instructor),before);
});
