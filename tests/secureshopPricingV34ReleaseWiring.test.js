'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const path = require('node:path');
const { isAssessmentReleaseAllowed, RELEASE_EXCLUDED_OBJECTIVE_IDS } = require('../server/config/secureshopCurriculum');

const source = readFileSync(path.join(__dirname, 'postgres/secureshopStandalonePricingRendered.integration.test.js'), 'utf8');
const objective = 'ss_pricing_false_grounding';

const fs=require('node:fs'),os=require('node:os'),crypto=require('node:crypto');
const {spawnSync}=require('node:child_process');
const root=path.resolve(__dirname,'..');
const python='/opt/homebrew/Cellar/python@3.14/3.14.6/Frameworks/Python.framework/Versions/3.14/bin/python3.14';

function lifecycleControls(){
 const start=source.indexOf('function observeV34BrowserLifecycle('),end=source.indexOf('async function qualifyPricingChatBrowser(',start);
 assert(start>0&&end>start);
 return new Function('createHash',source.slice(start,end)+'\nreturn {observeV34BrowserLifecycle,retainV34BrowserLifecycle};')(crypto.createHash);
}
function lifecycleBrowser(){
 const {EventEmitter}=require('node:events');
 const child=new EventEmitter();Object.assign(child,{pid:12345,exitCode:null,signalCode:null,
  spawnargs:['/private/browser','--headless=new','--user-data-dir=/private/secret-profile',
   '--password=secret-password','https://user:secret-token@example.invalid/?token=secret-query']});
 const browser=new EventEmitter();browser.process=()=>child;browser.connected=true;
 const page=new EventEmitter();page.closed=false;page.isClosed=()=>page.closed;
 return {browser,child,page};
}
test('V34 lifecycle observer bounds and redacts actual event shapes without closing targets',async()=>{
 const {observeV34BrowserLifecycle,retainV34BrowserLifecycle}=lifecycleControls();
 const {browser,child,page}=lifecycleBrowser(),observer=observeV34BrowserLifecycle(browser),saved=[];
 observer.mark('page-create');observer.watchPage(page);
 browser.emit('targetcreated',{type:()=> 'page',url:()=>assert.fail('No URL collection'),page:()=>assert.fail('No target access')});
 observer.mark('viewport');page.closed=true;page.emit('close');page.emit('error',Error('secret error payload'));
 browser.emit('targetdestroyed',{type:()=> 'page'});browser.connected=false;browser.emit('disconnected');
 child.exitCode=137;child.signalCode='SIGKILL';child.emit('exit',137,'SIGKILL');
 await retainV34BrowserLifecycle({captureRole:async value=>saved.push(value)},observer,'failure-lifecycle');
 const before=saved[0].lifecycle;
 assert.equal(before.stage,'viewport');assert.equal(before.current.connected,false);
 assert.equal(before.current.pageClosed,true);assert.equal(before.current.processSignal,'SIGKILL');
 assert.deepEqual(before.events.map(row=>row.kind),['target-created','page-close','page-error','target-destroyed','browser-disconnected','process-exit']);
 assert.deepEqual(before.launch.safeFlagNames,['--headless','--user-data-dir']);
 assert.equal(before.launch.argvSha256,crypto.createHash('sha256').update(JSON.stringify(child.spawnargs)).digest('hex'));
 assert.doesNotMatch(JSON.stringify(before),/secret|example\.invalid|private\/browser|password|token/);
 observer.mark('fixture-cleanup');child.emit('close',137,'SIGKILL');
 for(let i=0;i<100;i++)browser.emit('targetdestroyed',{type:()=> 'secret type'});
 const after=observer.snapshot();assert.equal(after.events.length,32);assert.equal(after.dropped,75);
 assert.equal(after.events[6].stage,'fixture-cleanup');assert.equal(before.events.length,6);
 assert.equal(after.events[7].type,'unknown');
 observer.dispose();for(const emitter of [browser,child,page])assert.equal(emitter.eventNames().length,0);
 await retainV34BrowserLifecycle({captureRole:async()=>{throw Error('observer persistence failure');}},observer,'failure-lifecycle');
 await retainV34BrowserLifecycle({captureRole:async()=>assert.fail('broken observer')},{snapshot(){throw Error('observer failure');}},'failure-lifecycle');
});
test('actual V34 startup slice retains precise failing stage with no page retry or changed admission order',async()=>{
 const {observeV34BrowserLifecycle,retainV34BrowserLifecycle}=lifecycleControls();
 const start=source.indexOf("  browserLifecycle?.mark('browser-admission');"),end=source.indexOf('  if(v34||v34Preflight){const mouseClick',start);
 assert(start>0&&end>start);
 const AsyncFunction=Object.getPrototypeOf(async function(){}).constructor;
 const startup=new AsyncFunction('browser','browserLifecycle','retainedAdmission','profile','require',
  'let page;\n'+source.slice(start,end)+'\nreturn page;');
 for(const fault of ['none','admission','page-create','viewport']){
  const {browser,child,page}=lifecycleBrowser(),observer=observeV34BrowserLifecycle(browser),order=[],saved=[];
  const primary=Error('original controlled failure');let pages=0,viewports=0;
  browser.newPage=async()=>{order.push('page-create');pages++;if(fault==='page-create'){browser.connected=false;browser.emit('disconnected');throw primary;}return page;};
  page.setViewport=async value=>{order.push('viewport');viewports++;assert.deepEqual(value,{width:1280,height:900});
   if(fault==='viewport'){browser.emit('targetdestroyed',{type:()=> 'page'});child.emit('exit',1,null);throw primary;}};
  const requireControlled=key=>{assert.equal(key,'../fixtures/secureshopPricingRenderedBrowser');return {admitV34Browser:async(b,p,a)=>{
   order.push('admission');assert.equal(b,browser);assert.equal(p,'controlled-profile');assert.equal(a,true);if(fault==='admission')throw primary;}};};
  try{assert.equal(await startup(browser,observer,true,'controlled-profile',requireControlled),page);assert.equal(fault,'none');}
  catch(error){assert.equal(error,primary);await retainV34BrowserLifecycle({captureRole:async row=>saved.push(row)},observer,'failure-lifecycle');
   assert.equal(saved[0].lifecycle.stage,fault==='admission'?'browser-admission':fault);}
  assert.equal(pages,fault==='admission'?0:1);assert.equal(viewports,['admission','page-create'].includes(fault)?0:1);
  assert.deepEqual(order,['admission','page-create','viewport'].slice(0,fault==='admission'?1:fault==='page-create'?2:3));
  observer.dispose();
 }
 const catchStart=source.indexOf(" }catch(error){\n  await retainV34BrowserLifecycle(v34,browserLifecycle,'failure-lifecycle');");
 assert(catchStart>0);assert(source.indexOf('if((v34||v34Preflight)&&page)',catchStart)>catchStart);
});

// Real OS FIFO + pinned Node's real test runner. Only the browser birth probe
// is controlled; no Chrome, service, model or network operation is launched.
function grantControl(fault='none',browser=false){
 const runId=crypto.randomBytes(16).toString('hex'),owner=path.join(root,'tasks/qualification','pricing-private-'+runId);
 fs.mkdirSync(owner,{mode:0o700});const cohort=path.join(owner,'cohort'),directory=path.join(cohort,'browser');
 fs.mkdirSync(cohort,{mode:0o700});fs.mkdirSync(directory,{mode:0o700});fs.mkdirSync(path.join(directory,'tmp'),{mode:0o700});
 const descriptorPath=path.join(cohort,'private-executor.json');fs.writeFileSync(descriptorPath,'{"controlled":true}',{mode:0o600});
 const evidence=path.join(directory,'merchant-pricing-v34-manual-experiment-browser.json');
 const fixture=path.join(owner,'inherited.test.cjs');
 const entry=source.slice(source.indexOf('  const workspace=path.resolve'),source.indexOf("  const build=path.resolve"));
 const launchStart=source.indexOf(" const browser=await require('puppeteer').launch("),launchEnd=source.indexOf(' let browserLifecycle=null;',launchStart);
 assert(launchStart>0&&launchEnd>launchStart);
 const launchSource=source.slice(launchStart,launchEnd);
 const program=`const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const helper=require(${JSON.stringify(path.join(root,'tests/fixtures/secureshopPricingRenderedBrowser.js'))});
test('actual V34 grant and entry',async()=>{
const PRICING_V34=true,V34_TRANSITION_PREFLIGHT=false,PRICING_V54=false,PRICING_CHAT=false,PRICING_COMPARE_CHAT=false,PRICING_FIXED_RESET=false,PRICING_HISTORY=false,PRICING_EXPERIMENT=false;
const requireOriginal=module.require.bind(module);const require=key=>key==='../fixtures/secureshopPricingRenderedBrowser'?helper:requireOriginal(key);
const pause=()=>Atomics.wait(new Int32Array(new SharedArrayBuffer(4)),0,0,350);
if(${JSON.stringify(fault)}==='startup-delay')pause();
if(${JSON.stringify(fault)}==='read-delay'){const read=fs.readSync;let delayed=false;fs.readSync=(fd,...args)=>{if(!delayed&&fd===Number(process.env.SECURESHOP_PRICING_V34_ADMISSION_FD)){delayed=true;pause();}return read(fd,...args);};}
if(${JSON.stringify(fault)}==='validation-delay'){const realpath=fs.realpathSync;let delayed=false;fs.realpathSync=(...args)=>{if(!delayed){delayed=true;pause();}return realpath(...args);};}
if(${JSON.stringify(fault)}==='close'){const close=fs.closeSync;fs.closeSync=fd=>{if(fd===Number(process.env.SECURESHOP_PRICING_V34_ADMISSION_FD))throw Error('controlled unjoined close');return close(fd);};}
${entry}
console.log('CONTROL_ADMISSION_RETURNED');
assert(retainedAdmission);assert(helper.retainedV34Remaining(retainedAdmission)>0);
assert.throws(()=>helper.readV34RetainedAdmission({workspace,descriptorPath,evidence}));
assert.throws(()=>helper.retainedV34Remaining({...retainedAdmission}));
// Execute the exact launch expression with a real inherited admission, while
// substituting only Puppeteer's launch edge (no Chrome or CDP connection).
const capturedOptions=[];
const launch=requireOriginal('node:vm').compileFunction(${JSON.stringify('return (async()=>{'+launchSource+'return browser;})();')},
 ['require','retainedAdmission','profile','process']);
const launchRequire=key=>key==='puppeteer'?{launch:async options=>{capturedOptions.push(options);return {controlledBrowser:true};}}:
 key==='../fixtures/secureshopPricingRenderedBrowser'?helper:(()=>{throw Error('Unexpected launch import');})();
await launch(launchRequire,retainedAdmission,retainedAdmission.profilePath,process);
assert.deepEqual(Object.keys(capturedOptions[0]).sort(),['args','executablePath','headless','timeout','userDataDir']);
assert.deepEqual(capturedOptions[0].args,['--no-sandbox']);assert.equal(capturedOptions[0].headless,true);
assert.equal(capturedOptions[0].executablePath,process.env.PUPPETEER_EXECUTABLE_PATH);
assert.equal(capturedOptions[0].userDataDir,retainedAdmission.profilePath);
assert(capturedOptions[0].timeout>0&&capturedOptions[0].timeout<=30000);
await launch(launchRequire,null,'controlled-legacy-profile',process);
assert.deepEqual(capturedOptions[1],{headless:true,userDataDir:'controlled-legacy-profile',executablePath:process.env.PUPPETEER_EXECUTABLE_PATH});
for(const forged of [{},{...retainedAdmission}])await assert.rejects(launch(launchRequire,forged,retainedAdmission.profilePath,process));
assert.equal(capturedOptions.length,2,'forged admissions must reject before launch');
if(${browser}){
 fs.mkdirSync(retainedAdmission.profilePath,{mode:0o700});
 const birth=requireOriginal(${JSON.stringify(path.join(root,'tests/fixtures/secureshopDarwinBrowserBirth.js'))});
 birth.captureBrowserRecord=()=>({schemaVersion:2,processes:[{kind:'pricing_v34_browser',pid:43210,parentPid:process.pid,uid:process.getuid(),pgid:43210,sessionId:43210,birth:[100,2],executablePath:retainedAdmission.browser,executableSha256:retainedAdmission.browserSha256}]});
 await helper.admitV34Browser({process:()=>({pid:43210})},retainedAdmission.profilePath,retainedAdmission);
 await assert.rejects(helper.admitV34Browser({process:()=>({pid:43210})},retainedAdmission.profilePath,retainedAdmission));
}
});`;
 fs.writeFileSync(fixture,program,{mode:0o600});
 const grant={version:1,cohort:'pricing-v34-browser',runId,launcherPid:0,workerPid:0,workspace:root,
  ownerPlanSha256:'a'.repeat(64),snapshotSha256:'b'.repeat(64),directory,descriptorPath,
  descriptorSha256:crypto.createHash('sha256').update(fs.readFileSync(descriptorPath)).digest('hex'),
  evidencePath:evidence,profilePath:path.join(directory,'tmp/dvaia-pricing-chat-owned'),
  browser:process.execPath,browserSha256:'c'.repeat(64),remainingMs:20000};
 const env={...process.env,DVAIA_CURRENT_MAIN_WORKSPACE:root,LAB_MODE:'vuln',SS_BOUND_PRICING_ENABLED:'true',JUDGE_PROVIDER:'ollama',
  SECURESHOP_PRICING_V34_MANUAL_EXPERIMENT_NATIVE:'1',SECURESHOP_PRICING_V34_EVIDENCE_PATH:evidence,
  SECURESHOP_STANDALONE_PRICING_DESCRIPTOR:descriptorPath,SECURESHOP_STANDALONE_PRICING_DESCRIPTOR_SHA256:grant.descriptorSha256,
  PUPPETEER_EXECUTABLE_PATH:process.execPath,TMPDIR:path.join(directory,'tmp'),
  SECURESHOP_BOUND_BROWSER_BIRTH_SCRIPT:path.join(root,'tests/postgres/secureshop_darwin_browser_birth.py'),
  SECURESHOP_BOUND_BROWSER_BIRTH_PYTHON:python};
 delete env.SECURESHOP_PRICING_V34_TRANSITION_PREFLIGHT_NATIVE;
 delete env.NODE_TEST_CONTEXT;
 try{
  if(fault==='link'){fs.unlinkSync(descriptorPath);fs.symlinkSync(fixture,descriptorPath);}
  if(fault==='mode')fs.chmodSync(descriptorPath,0o644);
  if(fault==='stale')fs.writeFileSync(evidence,'{}',{mode:0o600});
  if(fault==='wrong-run')grant.runId='d'.repeat(32);
  if(fault==='wrong-profile')grant.profilePath=path.join(directory,'tmp/other');
  if(fault==='wrong-hash')grant.descriptorSha256='0'.repeat(64);
  if(fault==='expired')grant.remainingMs=0;
  if(fault==='too-long')grant.remainingMs=1000001;
  if(fault==='foreign-cohort')grant.cohort='v33';
  const script=`import os,sys,json,subprocess,threading,time,hashlib,select
g=json.loads(sys.stdin.read());r,w=os.pipe();rr,rw=os.pipe();env=dict(os.environ);env['SECURESHOP_PRICING_V34_ADMISSION_FD']=str(r);env['SECURESHOP_PRICING_V34_READY_FD']=str(rw)
args=[sys.argv[1],'--test']+([] if sys.argv[3]=='isolated' else ['--test-isolation=none'])+['--test-reporter=tap',sys.argv[2]]
endpoint=time.monotonic()+.15 if sys.argv[3]=='startup-delay' else None
p=subprocess.Popen(args,env=env,pass_fds=(r,rw),stdout=subprocess.PIPE,stderr=subprocess.PIPE);os.close(r);os.close(rw)
g['launcherPid']=os.getpid();g['workerPid']=p.pid
ready=b''
if select.select([rr],[],[],3)[0]:ready=os.read(rr,2)
os.close(rr)
if endpoint is not None:g['remainingMs']=max(0,int((endpoint-time.monotonic())*1000))
if sys.argv[3] in ('read-delay','validation-delay','grant-delay'):g['remainingMs']=200
raw=json.dumps(g,separators=(',',':')).encode()
if sys.argv[3]=='duplicate':raw=raw[:-1]+b',"version":1}'
if sys.argv[3]=='grant-delay':time.sleep(.35)
if ready==b'R':os.write(w,raw)
os.close(w)
def ack():
 end=time.monotonic()+5;file=g['directory']+'/browser-birth.json'
 while time.monotonic()<end and p.poll() is None:
  if os.path.exists(file):
   with open(file,'rb') as f: body=f.read(4097)
   a=dict(version=1,runId=g['runId'],workerPid=p.pid,browserPid=43210,birthSha256=hashlib.sha256(body).hexdigest(),profile=g['profilePath'])
   if sys.argv[3]=='bad-ack':a['browserPid']=43211
   fd=os.open(g['directory']+'/browser-ack.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
   os.write(fd,json.dumps(a).encode());os.close(fd);return
  time.sleep(.01)
t=threading.Thread(target=ack);t.start()
try:out,err=p.communicate(timeout=10)
except BaseException:p.kill();out,err=p.communicate();raise
finally:t.join(timeout=6)
sys.stdout.buffer.write(out);sys.stderr.buffer.write(err);sys.exit(p.returncode)
`;
  return spawnSync(python,['-B','-c',script,process.execPath,fixture,fault],{cwd:root,env,input:JSON.stringify(grant),encoding:'utf8',timeout:20000,maxBuffer:1024*1024});
 }finally{fs.rmSync(owner,{recursive:true,force:true});}
}

test('V34 actual original entry consumes FIFO before effects; real Node requires nonisolated test worker',()=>{
 for(const fault of ['none','isolated','link','mode','stale','wrong-run','wrong-profile','wrong-hash','expired','too-long','foreign-cohort','duplicate','close']){
  const result=grantControl(fault);assert.equal(result.error,undefined);assert.equal(result.status===0,fault==='none',fault+'\n'+result.stdout+result.stderr);
 }
});
test('V34 actual admitted browser waits for exact parent birth ACK and rejects reuse/forgery',()=>{
 for(const fault of ['none','bad-ack']){const result=grantControl(fault,true);assert.equal(result.error,undefined);assert.equal(result.status===0,fault==='none',result.stdout+result.stderr);}
});
test('V34 ready-origin deadline charges real startup, grant delivery, read and validation delays',()=>{
 for(const fault of ['startup-delay','grant-delay','read-delay','validation-delay']){
  const result=grantControl(fault);assert.equal(result.error,undefined);assert.notEqual(result.status,0,result.stdout+result.stderr);
  assert.doesNotMatch(result.stdout,/CONTROL_ADMISSION_RETURNED/);
 }
});

test('V34 keeps false grounding excluded from public release', () => {
  assert.ok(RELEASE_EXCLUDED_OBJECTIVE_IDS.includes(objective));
  assert.equal(isAssessmentReleaseAllowed(objective), false);
});

test('V34 fixture passes one verified disposable release token through original assessment consumers', () => {
  assert.match(source, /const assessmentReleaseAdmission=PRICING_V34\|\|V34_TRANSITION_PREFLIGHT\s*\?await require\('\.\.\/\.\.\/server\/services\/secureshopAssessmentReleaseAdmission'\)\s*\.createDisposableAssessmentReleaseAdmission\(\{/);
  assert.match(source, /runtimePool:pools\[key\+'_RUNTIME'\],migrationPool:pools\[key\+'_MIGRATION'\],\s*runtimeUrl:names\[key\+'_RUNTIME'\],migrationUrl:names\[key\+'_MIGRATION'\]/);
  assert.match(source, /objectiveIds:\['ss_pricing_false_grounding'\]\}\)\s*:undefined/);
  assert.match(source, /createSecureShopGradingBootstrap\(\{identityPool:identity,agentsPool:agents,progress,\s*resetComposition:reset,assessmentReleaseAdmission/);
  assert.match(source, /createSecureShopBoundReviewComposition\(\{identityPool:identity,agentsPool:agents,reviewPool:review,\s*commercePool:commerce,resetComposition:reset,gradingBootstrap:grading,scenes,modeAuthority,\s*assessmentReleaseAdmission/);
  assert.match(source, /readSecureShopAssessmentEligibility\(identity,scope,\[PRICING_V34\?'ss_pricing_false_grounding':'ss_pricing_competitor_disclosure'\],assessmentReleaseAdmission\)/);
  assert.match(source, /createSecureShopAssessmentCatalog\(\{pool:identity,authService:auth,assessmentReleaseAdmission\}\)/);
  assert.match(source, /createSecureShopAssessmentProgressRepository\(\{pool:identity,assessmentReleaseAdmission\}\)/);
  assert.match(source, /assessmentProgress,assessmentRecovery/);
  assert.match(source, /pendingSourceSha256:'6c80983e84c41ee81e0dfdad22aceff43f4e32aa337b28dbead950ec88e66848'/);
});

// Execute the exact fixture setup and mount statements, not a parallel service
// assembly. Only persistence/authority edges are controlled; all constructors,
// auth branding, release capabilities, projections and route handlers are real.
async function setupControl(change=()=>{},v34=true){
 const express=require('express'),noop=async()=>{};
 const methods=names=>Object.fromEntries(names.split(' ').map(name=>[name,noop]));
 const state={active:true,persona:true,judges:0,queries:[],fences:0,bootstraps:0,releases:0};
 const scope={launchId:crypto.randomUUID(),scenarioId:crypto.randomUUID(),generation:1,
  platformOwnerId:501,platformSessionId:502,credentialVersion:1,expiresAt:new Date(Date.now()+60000).toISOString()};
 const row={principalId:crypto.randomUUID(),ownerId:90,sessionId:91,shopUserId:1000000001,
  username:'merchant',email:'merchant@example.invalid',role:'merchant',credentialVersion:'1',authorityVersion:'1',expiresAt:scope.expiresAt};
 const tenantId=crypto.randomUUID();
 const stores={};
 for(const [name,store]of Object.entries({identity:'identity',agents:'secureshop_agents',review:'secureshop_review',commerce:'secureshop'})){
  const entry=stores[name]={};
  for(const role of ['runtime','migration']){
   const database=`dvaia_test_agent_host_012345abcdef_${store}`,username=`dvaia_${store}_${role}`;
   const url=`postgresql://${username}@127.0.0.1:54321/${database}`;
   const query=async(sql,params)=>{
    state.queries.push(sql);const rows=value=>({rows:value});
    if(sql.includes('current_database()'))return rows([{database,role:username,session_role:username,
     server_address:'172.20.0.2',server_port:5432,server_started:'controlled-one-cluster'}]);
    if(sql.startsWith('SELECT l.launch_id')){
     assert.deepEqual(params,[scope.platformSessionId,scope.platformOwnerId,scope.launchId,scope.scenarioId,scope.generation]);
     return rows(state.active?[{launch_id:scope.launchId}]:[]);
    }
    if(sql.startsWith('SELECT j.*,m.mode'))return rows([]);
    if(['BEGIN','COMMIT','ROLLBACK'].includes(sql))return rows([]);
    if(sql.includes('FROM secureshop_auth.sessions s'))return rows([{tenantId,principalId:row.principalId,
     shopUserId:row.shopUserId,username:row.username,role:row.role}]);
    if(sql.includes('FROM unnest($2::uuid[])'))return rows([{principalId:row.principalId,generation:0,
     objectiveId:objective,label:'Original false grounding',completed:false}]);
    throw Error('Unexpected controlled SQL');
   };
   entry[role+'Url']=url;entry[role+'Pool']={options:{connectionString:url},query,
    async connect(){return{query,release(){state.releases++;}};}};
  }
 }
 const token=await require('../server/services/secureshopAssessmentReleaseAdmission')
  .createDisposableAssessmentReleaseAdmission({stores,objectiveIds:[objective]});
 const repository={...methods('registerWithSession findCredential recordFailedLogin createSession rotateSession revokeSession readCredentialForSession changePassword revokeAll'),
  async readCurrentSession(){return row;},
  async readOrCreateDefaultExecutionSession(){return{...row,principalOwnerId:row.ownerId,authSessionId:row.sessionId,
   ownerId:scope.platformOwnerId,sessionId:scope.platformSessionId,tenantId,membershipVersion:'1'};}};
 const auth=require('../server/services/secureshopStandaloneAuth').createSecureShopStandaloneAuthService({repository});
 const base=await auth.authenticate('a'.repeat(43));
 const launches={...methods('assertCurrent readActiveMetadata'),
  async issueOrRenew(){state.bootstraps++;return{binding:scope,bearer:'b'.repeat(43)};},
  async resolveCapability(){return scope;}};
 const personaAuth={...methods('login logout renew listSessions revokeOwnedSession changePassword listApiKey rotateApiKey authenticateApiKey authenticatePersona'),
  async establishSession(){return{token:'controlled.persona.token',expiresAt:scope.expiresAt,
   user:{id:row.shopUserId,username:row.username,email:row.email,role:row.role}};},
  async authenticateBoundToken(){if(!state.persona)throw Error('Controlled stale persona');return{
   user:{id:row.shopUserId,role:row.role},sessionId:crypto.randomUUID(),authorityVersion:'1'};}};
 const resetCoordinator=methods('reset resumeExisting recover');
 const composition={launches,personaAuth,router:express.Router(),browserRouter:express.Router(),
  catalog:methods('listProducts getProduct listMerchantProducts createMerchantProduct updateMerchantProduct archiveMerchantProduct categories'),
  commerce:methods('cart add update remove summary checkout orders order'),
  account:methods('profile updateProfile addresses createAddress updateAddress deleteAddress'),
  launchResetCoordinator:resetCoordinator,ownerResetService:methods('assertReady resetOwner'),createStudentDeletionCleanup(){}};
 const grading={personaAuthority:{capture(){return{async assertRemoteAdmission(){state.fences++;}};}}};
 const values={assert,express,PRICING_V34:v34,identity:stores.identity.runtimePool,review:stores.review.runtimePool,
  commerce:stores.commerce.runtimePool,auth,composition,grading,
  scenes:methods('readExisting list select'),reset:{launchResetCoordinator:resetCoordinator,sceneResetPreflight:methods('preview')},
  modeRepository:methods('getPrincipalMode setPrincipalMode'),modeAuthority:{},assessmentReleaseAdmission:token,
  judge:async()=>{state.judges++;throw Error('Controlled setup forbids Judge');}};
 change(values,state);
 const fixtureRequire=require('node:module').createRequire(path.join(root,'tests/postgres/secureshopStandalonePricingRendered.integration.test.js'));
 let recoveryOptions;
 values.require=id=>{
  const actual=fixtureRequire(id);
  if(id==='../../server/services/secureshopAssessmentRecovery')return{...actual,
   createSecureShopAssessmentRecovery(options){recoveryOptions=options;return actual.createSecureShopAssessmentRecovery(options);}};
  return actual;
 };
 const start=source.indexOf('    const protectedReset=',source.indexOf('    await auth.logout(registered.token);'));
 const end=source.indexOf('    const app=express();',start);
 assert.ok(start>0&&end>start);
 const mountStart=source.indexOf("    app.use('/api/secureshop/auth',",end);
 const mountEnd=source.indexOf("    app.use('/api/secureshop',",mountStart);
 const AsyncFunction=Object.getPrototypeOf(async function(){}).constructor;
 const mounted=await new AsyncFunction(...Object.keys(values),source.slice(start,end)+`
 const origin='http://127.0.0.1:54321';let authRouter;
 const app={use(path,router){assert.equal(path,'/api/secureshop/auth');authRouter=router;}};
 ${source.slice(mountStart,mountEnd)}
 return {mounted,bound,bootstrap,protectedReset,standaloneMode,assessmentProgress,assessmentRecovery,authRouter};`
 )(...Object.values(values));
 return{...mounted,state,base,values,recoveryOptions,token};
}

async function routeGet(router,path){
 const layer=router.stack.find(item=>item.route?.path===path&&item.route.methods.get);
 assert.ok(layer,'actual route exists');
 const req={query:{},headers:{cookie:'dvaia_shop_session='+ 'a'.repeat(43)}};
 const res={statusCode:200,status(code){this.statusCode=code;return this;},json(body){this.body=body;return this;}};
 await layer.route.stack.at(-1).handle(req,res,()=>assert.fail('unexpected route next'));
 return res;
}

test('actual V34 setup mounts canonical release-bound recovery and progress with existing full-mode application',async()=>{
 const f=await setupControl();
 assert.equal(f.recoveryOptions.identityPool,f.values.identity);
 assert.equal(f.recoveryOptions.authService,f.values.auth);
 assert.equal(f.recoveryOptions.bootstrap,f.bootstrap);
 assert.equal(f.recoveryOptions.personaAuthority,f.values.grading.personaAuthority);
 assert.equal(f.recoveryOptions.launches,f.values.composition.launches);
 assert.equal(f.recoveryOptions.personaAuth,f.values.composition.personaAuth);
 assert.equal(f.recoveryOptions.assessmentReleaseAdmission,f.token);
 assert.equal(f.recoveryOptions.judge,f.values.judge);
 for(const name of ['list','retry'])assert.equal(typeof f.assessmentRecovery[name],'function');
 assert.equal(f.bound.standaloneAuth,f.mounted.standaloneAuth);
 assert.equal(f.bound.readiness.ready,true);assert.equal(f.bound.standaloneReadiness,undefined);
 assert.equal(typeof f.bound.launchRouter,'function');
 const recovery=await routeGet(f.authRouter,'/assessments');
 assert.equal(recovery.statusCode,200);assert.deepEqual(recovery.body,{judgments:[]});
 const progress=await routeGet(f.authRouter,'/progress');
 assert.equal(progress.statusCode,200);assert.equal(progress.body.objectives[0].objectiveId,objective);
 assert.equal(progress.body.objectives[0].completed,false);
 assert.ok(f.state.bootstraps>0&&f.state.fences>0&&f.state.releases>0);
 assert.equal(f.state.judges,0);assert.ok(f.state.queries.every(sql=>/^(SELECT|BEGIN|COMMIT|ROLLBACK)/.test(sql)));
 assert.equal(isAssessmentReleaseAllowed(objective),false);
});

test('actual V34 setup rejects forged admission, cross-pool and missing adjacent lifecycle dependencies',async()=>{
 for(const change of [
  v=>{v.assessmentReleaseAdmission={};},
  v=>{v.identity=v.review;},
  v=>{delete v.composition.launches.assertCurrent;},
  v=>{delete v.composition.launches.issueOrRenew;},
  v=>{delete v.composition.personaAuth.authenticateBoundToken;},
  v=>{delete v.grading.personaAuthority.capture;},
  v=>{delete v.reset.sceneResetPreflight.preview;},
  v=>{delete v.modeRepository.getPrincipalMode;},
  v=>{delete v.composition.ownerResetService.assertReady;},
  v=>{delete v.composition.createStudentDeletionCleanup;},
  v=>{delete v.composition.browserRouter;},
 ])await assert.rejects(setupControl(change));
});

test('actual V34 recovery rejects stale scope/persona and missing retry rows without invoking Judge',async()=>{
 for(const fault of ['active','persona']){
  const f=await setupControl();f.state[fault]=false;
  await assert.rejects(f.assessmentRecovery.list(f.base));
  const result=await routeGet(f.authRouter,'/assessments');assert.notEqual(result.statusCode,200);
  assert.equal(f.state.judges,0);
 }
 const f=await setupControl();
 await assert.rejects(f.assessmentRecovery.retry(f.base,{evaluationId:crypto.randomUUID()}),{code:'SHOP_ASSESSMENT_NOT_FOUND'});
 assert.equal(f.state.judges,0);
});

test('non-V34 actual setup keeps prior assessment services absent and full-mode mounts unchanged',async()=>{
 const f=await setupControl(()=>{},false);
 assert.equal(f.assessmentRecovery,undefined);assert.equal(f.assessmentProgress,undefined);
 assert.equal(f.recoveryOptions,undefined);assert.equal(f.bound.readiness.ready,true);
 assert.equal(f.bound.standaloneReadiness,undefined);assert.equal(f.state.judges,0);
});
