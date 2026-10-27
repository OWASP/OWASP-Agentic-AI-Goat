'use strict';
// Qualification-only Chrome admission. The shared analytics browser path is unchanged.
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const {createHash}=require('node:crypto');
const {once}=require('node:events');
const {spawn}=require('node:child_process');
const owner=require('./secureshopAnalyticsBrowserOwner');
const ROOT=path.resolve(__dirname,'../..');
const FLAGS=Object.freeze(['--no-sandbox','--disable-background-networking',
  '--disable-component-update','--disable-domain-reliability','--disable-quic',
  '--force-webrtc-ip-handling-policy=disable_non_proxied_udp',
  '--proxy-server=http://blocked.invalid:9',
  '--proxy-bypass-list=127.0.0.1;localhost;[::1]',
  '--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1, EXCLUDE localhost, EXCLUDE [::1]']);
function privateDirectory(directory){
  const info=fs.lstatSync(directory);
  assert(info.isDirectory()&&!info.isSymbolicLink()&&info.uid===process.getuid()
    &&(info.mode&0o777)===0o700,'CTF browser directory must be private');
  assert.equal(fs.realpathSync(directory),directory);
}
function variant(label){
  assert(['content','config','preview','learner','attemptGate','fixedPractice'].includes(label),'Unknown CTF browser admission variant');
  return label==='content'?{
    native:'CTF_TEN_CONTENT_BROWSER_NATIVE',selector:'CTF_TEN_CONTENT_ISOLATED',
    temporary:'CTF_CONTENT_BROWSER_TMP',record:'CTF_CONTENT_BROWSER_RECORD',
    ack:'CTF_CONTENT_BROWSER_ACK',shortPrefix:'c-',profile:'content-profile',
    kind:'ctf_ten_content_browser',filePrefix:'content'}:label==='config'?{
    native:'CTF_CONFIG_BROWSER_NATIVE',selector:'CTF_CONFIG_RENDERED_ISOLATED',
    temporary:'CTF_CONFIG_BROWSER_TMP',record:'CTF_CONFIG_BROWSER_RECORD',
    ack:'CTF_CONFIG_BROWSER_ACK',shortPrefix:'g-',profile:'config-profile',
    kind:'ctf_config_browser',filePrefix:'config'}:label==='preview'?{
    native:'CTF_PREVIEW_BROWSER_NATIVE',selector:'CTF_PREVIEW_RENDERED_ISOLATED',
    temporary:'CTF_PREVIEW_BROWSER_TMP',record:'CTF_PREVIEW_BROWSER_RECORD',
    ack:'CTF_PREVIEW_BROWSER_ACK',shortPrefix:'p-',profile:'preview-profile',
    kind:'ctf_preview_browser',filePrefix:'preview'}:label==='attemptGate'?{
    native:'CTF_LEARNER_ATTEMPT_GATE_BROWSER_NATIVE',
    selector:'CTF_LEARNER_ATTEMPT_GATE_RENDERED_ISOLATED',
    temporary:'CTF_LEARNER_ATTEMPT_GATE_BROWSER_TMP',
    record:'CTF_LEARNER_ATTEMPT_GATE_BROWSER_RECORD',
    ack:'CTF_LEARNER_ATTEMPT_GATE_BROWSER_ACK',shortPrefix:'a-',
    profile:'learner-attempt-gate-profile',kind:'ctf_learner_attempt_gate_browser',
    filePrefix:'learner-attempt-gate'}:label==='fixedPractice'?{
    native:'CTF_FIXED_PRACTICE_BROWSER_NATIVE',
    selector:'CTF_FIXED_PRACTICE_RENDERED_ISOLATED',
    temporary:'CTF_FIXED_PRACTICE_BROWSER_TMP',
    record:'CTF_FIXED_PRACTICE_BROWSER_RECORD',
    ack:'CTF_FIXED_PRACTICE_BROWSER_ACK',shortPrefix:'f-',
    profile:'fixed-practice-profile',kind:'ctf_fixed_practice_browser',
    filePrefix:'fixed-practice'}:{
    native:'CTF_LEARNER_ENTRY_HINT_BROWSER_NATIVE',
    selector:'CTF_LEARNER_ENTRY_HINT_RENDERED_ISOLATED',
    temporary:'CTF_LEARNER_ENTRY_HINT_BROWSER_TMP',
    record:'CTF_LEARNER_ENTRY_HINT_BROWSER_RECORD',
    ack:'CTF_LEARNER_ENTRY_HINT_BROWSER_ACK',shortPrefix:'l-',
    profile:'learner-entry-hint-profile',kind:'ctf_learner_entry_hint_browser',
    filePrefix:'learner-entry-hint'};
}
function admit(env,root,label){
  const scope=variant(label);
  assert.equal(env[scope.native],'1');
  assert.equal(env[scope.selector],'1');
  for(const other of ['content','config','preview','learner','attemptGate','fixedPractice'])if(other!==label)
    assert.notEqual(env[variant(other).selector],'1','CTF rendered selectors are mutually exclusive');
  assert.equal(env.PG_TEST_DISPOSABLE,'yes');
  assert.equal(env.CTF_CONTENT_SOURCE_ROOT,ROOT);
  assert.equal(env.CTF_RENDERED_EVIDENCE,root);
  const run=path.dirname(root),qualification=path.join(ROOT,'tasks/qualification');
  assert.equal(path.dirname(run),qualification);
  assert.match(path.basename(run),/^dvaia-ctf-stages-route-[A-Za-z0-9_-]+$/);
  assert.equal(path.basename(root),'rendered-evidence');
  const runtime=path.join(run,'runtime'),profile=path.join(root,scope.profile);
  assert.equal(env.CTF_CONTENT_RUNTIME_DIRECTORY,runtime);
  assert.equal(env.TMPDIR,path.join(runtime,'tmp'));
  const shortTmp=env[scope.temporary];
  assert.equal(path.dirname(shortTmp),path.join(ROOT,'tasks/tmp'));
  assert.match(path.basename(shortTmp),new RegExp(`^${scope.shortPrefix}[A-Za-z0-9_-]{8}$`));
  assert.ok(Buffer.byteLength(shortTmp)<=80);
  assert.equal(env.XDG_CACHE_HOME,path.join(runtime,'cache'));
  assert.equal(env.XDG_CONFIG_HOME,path.join(runtime,'config'));
  assert.equal(env[scope.record],path.join(root,`${scope.filePrefix}-browser-birth.json`));
  assert.equal(env[scope.ack],path.join(root,`${scope.filePrefix}-browser-ack.json`));
  assert.equal(env.SECURESHOP_BOUND_BROWSER_BIRTH_SCRIPT,
    path.join(ROOT,'tests/postgres/secureshop_darwin_browser_birth.py'));
  assert.ok(path.isAbsolute(env.SECURESHOP_BOUND_BROWSER_BIRTH_PYTHON));
  assert.equal(fs.realpathSync(env.SECURESHOP_BOUND_BROWSER_BIRTH_PYTHON),
    env.SECURESHOP_BOUND_BROWSER_BIRTH_PYTHON);
  for(const directory of [qualification,run,runtime,root,env.TMPDIR,
    env.XDG_CACHE_HOME,env.XDG_CONFIG_HOME,shortTmp])privateDirectory(directory);
  const executable=env.ANALYTICS_BROWSER_EXECUTABLE;
  assert.equal(executable,env.PUPPETEER_EXECUTABLE_PATH);
  assert.ok(path.isAbsolute(executable)&&fs.realpathSync(executable)===executable);
  assert.match(env.ANALYTICS_BROWSER_SHA256,/^[a-f0-9]{64}$/);
  return {profile,executable};
}
async function acknowledge(env,{profile,pid,capture=require('./secureshopDarwinBrowserBirth').captureBrowserRecord}){
  const label=path.basename(profile)==='config-profile'?'config':
    path.basename(profile)==='preview-profile'?'preview':
    path.basename(profile)==='fixed-practice-profile'?'fixedPractice':
    path.basename(profile)==='learner-attempt-gate-profile'?'attemptGate':
    path.basename(profile)==='learner-entry-hint-profile'?'learner':'content',scope=variant(label);
  const record=capture({root:ROOT,kind:scope.kind,pid,
    executablePath:env.ANALYTICS_BROWSER_EXECUTABLE,
    executableSha256:env.ANALYTICS_BROWSER_SHA256});
  assert.equal(record.schemaVersion,2);
  assert.equal(record.processes.length,1);
  const birth=record.processes[0];
  assert.equal(birth.pid,pid);
  assert.equal(birth.parentPid,process.pid);
  assert.equal(birth.pgid,process.pid);
  assert.equal(birth.sessionId,process.pid);
  assert.equal(birth.uid,process.getuid());
  assert.equal(birth.executablePath,env.ANALYTICS_BROWSER_EXECUTABLE);
  assert.equal(birth.executableSha256,env.ANALYTICS_BROWSER_SHA256);
  const file=env[scope.record],temporary=`${file}.${process.pid}.tmp`;
  await fs.promises.writeFile(temporary,`${JSON.stringify(record)}\n`,{flag:'wx',mode:0o600});
  await fs.promises.rename(temporary,file);
  const recordSha256=createHash('sha256').update(await fs.promises.readFile(file)).digest('hex');
  const until=Date.now()+15000;
  while(Date.now()<until){
    let value;
    try{value=JSON.parse(await fs.promises.readFile(env[scope.ack],'utf8'));}
    catch(error){if(error.code!=='ENOENT')throw error;
      await new Promise(resolve=>setTimeout(resolve,25));continue;}
    const info=await fs.promises.lstat(env[scope.ack]);
    assert(info.isFile()&&!info.isSymbolicLink()&&info.uid===process.getuid()
      &&(info.mode&0o777)===0o600);
    assert.deepEqual(value,{schemaVersion:1,recordSha256,parentPid:process.pid,
      browserPid:pid,profile});
    return {pid,pgid:birth.pgid,sessionId:birth.sessionId,uid:birth.uid,
      qualificationPid:process.pid,qualificationPgid:birth.pgid,
      qualificationSessionId:birth.sessionId,workerPid:process.pid};
  }
  throw Error('CTF independent live browser acknowledgement unavailable');
}
function browserEnvironment(env,label='content'){
  const temporary=env[variant(label).temporary];
  return {PATH:'/usr/bin:/bin',TMPDIR:temporary,
    TMP:temporary,TEMP:temporary,
    MAC_CHROMIUM_TMPDIR:temporary,
    XDG_CACHE_HOME:env.XDG_CACHE_HOME,XDG_CONFIG_HOME:env.XDG_CONFIG_HOME};
}
async function launchCtfBrowser(root,label){
  const scope=variant(label);
  const env=process.env,{profile,executable}=admit(env,root,label);
  fs.accessSync(executable,fs.constants.X_OK);
  const executableSha256=createHash('sha256').update(fs.readFileSync(executable)).digest('hex');
  assert.equal(executableSha256,env.ANALYTICS_BROWSER_SHA256);
  fs.mkdirSync(profile,{mode:0o700});
  const puppeteer=require('puppeteer');
  const args=await puppeteer.defaultArgs({headless:true,userDataDir:profile,
    args:['--remote-debugging-port=0',...FLAGS]});
  const childEnv=browserEnvironment(env,label);
  let child,browser,identity;
  async function cleanup(){
    if(child){await owner.retireChild(child);
      assert.throws(()=>process.kill(child.pid,0),{code:'ESRCH'});}
    fs.writeFileSync(path.join(root,`${scope.filePrefix}-cleanup.json`),
      JSON.stringify(owner.profileDisposition(child?.pid??null,identity)),{mode:0o600});
  }
  try{
    child=spawn(executable,args,{detached:false,env:childEnv,
      stdio:['ignore','ignore','pipe']});
    const stderr=path.join(root,`${scope.filePrefix}-stderr.log`);
    fs.writeFileSync(stderr,'',{mode:0o600});
    const endpoint=owner.observeBrowserEndpoint(child,chunk=>fs.appendFileSync(stderr,chunk));
    endpoint.catch(()=>{});
    await owner.bounded(once(child,'spawn'),3000,'CTF Chrome spawn timeout');
    identity=await acknowledge(env,{profile,pid:child.pid});
    fs.writeFileSync(path.join(root,`${scope.filePrefix}-process.json`),
      JSON.stringify({...identity,profile,executableSha256}),{mode:0o600});
    browser=await owner.bounded(puppeteer.connect({browserWSEndpoint:await endpoint,
      protocolTimeout:15000}),20000,'CTF Chrome connection timeout');
    const original=browser.close.bind(browser);let closed=false;
    browser.close=async()=>{if(closed)return;closed=true;let primary;
      try{await owner.bounded(original(),3000,'CTF Chrome close timeout');}
      catch(error){primary=error;}
      try{await cleanup();}catch(error){throw new AggregateError(
        [...(primary?[primary]:[]),error],'CTF Chrome cleanup failed');}
      if(primary)throw primary;};
    return browser;
  }catch(error){try{await cleanup();}catch(cleanupError){throw new AggregateError(
    [error,cleanupError],'CTF Chrome launch cleanup failed');}throw error;}
}
async function launchCtfContentBrowser(root,label){assert.equal(label,'content');return launchCtfBrowser(root,label);}
async function launchCtfConfigBrowser(root,label){assert.equal(label,'config');return launchCtfBrowser(root,label);}
async function launchCtfPreviewBrowser(root,label){assert.equal(label,'preview');return launchCtfBrowser(root,label);}
async function launchCtfLearnerBrowser(root,label){assert.equal(label,'learner');return launchCtfBrowser(root,label);}
async function launchCtfLearnerAttemptGateBrowser(root,label){assert.equal(label,'attemptGate');return launchCtfBrowser(root,label);}
async function launchCtfFixedPracticeBrowser(root,label){assert.equal(label,'fixedPractice');return launchCtfBrowser(root,label);}
module.exports={admit,acknowledge,browserEnvironment,FLAGS,launchCtfContentBrowser,launchCtfConfigBrowser,launchCtfPreviewBrowser,launchCtfLearnerBrowser,launchCtfLearnerAttemptGateBrowser,launchCtfFixedPracticeBrowser};
