'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const {createHash}=require('node:crypto');
const owner=require('./secureshopAnalyticsBrowserOwner');
function admit(env,root){
  assert.equal(env.SECURESHOP_POLICY_OUTPUT_TEST_NO_SANDBOX,'1');
  for(const key of ['SECURESHOP_POLICY_OUTPUT_BROWSER_NATIVE','SECURESHOP_STANDALONE_SSRF_RENDERED_NATIVE',
    'SECURESHOP_POLICY_OUTPUT_REPOSITORY_EVIDENCE'])assert.equal(env[key],'1');
  assert.equal(env.PG_TEST_DISPOSABLE,'yes');
  const workspace=env.DVAIA_CURRENT_MAIN_WORKSPACE;
  assert.equal(workspace,process.cwd());
  const evidence=path.dirname(root),run=path.dirname(evidence);
  assert.equal(path.dirname(run),path.join(workspace,'tasks/qualification'));
  assert.match(path.basename(run),/^run-[a-z0-9_]{8}$/);
  assert.equal(evidence,path.join(run,'standalone-ssrf-rendered'));
  assert.equal(root,path.join(evidence,'runtime'));
  assert.equal(env.SECURESHOP_STANDALONE_SSRF_RENDERED_EVIDENCE_PATH,path.join(evidence,'result.json'));
  assert.equal(env.SECURESHOP_POLICY_OUTPUT_BROWSER_RECORD_PATH,path.join(evidence,'policy-output-browser.json'));
  assert.equal(env.SECURESHOP_POLICY_OUTPUT_BROWSER_ACK_PATH,path.join(evidence,'policy-output-browser-ack.json'));
  assert.equal(env.SECURESHOP_BOUND_BROWSER_BIRTH_SCRIPT,path.join(workspace,'tests/postgres/secureshop_darwin_browser_birth.py'));
  assert.ok(path.isAbsolute(env.SECURESHOP_BOUND_BROWSER_BIRTH_PYTHON));
  for(const directory of [run,evidence,root]){
    const stat=fs.lstatSync(directory);
    assert(stat.isDirectory()&&!stat.isSymbolicLink()&&stat.uid===process.getuid()&&(stat.mode&0o777)===0o700);
    assert.equal(fs.realpathSync(directory),directory);
  }
  return {workspace,evidence,profile:path.join(root,'browser-profile')};
}
async function acknowledge(env,{workspace,profile,pid,onBirth=()=>{}}){
  const executablePath=env.ANALYTICS_BROWSER_EXECUTABLE;
  assert.equal(fs.realpathSync(executablePath),executablePath);
  const record=require('./secureshopDarwinBrowserBirth').captureBrowserRecord({
    root:workspace,kind:'policy_output_browser',pid,executablePath,executableSha256:env.ANALYTICS_BROWSER_SHA256});
  assert.equal(record.schemaVersion,2);
  assert.equal(record.processes.length,1);
  const birth=record.processes[0];
  assert.equal(birth.pid,pid);
  assert.equal(birth.parentPid,process.pid);
  assert.equal(birth.pgid,process.pid);
  assert.equal(birth.sessionId,process.pid);
  assert.equal(birth.uid,process.getuid());
  assert.notEqual(pid,process.pid);
  onBirth(Object.freeze({pid,pgid:birth.pgid,sessionId:birth.sessionId,uid:birth.uid,
    qualificationPid:process.pid,qualificationPgid:birth.pgid,
    qualificationSessionId:birth.sessionId,workerPid:process.pid}));
  const file=env.SECURESHOP_POLICY_OUTPUT_BROWSER_RECORD_PATH,temporary=`${file}.${process.pid}.tmp`;
  await fs.promises.writeFile(temporary,`${JSON.stringify(record)}\n`,{flag:'wx',mode:0o600});
  await fs.promises.rename(temporary,file);
  const recordSha256=createHash('sha256').update(await fs.promises.readFile(file)).digest('hex');
  const until=Date.now()+15000;
  while(Date.now()<until){
    let value;
    try{value=JSON.parse(await fs.promises.readFile(env.SECURESHOP_POLICY_OUTPUT_BROWSER_ACK_PATH,'utf8'));}
    catch(error){if(error.code!=='ENOENT')throw error;await new Promise(resolve=>setTimeout(resolve,25));continue;}
    const stat=await fs.promises.lstat(env.SECURESHOP_POLICY_OUTPUT_BROWSER_ACK_PATH);
    assert(stat.isFile()&&!stat.isSymbolicLink()&&stat.uid===process.getuid()&&(stat.mode&0o777)===0o600);
    assert.deepEqual(value,{schemaVersion:1,recordSha256,parentPid:process.pid,browserPid:pid,profile});
    return;
  }
  throw Error('Policy output independent live browser acknowledgement unavailable');
}
const FLAGS=Object.freeze(['--no-sandbox','--disable-background-networking','--disable-component-update',
  '--disable-domain-reliability','--disable-quic','--force-webrtc-ip-handling-policy=disable_non_proxied_udp',
  '--proxy-server=http://blocked.invalid:9','--proxy-bypass-list=127.0.0.1;localhost;[::1]',
  '--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1, EXCLUDE localhost, EXCLUDE [::1]']);
function browserEnvironment(env,root){
  const {evidence}=admit(env,root),outer=path.join(path.dirname(evidence),'runtime');
  const expected={MAC_CHROMIUM_TMPDIR:path.join(outer,'tmp'),
    XDG_CACHE_HOME:path.join(outer,'home/.cache'),XDG_CONFIG_HOME:path.join(outer,'home/.config')};
  const privateDirectory=directory=>{
    const stat=fs.lstatSync(directory);
    assert(stat.isDirectory()&&!stat.isSymbolicLink()&&stat.uid===process.getuid()&&(stat.mode&0o777)===0o700);
    assert.equal(fs.realpathSync(directory),directory);
  };
  for(const directory of [outer,path.join(outer,'home'),path.join(outer,'tmp')])privateDirectory(directory);
  for(const [key,value]of Object.entries(expected)){
    assert.equal(env[key],value);
    if(key==='MAC_CHROMIUM_TMPDIR')continue;
    // Optional leaf may be created by Chrome, only beneath the verified private home.
    try{privateDirectory(value);}catch(error){if(error.code!=='ENOENT')throw error;}
  }
  return {PATH:'/usr/bin:/bin',HOME:root,TMPDIR:root,...expected};
}
async function launchPolicyOutputBrowser(root,label){
  if(process.env.SECURESHOP_POLICY_OUTPUT_TEST_NO_SANDBOX===undefined)
    return owner.launchOwnedAnalyticsBrowser(root,label);
  assert.equal(label,'browser');
  const env=process.env,{workspace,profile}=admit(env,root);
  const childEnvironment=browserEnvironment(env,root);
  const executable=env.ANALYTICS_BROWSER_EXECUTABLE;
  assert.equal(fs.realpathSync(executable),executable);
  fs.accessSync(executable,fs.constants.X_OK);
  const executableSha256=createHash('sha256').update(fs.readFileSync(executable)).digest('hex');
  assert.equal(executableSha256,env.ANALYTICS_BROWSER_SHA256);
  fs.mkdirSync(profile,{mode:0o700});
  let child,browser,identity;
  async function cleanup(){
    if(child){await owner.retireChild(child);assert.throws(()=>process.kill(child.pid,0),{code:'ESRCH'});}
    fs.writeFileSync(path.join(root,'browser-cleanup.json'),JSON.stringify(owner.profileDisposition(child?.pid??null,identity)),{mode:0o600});
  }
  try{
    const puppeteer=require('puppeteer');
    const args=await puppeteer.defaultArgs({headless:true,userDataDir:profile,args:['--remote-debugging-port=0',...FLAGS]});
    child=require('node:child_process').spawn(executable,args,{detached:false,
      env:childEnvironment,stdio:['ignore','ignore','pipe']});
    const stderr=path.join(root,'browser-stderr.log');fs.writeFileSync(stderr,'',{mode:0o600});
    const endpoint=owner.observeBrowserEndpoint(child,chunk=>fs.appendFileSync(stderr,chunk));endpoint.catch(()=>{});
    await owner.bounded(require('node:events').once(child,'spawn'),3000,'Chrome spawn timeout');
    await acknowledge(env,{workspace,profile,pid:child.pid,onBirth:value=>{
      identity=value;
      fs.writeFileSync(path.join(root,'browser-process.json'),JSON.stringify({...identity,profile,executableSha256}),{mode:0o600});
    }});
    browser=await owner.bounded(puppeteer.connect({browserWSEndpoint:await endpoint,protocolTimeout:15000}),20000,'Chrome connection timeout');
    const original=browser.close.bind(browser);let closed=false;
    browser.close=async()=>{if(closed)return;closed=true;let primary;
      try{await owner.bounded(original(),3000,'Chrome close timeout');}catch(error){primary=error;}
      try{await cleanup();}catch(error){throw new AggregateError([...(primary?[primary]:[]),error],'Chrome cleanup failed');}
      if(primary)throw primary;};
    return browser;
  }catch(error){try{await cleanup();}catch(cleanupError){throw new AggregateError([error,cleanupError],'Chrome launch cleanup failed');}throw error;}
}
module.exports={admit,acknowledge,browserEnvironment,FLAGS,launchPolicyOutputBrowser};
