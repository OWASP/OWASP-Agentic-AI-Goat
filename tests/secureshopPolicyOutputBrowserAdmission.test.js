'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),
 path=require('node:path'),vm=require('node:vm'),crypto=require('node:crypto'),{EventEmitter}=require('node:events');
const ROOT=path.resolve(__dirname,'..'),run=path.join(ROOT,'tasks/qualification/run-1234abcd'),
 evidence=path.join(run,'standalone-ssrf-rendered'),runtime=path.join(evidence,'runtime');
function setup({failure=null}={}){
 const events=[],files=new Map(),child=new EventEmitter();child.pid=456;
 const env={DVAIA_CURRENT_MAIN_WORKSPACE:ROOT,PG_TEST_DISPOSABLE:'yes',
  SECURESHOP_POLICY_OUTPUT_TEST_NO_SANDBOX:'1',SECURESHOP_POLICY_OUTPUT_BROWSER_NATIVE:'1',
  SECURESHOP_STANDALONE_SSRF_RENDERED_NATIVE:'1',SECURESHOP_POLICY_OUTPUT_REPOSITORY_EVIDENCE:'1',
  SECURESHOP_STANDALONE_SSRF_RENDERED_EVIDENCE_PATH:path.join(evidence,'result.json'),
  SECURESHOP_POLICY_OUTPUT_BROWSER_RECORD_PATH:path.join(evidence,'policy-output-browser.json'),
  SECURESHOP_POLICY_OUTPUT_BROWSER_ACK_PATH:path.join(evidence,'policy-output-browser-ack.json'),
  SECURESHOP_BOUND_BROWSER_BIRTH_SCRIPT:path.join(ROOT,'tests/postgres/secureshop_darwin_browser_birth.py'),
  SECURESHOP_BOUND_BROWSER_BIRTH_PYTHON:'/controlled/python',ANALYTICS_BROWSER_EXECUTABLE:'/controlled/chrome',
  MAC_CHROMIUM_TMPDIR:path.join(run,'runtime/tmp'),XDG_CACHE_HOME:path.join(run,'runtime/home/.cache'),
  XDG_CONFIG_HOME:path.join(run,'runtime/home/.config'),
  ANALYTICS_BROWSER_SHA256:crypto.createHash('sha256').update('binary').digest('hex')};
 let mode=0o700,uid=process.getuid(),link=false,missingLeaves=false;
 const stat=()=>({isDirectory:()=>true,isFile:()=>true,isSymbolicLink:()=>link,uid,mode});
 const owner={launchOwnedAnalyticsBrowser:async()=>{events.push('default');return 'default';},
  bounded:p=>p,observeBrowserEndpoint:async()=> 'ws://127.0.0.1:12345/browser',
  retireChild:async()=>events.push('retire'),profileDisposition:()=>({legacy:true})};
 const fakefs={constants:{X_OK:1},realpathSync:v=>v,lstatSync:n=>{
  if(missingLeaves&&['.cache','.config'].includes(path.basename(n)))throw Object.assign(Error('absent'),{code:'ENOENT'});
  return stat();
 },accessSync:()=>{},
  readFileSync:()=>Buffer.from('binary'),mkdirSync:()=>events.push('profile'),
  writeFileSync:(n,v)=>{files.set(n,v);},appendFileSync:()=>{},promises:{
   writeFile:async(n,v,o)=>{assert.equal(o.flag,'wx');files.set(n,v);},
   rename:async(a,b)=>files.set(b,files.get(a)),
   readFile:async n=>{
    if(n===env.SECURESHOP_POLICY_OUTPUT_BROWSER_RECORD_PATH)return files.get(n);
    events.push('ack');
    if(failure==='ack')throw Error('ACK invalid');
    return JSON.stringify({schemaVersion:1,parentPid:123,browserPid:456,profile:path.join(runtime,'browser-profile'),
     recordSha256:crypto.createHash('sha256').update(files.get(env.SECURESHOP_POLICY_OUTPUT_BROWSER_RECORD_PATH)).digest('hex')});
   },lstat:async()=>({...stat(),mode:0o600})}};
 const filename=path.join(__dirname,'fixtures/secureshopPolicyOutputBrowserAdmission.js');
 const real=require('node:module').createRequire(filename),module={exports:{}};
 const overrides={'node:fs':fakefs,'./secureshopAnalyticsBrowserOwner':owner,
  './secureshopDarwinBrowserBirth':{captureBrowserRecord:()=>{
   events.push('birth');
   if(failure==='birth')throw Error('birth unavailable');
   return {schemaVersion:2,processes:[{pid:456,parentPid:123,pgid:failure==='group'?999:123,
    sessionId:123,uid:process.getuid()}]};}},
  './browserProcessOwnership':{captureBrowserProcessIdentity:()=>{throw Error('ps forbidden');}},
  'node:child_process':{spawn:(_exe,args,options)=>{
   assert.equal(options.detached,false);assert.ok(args.includes('--no-sandbox'));
   assert.deepEqual(options.env,{PATH:'/usr/bin:/bin',HOME:runtime,TMPDIR:runtime,
    MAC_CHROMIUM_TMPDIR:env.MAC_CHROMIUM_TMPDIR,XDG_CACHE_HOME:env.XDG_CACHE_HOME,XDG_CONFIG_HOME:env.XDG_CONFIG_HOME});
   events.push('spawn');queueMicrotask(()=>child.emit('spawn'));return child;},
   execFileSync:()=>{throw Error('ps forbidden');},spawnSync:()=>{throw Error('ps forbidden');}},
  puppeteer:{defaultArgs:async options=>options.args,connect:async()=>{
   events.push('connect');if(failure==='connect')throw Error('connect failed');
   return {close:async()=>events.push('close')};}}};
 vm.compileFunction(fs.readFileSync(filename,'utf8'),['require','module','process'],{filename})(
  n=>Object.hasOwn(overrides,n)?overrides[n]:real(n),module,
  {env,cwd:()=>ROOT,pid:123,getuid:()=>process.getuid(),kill:()=>{throw Object.assign(Error('gone'),{code:'ESRCH'});}});
 return {api:module.exports,env,events,files,setMode:v=>mode=v,setUid:v=>uid=v,setLink:v=>link=v,
  setMissingLeaves:v=>missingLeaves=v};
}
test('V27 browser forwards only validated original Chromium/XDG roots, not credentials or inspector FD',()=>{
 const s=setup();
 s.env.SECURESHOP_PROCESS_INSPECTOR_FD='999';s.env.AUTH_TOKEN='never-forward';
 const child=s.api.browserEnvironment(s.env,runtime);
 assert.deepEqual(Object.keys(child).sort(),['PATH','HOME','TMPDIR','MAC_CHROMIUM_TMPDIR','XDG_CACHE_HOME','XDG_CONFIG_HOME'].sort());
 assert.equal(child.HOME,runtime);
 for(const key of ['MAC_CHROMIUM_TMPDIR','XDG_CACHE_HOME','XDG_CONFIG_HOME']){
  assert.equal(child[key],s.env[key]);
  assert.throws(()=>s.api.browserEnvironment({...s.env,[key]:'/outside'},runtime));
  assert.throws(()=>s.api.browserEnvironment({...s.env,[key]:undefined},runtime));
 }
 s.setMissingLeaves(true);assert.doesNotThrow(()=>s.api.browserEnvironment(s.env,runtime));
 s.setLink(true);assert.throws(()=>s.api.browserEnvironment(s.env,runtime));
});
test('V27 admission is exact repository-only and other default remains unchanged',async()=>{
 const s=setup();s.api.admit(s.env,runtime);
 for(const key of ['SECURESHOP_POLICY_OUTPUT_BROWSER_NATIVE','SECURESHOP_STANDALONE_SSRF_RENDERED_NATIVE',
  'SECURESHOP_POLICY_OUTPUT_REPOSITORY_EVIDENCE'])assert.throws(()=>s.api.admit({...s.env,[key]:'0'},runtime));
 assert.throws(()=>s.api.admit(s.env,path.join(run,'foreign')));
 s.setMode(0o755);assert.throws(()=>s.api.admit(s.env,runtime));s.setMode(0o700);
 s.setUid(process.getuid()+1);assert.throws(()=>s.api.admit(s.env,runtime));s.setUid(process.getuid());
 s.setLink(true);assert.throws(()=>s.api.admit(s.env,runtime));
 delete s.env.SECURESHOP_POLICY_OUTPUT_TEST_NO_SANDBOX;
 assert.equal(await s.api.launchPolicyOutputBrowser(runtime,'browser'),'default');
 assert.ok(!s.api.FLAGS.some(v=>/disable-web-security|ignore-certificate/.test(v)));
});
test('V27 same-group child is acknowledged before connection and retires on close',async()=>{
 const s=setup(),browser=await s.api.launchPolicyOutputBrowser(runtime,'browser');
 assert.ok(s.events.indexOf('ack')<s.events.indexOf('connect'));
 assert.ok(s.events.indexOf('birth')<s.events.indexOf('ack'));
 const legacy=JSON.parse(s.files.get(path.join(runtime,'browser-process.json')));
 assert.deepEqual(Object.fromEntries(['pid','pgid','sessionId','uid','qualificationPid','qualificationPgid',
  'qualificationSessionId','workerPid'].map(k=>[k,legacy[k]])),
  {pid:456,pgid:123,sessionId:123,uid:process.getuid(),qualificationPid:123,
   qualificationPgid:123,qualificationSessionId:123,workerPid:123});
 await browser.close();await browser.close();
 assert.equal(s.events.filter(v=>v==='retire').length,1);
});
test('V27 unavailable or foreign birth retires child without fabricated ownership journal',async()=>{
 for(const failure of ['birth','group']){
  const s=setup({failure});
  await assert.rejects(s.api.launchPolicyOutputBrowser(runtime,'browser'));
  assert.ok(s.events.includes('retire'));
  assert.ok(!s.events.includes('ack')&&!s.events.includes('connect'));
  assert.ok(!s.files.has(path.join(runtime,'browser-process.json')));
 }
});
test('V27 postspawn ACK and connection failures retire owned child preserving primary',async()=>{
 for(const failure of ['ack','connect']){
  const s=setup({failure});
  await assert.rejects(s.api.launchPolicyOutputBrowser(runtime,'browser'),failure==='ack'?/ACK invalid/:/connect failed/);
  assert.ok(s.events.includes('spawn')&&s.events.includes('retire'));
  if(failure==='ack')assert.ok(!s.events.includes('connect'));
 }
});
test('whole V27 fixture parses before any native admission',()=>{
 const filename=path.join(__dirname,'postgres/secureshopStandaloneSsrfRendered.integration.test.js');
 assert.doesNotThrow(()=>vm.compileFunction(fs.readFileSync(filename,'utf8'),['require','module','exports','__filename','__dirname'],{filename}));
});
