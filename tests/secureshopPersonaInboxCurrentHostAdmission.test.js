'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const {randomBytes,createHash}=require('node:crypto');
const vm=require('node:vm');
const admission=require('./fixtures/secureshopPersonaInboxCurrentHostAdmission');
const source=path.resolve(__dirname,'..');

test('C31 actual mail production options bind canonical publication modes before assessment construction',()=>{
 const file=path.join(source,'tests/postgres/secureshopStandalonePersonaInboxRendered.integration.test.js');
 const text=fs.readFileSync(file,'utf8');
 const matches=[...text.matchAll(/assessmentDependencies:(\{\.\.\.grading\.assessmentDependencies,[^\n]+\}),mode:'vuln'\}\);/g)];
 assert.equal(matches.length,1,'exact C31 production options expression required');
 const judge=async()=>{},modeRepository={getEvaluationScope:async()=>({mode:'vuln'})};
 const grading={assessmentDependencies:{receipts:{beginEvaluation:async()=>{},recordVerdict:async()=>{}},
  progress:{getGeneration:async()=>0},personaBindings:{capture:async()=>({})}}};
 const selected=vm.runInNewContext('('+matches[0][1]+')',{grading,judge,modeRepository});
 assert.equal(selected.judge,judge);
 assert.equal(selected.publicationModes,modeRepository);
 assert.equal(typeof selected.publicationModes.getEvaluationScope,'function');
 const construct=require('../server/services/secureshopMailHtmlInjectionAssessment').createMailHtmlInjectionAssessment;
 const noop=async()=>{},dependencies={...selected,
  identityPool:{query:noop},agentsPool:{query:noop},launches:{assertCurrent:noop},
  conversationRepository:{getBoundSession:noop,acquireBoundSession:noop},
  coordinator:{run:noop},journal:{claim:noop,complete:noop,markUncertain:noop},
  personaAuthority:{capture:noop},savedMailEvidence:{readHeader:noop},
  originalReader:{read:noop},browserQualification:{qualifyInjection:noop,readComponent:noop},
  resolveRetainedBinding:noop,qualifyModel:noop};
 assert.throws(()=>construct({...dependencies,publicationModes:undefined}),
  /Canonical agent mail HTML assessment dependencies required/);
 assert.doesNotThrow(()=>construct(dependencies));
});
function child(env){
 const vm=require('node:vm'),{createRequire}=require('node:module');
 const file=path.join(source,'tests/postgres/secureshopStandalonePersonaInboxRendered.integration.test.js');
 const realRequire=createRequire(file),output={exports:{}};
 vm.runInNewContext(fs.readFileSync(file,'utf8'),{module:output,__dirname:path.dirname(file),URL,Buffer,
  process:{env,cwd:()=>source,getuid:()=>process.getuid()},
  require:name=>name==='node:test'?()=>{}:realRequire(name)});
 return output.exports;
}
function childEnvironment(env){
 const result={...env,PG_TEST_DISPOSABLE:'yes',LIVE_OLLAMA_TEST:'1',LAB_MODE:'vuln'};
 for(const store of ['identity','secureshop_agents','secureshop_review','secureshop'])
  for(const role of ['RUNTIME','MIGRATION']){
   const name={identity:'IDENTITY',secureshop_agents:'AGENTS',secureshop_review:'REVIEW',
    secureshop:'COMMERCE'}[store];
   result[`PG_SECURESHOP_STANDALONE_PERSONA_${name}_${role}_URL`]=
    `postgresql://dvaia_${store}_${role.toLowerCase()}@127.0.0.1:5432/owasp_ai_goat_test_agent_host_abcdef123456_${store}`;
  }
 return result;
}

async function owned(callback){
 const run=path.join(source,'tasks/qualification',`run-${randomBytes(4).toString('hex')}`);
 const evidence=path.join(run,'persona-inbox-rendered'),outer=path.join(run,'runtime');
 for(const directory of [run,evidence,outer,path.join(outer,'home'),path.join(outer,'tmp'),
   path.join(evidence,'runtime')])fs.mkdirSync(directory,{mode:0o700});
 const executable=path.join(source,'tasks/runtime/node/node_modules/node/bin/node');
 const env={SECURESHOP_STANDALONE_PERSONA_CURRENT_HOST_EVIDENCE:'1',
  SECURESHOP_STANDALONE_PERSONA_EVIDENCE_PATH:evidence,OWASP_AI_GOAT_CURRENT_MAIN_WORKSPACE:source,
  TMPDIR:path.join(outer,'tmp'),MAC_CHROMIUM_TMPDIR:path.join(outer,'tmp'),
  XDG_CACHE_HOME:path.join(outer,'home/.cache'),XDG_CONFIG_HOME:path.join(outer,'home/.config'),
  ANALYTICS_BROWSER_EXECUTABLE:executable,
  ANALYTICS_BROWSER_SHA256:createHash('sha256').update(fs.readFileSync(executable)).digest('hex'),
  SECURESHOP_BOUND_BROWSER_BIRTH_SCRIPT:path.join(source,'tests/postgres/secureshop_darwin_browser_birth.py'),
  SECURESHOP_BOUND_BROWSER_BIRTH_PYTHON:executable,
  SECURESHOP_BOUND_BROWSER_BIRTH_PYTHON_SHA256:createHash('sha256').update(fs.readFileSync(executable)).digest('hex')};
 try{return await callback({run,evidence,outer,env});}
 finally{fs.rmSync(run,{recursive:true,force:false});}
}

test('C31 current-host child admits only its exact private repository evidence directory',()=>owned(({run,evidence,env})=>{
 assert.equal(admission.admit(env,source,evidence).run,run);
 for(const changed of [
  {env:{...env,SECURESHOP_STANDALONE_PERSONA_CURRENT_HOST_EVIDENCE:'0'}},
  {env:{...env,SECURESHOP_STANDALONE_PERSONA_EVIDENCE_PATH:path.join(run,'other')}},
  {env:{...env,OWASP_AI_GOAT_CURRENT_MAIN_WORKSPACE:path.join(source,'other')}},
  {evidence:path.join(run,'other')},
  {evidence:`${evidence}/../persona-inbox-rendered`},
 ])assert.throws(()=>admission.admit(changed.env||env,source,changed.evidence||evidence));
 fs.chmodSync(evidence,0o755);
 assert.throws(()=>admission.admit(env,source,evidence));
 fs.chmodSync(evidence,0o700);
 const alias=path.join(run,'alias');fs.symlinkSync(evidence,alias);
 assert.throws(()=>admission.admit({...env,SECURESHOP_STANDALONE_PERSONA_EVIDENCE_PATH:alias},source,alias));
}));

test('C31 current-host writer bounds names and preserves one owned private file',()=>owned(({evidence,env})=>{
 admission.writePrivate(env,source,evidence,'result.json',{status:'running'});
 admission.writePrivate(env,source,evidence,'result.json',{status:'passed'});
 const file=path.join(evidence,'result.json');
 assert.deepEqual(JSON.parse(fs.readFileSync(file)),{status:'passed'});
 assert.equal(fs.lstatSync(file).mode&0o777,0o600);
 assert.throws(()=>admission.writePrivate(env,source,evidence,'../escape.json',{}));
 fs.renameSync(file,path.join(evidence,'prior.json'));
 fs.symlinkSync(path.join(source,'AGENTS.md'),file);
 assert.throws(()=>admission.writePrivate(env,source,evidence,'result.json',{}));
}));

test('the actual C31 child marker selects admitted repository evidence and its private writer',()=>owned(({evidence,env})=>{
 const current=child(childEnvironment(env));
 assert.equal(current.admission().evidence,evidence);
 assert.equal(current.admission().currentHost,true);
 current.privateWrite(evidence,'result.json',{status:'running'});
 assert.deepEqual(JSON.parse(fs.readFileSync(path.join(evidence,'result.json'))),{status:'running'});
 const legacy=child(childEnvironment({...env,
  SECURESHOP_STANDALONE_PERSONA_CURRENT_HOST_EVIDENCE:'0'}));
 assert.throws(()=>legacy.admission(),/AssertionError/);
}));

test('C31 child writer propagates write and fsync failures and closes its descriptor',()=>owned(({evidence,env})=>{
 const current=child(childEnvironment(env));
 for(const method of ['writeFileSync','fsyncSync']){
  const original=fs[method],close=fs.closeSync,primary=Object.assign(new Error(`controlled ${method} failure`),{code:'EIO'});
  let descriptor=null,closes=0;
  try{
   fs[method]=function(...args){if(typeof args[0]==='number'){descriptor=args[0];throw primary;}
    return original.apply(this,args);};
   fs.closeSync=function(value){if(value===descriptor)closes++;return close.call(this,value);};
   assert.throws(()=>current.privateWrite(evidence,method==='writeFileSync'?'result.json':'terminal-wire.json',{}),
    error=>error===primary);
  }finally{fs[method]=original;fs.closeSync=close;}
  assert.equal(closes,1);
  assert.throws(()=>fs.fstatSync(descriptor),{code:'EBADF'});
 }
}));

test('C31 browser options use the owned outer temporary and XDG roots with exact executable',()=>owned(({evidence,outer,env})=>{
 const root=path.join(evidence,'runtime');
 const selected=admission.browserOptions(env,source,evidence,root,'browser');
 assert.equal(selected.environment.HOME,root);
 assert.equal(selected.environment.MAC_CHROMIUM_TMPDIR,path.join(outer,'tmp'));
 assert.equal(selected.environment.XDG_CACHE_HOME,path.join(outer,'home/.cache'));
 assert.equal(selected.flags.filter(flag=>flag==='--no-sandbox').length,1);
 for(const changed of [
  {MAC_CHROMIUM_TMPDIR:'/private/tmp'},
  {XDG_CACHE_HOME:'/private/tmp'},
  {ANALYTICS_BROWSER_SHA256:'0'.repeat(64)},
  {SECURESHOP_BOUND_BROWSER_BIRTH_PYTHON_SHA256:'0'.repeat(64)},
 ])assert.throws(()=>admission.browserOptions({...env,...changed},source,evidence,root,'browser'));
 assert.throws(()=>admission.browserOptions(env,source,evidence,root,'other'));
 assert.throws(()=>admission.browserOptions(env,source,evidence,outer,'browser'));
}));

test('C31 Darwin birth projection joins proved worker and Chrome group before journaling',()=>owned(({evidence,env})=>{
 const root=path.join(evidence,'runtime'),pid=process.pid+10000;
 const admitted={...env,
  SECURESHOP_BOUND_BROWSER_BIRTH_SCRIPT:path.join(source,'tests/postgres/secureshop_darwin_browser_birth.py')};
 const browser={kind:'c31_persona_inbox_browser',pid,parentPid:process.pid,uid:process.getuid(),
  pgid:process.pid,sessionId:process.pid,birth:[100,200],
  executablePath:env.ANALYTICS_BROWSER_EXECUTABLE,executableSha256:env.ANALYTICS_BROWSER_SHA256};
 const worker={pid:process.pid,parentPid:process.ppid,uid:process.getuid(),
  pgid:process.pid,sessionId:process.pid,birth:[90,100],executablePath:process.execPath};
 const capture=()=>({schemaVersion:2,processes:[browser]});
 const inspect=()=>worker;
 const proved=admission.browserIdentity(admitted,source,evidence,root,'browser',pid,
  env.ANALYTICS_BROWSER_SHA256,capture,inspect);
 assert.equal(proved.identity.workerPid,process.pid);
 assert.equal(proved.identity.qualificationPgid,process.pid);
 assert.deepEqual(proved.record.processes[0],browser);
 assert.deepEqual(proved.workerRecord.processes[0].birth,worker.birth);
 for(const changed of [
  {capture:()=>({schemaVersion:2,processes:[{...browser,parentPid:process.pid+1}]})},
  {capture:()=>({schemaVersion:2,processes:[{...browser,uid:process.getuid()+1}]})},
  {capture:()=>({schemaVersion:2,processes:[{...browser,birth:[0,200]}]})},
  {capture:()=>({schemaVersion:2,processes:[{...browser,executablePath:'wrong'}]})},
  {inspect:()=>({...worker,pgid:process.pid+1})},
  {inspect:()=>({...worker,sessionId:process.pid+1})},
  {inspect:()=>({...worker,parentPid:process.ppid+1})},
 ])assert.throws(()=>admission.browserIdentity(admitted,source,evidence,root,'browser',pid,
  env.ANALYTICS_BROWSER_SHA256,changed.capture||capture,changed.inspect||inspect));
 assert.throws(()=>admission.browserIdentity({...admitted,
  SECURESHOP_BOUND_BROWSER_BIRTH_SCRIPT:'/private/tmp/other.py'},source,evidence,root,'browser',pid,
  env.ANALYTICS_BROWSER_SHA256,capture,inspect));
}));

test('the actual browser owner receives C31 options before any process launch',async()=>{
 await owned(async({evidence,outer,env})=>{
  const vm=require('node:vm'),{createRequire}=require('node:module');
  const file=path.join(source,'tests/fixtures/secureshopAnalyticsBrowserOwner.js');
  const realRequire=createRequire(file),output={exports:{}};let requested,spawned;
  vm.runInNewContext(fs.readFileSync(file,'utf8'),{module:output,
   process:{env,cwd:()=>source,getuid:()=>process.getuid()},
   require:name=>name==='puppeteer'?{defaultArgs:async value=>{requested=value;return value.args;}}
    :name==='node:child_process'?{spawn:(...args)=>{spawned=args;throw Error('controlled stop before spawn');}}
    :realRequire(name)});
  await assert.rejects(output.exports.launchOwnedAnalyticsBrowser(path.join(evidence,'runtime'),'browser',
   {personaInboxCurrentHost:true}),/controlled stop before spawn/);
  assert.equal(requested.args.filter(value=>value==='--no-sandbox').length,1);
  assert.equal(spawned[2].env.MAC_CHROMIUM_TMPDIR,path.join(outer,'tmp'));
  assert.equal(spawned[2].env.XDG_CONFIG_HOME,path.join(outer,'home/.config'));
 });
});

test('the actual C31 browser owner journals only the proved Darwin birth, never the ps path',async()=>{
 await owned(async({evidence,env})=>{
  const {EventEmitter}=require('node:events'),{createRequire}=require('node:module');
  const file=path.join(source,'tests/fixtures/secureshopAnalyticsBrowserOwner.js');
  const realRequire=createRequire(file),output={exports:{}};
  const runtime=path.join(evidence,'runtime'),pid=process.pid+10000;
  const identity={pid,pgid:process.pid,sessionId:process.pid,uid:process.getuid(),
   qualificationPid:process.pid,qualificationPgid:process.pid,
   qualificationSessionId:process.pid,workerPid:process.pid};
  const browser={schemaVersion:2,processes:[{kind:'c31_persona_inbox_browser',pid,
   parentPid:process.pid,pgid:process.pid,sessionId:process.pid,uid:process.getuid(),
   birth:[100,200],executablePath:env.ANALYTICS_BROWSER_EXECUTABLE,
   executableSha256:env.ANALYTICS_BROWSER_SHA256}]};
  const worker={schemaVersion:2,processes:[{kind:'c31_persona_inbox_worker',pid:process.pid}]};
  let captured=0,spawned=0;
  const child=new EventEmitter();child.pid=pid;child.stderr=new EventEmitter();
  child.exitCode=null;child.signalCode=null;
  child.kill=()=>{child.exitCode=0;child.emit('exit',0,null);return true;};
  vm.runInNewContext(fs.readFileSync(file,'utf8'),{module:output,process:{...process,env,
   cwd:()=>source,kill:process.kill.bind(process),getuid:()=>process.getuid()},Buffer,setTimeout,clearTimeout,
   require:name=>name==='puppeteer'?{defaultArgs:async()=>[],connect:async()=>({close:async()=>{}})}
    :name==='node:child_process'?{spawn:()=>{spawned++;setImmediate(()=>{
      child.emit('spawn');child.stderr.emit('data',Buffer.from('DevTools listening on ws://127.0.0.1:1234/devtools/browser/test\n'));
     });return child;}}
    :name==='./secureshopPersonaInboxCurrentHostAdmission'?{
      browserOptions:admission.browserOptions,browserIdentity:()=>{captured++;return {identity,record:browser,workerRecord:worker};}}
    :name==='./browserProcessOwnership'?{captureBrowserProcessIdentity:()=>{throw Error('ps path forbidden');}}
    :realRequire(name),__dirname:path.dirname(file)});
  const instance=await output.exports.launchOwnedAnalyticsBrowser(runtime,'browser',
   {personaInboxCurrentHost:true});
  assert.equal(spawned,1);assert.equal(captured,1);
  assert.deepEqual(JSON.parse(fs.readFileSync(path.join(runtime,'browser-process.json'))),
   {...identity,profile:path.join(runtime,'browser-profile'),executableSha256:env.ANALYTICS_BROWSER_SHA256});
  assert.deepEqual(JSON.parse(fs.readFileSync(path.join(runtime,'browser-birth.json'))),
   {browser,worker});
  await instance.close();
 });
});

test('C31 browser birth denial leaves no process or birth journal',async()=>{
 await owned(async({evidence,env})=>{
  const {EventEmitter}=require('node:events'),{createRequire}=require('node:module');
  const file=path.join(source,'tests/fixtures/secureshopAnalyticsBrowserOwner.js');
  const realRequire=createRequire(file),output={exports:{}};
  const runtime=path.join(evidence,'runtime'),pid=process.pid+10001;
  const child=new EventEmitter();child.pid=pid;child.stderr=new EventEmitter();
  child.exitCode=null;child.signalCode=null;
  child.kill=()=>{child.exitCode=0;child.emit('exit',0,null);return true;};
  vm.runInNewContext(fs.readFileSync(file,'utf8'),{module:output,process:{...process,env,
   cwd:()=>source,kill:process.kill.bind(process),getuid:()=>process.getuid()},Buffer,setTimeout,clearTimeout,
   require:name=>name==='puppeteer'?{defaultArgs:async()=>[],connect:async()=>{throw Error('connect forbidden');}}
    :name==='node:child_process'?{spawn:()=>{setImmediate(()=>child.emit('spawn'));return child;}}
    :name==='./secureshopPersonaInboxCurrentHostAdmission'?{
      browserOptions:admission.browserOptions,browserIdentity:()=>{throw Error('controlled birth denial');}}
    :name==='./browserProcessOwnership'?{captureBrowserProcessIdentity:()=>{throw Error('ps path forbidden');}}
    :realRequire(name),__dirname:path.dirname(file)});
  await assert.rejects(output.exports.launchOwnedAnalyticsBrowser(runtime,'browser',
   {personaInboxCurrentHost:true}),/controlled birth denial/);
  assert.equal(fs.existsSync(path.join(runtime,'browser-birth.json')),false);
  assert.equal(fs.existsSync(path.join(runtime,'browser-process.json')),false);
 });
});
