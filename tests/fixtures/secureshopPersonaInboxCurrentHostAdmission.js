'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const {execFileSync}=require('node:child_process');
const {createHash}=require('node:crypto');

function privateDirectory(directory){
 const info=fs.lstatSync(directory);
 assert(info.isDirectory()&&!info.isSymbolicLink()&&info.uid===process.getuid()
  &&(info.mode&0o777)===0o700,'Private C31 directory required');
 assert.equal(fs.realpathSync(directory),directory);
}
function admit(env,source,evidence){
 assert.equal(env.SECURESHOP_STANDALONE_PERSONA_CURRENT_HOST_EVIDENCE,'1');
 assert.equal(env.OWASP_AI_GOAT_CURRENT_MAIN_WORKSPACE,source);
 assert.equal(source,process.cwd());
 assert.equal(fs.realpathSync(source),source);
 assert.equal(path.isAbsolute(evidence),true);
 assert.equal(path.resolve(evidence),evidence);
 const run=path.dirname(evidence),parent=path.join(source,'tasks/qualification');
 assert.equal(path.dirname(run),parent);
 assert.match(path.basename(run),/^run-[a-z0-9_]{8}$/);
 assert.equal(evidence,path.join(run,'persona-inbox-rendered'));
 assert.equal(env.SECURESHOP_STANDALONE_PERSONA_EVIDENCE_PATH,evidence);
 for(const directory of [parent,run,evidence])privateDirectory(directory);
 return {run,evidence,outerRuntime:path.join(run,'runtime'),browserRuntime:path.join(evidence,'runtime')};
}
function writePrivate(env,source,evidence,name,value){
 admit(env,source,evidence);
 assert(new Set(['result.json','terminal-wire.json','actor-judge-captures.json',
  'reset-evidence.json','rendered-evidence.json']).has(name));
 const bytes=JSON.stringify(value,null,2);
 assert(Buffer.byteLength(bytes)<=64*1024*1024);
 const file=path.join(evidence,name),descriptor=fs.openSync(file,fs.constants.O_RDWR|fs.constants.O_CREAT
  |fs.constants.O_NOFOLLOW,0o600);
 try{const opened=fs.fstatSync(descriptor),linked=fs.lstatSync(file);
  assert(opened.isFile()&&linked.isFile()&&!linked.isSymbolicLink()&&opened.nlink===1
   &&linked.nlink===1&&opened.uid===process.getuid()&&linked.uid===process.getuid()
   &&(opened.mode&0o777)===0o600&&opened.dev===linked.dev&&opened.ino===linked.ino);
  fs.ftruncateSync(descriptor,0);fs.writeFileSync(descriptor,bytes);fs.fsyncSync(descriptor);
 }finally{fs.closeSync(descriptor);}
}
function browserOptions(env,source,evidence,root,label){
 assert.equal(label,'browser');
 const admitted=admit(env,source,evidence);
 assert.equal(root,admitted.browserRuntime);
 const outer=admitted.outerRuntime,home=path.join(outer,'home'),temporary=path.join(outer,'tmp');
 for(const directory of [outer,home,temporary,root])privateDirectory(directory);
 const expected={TMPDIR:temporary,MAC_CHROMIUM_TMPDIR:temporary,
  XDG_CACHE_HOME:path.join(home,'.cache'),XDG_CONFIG_HOME:path.join(home,'.config')};
 for(const [key,value] of Object.entries(expected))assert.equal(env[key],value);
 for(const directory of [expected.XDG_CACHE_HOME,expected.XDG_CONFIG_HOME]){
  try{privateDirectory(directory);}catch(error){if(error.code!=='ENOENT')throw error;}
 }
 const executable=env.ANALYTICS_BROWSER_EXECUTABLE;
 assert.equal(path.isAbsolute(executable),true);
 assert.equal(fs.realpathSync(executable),executable);
 fs.accessSync(executable,fs.constants.X_OK);
 assert.match(env.ANALYTICS_BROWSER_SHA256,/^[a-f0-9]{64}$/);
 assert.equal(createHash('sha256').update(fs.readFileSync(executable)).digest('hex'),
  env.ANALYTICS_BROWSER_SHA256);
 const script=env.SECURESHOP_BOUND_BROWSER_BIRTH_SCRIPT;
 assert.equal(script,path.join(source,'tests/postgres/secureshop_darwin_browser_birth.py'));
 assert.equal(fs.realpathSync(script),script);
 const python=env.SECURESHOP_BOUND_BROWSER_BIRTH_PYTHON;
 assert.ok(typeof python==='string'&&path.isAbsolute(python));
 assert.equal(fs.realpathSync(python),python);fs.accessSync(python,fs.constants.X_OK);
 assert.match(env.SECURESHOP_BOUND_BROWSER_BIRTH_PYTHON_SHA256,/^[a-f0-9]{64}$/);
 assert.equal(createHash('sha256').update(fs.readFileSync(python)).digest('hex'),
  env.SECURESHOP_BOUND_BROWSER_BIRTH_PYTHON_SHA256);
 return {environment:{PATH:'/usr/bin:/bin',HOME:root,...expected},flags:[
  '--no-sandbox','--disable-background-networking','--disable-component-update',
  '--disable-domain-reliability','--disable-quic',
  '--proxy-server=http://blocked.invalid:9',
  '--proxy-bypass-list=127.0.0.1;localhost;[::1]',
  '--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1, EXCLUDE localhost, EXCLUDE [::1]']};
}
function inspectWorkerBirth(python,script,workerPid,parentPid,executable){
 const raw=execFileSync(python,[script,'--pid',String(workerPid),'--parent',String(parentPid),
  '--executable',executable],{encoding:'utf8',timeout:10000,maxBuffer:4096,
  env:{PATH:'/usr/bin:/bin'}});
 assert.ok(typeof raw==='string'&&Buffer.byteLength(raw)<4096);
 return JSON.parse(raw);
}
function browserIdentity(env,source,evidence,root,label,pid,executableSha256,
 capture=require('./secureshopDarwinBrowserBirth').captureBrowserRecord,
 inspectWorker=inspectWorkerBirth){
 browserOptions(env,source,evidence,root,label);
 assert.ok(Number.isSafeInteger(pid)&&pid>1&&pid!==process.pid);
 assert.equal(executableSha256,env.ANALYTICS_BROWSER_SHA256);
 assert.equal(env.SECURESHOP_BOUND_BROWSER_BIRTH_SCRIPT,
  path.join(source,'tests/postgres/secureshop_darwin_browser_birth.py'));
 const python=env.SECURESHOP_BOUND_BROWSER_BIRTH_PYTHON;
 assert.ok(typeof python==='string'&&path.isAbsolute(python));
 assert.equal(fs.realpathSync(python),python);fs.accessSync(python,fs.constants.X_OK);
 const birthEnv={PATH:'/usr/bin:/bin',
  SECURESHOP_BOUND_BROWSER_BIRTH_SCRIPT:env.SECURESHOP_BOUND_BROWSER_BIRTH_SCRIPT,
  SECURESHOP_BOUND_BROWSER_BIRTH_PYTHON:python};
 const record=capture({root:source,kind:'c31_persona_inbox_browser',pid,
  executablePath:env.ANALYTICS_BROWSER_EXECUTABLE,executableSha256,env:birthEnv});
 assert.equal(record?.schemaVersion,2);
 assert.equal(record?.processes?.length,1);
 const birth=record.processes[0];
 assert.equal(birth.kind,'c31_persona_inbox_browser');
 assert.equal(birth.pid,pid);assert.equal(birth.parentPid,process.pid);
 assert.equal(birth.uid,process.getuid());
 assert.ok(Number.isSafeInteger(birth.pgid)&&birth.pgid>1&&birth.pgid!==pid);
 assert.equal(birth.sessionId,birth.pgid);
 assert.deepEqual(Object.keys(birth.birth||{}).sort(),['0','1']);
 assert.ok(birth.birth.every((value,index)=>Number.isSafeInteger(value)&&value>=0
  &&(index!==0||value>0)&&(index!==1||value<1000000)));
 assert.equal(birth.executablePath,env.ANALYTICS_BROWSER_EXECUTABLE);
 assert.equal(birth.executableSha256,executableSha256);
 const workerPid=process.pid,parentPid=process.ppid,workerExecutable=process.execPath;
 assert.ok(Number.isSafeInteger(parentPid)&&parentPid>1&&parentPid!==workerPid);
 assert.equal(workerExecutable,path.join(source,'tasks/runtime/node/node_modules/node/bin/node'));
 assert.equal(fs.realpathSync(workerExecutable),workerExecutable);
 const worker=inspectWorker(python,env.SECURESHOP_BOUND_BROWSER_BIRTH_SCRIPT,
  workerPid,parentPid,workerExecutable);
 assert.deepEqual(Object.keys(worker).sort(),
  ['birth','executablePath','parentPid','pgid','pid','sessionId','uid']);
 assert.equal(worker.pid,workerPid);assert.equal(worker.parentPid,parentPid);
 assert.equal(worker.uid,process.getuid());
 assert.equal(worker.pgid,birth.pgid);assert.equal(worker.sessionId,birth.sessionId);
 assert.deepEqual(Object.keys(worker.birth||{}).sort(),['0','1']);
 assert.ok(worker.birth.every((value,index)=>Number.isSafeInteger(value)&&value>=0
  &&(index!==0||value>0)&&(index!==1||value<1000000)));
 assert.equal(worker.executablePath,workerExecutable);
 const workerRecord={schemaVersion:2,processes:[{kind:'c31_persona_inbox_worker',...worker,
  executableSha256:createHash('sha256').update(fs.readFileSync(workerExecutable)).digest('hex')}]};
 return {record,workerRecord,identity:{pid,pgid:birth.pgid,sessionId:birth.sessionId,uid:birth.uid,
  qualificationPid:birth.pgid,qualificationPgid:birth.pgid,
  qualificationSessionId:birth.sessionId,workerPid:process.pid}};
}
module.exports={admit,writePrivate,browserOptions,browserIdentity};
