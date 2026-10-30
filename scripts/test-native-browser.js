#!/usr/bin/env node
'use strict';
// Separate native browser qualification. This is not a unit sandbox or model gate.
const fs=require('node:fs'),os=require('node:os'),path=require('node:path'),crypto=require('node:crypto');
const {spawn,execFileSync}=require('node:child_process');
async function runOwnedBuild(command,args,{cwd,env,logPath,timeoutMs=120000}) {
 const fd=fs.openSync(logPath,'wx',0o600);let child,spawned=false,interrupted=null,timedOut=false,timer,closed=false,killSent=false;
 const kill=()=>{if(spawned&&!killSent){if(!Number.isSafeInteger(child.pid)||child.pid<=1)throw Error('Unsafe build PID');try{process.kill(-child.pid,'SIGKILL');killSent=true;}catch(e){if(e.code!=='ESRCH')throw e;killSent=true;}}};
 let cleanupError;
 const cancel=signal=>{interrupted=signal;try{kill();}catch(e){cleanupError=e;}};
 const term=()=>cancel('SIGTERM'),int=()=>cancel('SIGINT');
 process.on('SIGTERM',term);process.on('SIGINT',int);
 let outcome;
 try{
  outcome=await new Promise(resolve=>{
   child=spawn(command,args,{cwd,env,detached:true,stdio:['ignore',fd,fd]});
   child.once('spawn',()=>{spawned=true;if(interrupted)cancel(interrupted);});
   child.once('close',()=>{closed=true;});
   child.once('error',error=>resolve({error:error.code||'BUILD_SPAWN_FAILED'}));
   child.once('exit',(code,signal)=>resolve({code,signal}));
   timer=setTimeout(()=>{timedOut=true;try{kill();}catch(e){cleanupError=e;}resolve({error:'BUILD_DEADLINE'});},timeoutMs);
  });
  clearTimeout(timer);try{kill();}catch(e){cleanupError=e;}
  const deadline=Date.now()+5000;
  while(!closed&&Date.now()<deadline)await new Promise(resolve=>setTimeout(resolve,50));
  let absent=!spawned,lastProbeError;
  while(!absent&&Date.now()<deadline){try{process.kill(-child.pid,0);lastProbeError=null;}catch(e){if(e.code==='ESRCH')absent=true;else lastProbeError=e;}if(!absent)await new Promise(resolve=>setTimeout(resolve,50));}
  if(!absent&&lastProbeError)cleanupError ||= lastProbeError;
  const receipt={...outcome,pid:spawned?child.pid:null,groupAbsent:absent,closed,timedOut,interrupted,cleanupError:cleanupError?.message||null};
  if(outcome.code!==0||outcome.error||!absent||!closed||timedOut||interrupted||cleanupError){const error=Error('Owned build failed or retirement unproven');error.buildReceipt=receipt;throw error;}
  return receipt;
 }finally{clearTimeout(timer);process.off('SIGTERM',term);process.off('SIGINT',int);fs.closeSync(fd);}
}
const inventory=require('./lib/native-browser-suites');
const adminBundle=process.argv.length===3&&process.argv[2]==='--admin-bundle';
const secureshop=process.argv.length===3&&process.argv[2]==='--secureshop';
const secureshopE2e=process.argv.length===3&&process.argv[2]==='--secureshop-e2e';
const xss=process.argv.length===3&&process.argv[2]==='--xss';
if(process.platform!=='darwin'||!(process.argv.length===2||adminBundle||secureshop||xss||secureshopE2e))throw Error('Native browser qualification requires Darwin and only --admin-bundle, --secureshop --xss or --secureshop-e2e modes');
const secureshopE2eEnvironment=secureshopE2e?require('./lib/secureshop-e2e-postgres-admission').admitSecureShopE2ePostgres(process.env):null;
const suites=secureshopE2e?inventory.secureshopE2e:adminBundle?inventory.adminBundle:secureshop?inventory.secureshop:xss?inventory.xss:inventory.defaults;
const qualificationScope=secureshopE2e?'Four fixed SecureShop E2E/ReviewCard controlled-fixture browser flows; no genuine model credit':xss?'Four fixed XSS native browser suites; controlled Judge/evidence, no genuine model credit':secureshop?'Five fixed SecureShop native browser suites; controlled providers, no genuine objective credit':adminBundle?'Fixed admin production bundle native browser suite; no actual-model or installed application qualification':'Eight closed native browser suites; no actual-model or installed application qualification';
const source=fs.realpathSync(path.resolve(__dirname,'..'));
if(fs.realpathSync(process.cwd())!==source)throw Error('Run from the canonical main source root');
(async()=>{
const resolvedExecutable=await require('puppeteer').executablePath();
if(typeof resolvedExecutable!=='string'||!path.isAbsolute(resolvedExecutable)||resolvedExecutable.includes('\0'))throw Error('Invalid installed browser executable path');
const executable=fs.realpathSync(resolvedExecutable);
const binary=fs.lstatSync(executable);if(!binary.isFile()||binary.isSymbolicLink())throw Error('Invalid installed browser executable');fs.accessSync(executable,fs.constants.X_OK);
const sha=file=>crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
const sourcePins=Object.fromEntries([...suites.map(row=>row.file),'scripts/test-native-browser.js','scripts/lib/native-browser-suites.js',...(secureshopE2e?['tests/secureshop/fixtures/e2eServer.js','tests/secureshop/vuln/_fixture.js','client/vite.config.mjs','scripts/lib/isolated-test-boundary.js','scripts/lib/secureshop-e2e-postgres-admission.js']:[])].map(file=>[file,sha(path.join(source,file))]));
const directory=fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(),'owasp-ai-goat-native-browser-')));fs.chmodSync(directory,0o700);
const owned={};for(const key of ['home','tmp','logs','cache','config','data']){owned[key]=path.join(directory,key);fs.mkdirSync(owned[key],{mode:0o700});}
const env={PATH:path.dirname(process.execPath),HOME:owned.home,TMPDIR:owned.tmp,TMP:owned.tmp,TEMP:owned.tmp,LOGS_DIR:owned.logs,
 XDG_CACHE_HOME:owned.cache,XDG_CONFIG_HOME:owned.config,XDG_DATA_HOME:owned.data,NODE_ENV:'test',AI_PROVIDER:'mock',AWS_EC2_METADATA_DISABLED:'true',PUPPETEER_EXECUTABLE_PATH:executable,
 ...(secureshopE2eEnvironment||{})};
let buildReceipt=null;
if(secureshopE2e){
 const {buildBoundary,discoverSecrets,artifactEnvironment}=require('./lib/isolated-test-boundary');
 const data=artifactEnvironment(directory);for(const key of ['HOME','TMPDIR','LOGS_DIR','XDG_CONFIG_HOME','XDG_CACHE_HOME','XDG_DATA_HOME'])fs.mkdirSync(data[key],{recursive:true,mode:0o700});
 const masks=path.join(directory,'boundary-masks');fs.mkdirSync(masks,{mode:0o700});fs.mkdirSync(path.join(masks,'empty-dir'),{mode:0o500});fs.writeFileSync(path.join(masks,'empty-file'),'',{mode:0o400});
 const buildRoot=path.join(owned.tmp,'app-build'),client=path.join(source,'client');
 const boundary=buildBoundary({source,directory,secrets:discoverSecrets(source,os.homedir()),executable:process.execPath,args:[path.join(client,'node_modules/vite/bin/vite.js'),'build',client,'--config',path.join(client,'vite.config.mjs'),'--configLoader','runner','--outDir',buildRoot,'--emptyOutDir']});
 try{
  const buildProcess=await runOwnedBuild(boundary.command,boundary.args,{cwd:boundary.cwd,env:{...data,PATH:path.dirname(process.execPath)+':/usr/bin:/bin',NODE_ENV:'production',BUILD_PATH:buildRoot,CI:'false',BROWSERSLIST_IGNORE_OLD_DATA:'1'},logPath:path.join(directory,'build.log')});
  const pairs=[];function walk(dir){for(const name of fs.readdirSync(dir)){const file=path.join(dir,name),st=fs.lstatSync(file);if(st.isSymbolicLink())throw Error('Build symlink denied');if(st.isDirectory())walk(file);else if(st.isFile())pairs.push([path.relative(buildRoot,file).split(path.sep).join('/'),sha(file)]);else throw Error('Build special file denied');}}walk(buildRoot);pairs.sort((a,b)=>a[0]<b[0]?-1:a[0]>b[0]?1:0);
  const digest=crypto.createHash('sha256').update(JSON.stringify(pairs)).digest('hex');env.SS_E2E_BUILD_ROOT=fs.realpathSync(buildRoot);env.SS_E2E_BUILD_SHA256=digest;buildReceipt={process:buildProcess,root:env.SS_E2E_BUILD_ROOT,sha256:digest,files:pairs};
 }catch(error){fs.writeFileSync(path.join(directory,'result.json'),JSON.stringify({scope:qualificationScope,passed:false,stage:'owned-build',error:error.message,buildReceipt:error.buildReceipt||null,sourcePins})+'\n',{mode:0o600});throw error;}
}
const logPath=path.join(directory,'tests.tap'),log=fs.openSync(logPath,'wx',0o600);
const child=spawn(process.execPath,['--test','--test-reporter=tap','--test-concurrency=1','--test-timeout=300000',...suites.map(row=>row.file)],{cwd:source,env,detached:true,stdio:['ignore',log,log]});
let timedOut=false,interrupted=null,finished=false,inspectionError=null,spawned=false,poll,timer;
const safePid=pid=>Number.isSafeInteger(pid)&&pid>1;
const browsers=new Map();
function processes(){return execFileSync('/bin/ps',['-axo','pid=,ppid=,pgid=,uid=,command='],{encoding:'utf8',timeout:2000,maxBuffer:4*1024*1024}).split('\n').filter(line=>line.trim()).map(line=>{const m=line.match(/^\s*(\d+)\s+(\d+)\s+(\d+)\s+(-?\d+)(?:\s+(.*))?$/);if(!m||m.slice(1,5).some(value=>!Number.isSafeInteger(Number(value))))throw Error('Invalid process inventory');return{pid:+m[1],ppid:+m[2],pgid:+m[3],uid:+m[4],command:m[5]||''};});}
function startIdentity(pid){
 let start;try{start=execFileSync('/bin/ps',['-p',String(pid),'-o','lstart='],{encoding:'utf8',timeout:2000}).trim();}
 catch(error){if(!processes().some(row=>row.pid===pid))return null;throw error;}
 if(!start){if(!processes().some(row=>row.pid===pid))return null;throw Error('Missing process start identity');}return start;
}
function descendant(row,rows){const seen=new Set();while(row&&!seen.has(row.pid)){if(row.ppid===child.pid)return true;seen.add(row.pid);row=rows.find(value=>value.pid===row.ppid);}return false;}
function observe(){
 const rows=processes();
 for(const row of rows){
  if(!row.command.startsWith(executable+' ')||!row.command.includes('--user-data-dir='+owned.tmp+path.sep))continue;
  if(row.uid!==process.getuid()||row.pgid!==row.pid||row.pid===child.pid)throw Error('Browser ownership mismatch');
  const prior=browsers.get(row.pid);
  if(!prior&&!descendant(row,rows))throw Error('Browser lacks owned test ancestry');
  const start=startIdentity(row.pid);if(start===null)continue;
 if(prior&&(prior.start!==start||prior.command!==row.command))throw Error('Browser identity changed');
  browsers.set(row.pid,{...row,start});
 }
 return rows;
}
function signalGroup(pid,signal){if(!safePid(pid))throw Error('Unsafe process group identity');try{process.kill(-pid,signal);}catch(error){if(error.code!=='ESRCH')throw error;}}
function groupAbsent(pid){if(!safePid(pid))throw Error('Unsafe process group identity');try{process.kill(-pid,0);return false;}catch(error){if(error.code==='ESRCH')return true;throw error;}}
function retire(){
 const errors=[];let rows;
 try{if(spawned)rows=observe();}catch(error){errors.push(error);}
 // Test group ownership comes directly from this detached spawn, independently of ps.
 try{if(spawned&&safePid(child.pid))signalGroup(child.pid,'SIGKILL');}catch(error){errors.push(error);}
 for(const identity of browsers.values()){
  try{
   const current=processes(),leader=current.find(row=>row.pid===identity.pid),members=current.filter(row=>row.pgid===identity.pgid);
   if(!members.length)continue;
   if(!leader)throw Error('Browser leader absent; refusing stale group signal');
   const start=startIdentity(identity.pid);
   if(start===null)throw Error('Browser leader vanished; refusing group signal');
   if(leader.uid!==identity.uid||leader.command!==identity.command||leader.pgid!==identity.pgid||start!==identity.start||members.some(row=>row.uid!==identity.uid))throw Error('Refusing changed browser process');
   signalGroup(identity.pgid,'SIGKILL');
  }catch(error){errors.push(error);}
 }
 return errors;
}
function startMonitoring(){poll=setInterval(()=>{try{observe();}catch(error){inspectionError=error;void finish(null,null,error);}},200);
timer=setTimeout(()=>{timedOut=true;void finish(null,null,Error('Native browser overall deadline'));},600000);}
async function finish(code,signal,error){
 if(finished)return;finished=true;clearInterval(poll);clearTimeout(timer);
 const cleanupErrors=[];let receipt;
 try{
  cleanupErrors.push(...retire());fs.closeSync(log);
  const deadline=Date.now()+5000;let absent=false;
  if(!spawned)absent=true;
  while(spawned&&Date.now()<deadline){const rows=observe();absent=(safePid(child.pid)&&groupAbsent(child.pid))&&[...browsers.keys()].every(groupAbsent)&&!rows.some(row=>row.command.startsWith(executable+' ')&&row.command.includes('--user-data-dir='+owned.tmp+path.sep));if(absent)break;await new Promise(resolve=>setTimeout(resolve,50));}
  const output=fs.readFileSync(logPath,'utf8'),count=label=>Number(output.match(new RegExp('^# '+label+' (\\d+)$','m'))?.[1]??NaN);
  const names=suites.flatMap(row=>row.names),actual=[...output.matchAll(/^# Subtest: (.+)$/gm)].map(match=>match[1]);
  const expectedNames=[...names].sort(),actualNames=[...actual].sort();
  const complete=actualNames.length===expectedNames.length&&expectedNames.every((name,index)=>name===actualNames[index]);
  const unchanged=Object.entries(sourcePins).every(([file,digest])=>sha(path.join(source,file))===digest);
  const passed=cleanupErrors.length===0&&absent&&unchanged&&complete&&!error&&!inspectionError&&!timedOut&&!interrupted&&code===0&&count('tests')===names.length&&count('pass')===names.length&&count('fail')===0&&count('skipped')===0;
  receipt={scope:qualificationScope,buildReceipt,passed,childPid:safePid(child.pid)?child.pid:null,spawned,spawnErrorCode:typeof error?.code==='string'&&/^[A-Z0-9_]+$/.test(error.code)?error.code:null,code,signal,timedOut,interrupted,groupAbsent:absent,complete,unchanged,tests:count('tests'),pass:count('pass'),fail:count('fail'),skipped:count('skipped'),suites,sourcePins,executable,browserGroups:[...browsers.values()],logPath,error:error?.message||inspectionError?.message||null,cleanupErrors:cleanupErrors.map(value=>value.message)};
  fs.writeFileSync(path.join(directory,'result.json'),JSON.stringify(receipt,null,2)+'\n',{mode:0o600});console.log(JSON.stringify(receipt));process.exitCode=passed?0:1;
 }catch(failure){
  process.exitCode=1;receipt={scope:qualificationScope,passed:false,childPid:safePid(child.pid)?child.pid:null,spawned,spawnErrorCode:typeof error?.code==='string'&&/^[A-Z0-9_]+$/.test(error.code)?error.code:null,code,signal,timedOut,interrupted,sourcePins,logPath,error:failure.message,cleanupErrors:cleanupErrors.map(value=>value.message)};
  try{if(spawned&&safePid(child.pid))signalGroup(child.pid,'SIGKILL');}catch(cleanupError){receipt.cleanupErrors.push(cleanupError.message);}
  try{fs.closeSync(log);}catch{}
  fs.writeFileSync(path.join(directory,'result.json'),JSON.stringify(receipt,null,2)+'\n',{mode:0o600});console.log(JSON.stringify(receipt));
 }
 finally{process.off('SIGTERM',onTerm);process.off('SIGINT',onInt);}
}
const onTerm=()=>{interrupted='SIGTERM';void finish(null,'SIGTERM',Error('Interrupted'));},onInt=()=>{interrupted='SIGINT';void finish(null,'SIGINT',Error('Interrupted'));};
process.on('SIGTERM',onTerm);process.on('SIGINT',onInt);child.once('spawn',()=>{if(!safePid(child.pid)){void finish(null,null,Error('Invalid spawned PID'));return;}spawned=true;startMonitoring();});child.once('error',error=>finish(null,null,error));child.once('exit',(code,signal)=>finish(code,signal));

})().catch(error=>{console.error(error.message);process.exitCode=1;});
