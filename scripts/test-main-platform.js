#!/usr/bin/env node
'use strict';
const fs=require('node:fs'),path=require('node:path'),{spawn}=require('node:child_process');
const ROOT=path.resolve(__dirname,'..');
const FILES=Object.freeze(['tests/platformAuditMetadata.test.js','tests/platformSessionValidity.test.js','tests/authSessionHandlers.test.js','tests/instructorStudentHandlers.test.js','tests/adminRoleUpdates.test.js']);
const BOUNDS=Object.freeze({workMs:120000,cleanupMs:10000,logBytes:8*1024*1024});
function parse(args){if(args.length===0)return{plan:false};if(args.length===1&&args[0]==='--plan')return{plan:true};throw Error('Only --plan or the fixed main platform profile is supported');}
function environment(directory,inherited=process.env){return{PATH:path.dirname(process.execPath),HOME:path.join(directory,'home'),TMPDIR:path.join(directory,'tmp'),TMP:path.join(directory,'tmp'),TEMP:path.join(directory,'tmp'),XDG_CACHE_HOME:path.join(directory,'cache'),LOGS_DIR:path.join(directory,'logs'),NODE_ENV:'test',AI_PROVIDER:'mock',AWS_EC2_METADATA_DISABLED:'true',HF_HUB_OFFLINE:'1',TRANSFORMERS_OFFLINE:'1',MCP_SIDECARS_AUTOSTART:'false',MCP_WORKSHOP_AUTOSTART:'false',SS_ENABLE:'false',OWASP_AI_GOAT_MAIN_PLATFORM_PURE:'1'};}
async function executeChild({args,env,logFd,logSize,spawnProcess=spawn,stop=observed=>require('./start-application').stopOwnedChild(observed,{graceMs:4000}),signals=process,workMs=BOUNDS.workMs,pollMs=50}){
 let child,timer,poll,primary,cleanupError,result,failed=false;const cancel=()=>{failed=true;finish?.(Error('Main platform unit run cancelled'));};let finish;
 signals.once('SIGINT',cancel);signals.once('SIGTERM',cancel);
 try{result=await new Promise((resolve,reject)=>{let settled=false;finish=e=>{if(!settled){settled=true;e?reject(e):resolve();}};child=spawnProcess(process.execPath,args,{cwd:ROOT,env,detached:true,stdio:['ignore',logFd,logFd]});child.once('error',finish);child.once('exit',(code,signal)=>{if(code!==0||signal)finish(Error('Main platform selected tests failed'));else finish();});timer=setTimeout(()=>finish(Error('Main platform unit deadline')),workMs);poll=setInterval(()=>{try{if(logSize()>BOUNDS.logBytes)finish(Error('Main platform log cap'));}catch(e){finish(e);}},pollMs);});}catch(e){primary=e;}finally{clearTimeout(timer);clearInterval(poll);try{if(child)await stop({child});}catch(e){cleanupError=e;}signals.removeListener('SIGINT',cancel);signals.removeListener('SIGTERM',cancel);}
 if(failed&&!primary)primary=Error('Main platform unit run cancelled');if(logSize()>BOUNDS.logBytes&&!primary)primary=Error('Main platform log cap');if(primary||cleanupError)throw new AggregateError([primary,cleanupError].filter(Boolean),'Main platform unit run or physical cleanup failed');return{passed:true,cleanupVerified:true};
}
async function main(args=process.argv.slice(2)){
 const selection=parse(args);if(selection.plan){console.log(JSON.stringify({profile:'main-platform-pure-v1',files:FILES,bounds:BOUNDS,copy:false,initializer:false}));return;}
 if(process.platform==='win32')throw Error('Main platform profile currently requires POSIX owned process groups');
 require('./application-node-runtime').assertSupportedApplicationNodeVersion(process.versions.node);
 const parent=path.join(ROOT,'backups/private-recovery/platform-unit');fs.mkdirSync(parent,{recursive:true,mode:0o700});if(fs.realpathSync(parent)!==parent||fs.statSync(parent).uid!==process.getuid()||(fs.statSync(parent).mode&511)!==448)throw Error('Private main evidence directory required');
 const directory=fs.mkdtempSync(path.join(parent,'run-'));fs.chmodSync(directory,0o700);for(const d of ['home','tmp','cache','logs'])fs.mkdirSync(path.join(directory,d),{mode:0o700});
 const logfile=path.join(directory,'tests.log'),fd=fs.openSync(logfile,'wx',0o600);let state={profile:'main-platform-pure-v1',files:FILES,passed:false,fullAggregate:false,cleanupVerified:false};
 try{Object.assign(state,await executeChild({args:['--require',path.join(__dirname,'lib/main-platform-test-guard.cjs'),'--test','--test-isolation=none','--test-concurrency=1','--test-timeout=10000',...FILES],env:environment(directory),logFd:fd,logSize:()=>fs.fstatSync(fd).size}));}catch(e){state.failure='SELECTED_TEST_OR_CLEANUP_FAILURE';throw e;}finally{fs.fsyncSync(fd);fs.closeSync(fd);fs.writeFileSync(path.join(directory,'result.json'),JSON.stringify(state,null,2)+'\n',{mode:0o600,flag:'wx'});console.log(JSON.stringify({evidence:directory,...state}));}
}
if(require.main===module)main().catch(()=>{console.error('Main-only platform profile failed; inspect retained evidence.');process.exitCode=1;});
module.exports={FILES,BOUNDS,parse,environment,executeChild};
