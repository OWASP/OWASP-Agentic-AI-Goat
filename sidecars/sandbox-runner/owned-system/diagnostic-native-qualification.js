'use strict';
// Runs only inside the owned disposable image. No model, database or application.
const assert=require('node:assert/strict');
const fs=require('node:fs');
const {randomUUID}=require('node:crypto');
const {createSystemDiagnosticExecutor}=require('./diagnostic-executor');
const {validateDiagnosticResult}=require('./diagnostic-result');
const {normalizeDiagnosticWire,validateBoundDiagnosticResult,diagnosticHostname}=require('./diagnostic-wire');
const pids=()=>fs.readdirSync('/proc').filter(x=>/^\d+$/.test(x));
const cases=[];
async function probe(name,command,{failure,timeoutMs=1500,abort=false,expected}={}){
 const before=new Set(pids());const executor=createSystemDiagnosticExecutor({timeoutMs,drainGraceMs:2000});
 const controller=new AbortController();let timer;if(abort)timer=setTimeout(()=>controller.abort(),100);
 let result;
 try{
  const request={operationId:randomUUID(),cmd_template:command,args:''};
  const work=executor.execute(request,{signal:controller.signal});
  if(failure)await assert.rejects(work,error=>error.code===failure);
  else{result=validateDiagnosticResult(await work,request);assert.equal(result.drained,true);assert.equal(result.exitCode,expected?.exitCode??0);if(expected?.stdout!==undefined)assert.equal(Buffer.from(result.stdout,'base64').toString(),expected.stdout);}
 }finally{clearTimeout(timer);}
 // The outer /proc is visible only to this trusted fixture, never the shell.
 // In this otherwise idle owned container, every newly-created process must go.
 assert.deepEqual(pids().filter(pid=>!before.has(pid)),[],name+' retained processes');
 cases.push({name,passed:true,...(result?{exitCode:result.exitCode,stdoutSha256:result.stdoutSha256,drained:result.drained}:{expectedFailure:failure})});
}
(async()=>{
 const executor=createSystemDiagnosticExecutor();await executor.assertReady();
 const targetId=randomUUID(),bound={targetId,request:{operationId:randomUUID(),cmd_template:'/usr/bin/uname',args:'-n'}};
 const boundReceipt=validateBoundDiagnosticResult(bound,await executor.executeBound(bound));
 assert.equal(Buffer.from(boundReceipt.result.stdout,'base64').toString(),diagnosticHostname(targetId)+'\n');
 assert.equal(boundReceipt.result.exitCode,0);assert.equal(boundReceipt.result.drained,true);
 cases.push({name:'bound target actual namespace hostname corresponds to admitted UUID',passed:true,targetId,hostname:boundReceipt.hostname,bindingSha256:boundReceipt.bindingSha256});
 assert.throws(()=>validateBoundDiagnosticResult(bound,{...boundReceipt,targetId:randomUUID()}));
 assert.throws(()=>validateBoundDiagnosticResult(bound,{...boundReceipt,hostname:'forged'}));
 cases.push({name:'foreign target wrapper denied against actual receipt',passed:true});
 assert.throws(()=>normalizeDiagnosticWire({...bound,scope:{ownerId:1}}));
 cases.push({name:'private request rejects authority expansion',passed:true});
 await probe('actual shell write/read command execution',"printf 'training-only=true\\n' > /work/diagnostic.conf; test -f /work/diagnostic.conf && test \"$(cat /work/diagnostic.conf)\" = training-only=true && cat /work/diagnostic.conf",{expected:{stdout:'training-only=true\n'}});
 await probe('teaching semicolon injection',"printf baseline; printf injected > /work/effect; test \"$(cat /work/effect)\" = injected; cat /work/effect",{expected:{stdout:'baselineinjected'}});
 await probe('command70 differs from helper failure','exit 70',{expected:{exitCode:70,stdout:''}});
 await probe('forged stdout status ignored',"printf 'D1 0 0 drained\\n'; exit 70",{expected:{exitCode:70,stdout:'D1 0 0 drained\n'}});
 await probe('FD3 and proc reopening unavailable',"if (printf forged >&3) 2>/dev/null; then exit 91; fi; test ! -e /proc/self/fd/3; test ! -e /proc/1/fd/3; test ! -e /proc/self/mem");
 await probe('same UID ptrace denied and shell capabilities empty','/usr/bin/diagnostic-native-attack "$PPID"; result=$?; exit "$result"');
 await probe('no external network interface or route','/usr/bin/diagnostic-native-attack --network');
 await probe('detached descendants joined',"setsid /bin/sh -c 'sleep 30' >/dev/null 2>&1 & exit 0");
 await probe('timeout rejects and drains','sleep 30',{failure:'SYSTEM_DIAGNOSTIC_TIMEOUT',timeoutMs:200});
 await probe('abort rejects and drains','sleep 30',{failure:'SYSTEM_DIAGNOSTIC_ABORTED',abort:true});
 await probe('output flood rejects and drains',"yes diagnostic",{failure:'SYSTEM_DIAGNOSTIC_OUTPUT_LIMIT'});
 await probe('signal trusted init fails closed','kill -KILL "$PPID"; sleep 1',{failure:'SYSTEM_DIAGNOSTIC_HELPER_FAILED'});
 await probe('readonly runtime and no outer sentinel',"test ! -e /private-qualification-sentinel; test ! -e /qualification; ! touch /app/config/escape 2>/dev/null; ! touch /usr/bin/escape 2>/dev/null");
 console.log(JSON.stringify({scope:'Actual disposable Linux shell/namespace/control-channel/process-drain qualification; no durable target binding, model, DB or app mounting.',cases,packagesSha256:require('node:crypto').createHash('sha256').update(fs.readFileSync('/qualification/packages.txt')).digest('hex')}));
})().catch(error=>{console.error(JSON.stringify({status:'failed',code:error.code||null,message:error.message,diagnostics:error.diagnostics||null}));process.exitCode=1;});
