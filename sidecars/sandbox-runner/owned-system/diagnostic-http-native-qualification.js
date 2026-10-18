'use strict';
const assert=require('node:assert/strict');const fs=require('node:fs');const {randomUUID,randomBytes}=require('node:crypto');
const {createSystemDiagnosticHttpListener}=require('./diagnostic-http-listener');
const {createSystemDiagnosticExecutor}=require('./diagnostic-executor');
const {diagnosticHostname,validateBoundDiagnosticResult}=require('./diagnostic-wire');
const {createSecureShopSystemDiagnosticClient,isSystemDiagnosticOutcomeUncertain}=require('/server/services/secureshopSystemDiagnosticClient');
(async()=>{
 const token=randomBytes(32).toString('base64url'),native=createSystemDiagnosticExecutor();let calls=0,probes=0,onStart,onFinish;
 const executor={assertReady:async options=>{probes++;return native.assertReady(options);},executeBound:async(input,options)=>{calls++;onStart?.();try{return await native.executeBound(input,options);}finally{onFinish?.();}}};
 const listener=createSystemDiagnosticHttpListener({enabled:true,token,host:'127.0.0.1',port:0,executor,maxConcurrent:1});
 const pids=()=>fs.readdirSync('/proc').filter(x=>/^\d+$/.test(x));const before=new Set(pids());const cases=[];
 try{
  const address=await listener.start(),origin='http://127.0.0.1:'+address.port,client=createSecureShopSystemDiagnosticClient({baseURL:origin,token});
  const targetId=randomUUID(),wire={targetId,request:{operationId:randomUUID(),cmd_template:'/usr/bin/uname',args:'-n'}};
  const receipt=validateBoundDiagnosticResult(wire,await client.execute(wire,{assertCurrent:async()=>{}}));assert.equal(Buffer.from(receipt.result.stdout,'base64').toString(),diagnosticHostname(targetId)+'\n');assert.equal(calls,1);cases.push('actual authenticated client/listener/handler/executeBound hostname');
  const wrong=await fetch(origin+'/secureshop/system/diagnostic',{method:'POST',headers:{authorization:'Bearer '+randomBytes(32).toString('base64url'),'content-type':'application/json'},body:JSON.stringify(wire)});assert.equal(wrong.status,401);assert.equal(calls,1);cases.push('wrong bearer no execution');
  const malformed=await fetch(origin+'/secureshop/system/diagnostic',{method:'POST',headers:{authorization:'Bearer '+token,'content-type':'application/json'},body:JSON.stringify({...wire,root:'/private'})});assert.equal(malformed.status,400);assert.equal(calls,1);cases.push('authority expansion no execution');
  let started=new Promise(resolve=>onStart=resolve);const held={targetId,request:{operationId:randomUUID(),cmd_template:'sleep',args:'1'}};const work=client.execute(held,{assertCurrent:async()=>{}});await started;
  const busy=await fetch(origin+'/secureshop/system/diagnostic-health',{headers:{authorization:'Bearer '+token}});assert.equal(busy.status,503);await work;assert.equal(calls,2);cases.push('actual held command overload rejected without duplicate');
  started=new Promise(resolve=>onStart=resolve);const finished=new Promise(resolve=>onFinish=resolve);const abort=new AbortController();const interrupted=client.execute({targetId,request:{operationId:randomUUID(),cmd_template:'sleep',args:'30'}},{assertCurrent:async()=>{},signal:abort.signal});await started;abort.abort();await assert.rejects(interrupted,isSystemDiagnosticOutcomeUncertain);await finished;assert.equal(calls,3);cases.push('disconnect aborts actual executor without redispatch');
  await listener.close();assert.equal(listener.address(),null);assert.deepEqual(pids().filter(pid=>!before.has(pid)),[]);cases.push('listener close and actual descendant absence');
  console.log(JSON.stringify({scope:'Actual owned Linux HTTP client/listener/handler/target-bound executor; no DB/durable admission/app/model.',cases,diagnosticDispatches:calls,readinessProbes:probes,targetId,hostname:receipt.hostname,bindingSha256:receipt.bindingSha256,secretLogged:false}));
 }finally{await listener.close();}
})().catch(error=>{console.error(JSON.stringify({status:'failed',code:error.code||null,message:error.message,diagnostics:error.diagnostics||null}));process.exitCode=1;});
