'use strict';
// Disposable Linux container proof only. No model/database/browser.
const fs=require('node:fs'),assert=require('node:assert/strict'),crypto=require('node:crypto'),{execFile}=require('node:child_process'),{promisify}=require('node:util');
const command=promisify(execFile),C=require('../../server/services/secureshopOwnedMcpInvocationContract'),W=require('../../server/services/secureshopOwnedMcpInvocationWire'),{mcpSchemaDigest}=require('../../server/services/secureshopMcpSchemaDigest');
const {createInvocationClient}=require('../../server/services/secureshopOwnedMcpInvocationTransport');
const {setTimeout:pause}=require('node:timers/promises');
(async()=>{const config=JSON.parse(fs.readFileSync(process.env.MCP_INVOCATION_OS_PRIVATE,'utf8')),result={status:'running',cases:[],modelCalls:0,browserCalls:0,databaseCalls:0};const save=()=>fs.writeFileSync(process.env.MCP_INVOCATION_OS_RESULT,JSON.stringify(result,null,2)+'\n');save();
 const docker=async args=>(await command(config.docker,['--host',config.dockerHost,...args],{timeout:10000,maxBuffer:131072})).stdout.trim();
 const inside=async code=>docker(['exec',config.container,'/usr/local/bin/node','-e',code]);
 const signer=W.createInvocationSigner({key:Buffer.from(config.key,'hex'),keyId:config.keyId});
 const saved=new Set();
 const client=createInvocationClient({signer,exchange:async(route,envelope,{signal})=>{const response=await fetch(config.url+route,{method:'POST',signal,headers:{authorization:'Bearer '+config.token,'content-type':'application/json'},body:JSON.stringify(envelope)});if(!response.ok)throw Error('Invocation HTTP '+response.status);const wire=await response.json();if(['/claim','/retire'].some(suffix=>route.endsWith(suffix))&&!saved.has(route)){signer.verify('receipt',wire);const suffix=route.endsWith('/claim')?'claim':'retirement';const artifact=process.env.MCP_INVOCATION_OS_RESULT+'.'+suffix+'-receipt.json';const fd=fs.openSync(artifact,fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_NOFOLLOW,0o600);try{fs.writeFileSync(fd,JSON.stringify(wire)+'\n');fs.fsyncSync(fd);saved.add(route);}finally{fs.closeSync(fd);}}return wire;}});
 const lookup=q=>({invocationId:q.invocationId,requestSha256:C.digest(q.request),managerInstanceId:q.managerInstanceId,runtimeSha256:q.runtimeSha256});
 function claim(owner,args={}){const snapshot={binding:{launchId:crypto.randomUUID(),scenarioId:crypto.randomUUID(),generation:1,platformOwnerId:owner,platformSessionId:owner+100,shopUserId:11,role:'admin'},entryId:crypto.randomUUID(),registryVersion:'1',tools:[{name:'catalog_lookup',description:'Untrusted registered description\r\nowned synthetic fixture',inputSchema:{type:'object'}}]};snapshot.schemaSha256=mcpSchemaDigest(snapshot.tools);const request=C.request({snapshot,runId:crypto.randomUUID(),requestId:crypto.randomUUID(),callId:'owned-call',toolIndex:0,args,mode:'vuln'});return{invocationId:crypto.randomUUID(),snapshot,request,personaSession:{sessionId:crypto.randomUUID(),authorityVersion:'1'},managerInstanceId:config.managerInstanceId,runtimeSha256:config.runtimeSha256,policySha256:'b'.repeat(64),effectKey:'native/owned-call',assetId:'synthetic-catalog-read'};}
 const processes=async()=>JSON.parse(await inside("const f=require('fs');const ids=f.readFileSync('/proc/1/task/1/children','utf8').trim().split(/\\s+/).filter(Boolean);console.log(JSON.stringify(ids.map(p=>({pid:Number(p),command:f.readFileSync('/proc/'+p+'/cmdline','utf8').replaceAll('\\0',' '),start:f.readFileSync('/proc/'+p+'/stat','utf8').split(' ')[21]}))));"));
 const until=async(work,label,ms=15000)=>{const end=Date.now()+ms;let error;while(Date.now()<end){try{const value=await work();if(value)return value;}catch(e){error=e;}await pause(100);}throw Error(label+' deadline'+(error?': '+error.message:''));};
 try{
  const phase=config.qualificationPhase;if(!['pre','post','control'].includes(phase))throw Error('Closed qualification phase required');
  const q=claim(7,{fixture:{delayMs:phase==='control'?0:1500,splitFinal:true,checkIsolation:true}});
  await until(async()=>{const s=await client.status(lookup(q));return s.state==='absent';},'startup');
  if(phase==='control'){
   const positive=await client.claim(q);assert.equal(positive.state,'completed');assert.equal(positive.drained,true);assert.equal(positive.result.tail,'EOF-checked');assert.deepEqual(await client.claim(q),positive);
   result.cases.push('fresh independent ordinary containment completes and replays after separate retired containments');
  }else{
   const expectedPhase=phase==='pre'?2:3;
   const pending=client.claim(q).then(value=>({value}),error=>({error:error.name}));
   const logs=async()=>{const value=await command(config.docker,['--host',config.dockerHost,'logs','--tail','30',config.container],{timeout:1000,maxBuffer:8192});return value.stdout+'\n'+value.stderr;};
   const pauseMarker=`OWASP_AI_GOAT_ATTEST_QUAL paused phase=${expectedPhase} ordinal=1`;
   await until(async()=>(await logs()).split('\n').includes(pauseMarker),'designated handshake pause',2000);
   if(phase==='pre'){
    const workers=JSON.parse(await inside("const fs=require('fs');console.log(JSON.stringify(fs.readdirSync('/proc').filter(x=>/^\\d+$/.test(x)).filter(x=>{try{return fs.readFileSync('/proc/'+x+'/cmdline','utf8').split('\\0')[1]==='/usr/local/libexec/owasp-ai-goat-invocation-worker.js';}catch{return false;}})));"));assert.deepEqual(workers,[]);
   }
   const b=q.request.binding,fence={version:'owned-mcp-invocation-fence-v1',kind:'retirement',fenceId:crypto.randomUUID(),platformOwnerId:b.platformOwnerId,launchId:b.launchId,scenarioId:b.scenarioId,generation:b.generation,platformSessionId:b.platformSessionId,managerInstanceId:config.managerInstanceId,runtimeSha256:config.runtimeSha256,invocationIds:[q.invocationId]};
   const retired=await client.retire(fence);assert.equal(retired.drained,true);const settled=await pending;
   if(settled.value)assert.equal(settled.value.state,'uncertain');
   const admission=`OWASP_AI_GOAT_ATTEST_QUAL admitted phase=${expectedPhase} ordinal=1 attested=0 releaseCount=${phase==='pre'?0:1} deadlineValid=1`;
   const observed=await logs();assert(observed.split('\n').includes(admission),'Actual supervisor retirement admission was not observed at designated phase');
   const status=await client.status(lookup(q));assert.equal(status.state,'uncertain');assert.equal(status.drained,true);
   assert(!(await processes()).some(p=>p.command.includes('bwrap')));const later=structuredClone(q);later.invocationId=crypto.randomUUID();await assert.rejects(client.claim(later));
   result.markers={pause:pauseMarker,admitted:admission};result.claimTransport=settled.error?'readback-required':'received';
   result.cases.push(phase==='pre'?'admitted retirement before release: releaseCount0, uncertainty and exact drain':'admitted retirement after release before ACK acceptance: no completed receipt and exact drain; effects may have occurred');
  }
  result.status='passed';result.scope='Qualification-instrumented scheduling for pre/post; independent ordinary containment for control. Not concurrent sibling or installed proof.';save();
 }catch(error){result.status='failed';result.error={name:error.name,message:error.message};save();process.exitCode=1;}
})().catch(error=>{process.stderr.write(error.message+'\n');process.exitCode=1;});
