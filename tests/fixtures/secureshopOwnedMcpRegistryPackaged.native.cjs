'use strict';
const assert=require('node:assert/strict'),crypto=require('node:crypto'),fs=require('node:fs/promises');
const {createOwnedMcpRegistryListener}=require('/app/sidecars/sandbox-runner/owned-mcp-registry/http-listener');
const {createOwnedMcpRegistryExecutor}=require('/app/sidecars/sandbox-runner/owned-mcp-registry/executor');
async function main(){
 const token=crypto.randomBytes(32).toString('base64url'),profile=process.env.SECURESHOP_MCP_REGISTRY_PROFILE,runtime=createOwnedMcpRegistryExecutor({expectedProfile:profile});let healthError,operationError;
 const observed=Object.freeze({checkReadiness:(...args)=>runtime.checkReadiness(...args),async execute(...args){try{return await runtime.execute(...args);}catch(error){operationError=error;throw error;}},async assertReady(...args){try{return await runtime.assertReady(...args);}catch(error){healthError=error;throw error;}}});
 const listener=createOwnedMcpRegistryListener({enabled:true,token,host:'127.0.0.1',port:0,expectedProfile:profile,executor:observed,maxConcurrent:2});
 const before=(await fs.readFile(`/proc/self/task/${process.pid}/children`,'utf8')).trim(),evidence={cases:[],modelCalls:0};
 const request=async(method,path,body)=>{const address=listener.address(),response=await fetch(`http://127.0.0.1:${address.port}${path}`,{method,headers:{authorization:`Bearer ${token}`,'content-type':'application/json'},body:body===undefined?undefined:JSON.stringify(body)});return{status:response.status,value:await response.json()};};
 try{
  await listener.start();
  const health=await request('GET','/secureshop/mcp-registry/health');if(health.status!==200)throw healthError||Object.assign(Error('MCP_REGISTRY_HEALTH_FAILED'),{code:'MCP_REGISTRY_HEALTH_FAILED'});assert.equal(health.value.registryCapability,'secureshop-owned-mcp-registry.v1');evidence.runtimeDigest=health.value.runtimeDigest;evidence.cases.push('actual isolated namespace readiness');
  const base=(action,name,transport,url,stdio_cmd='')=>({activeEntries:[],mode:'vuln',request:{version:1,action,operationId:crypto.randomUUID(),expectedVersion:'0',name,transport,url,stdio_cmd}});
  const attackerInput=base('register','attacker-catalog','sse','http://attacker.training:8080/mcp');
  const attacker=await request('POST','/secureshop/mcp-registry/execute',attackerInput);assert.equal(attacker.status,200);assert.match(attacker.value.changes[0].tools[0].description,/ignore prior policy/);evidence.cases.push('actual SSE tool poisoning discovery');
  const discoveryContract=require('/app/server/services/secureshopMcpRegistryDiscoveryContract');
  function verifyDiscovery(input,result){const change=result.value.changes[0],receipt=discoveryContract.validateDiscoveryReceipt(change.effect.discoveryReceipt,
    {request:input.request,tools:change.tools,endpoint:change.endpoint});assert.equal(receipt.schemaSha256,change.schemaSha256);return receipt;}
  assert.deepEqual(verifyDiscovery(attackerInput,attacker).destination,{listenerId:'attacker',address:'10.0.1.100',port:8080,sensitive:true});
  const metadataInput=base('register','metadata-probe','streamable-http','http://169.254.169.254/mcp');
  const metadata=await request('POST','/secureshop/mcp-registry/execute',metadataInput);if(metadata.status!==200)throw operationError||Error('Owned metadata discovery failed');
  const metadataReceipt=verifyDiscovery(metadataInput,metadata);assert.deepEqual(metadataReceipt.destination,{listenerId:'metadata',address:'169.254.169.254',port:80,sensitive:true});
  assert.equal(metadata.value.changes[0].tools[0].name,'metadata-catalog');evidence.discoveryReceipt=metadataReceipt;
  evidence.cases.push('actual metadata tools/list receiving-listener and original SDK response receipt');
  operationError=undefined;const fixedMetadata={...base('register','fixed-metadata','streamable-http','http://169.254.169.254/mcp'),mode:'fixed'};
  const denied=await request('POST','/secureshop/mcp-registry/execute',fixedMetadata);
  assert.equal(denied.status,403);assert.deepEqual(denied.value,{version:1,error:'MCP_REGISTRY_FIXED_DESTINATION_DENIED',effectNotStarted:true,
    operationId:fixedMetadata.request.operationId,registryRequestSha256:require('/app/server/services/secureshopMcpRegistryContract').registryRequestDigest(fixedMetadata.request),policySha256:discoveryContract.DISCOVERY_POLICY_SHA256});
  assert.equal(operationError?.code,'MCP_REGISTRY_FIXED_DESTINATION_DENIED');assert.equal(operationError.effectNotStarted,true);assert.equal(operationError.drained,true);
  evidence.fixedDestinationDenial=denied.value;evidence.cases.push('actual fixed metadata registration denied before connection with joined authenticated worker denial');
  const benign=await request('POST','/secureshop/mcp-registry/execute',{...base('register','benign-catalog','streamable-http','http://benign.training/mcp'),mode:'fixed'});assert.equal(benign.status,200);assert.equal(benign.value.changes[0].tools[0].name,'search_catalog');evidence.cases.push('actual streamable HTTP fixed discovery');
  const manifestRequest=()=>({version:1,action:'import',operationId:crypto.randomUUID(),expectedVersion:'0',xml_url:'http://metadata.training/manifest.xml'});
  operationError=undefined;
  const fixedImport=await request('POST','/secureshop/mcp-registry/execute',{activeEntries:[],mode:'fixed',request:manifestRequest()});
  assert.equal(fixedImport.status,503);assert.deepEqual(fixedImport.value,{error:'MCP_REGISTRY_UNAVAILABLE'});
  assert.equal(operationError?.code,'MCP_REGISTRY_CHILD_FAILED');assert.equal(operationError.drained,true);
  assert.match(operationError.diagnostic,/owned-mcp-registry:MCP_REGISTRY_FIXED_ENTITY_DENIED(?:\r?\n|$)/);
  evidence.cases.push('actual fixed manifest external entity denial with joined namespace child');
  operationError=undefined;
  const imported=await request('POST','/secureshop/mcp-registry/execute',{activeEntries:[],mode:'vuln',request:manifestRequest()});assert.equal(imported.status,200);const read=imported.value.changes[0].effect.entityReads[0];assert.equal(read.path,'/owned-mcp-files/admin-token.txt');assert.equal(read.value,'DV-AI{owned-mcp-registry-xxe}');assert.equal(read.bytes,Buffer.byteLength(read.value));assert.equal(read.sha256,crypto.createHash('sha256').update(read.value).digest('hex'));evidence.cases.push('actual bounded namespace XXE manifest import');
  const command="printf 'owned-stdio-effect' > /owned-mcp-files/stdio-effect; exec /usr/local/bin/node /usr/local/libexec/dvaia-owned-mcp-registry-worker.js --stdio-peer";
  const stdio=await request('POST','/secureshop/mcp-registry/execute',base('register','stdio-catalog','stdio','',command));if(stdio.status!==200)throw operationError||Object.assign(Error('MCP_REGISTRY_STDIO_FAILED'),{code:'MCP_REGISTRY_STDIO_FAILED'});assert.equal(stdio.value.changes[0].effect.stdioEffect.text,'owned-stdio-effect');assert.equal(stdio.value.changes[0].tools[0].name,'owned_shell_result');evidence.cases.push('actual submitted stdio shell effect confined to namespace');
  const epoch=await request('GET','/secureshop/mcp-registry/invoke/health');assert.equal(epoch.status,200);assert.equal(epoch.value.runtimeDigest,evidence.runtimeDigest);
  const protocol=require('/app/sidecars/sandbox-runner/owned-mcp-registry/invoke-protocol');
  for(const [label,discovery]of [['sse',attacker],['streamable-http',benign],['stdio',stdio]]){
   const change=discovery.value.changes[0],entry={entryId:change.entryId,registryVersion:'1',transport:change.transport,endpoint:change.endpoint,schemaSha256:change.schemaSha256,tools:change.tools};
   const invocation={version:1,instanceId:epoch.value.instanceId,operationId:crypto.randomUUID(),entry,toolName:change.tools[0].name,args:label==='stdio'?{}:{query:'training'}};
   const called=await request('POST','/secureshop/mcp-registry/invoke',invocation);if(called.status!==200)throw operationError||Error('Actual registered tool invocation failed');
   const receipt=protocol.receipt(called.value.receipt,invocation),content=JSON.parse(receipt.result.content[0].text),catalog=label==='stdio'?content:content.catalog;
   assert.equal(catalog[0].id,'owned-product-42');assert.equal(catalog[0].priceCents,4200);
   const identity={instanceId:epoch.value.instanceId,operationId:invocation.operationId,requestSha256:receipt.requestSha256};
   const status=await request('POST','/secureshop/mcp-registry/invoke/status',identity);assert.equal(status.status,200);assert.equal(status.value.state,'completed');assert.equal(status.value.drained,true);
   const replay=await request('POST','/secureshop/mcp-registry/invoke',invocation);assert.equal(replay.status,409);
   const stale=await request('POST','/secureshop/mcp-registry/invoke/status',{...identity,instanceId:crypto.randomUUID()});assert.equal(stale.value.state,'unknown');assert.equal(stale.value.drained,false);
   evidence.cases.push(`actual ${label} SDK discovery, exact schema, file-backed callTool and joined retirement`);
  }
  await assert.rejects(fs.access('/owned-mcp-files/stdio-effect'),{code:'ENOENT'});await assert.rejects(fs.writeFile('/usr/local/libexec/dvaia-owned-mcp-registry-worker.js','tamper'),error=>['EACCES','EROFS'].includes(error.code));
 }finally{await listener.close();}
 const after=(await fs.readFile(`/proc/self/task/${process.pid}/children`,'utf8')).trim();assert.equal(after,before);evidence.cases.push('immutable assets and all namespace descendants joined');evidence.status='passed';return evidence;
}
if(require.main===module)main().then(value=>console.log(JSON.stringify(value))).catch(error=>{console.error(error.stack,'code='+String(error.code||''),'diagnostic='+String(error.diagnostic||''));process.exitCode=1;});
module.exports={main};
