'use strict';
const fs=require('node:fs/promises'),crypto=require('node:crypto'),assert=require('node:assert/strict'),path=require('node:path');
async function main(){
 const root=await fs.mkdtemp('/tmp/owned-http-service-'),token=crypto.randomBytes(32).toString('base64url');
 const server=require('/app/owned-http/service').createOwnedHttpService({token,root,profile:process.env.MCP_OWNED_TARGET_APPARMOR_PROFILE,maxActive:1,maxPending:2});
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));const base='http://127.0.0.1:'+server.address().port;
 async function request(route,body,bearer=token){const response=await fetch(base+'/owned-http/'+route,{method:'POST',headers:{authorization:'Bearer '+bearer,'content-type':'application/json'},body:JSON.stringify(body)});return {status:response.status,value:await response.json()};}
 try{
  assert.equal((await request('readiness',{},'wrong')).status,401);assert.equal((await request('readiness',{})).value.ready,true);
  const scope={targetId:crypto.randomUUID(),platformOwnerId:7,platformSessionId:11,generation:0};const sibling={...scope,targetId:crypto.randomUUID(),platformOwnerId:8,platformSessionId:12};
  const owned=(await request('admit',{scope})).value;const other=(await request('admit',{scope:sibling})).value;assert.notEqual(owned.capability,other.capability);
  const input={url:'http://169.254.169.254/latest/?raw=%2f',mode:'vuln',runId:crypto.randomUUID(),operationId:crypto.randomUUID(),invocationId:crypto.randomUUID(),mcpSessionId:'mcp_7'};
  const response=await request('execute',{capability:owned.capability,request:input});assert.equal(response.status,200,JSON.stringify(response.value));assert.equal(response.value.result.status,'completed');
  assert.deepEqual((await request('execute',{capability:owned.capability,request:input})).value,response.value);
  const read=(await request('receipt',{capability:owned.capability,operationId:input.operationId,requestDigest:response.value.requestDigest})).value;assert.equal(read.state,'completed');assert.deepEqual(read.receipt,response.value);
  assert.equal((await request('execute',{capability:other.capability,request:input})).value.error,'HTTP_OWNER_MISMATCH');
  const operationId=crypto.randomUUID();const retired=await request('retire',{scope,operationId});assert.equal(retired.status,200);assert.equal(retired.value.status,'completed');
  assert.deepEqual((await request('retirement',{scope,operationId})).value,retired.value);
  await assert.rejects(fs.lstat(path.join(root,'targets',scope.targetId)),{code:'ENOENT'});assert.ok((await fs.stat(path.join(root,'targets',sibling.targetId))).isDirectory());
  assert.equal((await request('execute',{capability:owned.capability,request:input})).value.error,'TARGET_RETIRED');
  await request('retire',{scope:sibling,operationId:crypto.randomUUID()});
  assert.equal((await fs.readFile(`/proc/self/task/${process.pid}/children`,'utf8')).trim(),'');
  return {actualPrivateApi:true,actualOwnedSocket:true,exactReplay:true,receiptReadWithoutExecution:true,siblingOwnerRejected:true,siblingTargetPreserved:true,canonicalRetirement:true,noChildren:true,receipt:response.value,objectivePromoted:false};
 }finally{server.closeAllConnections();await new Promise(resolve=>server.close(resolve));await fs.rm(root,{recursive:true,force:true});}
}
if(require.main===module)main().then(value=>console.log(JSON.stringify(value))).catch(error=>{console.error(error.stack);process.exitCode=1;});
module.exports={main};
