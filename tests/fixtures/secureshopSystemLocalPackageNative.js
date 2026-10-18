'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const {randomUUID} = require('node:crypto');
async function main() {
  const mode=process.env.OWNED_PACKAGE_MODE,baseURL=process.env.OWNED_PACKAGE_URL,token=process.env.OWNED_PACKAGE_TOKEN;
  assert.ok(['config','diagnostic'].includes(mode));assert.equal(new URL(baseURL).hostname,'127.0.0.1');
  let posts=0;
  const fetchImpl=(url,options)=>{if(options.method==='POST')posts++;return fetch(url,options);};
  const factory=mode==='config'
    ? require('../../server/services/secureshopSystemConfigClient').createSecureShopSystemConfigClient
    : require('../../server/services/secureshopSystemDiagnosticClient').createSecureShopSystemDiagnosticClient;
  const client=factory({baseURL,token,fetchImpl});await client.assertReady();
  const bad=factory({baseURL,token:'x'.repeat(43)});await assert.rejects(bad.assertReady());
  let authorityChecks=0;const options={assertCurrent:async()=>{authorityChecks++;}};
  let receipt,credentialReceipt;
  if(mode==='config') {
    receipt=await client.read({operationId:randomUUID(),path:'....//.env'},options);
    assert.equal(receipt.status,'completed');assert.equal(receipt.drained,true);
    assert.equal(receipt.readResult.content,require('../../sidecars/sandbox-runner/owned-system/executor').FIXTURES['/app/.env']);
    credentialReceipt=await client.read({operationId:randomUUID(),path:'....//platform_secrets.json'},options);
    assert.equal(credentialReceipt.status,'completed');assert.equal(credentialReceipt.drained,true);
    assert.notEqual(credentialReceipt.operationId,receipt.operationId);
    assert.equal(credentialReceipt.readResult.targetPath,'/app/platform_secrets.json');
    assert.equal(credentialReceipt.readResult.content,'{"synthetic":true,"api_key":"TRAINING-OWNED-SYSTEM-API-KEY-ONLY","session_token":"TRAINING-OWNED-SYSTEM-SESSION-TOKEN-ONLY"}\n');
    assert.equal(credentialReceipt.readResult.size,125);
    assert.equal(credentialReceipt.readResult.contentSha256,'d4aa181509c96df8c83d62b90dc27f21eb63682c064077393dab6f80592f6b1e');
    const metrics=await client.metrics();assert.equal(metrics.ok,true);assert.equal(metrics.metricsSource,'owned-system-listener');
  } else {
    const targetId=randomUUID();receipt=await client.execute({targetId,request:{operationId:randomUUID(),cmd_template:'/usr/bin/uname',args:'-n'}},options);
    assert.equal(receipt.targetId,targetId);assert.equal(receipt.hostname,'system-diag-'+targetId.replaceAll('-',''));
    assert.equal(Buffer.from(receipt.result.stdout,'base64').toString(),receipt.hostname+'\n');assert.equal(receipt.result.exitCode,0);assert.equal(receipt.result.drained,true);
  }
  assert.equal(posts,mode==='config'?2:1);assert.equal(authorityChecks,mode==='config'?6:3);
  fs.writeFileSync(process.env.OWNED_PACKAGE_RESULT,JSON.stringify({mode,ready:true,wrongBearerDenied:true,actualPosts:posts,receipt,...(credentialReceipt?{credentialReceipt}:{}),authority:'Controlled callback only; no DB/launch proof'},null,2));
}
main().catch(error=>{console.error(error.code||error.name);process.exitCode=1;});
