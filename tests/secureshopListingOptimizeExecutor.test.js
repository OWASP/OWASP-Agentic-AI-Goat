'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const {createHash,randomUUID}=require('node:crypto');
const {createListingOptimizeExecutor}=require('../server/services/secureshopListingOptimizeExecutor');
const {normalizeListingRequest}=require('../server/services/secureshopListingRequestContract');
const {bindDiagnosticResult,diagnosticHostname}=require('../sidecars/sandbox-runner/owned-system/diagnostic-wire');
const {VERSION,diagnosticRequestDigest,diagnosticCommand}=require('../sidecars/sandbox-runner/owned-system/diagnostic-contract');
const digest=value=>createHash('sha256').update(value).digest('hex');
function fixture(mode='vuln',witness=true){
 const targetId=randomUUID(),operationId=randomUUID(),sceneId=randomUUID(),grantId=randomUUID(),imageUrl='https://owned.invalid/p.jpg; /usr/bin/uname -n; #';
 const request=normalizeListingRequest({version:1,action:'optimize',operationId,productId:7,imageUrl,imageUrlSha256:digest(imageUrl),sceneId,sceneGeneration:9,grantId});
 const admission={binding:{targetId,mode},request};let calls=0,wire;
 const client={execute:async (value,{assertCurrent})=>{calls++;wire=value;await assertCurrent();await assertCurrent();const stdout=Buffer.from(witness?`${diagnosticHostname(targetId)}\n`:'' );
  const stderr=Buffer.from('convert unavailable\n');const receipt=bindDiagnosticResult(value,{version:VERSION,isolation:'bwrap-system-diagnostic-v1',operationId,
   requestSha256:diagnosticRequestDigest(value.request),command:diagnosticCommand(value.request),executed:true,exitCode:witness?0:127,signal:null,drained:true,
   stdout:stdout.toString('base64'),stderr:stderr.toString('base64'),encoding:'base64',stdoutBytes:stdout.length,stderrBytes:stderr.length,
   stdoutSha256:digest(stdout),stderrSha256:digest(stderr),timedOut:false,truncated:false});await assertCurrent();return receipt;}};
 return{targetId,operationId,sceneId,grantId,imageUrl,request,admission,client,get calls(){return calls},get wire(){return wire}};
}
test('closed optimize request preserves exact attack bytes and enforces duplicate command bound',()=>{
 const f=fixture();assert.equal(f.request.imageUrl,f.imageUrl);assert.equal(f.request.imageUrlSha256,digest(f.imageUrl));
 assert.throws(()=>normalizeListingRequest({...f.request,imageUrl:'https://owned.invalid/other'}),/Invalid owned listing request/);
 const long='https://owned.invalid/'+('x'.repeat(4070));
 assert.throws(()=>normalizeListingRequest({version:1,action:'optimize',operationId:randomUUID(),productId:1,imageUrl:long,imageUrlSha256:digest(long),sceneId:randomUUID(),sceneGeneration:1,grantId:randomUUID()}));
});
test('vulnerable execution uses direct Listings target and exact diagnostic command',async()=>{
 const f=fixture();let checks=0;const receipt=await createListingOptimizeExecutor({client:f.client}).execute({admission:f.admission,checkCurrent:async()=>checks++});
 assert.equal(f.calls,1);assert.equal(checks,5);assert.equal(f.wire.targetId,f.targetId);assert.equal(f.wire.request.cmd_template,'convert');
 assert.equal(f.wire.request.args,`${f.imageUrl} -strip -quality 82 ${f.imageUrl}.opt.jpg`);
 assert.equal(receipt.remoteReceipt.result.command,`convert ${f.wire.request.args}`);assert.equal(receipt.hostname,diagnosticHostname(f.targetId));
 assert.equal(Object.hasOwn(receipt,'optimized'),false);
});
test('fixed mode denies before readiness or POST',async()=>{
 const f=fixture('fixed');await assert.rejects(createListingOptimizeExecutor({client:f.client}).execute({admission:f.admission,checkCurrent:async()=>{}}),{code:'LISTING_OPTIMIZE_DENIED'});assert.equal(f.calls,0);
});
test('transport uncertainty keeps its original identity and ordinary nonzero execution remains an honest receipt',async()=>{
 const uncertain=Object.assign(Error('lost response'),{code:'SYSTEM_DIAGNOSTIC_OUTCOME_UNCERTAIN',outcome:'unknown',automaticRetry:false});
 const f=fixture();f.client.execute=async()=>{throw uncertain;};await assert.rejects(createListingOptimizeExecutor({client:f.client}).execute({admission:f.admission,checkCurrent:async()=>{}}),error=>error===uncertain);
 const ordinary=fixture('vuln',false),receipt=await createListingOptimizeExecutor({client:ordinary.client}).execute({admission:ordinary.admission,checkCurrent:async()=>{}});
 assert.equal(receipt.remoteReceipt.result.exitCode,127);assert.equal(Object.hasOwn(receipt,'optimized'),false);
});
test('wrong target identity and malformed execution receipts cannot become a Listings effect',async()=>{
 for(const mutate of [r=>({...r,hostname:diagnosticHostname(randomUUID())}),r=>({...r,result:{...r.result,drained:false}})]){
  const f=fixture(),original=f.client.execute;f.client.execute=async (wire,options)=>mutate(await original(wire,options));
  await assert.rejects(createListingOptimizeExecutor({client:f.client}).execute({admission:f.admission,checkCurrent:async()=>{}}),{code:'LISTING_OPTIMIZE_EFFECT_MISMATCH'});
 }
});
