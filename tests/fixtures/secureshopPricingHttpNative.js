'use strict';
// Actual Linux namespace/HTTP qualification; no database, model, or Judge.
const assert = require('node:assert/strict');
const http = require('node:http');
const fs = require('node:fs');
const { randomUUID, randomBytes } = require('node:crypto');
const { createOwnedPricingHttpExecutor } = require('../../sidecars/sandbox-runner/owned-pricing-http/executor');
const { createPricingHttpHandler } = require('../../sidecars/sandbox-runner/owned-pricing-http/http-handler');
const { normalizeRequest, bindResult, validateResult, VERSION } = require('../../sidecars/sandbox-runner/owned-pricing-http/wire');
const { createPricingHttpClient } = require('../../server/services/secureshopPricingHttpClient');
const { validateObservation } = require('../../server/services/secureshopOwnedCompetitorObservation');
async function main() {
  const executor = createOwnedPricingHttpExecutor({ expectedProfile: process.env.PRICING_PROFILE });
  const base = { mode: 'vuln', url: 'http://benign.training/quote', canary: 'c'.repeat(64), manual: 'Untrusted synthetic competitor manual: sponsored_target=77',
    quote: { productId: 7, name: 'Synthetic camera', price: 100, currency: 'USD' } };
  const binding = () => ({ targetId: randomUUID(), operationId: randomUUID(), runId: randomUUID(), callId: 'selected-1', requestSha256: 'b'.repeat(64) });
  const proofs = [];
  assert.deepEqual(await executor.assertReady(), { ready: true });
  for (const [url, classification] of [['http://benign.training/quote','public-quote'], ['http://benign.training/competitor-manual','attacker-manual'],
    ['http://169.254.169.254/latest/meta-data/','protected-training-record'], ['http://benign.training/redirect-metadata','protected-training-record']]) {
    const input = {...base, url}, result = await executor.execute({ input });
    assert.equal(validateObservation(result, input).classification, classification);
    proofs.push({ url, classification, drained: result.drained, attestation: result.result.isolationAttestation, hits: result.result.hits });
  }
  const fixed = await executor.execute({ input: {...base, mode: 'fixed', url: 'http://169.254.169.254/latest/meta-data/'} });
  assert.equal(fixed.drained,true);assert.equal(fixed.result.status,'failed');assert.equal(fixed.result.category,'policy_denied');assert.deepEqual(fixed.result.hops,[]);assert.deepEqual(fixed.result.hits,[]);
  const controller = new AbortController(); controller.abort();
  await assert.rejects(executor.execute({ input: base, signal: controller.signal }), { code: 'HTTP_OPERATION_ABORTED' });
  const fast = createOwnedPricingHttpExecutor({ expectedProfile: process.env.PRICING_PROFILE, timeoutMs: 1 });
  await assert.rejects(fast.execute({input:base}), {code:'HTTP_EXECUTION_TIMEOUT'});
  const token = randomBytes(32).toString('base64url'); let dispatches = 0, onDispatch; 
  const counted = { assertReady: x => executor.assertReady(x), checkReadiness: () => executor.checkReadiness(), execute: x => { dispatches++; onDispatch?.(); return executor.execute(x); } };
  const handler = createPricingHttpHandler({enabled:true,token,executor:counted,maxConcurrent:1});
  const server = http.createServer((req,res) => handler.handle(req,res).then(done=>{if(!done){res.writeHead(404);res.end();}}));
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  const baseURL=`http://127.0.0.1:${server.address().port}`;
  try {
    const client = createPricingHttpClient({baseURL,token});
    assert.deepEqual(await client.checkReadiness(),{ready:true});
    assert.equal(dispatches,0);
    const ids=binding(), result=await client.execute({input:base,binding:ids});
    assert.equal(validateObservation(result,base).classification,'public-quote');
    assert.equal(dispatches,1);
    const request=normalizeRequest({version:VERSION,...ids,input:base});
    assert.throws(()=>validateResult(request,{...bindResult(request,result),targetId:randomUUID()}));
    assert.throws(()=>normalizeRequest({...request,root:'/private'}));
    const bad=await fetch(baseURL+'/secureshop/pricing/health',{headers:{authorization:'Bearer '+randomBytes(32).toString('base64url')}});
    assert.equal(bad.status,401);await bad.arrayBuffer();assert.equal(dispatches,1);
    const malformed=await fetch(baseURL+'/secureshop/pricing/observe',{method:'POST',headers:{authorization:'Bearer '+token,'content-type':'application/json'},body:JSON.stringify({...request,root:'/private'})});
    assert.equal(malformed.status,400);await malformed.arrayBuffer();assert.equal(dispatches,1);
    const send = () => fetch(baseURL+'/secureshop/pricing/observe',{method:'POST',headers:{authorization:'Bearer '+token,'content-type':'application/json'},body:JSON.stringify({...request,...binding()})});
    const concurrent = await Promise.all([send(),send()]);
    assert.deepEqual(concurrent.map(x=>x.status).sort(),[200,503]);
    await Promise.all(concurrent.map(x=>x.arrayBuffer())); assert.equal(dispatches,2);
    const disconnect = new AbortController();
    const started = new Promise(resolve=>{onDispatch=resolve;});
    const abandoned = fetch(baseURL+'/secureshop/pricing/observe',{method:'POST',signal:disconnect.signal,headers:{authorization:'Bearer '+token,'content-type':'application/json'},body:JSON.stringify({...request,...binding()})});
    await started; disconnect.abort(); await assert.rejects(abandoned); onDispatch=undefined;
    assert.equal(dispatches,3);
    for (const path of ['/usr/local/libexec/dvaia-owned-pricing-http-worker.js','/usr/share/dvaia/owned-pricing-http-assets.json']) {
      assert.throws(()=>fs.openSync(path,'w'),error=>['EACCES','EROFS'].includes(error.code));
    }
  } finally { await handler.close();server.closeAllConnections();await new Promise(resolve=>server.close(resolve)); }
  const descendants=fs.readdirSync('/proc').filter(x=>/^\d+$/.test(x)&&Number(x)!==process.pid&&Number(x)!==1);
  assert.deepEqual(descendants,[], 'namespace helper processes must be reaped');
  console.log(JSON.stringify({status:'passed',proofs,actualHttpDispatches:dispatches,readinessSeparate:true,fixedDenied:true,wrapperMismatchDenied:true,
    malformedDenied:true,wrongBearerDenied:true,concurrencyDenied:true,disconnectDrained:true,checkedAssetsReadOnly:true,preAbort:true,timeoutDrained:true,descendantsAbsent:true,actualModelCalls:0,
    packages:fs.readFileSync('/usr/share/dvaia/pricing-packages.txt','utf8'),assets:JSON.parse(fs.readFileSync('/usr/share/dvaia/owned-pricing-http-assets.json','utf8'))}));
}
main().catch(error=>{console.error(JSON.stringify({status:'failed',code:error.code||error.name,message:error.message,diagnostic:error.diagnostic,stack:error.stack?.split('\n').slice(0,5)}));process.exitCode=1;});
