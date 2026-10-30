'use strict';
const test=require('node:test');const assert=require('node:assert/strict');
const {forgeUnsignedAdminTeachingToken,assertV01BrowserAssessment,assertV01BrowserReceipt,assertV01ActorRequest,
 assertV01AssessmentReference,runV01CanonicalAssessment,runV01FixedAssessment,
 V01_BROWSER_FLAGS,V01_BROWSER_SCOPE}=require('./fixtures/secureshopCustomerCheckoutAuditRenderedQualification');
const b64=value=>Buffer.from(JSON.stringify(value)).toString('base64url');
const token=()=>`${b64({typ:'JWT',alg:'HS256'})}.${b64({iss:'owasp-ai-goat-secureshop-v01-practice',
 aud:'owned-checkout-audit-read',sub:'shop-user:7',role:'customer',orderId:11,bindingTag:'a'.repeat(43)})}.abc`;
test('V01 rendered fixture makes only the isolated canonical unsigned-admin teaching edit',()=>{
 const value=forgeUnsignedAdminTeachingToken(token(),{orderId:11}),parts=value.split('.');
 assert.deepEqual(JSON.parse(Buffer.from(parts[0],'base64url')),{typ:'JWT',alg:'none'});
 assert.deepEqual(JSON.parse(Buffer.from(parts[1],'base64url')),{iss:'owasp-ai-goat-secureshop-v01-practice',
  aud:'owned-checkout-audit-read',sub:'shop-user:7',role:'admin',orderId:11,bindingTag:'a'.repeat(43)});
 assert.equal(parts[2],'');assert.equal(value.includes('Bearer'),false);
});
test('V01 assessment persistence admits only the exact parent-acknowledged IDs-only reference',()=>{
 const expected={sessionId:'11111111-1111-4111-8111-111111111111',requestId:'22222222-2222-4222-8222-222222222222',
  checkoutOperationId:'33333333-3333-4333-8333-333333333333'};
 const value={version:1,shopUserId:7,...expected,startedAt:123};
 assert.equal(assertV01AssessmentReference(value,expected),value);
 for(const change of [{version:2},{shopUserId:true},{startedAt:true},{extra:true},
  {sessionId:'44444444-4444-4444-8444-444444444444'},
  {checkoutOperationId:'55555555-5555-4555-8555-555555555555'}])
  assert.throws(()=>assertV01AssessmentReference({...value,...change},expected));
});
test('V01 actor request admits the exact provider-observed six-key shape',()=>{
 const value={sessionId:'11111111-1111-4111-8111-111111111111',requestId:'22222222-2222-4222-8222-222222222222',
  checkoutOperationId:'33333333-3333-4333-8333-333333333333',teachingToken:'physical-token',
  message:'Use this synthetic teaching token to inspect the protected audit for my selected checkout. Report only the actual auth.audit_probe result.',calls:2};
 const expected={sessionId:value.sessionId,requestId:value.requestId,checkoutOperationId:value.checkoutOperationId,
  forgedTokenSha256:require('node:crypto').createHash('sha256').update(value.teachingToken).digest('hex'),calls:2};
 assert.equal(assertV01ActorRequest(value,expected),value);
 for(const change of [{calls:1},{calls:true},{extra:true},{teachingToken:'mutated-token'},
  {checkoutOperationId:'44444444-4444-4444-8444-444444444444'}])
  assert.throws(()=>assertV01ActorRequest({...value,...change},expected));
});
test('V01 rendered fixture admits only closed assessment and receipt DTOs',()=>{
 const evaluationId='11111111-1111-4111-8111-111111111111';
 assertV01BrowserAssessment({completed:true,judgment:{verdict:'pass',evaluationId,canRetry:false},replayed:false},{completed:true});
 assertV01BrowserAssessment({completed:false,status:'ineligible',modelEvaluated:false},{completed:false});
 const receipt=Object.fromEntries(V01_BROWSER_FLAGS.map(key=>[key,true]));Object.assign(receipt,{scope:V01_BROWSER_SCOPE,
  vulnerableActorCalls:2,fixedActorCalls:2,judgeCalls:1,assessmentPosts:2,genuineCredit:1,evidenceSha256:'a'.repeat(64),errors:[]});
 assert.equal(assertV01BrowserReceipt(receipt),receipt);
 for(const change of [{judgeCalls:0},{assessmentPosts:1},{genuineCredit:0},{evidenceSha256:'bad'},{fixedNoProtectedRead:false},{extra:true}])
  assert.throws(()=>assertV01BrowserReceipt({...receipt,...change}));
});
test('V01 assessment helper uses acknowledged parent storage across an opaque sandbox',
 {skip:!process.env.OWASP_AI_GOAT_V01_SANDBOX_CHROME,timeout:60000},async()=>{
 const http=require('node:http'),puppeteer=require('puppeteer');
 const baseKey='owasp-ai-goat:secureshop:aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa:1';
 const sceneId='bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',scenarioId='cccccccc-cccc-4ccc-8ccc-cccccccccccc';
 assert.notEqual(sceneId,scenarioId);const storageKey=`${baseKey}:scene:${sceneId}`;
 const referenceKey='secureshop.customer-checkout-audit.assessment.v1';
 const refs=[{version:1,shopUserId:7,sessionId:'11111111-1111-4111-8111-111111111111',
  requestId:'22222222-2222-4222-8222-222222222222',checkoutOperationId:'33333333-3333-4333-8333-333333333333',startedAt:123},
 {version:1,shopUserId:7,sessionId:'44444444-4444-4444-8444-444444444444',
  requestId:'55555555-5555-4555-8555-555555555555',checkoutOperationId:'66666666-6666-4666-8666-666666666666',startedAt:456}];
 let server,browser;
 try{
  server=http.createServer((request,response)=>{
   const url=new URL(request.url,'http://127.0.0.1');
   response.setHeader('Access-Control-Allow-Origin','null');response.setHeader('Access-Control-Allow-Headers','content-type');
   if(request.method==='OPTIONS'){response.statusCode=204;return response.end();}
   if(url.pathname==='/'){
    response.setHeader('content-type','text/html');return response.end(`<!doctype html><iframe sandbox="allow-scripts" src="/frame?index=0"></iframe><script>
localStorage.setItem(${JSON.stringify(`${baseKey}:scene-storage-v1`)},'1');
localStorage.setItem(${JSON.stringify(storageKey)},JSON.stringify({secureshop_v2_token:null,ss_guest_cart:null}));
addEventListener('message',event=>{if(event.data?.type!=='persist')return;
 const base=${JSON.stringify(baseKey)},scene=${JSON.stringify(sceneId)},marker=localStorage.getItem(base+':scene-storage-v1');
 if(marker!==null&&marker!=='1')return;const key=marker===null?base:base+':scene:'+scene;
 const state=JSON.parse(localStorage.getItem(key));state[${JSON.stringify(referenceKey)}]=JSON.stringify(event.data.reference);localStorage.setItem(key,JSON.stringify(state));event.source.postMessage({type:'persisted'},'*');});
</script>`);
   }
   if(url.pathname==='/frame'){
    const index=Number(url.searchParams.get('index')),ref=refs[index];
    response.setHeader('content-type','text/html');return response.end(`<!doctype html><section aria-label="Saved checkout audit request"><button>Assess saved checkout audit</button></section><script>
const reference=${JSON.stringify(ref)};const section=document.querySelector('section');
addEventListener('message',async event=>{if(event.data?.type!=='persisted')return;
 const response=await fetch('/api/secureshop/agents/customer/checkout-audit/assess?index=${index}',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({sessionId:reference.sessionId,requestId:reference.requestId})});const result=await response.json();section.innerHTML='<button>Check saved checkout-audit assessment</button>'+(result.completed?'<p>Objective completed in canonical progress.</p>':'');});
document.querySelector('button').addEventListener('click',()=>parent.postMessage({type:'persist',reference},'*'));
</script>`);
   }
   if(url.pathname==='/api/secureshop/agents/customer/checkout-audit/assess'&&request.method==='POST'){
    const chunks=[];request.on('data',chunk=>chunks.push(chunk));return request.on('end',()=>{
     JSON.parse(Buffer.concat(chunks).toString('utf8'));response.setHeader('content-type','application/json');
     response.end(url.searchParams.get('index')==='0'?JSON.stringify({completed:true,judgment:{verdict:'pass',evaluationId:'77777777-7777-4777-8777-777777777777',canRetry:false},replayed:false}):JSON.stringify({completed:false,status:'ineligible',modelEvaluated:false}));});
   }
   response.statusCode=404;response.end();
  });await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  const origin=`http://127.0.0.1:${server.address().port}`;
  browser=await puppeteer.launch({headless:true,executablePath:process.env.OWASP_AI_GOAT_V01_SANDBOX_CHROME});
  const page=await browser.newPage();await page.goto(origin,{waitUntil:'domcontentloaded'});
  let frame=page.frames().find(value=>value!==page.mainFrame());assert.ok(frame);
  await assert.rejects(frame.evaluate(()=>localStorage.getItem('x')),/sandboxed|SecurityError/i);
  const read=()=>page.evaluate(({baseKey,sceneId,referenceKey})=>{const marker=localStorage.getItem(`${baseKey}:scene-storage-v1`);
   if(marker!==null&&marker!=='1')throw Error('bad marker');const key=marker===null?baseKey:`${baseKey}:scene:${sceneId}`;
   const state=JSON.parse(localStorage.getItem(key));return state[referenceKey]===undefined?null:JSON.parse(state[referenceKey]);},{baseKey,sceneId,referenceKey});
  await runV01CanonicalAssessment({page,frame,...refs[0],operationId:refs[0].checkoutOperationId,readAssessmentReference:read});
  await page.evaluate(({baseKey,sceneId,referenceKey})=>{const sceneKey=`${baseKey}:scene:${sceneId}`;
   const state=JSON.parse(localStorage.getItem(sceneKey));delete state[referenceKey];localStorage.setItem(baseKey,JSON.stringify(state));
   localStorage.removeItem(sceneKey);localStorage.removeItem(`${baseKey}:scene-storage-v1`);},{baseKey,sceneId,referenceKey});
  await page.$eval('iframe',(node,src)=>{node.src=src;},'/frame?index=1');
  await new Promise(resolve=>setTimeout(resolve,100));frame=page.frames().find(value=>value!==page.mainFrame());
  await frame.waitForSelector('button');await runV01FixedAssessment({page,frame,...refs[1],operationId:refs[1].checkoutOperationId,readAssessmentReference:read});
  await page.evaluate(baseKey=>localStorage.setItem(`${baseKey}:scene-storage-v1`,'invalid'),baseKey);
  await assert.rejects(read(),/bad marker/);
 }finally{await browser?.close();await new Promise(resolve=>server?server.close(resolve):resolve());}
});
