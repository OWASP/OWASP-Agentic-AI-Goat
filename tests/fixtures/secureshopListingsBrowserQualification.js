'use strict';
// Actual isolated Chromium attribution only. Provenance and boundary fixtures are controlled.
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const {randomUUID}=require('node:crypto');
const {spawn}=require('node:child_process');
const {prepareListingAdmission,hash}=require('../../server/services/secureshopListingJournalContract');
const {createTurnRequest}=require('../../server/services/secureshopTurnRequest');
const {createConversationBinding}=require('../../server/services/secureshopConversationBinding');
const {createListingsGeneratedBrowserEvidenceAdapter,buildListingsGeneratedBrowserEvidence}=require('../../server/services/secureshopListingsEvidence');
const {loadSecureShopProductDescriptionRenderer}=require('../../server/services/secureshopProductDescriptionRenderer');
const {createXssBrowserQualification}=require('../../server/services/xssBrowserQualification');
const {launchOwnedAssessmentBrowser}=require('./fullBackendAssessmentBrowser');
const {createOwnedChildren}=require('./fullBackendBootControls');
function admission(action='import'){
 return prepareListingAdmission({scope:{launchId:randomUUID(),scenarioId:randomUUID(),generation:1,platformOwnerId:1,platformSessionId:2},
  persona:{id:3,role:'merchant'},personaSession:{sessionId:randomUUID(),authorityVersion:'1'},targetId:randomUUID(),mode:'vuln',catalogRevision:'0',
  request:action==='import'?{version:1,action,operationId:randomUUID(),json_url:'http://owned/internal.json',xml_url:null}
   :{version:1,action,operationId:randomUUID(),title:'Synthetic product',description:'<img src=x onerror=alert(1)>'}});
}
async function browserFixture(html, qualifier, renderer){
 const a=prepareListingAdmission({...admission('rewrite').binding,request:{...admission('rewrite').request,description:html}}),model={provider:'qualified-provider',model:'qualified-model',callId:'exact-model-call',mocked:false,fallback:false};
 const receipt={version:1,operationId:a.request.operationId,requestSha256:a.requestSha256,sourceSha256:hash(JSON.stringify([a.request.title,a.request.description])),...model,html,htmlSha256:hash(html)};
 const save={version:1,saveOperationId:randomUUID(),rewriteOperationId:a.request.operationId,targetId:a.binding.targetId,
 productId:5,bindingSha256:a.bindingSha256,requestSha256:hash('save'),sourceSha256:receipt.sourceSha256,htmlSha256:receipt.htmlSha256};
 const source={admission:a,saveOperationId:save.saveOperationId,productId:5,html,htmlSha256:hash(html)};
 const binding=createConversationBinding(a.binding.scope,a.binding.persona),sessionId=randomUUID();
 const request=createTurnRequest({sessionId,requestId:a.request.operationId,binding,message:a.requestJson});
 const turn={sessionId,requestId:a.request.operationId,requestHash:request.hash,requestVersion:request.version,status:'completed',binding,
 result:{text:html,stopReason:'end_turn',steps:1,hops:[],taskMetadata:{listings:{action:'rewrite',decision:'rewritten',operationId:a.request.operationId,model}}}};
 const execution={runId:'browser-run',ownerKey:'owner',durableGeneration:3},browserRequestId=randomUUID();
 const boundary={identity:execution,async check(){},async effectWithReceipt(node,fn){return {value:await fn(),receipt:{version:1,status:'completed',runId:execution.runId,ownerKey:execution.ownerKey,generation:'3',effectKey:`${browserRequestId}:${node}`}};}};
 const adapter=createListingsGeneratedBrowserEvidenceAdapter({browserQualification:qualifier,
 renderProductDescription:renderer.renderProductDescription,componentSourceDigest:renderer.sourceSha256,componentArtifactDigest:renderer.artifactSha256});
 const browserEvidence=await adapter.capture({source,boundary,execution,requestId:browserRequestId});
 return {admission:a,operation:{operationId:a.request.operationId,state:'completed',receipt},save,source,readback:structuredClone(source),turn,execution,browserEvidence,qualifyModel:()=>true};
}

async function main(){
 const root=process.argv[2],executable=process.argv[3];
 const owned=createOwnedChildren(spawn),signal=AbortSignal.timeout(70000);
 let browser,qualifier;const observations=[];
 const report={scope:'actual isolated ProductDescription browser attribution; controlled model/boundary receipts',actualModelCalls:0,judgeCalls:0,databaseCalls:0,cases:[]};
 try{
  browser=await launchOwnedAssessmentBrowser({root,admission:{executable},owned,signal});
  qualifier=createXssBrowserQualification({connectBrowser:()=>require('puppeteer').connect({browserWSEndpoint:browser.endpoint,protocolTimeout:10000}),timeoutMs:8000});
  const observed={async qualify(markup,options){const result=await qualifier.qualify(markup,options);observations.push(result);return result;}};
  const renderer=loadSecureShopProductDescriptionRenderer();
  report.component={sourceSha256:renderer.sourceSha256,artifactSha256:renderer.artifactSha256};
  const positive=await browserFixture('<img src=x onerror="alert(1)">',observed,renderer);
  assert.equal(buildListingsGeneratedBrowserEvidence(positive).length,1);
  report.cases.push({name:'raw onerror in actual shared component',eligible:true,browser:observations.at(-1)});
  const manual={...positive,turn:null};assert.equal(buildListingsGeneratedBrowserEvidence(manual).length,0);
  report.cases.push({name:'manual HTML without canonical rewrite attribution',eligible:false});
  const escaped=await browserFixture('&lt;img src=x onerror="alert(1)"&gt;',observed,renderer);
  assert.equal(buildListingsGeneratedBrowserEvidence(escaped).length,0);
  report.cases.push({name:'escaped HTML',eligible:false,browser:observations.at(-1)});
  const unrelated=await browserFixture('<p>Owned benign source</p>',observed,{...renderer,
   renderProductDescription:async(product,options)=>'<img src=x onerror="alert(9)">'+await renderer.renderProductDescription(product,options)});
  assert.equal(buildListingsGeneratedBrowserEvidence(unrelated).length,0);
  assert.equal(observations.at(-1).executed,false);assert.equal(observations.at(-1).targetEventExecuted,false);
  report.cases.push({name:'unrelated sibling is suppressed and cannot attribute execution to saved source',eligible:false,browser:observations.at(-1)});
  report.passed=true;
 }catch(error){report.passed=false;report.error=error.stack;process.exitCode=1;}
 finally{
  await qualifier?.close();await browser?.close();await owned.cleanup();
  report.cleanup=JSON.parse(fs.readFileSync(path.join(root,'assessment-browser-cleanup.json'),'utf8'));
  assert.equal(report.cleanup.closed,true);
  fs.writeFileSync(path.join(root,'result.json'),JSON.stringify(report,null,2));
 }
}
main().catch(error=>{console.error(error);process.exitCode=1;});
