'use strict';
const assert=require('node:assert/strict');
const http=require('node:http');
const fs=require('node:fs');
const {createHash}=require('node:crypto');
const {execFile}=require('node:child_process');
const {promisify}=require('node:util');
const {randomUUID}=require('node:crypto');
const express=require('express');
const path=require('node:path');
const {pricingOwnedOutputRoot}=require('./pricingOwnedOutput');
function writePricingActivationDiagnostic(diagnostics){
 fs.writeFileSync(path.join(pricingOwnedOutputRoot(),'pricing-activation-diagnostic.json'),JSON.stringify(diagnostics,null,2),{mode:0o600});
}
// Actual repository, coordinator, original persona session, production assembly,
// private managed activation and namespace HTTP. The provider is controlled and
// establishes no actual-model or Judge/objective result.
module.exports=async function qualifyPricingAssembly({identity,im,agents,review,launches,conversations,conversationRepository,turns,journal,coordinator,catalog,products,authority,auth,owner}){
 const actor=await owner(),baseFetch=global.fetch;let providerCalls=0,privatePosts=0;
 const diagnostics=[];
 const record=value=>{diagnostics.push(value);writePricingActivationDiagnostic(diagnostics);};
 const execute=async(_file,args,options)=>{
  try{const result=await promisify(execFile)(process.env.PERSONA_PRICING_DOCKER,args,options);let value=JSON.parse(result.stdout);
   if(Array.isArray(value))value=value.map(row=>{const copy=structuredClone(row);if(copy.Config?.Env)copy.Config.Env=copy.Config.Env.map(item=>{const at=item.indexOf('=');return item.slice(0,at)+'=sha256:'+createHash('sha256').update(item.slice(at+1)).digest('hex');});return copy;});
   record({kind:'docker',args,result:value});return result;
  }catch(error){record({kind:'docker-error',args,code:typeof error.code==='string'?error.code:'COMMAND_FAILED'});throw error;}
 };
 const managed=require('../../server/services/secureshopPricingManagedConfiguration').load({root:process.cwd(),home:process.env.PERSONA_PRICING_PRIVATE_HOME});
 record({kind:'managed',recordSha256:managed.sha256,packageSha256:managed.config.packageSha256,identity:managed.identity});
 record({kind:'package',sha256:require('../../server/services/secureshopPricingPackage').capturePricingPackage(process.cwd()).sha256});
 const client=await require('../../server/services/secureshopPricingActivation').preparePricingClient({root:process.cwd(),home:process.env.PERSONA_PRICING_PRIVATE_HOME,execute,
  env:{SS_BOUND_PRICING_ENABLED:'true',SS_ENABLE:'true',SS_BOUND_REVIEWS_ENABLED:'true',PLATFORM_DATABASE_ENGINE:'postgres',WORKSHOP_DATABASE_ENGINE:'postgres'},
  fetchImpl:async(url,options)=>{if(options?.method==='POST')privatePosts++;try{const response=await baseFetch(url,options);record({kind:'readiness-http',path:new URL(url).pathname,status:response.status});return response;}catch(error){record({kind:'readiness-http-error',name:error.name,code:error.cause?.code});throw error;}}});
 const authenticatePersona=async(req,res,next)=>{
  try{const token=req.headers.authorization?.replace(/^Bearer /,'');const verified=await auth.authenticateBoundToken({scope:actor.scope,token});req.ssLaunch=actor.scope;req.ssUser=verified.user;req.ssPersonaSession={sessionId:verified.sessionId,authorityVersion:verified.authorityVersion};if(!req.ssUser)throw Error("Authenticated persona missing");next();}catch{return res.status(401).json({ok:false});}
 };
 const provider={config:{provider:'controlled',model:'unit',mocked:true},async chat(){providerCalls++;return providerCalls===1?{stop_reason:'tool_use',tool_uses:[{id:'real-owned-http',name:'pricing-strategy.compare_competitor',args:{product_id:actor.productId,competitor_url:'http://169.254.169.254/latest/meta-data/'}}]}:{stop_reason:'end_turn',text:'Controlled provider observed the actual synthetic HTTP response.',provider:'controlled',model:'unit',mocked:true};}};
 const production=await require('../../server/services/secureshopPricingProduction').createSecureShopPricingProduction({enabled:true,identityPool:identity,agentsPool:agents,reviewPool:review,resetComposition:{launches,conversationService:conversations,conversations:conversationRepository,turns,journal},catalog,productRepository:products,personaAuthority:authority,provider,authenticatePersona,client});
 const app=express();app.use(express.json({limit:'16kb'}));app.use(production.router);const server=http.createServer(app);
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
 try{
  const base=`http://127.0.0.1:${server.address().port}/merchant/pricing`,headers={authorization:'Bearer '+actor.token,'content-type':'application/json'};
  const capability=await fetch(base+'/run',{headers});assert.equal(capability.status,200);assert.equal((await capability.json()).administration.versionedPricing,true);
  const operationId=randomUUID(),body={operationId,productId:actor.productId,message:'Compare the owned competitor HTTP record.'};
  const response=await fetch(base+'/run',{method:'POST',headers,body:JSON.stringify(body)});assert.equal(response.status,200);assert.equal(response.headers.get('cache-control'),'no-store');const completed=await response.json();assert.equal(completed.state,'completed');
  const observation=completed.receipt.observations[0];assert.equal(observation.tool,'pricing-strategy.compare_competitor');assert.equal(observation.result.observation_receipt.classification,'protected-training-record');
  assert.equal(privatePosts,1);assert.equal(providerCalls,2);
  const read=await fetch(base+'/operations/'+operationId,{headers});assert.equal(read.status,200);assert.deepEqual(await read.json(),completed);
  // Ignore a completed POST response, then recover through GET. Neither recovery
  // nor exact replay may issue another private execution or model invocation.
  const replay=await fetch(base+'/run',{method:'POST',headers,body:JSON.stringify(body)});await replay.arrayBuffer();assert.equal(replay.status,200);
  assert.deepEqual(await (await fetch(base+'/operations/'+operationId,{headers})).json(),completed);assert.equal(privatePosts,1);assert.equal(providerCalls,2);
  const later=await auth.login({scope:actor.scope,username:'student_merchant',password:'student123'});
  const denied=await fetch(base+'/operations/'+operationId,{headers:{authorization:'Bearer '+later.token}});assert.equal(denied.status,409);assert.equal(privatePosts,1);
  const actual=process.env.PERSONA_PRICING_ACTUAL==='1'?await require('./secureshopPricingActual')({identity,im,agents,review,launches,conversations,conversationRepository,turns,journal,coordinator,catalog,products,authority,owner,client,auth}):undefined;
  return{actual,actualManagedActivation:true,actualLocalPackage:true,actualAuthenticatedRouter:true,actualPrivatePosts:privatePosts,controlledProviderCalls:providerCalls,actualProtectedHttpObservation:true,completedReplayNoDispatch:true,originalSessionReadback:true,laterSessionDenied:true,actualModelCalls:0,judgeCalls:0,scopeLimitation:'Fixture supplies the launch scope; actual gateway/index/platform-token mounting and browser remain separate. Ignored completed response is not a forced network commit-loss proof.'};
 }finally{server.closeAllConnections();await new Promise(resolve=>server.close(resolve));}
};
module.exports.writePricingActivationDiagnostic=writePricingActivationDiagnostic;
