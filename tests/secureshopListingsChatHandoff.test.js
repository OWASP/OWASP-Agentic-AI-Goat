'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {randomUUID,createHash}=require('node:crypto');
const {createListingActionSetup,projectListingActionSetup}=require('../server/services/secureshopRoleListingActionSetup');
const {createListingsApplication}=require('../server/services/secureshopListingsApplication');
const outer={version:1,featureId:'merchant_assistant',policyVersion:'owned-merchant-read-and-confirmation-v1',effectiveMode:'vuln',scope:{kind:'launch_feature',id:'merchant_assistant'}};
const listings={version:1,featureId:'listings',policyVersion:'owned-listing-import-v1',effectiveMode:'vuln',scope:{kind:'launch_feature',id:'listings'}};
const digest=v=>createHash('sha256').update(JSON.stringify(v)).digest('hex');
function fixture(){const scope={launchId:randomUUID(),scenarioId:randomUUID(),generation:1,platformOwnerId:1,platformSessionId:2};
 const context={scope,persona:{id:12,role:'merchant'},personaSession:{sessionId:randomUUID(),authorityVersion:'1'},
  target:{targetId:randomUUID(),scene:{sceneId:randomUUID(),sceneGeneration:1}}};
 const product={id:7,name:'Selected title',description:'Literal <em>description</em>',description_html:'<img src=x onerror=lab()>',
  price:4.25,category:'Owned',images:['https://owned.example/i'],template_source:'template',status:'active',stock_quantity:9,retailer_id:12};
 const snapshot={id:product.id,name:product.name,description:product.description,description_html:product.description_html,
  price:product.price,category:product.category,status:product.status,stock_quantity:product.stock_quantity};
 const selected={version:1,kind:'merchant_product',choiceId:randomUUID(),sourceId:7,snapshotSha256:digest(snapshot),card:{}};
 const source={sessionId:randomUUID(),requestId:randomUUID()},origin={step:1,callId:'tool'};
 const proposal=createListingActionSetup({context,source,origin,action:'rewrite',selected,input:{},modeCapability:outer,listingsModeCapability:listings,product});
 const chatSource={...source,proposalId:proposal.proposalId};return{context,product,proposal,chatSource};}
function app(f,options={}){let saved=0,ran=0,prepared=0,catalogReads=0;
 const admission={scope:f.context.scope,persona:f.context.persona,personaSession:f.context.personaSession,
  targetId:f.context.target.targetId,mode:'vuln',catalogRevision:'1',request:{version:1,action:'rewrite',operationId:f.proposal.operationId,
   title:f.product.name,description:f.product.description}};
 const authority={capture(x){return{binding:{...x.scope,personaId:x.personaId,role:x.role,sessionId:x.sessionId,authorityVersion:x.authorityVersion},async assertRemoteAdmission(){}};}};
 const catalog={async getOwnedMerchantProduct(){catalogReads++;return{binding:f.context.target,product:f.product};},async prepareTarget(){prepared++;return f.context.target;}};
 const composition={async recoverAdmission(){if(options.fresh)throw Object.assign(Error(),{code:'LISTING_NOT_FOUND'});return admission;},
  async run(_a,{beforeEffect}){ran++;if(options.fresh){await options.duringModel?.();await beforeEffect?.();}
   return{operation:{operationId:f.proposal.operationId,state:'completed',receipt:{html:'<p>real</p>'}}};},
  async recover(){return{operation:{operationId:f.proposal.operationId,state:'completed',receipt:{html:'<p>real</p>'}}};},async resume(){}};
 const rewriteSaveRepository={async save(){saved++;return{saveOperationId:options.saveOperationId,rewriteOperationId:f.proposal.operationId,productId:7};},
  async read({saveOperationId,admission:prepared}){if(saveOperationId!==options.saveOperationId)throw Object.assign(Error(),{code:'LISTING_NOT_FOUND'});
   const exact=require('../server/services/secureshopListingRewriteSaveContract').prepareListingRewriteSave({admission:prepared,
    saveOperationId,productId:7,item:f.proposal.item});
   return{saveOperationId,rewriteOperationId:f.proposal.operationId,requestedProductId:7,
    requestSha256:options.preemptHash?'f'.repeat(64):exact.itemSha256,productId:7};}};
 const application=createListingsApplication({composition,prepareTarget:async()=>({targetId:f.context.target.targetId,mode:'vuln',catalogRevision:'1'}),
  launches:{async assertCurrent(){}},personaAuthority:authority,rewriteSaveRepository,catalog,
  readChatSetup:async()=>({privateProposal:f.proposal,publicSetup:projectListingActionSetup(f.proposal)})});
 return{application,catalog,counts:()=>({saved,ran,prepared,catalogReads})};}
test('chat rewrite checks frozen full owned product again after model delay, before saved operation',async()=>{
 const f=fixture(),x=app(f,{fresh:true,duringModel(){f.product={...f.product,price:8.25};}});
 await assert.rejects(x.application.run({...f.context,request:{action:'rewrite',operationId:f.proposal.operationId},chatSource:f.chatSource}),{code:'ROLE_LISTINGS_PRODUCT_STALE'});
 assert.equal(x.counts().ran,1);assert.equal(x.counts().catalogReads>=2,true);
});
test('chat rewrite save rejects changed owned product before physical save; saved GET uses no catalog preparation',async()=>{
 const f=fixture(),saveOperationId=randomUUID(),x=app(f,{saveOperationId});
 const saved=await x.application.savedRewrite({...f.context,saveOperationId,chatSource:f.chatSource});
 assert.deepEqual(saved,{ok:true,state:'completed',saveOperationId,rewriteOperationId:f.proposal.operationId,productId:7});
 assert.deepEqual(x.counts(),{saved:0,ran:0,prepared:0,catalogReads:0});
 f.product={...f.product,template_source:'changed'};
 await assert.rejects(x.application.save({...f.context,request:{rewriteOperationId:f.proposal.operationId,saveOperationId:randomUUID()},chatSource:f.chatSource}),{code:'ROLE_LISTINGS_PRODUCT_STALE'});
 assert.equal(x.counts().saved,0);
});
test('same scene with substituted target is stale before model admission',async()=>{
 const f=fixture(),x=app(f,{fresh:true}),original=x.catalog.getOwnedMerchantProduct;
 x.catalog.getOwnedMerchantProduct=async()=>{const value=await original();return{...value,binding:{...value.binding,targetId:randomUUID()}};};
 await assert.rejects(x.application.run({...f.context,request:{action:'rewrite',operationId:f.proposal.operationId},chatSource:f.chatSource}),{code:'SHOP_SCENE_STALE'});
 assert.equal(x.counts().ran,0);
});
test('protected chat save GET does not attribute a different immutable same-ID item to the setup',async()=>{
 const f=fixture(),saveOperationId=randomUUID(),x=app(f,{saveOperationId,preemptHash:true});
 await assert.rejects(x.application.savedRewrite({...f.context,saveOperationId,chatSource:f.chatSource}),{code:'ROLE_LISTINGS_SETUP_MISMATCH'});
 assert.deepEqual(x.counts(),{saved:0,ran:0,prepared:0,catalogReads:0});
});
test('committed same-key rewrite replays after product edit without dispatch or fresh product read',async()=>{
 const f=fixture(),x=app(f);f.product={...f.product,price:11.25};
 const result=await x.application.run({...f.context,request:{action:'rewrite',operationId:f.proposal.operationId},chatSource:f.chatSource});
 assert.equal(result.state,'completed');assert.deepEqual(x.counts(),{saved:0,ran:1,prepared:0,catalogReads:0});
});
test('HTTP chat handoff accepts source tuple only and saved GET passes exact protected source',async t=>{
 const express=require('express'),{createBoundListingsRouter}=require('../server/routes/secureshop/boundListings');
 const f=fixture(),calls=[];const application={async run(v){calls.push(['run',v]);return{ok:false,state:'admitted',operationId:v.request.operationId};},
  async operation(){},async resume(){},async save(v){calls.push(['save',v]);return{ok:true,state:'completed'};},
  async savedRewrite(v){calls.push(['get',v]);return{ok:true,state:'completed',saveOperationId:v.saveOperationId,rewriteOperationId:f.proposal.operationId,productId:7};}};
 const app=express();app.use(express.json());app.use(createBoundListingsRouter({application,authenticatePersona(req,_res,next){
  req.ssLaunch=f.context.scope;req.ssUser=f.context.persona;req.ssPersonaSession=f.context.personaSession;next();}}));
 const server=await new Promise(resolve=>{const s=app.listen(0,'127.0.0.1',()=>resolve(s));});
 t.after(()=>new Promise(resolve=>{server.close(resolve);server.closeAllConnections();}));
 const base=`http://127.0.0.1:${server.address().port}/merchant/listings`;
 const post=(path,body)=>fetch(base+path,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body)});
 assert.equal((await post('/assist-write',{operationId:f.proposal.operationId,chatSource:f.chatSource})).status,202);
 assert.equal(calls[0][1].request.action,'rewrite');assert.deepEqual(calls[0][1].chatSource,f.chatSource);
 assert.equal((await post('/assist-write',{operationId:f.proposal.operationId,chatSource:f.chatSource,title:'override'})).status,400);
 assert.equal((await post('/rewrite-save',{rewriteOperationId:f.proposal.operationId,saveOperationId:randomUUID(),chatSource:f.chatSource,item:{}})).status,400);
 const saveOperationId=randomUUID(),query=new URLSearchParams(f.chatSource);
 assert.equal((await fetch(`${base}/rewrite-saves/${saveOperationId}?${query}`)).status,200);
 assert.equal(calls.at(-1)[1].saveOperationId,saveOperationId);assert.deepEqual(calls.at(-1)[1].chatSource,f.chatSource);
 assert.equal((await fetch(`${base}/rewrite-saves/${saveOperationId}`)).status,400);
});
