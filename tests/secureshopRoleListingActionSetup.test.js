'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {randomUUID,createHash}=require('node:crypto');
const {createListingsChatSetup,validateListingActionSetup,projectListingActionSetup}=require('../server/services/secureshopRoleListingActionSetup');
const mode={version:1,featureId:'merchant_assistant',policyVersion:'owned-merchant-read-and-confirmation-v1',effectiveMode:'vuln',scope:{kind:'launch_feature',id:'merchant_assistant'}};
const scope=()=>({launchId:randomUUID(),scenarioId:randomUUID(),generation:1,platformOwnerId:1,platformSessionId:2});
const digest=value=>createHash('sha256').update(JSON.stringify(value)).digest('hex');
function fixture(){const sceneId=randomUUID(),context={scope:scope(),persona:{id:12,role:'merchant'},
 personaSession:{sessionId:randomUUID(),authorityVersion:'1'},target:{targetId:randomUUID(),scene:{sceneId,sceneGeneration:1}}};
 const product={id:7,name:'Owned title',description:'<b>literal</b>',description_html:'<img src=x onerror=lab()>',
  price:3.25,category:'Catalog',images:['https://images.example/one'],template_source:'raw template',retailer_id:12,
  status:'active',stock_quantity:9};
 const snapshot={id:product.id,name:product.name,description:product.description,description_html:product.description_html,
  price:product.price,category:product.category,status:product.status,stock_quantity:product.stock_quantity};
 const selected={version:1,kind:'merchant_product',choiceId:randomUUID(),sourceId:product.id,snapshotSha256:digest(snapshot),
  card:{version:1,kind:'merchant_product',choiceId:randomUUID(),title:product.name,detail:'Owned'}};
 const source={sessionId:randomUUID(),requestId:randomUUID()},origin={step:1,callId:'tool_1'};
 const adapter=createListingsChatSetup({getApplication:()=>({modeAuthority:null,async prepareChatSetup(){return{product};}})});
 return{context,product,selected,source,origin,adapter};}
test('rewrite setup retains exact selected owned snapshot and reconstructs after JSONB key reordering without effects',async()=>{
 const f=fixture(),input={context:f.context,source:f.source,origin:f.origin,action:'rewrite',selected:f.selected,input:{},modeCapability:mode};
 const proposal=await f.adapter.prepare(input),publicSetup=projectListingActionSetup(proposal);
 assert.equal(publicSetup.kind,'listing_rewrite_setup');assert.equal(publicSetup.product.choiceId,f.selected.choiceId);
 assert.equal(publicSetup.product.name,f.product.name);assert.equal(publicSetup.product.templateSource,f.product.template_source);
 assert.equal(Object.hasOwn(publicSetup.product,'id'),false);
 const jsonb=Object.fromEntries(Object.entries(JSON.parse(JSON.stringify(proposal))).sort(([a],[b])=>a.localeCompare(b)));
 jsonb.choiceSnapshot=Object.fromEntries(Object.entries(jsonb.choiceSnapshot).sort(([a],[b])=>a.localeCompare(b)));
 assert.equal(validateListingActionSetup(jsonb),jsonb);
 const rebuilt=await f.adapter.reconstruct({...input,savedProposal:jsonb});
 assert.deepEqual(rebuilt,proposal);
 assert.deepEqual(projectListingActionSetup(rebuilt),publicSetup);
});
test('import setup preserves literal URL bytes and rejects a synthetic extra source',async()=>{
 const f=fixture(),input={context:f.context,source:f.source,origin:f.origin,action:'import',selected:null,
  input:{json_url:'http://owned.example/path?x=%3Ctag%3E',xml_url:null},modeCapability:mode};
 const proposal=await f.adapter.prepare(input);assert.deepEqual(projectListingActionSetup(proposal).sources,input.input);
 assert.deepEqual(await f.adapter.reconstruct({...input,savedProposal:proposal}),proposal);
 await assert.rejects(f.adapter.prepare({...input,input:{...input.input,extra:'ignored'}}),{code:'INVALID_TOOL_ARGUMENTS'});
});
