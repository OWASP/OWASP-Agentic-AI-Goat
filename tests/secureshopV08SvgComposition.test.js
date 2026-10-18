'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),Module=require('node:module'),fs=require('node:fs'),path=require('node:path');
const target=path.resolve(__dirname,'../server/services/secureshopBoundUploadComposition.js');
function deps(){const fn=async()=>{},pool={query:fn};return{identityPool:pool,agentsPool:pool,reviewPool:pool,
 launches:{assertCurrent:fn},conversationRepository:{},journal:{},coordinator:{},provider:{},personaAuthority:{capture:fn},
 modeAuthority:{capture:fn,assertToken:x=>x},toolPolicyRepository:{},authenticatePersona:fn,assetOrigin:'http://[::1]:49000',
 assetCapability:{mint(){}},uploadRepository:{claim:fn,recordEffect:fn,recordServe:fn},effectReader:{find:fn},
 assetRepository:{lookup:fn},writer:{},resolveTarget:fn,personaBindings:{},scenes:{},receipts:{},progress:{},
 publicationModes:{},judge:fn,qualifyModel:fn};}
async function construct(injected,previewClient){
 const prior=Module._load,calls={close:0};
 const graph={},saved={},v06={},source={read(){},mint(){}},svg={},router={};
 Module._load=function(request,parent,isMain){
  const factories={
   './secureshopBoundUploadApplication':['createSecureShopBoundUploadApplication',{}],
   './secureshopUploadAssetReader':['createSecureShopUploadAssetReader',async()=>{}],
   './secureshopBoundUploadGraph':['createSecureShopBoundUploadGraph',graph],
   './secureshopBoundUploadSavedOperation':['createSecureShopBoundUploadSavedOperation',saved],
   '../database/postgres/secureshopV06UploadTurnReader':['createV06UploadTurnReader',{}],
   './secureshopV06UploadSourceReader':['createV06UploadSourceReader',{}],
   './secureshopV06UploadAssessment':['createV06UploadAssessment',v06],
   './secureshopV08SvgSourceReader':['createV08SvgSourceReader',source],
   './secureshopV08SvgAssessment':['createV08SvgAssessment',svg],
   '../routes/secureshop/boundAvatarUpload':['createBoundAvatarUploadRouter',router],
   './secureshopSceneBinding':['executionScope',{}],
   './secureshopV07UploadSourceReader':['createV07UploadSourceReader',source],
   './secureshopV07UploadPreviewGraph':['createV07UploadPreviewGraph',graph],
  };
  if(request==='./secureshopV07UploadEvidence')return{evidenceContract:{objectiveId:'ss_upload_polyglot_server_execution'}};
  if(request==='./secureshopSvgAssetBrowserQualification')return{createSecureShopSvgAssetBrowserQualification(){return{async qualify(){},async close(){calls.close++;}}}};
  if(factories[request]){const[name,value]=factories[request];return{[name]:(options)=>{calls[name]=options;return value;}};}
  return prior.apply(this,arguments);
 };
 try{delete require.cache[target];const create=require(target).createSecureShopBoundUploadComposition;
  const options=deps();if(previewClient)options.uploadPreviewClient=previewClient;if(injected)options.svgBrowserQualification=injected;
  return{composition:create(options),calls,source,svg,router};
 }finally{Module._load=prior;delete require.cache[target];}
}
test('composition wires read/mint source, durable V08 assessment and route, and owns browser retirement',async()=>{
 const f=await construct();assert.equal(f.composition.svgAssessment,f.svg);assert.equal(f.composition.router,f.router);
 assert.equal(f.calls.createV08SvgAssessment.sourceReader,f.source);
 assert.equal(typeof f.calls.createV08SvgAssessment.browserQualification.qualify,'function');
 assert.equal(f.calls.createBoundAvatarUploadRouter.svgAssessment,f.svg);
 await f.composition.close();assert.equal(f.calls.close,1);
});
test('injected qualification remains caller-owned',async()=>{
 let closed=0;const witness={async qualify(){},async close(){closed++;}},f=await construct(witness);
 assert.equal(f.calls.createV08SvgAssessment.browserQualification,witness);await f.composition.close();assert.equal(closed,0);
});
test('review composition routes V08 retained packets into shared recovery',()=>{
 const text=fs.readFileSync(path.resolve(__dirname,'../server/services/secureshopBoundReviewComposition.js'),'utf8');
 assert.match(text,/svgUploadAssessment:value\.avatarUpload\?\.svgAssessment/);
});

test('V07 optional composition forwards owned client, source and canonical contract without taking client lifecycle ownership',async()=>{
 let closed=0;const client={async preview(){},async assertReady(){},async close(){closed++;}},f=await construct(undefined,client);
 assert.equal(f.calls.createV07UploadPreviewGraph.client,client);assert.equal(f.calls.createV07UploadPreviewGraph.sourceReader,f.source);
 assert.equal(f.calls.createV06UploadAssessment.evidenceContract.objectiveId,'ss_upload_polyglot_server_execution');
 assert.equal(f.calls.createV06UploadAssessment.sourceReader,f.source);
 assert.equal(f.calls.createBoundAvatarUploadRouter.polyglotPreview,f.composition.polyglotPreview);
 assert.equal(f.calls.createBoundAvatarUploadRouter.polyglotAssessment,f.composition.polyglotAssessment);
 await f.composition.close();assert.equal(closed,0);
 const text=fs.readFileSync(path.resolve(__dirname,'../server/services/secureshopBoundReviewComposition.js'),'utf8');
 assert.match(text,/polyglotUploadAssessment:value\.avatarUpload\?\.polyglotAssessment/);
 assert.match(text,/getUploadPreviewClient\(\)/);assert.match(text,/uploadPreviewClient:snapshot\.configured\.uploadPreviewClient/);
});
