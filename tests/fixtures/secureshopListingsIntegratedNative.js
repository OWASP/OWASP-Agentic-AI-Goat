'use strict';
// Candidate integration helper. Launcher owns and migrates four disposable stores
// and supplies the attested private listener configuration. Never reads app .env.
const assert=require('node:assert/strict');
const {randomUUID,randomBytes}=require('node:crypto');
async function qualifyListings({identity,leases,agents,commerce,review,executorConfiguration,dropProxy,holdBeforePublish,actualProvider,actualAction,transactionResetRace,savedEvidence}){
 const users=require('../../server/database/postgres/identityRepository').createIdentityRepository(identity);
 const launches=require('../../server/database/postgres/secureshopLaunchRepository').createSecureShopLaunchRepository(identity);
 const checkCurrent=scope=>launches.assertCurrent(scope);
 const personaAuthority=require('../../server/database/postgres/secureshopBoundPersonaAuthority').createSecureShopBoundPersonaAuthority({pool:agents,checkCurrent});
 const auditFactory=require('../../server/database/postgres/secureshopBoundAuditRepository').createBoundAuditStore;
 const personas=require('../../server/database/postgres/secureshopBoundPersonaRepository').createSecureShopBoundPersonaRepository({commercePool:commerce,agentsPool:agents,personaAuthority,auditStore:auditFactory({store:'agents',pool:agents})});
 await personas.ensureTemplates();
 const auth=require('../../server/services/secureshopBoundPersonaAuth').createSecureShopBoundPersonaAuth({repository:personas,personaAuthority,launches,jwtSecret:randomBytes(32).toString('hex')});
 const conversationRepository=require('../../server/database/postgres/secureshopBoundConversationsRepository').createBoundConversationsRepository({pool:agents,queue:async(_id,work)=>work()});
 const journal=require('../../server/database/postgres/secureshopTurnRequestsRepository').createTurnRequestsRepository({pool:agents});
 const ledger=require('../../server/agent-runtime/postgresRunLedger').createPostgresRunLedger(identity,{leasePool:leases});
 const coordinator=require('../../server/agent-runtime/runCoordinator').createRunCoordinator({family:'ListingsNative:'+randomUUID(),ledger});
 const products=require('../../server/database/postgres/secureshopBoundProductRepository').createSecureShopBoundProductRepository(review,{checkCurrent,checkCleanup:async()=>{throw Error('cleanup outside provisioning');}});
 async function owner(){
  const id=randomUUID(),passwordHash=await require('bcryptjs').hash('owned-only',4),u=await users.createUser({username:'list-'+id.slice(0,8),email:id+'@example.invalid',passwordHash});
  const expiresAt=new Date(Date.now()+600000).toISOString(),s=await users.createSession({userId:u.id,token:randomUUID(),expiresAt,expectedPasswordHash:passwordHash});
  const issued=await launches.issueOrRenew({platformOwnerId:u.id,platformSessionId:s.id,expiresAt});
  const scope=require('../../server/services/secureshopConversationBinding').createLaunchScope(issued.binding);
  const login=await auth.login({scope,username:'student_merchant',password:'student123'}),verified=await auth.authenticateBoundToken({scope,token:login.token});
  const reserved=await launches.reserveProductsTarget({...scope,expectedGeneration:scope.generation});
  await products.provision({...scope,targetId:reserved.targetId},{ownMerchantId:login.user.id,products:[{id:71,sourceRetailerId:login.user.id,retailerId:login.user.id,name:'Original',description:'owned',descriptionHtml:null,price:5,category:null,imageUrl:null,images:[],stockQuantity:1,status:'active',templateSource:null,createdAt:null,updatedAt:null}]});
  const revision=(await review.query('SELECT revision FROM secureshop_review.owned_listing_catalog_revisions WHERE target_id=$1',[reserved.targetId])).rows[0]?.revision||'0';
  return{scope,persona:{id:login.user.id,role:'merchant'},personaSession:{sessionId:verified.sessionId,authorityVersion:verified.authorityVersion},targetId:reserved.targetId,mode:'vuln',catalogRevision:String(revision)};
 }
 const a=await owner(),b=await owner();let calls=0,resumeOnly=false,resumeHook=null;const decisionMessages=[];
 const provider={async chat(input){calls++;if(savedEvidence)return{provider:'ollama',model:'llama3.1:8b',mocked:false,fallback:false,stop_reason:'end_turn',text:'<h1>Supplier lamp</h1><p>A warm desk lamp with adjustable brightness.</p>'};decisionMessages.push(structuredClone(input.messages));const selected=resumeOnly?'listing.publish':calls===1?'listing.fetch_parse':calls===2?'listing.publish':null;if(resumeHook)await resumeHook();if(selected==='listing.publish'&&holdBeforePublish)await holdBeforePublish({admission:a,launches,agents,review});return{provider:'ollama',model:'llama3.1:8b',mocked:false,fallback:false,...(selected?{stop_reason:'tool_use',tool_uses:[{id:randomUUID(),name:selected,args:{}}]}:{stop_reason:'end_turn',text:'Controlled publication complete'})};},async finalResponse(){return{provider:'ollama',model:'llama3.1:8b',mocked:false,fallback:false,stop_reason:'end_turn',responseMode:'structured_final',text:'Controlled publication complete'};}};
 const capabilityKey=randomBytes(32);
 const raceTools=transactionResetRace?require('./secureshopListingsPublicationResetRace'):null;
 const publicationBarrier=raceTools?.createPublicationBarrier(review);
 const create=()=>require('../../server/services/secureshopListingsComposition').createListingsComposition({pool:publicationBarrier?.pool||review,personaAuthority,capabilityKey,launches,conversationRepository,journal,coordinator,provider:actualProvider||provider,targetManager:{async resolveConfiguration({scope,targetId,mode}){return{scope,targetId,mode,...executorConfiguration};}}});
 const request={...a,request:{version:1,action:'import',operationId:randomUUID(),json_url:'http://192.0.2.10/catalog.json',xml_url:null}};
 if(actualAction==='rewrite'||savedEvidence)request.request={version:1,action:'rewrite',operationId:randomUUID(),title:'Supplier lamp',description:'A warm desk lamp with adjustable brightness.'};
 if(savedEvidence)return require('./secureshopListingsSavedEvidenceNative').qualifySavedEvidence({create,request,admissionOwner:a,sibling:b,review,personaAuthority,capabilityKey,products,launches});
 if(actualProvider){
  const result=await create().run(request);
  const output={actual:true,action:actualAction||'import',operation:result.operation,request};
  if(request.request.action==='rewrite'&&result.operation.state==='completed'){
   const admission=require('../../server/services/secureshopListingJournalContract').prepareListingAdmission(request);
   const saver=require('../../server/database/postgres/secureshopListingRewriteSaveRepository').createListingRewriteSaveRepository({pool:review,personaAuthority,capabilityKey});
   output.save=await saver.save({admission,saveOperationId:randomUUID(),productId:null,item:{name:request.request.title,description:request.request.description,price:5,category:null,images:[],templateSource:null}});
   const rows=(await review.query('SELECT description_html FROM secureshop_review.product_target_products WHERE target_id=$1 AND product_id=$2',[a.targetId,output.save.productId])).rows;
   assert.equal(rows[0].description_html,result.operation.receipt.html);output.savedHtml=rows[0].description_html;
  }
  if(request.request.action==='import'&&result.operation.state==='completed'){
   output.products=(await review.query('SELECT product_id,name FROM secureshop_review.product_target_products WHERE target_id=$1 ORDER BY product_id',[a.targetId])).rows;assert.equal(output.products.length,2);
  }
  return output;
 }
 if(transactionResetRace)return raceTools.qualifyPublicationResetRace({barrier:publicationBarrier,run:()=>create().run(request),replay:()=>create().run(request),review,identity,launches,admission:a,request,sibling:b});
 const composition=create();if(dropProxy)dropProxy.dropNext();let result,error;
 try{result=await composition.run(request);}catch(cause){error=cause;}
 if(dropProxy){
  const beforeCalls=calls,beforePosts=dropProxy.counters.posts;
  const recovered=await create().recover(request);
  assert.equal(recovered.operation.state,'unknown');assert.equal(recovered.executor.state,'completed');
  assert.equal(calls,beforeCalls);assert.equal(dropProxy.counters.posts,beforePosts);assert.equal(beforePosts,1);assert.equal(dropProxy.counters.dropped,1);assert.ok(dropProxy.counters.gets>=1);
  assert.equal((await review.query('SELECT count(*)::int n FROM secureshop_review.product_target_products WHERE target_id=$1',[a.targetId])).rows[0].n,1);
  result=recovered;
  resumeOnly=true;let release,entered;const held=new Promise(resolve=>release=resolve),started=new Promise(resolve=>entered=resolve);resumeHook=async()=>{entered();await held;};
  const beforeResume=calls,first=create().resume(request);let second,probe;
  try{
   await Promise.race([started,first.then(()=>{throw Error('first resume completed without model');})]);
   second=create().resume(request).then(value=>({value}),error=>({error}));
   let timer;try{probe=await Promise.race([second,new Promise(resolve=>{timer=setTimeout(()=>resolve({pending:true}),500);})]);}finally{clearTimeout(timer);}
   console.log(JSON.stringify({case:'concurrent_resume_second',pending:probe.pending===true,code:probe.error?.code||null}));
  }finally{release();}
  let timer;let pair;try{pair=await Promise.race([Promise.all([first,second]),new Promise((_,reject)=>{timer=setTimeout(()=>reject(Error('resume settlement timeout')),10000);})]);}finally{clearTimeout(timer);}
  const [resumed,secondResult]=pair;
  if(secondResult.error)assert.equal(secondResult.error.code,'TURN_RECOVERY_REQUIRED');else assert.equal(secondResult.value.operation.state,'completed');
  assert.equal(resumed.operation.state,'completed');assert.equal(calls,beforeResume+1);assert.match(JSON.stringify(decisionMessages.at(-1)),/recoveredObservation/);
  assert.equal((await create().resume(request)).replayed,true);assert.equal(calls,beforeResume+1);assert.equal(dropProxy.counters.posts,1);
  result={...recovered,resume:{state:resumed.operation.state,concurrentSerialized:true,modelDecisions:1}};

 }else if(!holdBeforePublish&&error)throw error;
 if(holdBeforePublish){
  assert.equal((await review.query('SELECT count(*)::int n FROM secureshop_review.owned_listing_publications WHERE operation_id=$1',[request.request.operationId])).rows[0].n,0);
  assert.equal((await review.query('SELECT count(*)::int n FROM secureshop_review.product_target_products WHERE target_id=$1',[a.targetId])).rows[0].n,1);
 }

 if(!dropProxy&&!holdBeforePublish){assert.equal(result.operation.state,'completed');assert.ok(decisionMessages.length>=2);assert.match(JSON.stringify(decisionMessages[1]),/Supplier lamp/);assert.equal((await review.query('SELECT count(*)::int n FROM secureshop_review.product_target_products WHERE target_id=$1',[a.targetId])).rows[0].n,2);const before=calls;assert.equal((await create().run(request)).replayed,true);assert.equal(calls,before);}
 assert.equal((await review.query('SELECT count(*)::int n FROM secureshop_review.product_target_products WHERE target_id=$1',[b.targetId])).rows[0].n,1);
 return{actualModelCalls:0,controlledDecisions:calls,request,result,scope:a.scope,siblingScope:b.scope};
}
module.exports={qualifyListings};
