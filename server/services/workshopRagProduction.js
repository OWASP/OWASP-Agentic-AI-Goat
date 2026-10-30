'use strict';
const {createWorkshopRagComposition}=require('./workshopRagComposition');
const {assertWorkshopRagReadiness}=require('./workshopRagReadiness');
const unavailable=()=>Object.assign(new Error('Workshop document production initialization failed'),{code:'RAG_PRODUCTION_NOT_READY',statusCode:503});
// Supported startup awaits this before lifecycle readiness and HTTP listen.
// Importing this file never changes configured stores.
function createWorkshopRagProduction({env=process.env,load=require,
 createComposition=createWorkshopRagComposition,assertReadiness=assertWorkshopRagReadiness}={}){
 const engine=env.PLATFORM_DATABASE_ENGINE,workshopEngine=env.WORKSHOP_DATABASE_ENGINE;
 let expectedDatabase;
 try{const url=new URL(env.IDENTITY_DATABASE_URL);if(!['postgres:','postgresql:'].includes(url.protocol))throw unavailable();expectedDatabase=decodeURIComponent(url.pathname.slice(1));if(!expectedDatabase||expectedDatabase.includes('/')||Buffer.byteLength(expectedDatabase)>63)throw unavailable();}catch{throw unavailable();}
 if(engine!=='postgres'||workshopEngine!=='postgres')throw unavailable();
 let pending,result,embeddingState='cold',embeddingAttempt;
 let productionEmbedder;
 const warmEmbedding=async()=>{
  if(!productionEmbedder)throw unavailable();
  if(!embeddingAttempt)embeddingAttempt=(async()=>{
   embeddingState='loading';
   const warm=await productionEmbedder.embed('OWASP-AI-GOAT document embedding startup readiness');
   if(warm?.embeddingDimension!==384||!Array.isArray(warm.embedding)||warm.embedding.length!==384
    ||!warm.embedding.every(Number.isFinite)||!warm.embedding.some(value=>value!==0)
    ||!/^[a-f0-9]{64}$/.test(productionEmbedder.getRuntimeFingerprint?.()?.fingerprint||''))throw unavailable();
   embeddingState='ready';return true;
  })().catch(()=>{embeddingState='unavailable';embeddingAttempt=null;return false;});
  return embeddingAttempt;
 };
 return Object.freeze({
  isReady:()=>Boolean(result),
  async initialize(){
   if(result)return result;
   if(!pending)pending=(async()=>{
    const identity=load('./postgresIdentityAdapter').getPostgresIdentityAdapter();
    if(typeof identity?.pool?.query!=='function'||typeof identity.validateSession!=='function')throw unavailable();
    const rag=load('../routes/ragInjection'),csrf=load('../routes/csrfWorkshop');
    for(const route of [rag,csrf])if(typeof route?.configureDurableRag!=='function'||typeof route.resetOwner!=='function'||typeof route.durableRagComposition!=='function')throw unavailable();
    const victimStore=load('../database/postgres/csrfWorkshopDb');
    if(victimStore.engine!=='postgres'||typeof victimStore.getVictimState!=='function'||typeof victimStore.saveVictimState!=='function')throw unavailable();
    if(rag.durableRagComposition()||csrf.durableRagComposition())throw unavailable();
    const embedder=load('./secureshopProductEmbedder').createSecureShopProductEmbedder();
    const composition=createComposition({pool:identity.pool,identityAdapter:identity,embedder,
     assertReady:pool=>assertReadiness({pool,expectedDatabase})});
    await composition.initialize();
    // Model availability is optional for application startup. Real ingestion
    // and query still await this same pipeline and fail closed when unavailable.
    productionEmbedder=embedder;
    const adaptersLoad=name=>name==='../routes/ragInjection'?rag:name==='../routes/csrfWorkshop'?csrf:load(name);
    const resetAdapters=load('./postgresWorkshopResetService').createPostgresWorkshopResetAdapters(adaptersLoad);
    const deletionAdapters=load('./studentDeletionAdapters').createStudentDeletionAdapters(adaptersLoad);
    for(const key of ['indirect_prompt_injection','csrf_workshop'])if(typeof resetAdapters[key]?.resetOwner!=='function'||typeof deletionAdapters[key]!=='function')throw unavailable();
    // Bootstrap is awaited before listening. Any partial binding is fatal to
    // this bootstrap instance; a running process must never fall back to RAM.
    rag.configureDurableRag(composition);csrf.configureDurableRag(composition);
    if(rag.durableRagComposition()!==composition||csrf.durableRagComposition()!==composition)throw unavailable();
    result=Object.freeze({ready:true,composition,resetAdapters,deletionAdapters,warmEmbedding,
     embeddingStatus:()=>embeddingState,
     legacyCsrfRecovery:Object.freeze({mode:'preserve-source-require-owner-reupload-or-reset',automaticImport:false,missingPoisonStatus:503}),
     legacyIpiRecovery:Object.freeze({mode:'activation-requires-separate-originating-process-preservation-review',exactOriginalBytesRecoverable:false})});
    void warmEmbedding();
    return result;
   })().catch(()=>{throw unavailable();});
   return pending;
  },
 });
}
let singleton;
function getWorkshopRagProduction(){if(!singleton)singleton=createWorkshopRagProduction();return singleton;}
module.exports={createWorkshopRagProduction,getWorkshopRagProduction};
