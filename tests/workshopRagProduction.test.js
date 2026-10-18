'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {createWorkshopRagProduction}=require('../server/services/workshopRagProduction');
function fixture(){
 const events=[],env={PLATFORM_DATABASE_ENGINE:'postgres',WORKSHOP_DATABASE_ENGINE:'postgres',IDENTITY_DATABASE_URL:'postgresql://user:private@127.0.0.1/owned_identity'};
 const identity={pool:{query:async()=>{}},validateSession:async()=>{}},composition={initialize:async()=>events.push('ready')};
 const routes=Array.from({length:2},()=>({resetOwner:async()=>{},durableRagComposition(){return this.configured||null;},configureDurableRag(value){events.push('bind');this.configured=value;}}));
 const embedder={embed:async()=>{events.push('actual-pipeline');return{embeddingDimension:384,embedding:Array(384).fill(1)};},getRuntimeFingerprint:()=>({fingerprint:'a'.repeat(64)})};
 const load=name=>{
  if(name==='./postgresIdentityAdapter')return{getPostgresIdentityAdapter:()=>identity};
  if(name==='../routes/ragInjection')return routes[0];if(name==='../routes/csrfWorkshop')return routes[1];
  if(name==='../database/postgres/csrfWorkshopDb')return{engine:'postgres',getVictimState:()=>{throw Error('Unexpected source read');},saveVictimState:()=>{throw Error('Unexpected source write');}};
  if(name==='./secureshopProductEmbedder')return{createSecureShopProductEmbedder:()=>embedder};
  if(name==='./postgresWorkshopResetService')return{createPostgresWorkshopResetAdapters:loader=>{assert.equal(loader('../routes/ragInjection'),routes[0]);return Object.fromEntries(['csrf_workshop','indirect_prompt_injection'].map(k=>[k,{resetOwner:async()=>{}}]));}};
  if(name==='./studentDeletionAdapters')return{createStudentDeletionAdapters:()=>Object.fromEntries(['csrf_workshop','indirect_prompt_injection'].map(k=>[k,async()=>{}]))};
  throw Error('Unexpected import');
 };
 const createComposition=args=>{assert.equal(args.identityAdapter,identity);assert.equal(args.pool,identity.pool);composition.initialize=async()=>{await args.assertReady(identity.pool);events.push('ready');};return composition;};
 return{events,env,identity,routes,embedder,composition,load,create:()=>createWorkshopRagProduction({env,load,createComposition,assertReadiness:async({pool,expectedDatabase})=>{assert.equal(pool,identity.pool);assert.equal(expectedDatabase,'owned_identity');}})};
}
test('production bootstrap is lazy, one-shot, ordered, and binds both routes to canonical lifecycle adapters',async()=>{const f=fixture(),production=f.create();assert.deepEqual(f.events,[]);const [a,b]=await Promise.all([production.initialize(),production.initialize()]);assert.equal(a,b);await a.warmEmbedding();assert.deepEqual(f.events,['ready','bind','bind','actual-pipeline']);assert.equal(production.isReady(),true);assert.equal(a.legacyCsrfRecovery.automaticImport,false);assert.equal(a.legacyCsrfRecovery.missingPoisonStatus,503);});
test('model failure leaves storage/routes ready and supports a real pipeline retry',async()=>{const f=fixture();const real=f.embedder.embed;f.embedder.embed=async()=>{throw Error('private credentials');};const p=f.create(),result=await p.initialize();assert.equal(await result.warmEmbedding(),false);assert.equal(p.isReady(),true);assert.equal(result.embeddingStatus(),'unavailable');f.embedder.embed=real;assert.equal(await result.warmEmbedding(),true);assert.equal(result.embeddingStatus(),'ready');});
test('production rejects legacy engine and malformed identity locator before importing any runtime',()=>{const f=fixture();for(const change of [{PLATFORM_DATABASE_ENGINE:'sqlite'},{WORKSHOP_DATABASE_ENGINE:'sqlite'},{IDENTITY_DATABASE_URL:'invalid'},{IDENTITY_DATABASE_URL:'https://example.invalid/db'}])assert.throws(()=>createWorkshopRagProduction({env:{...f.env,...change},load:()=>{throw Error('must not import');}}),{code:'RAG_PRODUCTION_NOT_READY'});});
test('preconfigured mismatched routes fail before any new binding',async()=>{const f=fixture();f.routes[0].configured={};await assert.rejects(f.create().initialize(),{code:'RAG_PRODUCTION_NOT_READY'});assert.equal(f.events.filter(e=>e==='bind').length,0);});
test('invalid actual embedding provenance is unavailable without blocking platform startup',async()=>{const f=fixture();f.embedder.getRuntimeFingerprint=()=>null;const result=await f.create().initialize();assert.equal(await result.warmEmbedding(),false);assert.equal(result.embeddingStatus(),'unavailable');});
test('storage readiness failure cannot bind routes or claim platform document readiness',async()=>{
 const f=fixture();const p=createWorkshopRagProduction({env:f.env,load:f.load,createComposition:()=>({initialize:async()=>{throw Error('private database URL');}})});
 await assert.rejects(p.initialize(),error=>error.code==='RAG_PRODUCTION_NOT_READY'&&!error.message.includes('private'));
 assert.equal(p.isReady(),false);assert.deepEqual(f.events,[]);
});
test('a pending model initialization does not delay storage activation',async()=>{
 const f=fixture();let release;f.embedder.embed=()=>new Promise(resolve=>{release=()=>resolve({embeddingDimension:384,embedding:Array(384).fill(1)});});
 const production=f.create(),activation=await production.initialize();assert.equal(production.isReady(),true);assert.equal(activation.embeddingStatus(),'loading');release();assert.equal(await activation.warmEmbedding(),true);
});
test('registered migration is exact qualified candidate and supported startup awaits storage before lifecycle/listen',()=>{
 const fs=require('node:fs'),path=require('node:path');const root=path.resolve(__dirname,'..');
 const candidate=fs.readFileSync(path.join(root,'docs/modernization/drafts/workshop-rag/0082_workshop_rag_sources.candidate.sql'));
 assert.deepEqual(fs.readFileSync(path.join(root,'db/postgres/identity-migrations/0082_workshop_rag_sources.sql')),candidate);
 const entry=fs.readFileSync(path.join(root,'server/applicationServer.js'),'utf8');
 const stores=entry.indexOf('workshopInitialization.then(async results =>');
 const bootstrap=entry.indexOf('await checked(initializeWorkshopRagProduction());',stores);
 const lifecycle=entry.indexOf('await checked(platformDataLifecycle.initialize(',stores),listen=entry.indexOf('server.listen(',stores);
 assert.ok(stores>=0&&bootstrap>stores&&lifecycle>bootstrap&&listen>lifecycle);
 const helperStart=entry.indexOf('function initializeWorkshopRagProduction() {');
 const helperEnd=entry.indexOf('\n}',helperStart);
 assert.ok(helperStart>=0&&helperEnd>helperStart&&helperEnd<stores);
 const helper=entry.slice(helperStart,helperEnd);
 assert.match(helper,/getWorkshopRagProduction\(\)\.initialize\(\)\.then/);
 assert.match(helper,/app\.locals\.workshopRagProduction = runtime/);
 assert.match(helper,/return workshopRagInitialization;/);
 assert.ok(!helper.includes('await warmEmbedding'));
 assert.ok(!entry.slice(bootstrap,listen).includes('await warmEmbedding'));
});
