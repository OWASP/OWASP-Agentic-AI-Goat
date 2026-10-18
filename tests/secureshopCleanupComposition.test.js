'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const {readMigrations}=require('../db/postgres/migrate');
const {STORES,CLEANUP_VISIBILITY_MIGRATION,assertSecureShopCleanupReadiness,
 createPersonaInboxTransportCleanup,createSecureShopCleanupComposition}=require('../server/services/secureshopCleanupComposition');

test('persona reset waits for authenticated retirement then exact target drain and preserves failure',async()=>{
 const scope={targetId:'owned'}, options={operationId:'reset'}, receipt={verified:true}, events=[];
 let failDatabase=false,failDrain=false;
 const cleanup=createPersonaInboxTransportCleanup({async cleanup(actual,args){
  assert.equal(actual,scope);assert.equal(args,options);events.push('database');
  if(failDatabase)throw Error('database failed');return receipt;}});
 const unregister=cleanup.register(async(actual,args,proof)=>{
  assert.equal(actual,scope);assert.equal(args,options);assert.equal(proof,receipt);
  events.push('drain owned');if(failDrain)throw Error('drain failed');});
 assert.equal(await cleanup.cleanup(scope,options),receipt);
 assert.deepEqual(events,['database','drain owned']);events.length=0;
 failDatabase=true;await assert.rejects(cleanup.cleanup(scope,options),/database failed/);
 assert.deepEqual(events,['database']);events.length=0;failDatabase=false;failDrain=true;
 await assert.rejects(cleanup.cleanup(scope,options),/drain failed/);
 assert.deepEqual(events,['database','drain owned']);events.length=0;unregister();
 assert.equal(await cleanup.cleanup(scope,options),receipt);assert.deepEqual(events,['database']);
});

async function readinessFixture({missingRelation=false,missingCapability=false,missingReviewRelation=null}={}){
 const runtime={};const migration={};const calls=[];
 for(const [name,store] of Object.entries(STORES)){
  const ledger=await readMigrations(store.directory);
  if(name==='identity'&&!ledger.some(row=>row.name===CLEANUP_VISIBILITY_MIGRATION.name))ledger.push(CLEANUP_VISIBILITY_MIGRATION);
  ledger.sort((a,b)=>a.name.localeCompare(b.name));
  runtime[name]={connect:async()=>{},async query(sql,params){calls.push([name,sql]);
   if(sql.startsWith('SELECT current_user'))return{rows:[{role:store.runtimeRole,database:`owned_${name}`}]};
   if(sql.includes('AS tables_present'))return{rows:[{database:`owned_${name}`,tables_present:true,table_grants:true,function_grants:true,cleanup_denied:true,guard_denied:true,actor_guard_denied:true,actor_guard_current:true,admission_guard_current:true,request_digest_denied:true,triggers_ready:true}]};
   if(sql.includes('to_regclass'))return{rows:params[0].map((value,index)=>({value,ready:!(missingRelation&&name==='agents'&&index===0)&&!(name==='review'&&value===missingReviewRelation)}))};
   throw Error('unexpected runtime query');}};
  migration[name]={async query(sql){if(sql.startsWith('SELECT current_user'))return{rows:[{role:store.migrationRole,database:`owned_${name}`}]};
   if(sql.includes('dvaia_migrations.ledger'))return{rows:missingCapability&&name==='identity'?ledger.slice(0,-1):ledger};
   throw Error('unexpected migration query');}};
 }
 return{identityPool:runtime.identity,agentsPool:runtime.agents,reviewPool:runtime.review,
  migrationPools:migration,calls};
}
test('cleanup readiness uses exact store ledgers and schemas without reading learner catalog visibility',async()=>{
 const fixture=await readinessFixture();assert.equal(await assertSecureShopCleanupReadiness(fixture),true);
 assert.equal(fixture.calls.some(([,sql])=>sql.includes('catalog_active')||sql.includes('workshop_platform.exercises')),false);
 assert.ok(STORES.agents.relations.includes('secureshop_agents.agent_sessions'));
 assert.equal(STORES.agents.relations.includes('secureshop_agents.bound_conversations'),false);
});
test('cleanup readiness rejects a partial lifecycle migration or relation manifest',async()=>{
 await assert.rejects(assertSecureShopCleanupReadiness(await readinessFixture({missingCapability:true})),{code:'SECURESHOP_CLEANUP_UNAVAILABLE'});
 await assert.rejects(assertSecureShopCleanupReadiness(await readinessFixture({missingRelation:true})),{code:'SECURESHOP_CLEANUP_UNAVAILABLE'});
});
test('cleanup readiness requires all retained support-ticket relations even with the exact migration ledger',async()=>{
 const relations=['secureshop_review.product_target_support_tickets',
  'secureshop_review.product_target_support_ticket_receipts',
  'secureshop_review.product_target_support_ticket_retirements'];
 for(const relation of relations){
  assert.ok(STORES.review.relations.includes(relation));
  await assert.rejects(assertSecureShopCleanupReadiness(await readinessFixture({missingReviewRelation:relation})),
   {code:'SECURESHOP_CLEANUP_UNAVAILABLE',message:'SecureShop cleanup schema is not ready'});
 }
 assert.equal(await assertSecureShopCleanupReadiness(await readinessFixture()),true);
});

test('catalog-independent cleanup composition exposes one coordinator to owner reset and deletion',async()=>{
 const auditCalls=[];
 const audit={agents:{append:async()=>{},recent:async()=>[]},review:{append:async()=>{},recent:async()=>[]},reader:{recent:async()=>({events:[]})},cleanup:async value=>{auditCalls.push(value);return{completed:true};}};
 let registryChecks=0;const pool={query:async sql=>{if(sql.includes('AS invocation_table'))return{rows:[{invocation_table:null}]};assert.ok(sql.includes('bound_mcp_registry_cleanup_receipts'));registryChecks++;return{rows:[{verified:true}]};},connect:async()=>{throw Error('unused')}};
 const reset=createSecureShopCleanupComposition({identityPool:pool,agentsPool:pool,reviewPool:pool,leasePool:pool,audit,
  launches:{assertCurrent:async()=>{},beginReset:async()=>{},commitReset:async()=>{}},
  cleanupAuthority:{getOperation:async()=>{},checkTarget:async()=>{},checkReviewTarget:async()=>{},
   checkProductTarget:async()=>{},listTargets:async()=>{},assertResolved:async()=>{},finalizeReconciliation:async()=>{}},
  conversationRepository:{},journal:{},reviewRepository:{cleanup:async()=>{},readCleanupReceipt:async()=>{}},productRepository:{cleanup:async()=>{},readCleanupReceipt:async()=>{}},
  runCoordinator:{run:async()=>{},reset:async()=>{}}});
 assert.equal(typeof reset.launchResetCoordinator.recover,'function');
 assert.equal(typeof reset.ownerResetService.resetOwner,'function');
 const deletionRepository={listSecureShopResetIds:async()=>[]};
 assert.equal(typeof reset.createStudentDeletionCleanup(deletionRepository),'function');
 assert.equal(reset.audit,audit);
 await reset.createStudentDeletionCleanup(deletionRepository)({subjectId:7,jobId:'f7240571-629f-4cac-92dc-48f8aa237af7',leaseToken:'lease',check:async()=>{}});
 assert.equal(registryChecks,1);
 assert.equal(auditCalls.length,1);assert.equal(auditCalls[0].subjectId,7);
 assert.equal(reset.runCoordinator,reset.runCoordinator);
});

test('cleanup composition retains the one supplied feature-mode authority for downstream catalog wiring',()=>{
 const pool={query:async()=>({rows:[]}),connect:async()=>{throw Error('unused')}};
 const modeAuthority=Object.freeze({capture:async()=>{},assertToken:()=>{}});
 const reset=createSecureShopCleanupComposition({identityPool:pool,agentsPool:pool,reviewPool:pool,leasePool:pool,
  launches:{assertCurrent:async()=>{},beginReset:async()=>{},commitReset:async()=>{}},modeAuthority,
  cleanupAuthority:{getOperation:async()=>{},checkTarget:async()=>{},checkReviewTarget:async()=>{},
   checkProductTarget:async()=>{},listTargets:async()=>{},assertResolved:async()=>{},finalizeReconciliation:async()=>{}},
  conversationRepository:{},journal:{},reviewRepository:{cleanup:async()=>{},readCleanupReceipt:async()=>{}},
  productRepository:{cleanup:async()=>{},readCleanupReceipt:async()=>{}},runCoordinator:{run:async()=>{},reset:async()=>{}},
  personaInboxFactory:false});
 assert.equal(reset.modeAuthority,modeAuthority);
});

test('optional persona inbox factory is retained by the aggregate cleanup coordinator',()=>{
 const audit={agents:{append:async()=>{},recent:async()=>[]},review:{append:async()=>{},recent:async()=>[]},reader:{recent:async()=>({events:[]})},cleanup:async()=>({completed:true})};
 const pool={query:async()=>({rows:[]}),connect:async()=>{throw Error('unused')}};
 const repository={cleanup:async()=>{},readCleanupReceipt:async()=>({version:1})};
 const bundle={repository,authorizeAclTransition:async()=>()=>{}};
 let factoryInput;
 const reset=createSecureShopCleanupComposition({identityPool:pool,agentsPool:pool,reviewPool:pool,leasePool:pool,
  launches:{assertCurrent:async()=>{},beginReset:async()=>{},commitReset:async()=>{}},
  cleanupAuthority:{getOperation:async()=>{},checkTarget:async()=>{},checkReviewTarget:async()=>{},
   checkProductTarget:async()=>{},listTargets:async()=>{},assertResolved:async()=>{},finalizeReconciliation:async()=>{}},
  conversationRepository:{},journal:{},reviewRepository:{cleanup:async()=>{},readCleanupReceipt:async()=>{}},
  productRepository:{cleanup:async()=>{},readCleanupReceipt:async()=>{}},runCoordinator:{run:async()=>{},reset:async()=>{}},
  audit,personaInboxFactory:input=>{factoryInput=input;return bundle;}});
 assert.equal(reset.personaInbox,bundle);
 assert.equal(factoryInput.agentsPool,pool);
 assert.equal(factoryInput.auditStore,audit.agents);
 assert.equal(factoryInput.launches,reset.launches);
 assert.equal(factoryInput.cleanupAuthority,reset.cleanupAuthority);
 assert.equal(typeof reset.launchResetCoordinator.reset,'function');
});

test('optional MCP trust bundle is created before reconciliation and drains transports on shutdown',async()=>{
 const pool={query:async()=>({rows:[]}),connect:async()=>{throw Error('unused')}};let factoryInput,closed=0;
 const bundle={cleanup:async()=>{},readCleanupReceipt:async()=>({kind:'mcp_rogue'}),close:async()=>{closed++;},
  repository:{readInvocation:async()=>{}},targetPool:{ensure:async()=>{}},authorizeRotation:async()=>()=>{}};
 const reset=createSecureShopCleanupComposition({identityPool:pool,agentsPool:pool,reviewPool:pool,leasePool:pool,
  launches:{assertCurrent:async()=>{},beginReset:async()=>{},commitReset:async()=>{}},
  cleanupAuthority:{getOperation:async()=>{},checkTarget:async()=>{},checkReviewTarget:async()=>{},
   checkProductTarget:async()=>{},listTargets:async()=>{},assertResolved:async()=>{},finalizeReconciliation:async()=>{}},
  conversationRepository:{},journal:{},reviewRepository:{cleanup:async()=>{},readCleanupReceipt:async()=>{}},
  productRepository:{cleanup:async()=>{},readCleanupReceipt:async()=>{}},runCoordinator:{run:async()=>{},reset:async()=>{}},
  mcpTrustFactory:input=>{factoryInput=input;return bundle;},mcpTrustFixtureRoot:'/tmp/owned-mcp-trust'});
 assert.equal(reset.mcpTrust,bundle);assert.equal(factoryInput.identityPool,pool);
 assert.equal(factoryInput.fixtureRoot,'/tmp/owned-mcp-trust');assert.equal(typeof reset.launchResetCoordinator.reset,'function');
 await reset.closeFeatureTransports();await reset.closeFeatureTransports();assert.equal(closed,1);
});

test('explicitly absent persona cleanup adapter remains unavailable instead of falsely resolving debt',()=>{
 const pool={query:async()=>({rows:[]}),connect:async()=>{throw Error('unused')}};
 const reset=createSecureShopCleanupComposition({identityPool:pool,agentsPool:pool,reviewPool:pool,leasePool:pool,
  launches:{assertCurrent:async()=>{},beginReset:async()=>{},commitReset:async()=>{}},
  cleanupAuthority:{getOperation:async()=>{},checkTarget:async()=>{},checkReviewTarget:async()=>{},
   checkProductTarget:async()=>{},listTargets:async()=>{},assertResolved:async()=>{},finalizeReconciliation:async()=>{}},
  conversationRepository:{},journal:{},reviewRepository:{cleanup:async()=>{},readCleanupReceipt:async()=>{}},
  productRepository:{cleanup:async()=>{},readCleanupReceipt:async()=>{}},runCoordinator:{run:async()=>{},reset:async()=>{}},
  personaInboxFactory:false});
 assert.equal(reset.personaInbox,undefined);
});
