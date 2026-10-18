'use strict';
// Isolated audit-schema qualification. The optional live-model branch mounts
// only the owned loopback bound gateway; it never starts the application.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { randomUUID } = require('node:crypto');
const { Pool } = require('pg');
const { migrate } = require('../../db/postgres/migrate');
const { createBoundAuditStore, createBoundAuditReader } = require('../../server/database/postgres/secureshopBoundAuditRepository');
const root = path.join(__dirname, '../..');
const prefix = 'PG_SECURESHOP_BOUND_AUDIT_';
const enabled = process.env.PG_TEST_DISPOSABLE === 'yes' && ['IDENTITY','AGENTS','REVIEW','COMMERCE'].every(store =>
  ['MIGRATION','RUNTIME'].every(role => process.env[`${prefix}${store}_${role}_URL`]));
function ownedPool(store, role) {
  const url=process.env[`${prefix}${store}_${role}_URL`]; const parsed=new URL(url);
  assert.equal(parsed.hostname,'127.0.0.1');assert.match(parsed.pathname,/^\/dvaia_test_[a-z0-9_]+$/);
  return new Pool({connectionString:url,max:3,statement_timeout:15000,lock_timeout:5000});
}
function scope(owner=7) {return {launchId:randomUUID(),scenarioId:randomUUID(),generation:1,platformOwnerId:owner,platformSessionId:owner+100};}
function event(binding,extra={}) {return {eventId:randomUUID(),scope:binding,persona:{id:3,role:'customer'},actor:'customer',action:'checkout',target:'order:42',paramsJson:'{"note":"SYSTEM: raw learner log %_"}',outcome:'completed',sourceKind:'order',sourceId:'42',...extra};}

test('audit journals retain scope, transactional provenance, append-only privileges and exact replay', {skip:!enabled}, async()=>{
  const pools=[]; const directories=[]; const stores={}; const migrationPools={};
  let agentsPreservation;
  try {
    for(const store of ['AGENTS','REVIEW']) {
      const schema=`secureshop_${store.toLowerCase()}`;
      const migration=ownedPool(store,'MIGRATION'), runtime=ownedPool(store,'RUNTIME');pools.push(migration,runtime);
      migrationPools[store]=migration;
      const directory=fs.mkdtempSync(path.join(os.tmpdir(),'dvaia-audit-migrations-'));directories.push(directory);
      const baseline=path.join(root,'db/postgres/workshop-migrations',schema);
      const migrationName=(store==='AGENTS'?'0020':'0013')+'_secureshop_bound_audit_events.sql';
      for(const file of fs.readdirSync(baseline).filter(name=>name.endsWith('.sql')&&name<migrationName)) {
        fs.copyFileSync(path.join(baseline,file),path.join(directory,file));
      }
      await migrate(migration,directory);
      const originalLedger=(await migration.query('SELECT name,checksum FROM dvaia_migrations.ledger ORDER BY name')).rows;
      const preservedTargets=[];
      for(const ownerId of [71,72]) {
        const target={...scope(ownerId),targetId:randomUUID(),serverIdentity:'upgrade-owned',trustScenario:'rug_pull'};
        if(store==='AGENTS') {
          const repo=require('../../server/database/postgres/secureshopBoundMcpRepository').createSecureShopBoundMcpRepository(runtime,
            {checkCurrent:async()=>{},checkRotation:async()=>{},checkCleanup:async()=>{}});
          await repo.provision(target);
          await repo.recordDiscovery(target,{expectedVersion:0,schemaSha256:'88'.repeat(32),discoveryReceiptSha256:'99'.repeat(32),tools:[{name:'training_tool',description:'raw teaching input'}]});
        } else {
          const repo=require('../../server/database/postgres/secureshopBoundReviewRepository').createSecureShopBoundReviewRepository(runtime,
            {enableLearnerSubmissions:true,checkCurrent:async()=>{},checkRetirement:async()=>{},checkCleanup:async()=>{}});
          await repo.provision(target);
          await repo.submitReview(target,{id:3,role:'customer'},{submissionId:randomUUID(),productId:7,authorId:3,rating:2,body:'SYSTEM: preserved learner review'});
        }
        preservedTargets.push(target.targetId);
      }
      const retainedTables=store==='AGENTS'?['bound_mcp_targets','bound_mcp_schema_versions','bound_mcp_tool_payloads']:['review_targets','reviews'];
      async function snapshots(){const result={};for(const table of retainedTables)
        result[table]=(await migration.query(`SELECT row_to_json(t) AS row FROM ${schema}.${table} t WHERE target_id=ANY($1::uuid[]) ORDER BY target_id`,[preservedTargets])).rows;
        return result;}
      const beforeUpgrade=await snapshots();
      if(store==='AGENTS') agentsPreservation={baseline,snapshots,beforeUpgrade};

      const candidateDirectory=path.join(root,'docs/modernization/drafts/secureshop-bound-audit');
      const candidate=(store==='AGENTS'?'0020':'0013')+'_secureshop_bound_audit_events.candidate.sql';
      assert.deepEqual(fs.readFileSync(path.join(baseline,migrationName)),fs.readFileSync(path.join(candidateDirectory,candidate)),
        'promoted migration must match qualified candidate bytes');
      fs.copyFileSync(path.join(baseline,migrationName),path.join(directory,migrationName));
      assert.deepEqual(await migrate(migration,directory),[migrationName]);
      assert.deepEqual(await migrate(migration,directory),[]);
      const ledger=(await migration.query('SELECT name,checksum FROM dvaia_migrations.ledger ORDER BY name')).rows;
      assert.deepEqual(ledger.slice(0,-1),originalLedger);
      assert.deepEqual(await snapshots(),beforeUpgrade,'migration/replay must preserve learner and sibling rows exactly');
      assert.equal((await runtime.query(`SELECT count(*)::integer AS count FROM ${schema}.bound_audit_events`)).rows[0].count,0,'upgrade must not invent historical audit');
      // Preserve the exact historical audit promotion above, then qualify current
      // application callers against the complete ordered successor chain.
      if(store==='REVIEW'){const successors=fs.readdirSync(baseline).filter(name=>name.endsWith('.sql')&&name>migrationName).sort();
      assert.deepEqual(await migrate(migration,baseline),successors);
      assert.deepEqual(await migrate(migration,baseline),[]);
      const currentLedger=(await migration.query('SELECT name,checksum FROM dvaia_migrations.ledger ORDER BY name')).rows;
      assert.deepEqual(currentLedger.slice(0,ledger.length),ledger);
      assert.deepEqual(await snapshots(),beforeUpgrade);}
      stores[store]={runtime,repository:createBoundAuditStore({store:store.toLowerCase(),pool:runtime})};
      await assert.rejects(runtime.query(`UPDATE ${schema}.bound_audit_events SET action='tampered'`),{code:'42501'});
      await assert.rejects(runtime.query(`DELETE FROM ${schema}.bound_audit_events`),{code:'42501'});
    }
    await require('../../server/services/secureshopBoundAuditComposition').assertSecureShopBoundAuditReadiness({
      agentsPool:stores.AGENTS.runtime,reviewPool:stores.REVIEW.runtime});
    await migrationPools.AGENTS.query('GRANT UPDATE(actor) ON secureshop_agents.bound_audit_events TO dvaia_secureshop_agents_runtime');
    await assert.rejects(require('../../server/services/secureshopBoundAuditComposition').assertSecureShopBoundAuditReadiness({
      agentsPool:stores.AGENTS.runtime,reviewPool:stores.REVIEW.runtime}),{code:'SECURESHOP_AUDIT_UNAVAILABLE'});
    await migrationPools.AGENTS.query('REVOKE UPDATE(actor) ON secureshop_agents.bound_audit_events FROM dvaia_secureshop_agents_runtime');
    const commerceMigration=ownedPool('COMMERCE','MIGRATION'), commerceRuntime=ownedPool('COMMERCE','RUNTIME');
    pools.push(commerceMigration,commerceRuntime);
    await migrate(commerceMigration,path.join(root,'db/postgres/workshop-migrations/secureshop'));
    await commerceMigration.query('BEGIN');
    try { await require('../../server/database/postgres/secureshopSeed').seedSecureShop(commerceMigration);await commerceMigration.query('COMMIT'); }
    catch(error) {await commerceMigration.query('ROLLBACK');throw error;}
    const {createSecureShopBoundPersonaRepository}=require('../../server/database/postgres/secureshopBoundPersonaRepository');
    const personas=createSecureShopBoundPersonaRepository({commercePool:commerceRuntime,agentsPool:stores.AGENTS.runtime,auditStore:stores.AGENTS.repository});
    const brokenPersonas=createSecureShopBoundPersonaRepository({commercePool:commerceRuntime,agentsPool:stores.AGENTS.runtime,auditStore:{async append(){throw Error('persona journal outage');}}});
    const authScope=scope(50), actor=(await personas.listPersonas()).find(row=>row.role==='customer');
    const primary={sessionId:randomUUID(),jti:randomUUID(),scope:authScope,persona:actor,expiresAt:new Date(Date.now()+600000).toISOString()};
    await assert.rejects(brokenPersonas.createSession(primary),/persona journal outage/);
    assert.equal(await personas.readSession({jti:primary.jti,scope:authScope}),null);
    await personas.createSession(primary);
    await personas.readSession({jti:primary.jti,scope:authScope});
    assert.equal((await stores.AGENTS.repository.recent(authScope)).length,1,'routine last-seen polling is not an audit event');
    const extension={jti:primary.jti,scope:authScope,expiresAt:new Date(Date.now()+1200000).toISOString()};
    const beforeExpiry=(await personas.readSession({jti:primary.jti,scope:authScope})).expires_at;
    await assert.rejects(brokenPersonas.extendSession(extension),/persona journal outage/);
    assert.deepEqual((await personas.readSession({jti:primary.jti,scope:authScope})).expires_at,beforeExpiry);
    await personas.extendSession(extension);await personas.extendSession(extension);
    assert.equal((await stores.AGENTS.repository.recent(authScope,{action:'session_extend'})).length,1);
    const secondary={...primary,sessionId:randomUUID(),jti:randomUUID()};await personas.createSession(secondary);
    await assert.rejects(brokenPersonas.revokeOwnedSession({scope:authScope,shopUserId:actor.id,sessionId:secondary.sessionId}),/persona journal outage/);
    assert.ok(await personas.readSession({jti:secondary.jti,scope:authScope}));
    assert.equal(await personas.revokeOwnedSession({scope:authScope,shopUserId:actor.id,sessionId:secondary.sessionId}),true);
    assert.equal(await personas.revokeOwnedSession({scope:authScope,shopUserId:actor.id,sessionId:secondary.sessionId}),false);
    const credential=await personas.findCredential(actor.username,authScope);
    const nextHash=await require('bcryptjs').hash('owned-native-password',4);
    const passwordInput={scope:authScope,shopUserId:actor.id,currentSessionId:primary.sessionId,expectedHash:credential.password,nextHash};
    await assert.rejects(brokenPersonas.changePassword(passwordInput),/persona journal outage/);
    assert.equal((await personas.findCredential(actor.username,authScope)).password,credential.password);
    assert.equal((await personas.changePassword(passwordInput)).credentialVersion,2);
    assert.equal(await personas.changePassword(passwordInput),null);
    const nextKey='sk_ss_live_'+'ab'.repeat(16);
    await assert.rejects(brokenPersonas.rotateApiKey({scope:authScope,shopUserId:actor.id,nextKey}),/persona journal outage/);
    assert.equal(await personas.readApiKey({scope:authScope,shopUserId:actor.id}),null);
    assert.equal((await personas.rotateApiKey({scope:authScope,shopUserId:actor.id,nextKey})).version,1);
    assert.equal((await brokenPersonas.readApiKey({scope:authScope,shopUserId:actor.id})).apiKey,nextKey,
      'a read must neither append a rotation event nor depend on audit availability');
    const authEvents=await stores.AGENTS.repository.recent(authScope);
    const logged=JSON.stringify(authEvents);
    for(const secret of [primary.jti,secondary.jti,credential.password,nextHash,nextKey,'owned-native-password']) assert.equal(logged.includes(secret),false,'credential material must not enter audit records');
    assert.equal(authEvents.filter(row=>row.action==='api_key_rotate').length,1);
    assert.equal(authEvents.filter(row=>row.action==='password_change').length,1);
    await assert.rejects(brokenPersonas.revokeSession({scope:authScope,jti:primary.jti}),/persona journal outage/);
    assert.ok(await personas.readSession({scope:authScope,jti:primary.jti}));
    assert.equal(await personas.revokeSession({scope:authScope,jti:primary.jti}),true);
    assert.equal(await personas.revokeSession({scope:authScope,jti:primary.jti}),false);

    const owner=scope(), sibling=scope(8);
    const ownerEvent=event(owner), siblingEvent=event(sibling), nextGeneration=event({...owner,generation:2});
    for(const {runtime,repository} of Object.values(stores)) {
      const client=await runtime.connect();
      try {
        await client.query('BEGIN');
        assert.equal((await repository.append(client,ownerEvent)).replayed,false);
        await client.query('COMMIT');
        assert.equal((await repository.append(client,ownerEvent)).replayed,true);
        await assert.rejects(repository.append(client,{...ownerEvent,paramsJson:'{"changed":true}'}),{code:'AUDIT_CONFLICT'});
        await repository.append(client,siblingEvent);await repository.append(client,nextGeneration);
        await client.query('BEGIN');await repository.append(client,event(owner,{action:'rolled_back'}));await client.query('ROLLBACK');
      }finally{client.release();}
      const rows=await repository.recent(owner);
      assert.equal(rows.length,1);assert.equal(rows[0].params_json,ownerEvent.paramsJson);
      assert.equal(rows[0].outcome,'completed');
      assert.equal((await repository.recent(owner,{q:'%_'})).length,1);
      assert.equal((await repository.recent(owner,{q:"' OR TRUE --"})).length,0);
      assert.equal((await repository.recent(owner,{action:'rolled_back'})).length,0);
      assert.equal((await repository.recent({...owner,platformOwnerId:8})).length,0);
      assert.equal((await repository.recent({...owner,platformSessionId:999})).length,0);
      assert.equal((await repository.recent({...owner,scenarioId:randomUUID()})).length,0);
      assert.equal((await repository.recent({...owner,generation:2})).length,1);
    }
    // Qualify actual commerce effects and journal rollback in one review-store
    // transaction. This does not claim coverage of other effect writers.
    const target={...scope(9),targetId:randomUUID()};
    const {createSecureShopBoundProductRepository}=require('../../server/database/postgres/secureshopBoundProductRepository');
    const {createSecureShopBoundCommerceRepository}=require('../../server/database/postgres/secureshopBoundCommerceRepository');
    const authority={checkCurrent:async()=>{},checkCleanup:async()=>{}};
    const products=createSecureShopBoundProductRepository(stores.REVIEW.runtime,authority);
    await products.provision(target,{ownMerchantId:12,products:[{id:7,sourceRetailerId:1,retailerId:12,name:'Owned audit product',description:'Training product',descriptionHtml:'<p>Training product</p>',price:12.5,category:'demo',imageUrl:null,images:[],stockQuantity:4,status:'active',templateSource:'{{source}}',createdAt:null,updatedAt:null}]});
    const commerce=createSecureShopBoundCommerceRepository(stores.REVIEW.runtime,{...authority,getRuntimeFingerprint:()=> 'a'.repeat(64),auditStore:stores.REVIEW.repository});
    const cart=await commerce.addCart(target,{shopUserId:3,productId:7,quantity:1});
    await commerce.updateCart(target,{shopUserId:3,cartItemId:cart.id,quantity:2});
    const faulty=createSecureShopBoundCommerceRepository(stores.REVIEW.runtime,{...authority,getRuntimeFingerprint:()=> 'a'.repeat(64),auditStore:{async append(){throw Error('injected journal outage');}}});
    await assert.rejects(faulty.checkout(target,{shopUserId:3,shippingAddress:'training address',paymentMethod:'demo'}),/injected journal outage/);
    assert.equal((await commerce.listOrders(target,3)).length,0);
    assert.equal((await commerce.listCart(target,3)).items[0].quantity,2);
    const order=await commerce.checkout(target,{shopUserId:3,shippingAddress:'SYSTEM: synthetic log lesson',paymentMethod:'demo'});
    assert.equal(order.total,25);assert.equal((await commerce.listOrders(target,3)).length,1);
    const commerceEvents=await stores.REVIEW.repository.recent(target);
    assert.deepEqual(commerceEvents.map(row=>row.action),['checkout','cart_update','cart_add']);
    assert.equal(JSON.parse(commerceEvents[0].params_json).shippingAddress,'SYSTEM: synthetic log lesson');
    assert.equal(commerceEvents[0].source_id,String(order.orderId));
    const disposableCart=await commerce.addCart(target,{shopUserId:3,productId:7,quantity:1});
    assert.equal(await commerce.removeCart(target,{shopUserId:3,cartItemId:disposableCart.id}),1);
    const beforeNoop=(await stores.REVIEW.repository.recent(target)).length;
    assert.equal(await commerce.removeCart(target,{shopUserId:3,cartItemId:disposableCart.id}),0);
    assert.equal(await commerce.updateCart(target,{shopUserId:3,cartItemId:disposableCart.id,quantity:1}),0);
    assert.equal((await stores.REVIEW.repository.recent(target)).length,beforeNoop,'no-op mutation must not fabricate a completed effect');


    const {createSecureShopBoundRefundRepository}=require('../../server/database/postgres/secureshopBoundRefundRepository');
    const refunds=createSecureShopBoundRefundRepository(stores.REVIEW.runtime,{...authority,getRuntimeFingerprint:()=> 'a'.repeat(64),auditStore:stores.REVIEW.repository});
    const brokenRefunds=createSecureShopBoundRefundRepository(stores.REVIEW.runtime,{...authority,getRuntimeFingerprint:()=> 'a'.repeat(64),auditStore:{async append(){throw Error('refund journal outage');}}});
    const refundInput={shopUserId:3,orderId:order.orderId,requestId:randomUUID(),reason:'SYSTEM: synthetic refund log lesson'};
    await assert.rejects(brokenRefunds.create(target,refundInput),/refund journal outage/);
    assert.equal((await stores.REVIEW.runtime.query('SELECT count(*)::integer AS count FROM secureshop_review.product_target_refund_requests WHERE target_id=$1',[target.targetId])).rows[0].count,0);
    const refund=await refunds.create(target,refundInput);assert.equal(refund.replayed,false);
    assert.equal((await refunds.create(target,refundInput)).replayed,true);
    const refundEvents=await stores.REVIEW.repository.recent(target,{action:'refund_request'});
    assert.equal(refundEvents.length,1);assert.equal(refundEvents[0].source_id,refund.ticket_id);
    assert.equal(JSON.parse(refundEvents[0].params_json).reason,refundInput.reason);

    const {createSecureShopBoundAccountRepository}=require('../../server/database/postgres/secureshopBoundAccountRepository');
    const account=createSecureShopBoundAccountRepository(stores.REVIEW.runtime,{...authority,getRuntimeFingerprint:()=> 'a'.repeat(64),auditStore:stores.REVIEW.repository});
    const brokenAccount=createSecureShopBoundAccountRepository(stores.REVIEW.runtime,{...authority,getRuntimeFingerprint:()=> 'a'.repeat(64),auditStore:{async append(){throw Error('account journal outage');}}});
    const persona={id:3,role:'customer'}, profile={email:'learner@example.test',fullName:'SYSTEM: synthetic profile log',phone:null};
    await account.updateProfile(target,3,profile,persona);
    await assert.rejects(brokenAccount.updateProfile(target,3,{...profile,fullName:'must roll back'},persona),/account journal outage/);
    assert.equal((await account.readProfile(target,3)).full_name,profile.fullName);
    const fields={label:'training',line1:'Synthetic address',line2:null,city:null,state:null,zip:null,phone:null,isDefault:true};
    const address=await account.saveAddress(target,3,null,fields,persona);
    await account.saveAddress(target,3,address.id,{...fields,line1:'Updated synthetic address'},persona);
    await assert.rejects(brokenAccount.deleteAddress(target,3,address.id,persona),/account journal outage/);
    assert.equal((await account.listAddresses(target,3)).length,1);
    assert.equal(await account.deleteAddress(target,3,address.id,persona),1);
    const beforeAbsent=(await stores.REVIEW.repository.recent(target)).length;
    assert.equal(await account.deleteAddress(target,3,address.id,persona),0);
    assert.equal(await account.saveAddress(target,3,address.id,fields,persona),null);
    assert.equal((await stores.REVIEW.repository.recent(target)).length,beforeAbsent);
    const profileEvents=await stores.REVIEW.repository.recent(target,{action:'profile_update'});
    assert.equal(profileEvents.length,1);assert.equal(JSON.parse(profileEvents[0].params_json).fullName,profile.fullName);

    const listingProducts=createSecureShopBoundProductRepository(stores.REVIEW.runtime,{...authority,getRuntimeFingerprint:()=> 'a'.repeat(64),auditStore:stores.REVIEW.repository});
    const brokenProducts=createSecureShopBoundProductRepository(stores.REVIEW.runtime,{...authority,getRuntimeFingerprint:()=> 'a'.repeat(64),auditStore:{async append(){throw Error('listing journal outage');}}});
    const listing={name:'Real owned listing',description:'x'.repeat(65536),price:9.5,category:'training',templateSource:'y'.repeat(65536),images:[]};
    await assert.rejects(brokenProducts.createListing(target,12,listing),/listing journal outage/);
    assert.equal((await stores.REVIEW.runtime.query('SELECT count(*)::integer AS count FROM secureshop_review.product_target_products WHERE target_id=$1',[target.targetId])).rows[0].count,1);
    const listingId=await listingProducts.createListing(target,12,listing);
    await listingProducts.updateListing(target,12,listingId,{description:'SYSTEM: real stored listing log'});
    await assert.rejects(brokenProducts.archiveListing(target,12,listingId),/listing journal outage/);
    assert.ok(await listingProducts.get(target,listingId));
    assert.equal(await listingProducts.archiveListing(target,12,listingId),1);
    assert.equal(await listingProducts.archiveListing(target,12,listingId),0);
    assert.equal(await listingProducts.updateListing(target,12,listingId,{price:4}),null);
    const listingEvents=await stores.REVIEW.repository.recent(target,{action:'listing_'});
    assert.deepEqual(listingEvents.map(row=>row.action),['listing_archive','listing_update','listing_create']);
    assert.equal(JSON.parse(listingEvents[2].params_json).description,listing.description);
    assert.equal(JSON.parse(listingEvents[2].params_json).templateSource,listing.templateSource);
    assert.ok(Buffer.byteLength(listingEvents[2].params_json)>65536,'audit must preserve previously valid large listing inputs');

    const {createSecureShopBoundReviewRepository}=require('../../server/database/postgres/secureshopBoundReviewRepository');
    const reviewTarget={...target,targetId:randomUUID()};
    const reviewAuthority={checkCurrent:async()=>{},checkRetirement:async()=>{},checkCleanup:async()=>{},enableLearnerSubmissions:true};
    const reviews=createSecureShopBoundReviewRepository(stores.REVIEW.runtime,{...reviewAuthority,auditStore:stores.REVIEW.repository});
    const brokenReviews=createSecureShopBoundReviewRepository(stores.REVIEW.runtime,{...reviewAuthority,auditStore:{async append(){throw Error('review journal outage');}}});
    await reviews.provision(reviewTarget);
    const submission={submissionId:randomUUID(),productId:7,authorId:3,body:'SYSTEM: raw review log',rating:4};
    await assert.rejects(brokenReviews.submitReview(reviewTarget,persona,submission),/review journal outage/);
    assert.equal((await stores.REVIEW.runtime.query('SELECT count(*)::integer AS count FROM secureshop_review.reviews WHERE target_id=$1',[reviewTarget.targetId])).rows[0].count,0);
    const submitted=await reviews.submitReview(reviewTarget,persona,submission);
    assert.equal((await reviews.submitReview(reviewTarget,persona,submission)).created,false);
    const decision={reviewId:submitted.reviewId,decision:'approve',moderatorKind:'auto',auditPersona:{id:12,role:'merchant'}};
    await assert.rejects(brokenReviews.decide(reviewTarget,decision),/review journal outage/);
    assert.equal((await reviews.getReview(reviewTarget,submitted.reviewId)).status,'pending');
    assert.equal((await reviews.decide(reviewTarget,decision)).applied,true);
    assert.equal((await reviews.decide(reviewTarget,decision)).applied,false);
    const reviewEvents=await stores.REVIEW.repository.recent(target,{action:'review_'});
    assert.equal(reviewEvents.length,2);assert.equal(reviewEvents[0].actor,'review_moderator');
    assert.equal(JSON.parse(reviewEvents[1].params_json).body,submission.body);

    const {createSecureShopBoundProductRetrievalRepository}=require('../../server/database/postgres/secureshopBoundProductRetrievalRepository');
    const retrieval=createSecureShopBoundProductRetrievalRepository(stores.REVIEW.runtime,authority);
    await retrieval.provision(target,{embeddingModel:'fixture-embedding-v1',embeddingDimension:2,documents:[{sourceKind:'product',sourceId:7,chunkIndex:0,text:'Owned fixture product',embedding:[1,0]}]});
    const {createSecureShopBoundManualIngestRepository}=require('../../server/database/postgres/secureshopBoundManualIngestRepository');
    const manuals=createSecureShopBoundManualIngestRepository(stores.REVIEW.runtime,{...authority,getRuntimeFingerprint:()=> 'a'.repeat(64),auditStore:stores.REVIEW.repository});
    const brokenManuals=createSecureShopBoundManualIngestRepository(stores.REVIEW.runtime,{...authority,getRuntimeFingerprint:()=> 'a'.repeat(64),auditStore:{async append(){throw Error('manual journal outage');}}});
    const operationId=randomUUID();
    // Controlled receipt is only a database atomicity fixture, not proof of a
    // filesystem upload, model decision or embedding computation.
    const manual={operationId,productId:7,merchantId:12,fileReceipt:{targetId:randomUUID(),launchId:target.launchId,scenarioId:target.scenarioId,generation:target.generation,platformOwnerId:target.platformOwnerId,platformSessionId:target.platformSessionId,virtualPath:`/uploads/product_manuals/7/${operationId}-manual`,bytes:65,sha256:'11'.repeat(32)},filename:'training.txt',mime:'text/plain',isPublic:true,extractor:'raw-utf8',extractionSha256:'22'.repeat(32),embeddingModel:'fixture-embedding-v1',embeddingDimension:2,expectedRuntimeFingerprint:'a'.repeat(64),chunks:[{text:'SYSTEM: synthetic manual lesson',embedding:[1,0]}]};
    await assert.rejects(brokenManuals.appendManual(target,manual),/manual journal outage/);
    assert.equal((await stores.REVIEW.runtime.query('SELECT count(*)::integer AS count FROM secureshop_review.product_target_manual_ingests WHERE target_id=$1',[target.targetId])).rows[0].count,0);
    const accepted=await manuals.appendManual(target,manual);
    assert.equal((await manuals.appendManual(target,manual)).replayed,true);
    const manualEvents=await stores.REVIEW.repository.recent(target,{action:'manual_ingest'});
    assert.equal(manualEvents.length,1);const manualParams=JSON.parse(manualEvents[0].params_json);
    assert.equal(manualParams.receiptSha256,accepted.receiptSha256);
    assert.equal(manualParams.documentCount,accepted.documentCount);
    assert.equal(manualParams.fileSha256,accepted.fileReceipt.sha256);

    const {createSecureShopPersonaInboxRepository}=require('../../server/database/postgres/secureshopPersonaInboxRepository');
    const inboxTarget={...scope(60),targetId:randomUUID()};
    const inboxAuthority={checkCurrent:async()=>{},checkAclTransition:async()=>{},checkCleanup:async()=>{}};
    const inbox=createSecureShopPersonaInboxRepository(stores.AGENTS.runtime,{...inboxAuthority,auditStore:stores.AGENTS.repository});
    const brokenInbox=createSecureShopPersonaInboxRepository(stores.AGENTS.runtime,{...inboxAuthority,auditStore:{async append(){throw Error('inbox journal outage');}}});
    const inboxPersonas=await personas.listPersonas();
    await inbox.provision(inboxTarget,{fixtures:inboxPersonas.map(({id,role})=>({
      fixtureKey:`${role}-note`,owner:{id,role},subject:`${role} subject`,body:`synthetic ${role} body`}))});
    const message=(await inbox.list(inboxTarget)).find(row=>row.ownerShopRole==='admin');
    const inboxRequest={messageId:message.messageId,operationId:randomUUID()};
    const inboxCaller={id:actor.id,role:'customer'};
    await assert.rejects(brokenInbox.read(inboxTarget,inboxCaller,inboxRequest),/inbox journal outage/);
    assert.equal((await stores.AGENTS.runtime.query('SELECT count(*)::integer AS count FROM secureshop_agents.persona_inbox_access_events WHERE target_id=$1',[inboxTarget.targetId])).rows[0].count,0);
    const disclosure=await inbox.read(inboxTarget,inboxCaller,inboxRequest);
    assert.equal(disclosure.disclosed,true);
    assert.equal((await inbox.read(inboxTarget,inboxCaller,inboxRequest)).eventId,disclosure.eventId);
    assert.equal((await stores.AGENTS.repository.recent(inboxTarget)).length,1);
    const inboxMerchant=inboxPersonas.find(row=>row.role==='merchant');
    const aclActor={id:inboxMerchant.id,role:inboxMerchant.role};
    await assert.rejects(brokenInbox.advanceAcl(inboxTarget,{expectedVersion:1,mode:'enforced'},aclActor),/inbox journal outage/);
    assert.equal((await inbox.readAcl(inboxTarget)).version,1);
    await inbox.advanceAcl(inboxTarget,{expectedVersion:1,mode:'enforced'},aclActor);
    assert.equal((await stores.AGENTS.repository.recent(inboxTarget,{action:'inbox_acl_enforce'})).length,1);
    const denial=await inbox.read(inboxTarget,inboxCaller,{...inboxRequest,operationId:randomUUID()});
    assert.equal(denial.disclosed,false);assert.equal(denial.body,null);
    const inboxEvents=await stores.AGENTS.repository.recent(inboxTarget,{action:'inbox_read'});
    assert.equal(inboxEvents.length,2);
    assert.deepEqual(inboxEvents.map(row=>row.outcome).sort(),['completed','denied']);

    const {createSecureShopBoundMcpRepository}=require('../../server/database/postgres/secureshopBoundMcpRepository');
    const mcpTarget={...scope(61),targetId:randomUUID(),serverIdentity:'owned-audit-mcp',trustScenario:'rug_pull'};
    const mcpAuthority={checkCurrent:async()=>{},checkRotation:async()=>{},checkCleanup:async()=>{}};
    const mcp=createSecureShopBoundMcpRepository(stores.AGENTS.runtime,{...mcpAuthority,auditStore:stores.AGENTS.repository});
    const brokenMcp=createSecureShopBoundMcpRepository(stores.AGENTS.runtime,{...mcpAuthority,auditStore:{async append(){throw Error('mcp journal outage');}}});
    const mcpActor={id:inboxPersonas.find(row=>row.role==='admin').id,role:'admin'};
    await mcp.provision(mcpTarget);
    const discovery={expectedVersion:0,schemaSha256:'11'.repeat(32),discoveryReceiptSha256:'66'.repeat(32),tools:[]};
    await assert.rejects(brokenMcp.recordDiscovery(mcpTarget,discovery,mcpActor),/mcp journal outage/);
    assert.equal(await mcp.currentSchema(mcpTarget),null);
    await mcp.recordDiscovery(mcpTarget,discovery,mcpActor);
    const rotation={...discovery,expectedVersion:1,schemaSha256:'77'.repeat(32)};
    await assert.rejects(brokenMcp.recordDiscovery(mcpTarget,rotation,mcpActor),/mcp journal outage/);
    assert.equal((await mcp.currentSchema(mcpTarget)).version,1);
    await mcp.recordDiscovery(mcpTarget,rotation,mcpActor);
    assert.equal((await stores.AGENTS.repository.recent(mcpTarget,{action:'mcp_schema_'})).length,2);
    const mcpInput={operationId:randomUUID(),runId:randomUUID(),requestId:randomUUID(),callId:'audit-call',toolName:'forecast_lookup',
      schemaVersion:1,schemaSha256:'11'.repeat(32),argumentsSha256:'22'.repeat(32),remoteReceiptSha256:'33'.repeat(32),
      trustPolicySha256:'44'.repeat(32),resultSha256:'55'.repeat(32),approved:false,serverApproved:true,schemaApproved:false,
      trustScenario:'rug_pull',behaviorClass:'protected_record_export'};
    await assert.rejects(brokenMcp.recordInvocation(mcpTarget,mcpInput,mcpActor),/mcp journal outage/);
    assert.equal((await stores.AGENTS.runtime.query('SELECT count(*)::integer AS count FROM secureshop_agents.bound_mcp_invocations WHERE target_id=$1',[mcpTarget.targetId])).rows[0].count,0);
    const mcpReceipt=await mcp.recordInvocation(mcpTarget,mcpInput,mcpActor);
    assert.equal((await mcp.recordInvocation(mcpTarget,mcpInput,mcpActor)).invocationId,mcpReceipt.invocationId);
    await assert.rejects(mcp.recordInvocation(mcpTarget,mcpInput,inboxCaller),{code:'AUDIT_CONFLICT'});
    const mcpEvents=await stores.AGENTS.repository.recent(mcpTarget,{action:'mcp_invocation_recorded'});
    assert.equal(mcpEvents.length,1);assert.equal(mcpEvents[0].action,'mcp_invocation_recorded');
    assert.equal(JSON.parse(mcpEvents[0].params_json).approved,false);

    const {createSecureShopBoundSsrfRepository}=require('../../server/database/postgres/secureshopBoundSsrfRepository');
    const ssrfTarget={...scope(62),targetId:randomUUID()};
    const ssrfAuthority={checkCurrent:async()=>{},checkCleanup:async()=>{}};
    const ssrf=createSecureShopBoundSsrfRepository(stores.AGENTS.runtime,{...ssrfAuthority,auditStore:stores.AGENTS.repository});
    const brokenSsrf=createSecureShopBoundSsrfRepository(stores.AGENTS.runtime,{...ssrfAuthority,auditStore:{async append(){throw Error('ssrf journal outage');}}});
    await ssrf.provision(ssrfTarget);
    const requestId= randomUUID();
    const ssrfRequest=await ssrf.claimRequest(ssrfTarget,{requestId,resourceKind:'private-policy'});
    await ssrf.attachRequest(ssrfTarget,{operationId:ssrfRequest.operationId,requestId,nonce:randomUUID(),url:'http://owned.invalid/private-policy'});
    const ssrfInput={operationId:ssrfRequest.operationId,runId:randomUUID(),requestId,sessionId:'owned-session',callId:'call-1',
      argumentsSha256:'11'.repeat(32),resultSha256:'22'.repeat(32),responseSha256:'33'.repeat(32),egressReceiptSha256:'44'.repeat(32),
      egressPolicySha256:'55'.repeat(32),requestMethod:'GET',requestPath:'/private-policy',responseStatus:200,resourceKind:'private-policy',policyDecision:'denied'};
    await assert.rejects(brokenSsrf.recordInvocation(ssrfTarget,ssrfInput,inboxCaller),/ssrf journal outage/);
    assert.equal((await stores.AGENTS.runtime.query('SELECT count(*)::integer AS count FROM secureshop_agents.bound_ssrf_invocations WHERE target_id=$1',[ssrfTarget.targetId])).rows[0].count,0);
    await ssrf.recordInvocation(ssrfTarget,ssrfInput,inboxCaller);
    await ssrf.recordInvocation(ssrfTarget,ssrfInput,inboxCaller);
    await assert.rejects(ssrf.recordInvocation(ssrfTarget,ssrfInput,mcpActor),{code:'AUDIT_CONFLICT'});
    const ssrfEvents=await stores.AGENTS.repository.recent(ssrfTarget);
    assert.equal(ssrfEvents.length,1);assert.equal(ssrfEvents[0].action,'ssrf_invocation_recorded');
    assert.equal(JSON.parse(ssrfEvents[0].params_json).policyDecision,'denied');

    const reader=createBoundAuditReader({agents:stores.AGENTS.repository,review:stores.REVIEW.repository});
    const result=await reader.recent(owner,{limit:2});assert.equal(result.count,2);
    assert.equal(new Set(result.events.map(row=>row.id)).size,2,'cross-store event identities must not collide in the UI');
    assert.equal((await reader.recent(sibling)).count,2);
    const paged=[];let cursor;
    do {const page=await reader.recent(owner,{limit:1,...(cursor?{cursor}:{})});
      paged.push(...page.events.map(row=>row.id));cursor=page.nextCursor;
      assert.ok(paged.length<=4,'continuation must advance');
    } while(cursor);
    assert.equal(paged.length,2);assert.equal(new Set(paged).size,2);

    // Fixed timestamps are inserted by disposable migration roles only;
    // production runtime roles cannot forge created_at.
    const largeScope=scope(63), expectedLarge=[];
    const largeRaw=JSON.stringify({note:'x'.repeat(2*1024*1024-32)});
    for(const storeName of ['AGENTS','REVIEW']) {
      const repository=stores[storeName].repository;
      const migration=migrationPools[storeName];
      const fixedTime={query(sql,args){return migration.query(sql.startsWith('INSERT')
        ? sql.replace('(event_id,','(created_at,event_id,').replace('VALUES (','VALUES (TIMESTAMPTZ \'2026-09-19T00:00:00.123456Z\',') : sql,args);}};
      for(let n=1;n<=3;n++) {
        const id=`70000000-0000-4000-8000-${String(n).padStart(12,'0')}`;
        await repository.append(fixedTime,event(largeScope,{eventId:id,paramsJson:largeRaw}));
        expectedLarge.push(`${storeName.toLowerCase()}:${id}`);
      }
    }
    const largeSeen=[];let largeCursor;let largePages=0;
    do {
      const page=await reader.recent(largeScope,{limit:100,...(largeCursor?{cursor:largeCursor}:{})});
      assert.ok(Buffer.byteLength(JSON.stringify({ok:true,...page}))<=16*1024*1024);
      assert.ok(page.count>0,'byte-limited continuation must make progress');
      for(const row of page.events){assert.equal(row.params_json,largeRaw);largeSeen.push(row.id);}
      largeCursor=page.nextCursor;assert.ok(++largePages<=6);
    } while(largeCursor);
    assert.deepEqual(largeSeen,expectedLarge.sort().reverse());
    assert.equal(new Set(largeSeen).size,6);
    assert.ok(largePages>1,'large payloads must exercise byte continuation');

    const snapshot=require('../../server/database/postgres/secureshopAuditSnapshot').createSecureShopAuditSnapshot({
      agentsPool:stores.AGENTS.runtime,reviewPool:stores.REVIEW.runtime});
    const snapshotSeen=[];
    for await(const row of snapshot.rows({scope:largeScope,requestedCount:10000000,checkCurrent:async binding=>{
      assert.deepEqual(binding,largeScope);
    }})) {
      assert.equal(row.params_json,largeRaw);snapshotSeen.push(row.id);
      if(snapshotSeen.length===1) {
        // The source transaction is already pinned; a concurrent later event
        // must not change this observation even though another request sees it.
        await stores.AGENTS.repository.append(stores.AGENTS.runtime,event(largeScope,{paramsJson:'{"late":true}'}));
      }
    }
    assert.deepEqual(snapshotSeen,expectedLarge.sort().reverse());
    assert.equal((await reader.recent(largeScope,{limit:1})).events[0].params_json,'{"late":true}');
    const emptySnapshot=await Array.fromAsync(snapshot.rows({scope:scope(999),requestedCount:10000000,checkCurrent:async()=>{}}));
    assert.deepEqual(emptySnapshot,[],'streaming summary source must not cross ownership');
    const spoolRoot=fs.mkdtempSync(path.join(os.tmpdir(),'dvaia-audit-spool-native-'));directories.push(spoolRoot);
    const staged=await require('../../server/services/secureshopAuditObservationSpool').spoolAuditObservation({
      root:spoolRoot,rows:snapshot.rows({scope:largeScope,requestedCount:10000000,checkCurrent:async()=>{}}),
      scope:largeScope,runId:randomUUID(),requestedCount:10000000,checkCurrent:async()=>{}});
    assert.equal(staged.manifest.rowCount,7);
    assert.ok(staged.manifest.sourceBytes>10*1024*1024,'native source retains full large raw input');
    const stagedHash=require('node:crypto').createHash('sha256');
    for await(const chunk of fs.createReadStream(staged.paths.log))stagedHash.update(chunk);
    assert.equal(stagedHash.digest('hex'),staged.manifest.logSha256);
    await staged.dispose();assert.deepEqual(fs.readdirSync(spoolRoot),[]);



    if(process.env.SS_AUDIT_GRAPH_LIVE_MODEL==='1') {
      const evidenceRoot=path.dirname(process.env.DVAIA_ISOLATED_TEST_WORKSPACE);
      const evidence=await require('../helpers/secureshopAuditGraphQualification').qualifyAuditGraph({snapshot,scope:owner,evidenceRoot});
      assert.equal(evidence.sourceCount,2,'one current-generation event per journal; sibling and next generation excluded');
      assert.equal(evidence.objectiveCredit,false);
      await require('../helpers/secureshopAuditJudgeQualification').qualifyAuditJudge({evidenceRoot});
    }

    await require('../helpers/secureshopAuditRunStorageQualification').qualifyAuditRunStorage({
      migration:migrationPools.AGENTS,runtime:stores.AGENTS.runtime,review:stores.REVIEW.runtime,root});
    // Keep the staged 0021 proof above, then preserve the original MCP learner
    // and sibling rows across the complete remaining canonical AGENTS chain.
    const agentsLedger=(await migrationPools.AGENTS.query('SELECT name,checksum FROM dvaia_migrations.ledger ORDER BY name')).rows;
    const appliedAgentNames=new Set(agentsLedger.map(row=>row.name));
    const agentSuccessors=fs.readdirSync(agentsPreservation.baseline)
      .filter(name=>name.endsWith('.sql')&&!appliedAgentNames.has(name)).sort();
    assert.deepEqual(await agentsPreservation.snapshots(),agentsPreservation.beforeUpgrade);
    assert.deepEqual(await migrate(migrationPools.AGENTS,agentsPreservation.baseline),agentSuccessors);
    assert.deepEqual(await migrate(migrationPools.AGENTS,agentsPreservation.baseline),[]);
    const agentsCurrentLedger=(await migrationPools.AGENTS.query('SELECT name,checksum FROM dvaia_migrations.ledger ORDER BY name')).rows;
    assert.deepEqual(agentsCurrentLedger.slice(0,agentsLedger.length),agentsLedger);
    assert.deepEqual(await agentsPreservation.snapshots(),agentsPreservation.beforeUpgrade);
    const identityMigration=ownedPool('IDENTITY','MIGRATION'),identity=ownedPool('IDENTITY','RUNTIME'),leases=ownedPool('IDENTITY','RUNTIME');
    pools.push(identityMigration,identity,leases);
    await require('../../server/database/postgres/identityRepository').initializeIdentityRepository(identity,identityMigration);
    await require('../helpers/secureshopAuditCatalogQualification').qualifyAuditCatalog({identity,migration:identityMigration});
    const parentEvidence=await require('../helpers/secureshopAuditParentQualification').qualifyAuditParent({
      identity,identityMigration,leases,agents:stores.AGENTS.runtime,review:stores.REVIEW.runtime,commerce:commerceRuntime,snapshot,root:spoolRoot,
      actualModel:process.env.SS_AUDIT_GRAPH_LIVE_MODEL==='1'});
    assert.equal(parentEvidence.artifactsConsumed,5);
    if(process.env.SS_AUDIT_GRAPH_LIVE_MODEL==='1'){
      const injectionEvidence=await require('../helpers/secureshopAuditParentQualification').qualifyAuditParent({
        identity,identityMigration,leases,agents:stores.AGENTS.runtime,review:stores.REVIEW.runtime,commerce:commerceRuntime,snapshot,
        root:spoolRoot,actualModel:true,injected:true});
      assert.equal(injectionEvidence.objectiveCredit,true);
    }


    const {createSecureShopBoundAuditCleanup}=require('../../server/services/secureshopBoundAuditCleanup');
    const clean=createSecureShopBoundAuditCleanup({agentsPool:stores.AGENTS.runtime,reviewPool:stores.REVIEW.runtime});
    const deletionInput={subjectId:9,jobId:randomUUID(),leaseToken:'owned-test-lease',check:async()=>{}};
    const cleaned=await clean(deletionInput);assert.equal(cleaned.completed,true);
    assert.deepEqual(await clean(deletionInput),cleaned);
    assert.equal((await stores.REVIEW.repository.recent(target)).length,0);
    assert.equal((await reader.recent(sibling)).count,2);



    for(const [store,{runtime,repository}] of Object.entries(stores)) {
      const schema=`secureshop_${store.toLowerCase()}`;const job=randomUUID();
      const cleanup=await runtime.query(`SELECT * FROM ${schema}.destroy_bound_audit_owner($1,$2)`,[owner.platformOwnerId,job]);
      assert.equal(Number(cleanup.rows[0].deleted_event_count),2);
      assert.equal(cleanup.rows[0].receipt_sha256.length,32);
      const replay=await runtime.query(`SELECT * FROM ${schema}.destroy_bound_audit_owner($1,$2)`,[owner.platformOwnerId,job]);
      assert.deepEqual(replay.rows,cleanup.rows);
      await assert.rejects(runtime.query(`SELECT * FROM ${schema}.destroy_bound_audit_owner($1,$2)`,[sibling.platformOwnerId,job]),{code:'55000'});
      await assert.rejects(repository.append(runtime,event(owner)),{code:'55000'});
      assert.equal((await repository.recent(owner)).length,0);
      assert.equal((await repository.recent(sibling)).length,1);
      const racingOwner=scope(30), appendClient=await runtime.connect(), cleanupClient=await runtime.connect();
      let pending;
      try {
        await appendClient.query('BEGIN');await repository.append(appendClient,event(racingOwner));
        const pid=(await cleanupClient.query('SELECT pg_backend_pid() AS pid')).rows[0].pid;
        pending=cleanupClient.query(`SELECT * FROM ${schema}.destroy_bound_audit_owner($1,$2)`,[30,randomUUID()]);
        const deadline=Date.now()+3000;let blocked=false;
        while(Date.now()<deadline) {
          blocked=(await migrationPools[store].query("SELECT EXISTS(SELECT 1 FROM pg_locks WHERE pid=$1 AND locktype='advisory' AND NOT granted) AS blocked",[pid])).rows[0].blocked;
          if(blocked)break;
          await new Promise(resolve=>setTimeout(resolve,10));
        }
        assert.equal(blocked,true,'cleanup must wait for the in-flight owner append');
        await appendClient.query('COMMIT');
        const receipt=await pending;assert.equal(Number(receipt.rows[0].deleted_event_count),1);
        assert.equal((await repository.recent(racingOwner)).length,0);
        await assert.rejects(repository.append(runtime,event(racingOwner)),{code:'55000'});
      } finally {
        await appendClient.query('ROLLBACK');
        if(pending)await pending.catch(()=>{});
        appendClient.release();cleanupClient.release();
      }

    }

  }finally{await Promise.all(pools.map(pool=>pool.end()));for(const directory of directories)fs.rmSync(directory,{recursive:true,force:true});}
});
