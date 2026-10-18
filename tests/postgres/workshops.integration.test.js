'use strict';
const {test}=require('node:test');
const assert=require('node:assert/strict');
const {createPool}=require('../../server/database/postgres');
const {createSqlWorkshopDb}=require('../../server/database/postgres/sqlWorkshopDb');
const {createNosqlWorkshopDb}=require('../../server/database/postgres/nosqlWorkshopDb');
const enabled=process.env.PG_TEST_DISPOSABLE==='yes'&&Boolean(process.env.PG_ARIA_TEST_MIGRATION_URL)&&Boolean(process.env.PG_NOVA_TEST_MIGRATION_URL);
function pool(key) {
  assert.match(new URL(process.env[key]).pathname,/^\/dvaia_test_[a-z0-9_]+$/);
  return createPool(process.env,key);
}

test('real PG18 ARIA/NOVA: exact tool contracts, curriculum proofs, owner isolation, durable atomic mutations', {skip:!enabled}, async()=>{
  const ariaMigration=pool('PG_ARIA_TEST_MIGRATION_URL');
  const novaMigration=pool('PG_NOVA_TEST_MIGRATION_URL');
  const ariaPool=pool('PG_ARIA_TEST_RUNTIME_URL');
  const novaPool=pool('PG_NOVA_TEST_RUNTIME_URL');
  const aria=createSqlWorkshopDb(ariaPool),nova=createNosqlWorkshopDb(novaPool);
  try {
    for(const p of [ariaMigration,novaMigration])assert.equal((await p.query("SELECT to_regnamespace('dvaia_migrations') AS schema")).rows[0].schema,null,'Fresh disposable database required');
    await aria.initializeSqlWorkshopDb(ariaMigration);
    await nova.initializeNosqlWorkshopDb(novaMigration);
    const qualificationCases=await require('../fixtures/sqlNoSqlJudgeCases').captureSqlNoSqlJudgeCases({aria,nova});
    assert.equal(qualificationCases.length,40);
    const {hasObjectiveObservation}=require('../../server/services/sqlNoSqlObjectiveEvidence');
    for(const item of qualificationCases) assert.equal(hasObjectiveObservation({...item,userId:7,
      history:item.history.map(r=>({evidence:{invocation:r.toolInvocation,result:r.toolResult}}))}),item.positive,`${item.objectiveId} observation prerequisite`);

    require('node:fs').writeFileSync('/tmp/dvaia-sql-nosql-judge-cases.json',JSON.stringify(qualificationCases,null,2));
    const leaked=await nova.searchPapers('{"access_level":{"$ne":"public"}}',null,null,'vuln');
    assert.equal(leaked.filter(p=>p.access_level==='restricted').length,2);
    for(const record of leaked.filter(p=>p.access_level==='restricted')) {
      assert.deepEqual(await nova.searchPapers(record.title,null,null,'fixed'),[]);
      assert.deepEqual(await nova.searchPapers(record.title,null,null,'vuln'),[],'Normal literal search retains public scope');
    }
    const nativeSolutions=await novaMigration.query("SELECT objective_id,examples FROM nova.nosql_injection_solutions WHERE objective_id IN ('nosqli_4','nosqli_5') ORDER BY objective_id");
    assert.match(nativeSolutions.rows[0].examples,/db\.version/);
    assert.match(nativeSolutions.rows[1].examples,/Object\.keys/);
    const routeSource=require('node:fs').readFileSync(require('node:path').join(__dirname,'../../server/routes/sqlWorkshop.js'),'utf8');
    const detectorStart=routeSource.indexOf('function detectCompletedObjectives(');
    const detectorEnd=routeSource.indexOf('// ── GET',detectorStart);
    const detect=require('node:vm').runInNewContext(`(${routeSource.slice(detectorStart,detectorEnd).trim()})`,{process:{env:{WORKSHOP_DATABASE_ENGINE:'postgres'}}});
    const solutions=require('../../server/data/sqlInjectionWorkshopSolutions');
    for(const [id,solution] of Object.entries(solutions)) {
      const payload=solution.examples[0].replace(/^search for /i,'');
      let result;
      try {result=await aria.searchProducts(payload,null,'vuln');}catch(error){result={error:error.message};}
      assert.ok(detect(payload,'search_products',result,'vuln').includes(id),`Published PostgreSQL solution must prove ${id}: ${JSON.stringify(result)}`);
      assert.equal(detect(payload,'search_products',result,'fixed').length,0);
    }
    assert.equal((await aria.searchProducts('')).length,25);
    assert.equal((await aria.listOrders('current_user')).length,10);
    assert.equal((await aria.lookupOrder('ORD-2024-001','current_user')).length,1);
    assert.deepEqual(await aria.lookupOrder('ORD-2024-001','other_attendee'),[]);
    assert.equal((await aria.getReceipt('ORD-2024-001','current_user'))[0].receipt_number,'RCP-2024-001');
    assert.equal((await aria.getOrderStatus('ORD-2024-001','current_user')).status,'delivered');
    assert.ok((await aria.searchProducts('keyboard',100)).length);
    assert.deepEqual(await aria.searchProducts("' OR 1=1 --",null,'fixed'),[]);
    assert.equal((await aria.searchProducts("' OR 1=1 --",null,'vuln')).length,25);
    await assert.rejects(aria.searchProducts("%' ; SELECT 1 --",null,'vuln'),{code:'42601'},'Keep the legacy single-statement sink; do not accidentally introduce stacked commands');
    const catalogPayload="' UNION SELECT NULL,NULL,tablename,NULL,NULL,NULL,NULL,NULL FROM pg_catalog.pg_tables WHERE schemaname='aria' --";
    assert.ok((await aria.searchProducts(catalogPayload,null,'vuln')).some(r=>r.name==='orders'));
    assert.deepEqual(await aria.searchProducts(catalogPayload,null,'fixed'),[]);
    assert.equal((await aria.updateAddress('ORD-2024-001','other','bad')).success,false);
    assert.equal((await aria.updateAddress('ORD-2024-001','current_user','new')).success,false);
    assert.equal((await aria.updateAddress('ORD-2024-007','current_user','new')).success,true);
    assert.equal((await aria.returnRefund('ORD-2024-001','other')).success,false);
    const refunds=await Promise.all([aria.returnRefund('ORD-2024-001','current_user'),aria.returnRefund('ORD-2024-001','current_user')]);
    assert.equal(refunds.filter(r=>r.success).length,1);
    assert.equal((await aria.addToCart('a','not-real')).success,false);
    await Promise.all(Array.from({length:8},()=>aria.addToCart('a','Mechanical Keyboard',1)));
    assert.equal((await aria.viewCart('a'))[0].quantity,8);
    await aria.addToCart('b','Mechanical Keyboard',1);
    // Failed receipt insert must restore both order and cart; restrict failure to this test transaction.
    await ariaMigration.query("ALTER TABLE aria.receipts ADD CONSTRAINT test_reject_receipt CHECK (amount <> 719.92) NOT VALID");
    await assert.rejects(aria.checkout('a','address'));
    assert.equal((await aria.listOrders('a')).length,0);
    assert.equal((await aria.viewCart('a'))[0].quantity,8);
    await ariaMigration.query('ALTER TABLE aria.receipts DROP CONSTRAINT test_reject_receipt');
    const checkouts=await Promise.all([aria.checkout('a','address'),aria.checkout('a','address')]);
    assert.equal(checkouts.filter(r=>r.success).length,1);
    const order=checkouts.find(r=>r.success).orders[0];
    assert.equal(order.total,'719.92');
    assert.match(order.orderNumber,/^ORD-\d{4}-\d{3,}$/,'Generated order IDs must remain recognizable by ARIA intent detection');
    assert.equal((await aria.getReceipt(order.orderNumber,'a'))[0].receipt_number,order.receiptNumber);
    assert.equal((await aria.viewCart('b')).length,1);
    assert.equal((await aria.removeFromCart('b','Keyboard')).removed,1);
    await aria.clearCart('current_user');
    await aria.initializeSqlWorkshopDb(ariaMigration);
    assert.deepEqual(await aria.viewCart('current_user'),[],'Seed must not resurrect cleared cart');
    assert.equal((await aria.lookupOrder('ORD-2024-001','current_user'))[0].status,'refunded','Seed must not overwrite changed orders');

    assert.equal((await nova.getPaperDetails('PAPER-2024-001')).title,'Attention Is All You Need');
    assert.equal(await nova.getPaperDetails('missing'),null);
    assert.ok((await nova.listPapersByAuthor('Vaswani')).length);
    assert.ok((await nova.browseByTopic('transformers')).length);
    assert.ok((await nova.getAuthorProfile('Vaswani')).expertise.length);
    assert.ok((await nova.searchAuthors('')).length);
    assert.ok((await nova.searchPapers('',null,2017)).every(p=>p.year===2017));
    assert.equal((await nova.addToReadingList('a','missing')).success,false);
    const additions=await Promise.all([nova.addToReadingList('a','PAPER-2024-001'),nova.addToReadingList('a','PAPER-2024-001')]);
    assert.equal(additions.filter(r=>r.success).length,1);
    await nova.addToReadingList('b','PAPER-2024-001','other notes');
    assert.equal((await nova.removeFromReadingList('a','PAPER-2024-001')).removed,1);
    assert.equal((await nova.viewReadingList('b'))[0].notes,'other notes');
    assert.ok((await nova.getRecommendations(null,'PAPER-2024-001')).length);
    assert.ok((await nova.getRecommendations('transformers')).length);
    assert.ok((await nova.getRecommendations()).length);
    assert.ok((await nova.getTrendingTopics())[0].paperCount);
    assert.ok((await nova.getCitationNetwork('PAPER-2024-001')).citedBy.length);
    assert.equal((await nova.getCitationNetwork('missing')).success,false);
    for(const payload of ['{"title":{"$gt":""}}','{"$or":[{"title":"none"},{}]}','{"title":{"$exists":true}}','{"$where":"return true"}','{"title":{"$ne":"none"}}','{"access_level":{"$ne":"restricted"}}']) {
      assert.ok((await nova.searchPapers(payload,null,null,'vuln')).length>10);
      assert.deepEqual(await nova.searchPapers(payload,null,null,'fixed'),[]);
    }
    assert.ok((await nova.searchPapers('{"title":{"$regex":".*"}}',null,null,'vuln')).length);
    assert.ok((await nova.searchPapers('{"topics":{"$in":["transformers"]}}',null,null,'vuln')).length);
    assert.ok((await nova.searchPapers('{"email":{"$regex":".*"}}',null,null,'vuln'))[0].email);
    assert.match((await nova.searchPapers('{"$bad":1}',null,null,'vuln')).error,/unknown operator/);
    assert.match((await nova.searchPapers('{bad}',null,null,'vuln')).error,/Failed to parse/);
    const metadata=(await nova.searchPapers('{"$where":"db.version()"}',null,null,'vuln'))[0];
    assert.equal(metadata.storage_engine,'PostgreSQL');
    assert.match(metadata.db_version,/^18\./);
    const schema=await nova.searchPapers('{"$where":"Object.keys(this)"}',null,null,'vuln');
    assert.ok(schema[0].fields.find(f=>f.name==='paper_id').unique);
    assert.equal(schema[0].fields.find(f=>f.name==='id').type,'Integer');
    await nova.clearReadingList('current_user');
    await nova.initializeNosqlWorkshopDb(novaMigration);
    assert.deepEqual(await nova.viewReadingList('current_user'),[]);

    for(const db of [aria,nova]) {
      const saved=await db.saveMessage('a','user','one');assert.ok(saved.lastID);assert.equal(saved.changes,1);
      await db.saveMessage('a','assistant','two');await db.saveMessage('b','user','private');
      assert.deepEqual(await db.getHistory('a',1),[{message_type:'assistant',message:'two'}]);
      await db.clearHistory('a');assert.deepEqual(await db.getHistory('a'),[]);assert.equal((await db.getHistory('b')).length,1);
    }
    // Runtime roles cannot edit catalogs or migration/solution control data.
    await assert.rejects(ariaPool.query('DELETE FROM aria.products'),{code:'42501'});
    await assert.rejects(ariaPool.query('SELECT * FROM dvaia_migrations.ledger'),{code:'42501'});
    await assert.rejects(novaPool.query('UPDATE nova.nosql_injection_solution_visibility SET solutions_enabled=1'),{code:'42501'});
    const freshAria=createSqlWorkshopDb(ariaPool);
    assert.equal((await freshAria.listOrders('a')).length,1,'State survives repository recreation');
  } finally {await Promise.all([ariaPool.end(),novaPool.end(),ariaMigration.end(),novaMigration.end()]);}
});
