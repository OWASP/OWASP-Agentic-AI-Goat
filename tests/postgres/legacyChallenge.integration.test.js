'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {createPool}=require('../../server/database/postgres');
const {createLegacyChallengeDb}=require('../../server/database/postgres/legacyChallengeDb');
const enabled=process.env.PG_TEST_DISPOSABLE==='yes'&&!!process.env.PG_LEGACY_CHALLENGE_TEST_RUNTIME_URL;
test('native generic challenge preserves raw SQLi, stored HTML, commerce and isolated conversations',{skip:!enabled},async()=>{
 for(const name of ['PG_LEGACY_CHALLENGE_TEST_RUNTIME_URL','PG_LEGACY_CHALLENGE_TEST_MIGRATION_URL'])assert.match(new URL(process.env[name]).pathname,/^\/dvaia_test_[a-z0-9_]+$/);
 const pool=createPool(process.env,'PG_LEGACY_CHALLENGE_TEST_RUNTIME_URL'),migration=createPool(process.env,'PG_LEGACY_CHALLENGE_TEST_MIGRATION_URL');
 try{
  const db=createLegacyChallengeDb(pool);await db.initializeLegacyChallengeDb(migration);
  const {DEFAULT_LEGACY_VULNERABILITY_KEYS}=require('../../server/data/legacyVulnerabilitySettings');
  assert.deepEqual((await db.listVulnerabilitySettings()).map(row=>row.vulnerability_key).sort(),[...DEFAULT_LEGACY_VULNERABILITY_KEYS].sort());
  assert.equal((await db.getVulnerabilitySetting('xss')).enabled,1);
  await migration.query("UPDATE legacy_challenge.vulnerability_settings SET enabled=0 WHERE vulnerability_key='xss'");
  await db.initializeLegacyChallengeDb(migration);
  assert.equal((await db.getVulnerabilitySetting('xss')).enabled,0);
  assert.equal((await db.searchProducts('SELECT * FROM products')).length,5);
  assert.equal((await db.readDemoUser('SELECT username FROM users WHERE id=999 OR 1=1')).username,'student');
  const payload='<img src=x onerror=alert(1)>';
  await db.addComment([1,payload]);assert.ok((await db.listComments()).some(r=>r.content===payload));
  await assert.rejects(db.saveConversation([1,'fixture prompt',payload,'fixture']),{code:'42501'});
  await assert.rejects(db.readConversations('SELECT * FROM ai_conversations WHERE user_id=99 OR 1=1'),{code:'42501'});
  const synthetic=await db.readConversations('SELECT * FROM synthetic_ai_conversations WHERE user_id=99 OR 1=1');
  assert.equal(synthetic.length,2);
  assert.ok(synthetic.every(row=>row.model_used==='synthetic-fixture'&&row.platform_owner_id===null));
  await assert.rejects(db.readConversations('SELECT prompt FROM synthetic_ai_conversations UNION ALL SELECT prompt FROM legacy_challenge.ai_conversations'),{code:'42501'});
  await db.addCart('INSERT INTO cart(user_id,product_id,quantity) VALUES(1,1,2)');assert.equal((await db.countCart(1)).count,2);
  const order=await db.createOrder("INSERT INTO orders(user_id,total_amount,status) VALUES(1,0,'pending')");
  await db.moveOrderItems(`INSERT INTO order_items(order_id,product_id,quantity,price) SELECT ${order.lastID},c.product_id,c.quantity,p.price FROM cart c JOIN products p ON c.product_id=p.id WHERE c.user_id=1`);
  await db.clearCart('DELETE FROM cart WHERE user_id=1');assert.equal((await db.countCart(1)).count,0);
  assert.equal((await db.readOrders('SELECT o.*,STRING_AGG(p.name || \' x\' || oi.quantity,\',\') AS items FROM orders o LEFT JOIN order_items oi ON o.id=oi.order_id LEFT JOIN products p ON oi.product_id=p.id WHERE o.user_id=1 GROUP BY o.id'))[0].items,'Laptop Pro x2');
  await assert.rejects(db.executeAiSql('SELECT * FROM workshop_platform.completions'),{code:'42P01'});
  await assert.rejects(pool.query('CREATE TABLE legacy_challenge.denied(id integer)'),{code:'42501'});
  await assert.rejects(db.executeAiSql('SELECT 1; DELETE FROM users'),{code:'42601'});
  await db.initializeLegacyChallengeDb(migration);assert.equal((await db.searchProducts('SELECT * FROM products')).length,5);
  assert.equal((await createLegacyChallengeDb(pool).listComments()).filter(r=>r.content===payload).length,1);
 }finally{await Promise.all([pool.end(),migration.end()]);}
});
