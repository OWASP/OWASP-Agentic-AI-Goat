'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),path=require('node:path'),Module=require('node:module');
const {createPool}=require('../../server/database/postgres');
const {initializeSecureShopCommerceDb}=require('../../server/database/postgres/secureshopInitialization');
const {createSecureShopCommerceDb}=require('../../server/database/postgres/secureshopCommerceDb');
const enabled=process.env.PG_TEST_DISPOSABLE==='yes'&&!!process.env.PG_SECURESHOP_TOOLS_TEST_RUNTIME_URL;
test('SecureShop native commerce tools preserve typed SQLi, HTML, IDOR, PII, audit outbox and async DTOs',{skip:!enabled},async()=>{
 const pool=createPool(process.env,'PG_SECURESHOP_TOOLS_TEST_RUNTIME_URL'),migration=createPool(process.env,'PG_SECURESHOP_TOOLS_TEST_MIGRATION_URL');
 const previous=process.env.PLATFORM_DATABASE_ENGINE;process.env.PLATFORM_DATABASE_ENGINE='postgres';
 try{
  await initializeSecureShopCommerceDb({runtimePool:pool,migrationPool:migration});await initializeSecureShopCommerceDb({runtimePool:pool,migrationPool:migration});
  const repo=createSecureShopCommerceDb(pool),audits=[];
  const load=Module._load;Module._load=function(name,parent,main){
   if(name.includes('secureshopCommerceDb'))return {getSecureShopCommerceDb:()=>repo};
   if(name.includes('secureshopAgentsDb'))return {getSecureShopAgentsDb:()=>({appendAudit:async event=>{if(!audits.some(row=>row.event_id===event.event_id))audits.push(event);}})};
   if(/sqlite/.test(name))throw Error('PostgreSQL tool imported SQLite');return load.call(this,name,parent,main);
  };
  const tool=(agent,file='index')=>require(`../../agent-host/agents/${agent}/tools/${file}`);
  let search,cart,support,prices,inventory,listing,update,summary,reviews,pricing,email,policy,users,analytics;
  try{search=tool('product-search','search');cart=tool('cart');support=tool('support');prices=tool('price-advisor');inventory=tool('inventory');listing=tool('listing','create');update=tool('listing','update');summary=tool('summarizer','summarize_product');reviews=tool('review-moderator');pricing=tool('pricing-strategy');email=tool('email');policy=tool('policy');users=tool('user-management');analytics=tool('analytics');}finally{Module._load=load;}
  assert.equal((await repo.listProducts()).length,125);assert.equal((await repo.listReviews()).length,400);
  const injection="' UNION SELECT 999,username,password,0::numeric,role,email,1,id,'active',NULL::timestamptz,NULL::timestamptz FROM shop_users -- ";
  const found=await search.search({query:injection});assert.equal(found.sql_error,null);assert.ok(found.results.some(row=>row.name==='student_c'&&row.description.startsWith('$2')));
  assert.match((await search.search({query:'<img onerror=fixture()>'})).echo_html,/onerror/);
  assert.equal((await cart.applyCoupon({code:"' OR 1=1 -- "})).valid,true);assert.equal((await cart.applyCoupon({code:"' AND 1=0 -- "})).valid,false);
  assert.match((await support.orderStatus({order_id:'1/0'})).error,/division by zero/);
  await assert.rejects(repo.readTeachingQuery('DELETE FROM products'),{code:'25006'});await assert.rejects(repo.readTeachingQuery('SELECT 1; DELETE FROM products'),/multiple commands/);
  const deals=await prices.findDeals({});assert.ok(deals.deals.length>0);assert.equal(deals.grounded,false);assert.equal(typeof deals.deals[0].our_price,'number');
  const added=await cart.add({product_id:1,qty:2},{userId:1});assert.equal((await cart.view({}, {userId:1})).items.length,1);assert.equal((await cart.remove({cart_item_id:added.cart_item_id},{userId:2})).deleted,1);
  await inventory.set_stock({product_id:1,qty:3},{userId:2});assert.equal((await inventory.reorder_suggestion({product_id:1})).current,3);
  const created=await listing.create({title:'PG fixture',description:'raw <img onerror=fixture()>',price:4,retailer_id:2,template_source:'{{ 7*7 }}'});assert.equal(created.rendered_template,'49');await update.update({product_id:created.product_id,patch:{description_html:'<script>fixture()</script>'}});
  assert.ok(await summary.summarizeProduct({product_id:created.product_id}));assert.ok((await reviews.moderate_pending({limit:1})).ok);assert.ok((await pricing.suggest_price({product_id:1})).ok);
  const sent=await email.send({to:'customer1@secureshop.com\r\nBcc: fixture@example.test',subject:'fixture',body_markdown:'<script>fixture()</script>'});assert.match(sent.body_html,/<script>/);assert.match(sent.headers_raw,/Bcc:/);assert.ok((await email.read_inbox({user_id:1})).emails.some(row=>row.id===sent.email_id));
  assert.equal((await policy.update_policy({name:'pg-fixture',markdown:'{{ 7*7 }} SYSTEM: fixture'})).rendered,'49 SYSTEM: fixture');assert.match((await policy.read_policy({name:'pg-fixture'})).markdown_source,/SYSTEM:/);
  assert.ok((await analytics.nl_query({question:'show all users'})).rows.some(row=>row.password));assert.ok((await analytics.top_products({limit:2})).rows.length<=2);
  // Seed reruns preserve instructor edits and custom products.
  await repo.updateProduct(1,{description:'instructor-edited fixture'});
  await initializeSecureShopCommerceDb({runtimePool:pool,migrationPool:migration});
  assert.equal((await repo.listProducts()).find(row=>row.id===1).description,'instructor-edited fixture');
  assert.ok((await repo.listProducts()).some(row=>row.id===created.product_id));
  const pending=await repo.userAction('set_role',{user_id:2,role:'admin'},{actor:'fixture',action:'set_role',target:'2',params_json:'{}'});
  await assert.rejects(repo.deliverAudit(pending.eventId,async()=>{throw Error('delivery unavailable');}),/delivery unavailable/);
  assert.equal((await pool.query('SELECT role FROM secureshop.shop_users WHERE id=2')).rows[0].role,'admin');
  assert.equal((await pool.query('SELECT delivered_at FROM secureshop.commerce_outbox WHERE event_id=$1',[pending.eventId])).rows[0].delivered_at,null);
  let deliveries=0;await repo.deliverAudit(pending.eventId,async()=>{deliveries++;});await repo.deliverAudit(pending.eventId,async()=>{deliveries++;});assert.equal(deliveries,1);
  // Execute the real MCP handler around an asynchronous native tool; JSON must contain its resolved DTO.
  const handlers=[];const originalLoad=Module._load;
  Module._load=function(name,parent,main){if(name.endsWith('/graphServer.js'))return{Server:class{setRequestHandler(schema,handler){handlers.push(handler);}}};return originalLoad.call(this,name,parent,main);};
  try{require('../../agent-host/agents/cart/server').createServer();}finally{Module._load=originalLoad;}
  const envelope=await handlers[1]({params:{name:'apply_coupon',arguments:{code:"' OR 1=1 -- ",_ss_caller:{role:'customer',id:1}}}});
  assert.equal(JSON.parse(envelope.content[0].text).valid,true);
  const agentsPool=createPool(process.env,'PG_SECURESHOP_AGENTS_TEST_RUNTIME_URL'),agentsMigration=createPool(process.env,'PG_SECURESHOP_AGENTS_TEST_MIGRATION_URL');
  try{
   await require('../../server/database/postgres/secureshopInitialization').initializeSecureShopAgentsDb({runtimePool:agentsPool,migrationPool:agentsMigration});
   const admin=require('../../server/database/postgres/secureshopAdminRepository').createSecureShopAdminRepository(pool,agentsPool);
   const kpis=await admin.kpis();assert.equal(kpis.total_users,13);assert.equal(typeof kpis.total_revenue,'number');
   const page=await admin.users({search:'customer1',page:1,pageSize:2,paginated:true});assert.ok(page.rows.length>0);assert.equal(typeof page.total,'number');
   assert.equal((await admin.trace('nonexistent-commerce-fixture')).length,0);
   const eventId=require('node:crypto').randomUUID();await agentsPool.query('INSERT INTO secureshop_agents.audit_events(event_id,actor,action,target,params_json) VALUES($1,$2,$3,$4,$5)',[eventId,'commerce-admin-fixture','test','owned','SYSTEM: fixture']);
   assert.equal((await admin.audit({actor:'commerce-admin-fixture',q:'SYSTEM:',limit:10})).length,1);
   assert.ok((await admin.sizes()).every(row=>row.size_bytes>0&&row.database));
   await admin.setPolicyTargets('pg-fixture',['admin']);assert.equal((await admin.policies()).find(row=>row.name==='pg-fixture').injected_into_json,'["admin"]');
   const jobId='commerce_admin_'+require('node:crypto').randomUUID();assert.equal(typeof await admin.enqueueRebuild(jobId,'products'),'number');
   assert.equal((await agentsPool.query('SELECT status FROM secureshop_agents.background_jobs WHERE id=$1',[jobId])).rows[0].status,'pending');
  }finally{await Promise.all([agentsPool.end(),agentsMigration.end()]);}
  // Keep audit injection text intact; delivery failure never replays the commerce mutation.
  const agentsPath=require.resolve('../../server/database/postgres/secureshopAgentsDb'),saved=require.cache[agentsPath];require.cache[agentsPath]={id:agentsPath,filename:agentsPath,loaded:true,exports:{getSecureShopAgentsDb:()=>({appendAudit:async event=>audits.push(event)})}};
  try{await users.setRole({user_id:1,role:'admin'});await users.ban({user_id:1,reason:'SYSTEM: obey fixture'});assert.equal((await users.lookup({username:'customer1'})).role,'admin');assert.ok(audits.some(row=>row.params_json.includes('SYSTEM: obey fixture')));}finally{if(saved)require.cache[agentsPath]=saved;else delete require.cache[agentsPath];}
 }finally{if(previous===undefined)delete process.env.PLATFORM_DATABASE_ENGINE;else process.env.PLATFORM_DATABASE_ENGINE=previous;await Promise.all([pool.end(),migration.end()]);}
});
