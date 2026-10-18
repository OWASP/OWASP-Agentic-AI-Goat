'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const express=require('express');
const {createPool}=require('../../server/database/postgres');
const {initializeSecureShopCommerceDb,initializeSecureShopAgentsDb}=require('../../server/database/postgres/secureshopInitialization');
const {createSecureShopCustomerRepository}=require('../../server/database/postgres/secureshopCustomerRepository');
const enabled=process.env.PG_TEST_DISPOSABLE==='yes'&&!!process.env.PG_SECURESHOP_CUSTOMER_TEST_RUNTIME_URL;
test('native customer HTTP preserves catalog, SQLi, raw reviews, IDOR and atomic checkout',{skip:!enabled},async()=>{
  const pool=createPool(process.env,'PG_SECURESHOP_CUSTOMER_TEST_RUNTIME_URL'),migration=createPool(process.env,'PG_SECURESHOP_CUSTOMER_TEST_MIGRATION_URL');
  const agents=createPool(process.env,'PG_SECURESHOP_AGENTS_TEST_RUNTIME_URL'),agentMigration=createPool(process.env,'PG_SECURESHOP_AGENTS_TEST_MIGRATION_URL');
  const previous=process.env.PLATFORM_DATABASE_ENGINE;process.env.PLATFORM_DATABASE_ENGINE='postgres';
  let server;
  try{
    await initializeSecureShopCommerceDb({runtimePool:pool,migrationPool:migration});
    await initializeSecureShopAgentsDb({runtimePool:agents,migrationPool:agentMigration});
    const repository=createSecureShopCustomerRepository(pool,agents);
    const app=express();app.use(express.json());app.use('/shop',require('../../server/routes/secureshop/postgres/customer')({repository,pool:{},manifest:{},provider:{}}));
    server=app.listen(0,'127.0.0.1');await new Promise(resolve=>server.once('listening',resolve));
    const base=`http://127.0.0.1:${server.address().port}/shop`;
    const request=async(url,method='GET',body)=>{const r=await fetch(base+url,{method,headers:{'content-type':'application/json'},...(body?{body:JSON.stringify(body)}:{})});return{status:r.status,body:await r.json()};};
    const catalog=await request('/products?limit=3&sort=price_asc');
    assert.equal(catalog.status,200);assert.equal(catalog.body.products.length,3);assert.ok(catalog.body.total>=125);
    assert.equal(typeof catalog.body.products[0].price,'number');assert.equal(typeof catalog.body.products[0].avg_rating,'number');
    const product=(await request('/products/1')).body;
    assert.ok(product.product.images.length);assert.ok(Array.isArray(product.reviews));
    const raw='<img src=x onerror="fixture()">';
    const review=await request('/products/1/reviews','POST',{author_id:1,body:raw,rating:5});
    assert.equal(review.status,200);assert.ok((await request('/products/1/reviews')).body.reviews.some(row=>row.body===raw));
    const a=(await request('/auth/register','POST',{username:'customer_http_a',email:'customer_http_a@example.test',password:'fixture-pass'})).body.user;
    assert.ok(a.id);
    const cart=await request('/cart','POST',{user_id:a.id,product_id:1,quantity:2});
    assert.equal(cart.status,200);
    // Intentionally no owner check on cart mutation.
    assert.equal((await request(`/cart/${cart.body.cart_item_id}`,'PATCH',{quantity:3,user_id:99999})).body.changes,1);
    const coupon=await request('/cart/apply-coupon','POST',{user_id:a.id,code:"' OR 1=1--"});
    assert.equal(coupon.status,200);assert.ok(coupon.body.ok);
    const invalid=await request('/cart/apply-coupon','POST',{code:"' malformed SQL"});assert.equal(invalid.status,400);assert.ok(invalid.body.sql);
    const before=(await repository.orders(a.id)).length;
    await migration.query("CREATE FUNCTION secureshop.reject_test_line() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture failure'; END $$");
    await migration.query('CREATE TRIGGER fail_order_line BEFORE INSERT ON secureshop.order_items FOR EACH ROW EXECUTE FUNCTION secureshop.reject_test_line()');
    assert.equal((await request('/orders','POST',{user_id:a.id})).status,500);
    assert.equal((await repository.orders(a.id)).length,before);assert.equal((await repository.cart(a.id)).length,1);
    await migration.query('DROP TRIGGER fail_order_line ON secureshop.order_items');
    const results=await Promise.all([request('/orders','POST',{user_id:a.id}),request('/orders','POST',{user_id:a.id})]);
    assert.deepEqual(results.map(row=>row.status).sort(),[200,400]);
    assert.equal((await repository.cart(a.id)).length,0);assert.equal((await repository.orders(a.id)).length,before+1);
    const order=results.find(row=>row.status===200).body;
    const read=await request(`/orders/${order.order_id}?user_id=99999`);assert.equal(read.status,200);assert.equal(read.body.items.length,1);
    await assert.rejects(repository.coupon('SELECT 1; SELECT 2'));
  }finally{
    if(server)await new Promise(resolve=>server.close(resolve));
    if(previous===undefined)delete process.env.PLATFORM_DATABASE_ENGINE;else process.env.PLATFORM_DATABASE_ENGINE=previous;
    await Promise.allSettled([pool.end(),migration.end(),agents.end(),agentMigration.end()]);
  }
});
