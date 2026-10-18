'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {createSecureShopBoundCommerceRepository}=require('../server/database/postgres/secureshopBoundCommerceRepository');
const {createSecureShopBoundCommerce}=require('../server/services/secureshopBoundCommerce');
const scope={launchId:'10000000-0000-4000-8000-000000000001',scenarioId:'20000000-0000-4000-8000-000000000001',generation:1,platformOwnerId:7,platformSessionId:8};
const target={...scope,kind:'products',targetId:'30000000-0000-4000-8000-000000000001'};
function repositoryFixture(){const queries=[];let rows=[{order_id:'12',status:'confirmed',order_date:new Date('2026-10-10T00:00:00Z'),items:[{product_id:11,product_name:'Sold name',quantity:3,price:'0.10',discount_amount:'0.02'}]}];
 const client={async query(sql,args){queries.push([sql,args]);if(['BEGIN','COMMIT','ROLLBACK'].includes(sql))return{rows:[]};if(sql.includes('SELECT lifecycle'))return{rows:[{lifecycle:'active'}]};if(sql.startsWith('WITH owned'))return{rows};throw Error('unexpected query')},release(){}};
 return{queries,setRows(value){rows=value},repo:createSecureShopBoundCommerceRepository({query:async()=>{},connect:async()=>client},{checkCurrent:async()=>{}})};
}
test('merchant read SQL restricts both joins and retailer, selects no checkout-private fields, uses saved cents',async()=>{
 const f=repositoryFixture();assert.deepEqual(await f.repo.listMerchantOrders(target,42),{orders:[{orderId:12,status:'confirmed',orderDate:'2026-10-10T00:00:00.000Z',merchantSubtotal:0.28,items:[{productId:11,name:'Sold name',quantity:3,price:0.1,discountAmount:0.02,lineTotal:0.28}]}],nextCursor:null});
 const [sql,args]=f.queries.find(([q])=>q.startsWith('WITH owned'));
 assert.deepEqual(args,[target.targetId,42,null,null,null]);assert.match(sql,/oi.target_id=o.target_id AND oi.order_id=o.order_id/);
 assert.match(sql,/p.target_id=oi.target_id AND p.product_id=oi.product_id/);assert.match(sql,/o.target_id=\$1 AND p.retailer_id=\$2/);
 assert.match(sql,/ORDER BY order_date DESC,order_id DESC LIMIT 6/);
 assert.doesNotMatch(sql,/shipping_address|payment_|shop_user_id|total_amount|listing_overlays|SELECT \*/);
 const detail=await f.repo.getMerchantOrder(target,{merchantId:42,orderId:12});assert.equal(detail.orderId,12);
 assert.deepEqual(f.queries.filter(([q])=>q.startsWith('WITH owned'))[1][1],[target.targetId,42,12,null,null]);
 assert.equal(f.queries.some(([q])=>/^(INSERT|UPDATE|DELETE)/.test(q)),false);
 f.setRows([]);assert.equal(await f.repo.getMerchantOrder(target,{merchantId:43,orderId:12}),null);
});
test('merchant projection fails closed on excessive lines, unsafe totals and corrupt stored dates',async()=>{
 const f=repositoryFixture(),line={product_id:11,product_name:'Sold name',quantity:1,price:'1.00',discount_amount:'0.00'};
 for(const row of [
  {order_id:'12',status:'confirmed',order_date:new Date(),items:Array(257).fill(line)},
  {order_id:'12',status:'confirmed',order_date:new Date(),items:[{...line,discount_amount:'2.00'}]},
  {order_id:'12',status:'confirmed',order_date:'invalid',items:[line]},
 ]){f.setRows([row]);await assert.rejects(f.repo.listMerchantOrders(target,42));}
});
test('merchant service reads existing target only with current merchant session before and after, never effect fence',async()=>{
 let revoked=false,revokeAfterRead=false,reads=0,effects=0,prepares=0;
 const repository=Object.fromEntries(['listCart','addCart','updateCart','removeCart','checkout','listOrders','getOrder'].map(k=>[k,async()=>null]));
 repository.listMerchantOrders=async(t,id)=>{assert.deepEqual(t,{...scope,targetId:target.targetId,role:'merchant',shopUserId:42});assert.equal(id,42);reads++;if(revokeAfterRead)revoked=true;return[]};
 repository.getMerchantOrder=async(t,args)=>{assert.deepEqual(t,{...scope,targetId:target.targetId,role:'merchant',shopUserId:42});assert.deepEqual(args,{merchantId:42,orderId:12});reads++;return null};
 const personaAuthority={capture(v){return{binding:{...v.scope,personaId:v.personaId,role:v.role,sessionId:v.sessionId,authorityVersion:v.authorityVersion},async assertRemoteAdmission(){if(revoked)throw Object.assign(Error('revoked'),{code:'SHOP_AUTH_INVALID'})},async withCrossStoreEffect(){effects++;throw Error('read cannot dispatch effect')}}}};
 const service=createSecureShopBoundCommerce({repository,personaAuthority,resolveExistingTarget:async()=>target,catalog:{prepareTarget(){prepares++;return target},hasProduct:async()=>true}});
 const input={scope,persona:{id:42,role:'merchant'},personaSession:{sessionId:'40000000-0000-4000-8000-000000000001',authorityVersion:'1'}};
 assert.deepEqual(await service.merchantOrders(input),[]);assert.equal(await service.merchantOrder({...input,orderId:12}),null);
 await assert.rejects(service.merchantOrders({...input,persona:{id:42,role:'customer'}}),{code:'OWNER_MISMATCH'});
 await assert.rejects(service.merchantOrders({...input,personaSession:undefined}),{code:'SHOP_AUTH_INVALID'});assert.equal(reads,2);
 revokeAfterRead=true;await assert.rejects(service.merchantOrders(input),{code:'SHOP_AUTH_INVALID'});assert.equal(reads,3);
 await assert.rejects(service.merchantOrders(input),{code:'SHOP_AUTH_INVALID'});assert.equal(reads,3);assert.equal(effects,0);assert.equal(prepares,0);
});

test('merchant list cursor preserves microsecond date and equal-date ID ordering with an explicit next page',async()=>{
 const f=repositoryFixture(),date='2026-10-10T00:00:00.123456Z';
 const row=id=>({order_id:String(id),status:'confirmed',order_date:new Date(date),cursor_date:date,
  items:[{product_id:11,product_name:'Owned line',quantity:1,price:'1.00',discount_amount:'0.00'}]});
 f.setRows([9,8,7,6,5,4].map(row));
 const first=await f.repo.listMerchantOrders(target,42);
 assert.deepEqual(first.orders.map(o=>o.orderId),[9,8,7,6,5]);
 assert.deepEqual(JSON.parse(Buffer.from(first.nextCursor,'base64url')),[date,5]);
 f.setRows([4,3].map(row));const next=await f.repo.listMerchantOrders(target,42,first.nextCursor);
 assert.deepEqual(next.orders.map(o=>o.orderId),[4,3]);assert.equal(next.nextCursor,null);
 const calls=f.queries.filter(([sql])=>sql.startsWith('WITH owned'));
 assert.deepEqual(calls[1][1],[target.targetId,42,null,date,5]);
 assert.match(calls[1][0],/\(o.order_date,o.order_id\)<\(\$4::timestamptz,\$5::bigint\)/);
 assert.match(calls[1][0],/ORDER BY order_date DESC,order_id DESC LIMIT 6/);
 assert.match(calls[1][0],/o.target_id=\$1 AND p.retailer_id=\$2/);
 const before=calls.length;
 for(const cursor of ['',null,'x',first.nextCursor+'=',Buffer.from(JSON.stringify([date,0])).toString('base64url'),
  Buffer.from(JSON.stringify(['2026-02-31T00:00:00.123456Z',5])).toString('base64url'),
  Buffer.from(JSON.stringify([date,5,'extra'])).toString('base64url')])
  await assert.rejects(f.repo.listMerchantOrders(target,42,cursor),{code:'INVALID_ARGUMENT'});
 assert.equal(f.queries.filter(([sql])=>sql.startsWith('WITH owned')).length,before);
});

test('saved pagination lookup is completed same-session/scene/grant and skips null detail metadata',async()=>{
 const {createRoleChatBindingRepository}=require('../server/database/postgres/secureshopRoleChatBindingRepository');
 const {createSceneBinding}=require('../server/services/secureshopSceneBinding');
 const scene=createSceneBinding(target,{sceneId:'50000000-0000-4000-8000-000000000001',sceneGeneration:1,
  grantId:'60000000-0000-4000-8000-000000000001',execution:scope,withLease:work=>work()});
 const queries=[],client={async query(sql,args){queries.push([sql,args]);return{rows:[]}},release(){}};
 const repo=createRoleChatBindingRepository({pool:{query:async()=>{},connect:async()=>client}});
 const sessionId='70000000-0000-4000-8000-000000000001',personaSession={sessionId:'40000000-0000-4000-8000-000000000001',authorityVersion:'1'};
 assert.equal(await repo.readLatestOrdersPage({sessionId,scope,persona:{id:42,role:'merchant'},personaSession,target:scene}),null);
 const [sql,args]=queries[0];assert.equal(args.length,15);assert.equal(args[0],sessionId);assert.equal(args[8],42);
 assert.equal(args[9],personaSession.sessionId);assert.equal(args[11],scene.scene.sceneId);assert.equal(args[13],scene.scene.grantId);assert.equal(args[14],scene.targetId);
 assert.match(sql,/tr.status='completed'/);assert.match(sql,/jsonb_typeof\(tr.result_json #> '\{taskMetadata,roleChat,ordersPage\}'\)='object'/);
 assert.match(sql,/tr.result_json->>'stopReason'='end_turn'/);assert.match(sql,/ORDER BY t.created_at DESC,t.request_id DESC LIMIT 1/);
 assert.match(sql,/s.binding_state='active'/);assert.match(sql,/t.persona_session_id=\$10 AND t.authority_version=\$11/);
});

test('named merchant order SQL selects matches within own lines, then projects all own lines and preserves cursor',async()=>{
 const date='2026-10-10T00:00:00.123456Z',lines=[
  {product_id:11,product_name:'Purchased 50%_\\ widget',quantity:2,price:'1.00',discount_amount:'0.00'},
  {product_id:12,product_name:'Own unrelated line',quantity:1,price:'3.00',discount_amount:'0.50'},
 ];
 const f=repositoryFixture(),row=id=>({order_id:String(id),status:'confirmed',order_date:new Date(date),cursor_date:date,items:lines});
 f.setRows([9,8,7,6,5,4].map(row));
 const first=await f.repo.listMerchantOrders(target,42,undefined,'  50%_\\  ');
 assert.equal(first.productName,'50%_\\');assert.equal(first.orders[0].merchantSubtotal,4.5);assert.equal(first.orders[0].items.length,2);
 assert.deepEqual(JSON.parse(Buffer.from(first.nextCursor,'base64url')),[date,5]);
 const [sql,args]=f.queries.find(([q])=>q.startsWith('WITH owned'));
 assert.deepEqual(args,[target.targetId,42,null,null,null,'50%_\\']);
 const owned=sql.slice(sql.indexOf('WITH owned'),sql.indexOf('), picked AS'));
 assert.match(owned,/o.target_id=\$1 AND p.retailer_id=\$2/);assert.doesNotMatch(owned,/strpos|ILIKE|listing_overlays/);
 assert.match(sql,/GROUP BY order_id,order_date\s+HAVING bool_or\(strpos\(lower\(product_name\),lower\(\$6::text\)\) > 0\)/);
 const aggregate=sql.slice(sql.indexOf(') SELECT x.order_id'));
 assert.match(aggregate,/FROM owned x JOIN picked p USING\(order_id\)/);assert.doesNotMatch(aggregate,/strpos|retailer_id|total_amount|shop_user_id|payment/);
 f.setRows([4,3].map(row));const next=await f.repo.listMerchantOrders(target,42,first.nextCursor,first.productName);
 assert.deepEqual(next.orders.map(o=>o.orderId),[4,3]);assert.equal(next.productName,first.productName);
 assert.deepEqual(f.queries.filter(([q])=>q.startsWith('WITH owned'))[1][1],[target.targetId,42,null,date,5,'50%_\\']);
 f.setRows([]);assert.deepEqual(await f.repo.listMerchantOrders(target,43,undefined,'50%_\\'),{orders:[],nextCursor:null,productName:'50%_\\'});
 assert.equal(f.queries.some(([q])=>/^(INSERT|UPDATE|DELETE)/.test(q)),false);
});

test('merchant product-name validation is literal, trimmed, byte-bounded and cannot query invalid input',async()=>{
 const f=repositoryFixture();
 for(const name of ['%', '_', '\\', 'é'.repeat(64)])assert.equal((await f.repo.listMerchantOrders(target,42,undefined,' '+name+' ')).productName,name);
 for(const name of ['', '  ','owned\0name',null,12,[],{},'é'.repeat(65),'x'.repeat(129)]){
  const before=f.queries.length;assert.throws(()=>f.repo.listMerchantOrders(target,42,undefined,name),{code:'INVALID_ARGUMENT'});assert.equal(f.queries.length,before);
 }
 assert.equal(Object.hasOwn(await f.repo.listMerchantOrders(target,42),'productName'),false);
});

test('customer and merchant services capture normalized names before asynchronous authority checks without changing old calls',async()=>{
 const seen=[],repository=Object.fromEntries(['listCart','addCart','updateCart','removeCart','checkout','listOrders','getOrder'].map(k=>[k,async(...args)=>{seen.push([k,...args]);return []}]));
 repository.listMerchantOrders=async(...args)=>{seen.push(['merchant',...args]);return{orders:[],nextCursor:null}};
 const catalog={prepareTarget:async()=>target,hasProduct:async()=>true};
 const service=createSecureShopBoundCommerce({repository,catalog,resolveExistingTarget:async()=>target});
 const customer={scope,persona:{id:9,role:'customer'},productName:'  Purchased name  '};
 const pending=service.orders(customer);customer.productName='Substituted';await pending;
 const merchant={scope,persona:{id:42,role:'merchant'},productName:'  Purchased name  '};
 const second=service.merchantOrders(merchant);merchant.productName='Substituted';await second;
 assert.deepEqual(seen[0].slice(2),[9,'Purchased name']);assert.deepEqual(seen[1].slice(2),[42,undefined,'Purchased name']);
 await service.orders({scope,persona:{id:9,role:'customer'}});await service.merchantOrders({scope,persona:{id:42,role:'merchant'}});
 assert.equal(seen[2].length,3);assert.equal(seen[3].length,4);
 for(const productName of [null,' ','é'.repeat(65)]){
  await assert.rejects(service.orders({scope,persona:{id:9,role:'customer'},productName}),{code:'INVALID_ARGUMENT'});
  await assert.rejects(service.merchantOrders({scope,persona:{id:42,role:'merchant'},productName}),{code:'INVALID_ARGUMENT'});
 }
 assert.equal(seen.length,4);
});

test('direct customer order list uses owned item EXISTS and preserves full header totals',async()=>{
 const queries=[],client={async query(sql,args){queries.push([sql,args]);if(['BEGIN','COMMIT','ROLLBACK'].includes(sql))return{rows:[]};
  if(sql.includes('SELECT lifecycle'))return{rows:[{lifecycle:'active'}]};
  if(sql.startsWith('SELECT *'))return{rows:[{order_id:'12',shop_user_id:9,total_amount:'999.00',status:'pending'}]};throw Error('unexpected query');},release(){}};
 const repo=createSecureShopBoundCommerceRepository({query:async()=>{},connect:async()=>client},{checkCurrent:async()=>{}});
 assert.equal((await repo.listOrders(target,9,' Sold%_\\ '))[0].total_amount,999);
 const [sql,args]=queries.find(([q])=>q.startsWith('SELECT *'));
 assert.deepEqual(args,[target.targetId,9,'Sold%_\\']);assert.match(sql,/target_id=\$1 AND shop_user_id=\$2/);
 assert.match(sql,/oi.target_id=product_target_orders.target_id AND oi.order_id=product_target_orders.order_id/);
 assert.match(sql,/strpos\(lower\(oi.product_name\),lower\(\$3::text\)\) > 0/);
 assert.doesNotMatch(sql,/ILIKE|product_target_products|listing_overlays/);
 const before=queries.length;assert.throws(()=>repo.listOrders(target,9,null),{code:'INVALID_ARGUMENT'});assert.equal(queries.length,before);
});
