'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {randomUUID}=require('node:crypto');
const C=require('../server/services/secureshopConversationalCommerceContract');
const {createConversationalCommerceRepository}=require('../server/database/postgres/secureshopConversationalCommerceRepository');
const {createSceneBinding}=require('../server/services/secureshopSceneBinding');
const orderTime=value=>String(value).replace(/\.(\d{3})Z$/,(_,fraction)=>`.${fraction}000Z`);
function fixture({stringIds=false,failCompletion=false,failOperationInsert=false,failCommit=false,catalogTotal}={}){
 const scope={launchId:randomUUID(),scenarioId:randomUUID(),generation:1,platformOwnerId:1,platformSessionId:2};
 const target=createSceneBinding({...scope,targetId:randomUUID()},{sceneId:randomUUID(),sceneGeneration:1,grantId:randomUUID(),execution:scope,withLease:work=>work()});
 const auth={shopUserId:9,mode:'vuln',personaSession:{sessionId:randomUUID(),authorityVersion:'1'}};
 let state={choices:[],ops:[],methods:[],products:[{product_id:1,name:'Real named product',description:'data',description_html:null,price:'10.00',stock_quantity:10,status:'active',archived:false}],cart:[],addresses:[{address_id:1,label:null,line1:'123 Practice street',line2:null,city:null,state:null,zip:null,phone:null,is_default:true}],orders:[],orderItems:[],legacy:[]};
 const calls=[],queryArgs=[];
 const client={async query(sql,p=[]){calls.push(sql);queryArgs.push(p);let rows=[],rowCount;
  if(sql.startsWith('SELECT pg_advisory'))return {rows:[],rowCount:1};
  if(sql.startsWith('SELECT count(*)')){const rows=sql.includes('chat_commerce_operations')?state.ops:state.choices;return {rows:[{count:rows.length}],rowCount:1};}
  if(sql.startsWith('INSERT INTO secureshop_review.chat_commerce_choices')){state.choices.push({choice_id:p[0],target_id:p[1],shop_user_id:p[2],kind:p[3],context_json:p[4],snapshot_json:p[5],snapshot_sha256:p[6],state:'active'});return {rows:[],rowCount:1};}
  if(sql.startsWith('SELECT choice_id'))rows=state.choices.filter(r=>r.target_id===p[0]&&r.shop_user_id===p[1]&&r.kind===p[2]&&r.context_json===p[3]&&r.snapshot_sha256===p[4]&&r.snapshot_json===p[5]);
  else if(sql.startsWith('SELECT * FROM secureshop_review.chat_commerce_choices'))rows=state.choices.filter(r=>r.choice_id===p[0]);
  else if(sql.startsWith('INSERT INTO secureshop_review.chat_commerce_operations')){if(failOperationInsert)throw Object.assign(new Error('controlled insert failure'),{code:'RECEIPT_WRITE_FAILED'});state.ops.push({operation_id:p[0],target_id:p[1],shop_user_id:p[2],kind:p[3],context_json:p[4],request_json:p[5],intent_sha256:p[6],proposal_json:p[7],proposal_sha256:p[8],result_json:p[9],result_sha256:p[10],state:p[11]});return {rows:[],rowCount:1};}
  else if(sql.startsWith('UPDATE secureshop_review.chat_commerce_operations')){if(failCompletion)throw Object.assign(new Error('controlled receipt failure'),{code:'RECEIPT_WRITE_FAILED'});const row=state.ops.find(r=>r.operation_id===p[0]&&r.state==='prepared');if(row){row.state='completed';row.result_json=p[1];row.result_sha256=p[2];}return {rows:[],rowCount:row?1:0};}
  else if(sql.startsWith('SELECT * FROM secureshop_review.chat_commerce_operations'))rows=sql.includes('request_json::jsonb')?state.ops.filter(r=>r.target_id===p[0]&&r.shop_user_id===p[1]&&r.context_json===p[2]&&JSON.parse(r.request_json).origin?.turnSessionId===p[3]&&JSON.parse(r.request_json).origin?.turnRequestId===p[4]):state.ops.filter(r=>r.operation_id===p[0]&&(p.length<3||(r.target_id===p[1]&&r.shop_user_id===p[2])));
  else if(sql.startsWith('INSERT INTO secureshop_review.practice_payment_methods')){const row={method_id:p[0],target_id:p[1],shop_user_id:p[2],scenario:p[3]};state.methods.push(row);rows=[{method_id:row.method_id,scenario:row.scenario}];}
  else if(sql.startsWith('SELECT method_id,scenario'))rows=state.methods.filter(r=>r.target_id===p[0]&&r.shop_user_id===p[1]&&(p[2]===r.scenario||p[2]===r.method_id)).map(({method_id,scenario})=>({method_id,scenario}));
  else if(sql.startsWith('SELECT address_id,label'))rows=state.addresses.filter(r=>r.address_id===p[2]);
  else if(sql.startsWith('SELECT address_id FROM'))rows=state.addresses.map(r=>({address_id:r.address_id}));
  else if(sql.startsWith('SELECT order_id,total_amount')){
   const hasCursor=sql.includes('(order_date,order_id) <'),hasFilter=sql.includes('AND EXISTS');
   const candidates=state.orders.filter(r=>r.shop_user_id===p[1]&&(r.target_id===undefined||r.target_id===p[0])
    &&(!hasFilter||state.orderItems.some(item=>item.target_id===p[0]&&item.order_id===r.order_id
     &&item.product_name.toLowerCase().includes(p[hasCursor?4:2].toLowerCase()))));
   rows=(sql.includes('LIMIT 13')
    ?candidates.filter(r=>!hasCursor||orderTime(r.order_date)<orderTime(p[2])
      ||orderTime(r.order_date)===orderTime(p[2])&&Number(r.order_id)<Number(p[3]))
      .sort((a,b)=>orderTime(a.order_date)<orderTime(b.order_date)?1
       :orderTime(a.order_date)>orderTime(b.order_date)?-1:Number(b.order_id)-Number(a.order_id)).slice(0,13)
    :candidates.filter(r=>r.order_id===p[2]))
    .map(({order_id,total_amount,status,payment_status,order_date})=>({order_id,total_amount,status,payment_status,order_date}));
  }
  else if(sql.startsWith('SELECT shipping_address'))rows=state.orders.filter(r=>r.shop_user_id===p[1]&&r.order_id===p[2]).map(({shipping_address})=>({shipping_address}));
  else if(sql.startsWith('SELECT product_id,product_name'))rows=[];
  else if(sql.startsWith('SELECT operation_id FROM secureshop_review.bound_commerce_operations'))rows=state.legacy.filter(row=>row.operation_id===p[0]);
  else if(sql.startsWith('SELECT product_id FROM'))rows=state.products.filter(r=>p[1].includes(r.product_id)).map(r=>({product_id:r.product_id}));
  else if(sql.includes('(o.product_id IS NOT NULL) AS overlay'))rows=state.products.filter(r=>p[1].includes(r.product_id)).map(r=>({...r,retailer_id:7,overlay:false}));
  else if(sql.startsWith('WITH catalog_matches AS')){
   const matches=state.products.filter(r=>(r.target_id===undefined||r.target_id===p[0])&&r.status==='active'&&!r.archived&&r.name.toLowerCase().includes(String(p[1]).slice(1,-1).toLowerCase()));
   const page=matches.filter(r=>p[2]===null||Number(r.product_id)>p[2]).sort((a,b)=>Number(a.product_id)-Number(b.product_id)).slice(0,13);
   rows=page.length?page.map(row=>(({target_id,...product})=>({...product,matched_total:catalogTotal??matches.length}))(row)):[{product_id:null,matched_total:catalogTotal??matches.length}];
  }
  else if(sql.startsWith('SELECT p.product_id,'))rows=state.products.filter(r=>Array.isArray(p[1])?p[1].includes(r.product_id):typeof p[1]==='number'?r.product_id===p[1]:r.name.includes(String(p[1]).replaceAll('%','')));
  else if(sql.startsWith('SELECT quantity FROM'))rows=state.cart.filter(r=>r.product_id===p[2]).map(r=>({quantity:r.quantity}));
  else if(sql.startsWith('SELECT c.cart_item_id'))rows=state.cart.filter(r=>r.cart_item_id===p[2]).map(r=>({cart_item_id:r.cart_item_id,product_id:r.product_id,quantity:r.quantity,name:'Real named product',price:'10.00'}));
  else throw Error('Unexpected controlled query: '+sql.slice(0,90));
  const copied=structuredClone(rows);if(stringIds)for(const row of copied)for(const key of ['address_id','cart_item_id','order_id'])if(row[key]!==undefined)row[key]=String(row[key]);
  return {rows:copied,rowCount:rowCount??rows.length};
 }};
 const domain=createConversationalCommerceRepository({guarded:async(_target,work)=>{const before=structuredClone(state);try{const answer=await work(client,target);if(failCommit&&state.ops.length>before.ops.length)throw Object.assign(new Error('controlled commit failure'),{code:'COMMIT_FAILED'});return answer;}catch(error){state=before;throw error;}},durableCheckout:true,
  listCartWithClient:async()=>({items:state.cart.map(r=>({id:r.cart_item_id,product_id:r.product_id,quantity:r.quantity,name:'Real named product',price:10})),subtotal:state.cart.reduce((s,r)=>s+r.quantity*10,0),discount:0,total:state.cart.reduce((s,r)=>s+r.quantity*10,0),coupon:null}),
  addCartWithClient:async(_c,_t,_o,id,qty)=>{let row=state.cart.find(r=>r.product_id===id);if(row)row.quantity+=qty;else{row={cart_item_id:1,product_id:id,quantity:qty};state.cart.push(row);}return {id:row.cart_item_id};},
  updateCartWithClient:async(_c,_t,_o,id,qty)=>{state.cart.find(r=>r.cart_item_id===id).quantity=qty;return 1;},
  removeCartWithClient:async(_c,_t,_o,id)=>{state.cart=state.cart.filter(r=>r.cart_item_id!==id);return 1;},
  checkoutWithClient:async(_c,_t,_o,_s,_p,id)=>{const total=state.cart.reduce((s,r)=>s+r.quantity*10,0);state.orders.push({id,order_id:1,shop_user_id:9,shipping_address:_s,payment_method:'PRIVATE_PAYMENT_SENTINEL',total_amount:String(total),status:'pending',payment_status:'completed',order_date:'2026-10-10T00:00:00.000Z'});state.products[0].stock_quantity-=state.cart[0].quantity;state.cart=[];return {orderId:1,total,subtotal:total,discount:0};},
 });
 return {domain,target,auth,calls,queryArgs,state:()=>state};
}
async function product(f){return (await f.domain.search(f.target,{...f.auth,search:'Real'})).cards[0];}
async function commitCart(f,args){const proposal=await f.domain.prepareCart(f.target,args);return f.domain.confirmCart(f.target,{...f.auth,proposalId:proposal.proposalId});}
async function setup(f,scenario='approved'){const selected=await product(f);await commitCart(f,{...f.auth,operationId:randomUUID(),action:'add',choiceId:selected.choiceId,quantity:2});const address=(await f.domain.addresses(f.target,f.auth)).cards[0];const payment=(await f.domain.createPaymentMethod(f.target,{...f.auth,operationId:randomUUID(),scenario})).result.cards[0];return {operationId:randomUUID(),addressChoiceId:address.choiceId,paymentChoiceId:payment.choiceId};}
test('opaque selection mutation replays once and cross-kind/conflicting UUID does not mutate',async()=>{const f=fixture(),p=await product(f),id=randomUUID();const args={...f.auth,operationId:id,action:'add',choiceId:p.choiceId,quantity:2};const saved=await commitCart(f,args);assert.equal(f.state().cart[0].quantity,2);assert.deepEqual(await commitCart(f,args),{...saved,replayed:true});assert.equal(f.state().cart[0].quantity,2);await assert.rejects(f.domain.prepareCart(f.target,{...args,quantity:3}),{code:'COMMERCE_OPERATION_CONFLICT'});await assert.rejects(f.domain.createPaymentMethod(f.target,{...f.auth,operationId:id,scenario:'approved'}),{code:'COMMERCE_OPERATION_CONFLICT'});assert.equal(f.state().methods.length,0);});
test('issued cart cards carry the current database quantity as a bounded numeric field',async()=>{const f=fixture();await setup(f);const item=(await f.domain.cartView(f.target,f.auth)).cards[0];assert.deepEqual(Object.keys(item).sort(),['choiceId','detail','kind','quantity','title','version'].sort());assert.equal(item.kind,'cart_item');assert.equal(item.quantity,2);});
test('changed cart quantity stales its old choice and a fresh card exposes the new snapshot without a write',async()=>{const f=fixture();await setup(f);const old=(await f.domain.cartView(f.target,f.auth)).cards[0],beforeOps=f.state().ops.length;f.state().cart[0].quantity=3;await assert.rejects(f.domain.prepareCart(f.target,{...f.auth,operationId:randomUUID(),action:'update',choiceId:old.choiceId,quantity:3}),{code:'COMMERCE_CHOICE_STALE'});const fresh=(await f.domain.cartView(f.target,f.auth)).cards[0];assert.equal(fresh.quantity,3);assert.notEqual(fresh.choiceId,old.choiceId);assert.equal(f.state().cart[0].quantity,3);assert.equal(f.state().ops.length,beforeOps);});
test('choice rejects different session, role capability forgery and changed product before effect',async()=>{const f=fixture(),p=await product(f);await assert.rejects(f.domain.prepareCart(f.target,{...f.auth,personaSession:{sessionId:randomUUID(),authorityVersion:'1'},operationId:randomUUID(),action:'add',choiceId:p.choiceId,quantity:1}),{code:'COMMERCE_CHOICE_DENIED'});assert.throws(()=>f.domain.search({...f.target},{...f.auth,search:'Real'}),{code:'SHOP_SCENE_STALE'});f.state().products[0].price='11.00';await assert.rejects(f.domain.prepareCart(f.target,{...f.auth,operationId:randomUUID(),action:'add',choiceId:p.choiceId,quantity:1}),{code:'COMMERCE_CHOICE_STALE'});assert.equal(f.state().cart.length,0);});
test('unlabelled address is selectable and checkout approval/order result replays exactly once',async()=>{const f=fixture(),args=await setup(f),proposal=await f.domain.prepareCheckout(f.target,{...f.auth,...args});assert.equal(proposal.address.title,'Saved address');assert.equal(proposal.totalCents,2000);assert.equal(proposal.currency,'USD');assert.ok(!JSON.stringify(proposal).includes('123 Practice street'));const result=await f.domain.confirmCheckout(f.target,{...f.auth,proposalId:proposal.proposalId});assert.equal(result.status,'approved');assert.equal(f.state().orders.length,1);assert.equal(f.state().products[0].stock_quantity,8);assert.deepEqual(await f.domain.confirmCheckout(f.target,{...f.auth,proposalId:proposal.proposalId}),{...result,replayed:true});assert.equal(f.state().orders.length,1);assert.deepEqual((await f.domain.readOperation(f.target,{...f.auth,operationId:proposal.proposalId})).receipt,Object.fromEntries(Object.entries({...result,replayed:true}).filter(([key])=>key!=='scopeKey')));});
test('decline persists once without order, stock or cart effect; stale cart requires new consent',async()=>{const f=fixture(),args=await setup(f,'declined'),p=await f.domain.prepareCheckout(f.target,{...f.auth,...args});const result=await f.domain.confirmCheckout(f.target,{...f.auth,proposalId:p.proposalId});assert.equal(result.status,'declined');assert.equal(f.state().orders.length,0);assert.equal(f.state().products[0].stock_quantity,10);assert.equal(f.state().cart[0].quantity,2);assert.equal((await f.domain.confirmCheckout(f.target,{...f.auth,proposalId:p.proposalId})).replayed,true);const g=fixture(),a=await setup(g),q=await g.domain.prepareCheckout(g.target,{...g.auth,...a});g.state().cart[0].quantity=3;assert.equal((await g.domain.confirmCheckout(g.target,{...g.auth,proposalId:q.proposalId})).status,'stale');assert.equal(g.state().orders.length,0);assert.equal(g.state().cart[0].quantity,3);});
test('same-store originating turn recovers effect after missing graph final without redispatch',async()=>{const f=fixture(),p=await product(f),origin={turnSessionId:randomUUID(),turnRequestId:randomUUID(),toolKey:'cart.add',invocationStep:1,callId:'selected-call'};const operationId=C.operationIdForOrigin(origin);await commitCart(f,{...f.auth,operationId,origin,action:'add',choiceId:p.choiceId,quantity:1});const result=await f.domain.readTurnOperations(f.target,{...f.auth,sessionId:origin.turnSessionId,requestId:origin.turnRequestId});assert.equal(result.operations.length,1);assert.equal(result.operations[0].operationId,operationId);assert.equal(result.operations[0].receipt.replayed,true);assert.equal(f.state().cart[0].quantity,1);await assert.rejects(async()=>f.domain.prepareCart(f.target,{...f.auth,operationId:randomUUID(),origin,action:'add',choiceId:p.choiceId,quantity:1}),{code:'COMMERCE_OPERATION_CONFLICT'});});
test('operation read hides foreign owner IDs but rejects stale context on an owned row',async()=>{
 const f=fixture(),p=await product(f),id=randomUUID();
 await f.domain.prepareCart(f.target,{...f.auth,operationId:id,action:'add',choiceId:p.choiceId,quantity:1});
 const absent=await f.domain.readOperation(f.target,{...f.auth,operationId:randomUUID()});
 const foreign=await f.domain.readOperation(f.target,{...f.auth,shopUserId:f.auth.shopUserId+1,operationId:id});
 assert.equal(foreign.status,'not_found');assert.deepEqual(Object.keys(foreign),Object.keys(absent));
 await assert.rejects(f.domain.readOperation(f.target,{...f.auth,
  personaSession:{sessionId:randomUUID(),authorityVersion:'1'},operationId:id}),{code:'COMMERCE_OPERATION_CONFLICT'});
 assert.equal((await f.domain.readOperation(f.target,{...f.auth,operationId:id})).status,'prepared');
});
test('closed payment and confirmation contracts reject arbitrary card credentials and forged quote rows',()=>{assert.throws(()=>C.practice({operationId:randomUUID(),scenario:'approved',pan:'practice'}));assert.throws(()=>C.practice({operationId:randomUUID(),scenario:'unknown'}));assert.throws(()=>C.confirm({proposalId:randomUUID(),payment_method:'unknown'}));assert.throws(()=>C.confirmation({version:1,operationId:randomUUID(),kind:'checkout.confirm',status:'declined',currency:'USD',totalCents:100,order:{orderId:1},replayed:false}));});
test('payment GET binds both saved scenarios without changing historical receipts or consulting display text',async()=>{
 for(const scenario of ['approved','declined'])for(const historical of [false,true]){
  const f=fixture(),operationId=randomUUID();
  await f.domain.createPaymentMethod(f.target,{...f.auth,operationId,scenario});
  const row=f.state().ops[0];
  if(historical){const request=JSON.parse(row.request_json);delete request.origin;row.request_json=JSON.stringify(request);row.intent_sha256=C.digest(row.request_json);}
  const original=JSON.parse(row.result_json);original.result.cards[0].title='Unrelated historical display title';
  row.result_json=JSON.stringify(original);row.result_sha256=C.digest(row.result_json);
  const before=structuredClone(f.state()),queryStart=f.calls.length;
  const saved=await f.domain.readOperation(f.target,{...f.auth,operationId});
  assert.equal(saved.paymentScenario,scenario);assert.notEqual(saved.paymentScenario,scenario==='approved'?'declined':'approved');
  assert.deepEqual(saved.receipt,{...original,replayed:true});assert.deepEqual(f.state(),before);
  assert.equal(f.calls.slice(queryStart).some(sql=>sql.includes('practice_payment_methods')),false);
  const foreign=await f.domain.readOperation(f.target,{...f.auth,shopUserId:10,operationId});assert.equal(foreign.status,'not_found');assert.equal(Object.hasOwn(foreign,'paymentScenario'),false);
 }
});
test('payment GET rejects tampered hashes and invalid saved intent instead of projecting a scenario',async()=>{
 for(const change of ['hash','scenario','operation','extra','origin','state']){
  const f=fixture(),operationId=randomUUID();await f.domain.createPaymentMethod(f.target,{...f.auth,operationId,scenario:'approved'});
  const row=f.state().ops[0],request=JSON.parse(row.request_json);
  if(change==='hash')request.scenario='declined';
  if(change==='scenario')request.scenario='unknown';
  if(change==='operation')request.operationId=randomUUID();
  if(change==='extra')request.extra=true;
  if(change==='origin')request.origin={turnSessionId:randomUUID(),turnRequestId:randomUUID(),toolKey:'payment.create',invocationStep:1,callId:'historic'};
  if(change==='state')row.state='prepared';
  row.request_json=JSON.stringify(request);if(change!=='hash')row.intent_sha256=C.digest(row.request_json);
  await assert.rejects(f.domain.readOperation(f.target,{...f.auth,operationId}),{code:'COMMERCE_STATE_INVALID'});
 }
});
test('historical model-origin payment GET preserves receipt while nonpayment projections stay unchanged',async()=>{
 const f=fixture(),origin={turnSessionId:randomUUID(),turnRequestId:randomUUID(),toolKey:'payment.create',invocationStep:1,callId:'historic-payment'},operationId=C.operationIdForOrigin(origin);
 await f.domain.createPaymentMethod(f.target,{...f.auth,operationId,scenario:'declined',origin});
 assert.equal((await f.domain.readOperation(f.target,{...f.auth,operationId})).paymentScenario,'declined');
 const turn=await f.domain.readTurnOperations(f.target,{...f.auth,sessionId:origin.turnSessionId,requestId:origin.turnRequestId});assert.equal(Object.hasOwn(turn.operations[0],'paymentScenario'),false);
 const p=await product(f),proposal=await f.domain.prepareCart(f.target,{...f.auth,operationId:randomUUID(),action:'add',choiceId:p.choiceId,quantity:1});
 assert.equal(Object.hasOwn(await f.domain.readOperation(f.target,{...f.auth,operationId:proposal.proposalId}),'paymentScenario'),false);
});
test('proposal admission capacity failure creates no cart effect',async()=>{const f=fixture(),p=await product(f);const id=randomUUID();const original=f.domain;f.state().ops=Array.from({length:256},()=>({operation_id:randomUUID()}));await assert.rejects(original.prepareCart(f.target,{...f.auth,operationId:id,action:'add',choiceId:p.choiceId,quantity:2}),{code:'COMMERCE_OPERATION_CAPACITY'});assert.equal(f.state().cart.length,0);assert.equal(f.state().ops.length,256);});
test('changed address or payment choice cannot be substituted into an already prepared proposal',async()=>{const f=fixture(),args=await setup(f),p=await f.domain.prepareCheckout(f.target,{...f.auth,...args});f.state().addresses[0].line1='Different place';const receipt=await f.domain.confirmCheckout(f.target,{...f.auth,proposalId:p.proposalId});assert.equal(receipt.status,'stale');assert.equal(f.state().cart[0].quantity,2);assert.equal(f.state().orders.length,0);assert.equal((await f.domain.prepareCheckout(f.target,{...f.auth,...args})).quoteSha256,p.quoteSha256);});

test('first chat confirmation never adopts an equal-total matching prior legacy order',async()=>{const f=fixture(),args=await setup(f),p=await f.domain.prepareCheckout(f.target,{...f.auth,...args});f.state().legacy.push({operation_id:p.proposalId,state:'completed',result:{orderId:99,total:20,subtotal:20,discount:0}});const before=structuredClone(f.state());await assert.rejects(f.domain.confirmCheckout(f.target,{...f.auth,proposalId:p.proposalId}),{code:'COMMERCE_OPERATION_CONFLICT'});assert.deepEqual(f.state(),before);assert.equal((await f.domain.readOperation(f.target,{...f.auth,operationId:p.proposalId})).status,'prepared');});


test('PostgreSQL bigint string IDs preserve cart choices, address quote and order recovery',async()=>{
 const f=fixture({stringIds:true}),args=await setup(f);
 const item=(await f.domain.cartView(f.target,f.auth)).cards[0];
 await commitCart(f,{...f.auth,operationId:randomUUID(),action:'update',choiceId:item.choiceId,quantity:3});
 const proposal=await f.domain.prepareCheckout(f.target,{...f.auth,...args});assert.equal(proposal.totalCents,3000);
 const result=await f.domain.confirmCheckout(f.target,{...f.auth,proposalId:proposal.proposalId});assert.equal(result.status,'approved');
 assert.deepEqual(await f.domain.confirmCheckout(f.target,{...f.auth,proposalId:proposal.proposalId}),{...result,replayed:true});
 const order=(await f.domain.ordersList(f.target,f.auth)).cards[0];
 assert.equal((await f.domain.orderDetails(f.target,{...f.auth,choiceId:order.choiceId})).order.order_id,'1');
 const g=fixture({stringIds:true});await setup(g);const removable=(await g.domain.cartView(g.target,g.auth)).cards[0];
 await commitCart(g,{...g.auth,operationId:randomUUID(),action:'remove',choiceId:removable.choiceId});assert.equal(g.state().cart.length,0);
});

test('database ID normalization rejects noncanonical or out-of-range strings without client coercion',async()=>{
 for(const id of ['01','1e0',' 1','2147483648','9007199254740993']){const f=fixture();f.state().addresses[0].address_id=id;await assert.rejects(f.domain.addresses(f.target,f.auth),{code:'COMMERCE_STATE_INVALID'});assert.equal(f.state().choices.length,0);}
 assert.throws(()=>C.mutation({operationId:randomUUID(),action:'add',choiceId:randomUUID(),quantity:'1'}),{code:'INVALID_ARGUMENT'});
});

test('cart tools prepare exact intent without effect; confirmation revalidates and recovers once',async()=>{
 const f=fixture(),p=await product(f),id=randomUUID(),args={...f.auth,operationId:id,action:'add',choiceId:p.choiceId,quantity:2};
 const proposal=await f.domain.prepareCart(f.target,args);assert.equal(proposal.kind,'cart.add');assert.equal(proposal.quantity,2);assert.equal(f.state().cart.length,0);
 assert.deepEqual(await f.domain.prepareCart(f.target,args),proposal);assert.equal((await f.domain.readOperation(f.target,{...f.auth,operationId:id})).status,'prepared');
 await assert.rejects(f.domain.confirmCart(f.target,{...f.auth,personaSession:{sessionId:randomUUID(),authorityVersion:'1'},proposalId:id}),{code:'COMMERCE_OPERATION_CONFLICT'});assert.equal(f.state().cart.length,0);
 const receipt=await f.domain.confirmCart(f.target,{...f.auth,proposalId:id});assert.equal(receipt.status,'completed');assert.equal(f.state().cart[0].quantity,2);
 assert.deepEqual(await f.domain.confirmCart(f.target,{...f.auth,proposalId:id}),{...receipt,replayed:true});assert.equal(f.state().cart[0].quantity,2);
 const recovered=await f.domain.readOperation(f.target,{...f.auth,operationId:id});assert.deepEqual(recovered.proposal,Object.fromEntries(Object.entries(proposal).filter(([key])=>key!=='scopeKey')));assert.equal(recovered.receipt.replayed,true);
});
test('changed cart or product makes prepared cart intent stale without another effect',async()=>{
 for(const change of ['cart','product']){const f=fixture(),p=await product(f),args={...f.auth,operationId:randomUUID(),action:'add',choiceId:p.choiceId,quantity:2},proposal=await f.domain.prepareCart(f.target,args);
 if(change==='cart')f.state().cart.push({cart_item_id:1,product_id:1,quantity:1});else f.state().products[0].price='11.00';
 const before=structuredClone(f.state().cart),receipt=await f.domain.confirmCart(f.target,{...f.auth,proposalId:proposal.proposalId});assert.equal(receipt.status,'stale');assert.equal(receipt.result,null);assert.deepEqual(f.state().cart,before);assert.deepEqual(await f.domain.confirmCart(f.target,{...f.auth,proposalId:proposal.proposalId}),{...receipt,replayed:true});
 }
});

test('cart confirmation receipt failure rolls back worker effect and retains exact prepared intent',async()=>{
 const f=fixture({failCompletion:true}),p=await product(f),proposal=await f.domain.prepareCart(f.target,{...f.auth,operationId:randomUUID(),action:'add',choiceId:p.choiceId,quantity:2}),before=structuredClone(f.state());
 await assert.rejects(f.domain.confirmCart(f.target,{...f.auth,proposalId:proposal.proposalId}),{code:'RECEIPT_WRITE_FAILED'});assert.deepEqual(f.state(),before);assert.equal((await f.domain.readOperation(f.target,{...f.auth,operationId:proposal.proposalId})).status,'prepared');
});

test('selected owned order details expose immutable saved shipping address without payment data',async()=>{
 const f=fixture({stringIds:true});Object.assign(f.state().addresses[0],{label:'Practice destination',line2:'Unit 7',city:'Practice town',state:'CA',zip:'00000'});const args=await setup(f),proposal=await f.domain.prepareCheckout(f.target,{...f.auth,...args});await f.domain.confirmCheckout(f.target,{...f.auth,proposalId:proposal.proposalId});
 const listed=await f.domain.ordersList(f.target,f.auth),card=listed.cards[0],choiceSnapshot=f.state().choices.find(row=>row.choice_id===card.choiceId).snapshot_json;
 assert.ok(!JSON.stringify(listed).includes('123 Practice street'));assert.ok(!choiceSnapshot.includes('shipping_address'));
 f.state().addresses[0].line1='Current address changed';
 const request={...f.auth,choiceId:card.choiceId},detail=await f.domain.orderDetails(f.target,request);assert.equal(detail.order.shipping_address,'Practice destination\n123 Practice street\nUnit 7\nPractice town\nCA\n00000');assert.ok(!JSON.stringify(detail).includes('PRIVATE_PAYMENT_SENTINEL'));assert.equal(Object.hasOwn(detail.order,'payment_method'),false);
 assert.deepEqual(await f.domain.orderDetails(f.target,request),detail);assert.equal(f.state().choices.find(row=>row.choice_id===card.choiceId).snapshot_json,choiceSnapshot);
 const queries=f.calls.filter(sql=>sql.startsWith('SELECT shipping_address')).length;
 await assert.rejects(f.domain.orderDetails(f.target,{...request,choiceId:randomUUID()}),{code:'COMMERCE_CHOICE_DENIED'});
 await assert.rejects(f.domain.orderDetails(f.target,{...request,shopUserId:10}),{code:'COMMERCE_CHOICE_DENIED'});
 await assert.rejects(f.domain.orderDetails(f.target,{...request,personaSession:{sessionId:randomUUID(),authorityVersion:'1'}}),{code:'COMMERCE_CHOICE_DENIED'});
 assert.equal(f.calls.filter(sql=>sql.startsWith('SELECT shipping_address')).length,queries);
});

test('older order pages use an owned opaque cursor and stable timestamp/id keyset',async()=>{
 const f=fixture({stringIds:true}),when='2026-10-10T12:00:00.000Z';
 for(let id=1;id<=15;id++)f.state().orders.push({order_id:id,shop_user_id:9,shipping_address:'Owned practice address',total_amount:'10.00',status:'pending',payment_status:'completed',order_date:when});
 f.state().orders.push({order_id:99,shop_user_id:10,total_amount:'99.00',status:'private',payment_status:'private',order_date:when});
 const first=await f.domain.ordersList(f.target,f.auth);
 assert.deepEqual(first.orders.map(row=>Number(row.order_id)),[15,14,13,12,11,10,9,8,7,6,5,4]);
 assert.equal(first.cards.length,12);assert.equal(first.nextCursor,first.cards.at(-1).choiceId);
 const id=first.nextCursor;
 f.state().orders.push({order_id:16,shop_user_id:9,total_amount:'10.00',status:'pending',payment_status:'completed',order_date:when});
 const older=await f.domain.ordersList(f.target,{...f.auth,cursor:id});
 assert.deepEqual(older.orders.map(row=>Number(row.order_id)),[3,2,1]);
 assert.equal(older.nextCursor,null);assert.equal(older.cards.length,3);
 assert.equal((await f.domain.orderDetails(f.target,{...f.auth,choiceId:older.cards[0].choiceId})).order.order_id,'3');
 const before=f.state().choices.length;
 await assert.rejects(f.domain.ordersList(f.target,{...f.auth,cursor:randomUUID()}),{code:'COMMERCE_CHOICE_DENIED'});
 assert.throws(()=>f.domain.ordersList(f.target,{...f.auth,cursor:id.slice(0,-1)+'x'}),{code:'INVALID_ARGUMENT'});
 for(const wrong of [{shopUserId:10},{personaSession:{sessionId:randomUUID(),authorityVersion:'1'}},{mode:'fixed'}])
  await assert.rejects(f.domain.ordersList(f.target,{...f.auth,...wrong,cursor:id}),{code:'COMMERCE_CHOICE_DENIED'});
 assert.equal(f.state().choices.length,before);
 f.state().orders.find(row=>row.order_id===4).status='shipped';
 await assert.rejects(f.domain.ordersList(f.target,{...f.auth,cursor:id}),{code:'COMMERCE_CHOICE_STALE'});
});

test('older order pages retain PostgreSQL microseconds across a page boundary',async()=>{
 const f=fixture({stringIds:true}),base='2026-10-10T12:00:00.';
 for(let id=1;id<=13;id++)f.state().orders.push({order_id:id,shop_user_id:9,
  total_amount:'10.00',status:'pending',payment_status:'completed',
  order_date:`${base}${String(id).padStart(6,'0')}Z`});
 const first=await f.domain.ordersList(f.target,f.auth);
 assert.deepEqual(first.orders.map(row=>Number(row.order_id)),[13,12,11,10,9,8,7,6,5,4,3,2]);
 assert.equal(first.nextCursor,first.cards.at(-1).choiceId);
 const older=await f.domain.ordersList(f.target,{...f.auth,cursor:first.nextCursor});
 assert.deepEqual(older.orders.map(row=>Number(row.order_id)),[1]);
 assert.equal(older.nextCursor,null);
});

test('locked stock shortage stores one exact terminal rejection, replaying unchanged after restock',async()=>{
 const f=fixture();f.state().products[0].stock_quantity=0;const p=await product(f);
 const origin={turnSessionId:randomUUID(),turnRequestId:randomUUID(),toolKey:'cart.add',invocationStep:1,callId:'requested-out-of-stock'};
 const operationId=C.operationIdForOrigin(origin),args={...f.auth,operationId,origin,action:'add',choiceId:p.choiceId,quantity:2};
 const before=structuredClone(f.state());f.calls.length=0;
 const result=await f.domain.prepareCart(f.target,args);
 assert.deepEqual(C.cartRejection(Object.fromEntries(Object.entries(result).filter(([key])=>key!=='scopeKey'))),
  {version:1,operationId,kind:'cart.add',status:'rejected',result:{code:'INSUFFICIENT_STOCK',choiceId:p.choiceId,quantity:2},replayed:false});
 assert.match(result.scopeKey,/^[a-f0-9]{64}$/);assert.equal(f.state().ops.length,1);
 const row=f.state().ops[0];assert.equal(row.state,'completed');assert.equal(row.proposal_json,null);assert.equal(row.proposal_sha256,null);
 assert.equal(row.intent_sha256,C.digest(row.request_json));assert.equal(row.result_sha256,C.digest(row.result_json));
 assert.deepEqual({...f.state(),ops:[]},before);
 const stockRead=f.calls.findIndex(sql=>sql.includes('(o.product_id IS NOT NULL) AS overlay'));
 const receiptInsert=f.calls.findIndex(sql=>sql.startsWith('INSERT INTO secureshop_review.chat_commerce_operations'));
 assert.ok(stockRead>=0&&receiptInsert>stockRead);
 const savedRow=structuredClone(row);f.state().products[0].stock_quantity=10;
 assert.deepEqual(await f.domain.prepareCart(f.target,args),{...result,replayed:true});assert.deepEqual(f.state().ops,[savedRow]);
 const read=await f.domain.readOperation(f.target,{...f.auth,operationId});
 assert.deepEqual(read,{scopeKey:result.scopeKey,operationId,status:'completed',receipt:{...JSON.parse(row.result_json),replayed:true}});
 const turn=await f.domain.readTurnOperations(f.target,{...f.auth,sessionId:origin.turnSessionId,requestId:origin.turnRequestId});
 assert.deepEqual(turn.operations,[{operationId,status:'completed',receipt:read.receipt}]);
 await assert.rejects(f.domain.prepareCart(f.target,{...args,quantity:1}),{code:'COMMERCE_OPERATION_CONFLICT'});
 await assert.rejects(f.domain.confirmCart(f.target,{...f.auth,proposalId:operationId}),{code:'COMMERCE_PROPOSAL_NOT_FOUND'});
 const foreign=await f.domain.readOperation(f.target,{...f.auth,shopUserId:10,operationId});assert.equal(foreign.status,'not_found');
 await assert.rejects(f.domain.readOperation(f.target,{...f.auth,personaSession:{...f.auth.personaSession,sessionId:randomUUID()},operationId}),{code:'COMMERCE_OPERATION_CONFLICT'});
 assert.equal(f.state().cart.length,0);assert.equal(f.state().orders.length,0);assert.equal(f.state().products[0].stock_quantity,10);
});

test('rejection persistence failures throw and leave no receipt or business mutation',async()=>{
 for(const options of [{failOperationInsert:true},{failCommit:true}]){
  const f=fixture(options);f.state().products[0].stock_quantity=0;const p=await product(f),before=structuredClone(f.state());
  await assert.rejects(f.domain.prepareCart(f.target,{...f.auth,operationId:randomUUID(),action:'add',choiceId:p.choiceId,quantity:1}),
   {code:options.failOperationInsert?'RECEIPT_WRITE_FAILED':'COMMIT_FAILED'});
  assert.deepEqual(f.state(),before);
 }
});

test('rejection readback checks result choice/quantity against the immutable request and origin',async()=>{
 for(const change of ['quantity','choice','origin']){
  const f=fixture();f.state().products[0].stock_quantity=0;const p=await product(f),operationId=randomUUID();
  await f.domain.prepareCart(f.target,{...f.auth,operationId,action:'add',choiceId:p.choiceId,quantity:1});
  const row=f.state().ops[0];
  if(change==='origin'){const request=JSON.parse(row.request_json);request.origin={turnSessionId:randomUUID(),turnRequestId:randomUUID(),toolKey:'cart.add',invocationStep:1,callId:'forged'};row.request_json=JSON.stringify(request);row.intent_sha256=C.digest(row.request_json);}
  else{const result=JSON.parse(row.result_json);if(change==='quantity')result.result.quantity=2;else result.result.choiceId=randomUUID();row.result_json=JSON.stringify(result);row.result_sha256=C.digest(row.result_json);}
  await assert.rejects(f.domain.readOperation(f.target,{...f.auth,operationId}),{code:'COMMERCE_STATE_INVALID'});
 }
});

test('historical completed cart receipt without proposal preserves operation-conflict replay behavior',async()=>{
 const f=fixture();f.state().products[0].stock_quantity=0;const p=await product(f),operationId=randomUUID();
 const args={...f.auth,operationId,action:'add',choiceId:p.choiceId,quantity:1};await f.domain.prepareCart(f.target,args);
 const row=f.state().ops[0];row.result_json=JSON.stringify({version:1,operationId,kind:'cart.add',status:'completed',result:{id:1},replayed:false});row.result_sha256=C.digest(row.result_json);
 await assert.rejects(f.domain.prepareCart(f.target,args),{code:'COMMERCE_OPERATION_CONFLICT'});
 assert.equal((await f.domain.readOperation(f.target,{...f.auth,operationId})).receipt.status,'completed');
});

test('named customer orders match literal purchased snapshots and retain full totals across owned tied-date pages',async()=>{
 const f=fixture({stringIds:true}),when='2026-10-10T12:00:00.123456Z',name='Historic 50%_\\ Product';
 const seed=(id,owner=9,targetId=f.target.targetId,soldName=name)=>{
  f.state().orders.push({target_id:targetId,order_id:id,shop_user_id:owner,total_amount:'999.00',status:'pending',payment_status:'completed',order_date:when});
  f.state().orderItems.push({target_id:targetId,order_id:id,product_name:soldName});
 };
 for(let id=1;id<=14;id++)seed(id);
 seed(50,10);seed(51,9,randomUUID());seed(52,9,f.target.targetId,'Historic 50xyz Product');
 f.state().orderItems.push({target_id:randomUUID(),order_id:52,product_name:name});
 f.state().products[0].name='Renamed current catalog product';
 const first=await f.domain.ordersList(f.target,{...f.auth,productName:'  historic 50%_\\  '});
 assert.equal(first.productName,'historic 50%_\\');assert.equal(first.orders.length,12);
 assert.deepEqual(first.orders.map(row=>Number(row.order_id)),[14,13,12,11,10,9,8,7,6,5,4,3]);
 assert.ok(first.orders.every(row=>row.total_amount==='999.00'));
 const index=f.calls.findIndex(sql=>sql.includes('LIMIT 13')),sql=f.calls[index];
 assert.match(sql,/oi.target_id=product_target_orders.target_id AND oi.order_id=product_target_orders.order_id/);
 assert.match(sql,/strpos\(lower\(oi.product_name\),lower\(\$3::text\)\)/);assert.doesNotMatch(sql,/ILIKE|listing_overlays|JOIN.*product_target_products/);
 assert.deepEqual(f.queryArgs[index],[f.target.targetId,9,'historic 50%_\\']);
 const next=await f.domain.ordersList(f.target,{...f.auth,cursor:first.nextCursor,productName:first.productName});
 assert.equal(next.productName,first.productName);assert.deepEqual(next.orders.map(row=>Number(row.order_id)),[2,1]);assert.equal(next.nextCursor,null);
 const tail=f.calls.findLastIndex(query=>query.includes('LIMIT 13'));
 assert.match(f.calls[tail],/lower\(\$5::text\)/);assert.deepEqual(f.queryArgs[tail],[f.target.targetId,9,when,3,first.productName]);
 assert.equal(f.state().ops.length,0);assert.equal(Object.hasOwn(await f.domain.ordersList(f.target,f.auth),'productName'),false);
});

test('customer product-name bounds are UTF8 after trimming; invalid names and extra fields never query',async()=>{
 const f=fixture(),accepted=['x'.repeat(128),'é'.repeat(64),'  '+('é'.repeat(64))+'  '];
 for(const productName of accepted)assert.equal((await f.domain.ordersList(f.target,{...f.auth,productName})).productName,productName.trim());
 for(const productName of ['', ' \t\n','owned\0name',null,1,[],{},'x'.repeat(129),'é'.repeat(65)]){
  const before=f.calls.length;assert.throws(()=>f.domain.ordersList(f.target,{...f.auth,productName}),{code:'INVALID_ARGUMENT'});assert.equal(f.calls.length,before);
 }
 assert.throws(()=>f.domain.ordersList(f.target,{...f.auth,productName:'owned',extra:true}),{code:'INVALID_ARGUMENT'});
});


test('catalog pages issue only visible choices and retain exact total beyond twelve products',async()=>{
 const f=fixture({stringIds:true}),base={...f.state().products[0]};
 f.state().products=Array.from({length:15},(_,i)=>({...base,product_id:i+1}));
 f.state().products.push({...base,product_id:16,status:'inactive'}, {...base,product_id:17,archived:true});
 const first=await f.domain.search(f.target,{...f.auth,search:'Real'});
 assert.equal(first.total,15);assert.deepEqual(first.products.map(row=>Number(row.product_id)),Array.from({length:12},(_,i)=>i+1));
 assert.equal(first.cards.length,12);assert.equal(f.state().choices.length,12);assert.equal(first.nextCursor,first.cards.at(-1).choiceId);
 const next=await f.domain.search(f.target,{...f.auth,search:'Real',cursor:first.nextCursor});
 assert.equal(next.total,15);assert.deepEqual(next.products.map(row=>Number(row.product_id)),[13,14,15]);
 assert.equal(next.nextCursor,null);assert.equal(f.state().choices.length,15);
 const empty=await f.domain.search(f.target,{...f.auth,search:'Real',cursor:next.cards.at(-1).choiceId});
 assert.equal(empty.total,15);assert.deepEqual(empty.products,[]);assert.deepEqual(empty.cards,[]);assert.equal(empty.nextCursor,null);
 const missing=await f.domain.search(f.target,{...f.auth,search:'absent'});
 assert.equal(missing.total,0);assert.deepEqual(missing.cards,[]);assert.equal(missing.nextCursor,null);
 assert.equal(f.state().ops.length,0);assert.equal(f.state().cart.length,0);
 const sql=f.calls.find(sql=>sql.startsWith('WITH catalog_matches AS'));
 assert.match(sql,/p.target_id=\$1/);assert.match(sql,/status END\)='active' AND o.archived_at IS NULL/);
 assert.match(sql,/SELECT count\(\*\)::integer FROM catalog_matches/);
 assert.match(sql,/product_id>\$3[\s\S]*ORDER BY product_id LIMIT 13/);
});

test('catalog continuation rejects foreign and stale choices before issuing another page',async()=>{
 const f=fixture(),base={...f.state().products[0]};
 f.state().products=Array.from({length:14},(_,i)=>({...base,product_id:i+1}));
 const page=await f.domain.search(f.target,{...f.auth,search:'Real'}),cursor=page.nextCursor;
 for(const wrong of [{shopUserId:10},{personaSession:{sessionId:randomUUID(),authorityVersion:'1'}},{mode:'fixed'}])
  await assert.rejects(f.domain.search(f.target,{...f.auth,...wrong,search:'Real',cursor}),{code:'COMMERCE_CHOICE_DENIED'});
 await assert.rejects(f.domain.search(f.target,{...f.auth,search:'Real',cursor:randomUUID()}),{code:'COMMERCE_CHOICE_DENIED'});
 assert.throws(()=>f.domain.search(f.target,{...f.auth,search:'Real',cursor:'not-a-choice'}),{code:'INVALID_ARGUMENT'});
 f.state().products.find(row=>row.product_id===12).price='11.00';
 await assert.rejects(f.domain.search(f.target,{...f.auth,search:'Real',cursor}),{code:'COMMERCE_CHOICE_STALE'});
 assert.equal(f.state().choices.length,12);assert.equal(f.state().ops.length,0);
});


test('catalog count overflow fails before publishing choices',async()=>{
 for(const catalogTotal of ['9007199254740992','not-a-count',-1]){
  const f=fixture({catalogTotal});
  await assert.rejects(f.domain.search(f.target,{...f.auth,search:'Real'}),{code:'COMMERCE_STATE_INVALID'});
  assert.equal(f.state().choices.length,0);assert.equal(f.state().ops.length,0);
 }
});
