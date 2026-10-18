'use strict';
const { randomUUID }=require('node:crypto');
const C=require('../../services/secureshopConversationalCommerceContract');
const Address=require('../../services/secureshopAddressSetupContract');
const Profile=require('../../services/secureshopProfileUpdateContract');
const {saveAddressWithClient,saveProfileWithClient,appendAccountAudit}=require('./secureshopBoundAccountRepository');
const { executionScope }=require('../../services/secureshopSceneBinding');
const Stock=require('./secureshopOwnedStock');
const {normalizeOrderProductName}=require('./secureshopBoundCommerceRepository');
const CART_STOCK_UNAVAILABLE=Symbol('locked cart stock unavailable');
const effective=`SELECT p.product_id,
 CASE WHEN o.product_id IS NULL THEN p.name ELSE o.name END AS name,
 CASE WHEN o.product_id IS NULL THEN p.description ELSE o.description END AS description,
 CASE WHEN o.product_id IS NULL THEN p.description_html ELSE o.description_html END AS description_html,
 CASE WHEN o.product_id IS NULL THEN p.price ELSE o.price END AS price,
 CASE WHEN o.product_id IS NULL THEN p.stock_quantity ELSE o.stock_quantity END AS stock_quantity,
 CASE WHEN o.product_id IS NULL THEN p.status ELSE o.status END AS status,
 (o.archived_at IS NOT NULL) AS archived
 FROM secureshop_review.product_target_products p
 LEFT JOIN secureshop_review.product_target_listing_overlays o ON o.target_id=p.target_id AND o.product_id=p.product_id`;
function createConversationalCommerceRepository({guarded,listCartWithClient,addCartWithClient,updateCartWithClient,removeCartWithClient,checkoutWithClient,durableCheckout,couponRepository,auditStore}){
 if([guarded,listCartWithClient,addCartWithClient,updateCartWithClient,removeCartWithClient,checkoutWithClient].some(fn=>typeof fn!=='function'))throw new TypeError('Commerce transaction workers required');
 function capture(target,args){
  if(!target?.scene)throw C.fail('SHOP_SCENE_STALE');
  const e=executionScope(target), owner=C.integer(args?.shopUserId), session=args?.personaSession;
  if(!session||typeof session.authorityVersion!=='string'||!/^[1-9]\d*$/.test(session.authorityVersion))throw C.fail('SHOP_AUTH_INVALID');
  if(!['vuln','fixed'].includes(args.mode))throw C.fail();
  const context={version:1,scope:{launchId:e.launchId,scenarioId:e.scenarioId,generation:e.generation,platformOwnerId:e.platformOwnerId,platformSessionId:e.platformSessionId},
   targetId:target.targetId,sceneId:target.scene.sceneId,sceneGeneration:target.scene.sceneGeneration,grantId:target.scene.grantId,
   shopUserId:owner,role:'customer',personaSession:{sessionId:C.uuid(session.sessionId),authorityVersion:session.authorityVersion},mode:args.mode};
  return Object.freeze({owner,mode:args.mode,credential:Object.freeze(context.personaSession),contextJson:JSON.stringify(context)});
 }
 const transaction=(target,args,work)=>{const a=capture(target,args);return guarded(target,async(client,value)=>{await lock(client,value.targetId,a.owner);return {...await work(client,value,a),scopeKey:C.digest(a.contextJson)};});};
 async function lock(client,target,owner){await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1::text,$2::bigint))',[target,owner]);}
 async function opLock(client,id){await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1::text,0))',['chat-commerce:'+id]);}
 function unpack(row,a,target,kind,request){
  if(!row||row.state==='redacted'||row.target_id!==target.targetId||Number(row.shop_user_id)!==a.owner||row.context_json!==a.contextJson
   ||(kind!==undefined&&row.kind!==kind)||(request!==undefined&&(row.request_json!==JSON.stringify(request)||row.intent_sha256!==C.digest(request))))throw C.fail('COMMERCE_OPERATION_CONFLICT');
  if(C.digest(row.request_json)!==row.intent_sha256)throw C.fail('COMMERCE_STATE_INVALID');
  if(row.proposal_json&&C.digest(row.proposal_json)!==row.proposal_sha256)throw C.fail('COMMERCE_STATE_INVALID');
  if(row.result_json&&C.digest(row.result_json)!==row.result_sha256)throw C.fail('COMMERCE_STATE_INVALID');
  return row;
 }
 async function prior(client,value,a,id,kind,request){await opLock(client,id);const row=(await client.query('SELECT * FROM secureshop_review.chat_commerce_operations WHERE operation_id=$1 FOR UPDATE',[id])).rows[0];return row?unpack(row,a,value,kind,request):null;}
 async function insert(client,value,a,id,kind,request,proposal,result){
  const count=Number((await client.query('SELECT count(*) AS count FROM secureshop_review.chat_commerce_operations WHERE target_id=$1 AND shop_user_id=$2',[value.targetId,a.owner])).rows[0].count);
  if(count>=256)throw C.fail('COMMERCE_OPERATION_CAPACITY');
  const requestJson=JSON.stringify(request),proposalJson=proposal?JSON.stringify(proposal):null,resultJson=result?JSON.stringify(result):null;
  await client.query(`INSERT INTO secureshop_review.chat_commerce_operations
   (operation_id,target_id,shop_user_id,kind,context_json,request_json,intent_sha256,proposal_json,proposal_sha256,result_json,result_sha256,state)
   VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,[id,value.targetId,a.owner,kind,a.contextJson,requestJson,C.digest(requestJson),proposalJson,proposalJson?C.digest(proposalJson):null,resultJson,resultJson?C.digest(resultJson):null,proposal&&!result?'prepared':'completed']);
 }
 async function complete(client,id,result){const json=JSON.stringify(result);const changed=await client.query("UPDATE secureshop_review.chat_commerce_operations SET state='completed',result_json=$2,result_sha256=$3 WHERE operation_id=$1 AND state='prepared'",[id,json,C.digest(json)]);if(changed.rowCount!==1)throw C.fail('COMMERCE_OPERATION_CONFLICT');}
 function withOrigin(args,intent,key){const origin=C.origin(args.origin);if(origin&&(origin.toolKey!==key||C.operationIdForOrigin(origin)!==intent.operationId))throw C.fail('COMMERCE_OPERATION_CONFLICT');return Object.freeze({...intent,origin});}
 // Project the selected scenario from the verified request, never its display card.
 // Historical receipts remain byte-for-byte unchanged, including origin-less requests.
 function paymentScenario(row){
  try{
   const request=JSON.parse(row.request_json);
   if(row.state!=='completed'||!C.exact(request,Object.hasOwn(request,'origin')?['operationId','scenario','origin']:['operationId','scenario']))throw C.fail();
   const intent=C.practice({operationId:request.operationId,scenario:request.scenario});
   if(intent.operationId!==row.operation_id)throw C.fail();
   if(request.origin!=null){const origin=C.origin(request.origin);if(origin.toolKey!=='payment.create'||C.operationIdForOrigin(origin)!==row.operation_id)throw C.fail();}
   return intent.scenario;
  }catch{throw C.fail('COMMERCE_STATE_INVALID');}
 }
 function receipt(id,kind,result){return Object.freeze({version:1,operationId:id,kind,status:'completed',result,replayed:false});}
 // PostgreSQL bigint IDs are returned as decimal strings. Normalize only
 // database-derived identifiers; public request codecs remain strict.
 function databaseId(value){
  if(typeof value==='string'){if(!/^[1-9]\d{0,9}$/.test(value))throw C.fail('COMMERCE_STATE_INVALID');value=Number(value);}
  try{return C.integer(value);}catch{throw C.fail('COMMERCE_STATE_INVALID');}
 }
 async function snapshot(client,value,a,kind,id){
  let row;
  if(kind==='product')row=(await client.query(effective+' WHERE p.target_id=$1 AND p.product_id=$2',[value.targetId,databaseId(id)])).rows[0];
  if(kind==='cart_item')row=(await client.query(`SELECT c.cart_item_id,c.product_id,c.quantity,
   CASE WHEN o.product_id IS NULL THEN p.name ELSE o.name END AS name,
   CASE WHEN o.product_id IS NULL THEN p.price ELSE o.price END AS price
   FROM secureshop_review.product_target_cart_items c JOIN secureshop_review.product_target_products p ON p.target_id=c.target_id AND p.product_id=c.product_id
   LEFT JOIN secureshop_review.product_target_listing_overlays o ON o.target_id=p.target_id AND o.product_id=p.product_id
   WHERE c.target_id=$1 AND c.shop_user_id=$2 AND c.cart_item_id=$3`,[value.targetId,a.owner,databaseId(id)])).rows[0];
  if(kind==='order')row=(await client.query(`SELECT order_id,total_amount,status,payment_status,
   to_char(order_date AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS order_date
   FROM secureshop_review.product_target_orders WHERE target_id=$1 AND shop_user_id=$2 AND order_id=$3`,[value.targetId,a.owner,databaseId(id)])).rows[0];
  if(kind==='address')row=(await client.query('SELECT address_id,label,line1,line2,city,state,zip,phone,is_default FROM secureshop_review.product_target_addresses WHERE target_id=$1 AND shop_user_id=$2 AND address_id=$3',[value.targetId,a.owner,databaseId(id)])).rows[0];
  if(kind==='payment_method')row=(await client.query('SELECT method_id,scenario FROM secureshop_review.practice_payment_methods WHERE target_id=$1 AND shop_user_id=$2 AND method_id=$3',[value.targetId,a.owner,C.uuid(id)])).rows[0];
  if(!row||(kind==='product'&&(row.archived||row.status!=='active')))throw C.fail('COMMERCE_CHOICE_STALE');
  const normalized=JSON.parse(JSON.stringify(row));return kind==='product'?productSnapshot(normalized):normalized;
 }
 function boundedLabel(value,max=256){C.text(value,4096);let result='',bytes=0;for(const ch of value){const size=Buffer.byteLength(ch);if(bytes+size>max)break;result+=ch;bytes+=size;}return result;}
 function productSnapshot(row){const {description,description_html,...fields}=row;return {...fields,content_sha256:C.digest({description,description_html})};}
 function recordId(kind,row){return row[{product:'product_id',cart_item:'cart_item_id',order:'order_id',address:'address_id',payment_method:'method_id'}[kind]];}
 function display(kind,row){
  if(kind==='product')return [boundedLabel(row.name),`USD ${(C.money(row.price)/100).toFixed(2)} · ${row.stock_quantity} available`];
  if(kind==='cart_item')return [boundedLabel(row.name),`${row.quantity} in cart · USD ${(C.money(row.price)/100).toFixed(2)} each`];
  if(kind==='order')return [`Order #${row.order_id}`,`USD ${(C.money(row.total_amount)/100).toFixed(2)} · ${row.status} · ${row.payment_status}`];
  if(kind==='address')return [row.label?.trim()||'Saved address',[row.city,row.state].filter(value=>typeof value==='string'&&value.trim()).join(', ')||'Saved shipping address'];
  return [row.scenario==='approved'?'Practice card — approved':'Practice card — declined','Synthetic payment only · no real charge'];
 }
 async function issue(client,value,a,kind,row){
  const json=JSON.stringify(row),hash=C.digest(json);
  if(Buffer.byteLength(json)>65536)throw C.fail('COMMERCE_CHOICE_LIMIT');
  const existing=(await client.query("SELECT choice_id FROM secureshop_review.chat_commerce_choices WHERE target_id=$1 AND shop_user_id=$2 AND kind=$3 AND context_json=$4 AND snapshot_sha256=$5 AND snapshot_json=$6 AND state='active' ORDER BY created_at,choice_id LIMIT 1",[value.targetId,a.owner,kind,a.contextJson,hash,json])).rows[0];
  const id=existing?.choice_id||randomUUID();
  if(!existing){const count=Number((await client.query('SELECT count(*) AS count FROM secureshop_review.chat_commerce_choices WHERE target_id=$1 AND shop_user_id=$2',[value.targetId,a.owner])).rows[0].count);if(count>=512)throw C.fail('COMMERCE_CHOICE_CAPACITY');
   await client.query('INSERT INTO secureshop_review.chat_commerce_choices(choice_id,target_id,shop_user_id,kind,context_json,snapshot_json,snapshot_sha256) VALUES($1,$2,$3,$4,$5,$6,$7)',[id,value.targetId,a.owner,kind,a.contextJson,json,hash]);}
  return C.card(kind,id,...display(kind,row),kind==='cart_item'?C.integer(Number(row.quantity),1,99):undefined);
 }
 async function choice(client,value,a,id,kind){
  const row=(await client.query('SELECT * FROM secureshop_review.chat_commerce_choices WHERE choice_id=$1',[C.uuid(id)])).rows[0];
  if(!row||row.state!=='active'||row.target_id!==value.targetId||Number(row.shop_user_id)!==a.owner||row.context_json!==a.contextJson||(kind&&row.kind!==kind)||C.digest(row.snapshot_json)!==row.snapshot_sha256)throw C.fail('COMMERCE_CHOICE_DENIED');
  const saved=JSON.parse(row.snapshot_json),current=await snapshot(client,value,a,row.kind,recordId(row.kind,saved));
  if(C.digest(current)!==row.snapshot_sha256)throw C.fail('COMMERCE_CHOICE_STALE');
  return {kind:row.kind,row:current,card:C.card(row.kind,row.choice_id,...display(row.kind,current),
   row.kind==='cart_item'?C.integer(Number(current.quantity),1,99):undefined)};
 }
 async function cartIntentSnapshot(client,value,a,intent){
  const kind='cart.'+intent.action,selected=await choice(client,value,a,intent.choiceId,intent.action==='add'?'product':'cart_item');
  const cart=await listCartWithClient(client,value,a.owner,a.mode);
  const items=cart.items.map(row=>({cartItemId:databaseId(row.id),productId:databaseId(row.product_id),quantity:C.integer(row.quantity,1,99),unitPriceCents:C.money(row.price),nameSha256:C.digest(row.name)})).sort((left,right)=>left.cartItemId-right.cartItemId);
  if(intent.action==='add'){
   const stock=await Stock.lockStock(client,value.targetId,[databaseId(selected.row.product_id)]);
   const current=await snapshot(client,value,a,'product',selected.row.product_id);if(C.digest(current)!==C.digest(selected.row))throw C.fail('COMMERCE_CHOICE_STALE');
   const existing=items.find(row=>row.productId===databaseId(selected.row.product_id));if(stock[0].quantity<(existing?.quantity||0)+intent.quantity)return CART_STOCK_UNAVAILABLE;
  }
  return {version:1,kind,choice:selected.card,selection:selected.row,quantity:intent.action==='remove'?null:intent.quantity,items};
 }
 function publicCartProposal(id,q){return C.cartProposal({version:1,proposalId:id,status:'prepared',kind:q.kind,choice:q.choice,quantity:q.quantity,quoteSha256:C.digest(q)});}
 function savedCartRejection(row){
  try{
   const result=C.cartRejection(JSON.parse(row.result_json)),request=JSON.parse(row.request_json);
   if(row.state!=='completed'||row.kind!=='cart.add'||row.proposal_json!==null||row.proposal_sha256!==null
    ||!C.exact(request,Object.hasOwn(request,'origin')?['operationId','action','choiceId','quantity','origin']:['operationId','action','choiceId','quantity']))throw C.fail();
   const intent=C.mutation({operationId:request.operationId,action:request.action,choiceId:request.choiceId,quantity:request.quantity});
   if(intent.action!=='add'||intent.operationId!==row.operation_id||result.operationId!==row.operation_id
    ||result.result.choiceId!==intent.choiceId||result.result.quantity!==intent.quantity)throw C.fail();
   if(request.origin!=null){const origin=C.origin(request.origin);if(origin.toolKey!=='cart.add'||C.operationIdForOrigin(origin)!==row.operation_id)throw C.fail();}
   return {...result,replayed:true};
  }catch{throw C.fail('COMMERCE_STATE_INVALID');}
 }
 function savedOperationReceipt(row){const result=JSON.parse(row.result_json);return result.status==='rejected'
  ?savedCartRejection(row):{...result,replayed:true};}
 function operationProposal(row){const q=JSON.parse(row.proposal_json);return row.kind==='checkout'?publicProposal(row.operation_id,q):publicCartProposal(row.operation_id,q);}
 async function quote(client,value,a,addressId,paymentId){
  await lock(client,value.targetId,a.owner);
  const address=await choice(client,value,a,addressId,'address'),payment=await choice(client,value,a,paymentId,'payment_method');
  const cart=await listCartWithClient(client,value,a.owner,a.mode);
  if(!cart.items.length||cart.items.length>50)throw C.fail('CART_EMPTY');
  const stock=await Stock.lockStock(client,value.targetId,cart.items.map(row=>row.product_id));
  if(!Stock.stockAvailable(stock,cart.items.map(row=>({product_id:row.product_id,quantity:row.quantity}))))throw C.fail('INSUFFICIENT_STOCK');
  const items=cart.items.map(row=>({cartItemId:row.id,productId:row.product_id,name:boundedLabel(row.name),nameSha256:C.digest(row.name),quantity:C.integer(row.quantity,1,99),unitPriceCents:C.money(row.price),lineTotalCents:C.money(row.price)*row.quantity}));
  const money=require('../../services/secureshopCouponContract').money(items.map(row=>row.lineTotalCents),cart.coupon?.discount_percent||0);
  return {version:1,currency:'USD',items,stock:stock.map(row=>({productId:row.productId,quantity:row.quantity,status:row.status,archived:row.archived})),coupon:cart.coupon,
   subtotalCents:money.subtotalCents,discountCents:money.discountCents,totalCents:money.totalCents,
   address:{choiceId:addressId,snapshot:address.row,card:address.card},payment:{choiceId:paymentId,snapshot:payment.row,card:payment.card}};
 }
 function publicProposal(id,q){return C.proposal({version:1,proposalId:id,status:'prepared',currency:'USD',items:q.items.map(({cartItemId,nameSha256,...row})=>row),subtotalCents:q.subtotalCents,discountCents:q.discountCents,totalCents:q.totalCents,
  address:{choiceId:q.address.choiceId,title:q.address.card.title,detail:q.address.card.detail},paymentMethod:{choiceId:q.payment.choiceId,title:q.payment.card.title,detail:q.payment.card.detail},quoteSha256:C.digest(q)});}
 function addressFields(row){return {label:row.label,line1:row.line1,line2:row.line2,city:row.city,state:row.state,zip:row.zip,phone:row.phone,isDefault:row.is_default===true};}
 function addressVersion(row){
  const id=Number(row.address_id);C.integer(id,1,Number.MAX_SAFE_INTEGER);
  const updatedAt=row.updated_at instanceof Date?row.updated_at.toISOString():row.updated_at;
  if(typeof updatedAt!=='string'||!Number.isFinite(Date.parse(updatedAt)))throw C.fail('COMMERCE_STATE_INVALID');
  return {addressId:id,fields:Address.normalizeAddressFields(addressFields(row)),updatedAt};
 }
 async function addressState(client,value,a){
  const rows=(await client.query(`SELECT address_id,label,line1,line2,city,state,zip,phone,is_default,updated_at::text AS updated_at
   FROM secureshop_review.product_target_addresses WHERE target_id=$1 AND shop_user_id=$2 ORDER BY address_id FOR UPDATE`,[value.targetId,a.owner])).rows;
  if(rows.length>32)throw C.fail('COMMERCE_STATE_INVALID');
  const versions=rows.map(addressVersion);
  return {rows,versions,defaultSetSha256:C.digest(versions.map(row=>({addressId:row.addressId,isDefault:row.fields.isDefault,updatedAt:row.updatedAt})))};
 }
 function savedAddressReceipt(row){
  try{
   const request=JSON.parse(row.request_json),result=Address.addressReceipt(JSON.parse(row.result_json));
   if(!C.exact(request,['operationId','action','choiceId','expectedSnapshotSha256','defaultSetSha256','fieldsSha256'])
    ||request.operationId!==row.operation_id||result.operationId!==row.operation_id||result.kind!==row.kind
    ||row.kind!=='address.'+request.action||row.state!=='completed'||result.result.fieldsSha256!==request.fieldsSha256
    ||!(/^[a-f0-9]{64}$/).test(request.fieldsSha256)||!(/^[a-f0-9]{64}$/).test(request.defaultSetSha256))throw C.fail();
   Address.addressFormRequest({action:request.action,choiceId:request.choiceId});
   if(request.action==='create'?request.expectedSnapshotSha256!==null:!(/^[a-f0-9]{64}$/).test(request.expectedSnapshotSha256))throw C.fail();
   return {...result,replayed:true};
  }catch{throw C.fail('COMMERCE_STATE_INVALID');}
 }
 async function profileState(client,value,a,canonicalProfile){
  const fallback=Profile.normalizeProfileView(canonicalProfile);
  const row=(await client.query(`SELECT email,full_name,phone,updated_at::text AS updated_at
   FROM secureshop_review.product_target_profile_overlays WHERE target_id=$1 AND shop_user_id=$2 FOR UPDATE`,[value.targetId,a.owner])).rows[0];
  if(row&&(typeof row.updated_at!=='string'||!Number.isFinite(Date.parse(row.updated_at))))throw C.fail('COMMERCE_STATE_INVALID');
  const fields=row?Profile.normalizeProfileView({fullName:row.full_name,email:row.email,phone:row.phone}):fallback;
  const version={version:1,scopeKey:C.digest(a.contextJson),overlayPresent:!!row,fields,updatedAt:row?row.updated_at:null};
  return {fields,expectedSnapshotSha256:C.digest(version)};
 }
 function savedProfileReceipt(row){
  try{
   const request=JSON.parse(row.request_json),result=Profile.profileReceipt(JSON.parse(row.result_json));
   if(!C.exact(request,['operationId','expectedSnapshotSha256','fieldsSha256'])||request.operationId!==row.operation_id
    ||result.operationId!==row.operation_id||row.kind!=='profile.update'||row.state!=='completed'
    ||row.proposal_json!==null||row.proposal_sha256!==null||result.result.fieldsSha256!==request.fieldsSha256
    ||!(/^[a-f0-9]{64}$/).test(request.expectedSnapshotSha256)||!(/^[a-f0-9]{64}$/).test(request.fieldsSha256))throw C.fail();
   return {...result,replayed:true};
  }catch{throw C.fail('COMMERCE_STATE_INVALID');}
 }
 async function listKind(client,value,a,kind,ids){const cards=[];for(const id of ids.slice(0,12)){const row=await snapshot(client,value,a,kind,id);cards.push(await issue(client,value,a,kind,row));}return {cards};}
 const api={
  search(target,args){
   const search=C.text(args.search,128),cursor=args.cursor===undefined?null:C.uuid(args.cursor);
   return transaction(target,args,async(client,value,a)=>{
    const after=cursor?await choice(client,value,a,cursor,'product'):null;
    const afterId=after?databaseId(after.row.product_id):null;
    // Count the whole filtered catalog and page it in one SQL snapshot. Keep
    // pg scalar types intact; JSON aggregation would change numeric snapshots.
    const rows=(await client.query(`WITH catalog_matches AS (${effective}
     WHERE p.target_id=$1 AND (CASE WHEN o.product_id IS NULL THEN p.name ELSE o.name END) ILIKE $2
      AND (CASE WHEN o.product_id IS NULL THEN p.status ELSE o.status END)='active' AND o.archived_at IS NULL)
     SELECT page.*, (SELECT count(*)::integer FROM catalog_matches) AS matched_total
     FROM (SELECT 1) singleton LEFT JOIN LATERAL
      (SELECT * FROM catalog_matches WHERE ($3::integer IS NULL OR product_id>$3)
       ORDER BY product_id LIMIT 13) page ON true ORDER BY page.product_id`,
    [value.targetId,'%'+search+'%',afterId])).rows;
    const total=Number(rows[0]?.matched_total);
    if(!Number.isSafeInteger(total)||total<0)throw C.fail('COMMERCE_STATE_INVALID');
    const available=rows.filter(row=>row.product_id!==null).map(({matched_total,...row})=>row);
    const products=available.slice(0,12),cards=[];
    for(const row of products)cards.push(await issue(client,value,a,'product',productSnapshot(JSON.parse(JSON.stringify(row)))));
    return {products,total,cards,nextCursor:available.length>12?cards.at(-1).choiceId:null};
   });
  },
  resolveChoice(target,args){const id=C.uuid(args.choiceId);return transaction(target,args,async(client,value,a)=>{const picked=await choice(client,value,a,id);return {kind:picked.kind,choiceId:id};});},
  details(target,args){const id=C.uuid(args.choiceId);return transaction(target,args,async(client,value,a)=>{const picked=await choice(client,value,a,id,'product');const product=(await client.query(effective+' WHERE p.target_id=$1 AND p.product_id=$2',[value.targetId,picked.row.product_id])).rows[0];if(!product||C.digest(productSnapshot(JSON.parse(JSON.stringify(product))))!==C.digest(picked.row))throw C.fail('COMMERCE_CHOICE_STALE');return {product,cards:[picked.card]};});},
  cartView(target,args){return transaction(target,args,async(client,value,a)=>{await lock(client,value.targetId,a.owner);const data=await listCartWithClient(client,value,a.owner,a.mode);return {...data,...await listKind(client,value,a,'cart_item',data.items.map(row=>row.id))};});},
  prepareCart(target,args){const intent=withOrigin(args,C.mutation({operationId:args.operationId,action:args.action,choiceId:args.choiceId,...(args.action==='remove'?{}:{quantity:args.quantity})}),'cart.'+args.action);const kind='cart.'+intent.action;
   return transaction(target,args,async(client,value,a)=>{const saved=await prior(client,value,a,intent.operationId,kind,intent);if(saved){if(!saved.proposal_json){if(JSON.parse(saved.result_json)?.status!=='rejected')throw C.fail('COMMERCE_OPERATION_CONFLICT');return savedCartRejection(saved);}return publicCartProposal(intent.operationId,JSON.parse(saved.proposal_json));}
    const q=await cartIntentSnapshot(client,value,a,intent);
    if(q===CART_STOCK_UNAVAILABLE){const answer=C.cartRejection({version:1,operationId:intent.operationId,kind,
      status:'rejected',result:{code:'INSUFFICIENT_STOCK',choiceId:intent.choiceId,quantity:intent.quantity},replayed:false});
     await insert(client,value,a,intent.operationId,kind,intent,null,answer);return answer;}
    await insert(client,value,a,intent.operationId,kind,intent,q,null);return publicCartProposal(intent.operationId,q);});},
  confirmCart(target,args){const id=C.uuid(args.proposalId);return transaction(target,args,async(client,value,a)=>{const saved=await prior(client,value,a,id);if(!saved||!['cart.add','cart.update','cart.remove'].includes(saved.kind)||!saved.proposal_json)throw C.fail('COMMERCE_PROPOSAL_NOT_FOUND');if(saved.state==='completed')return {...JSON.parse(saved.result_json),replayed:true};
   const intent=JSON.parse(saved.request_json);let q;
   try{q=await cartIntentSnapshot(client,value,a,intent);}catch(error){if(!['COMMERCE_CHOICE_STALE','COMMERCE_CHOICE_DENIED','INSUFFICIENT_STOCK'].includes(error.code))throw error;}
   if(!q||q===CART_STOCK_UNAVAILABLE||C.digest(q)!==saved.proposal_sha256){const answer={version:1,operationId:id,kind:saved.kind,status:'stale',result:null,replayed:false};await complete(client,id,answer);return answer;}
   const selected=q.selection;let result;
   if(intent.action==='add'){result=await addCartWithClient(client,value,a.owner,databaseId(selected.product_id),intent.quantity);if(typeof result==='symbol')throw C.fail('CART_QUANTITY_LIMIT');}
   else if(intent.action==='update')result={changed:await updateCartWithClient(client,value,a.owner,databaseId(selected.cart_item_id),intent.quantity)};
   else result={changed:await removeCartWithClient(client,value,a.owner,databaseId(selected.cart_item_id))};
   const answer=receipt(id,saved.kind,result);await complete(client,id,answer);return answer;});},
  ordersList(target,args){const cursor=args.cursor===undefined?null:C.uuid(args.cursor),productName=normalizeOrderProductName(args.productName);return transaction(target,args,async(client,value,a)=>{
   const after=cursor?await choice(client,value,a,cursor,'order'):null;
   const date=after?.row.order_date;
   if(after&&(typeof date!=='string'||!Number.isFinite(Date.parse(date))))throw C.fail('COMMERCE_STATE_INVALID');
   const id=after?databaseId(after.row.order_id):null;
   const rows=(await client.query(`SELECT order_id,total_amount,status,payment_status,
    to_char(order_date AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS order_date
    FROM secureshop_review.product_target_orders WHERE target_id=$1 AND shop_user_id=$2
    ${after?'AND (order_date,order_id) < ($3::timestamptz,$4::bigint)':''}
    ${productName===undefined?'':`AND EXISTS (SELECT 1 FROM secureshop_review.product_target_order_items oi
     WHERE oi.target_id=product_target_orders.target_id AND oi.order_id=product_target_orders.order_id
       AND strpos(lower(oi.product_name),lower($${after?5:3}::text)) > 0)`}
    ORDER BY secureshop_review.product_target_orders.order_date DESC,order_id DESC LIMIT 13`,[value.targetId,a.owner,...(after?[date,id]:[]),...(productName===undefined?[]:[productName])])).rows;
   const orders=rows.slice(0,12),{cards}=await listKind(client,value,a,'order',orders.map(row=>databaseId(row.order_id)));
   return {orders,cards,nextCursor:rows.length>12?cards.at(-1).choiceId:null,...(productName===undefined?{}:{productName})};
  });},
  orderDetails(target,args){return transaction(target,args,async(client,value,a)=>{const picked=await choice(client,value,a,C.uuid(args.choiceId),'order');const saved=(await client.query('SELECT shipping_address FROM secureshop_review.product_target_orders WHERE target_id=$1 AND shop_user_id=$2 AND order_id=$3',[value.targetId,a.owner,databaseId(picked.row.order_id)])).rows[0];if(!saved)throw C.fail('COMMERCE_CHOICE_STALE');const shippingAddress=C.text(saved.shipping_address,4096);const items=(await client.query('SELECT product_id,product_name,quantity,price FROM secureshop_review.product_target_order_items WHERE target_id=$1 AND order_id=$2 ORDER BY product_id',[value.targetId,picked.row.order_id])).rows;return {order:{...picked.row,shipping_address:shippingAddress,items},cards:[picked.card]};});},
  addresses(target,args){return transaction(target,args,async(client,value,a)=>{const rows=(await client.query('SELECT address_id FROM secureshop_review.product_target_addresses WHERE target_id=$1 AND shop_user_id=$2 ORDER BY is_default DESC,address_id LIMIT 12',[value.targetId,a.owner])).rows;return listKind(client,value,a,'address',rows.map(row=>databaseId(row.address_id)));});},
  addressChoices(target,args){return transaction(target,args,async(client,value,a)=>{
   const rows=(await client.query('SELECT address_id FROM secureshop_review.product_target_addresses WHERE target_id=$1 AND shop_user_id=$2 ORDER BY is_default DESC,address_id LIMIT 32',[value.targetId,a.owner])).rows;
   const cards=[],addresses=[];
   for(const row of rows){
    const current=await snapshot(client,value,a,'address',databaseId(row.address_id)),card=await issue(client,value,a,'address',current);
    cards.push(card);addresses.push({addressId:databaseId(current.address_id),choiceId:card.choiceId,fields:Address.normalizeAddressFields(addressFields(current))});
   }
   return {cards,addresses};
  });},
  addressForm(target,args){const intent=Address.addressFormRequest({action:args.action,choiceId:args.choiceId});return transaction(target,args,async(client,value,a)=>{
   const selected=intent.action==='update'?await choice(client,value,a,intent.choiceId,'address'):null;
   const current=await addressState(client,value,a);
   const row=selected?current.versions.find(row=>row.addressId===Number(selected.row.address_id)):null;
   if(selected&&!row)throw C.fail('COMMERCE_CHOICE_STALE');
   return {...intent,fields:row?row.fields:{label:null,line1:'',line2:null,city:null,state:null,zip:null,phone:null,isDefault:false},expectedSnapshotSha256:row?C.digest(row):null,defaultSetSha256:current.defaultSetSha256};
  });},
  saveAddress(target,args){const requested=Address.addressSaveRequest(Object.fromEntries(['operationId','action','choiceId','expectedSnapshotSha256','defaultSetSha256','fields'].map(key=>[key,args[key]]))),intent=Address.addressIntent(requested),kind='address.'+intent.action;
   return transaction(target,args,async(client,value,a)=>{
    const saved=await prior(client,value,a,intent.operationId,kind,intent);if(saved)return savedAddressReceipt(saved);
    const stale=async()=>{
     const answer=Address.addressReceipt({...receipt(intent.operationId,kind,{fieldsSha256:intent.fieldsSha256}),status:'stale'});
     await insert(client,value,a,intent.operationId,kind,intent,null,answer);return answer;
    };
    let selected=null;
    if(intent.action==='update')try{selected=await choice(client,value,a,intent.choiceId,'address');}
    catch(error){if(error?.code==='COMMERCE_CHOICE_STALE')return stale();throw error;}
    const before=await addressState(client,value,a),current=selected?before.versions.find(row=>row.addressId===Number(selected.row.address_id)):null;
    if(before.defaultSetSha256!==intent.defaultSetSha256||(selected&&(!current||C.digest(current)!==intent.expectedSnapshotSha256)))return stale();
    if(intent.action==='create'&&before.rows.length>=32)throw C.fail('COMMERCE_ADDRESS_CAPACITY');
    const result=await saveAddressWithClient(client,value,a.owner,current?.addressId??null,requested.fields,{id:a.owner,role:'customer'},(...params)=>appendAccountAudit(auditStore,...params));
    if(!result)throw C.fail('COMMERCE_ADDRESS_STALE');
    const after=await addressState(client,value,a),updated=after.versions.find(row=>row.addressId===result.id);
    if(!updated||Address.addressFieldsDigest(updated.fields)!==intent.fieldsSha256)throw C.fail('COMMERCE_STATE_INVALID');
    const answer=Address.addressReceipt(receipt(intent.operationId,kind,{addressId:result.id,fieldsSha256:intent.fieldsSha256,addressSnapshotSha256:C.digest(updated),defaultSetSha256:after.defaultSetSha256}));
    await insert(client,value,a,intent.operationId,kind,intent,null,answer);return answer;
   });},
  profileForm(target,args){return transaction(target,args,async(client,value,a)=>({version:1,...await profileState(client,value,a,args.canonicalProfile)}));},
  saveProfile(target,args){const requested=Profile.profileSaveRequest(Object.fromEntries(['operationId','expectedSnapshotSha256','fields'].map(key=>[key,args[key]]))),intent=Profile.profileIntent(requested),kind='profile.update';
   return transaction(target,args,async(client,value,a)=>{
    if(args.expectedScopeKey!==undefined&&(typeof args.expectedScopeKey!=='string'||!(/^[a-f0-9]{64}$/).test(args.expectedScopeKey)||args.expectedScopeKey!==C.digest(a.contextJson)))throw C.fail('COMMERCE_OPERATION_CONFLICT');
    const saved=await prior(client,value,a,intent.operationId,kind,intent);if(saved)return savedProfileReceipt(saved);
    const before=await profileState(client,value,a,args.canonicalProfile);
    if(before.expectedSnapshotSha256!==intent.expectedSnapshotSha256){
     const answer=Profile.profileReceipt({...receipt(intent.operationId,kind,{fieldsSha256:intent.fieldsSha256}),status:'stale'});
     await insert(client,value,a,intent.operationId,kind,intent,null,answer);return answer;
    }
    if(requested.fields.email!==before.fields.email)Profile.normalizeProfilePatch({email:requested.fields.email});
    await saveProfileWithClient(client,value,a.owner,requested.fields,{id:a.owner,role:'customer'},(...params)=>appendAccountAudit(auditStore,...params));
    const after=await profileState(client,value,a,args.canonicalProfile);
    if(Profile.profileFieldsDigest(after.fields)!==intent.fieldsSha256)throw C.fail('COMMERCE_STATE_INVALID');
    const answer=Profile.profileReceipt(receipt(intent.operationId,kind,{fieldsSha256:intent.fieldsSha256,profileSnapshotSha256:after.expectedSnapshotSha256}));
    await insert(client,value,a,intent.operationId,kind,intent,null,answer);return answer;
   });},
  paymentMethods(target,args){return transaction(target,args,async(client,value,a)=>{const rows=(await client.query('SELECT method_id FROM secureshop_review.practice_payment_methods WHERE target_id=$1 AND shop_user_id=$2 ORDER BY scenario,method_id LIMIT 12',[value.targetId,a.owner])).rows;return listKind(client,value,a,'payment_method',rows.map(row=>row.method_id));});},
  createPaymentMethod(target,args){const intent=withOrigin(args,C.practice({operationId:args.operationId,scenario:args.scenario}),'payment.create');return transaction(target,args,async(client,value,a)=>{const saved=await prior(client,value,a,intent.operationId,'payment.create',intent);if(saved)return {...JSON.parse(saved.result_json),replayed:true};await lock(client,value.targetId,a.owner);let method=(await client.query('SELECT method_id,scenario FROM secureshop_review.practice_payment_methods WHERE target_id=$1 AND shop_user_id=$2 AND scenario=$3',[value.targetId,a.owner,intent.scenario])).rows[0];if(!method)method=(await client.query('INSERT INTO secureshop_review.practice_payment_methods(method_id,target_id,shop_user_id,scenario) VALUES($1,$2,$3,$4) RETURNING method_id,scenario',[randomUUID(),value.targetId,a.owner,intent.scenario])).rows[0];const answer=receipt(intent.operationId,'payment.create',{cards:[await issue(client,value,a,'payment_method',method)]});await insert(client,value,a,intent.operationId,'payment.create',intent,null,answer);return answer;});},
  prepareCheckout(target,args){const intent=withOrigin(args,C.prepare({operationId:args.operationId,addressChoiceId:args.addressChoiceId,paymentChoiceId:args.paymentChoiceId}),'checkout.prepare');return transaction(target,args,async(client,value,a)=>{if(!durableCheckout)throw C.fail('SERVICE_UNAVAILABLE');const saved=await prior(client,value,a,intent.operationId,'checkout',intent);if(saved)return publicProposal(intent.operationId,JSON.parse(saved.proposal_json));const q=await quote(client,value,a,intent.addressChoiceId,intent.paymentChoiceId);await insert(client,value,a,intent.operationId,'checkout',intent,q,null);return publicProposal(intent.operationId,q);});},
  confirmCheckout(target,args){const id=C.uuid(args.proposalId);return transaction(target,args,async(client,value,a)=>{if(!durableCheckout)throw C.fail('SERVICE_UNAVAILABLE');const saved=await prior(client,value,a,id,'checkout');if(!saved)throw C.fail('COMMERCE_PROPOSAL_NOT_FOUND');if(saved.state==='completed')return {...JSON.parse(saved.result_json),replayed:true};
   // First chat confirmation must create its own legacy checkout claim. A
   // matching old order is not an effect of this exact displayed proposal.
   const occupied=await client.query('SELECT operation_id FROM secureshop_review.bound_commerce_operations WHERE operation_id=$1',[id]);
   if(occupied.rows.length)throw C.fail('COMMERCE_OPERATION_CONFLICT');
   const original=JSON.parse(saved.proposal_json),intent=JSON.parse(saved.request_json);let q,status;
   try{q=await quote(client,value,a,intent.addressChoiceId,intent.paymentChoiceId);status=C.digest(q)===saved.proposal_sha256?'ready':'stale';}catch(error){if(!['COMMERCE_CHOICE_STALE','COMMERCE_CHOICE_DENIED','CART_EMPTY','INSUFFICIENT_STOCK'].includes(error.code))throw error;status='stale';}
   const base={version:1,operationId:id,kind:'checkout.confirm',status:status==='stale'?'stale':original.payment.snapshot.scenario,currency:'USD',totalCents:original.totalCents,order:null,replayed:false};
   if(status==='ready'&&original.payment.snapshot.scenario==='approved'){
    const address=original.address.snapshot,shipping=C.text([address.label,address.line1,address.line2,address.city,address.state,address.zip].filter(Boolean).join('\n'),4096);
    const order=await checkoutWithClient(client,value,a.owner,shipping,original.payment.card.title,id,{id:a.owner,role:'customer'},a.credential,a.mode);
    if(typeof order==='symbol')throw C.fail('COMMERCE_QUOTE_CHANGED');
    if(C.money(order.total)!==original.totalCents||C.money(order.subtotal)!==original.subtotalCents||C.money(order.discount)!==original.discountCents)throw C.fail('COMMERCE_QUOTE_CHANGED');
    base.order=order;
   }
   C.confirmation(base);await complete(client,id,base);return base;});},
  readTurnOperations(target,args){const sessionId=C.uuid(args.sessionId),requestId=C.uuid(args.requestId);return transaction(target,args,async(client,value,a)=>{const rows=(await client.query("SELECT * FROM secureshop_review.chat_commerce_operations WHERE target_id=$1 AND shop_user_id=$2 AND context_json=$3 AND request_json::jsonb->'origin'->>'turnSessionId'=$4 AND request_json::jsonb->'origin'->>'turnRequestId'=$5 ORDER BY created_at,operation_id LIMIT 5",[value.targetId,a.owner,a.contextJson,sessionId,requestId])).rows;if(rows.length>4)throw C.fail('COMMERCE_STATE_INVALID');return {operations:rows.map(row=>{unpack(row,a,value);const request=JSON.parse(row.request_json),origin=C.origin(request.origin);if(!origin||C.operationIdForOrigin(origin)!==row.operation_id)throw C.fail('COMMERCE_STATE_INVALID');return {operationId:row.operation_id,status:row.state,...(row.proposal_json?{proposal:operationProposal(row)}:{}),...(row.result_json?{receipt:savedOperationReceipt(row)}:{})};})};});},
  readOperation(target,args){const id=C.uuid(args.operationId);return transaction(target,args,async(client,value,a)=>{const row=(await client.query('SELECT * FROM secureshop_review.chat_commerce_operations WHERE operation_id=$1 AND target_id=$2 AND shop_user_id=$3',[id,value.targetId,a.owner])).rows[0];if(!row)return {operationId:id,status:'not_found'};unpack(row,a,value);return {operationId:id,status:row.state,...(row.kind==='payment.create'?{paymentScenario:paymentScenario(row)}:{}),...(row.proposal_json?{proposal:operationProposal(row)}:{}),...(row.result_json?{receipt:row.kind.startsWith('address.')?savedAddressReceipt(row):row.kind==='profile.update'?savedProfileReceipt(row):savedOperationReceipt(row)}:{})};});},
 };
 const keys={profileForm:['canonicalProfile'],saveProfile:['canonicalProfile','operationId','expectedSnapshotSha256','fields'],search:['search'],details:['choiceId'],resolveChoice:['choiceId'],cartView:[],ordersList:[],orderDetails:['choiceId'],addresses:[],addressChoices:[],addressForm:['action','choiceId'],saveAddress:['operationId','action','choiceId','expectedSnapshotSha256','defaultSetSha256','fields'],paymentMethods:[],createPaymentMethod:['operationId','scenario'],prepareCheckout:['operationId','addressChoiceId','paymentChoiceId'],confirmCheckout:['proposalId'],readOperation:['operationId'],readTurnOperations:['sessionId','requestId'],confirmCart:['proposalId']};
 return Object.freeze(Object.fromEntries(Object.entries(api).map(([name,method])=>[name,(target,args)=>{
  const fields=name==='prepareCart'?['operationId','action','choiceId',...(args?.action==='remove'?[]:['quantity'])]
   :name==='ordersList'?['cursor','productName'].filter(key=>Object.hasOwn(args||{},key)):keys[name];
  const expected=['shopUserId','personaSession','mode',...fields];
  if(name==='search'&&Object.hasOwn(args||{},'cursor'))expected.push('cursor');
  if(name==='saveProfile'&&Object.hasOwn(args||{},'expectedScopeKey'))expected.push('expectedScopeKey');
  if(['prepareCart','createPaymentMethod','prepareCheckout'].includes(name)&&Object.hasOwn(args||{},'origin'))expected.push('origin');
  if(!C.exact(args,expected)||!C.exact(args.personaSession,['sessionId','authorityVersion']))throw C.fail();
  return method(target,args);
 }])));

}
module.exports={createConversationalCommerceRepository};
