'use strict';
const {withTransaction}=require('./index');
const c=require('../../services/secureshopInventoryContract');
const {createLaunchScope}=require('../../services/secureshopConversationBinding');
const {assertSceneGrant,withSceneLease}=require('../../services/secureshopSceneBinding');
const {lockStock,writeStock}=require('./secureshopOwnedStock');
const TABLE='secureshop_review.owned_inventory_operations';
function createOwnedInventoryRepository({pool,checkCurrent}={}){
 if(typeof pool?.connect!=='function'||typeof checkCurrent!=='function')throw TypeError('Owned inventory dependencies required');
 async function transaction(raw,work){const request=c.request(raw),storage=createLaunchScope(raw.target);await checkCurrent(request.scope);return withSceneLease(raw.target,()=>withTransaction(pool,async client=>{
  await client.query("SET LOCAL statement_timeout='3000ms'");await client.query("SET LOCAL lock_timeout='3000ms'");await assertSceneGrant(client,raw.target);const s=storage;
  const target=(await client.query('SELECT lifecycle FROM secureshop_review.product_targets WHERE target_id=$1 AND launch_id=$2 AND scenario_id=$3 AND generation=$4 AND original_platform_owner_id=$5 AND original_platform_session_id=$6 FOR SHARE',[request.targetId,s.launchId,s.scenarioId,s.generation,s.platformOwnerId,s.platformSessionId])).rows[0];if(target?.lifecycle!=='active')throw c.fail('PRODUCT_TARGET_UNAVAILABLE');
  await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1::text,$2::bigint))',['inventory:'+request.targetId,request.persona.id]);
  const result=await work(client,request);await checkCurrent(request.scope);await assertSceneGrant(client,raw.target);return result;
 }));}
 async function read(client,request){const row=(await client.query(`SELECT * FROM ${TABLE} WHERE operation_id=$1`,[request.operationId])).rows[0];if(!row)return null;
  if(row.target_id!==request.targetId||Number(row.shop_user_id)!==request.persona.id||row.persona_session_id!==request.personaSession.sessionId||String(row.authority_version)!==request.personaSession.authorityVersion||row.mode!==request.mode||row.action!==request.action||row.request_sha256!==c.hash(request))throw c.fail('INVENTORY_OPERATION_CONFLICT');
  if(row.state==='redacted'||row.request_json===null)throw c.fail('INVENTORY_RETIRED');if(c.hash(row.request_json)!==row.request_sha256||row.state!=='completed'||!row.result_json||c.hash(row.result_json)!==row.result_sha256)throw c.fail('INVENTORY_INTEGRITY_UNAVAILABLE');return JSON.parse(row.result_json);
 }
 async function observe(client,request){
  if(request.action==='stock_levels'){
   const rows=(await client.query(`SELECT p.product_id,p.retailer_id,CASE WHEN o.product_id IS NULL THEN p.name ELSE o.name END AS name,CASE WHEN o.product_id IS NULL THEN p.stock_quantity ELSE o.stock_quantity END AS stock_quantity
    FROM secureshop_review.product_target_products p LEFT JOIN secureshop_review.product_target_listing_overlays o ON o.target_id=p.target_id AND o.product_id=p.product_id
    WHERE p.target_id=$1 AND o.archived_at IS NULL ORDER BY p.product_id LIMIT 257`,[request.targetId])).rows;
   if(rows.length>256)throw c.fail('INVENTORY_CAPACITY');const items=rows.map(row=>{const item={productId:Number(row.product_id),retailerId:Number(row.retailer_id),name:row.name,quantity:Number(row.stock_quantity)};if(!Number.isSafeInteger(item.productId)||item.productId<1||!Number.isSafeInteger(item.retailerId)||item.retailerId<1||!Number.isSafeInteger(item.quantity)||item.quantity<0||typeof item.name!=='string')throw c.fail('INVENTORY_INVALID');return item;});return{items,lowStock:items.filter(row=>row.quantity<5),count:items.length};
  }
  const stock=(await lockStock(client,request.targetId,[request.args.productId]))[0];if(stock.archived)throw c.fail('PRODUCT_NOT_FOUND');
  if(request.action==='reorder_suggestion'){
   const units=Number((await client.query(`SELECT COALESCE(sum(i.quantity),0)::text AS units FROM secureshop_review.product_target_order_items i JOIN secureshop_review.product_target_orders o ON o.target_id=i.target_id AND o.order_id=i.order_id WHERE i.target_id=$1 AND i.product_id=$2 AND o.payment_status='approved' AND o.status<>'cancelled'`,[request.targetId,stock.productId])).rows[0].units);
   return{productId:stock.productId,retailerId:stock.retailerId,current:stock.quantity,unitsSold:units,suggestedReorder:c.reorder(units,stock.quantity)};
  }
  // @intentional-vulnerability broken-access-inventory
  // Vulnerable mode deliberately omits only the in-target retailer check.
  if(request.mode==='fixed'&&stock.retailerId!==request.persona.id)return{applied:false,reason:'retailer_ownership_required',productId:stock.productId};
  const effect=await writeStock(client,request.targetId,stock,request.args.quantity);return{applied:true,...effect};
 }
 return Object.freeze({
  recover(raw){return transaction(raw,(client,request)=>read(client,request));},
  execute(raw){return transaction(raw,async(client,request)=>{
   const prior=await read(client,request);if(prior)return prior;
   const count=Number((await client.query(`SELECT count(*)::int AS count FROM ${TABLE} WHERE target_id=$1 AND shop_user_id=$2`,[request.targetId,request.persona.id])).rows[0].count);if(count>=256)throw c.fail('INVENTORY_CAPACITY');
   const json=JSON.stringify(request),digest=c.hash(json),execution=request.execution;
   await client.query(`INSERT INTO ${TABLE}(operation_id,target_id,shop_user_id,persona_session_id,authority_version,mode,action,run_id,request_id,call_id,request_sha256,request_json) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,[request.operationId,request.targetId,request.persona.id,request.personaSession.sessionId,request.personaSession.authorityVersion,request.mode,request.action,execution?.runId||null,execution?.requestId||null,execution?.callId||null,digest,json]);
   const result=await observe(client,request),receipt={version:1,operationId:request.operationId,requestSha256:digest,binding:request,result},text=JSON.stringify(receipt);
   const updated=await client.query(`UPDATE ${TABLE} SET state='completed',result_json=$2,result_sha256=$3 WHERE operation_id=$1 AND state='admitted'`,[request.operationId,text,c.hash(text)]);if(updated.rowCount!==1)throw c.fail('INVENTORY_OPERATION_CONFLICT');return Object.freeze(receipt);
  });},
 });
}
module.exports={createOwnedInventoryRepository};
