'use strict';
// Callers hold the active target FOR SHARE (or stronger). Listing publishers
// hold that target FOR UPDATE, so overlay creation/replacement cannot race us.
const fail=code=>Object.assign(Error('Owned product stock unavailable'),{code});
async function lockStock(client,targetId,productIds){
 if(!Array.isArray(productIds)||!productIds.length||productIds.length>256||productIds.some(id=>!Number.isSafeInteger(id)||id<1)||new Set(productIds).size!==productIds.length)throw fail('STOCK_REQUEST_INVALID');
 const ids=[...productIds].sort((a,b)=>a-b);
 // Every stock writer uses this namespace and ascending order. The target
 // SHARE lock excludes listing publishers, which acquire target UPDATE first.
 for(const id of ids)await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1::text,$2::bigint))',['stock:'+targetId,id]);
 const locked=(await client.query('SELECT product_id FROM secureshop_review.product_target_products WHERE target_id=$1 AND product_id=ANY($2::integer[]) ORDER BY product_id',[targetId,ids])).rows;
 if(locked.length!==ids.length||locked.some((row,i)=>Number(row.product_id)!==ids[i]))throw fail('PRODUCT_NOT_FOUND');
 const rows=(await client.query(`SELECT p.product_id,p.retailer_id,CASE WHEN o.product_id IS NULL THEN p.stock_quantity ELSE o.stock_quantity END AS stock_quantity,
  (o.product_id IS NOT NULL) AS overlay,(o.archived_at IS NOT NULL) AS archived,
  CASE WHEN o.product_id IS NULL THEN p.status ELSE o.status END AS status
  FROM secureshop_review.product_target_products p LEFT JOIN secureshop_review.product_target_listing_overlays o ON o.target_id=p.target_id AND o.product_id=p.product_id
  WHERE p.target_id=$1 AND p.product_id=ANY($2::integer[]) ORDER BY p.product_id`,[targetId,ids])).rows;
 if(rows.length!==ids.length)throw fail('STOCK_STATE_UNAVAILABLE');
 return Object.freeze(rows.map(row=>{const stock=Number(row.stock_quantity),productId=Number(row.product_id),retailerId=Number(row.retailer_id);if(!Number.isSafeInteger(stock)||stock<0||!Number.isSafeInteger(productId)||productId<1||!Number.isSafeInteger(retailerId)||retailerId<1)throw fail('STOCK_STATE_UNAVAILABLE');return Object.freeze({productId,retailerId,quantity:stock,overlay:row.overlay===true,archived:row.archived===true,status:row.status});}));
}
async function writeStock(client,targetId,row,quantity){
 if(!Number.isSafeInteger(quantity)||quantity<0||quantity>2147483647)throw fail('STOCK_REQUEST_INVALID');
 // Base snapshots are immutable. First stock mutation creates an exact
 // presentation copy; subsequent mutations update only its stock column.
 const sql=row.overlay?'UPDATE secureshop_review.product_target_listing_overlays SET stock_quantity=$3 WHERE target_id=$1 AND product_id=$2 AND stock_quantity=$4':`INSERT INTO secureshop_review.product_target_listing_overlays
  (target_id,product_id,shop_user_id,name,description,description_html,price,category,image_url,images,stock_quantity,status,template_source)
  SELECT target_id,product_id,retailer_id,name,description,description_html,price,category,image_url,images,$3,status,template_source
  FROM secureshop_review.product_target_products WHERE target_id=$1 AND product_id=$2 AND stock_quantity=$4`;
 const updated=await client.query(sql,[targetId,row.productId,quantity,row.quantity]);
 if(updated.rowCount!==1)throw fail('STOCK_CONFLICT');return Object.freeze({productId:row.productId,retailerId:row.retailerId,before:row.quantity,after:quantity});
}
function stockAvailable(stock,lines){
 const quantities=new Map(lines.map(row=>[Number(row.product_id),Number(row.quantity)]));
 if(quantities.size!==lines.length||stock.length!==lines.length||new Set(stock.map(row=>row.productId)).size!==stock.length)throw fail('STOCK_REQUEST_INVALID');
 let available=true;
 for(const row of stock){const quantity=quantities.get(row.productId);if(!Number.isSafeInteger(quantity)||quantity<1||quantity>99||!Number.isSafeInteger(row.quantity)||row.quantity<0)throw fail('STOCK_REQUEST_INVALID');if(row.archived||row.status!=='active'||row.quantity<quantity)available=false;}
 return available;
}
async function consumeStock(client,targetId,stock,lines){
 if(!stockAvailable(stock,lines))throw fail('INSUFFICIENT_STOCK');
 const quantities=new Map(lines.map(row=>[Number(row.product_id),Number(row.quantity)]));
 const effects=[];for(const row of stock)effects.push(await writeStock(client,targetId,row,row.quantity-quantities.get(row.productId)));return Object.freeze(effects);
}
module.exports={lockStock,writeStock,consumeStock,stockAvailable};
