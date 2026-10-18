'use strict';
const {createBoundCouponRepository}=require('../database/postgres/secureshopBoundCouponRepository');
const {createBoundCoupon}=require('./secureshopBoundCoupon');
const {fail}=require('./secureshopCouponContract');
const {UUID,HASH,exact,scope:checkedScope,target:checkedTarget,sameScope}=require('../../sidecars/analytics-sql-target/contract');
function createOwnedCouponSqlReceiptReader({service}={}){
 if(typeof service?.resolve!=='function'||typeof service?.readCouponReceipt!=='function')throw fail('COUPON_RUNTIME_UNAVAILABLE');
 return async function readCouponReceipt(input,options){
  exact(input,['scope','operationId','requestSha256']);
  const request=Object.freeze({scope:checkedScope(input.scope),operationId:input.operationId,requestSha256:input.requestSha256});
  if(!UUID.test(request.operationId)||!HASH.test(request.requestSha256))throw fail('COUPON_INVALID');
  let resolved;
  try{resolved=await service.resolve(request.scope,options);}catch(error){
   if(error?.code==='ANALYTICS_TARGET_UNAVAILABLE')return null;
   throw error;
  }
  const target=checkedTarget(resolved);
  if(!sameScope(target.scope,request.scope))throw fail('ANALYTICS_TARGET_INVALID');
  const receipt=await service.readCouponReceipt({...request,targetId:target.targetId},options);
  if(receipt===null)return null;
  if(receipt?.targetId!==target.targetId||receipt?.sourceManifestSha256!==target.sourceManifestSha256
   ||!sameScope(receipt?.scope,target.scope)||receipt?.operationId!==request.operationId
   ||receipt?.requestSha256!==request.requestSha256)throw fail('ANALYTICS_QUERY_CONFLICT');
  return Object.freeze({targetId:target.targetId,receipt});
 };
}
async function assertCouponSchema(pool){
 const tables=['bound_commerce_operations','product_target_cart_coupons'];
 const rows=(await pool.query("SELECT name,to_regclass('secureshop_review.'||name) IS NOT NULL AND has_table_privilege(current_user,to_regclass('secureshop_review.'||name),'SELECT') AND has_table_privilege(current_user,to_regclass('secureshop_review.'||name),'INSERT') AND has_table_privilege(current_user,to_regclass('secureshop_review.'||name),'UPDATE') AS ready FROM unnest($1::text[]) name",[tables])).rows;
 if(rows.length!==2||new Set(rows.map(r=>r.name)).size!==2||rows.some(r=>!tables.includes(r.name)||r.ready!==true))throw fail('COUPON_SCHEMA_UNAVAILABLE');
 const columns=(await pool.query("SELECT table_name,column_name FROM information_schema.columns WHERE table_schema='secureshop_review' AND ((table_name='product_target_orders' AND column_name=ANY($1::text[])) OR (table_name='product_target_order_items' AND column_name='discount_amount'))",[['subtotal_amount','discount_amount','coupon_code','coupon_percent']])).rows;
 if(columns.length!==5)throw fail('COUPON_SCHEMA_UNAVAILABLE');
 const triggers=(await pool.query("SELECT t.tgname,t.tgrelid::regclass::text AS relation,t.tgfoid::regprocedure::text AS function,t.tgtype::integer AS type FROM pg_trigger t WHERE NOT t.tgisinternal AND t.tgenabled='O' AND t.tgname=ANY($1::text[])",[['bound_commerce_operation_guard','cart_coupon_guard','retire_bound_commerce_operations','default_order_subtotal']])).rows;
 const expected=[['bound_commerce_operation_guard','bound_commerce_operations','guard_bound_commerce_operation',31],['cart_coupon_guard','product_target_cart_coupons','guard_cart_coupon',23],['retire_bound_commerce_operations','product_targets','retire_bound_commerce_operations',17],['default_order_subtotal','product_target_orders','default_order_subtotal',7]];
 if(triggers.length!==4||!expected.every(([name,table,fn,type])=>triggers.some(r=>r.tgname===name&&r.relation==='secureshop_review.'+table&&r.function==='secureshop_review.'+fn+'()'&&r.type===type)))throw fail('COUPON_SCHEMA_UNAVAILABLE');
 const guards=(await pool.query("SELECT p.proname,has_function_privilege(current_user,p.oid,'EXECUTE') AS executable,EXISTS(SELECT 1 FROM aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) a WHERE a.grantee=0 AND a.privilege_type='EXECUTE') AS public_execute FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='secureshop_review' AND p.proname=ANY($1::text[]) AND p.pronargs=0",[expected.map(row=>row[2])])).rows;
 if(guards.length!==4||new Set(guards.map(r=>r.proname)).size!==4||guards.some(r=>r.executable!==true||r.public_execute!==false))throw fail('COUPON_SCHEMA_UNAVAILABLE');
 const privileges=(await pool.query("SELECT has_table_privilege(current_user,'secureshop_review.bound_commerce_operations','DELETE') AS deletes_operations,has_table_privilege(current_user,'secureshop_review.product_target_cart_coupons','DELETE') AS deletes_coupon")).rows[0];
 if(privileges?.deletes_operations!==false||privileges.deletes_coupon!==true)throw fail('COUPON_SCHEMA_UNAVAILABLE');
 return true;
}
async function prepareCommerceDependencies({reviewPool,launches,mode='vuln',modeAuthority}={}){
 if(typeof launches?.assertCurrent!=='function'||!['vuln','fixed'].includes(mode))throw fail('COUPON_RUNTIME_UNAVAILABLE');
 await assertCouponSchema(reviewPool);return Object.freeze({repository:createBoundCouponRepository({pool:reviewPool,checkCurrent:s=>launches.assertCurrent(s)}),mode,modeAuthority});
}
async function prepareCouponDependencies({reviewPool,commercePool,launches,runtime,lifecycle,mode='vuln',modeAuthority}={}){
 if(runtime?.admissions!==true||typeof runtime?.assertReady!=='function'||typeof runtime.service?.lookupCoupon!=='function'||typeof runtime.service?.resolve!=='function'||typeof runtime.service?.readCouponReceipt!=='function'||!require('./secureshopAnalyticsLifecycle').isAnalyticsLifecycleFor(lifecycle,runtime.service)||typeof commercePool?.query!=='function'||typeof launches?.assertCurrent!=='function')throw fail('COUPON_RUNTIME_UNAVAILABLE');
 await assertCouponSchema(reviewPool);await runtime.assertReady();
 const repository=createBoundCouponRepository({pool:reviewPool,checkCurrent:s=>launches.assertCurrent(s)});
 const workflow=createBoundCoupon({repository,service:runtime.service,mode,modeAuthority,checkCurrent:s=>launches.assertCurrent(s),readCoupons:async()=>{const rows=(await commercePool.query('SELECT id,code,discount_percent,active FROM secureshop.coupons ORDER BY id LIMIT 65')).rows;return rows.map(r=>({id:r.id,code:r.code,discount_percent:r.discount_percent,active:r.active}));}});
 return Object.freeze({repository,workflow,mode,modeAuthority,readCouponReceipt:createOwnedCouponSqlReceiptReader({service:runtime.service})});
}
module.exports={assertCouponSchema,prepareCouponDependencies,prepareCommerceDependencies,createOwnedCouponSqlReceiptReader};
