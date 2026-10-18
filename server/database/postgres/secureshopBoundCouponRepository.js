'use strict';
const {withTransaction}=require('./index');
const c=require('../../services/secureshopCouponContract');
const {createLaunchScope}=require('../../services/secureshopConversationBinding');
const {executionScope,assertSceneGrant,withSceneLease}=require('../../services/secureshopSceneBinding');
function context(raw){
 const storageScope=createLaunchScope(raw.target),scope=createLaunchScope(executionScope(raw.target)),targetId=raw.target?.targetId;
 if(!c.UUID.test(targetId||'')||raw.persona?.role!=='customer'||!Number.isSafeInteger(raw.persona.id)||raw.persona.id<1||!c.UUID.test(raw.personaSession?.sessionId||'')||!/^[1-9][0-9]*$/.test(raw.personaSession?.authorityVersion||'')||!['vuln','fixed'].includes(raw.mode)||!c.UUID.test(raw.operationId||''))throw c.fail('COUPON_INVALID');
 return Object.freeze({scope,storageScope,targetId,persona:Object.freeze({id:raw.persona.id,role:'customer'}),personaSession:Object.freeze({sessionId:raw.personaSession.sessionId,authorityVersion:raw.personaSession.authorityVersion}),mode:raw.mode,operationId:raw.operationId});
}
const T='secureshop_review.';
function createBoundCouponRepository({pool,checkCurrent}={}){
 if(typeof pool?.connect!=='function'||typeof checkCurrent!=='function')throw TypeError('Coupon repository dependencies required');
 async function lock(client,b){await client.query("SET LOCAL statement_timeout='3000ms'");await client.query("SET LOCAL lock_timeout='3000ms'");const s=b.storageScope;
  const row=(await client.query(`SELECT lifecycle FROM ${T}product_targets WHERE target_id=$1 AND launch_id=$2 AND scenario_id=$3 AND generation=$4 AND original_platform_owner_id=$5 AND original_platform_session_id=$6 FOR SHARE`,[b.targetId,s.launchId,s.scenarioId,s.generation,s.platformOwnerId,s.platformSessionId])).rows[0];if(row?.lifecycle!=='active')throw c.fail('PRODUCT_TARGET_UNAVAILABLE');
  await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1::text,$2::bigint))',[b.targetId,b.persona.id]);
 }
 async function tx(raw,work,atEffect){const b=context(raw);await checkCurrent(b.scope);return withSceneLease(raw.target,()=>withTransaction(pool,async client=>{await assertSceneGrant(client,raw.target);await lock(client,b);await atEffect?.();const result=await work(client,b);await atEffect?.();await checkCurrent(b.scope);await assertSceneGrant(client,raw.target);return result;}));}
 function verify(row,b,kind){if(!row)return null;if(row.target_id!==b.targetId||Number(row.shop_user_id)!==b.persona.id||row.kind!==kind||row.persona_session_id!==b.personaSession.sessionId||String(row.authority_version)!==b.personaSession.authorityVersion)throw c.fail('COMMERCE_OPERATION_CONFLICT');if(row.mode!==b.mode)throw c.fail('COMMERCE_MODE_CHANGED');if(row.state==='redacted'||row.request_json===null)throw c.fail('COMMERCE_RETIRED');if(c.hash(row.request_json)!==row.request_sha256||(row.result_json!==null&&c.hash(row.result_json)!==row.result_sha256))throw c.fail('COMMERCE_INTEGRITY_UNAVAILABLE');const request=JSON.parse(row.request_json);if(JSON.stringify(request.scope)!==JSON.stringify(b.scope))throw c.fail('COMMERCE_OPERATION_CONFLICT');return Object.freeze({state:row.state,request,result:row.result_json===null?null:JSON.parse(row.result_json)});}
 async function read(client,b,kind){return verify((await client.query(`SELECT * FROM ${T}bound_commerce_operations WHERE operation_id=$1`,[b.operationId])).rows[0],b,kind);}
 async function admit(client,b,kind,request){const prior=await read(client,b,kind),json=JSON.stringify(request);if(prior){if(JSON.stringify(prior.request)!==json){const error=c.fail('COMMERCE_OPERATION_CONFLICT');Object.defineProperty(error,'effectNotApplied',{value:true});throw error;}return prior;}
  const count=Number((await client.query(`SELECT count(*) AS count FROM ${T}bound_commerce_operations WHERE target_id=$1 AND shop_user_id=$2`,[b.targetId,b.persona.id])).rows[0].count);if(count>=256)throw c.fail('COMMERCE_OPERATION_CAPACITY');
  await client.query(`INSERT INTO ${T}bound_commerce_operations(operation_id,target_id,shop_user_id,kind,persona_session_id,authority_version,mode,request_sha256,request_json) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`,[b.operationId,b.targetId,b.persona.id,kind,b.personaSession.sessionId,b.personaSession.authorityVersion,b.mode,c.hash(json),json]);return Object.freeze({state:'admitted',request,result:null});
 }
 async function complete(client,b,result){const json=JSON.stringify(result);const r=await client.query(`UPDATE ${T}bound_commerce_operations SET state='completed',result_json=$2,result_sha256=$3 WHERE operation_id=$1 AND state='admitted'`,[b.operationId,json,c.hash(json)]);if(r.rowCount!==1)throw c.fail('COMMERCE_OPERATION_CONFLICT');}
 async function currentWithClient(client,targetId,owner,mode){const row=(await client.query(`SELECT coupon_id,code,discount_percent,mode FROM ${T}product_target_cart_coupons WHERE target_id=$1 AND shop_user_id=$2`,[targetId,owner])).rows[0];if(!row)return null;if(row.mode!==mode)throw c.fail('COMMERCE_MODE_CHANGED');return c.coupon({id:Number(row.coupon_id),code:row.code,discount_percent:Number(row.discount_percent),active:1});}
 return Object.freeze({
  recover(raw,kind='coupon',atEffect){return tx(raw,(client,b)=>read(client,b,kind),atEffect);},
  admitCoupon(raw,atEffect){return tx(raw,async(client,b)=>{const request=c.lookup({scope:b.scope,operationId:b.operationId,persona:b.persona,personaSession:b.personaSession,mode:b.mode,code:raw.code,coupons:raw.coupons});return admit(client,b,'coupon',request);},atEffect);},
  completeCoupon(raw,{request,receipt,atEffect}){return tx(raw,async(client,b)=>{const prior=await read(client,b,'coupon');if(!prior||JSON.stringify(prior.request)!==JSON.stringify(request))throw c.fail('COMMERCE_OPERATION_CONFLICT');if(prior.state==='completed')return prior.result;
   const remote=require('../../../sidecars/analytics-sql-target/contract');if(receipt?.kind!=='coupon'||receipt.version!==1||receipt.operationId!==b.operationId||JSON.stringify(receipt.scope)!==JSON.stringify(b.scope)||receipt.requestSha256!==remote.hash({kind:'coupon-v1',request})||receipt.resultSha256!==remote.hash(receipt.result))throw c.fail('COUPON_RESULT_INVALID');
   const subtotal=(await client.query(`SELECT COALESCE(sum(i.quantity*(CASE WHEN o.product_id IS NULL THEN p.price ELSE o.price END)*100),0)::text AS subtotal_cents FROM ${T}product_target_cart_items i JOIN ${T}product_target_products p ON p.target_id=i.target_id AND p.product_id=i.product_id LEFT JOIN ${T}product_target_listing_overlays o ON o.target_id=p.target_id AND o.product_id=p.product_id WHERE i.target_id=$1 AND i.shop_user_id=$2`,[b.targetId,b.persona.id])).rows[0];
   const selected=c.selected(receipt.result?.coupon?[receipt.result.coupon]:[],request.coupons),quote=c.money([Number(subtotal.subtotal_cents)],selected?.discount_percent||0),result=selected?{ok:true,code:selected.code,discount_percent:selected.discount_percent,subtotal:quote.subtotalCents/100,applied_amount:quote.discountCents/100}:{ok:false,error:'coupon not found'};
   await complete(client,b,result);
   if(selected)await client.query(`INSERT INTO ${T}product_target_cart_coupons(target_id,shop_user_id,operation_id,coupon_id,code,discount_percent,mode) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(target_id,shop_user_id) DO UPDATE SET operation_id=EXCLUDED.operation_id,coupon_id=EXCLUDED.coupon_id,code=EXCLUDED.code,discount_percent=EXCLUDED.discount_percent,mode=EXCLUDED.mode`,[b.targetId,b.persona.id,b.operationId,selected.id,selected.code,selected.discount_percent,b.mode]);return result;
  },atEffect);},
  currentWithClient,
  async beginCheckoutWithClient(client,raw){const b=context(raw);const shippingAddress=c.text(raw.shippingAddress,4096),paymentMethod=c.text(raw.paymentMethod,256);if(!shippingAddress.trim()||!paymentMethod.trim())throw c.fail('COUPON_INVALID');try{return await admit(client,b,'checkout',{scope:b.scope,targetId:b.targetId,persona:b.persona,personaSession:b.personaSession,mode:b.mode,operationId:b.operationId,shippingAddress,paymentMethod});}catch(error){
   // Admission only reads the retained operation before any checkout stock,
   // order, or cart effect. Preserve the definitive conflict across the
   // agents/review transaction boundary; late completion failures stay uncertain.
   if(error?.code==='COMMERCE_OPERATION_CONFLICT')Object.defineProperty(error,'effectNotApplied',{value:true});
   throw error;
  }},
  async finishCheckoutWithClient(client,raw,result){const b=context(raw);await complete(client,b,result);await client.query(`DELETE FROM ${T}product_target_cart_coupons WHERE target_id=$1 AND shop_user_id=$2`,[b.targetId,b.persona.id]);},
 });
}
module.exports={createBoundCouponRepository,context};
