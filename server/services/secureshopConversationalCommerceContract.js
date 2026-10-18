'use strict';
const { createHash } = require('node:crypto');
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const KINDS=Object.freeze(['product','cart_item','order','address','payment_method']);
const fail=(code='INVALID_ARGUMENT')=>Object.assign(new Error('Conversational commerce unavailable'),{code});
function exact(value,keys){return value&&Object.getPrototypeOf(value)===Object.prototype&&Object.keys(value).sort().join(',')===keys.slice().sort().join(',');}
function uuid(value){if(typeof value!=='string'||!UUID.test(value))throw fail();return value.toLowerCase();}
function integer(value,min=1,max=2147483647){if(!Number.isSafeInteger(value)||value<min||value>max)throw fail();return value;}
function text(value,max){if(typeof value!=='string'||!value.trim()||!value.isWellFormed()||value.includes('\0')||Buffer.byteLength(value)>max)throw fail();return value;}
function digest(value){return createHash('sha256').update(typeof value==='string'?value:JSON.stringify(value)).digest('hex');}
function money(value){const match=/^(\d{1,10})(?:\.(\d{1,2}))?$/.exec(String(value));if(!match)throw fail('COMMERCE_STATE_INVALID');return integer(Number(match[1])*100+Number((match[2]||'').padEnd(2,'0')),0,Number.MAX_SAFE_INTEGER);}
function card(kind,choiceId,title,detail,quantity){
 if(!KINDS.includes(kind)||quantity!==undefined&&kind!=='cart_item')throw fail();
 return Object.freeze({version:1,kind,choiceId:uuid(choiceId),title:text(title,256),detail:text(detail,512),
  ...(quantity===undefined?{}:{quantity:integer(quantity,1,99)})});
}
function cards(value){if(!Array.isArray(value)||value.length>12)throw fail();for(const row of value){
 const quantityPresent=!!row&&Object.hasOwn(row,'quantity');
 if(!exact(row,['version','kind','choiceId','title','detail',...(quantityPresent?['quantity']:[])])||row.version!==1
  ||quantityPresent&&row.kind!=='cart_item')throw fail();
 if(quantityPresent)integer(row.quantity,1,99);
 card(row.kind,row.choiceId,row.title,row.detail,quantityPresent?row.quantity:undefined);
 }return value;}
function mutation(value){if(!value||!['add','update','remove'].includes(value.action)||!exact(value,value.action==='remove'?['operationId','action','choiceId']:['operationId','action','choiceId','quantity']))throw fail();return Object.freeze({operationId:uuid(value.operationId),action:value.action,choiceId:uuid(value.choiceId),...(value.action==='remove'?{}:{quantity:integer(value.quantity,1,99)})});}
function practice(value){if(!exact(value,['operationId','scenario'])||!['approved','declined'].includes(value.scenario))throw fail();return Object.freeze({operationId:uuid(value.operationId),scenario:value.scenario});}
function prepare(value){if(!exact(value,['operationId','addressChoiceId','paymentChoiceId']))throw fail();return Object.freeze({operationId:uuid(value.operationId),addressChoiceId:uuid(value.addressChoiceId),paymentChoiceId:uuid(value.paymentChoiceId)});}
function confirm(value){if(!exact(value,['proposalId']))throw fail();return Object.freeze({proposalId:uuid(value.proposalId)});}
function origin(value){if(value===undefined)return null;if(!exact(value,['turnSessionId','turnRequestId','toolKey','invocationStep','callId'])||!['cart.add','cart.update','cart.remove','cart.coupon_prepare','payment.create','checkout.prepare','profile.update'].includes(value.toolKey))throw fail();return Object.freeze({turnSessionId:uuid(value.turnSessionId),turnRequestId:uuid(value.turnRequestId),toolKey:value.toolKey,invocationStep:integer(value.invocationStep,1,4),callId:text(value.callId,128)});}
function operationIdForOrigin(value){const o=origin(value);if(!o)throw fail();const h=digest({version:1,origin:o});return h.slice(0,8)+'-'+h.slice(8,12)+'-5'+h.slice(13,16)+'-'+((parseInt(h[16],16)&3)|8).toString(16)+h.slice(17,20)+'-'+h.slice(20,32);}
function summary(value){if(!exact(value,['choiceId','title','detail']))throw fail();uuid(value.choiceId);text(value.title,256);text(value.detail,512);}
function proposal(value){if(!exact(value,['version','proposalId','status','currency','items','subtotalCents','discountCents','totalCents','address','paymentMethod','quoteSha256'])||value.version!==1||value.status!=='prepared'||value.currency!=='USD'||!Array.isArray(value.items)||!value.items.length||value.items.length>50||!(/^[a-f0-9]{64}$/).test(value.quoteSha256))throw fail('COMMERCE_STATE_INVALID');uuid(value.proposalId);summary(value.address);summary(value.paymentMethod);let subtotal=0;for(const row of value.items){if(!exact(row,['productId','name','quantity','unitPriceCents','lineTotalCents']))throw fail();integer(row.productId);text(row.name,256);integer(row.quantity,1,99);integer(row.unitPriceCents,0,Number.MAX_SAFE_INTEGER);integer(row.lineTotalCents,0,Number.MAX_SAFE_INTEGER);if(row.lineTotalCents!==row.quantity*row.unitPriceCents)throw fail();subtotal+=row.lineTotalCents;}for(const key of ['subtotalCents','discountCents','totalCents'])integer(value[key],0,Number.MAX_SAFE_INTEGER);if(subtotal!==value.subtotalCents||value.totalCents!==value.subtotalCents-value.discountCents)throw fail();return value;}
function cartProposal(value){
 if(!exact(value,['version','proposalId','status','kind','choice','quantity','quoteSha256'])||value.version!==1||value.status!=='prepared'||!['cart.add','cart.update','cart.remove'].includes(value.kind)||!(/^[a-f0-9]{64}$/).test(value.quoteSha256))throw fail('COMMERCE_STATE_INVALID');
 uuid(value.proposalId);cards([value.choice]);if(value.choice.kind!==(value.kind==='cart.add'?'product':'cart_item'))throw fail('COMMERCE_STATE_INVALID');
 if(value.kind==='cart.remove'){if(value.quantity!==null)throw fail('COMMERCE_STATE_INVALID');}else integer(value.quantity,1,99);return value;
}
function cartRejection(value){
 if(!exact(value,['version','operationId','kind','status','result','replayed'])||value.version!==1
  ||value.kind!=='cart.add'||value.status!=='rejected'||typeof value.replayed!=='boolean'
  ||!exact(value.result,['code','choiceId','quantity'])||value.result.code!=='INSUFFICIENT_STOCK')throw fail('COMMERCE_STATE_INVALID');
 uuid(value.operationId);uuid(value.result.choiceId);integer(value.result.quantity,1,99);return value;
}
function confirmation(value){if(!exact(value,['version','operationId','kind','status','currency','totalCents','order','replayed'])||value.version!==1||value.kind!=='checkout.confirm'||!['approved','declined','stale'].includes(value.status)||value.currency!=='USD'||typeof value.replayed!=='boolean')throw fail();uuid(value.operationId);integer(value.totalCents,0,Number.MAX_SAFE_INTEGER);if(value.status!=='approved'){if(value.order!==null)throw fail();}else{if(!exact(value.order,['orderId','total','subtotal','discount']))throw fail();integer(value.order.orderId);if(money(value.order.total)!==value.totalCents||money(value.order.total)!==money(value.order.subtotal)-money(value.order.discount))throw fail();}return value;}
module.exports={UUID,KINDS,fail,exact,uuid,integer,text,digest,money,card,cards,mutation,practice,prepare,confirm,origin,operationIdForOrigin,proposal,cartProposal,cartRejection,confirmation};
