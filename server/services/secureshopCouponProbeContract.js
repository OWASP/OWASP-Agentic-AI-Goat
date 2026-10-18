'use strict';

const Coupon=require('./secureshopCouponContract');
const Analytics=require('../../sidecars/analytics-sql-target/contract');

const fail=code=>Object.assign(Error('Coupon probe unavailable'),{code});
const DECIMAL=/^(0|[1-9][0-9]*)$/;
const CALL_ID=/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;

function exact(value,keys){
 try{Analytics.exact(value,keys);}catch{throw fail('COUPON_PROBE_INVALID');}
}

function execution(value){
 exact(value,['runId','ownerKey','generation','sessionId','requestId','step','callId']);
 if(!Analytics.UUID.test(value.runId)||!Analytics.UUID.test(value.sessionId)||!Analytics.UUID.test(value.requestId)
  ||typeof value.ownerKey!=='string'||!value.ownerKey||!value.ownerKey.isWellFormed()||Buffer.byteLength(value.ownerKey)>1024
  ||typeof value.generation!=='string'||!DECIMAL.test(value.generation)
  ||!Number.isSafeInteger(value.step)||value.step<1||value.step>9
  ||typeof value.callId!=='string'||!CALL_ID.test(value.callId))throw fail('COUPON_PROBE_INVALID');
 return Object.freeze({...value});
}

function request(value){
 exact(value,['version','lookup','execution']);
 if(value.version!==1)throw fail('COUPON_PROBE_INVALID');
 let lookup;try{lookup=Coupon.lookup(value.lookup);}catch{throw fail('COUPON_PROBE_INVALID');}
 const run=execution(value.execution);
 return Object.freeze({version:1,lookup,execution:run});
}

function result(value){
 exact(value,['coupon']);
 if(value.coupon===null)return Object.freeze({coupon:null});
 try{return Object.freeze({coupon:Coupon.coupon(value.coupon)});}catch{throw fail('COUPON_PROBE_RESULT_INVALID');}
}

function statement(value){
 const source=request(value),sql=Coupon.statement(source.lookup);
 return Object.freeze({text:sql.text,values:Object.freeze([...sql.values])});
}

function receipt(value,expectedRequest){
 exact(value,['version','kind','operationId','requestSha256','targetId','scope','sourceManifestSha256','execution','sqlSha256','valuesSha256','resultSha256','result']);
 if(value.version!==1||value.kind!=='coupon-probe')throw fail('COUPON_PROBE_RECEIPT_INVALID');
 const source=request(expectedRequest),target=Analytics.target({targetId:value.targetId,scope:value.scope,sourceManifestSha256:value.sourceManifestSha256});
 const expectedStatement=statement(source),actualResult=result(value.result);
 if(value.operationId!==source.lookup.operationId||value.requestSha256!==Analytics.hash(source)
  ||value.execution?.runId!==source.execution.runId||value.execution?.ownerKey!==source.execution.ownerKey
  ||value.execution?.generation!==source.execution.generation||value.execution?.sessionId!==source.execution.sessionId
  ||value.execution?.requestId!==source.execution.requestId||value.execution?.step!==source.execution.step||value.execution?.callId!==source.execution.callId
  ||value.sqlSha256!==Analytics.hash(expectedStatement.text)||value.valuesSha256!==Analytics.hash(expectedStatement.values)
  ||value.resultSha256!==Analytics.hash(actualResult))throw fail('COUPON_PROBE_RECEIPT_INVALID');
 execution(value.execution);
 return Object.freeze({version:1,kind:'coupon-probe',operationId:value.operationId,requestSha256:value.requestSha256,
  targetId:target.targetId,scope:target.scope,sourceManifestSha256:target.sourceManifestSha256,
  execution:source.execution,sqlSha256:value.sqlSha256,valuesSha256:value.valuesSha256,
  resultSha256:value.resultSha256,result:actualResult});
}

function storedReceipt(value){
 exact(value,['version','kind','operationId','requestSha256','targetId','scope','sourceManifestSha256','execution','sqlSha256','valuesSha256','resultSha256','result']);
 if(value.version!==1||value.kind!=='coupon-probe'||!Analytics.UUID.test(value.operationId)
  ||!Analytics.HASH.test(value.requestSha256)||!Analytics.HASH.test(value.sqlSha256)
  ||!Analytics.HASH.test(value.valuesSha256)||!Analytics.HASH.test(value.resultSha256))throw fail('COUPON_PROBE_RECEIPT_INVALID');
 const target=Analytics.target({targetId:value.targetId,scope:value.scope,sourceManifestSha256:value.sourceManifestSha256});
 const run=execution(value.execution),valueResult=result(value.result);
 if(value.resultSha256!==Analytics.hash(valueResult))throw fail('COUPON_PROBE_RECEIPT_INVALID');
 return Object.freeze({version:1,kind:'coupon-probe',operationId:value.operationId,requestSha256:value.requestSha256,
  targetId:target.targetId,scope:target.scope,sourceManifestSha256:target.sourceManifestSha256,
  execution:run,sqlSha256:value.sqlSha256,valuesSha256:value.valuesSha256,resultSha256:value.resultSha256,result:valueResult});
}

function buildReceipt({target,request:source,result:rawResult}){
 const checked=request(source),bound=Analytics.target(target),query=statement(checked),value=result(rawResult);
 return receipt({version:1,kind:'coupon-probe',operationId:checked.lookup.operationId,requestSha256:Analytics.hash(checked),
  targetId:bound.targetId,scope:bound.scope,sourceManifestSha256:bound.sourceManifestSha256,
  execution:checked.execution,sqlSha256:Analytics.hash(query.text),valuesSha256:Analytics.hash(query.values),
  resultSha256:Analytics.hash(value),result:value},checked);
}

function readRequest(value){
 exact(value,['scope','targetId','operationId','requestSha256']);
 const scope=Analytics.scope(value.scope);
 if(!Analytics.UUID.test(value.targetId)||!Analytics.UUID.test(value.operationId)||!Analytics.HASH.test(value.requestSha256))throw fail('COUPON_PROBE_INVALID');
 return Object.freeze({scope,targetId:value.targetId,operationId:value.operationId,requestSha256:value.requestSha256});
}

function referenceRequest(value){
 exact(value,['scope','targetId','operationId','requestSha256','position']);
 const base=readRequest({scope:value.scope,targetId:value.targetId,operationId:value.operationId,requestSha256:value.requestSha256});
 if(!Number.isSafeInteger(value.position)||value.position<1||value.position>256)throw fail('COUPON_PROBE_INVALID');
 return Object.freeze({...base,position:value.position});
}

module.exports={fail,execution,request,result,statement,receipt,storedReceipt,buildReceipt,readRequest,referenceRequest};
