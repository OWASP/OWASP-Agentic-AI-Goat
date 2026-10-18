'use strict';
const {createHash}=require('node:crypto');
const {executionScope}=require('../../services/secureshopSceneBinding');
const uuid=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
function fail(){throw Object.assign(Error('Refund operation unavailable'),{code:'REFUND_OPERATION_CONFLICT',executionBoundary:true,effectNotApplied:true});}
function request(scope,input,operation){
 if(!uuid.test(operation?.operationId)||!uuid.test(operation?.personaSessionId)||!uuid.test(input.runId)||typeof operation.authorityVersion!=='string'||!(/^[1-9]\d*$/).test(operation.authorityVersion)||typeof operation.toolInvocationId!=='string'||!operation.toolInvocationId||operation.toolInvocationId.length>256)fail();
 const exact={scope:{targetId:scope.targetId,...executionScope(scope)},shopUserId:input.shopUserId,personaSessionId:operation.personaSessionId,authorityVersion:operation.authorityVersion,requestId:input.requestId,runId:input.runId,toolInvocationId:operation.toolInvocationId,orderId:input.orderId,reason:input.reason};
 return {operationId:operation.operationId.toLowerCase(),exact,digest:createHash('sha256').update(JSON.stringify(exact)).digest('hex')};
}
async function find(client,scope,id,actor){
 const row=(await client.query('SELECT * FROM secureshop_review.bound_audit_events WHERE event_id=$1',[id])).rows[0];if(!row)return null;
 const current=executionScope(scope);
 if(row.source_kind!=='refund_operation'||row.launch_id!==current.launchId||row.scenario_id!==current.scenarioId||Number(row.generation)!==current.generation||row.original_platform_owner_id!==current.platformOwnerId||row.original_platform_session_id!==current.platformSessionId||row.shop_user_id!==actor||row.shop_role!=='customer')fail();
 let packet;try{packet=JSON.parse(row.params_json);}catch{fail();}
 const expected={targetId:scope.targetId,...current};
 if(packet?.receipt?.operationId!==id||Object.keys(expected).some(key=>packet.receipt.scope?.[key]!==expected[key])||!packet.result||typeof packet.digest!=='string')fail();return packet;
}
module.exports={request,find,fail};
