'use strict';
const crypto=require('node:crypto');
const uuid=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const fail=()=>{throw Object.assign(Error('Review decision operation conflict'),{code:'REVIEW_OPERATION_CONFLICT',executionBoundary:true,effectNotApplied:true});};
function request(scope,input,operation){
 if(!operation||!uuid.test(operation.operationId)||!uuid.test(operation.personaSessionId)||!['manual','agent'].includes(operation.kind)
  ||typeof operation.authorityVersion!=='string'||!(/^[1-9]\d*$/).test(operation.authorityVersion)||!input.auditPersona)fail();
 if(operation.kind==='agent'&&(!uuid.test(operation.runId)||typeof operation.toolInvocationId!=='string'||!operation.toolInvocationId||operation.toolInvocationId.length>256))fail();
 if((operation.kind==='manual')!==(input.moderatorKind==='manual'))fail();
 if(operation.kind==='manual'&&(operation.runId!=null||operation.toolInvocationId!=null))fail();
 const exact={version:1,scope:{targetId:scope.targetId,launchId:scope.launchId,scenarioId:scope.scenarioId,generation:scope.generation,platformOwnerId:scope.platformOwnerId,platformSessionId:scope.platformSessionId},actor:{...input.auditPersona,personaSessionId:operation.personaSessionId,authorityVersion:operation.authorityVersion},kind:operation.kind,runId:operation.runId??null,toolInvocationId:operation.toolInvocationId??null,reviewId:input.reviewId,decision:input.decision,notes:input.notes??null,moderatorKind:input.moderatorKind};
 if(input.expectedSnapshotSha256!==undefined){if(operation.kind!=='manual'||typeof input.expectedSnapshotSha256!=='string'||!(/^[a-f0-9]{64}$/).test(input.expectedSnapshotSha256))fail();exact.expectedSnapshotSha256=input.expectedSnapshotSha256;}
 return Object.freeze({operationId:operation.operationId.toLowerCase(),exact,sha256:crypto.createHash('sha256').update(JSON.stringify(exact)).digest('hex')});
}
async function find(client,scope,operationId,persona){
 const row=(await client.query('SELECT * FROM secureshop_review.bound_audit_events WHERE event_id=$1',[operationId])).rows[0];if(!row)return null;
 if(row.source_kind!=='review_decision_operation'||row.launch_id!==scope.launchId||row.scenario_id!==scope.scenarioId||Number(row.generation)!==scope.generation||row.original_platform_owner_id!==scope.platformOwnerId||row.original_platform_session_id!==scope.platformSessionId||row.shop_user_id!==persona.id||row.shop_role!==persona.role)fail();
 let packet;try{packet=JSON.parse(row.params_json);}catch{fail();}if(packet?.version!==1||packet.receipt?.operationId!==operationId||typeof packet.requestSha256!=='string'||!packet.result)fail();return packet;
}
function packet(requested,result){
 const row=result.review;
 const review={...row};delete review.body;
 return {version:1,requestSha256:requested.sha256,receipt:{operationId:requested.operationId,requestSha256:requested.sha256,...requested.exact,bodySha256:crypto.createHash('sha256').update(row.body??'').digest('hex'),applied:result.applied,resultStatus:row.status,...(requested.exact.expectedSnapshotSha256===undefined?{}:{resultCode:result.code??null})},result:{...result,review}};
}
module.exports={request,find,packet,fail};
