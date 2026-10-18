'use strict';
const assert=require('node:assert/strict'),{randomUUID}=require('node:crypto');
const {hash,request}=require('../../sidecars/analytics-sql-target/contract');
module.exports=async({service,control,scope,evidence,save})=>{
 const target=await service.resolve(scope),input=sql=>({target,operationId:randomUUID(),runId:randomUUID(),requestId:randomUUID(),sessionId:randomUUID(),callId:'native-origin',sql});
 const directInput=input('SELECT api_key AS credential FROM shop_users WHERE id=1'),direct=await service.execute(directInput),value=direct.result.rows[0].credential;assert.equal(direct.version,2);assert.match(value,/^SYNTHETIC_KEY_[a-f0-9]{48}$/);assert.deepEqual(direct.protectedEvidence,{version:1,observations:[{rowIndex:0,column:'credential',category:'synthetic_api_key',relation:'shop_users',attribute:'api_key',valueSha256:hash(value)}],truncated:false});assert.deepEqual(await service.execute(directInput),direct);
 for(const sql of [`SELECT '${value}' AS api_key`,`SELECT api_key || '' AS credential FROM shop_users WHERE id=1`,`SELECT api_key FROM (VALUES ('${value}')) AS shop_users(api_key)`]){const receipt=await service.execute(input(sql));assert.equal(Object.values(receipt.result.rows[0])[0],value);assert.deepEqual(receipt.protectedEvidence.observations,[]);}
 // Seed a historical v1 completed operation in this disposable control store.
 // Its replay is compatibility proof, not a claim that this fixture ran its SQL.
 const prior=input('SELECT 1 AS old_result'),result={sql:prior.sql,columns:['old_result'],rows:[{old_result:1}],row_count:1,error:null},legacy={version:1,operationId:prior.operationId,targetId:target.targetId,scope:target.scope,runId:prior.runId,requestId:prior.requestId,sessionId:prior.sessionId,callId:prior.callId,sqlSha256:hash(prior.sql),sourceManifestSha256:target.sourceManifestSha256,resultSha256:hash(result),result};
 await control.query("INSERT INTO owned_analytics_queries(target_id,operation_id,request_sha256,state,receipt,result_sha256) VALUES($1,$2,$3,'completed',$4,$5)",[target.targetId,prior.operationId,hash(request(prior)),legacy,legacy.resultSha256]);assert.deepEqual(await service.execute(prior),legacy);
 evidence.protectedColumnNative={directAliasOrigin:true,copiedLiteralRejected:true,derivedValuesRejected:true,expressionRemainsExecutable:true,v2JsonbReplay:true,seededV1Replay:true};save();
};
