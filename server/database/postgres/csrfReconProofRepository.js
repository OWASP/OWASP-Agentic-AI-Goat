'use strict';
const {validProof}=require('../../services/csrfReconProof');
const {canonicalDurableGeneration}=require('../../agent-runtime/durableGeneration');
function createCsrfReconProofRepository(pool){
 if(typeof pool?.connect!=='function')throw new TypeError('Identity pool required');
 return {async read({execution,userId}){
  await execution.check();const ownerKey=JSON.stringify(['CSRF',String(userId)]),generation=canonicalDurableGeneration(execution.durableGeneration);
  if(execution.ownerKey!==ownerKey||!generation)throw new Error('Recon owner/generation required');
  const client=await pool.connect();let rows;
  try{await client.query('BEGIN READ ONLY');await client.query("SET LOCAL statement_timeout='3s'");await client.query("SET LOCAL lock_timeout='1s'");
   rows=(await client.query(`SELECT r.run_id AS "runId",p.provider,p.model,p.decision_seq AS "decisionSeq",p.effect_seq AS "effectSeq",p.end_seq AS "endSeq"
    FROM graph_runtime.runs r JOIN graph_runtime.owners o USING(owner_key)
    JOIN LATERAL (
      SELECT d.metadata->>'provider' AS provider,d.metadata->>'model' AS model,d.sequence AS decision_seq,m.sequence AS effect_seq,e.sequence AS end_seq
      FROM graph_runtime.events d JOIN graph_runtime.events m ON m.run_id=d.run_id AND m.owner_key=d.owner_key AND m.sequence>d.sequence
      JOIN graph_runtime.events e ON e.run_id=m.run_id AND e.owner_key=m.owner_key AND e.sequence>m.sequence
      WHERE d.run_id=r.run_id AND d.owner_key=r.owner_key AND d.node='classify' AND d.event_type='decision'
       AND d.metadata->>'decisionSource'='model' AND d.metadata->>'tool'='recon'
       AND length(trim(d.metadata->>'provider')) BETWEEN 1 AND 160 AND length(trim(d.metadata->>'model')) BETWEEN 1 AND 160
       AND lower(d.metadata->>'provider') IN ('ollama','anthropic','claude','openai','chatgpt','bedrock','lmstudio')
       AND d.metadata->>'provider' !~* 'mock|fixture|fallback|unavailable|scripted|controlled|synthetic' AND d.metadata->>'model' !~* 'mock|fixture|fallback|unavailable|scripted|controlled|synthetic'
       AND m.node='csrf_recon_get' AND m.event_type='tool' AND m.metadata->>'tool'='recon'
       AND e.node='recon' AND e.event_type='node_end'
      ORDER BY e.sequence DESC LIMIT 1
    ) p ON true
    WHERE r.owner_key=$1 AND r.generation=$2::bigint AND o.generation=$2::bigint
     AND (r.status='completed' OR (r.run_id=$3::uuid AND r.status='running'))
    ORDER BY (r.run_id=$3::uuid) DESC,r.started_at DESC LIMIT 2`,[ownerKey,generation,execution.runId])).rows;
   await client.query('COMMIT');
  }catch(error){await client.query('ROLLBACK').catch(()=>{});throw error;}finally{client.release();}
  await execution.check();const proof={version:1,ownerKey,generation,currentRunId:execution.runId,runs:rows};
  return validProof(proof,{ownerKey,runId:execution.runId,generation})?Object.freeze(proof):null;
 }};
}
module.exports={createCsrfReconProofRepository};
