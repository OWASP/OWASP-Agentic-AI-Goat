'use strict';
function createLegacySensitiveProgressStore(db){
 if(db?.engine==='postgres')return db;
 return {async recordJudgment({userId,objectiveId,runId,flagFound,exploitUsed,completed,judgment}){
  // Raw file contents and prompts are deliberately excluded from receipt metadata.
  const metadata=JSON.stringify({verdict:judgment.verdict,judgeVersion:judgment.judgeVersion,rubricVersion:judgment.rubricVersion,evidenceDigest:judgment.evidenceDigest,provider:judgment.provider,model:judgment.model,evidenceSummary:judgment.evidenceSummary});
  await new Promise((resolve,reject)=>db.run(`INSERT INTO challenge_progress (user_id,challenge_type,flag_found,exploit_used,payload,success,run_id,judgment) VALUES (?,?,?,?,NULL,?,?,?) ON CONFLICT(run_id,challenge_type) DO NOTHING`,[userId,objectiveId,flagFound,exploitUsed,completed?1:0,runId,metadata],error=>error?reject(error):resolve()));
 }};
}
module.exports={createLegacySensitiveProgressStore};
