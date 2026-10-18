'use strict';
const { withTransaction } = require('./index');
function createPostgresEmailStore(pool) {
  const one = async (sql, params) => (await pool.query(sql, params)).rows[0];
  const all = async (sql, params) => (await pool.query(sql, params)).rows;
  return {
    assertBuilderResetReady: async () => { const row=await one("SELECT to_regprocedure('xss.clear_email_builder(uuid,integer,bigint,bigint)') IS NOT NULL AND has_function_privilege(current_user,'xss.clear_email_builder(uuid,integer,bigint,bigint)','EXECUTE') AS ready",[]); if(!row?.ready)throw new Error('Builder reset storage unavailable');return true; },
    clearBuilder: async row => one('SELECT * FROM xss.clear_email_builder($1,$2,$3,$4)', [row.operation_id,row.owner_id,row.from_generation,row.to_generation]),
    getProfile: owner => one('SELECT * FROM xss.email_profiles WHERE user_id=$1', [owner]),
    ensureProfile: owner => one(`INSERT INTO xss.email_profiles(user_id,full_name,email_address,company_name,job_title,phone_number,signature_html,signature_plain)
      VALUES($1,$2,$3,'','','','','') ON CONFLICT(user_id) DO UPDATE SET user_id=excluded.user_id RETURNING *`, [owner, `User ${owner}`, `user${owner}@example.com`]),
    updateProfile: (owner, fields) => one(`UPDATE xss.email_profiles SET full_name=$2,email_address=$3,company_name=$4,job_title=$5,phone_number=$6,signature_html=$7,signature_plain=$8,updated_at=CURRENT_TIMESTAMP WHERE user_id=$1 RETURNING *`, [owner, ...fields]),
    saveTemplate: async params => (await one(`INSERT INTO xss.email_templates(user_id,profile_id,template_name,template_type,html_content,ai_prompt,ai_model) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING id`, params)).id,
    listTemplates: owner => all('SELECT * FROM xss.email_templates WHERE user_id=$1 ORDER BY created_at DESC,id DESC', [owner]),
    getTemplate: (owner, id) => one('SELECT * FROM xss.email_templates WHERE id=$1 AND user_id=$2', [id, owner]),
    recordView: (owner, id) => pool.query('UPDATE xss.email_templates SET view_count=view_count+1,last_viewed=CURRENT_TIMESTAMP WHERE id=$1 AND user_id=$2', [id, owner]),
    recordPreview: (owner, id, detected) => pool.query(`INSERT INTO xss.template_previews(template_id,user_id,preview_type,xss_detected,xss_payload) VALUES($1,$2,'html',$3,$4)`, [id, owner, detected ? 1 : 0, detected ? 'XSS detected in preview' : null]),
    listProgress: owner => all('SELECT * FROM xss.xss_challenge_progress WHERE user_id=$1 ORDER BY challenge_level', [owner]),
    persistCompletion: ({userId, level, challengeName, receipt}) => pool.query(`INSERT INTO xss.xss_challenge_progress(user_id,challenge_level,challenge_name,completed,payload_used,completed_at,attempts)
      VALUES($1,$2,$3,1,$4,CURRENT_TIMESTAMP,1) ON CONFLICT(user_id,challenge_level) DO UPDATE SET completed=1,challenge_name=excluded.challenge_name,payload_used=excluded.payload_used,completed_at=CURRENT_TIMESTAMP,attempts=xss.xss_challenge_progress.attempts+1`, [userId, level, challengeName, JSON.stringify(receipt)]),
    persistJudgment: async row => {
      // Validate current template ownership at insertion; the historical receipt
      // deliberately has no cascading FK so it survives later template reset.
      const saved=await one(`INSERT INTO xss.xss_email_judge_receipts(user_id,challenge_level,template_id,verdict,judge_version,rubric_version,evidence_digest,run_id,error_code,browser_executed,browser_reason)
        SELECT $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11 FROM xss.email_templates WHERE id=$3 AND user_id=$1 RETURNING id`,
        [row.userId,row.level,row.templateId,row.verdict,row.judgeVersion,row.rubricVersion,row.evidenceDigest,row.runId??null,row.errorCode??null,row.browserExecuted ? 1 : 0,row.browserReason??null]);
      if(!saved)throw Object.assign(new Error('Template does not belong to receipt owner'),{code:'TEMPLATE_NOT_FOUND'});
      return saved.id;
    },
    reset: owner => withTransaction(pool, async client => {
      await client.query('DELETE FROM xss.email_templates WHERE user_id=$1', [owner]);
      await client.query('DELETE FROM xss.xss_challenge_progress WHERE user_id=$1', [owner]);
    }),
  };
}
module.exports = { createPostgresEmailStore };
