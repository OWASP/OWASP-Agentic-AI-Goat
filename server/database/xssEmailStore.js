'use strict';

// Explicit SQLite adapter for the staged migration. No SQL dialect translation.
function createSqliteEmailStore(db) {
  const get = (sql, args) => new Promise((resolve, reject) => db.get(sql, args, (error, row) => error ? reject(error) : resolve(row)));
  const all = (sql, args) => new Promise((resolve, reject) => db.all(sql, args, (error, rows) => error ? reject(error) : resolve(rows)));
  const run = (sql, args) => new Promise((resolve, reject) => db.run(sql, args, function(error) { error ? reject(error) : resolve({ id: this.lastID, changes: this.changes }); }));
  const getProfile = owner => get('SELECT * FROM email_profiles WHERE user_id = ?', [owner]);
  return {
    getProfile,
    async ensureProfile(owner) {
      const existing = await getProfile(owner);
      if (existing) return existing;
      await run(`INSERT OR IGNORE INTO email_profiles (user_id,full_name,email_address,company_name,job_title,phone_number,signature_html,signature_plain)
        VALUES (?,?,?,'','','','','')`, [owner, `User ${owner}`, `user${owner}@example.com`]);
      return getProfile(owner);
    },
    async updateProfile(owner, fields) {
      const result = await run(`UPDATE email_profiles SET full_name=?,email_address=?,company_name=?,job_title=?,phone_number=?,signature_html=?,signature_plain=?,updated_at=CURRENT_TIMESTAMP WHERE user_id=?`, [...fields, owner]);
      return result.changes ? getProfile(owner) : null;
    },
    async saveTemplate(params) { return (await run(`INSERT INTO email_templates (user_id,profile_id,template_name,template_type,html_content,ai_prompt,ai_model) VALUES (?,?,?,?,?,?,?)`, params)).id; },
    listTemplates: owner => all('SELECT * FROM email_templates WHERE user_id = ? ORDER BY created_at DESC', [owner]),
    getTemplate: (owner, id) => get('SELECT * FROM email_templates WHERE id = ? AND user_id = ?', [id, owner]),
    recordView: (owner, id) => run('UPDATE email_templates SET view_count=view_count+1,last_viewed=CURRENT_TIMESTAMP WHERE id=? AND user_id=?', [id, owner]),
    recordPreview: (owner, id, detected) => run('INSERT INTO template_previews (template_id,user_id,preview_type,xss_detected,xss_payload) VALUES (?,?,?,?,?)', [id, owner, 'html', detected ? 1 : 0, detected ? 'XSS detected in preview' : null]),
    listProgress: owner => all('SELECT * FROM xss_challenge_progress WHERE user_id = ? ORDER BY challenge_level', [owner]),
    persistCompletion: ({ userId, level, challengeName, receipt }) => run(`INSERT OR REPLACE INTO xss_challenge_progress (user_id,challenge_level,challenge_name,completed,payload_used,completed_at,attempts) VALUES (?,?,?,1,?,CURRENT_TIMESTAMP,COALESCE((SELECT attempts FROM xss_challenge_progress WHERE user_id=? AND challenge_level=?),0)+1)`, [userId, level, challengeName, JSON.stringify(receipt), userId, level]),
    persistJudgment: row => run(`INSERT INTO xss_email_judge_receipts (user_id,challenge_level,template_id,verdict,judge_version,rubric_version,evidence_digest,run_id,error_code,browser_executed,browser_reason) VALUES (?,?,?,?,?,?,?,?,?,?,?)`, [row.userId, row.level, row.templateId, row.verdict, row.judgeVersion, row.rubricVersion, row.evidenceDigest, row.runId, row.errorCode, row.browserExecuted ? 1 : 0, row.browserReason]),
    async reset(owner) {
      await run('DELETE FROM template_previews WHERE template_id IN (SELECT id FROM email_templates WHERE user_id = ?)', [owner]);
      await run('DELETE FROM email_templates WHERE user_id = ?', [owner]);
      await run('DELETE FROM xss_challenge_progress WHERE user_id = ?', [owner]);
    },
  };
}
module.exports = { createSqliteEmailStore };
