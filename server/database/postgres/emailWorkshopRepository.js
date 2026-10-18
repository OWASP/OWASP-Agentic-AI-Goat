'use strict';

function createEmailWorkshopRepository(pool) {
  return {
    async saveConfiguredEmail(owner, email) {
      await pool.query('INSERT INTO identity.email_agent_progress(user_key,objective_number,completed,user_email) VALUES($1,1,0,$2) ON CONFLICT(user_key,objective_number) DO UPDATE SET user_email=excluded.user_email,updated_at=CURRENT_TIMESTAMP', [owner, email]);
    },
    async logSentEmail(owner, recipient, scenario, subject, messageId) {
      return (await pool.query('INSERT INTO identity.sent_emails_log(user_key,recipient_email,scenario_type,email_subject,gmail_message_id) VALUES($1,$2,$3,$4,$5) RETURNING id', [owner, recipient, scenario, subject, messageId])).rows[0];
    },
    async completeObjective(owner, objective, email) {
      await pool.query('INSERT INTO identity.email_agent_progress(user_key,objective_number,completed,user_email,completed_at) VALUES($1,$2,1,$3,CURRENT_TIMESTAMP) ON CONFLICT(user_key,objective_number) DO UPDATE SET completed=1,user_email=COALESCE(excluded.user_email,identity.email_agent_progress.user_email),completed_at=COALESCE(identity.email_agent_progress.completed_at,CURRENT_TIMESTAMP),updated_at=CURRENT_TIMESTAMP', [owner, objective, email]);
    },
    async listProgress(owner) {
      return (await pool.query('SELECT objective_number,completed,completed_at FROM identity.email_agent_progress WHERE user_key=$1 ORDER BY objective_number', [owner])).rows;
    },
    async resetProgress(owner) {
      await pool.query('DELETE FROM identity.email_agent_progress WHERE user_key=$1', [owner]);
    },
    async getConfiguredEmail(owner) {
      return (await pool.query('SELECT user_email FROM identity.email_agent_progress WHERE user_key=$1 AND user_email IS NOT NULL ORDER BY updated_at DESC,objective_number DESC LIMIT 1', [owner])).rows[0]?.user_email || null;
    }
  };
}
module.exports = {
  createEmailWorkshopRepository
};
