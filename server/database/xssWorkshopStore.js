'use strict';

const PROFILE_FIELDS = new Set(['name', 'bio', 'website']);
function profileField(field) {
  if (!PROFILE_FIELDS.has(field)) throw new Error('Unknown profile field');
  return field;
}
function callbackResult(promise, callback) {
  if (callback) promise.then(value => callback(null, value), error => callback(error));
  return promise;
}

// Temporary legacy implementation of the explicit workshop interface. All HTML
// remains raw: stored-XSS and prompt-injection payloads are the lesson material.
function createLegacyXssWorkshopStore(db) {
  const query = (method, sql, params, callback) => callbackResult(new Promise((resolve, reject) => {
    db[method](sql, params, function (error, result) {
      if (error) reject(error);else resolve(method === 'run' ? {
        changes: this.changes,
        lastID: this.lastID
      } : result);
    });
  }), callback);
  return {
    updateProfileField: (owner, field, value, cb) => query('run', `INSERT INTO xss_workshop_profiles (user_key, ${profileField(field)}, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP) ON CONFLICT(user_key) DO UPDATE SET ${profileField(field)}=excluded.${profileField(field)}, updated_at=CURRENT_TIMESTAMP`, [owner, value], cb),
    getProfile: (owner, cb) => query('get', 'SELECT name,bio,website FROM xss_workshop_profiles WHERE user_key=?', [owner], cb),
    listProgress: (owner, cb) => query('all', 'SELECT objective_id,completed,completed_at FROM xss_workshop_progress WHERE user_key=?', [owner], cb),
    completeObjective: (owner, objective, cb) => query('run', 'INSERT INTO xss_workshop_progress(user_key,objective_id,completed,completed_at) VALUES(?,?,1,CURRENT_TIMESTAMP) ON CONFLICT(user_key,objective_id) DO UPDATE SET completed=1,completed_at=CURRENT_TIMESTAMP', [owner, objective], cb),
    resetProfile: (owner, cb) => query('run', "INSERT INTO xss_workshop_profiles(user_key,name,bio,website,updated_at) VALUES(?,'Security Student','Learning about web security.','https://example.com',CURRENT_TIMESTAMP) ON CONFLICT(user_key) DO UPDATE SET name=excluded.name,bio=excluded.bio,website=excluded.website,updated_at=CURRENT_TIMESTAMP", [owner], cb),
    resetProgress: (owner, objectives, cb) => query('run', `DELETE FROM xss_workshop_progress WHERE user_key=?${objectives ? ` AND objective_id IN (${objectives.map(() => '?').join(',')})` : ''}`, [owner, ...(objectives || [])], cb),
    listEmails: (owner, cb) => {
      // Keep the legacy adapter compatible with the active route's owner
      // contract while retaining its historical no-owner fixture helper.
      if (typeof owner === 'function') { cb = owner; owner = null; }
      return owner
        ? query('all', 'SELECT id,subject,sender,received_at FROM xss_workshop_emails WHERE user_key IS NULL OR user_key=? ORDER BY received_at DESC', [owner], cb)
        : query('all', 'SELECT id,subject,sender,received_at FROM xss_workshop_emails ORDER BY received_at DESC', [], cb);
    }
  };
}
module.exports = {
  createLegacyXssWorkshopStore,
  callbackResult,
  profileField
};
