'use strict';

const {
  createPool
} = require('./index');
const {
  initialize,
  singleton
} = require('./workshopSupport');
const {
  callbackResult,
  profileField
} = require('../xssWorkshopStore');
const {
  createXssProfileOriginRepository
} = require('./xssProfileOriginRepository');
const { isAnonymousOwner } = require('./xssProfileOriginRepository');
function createXssWorkshopDb(pool) {
  const query = (sql, params, cb, single = false) => callbackResult(pool.query(sql, params).then(result => single ? result.rows[0] : result.rows), cb);
  const emailBuilder = require('./xssEmailStore').createPostgresEmailStore(pool);
  const originRepository = createXssProfileOriginRepository(pool);
  const scopedProfileReset = require('./xssScopedProfileResetRepository').createXssScopedProfileResetRepository(pool);
  return {
    getScopedProfileResetRepository: () => scopedProfileReset,
    async getSolutionsEnabled() {
      const result = await pool.query("SELECT config_value FROM xss.legacy_challenge_config WHERE config_key='solutions_enabled'");
      return result.rows.length ? JSON.parse(result.rows[0].config_value) : false;
    },
    async setSolutionsEnabled(value) {
      await pool.query("INSERT INTO xss.legacy_challenge_config(config_key,config_value) VALUES('solutions_enabled',$1) ON CONFLICT(config_key) DO UPDATE SET config_value=excluded.config_value,updated_at=CURRENT_TIMESTAMP", [JSON.stringify(value) ?? null]);
    },
    emailBuilderCall: (name, ...args) => emailBuilder[name](...args),
    async initializeXssWorkshopDb(migrationPool) {
      const owned = !migrationPool;
      migrationPool ||= createPool(process.env, 'XSS_WORKSHOP_MIGRATION_DATABASE_URL');
      try {
        await initialize(pool, migrationPool, 'xss', async () => {});
      } finally {
        if (owned) await migrationPool.end();
      }
    },
    writeModelProfileField: input => originRepository.writeModelField(input),
    writeScopedManualProfileField: input => originRepository.writeScopedManualField(input),
    readCurrentProfileField: input => originRepository.readCurrent(input),
    updateAnonymousProfileField: (owner, field, value, cb) => callbackResult(originRepository.writeAnonymousField({ userKey: owner, field, value }), cb),
    updateProfileField: (owner, field, value, cb) => callbackResult(
      isAnonymousOwner(owner) ? originRepository.writeAnonymousField({ userKey: owner, field, value })
        : originRepository.writeManualField({ userKey: owner, platformUserId: Number(owner), field, value }), cb),
    getProfile: (owner, cb) => query('SELECT name,bio,website FROM xss.profiles WHERE user_key=$1', [owner], cb, true),
    listProgress: (owner, cb) => query('SELECT objective_id,completed,completed_at FROM xss.progress WHERE user_key=$1 ORDER BY objective_id', [owner], cb),
    completeObjective: (owner, objective, cb) => query('INSERT INTO xss.progress(user_key,objective_id,completed,completed_at) VALUES($1,$2,1,CURRENT_TIMESTAMP) ON CONFLICT(user_key,objective_id) DO UPDATE SET completed=1,completed_at=CURRENT_TIMESTAMP', [owner, objective], cb),
    resetAnonymousProfile: (owner, cb) => callbackResult(originRepository.resetAnonymousProfile({ userKey: owner }), cb),
    resetProfile: (owner, cb) => callbackResult(
      isAnonymousOwner(owner) ? originRepository.resetAnonymousProfile({ userKey: owner })
        : originRepository.resetProfile({ userKey: owner, platformUserId: Number(owner) }), cb),
    resetProgress: (owner, objectives, cb) => query('DELETE FROM xss.progress WHERE user_key=$1' + (objectives ? ' AND objective_id=ANY($2::text[])' : ''), objectives ? [owner, objectives] : [owner], cb),
    // Public archive rows (user_key IS NULL) are visible to every workshop
    // session; imported/learner rows are visible only to their owner.  The
    // owner is supplied by the server-derived route identity, never by the model.
    listEmails: (owner, cb) => {
      if (typeof owner !== 'string' || !owner.length) {
        throw new TypeError('XSS email owner is required');
      }
      return query(
        'SELECT id,subject,sender,received_at FROM xss.emails WHERE user_key IS NULL OR user_key=$1 ORDER BY received_at DESC,id DESC',
        [owner], cb
      );
    }
  };
}
const lazy = singleton(createXssWorkshopDb, 'XSS_WORKSHOP_DATABASE_URL');
const api = Object.fromEntries(['getScopedProfileResetRepository', 'getSolutionsEnabled', 'setSolutionsEnabled', 'emailBuilderCall', 'initializeXssWorkshopDb',
  'writeModelProfileField', 'writeScopedManualProfileField', 'readCurrentProfileField', 'updateAnonymousProfileField', 'updateProfileField', 'getProfile', 'listProgress',
  'completeObjective', 'resetAnonymousProfile', 'resetProfile', 'resetProgress', 'listEmails'].map(name => [name, lazy(name)]));
module.exports = {
  getXssWorkshopPool: lazy.getPool,
  ...api,
  emailBuilder: Object.fromEntries(['assertBuilderResetReady','clearBuilder','getProfile','ensureProfile','updateProfile','saveTemplate','listTemplates','getTemplate','recordView','recordPreview','listProgress','persistCompletion','persistJudgment','reset'].map(name => [name, (...args) => api.emailBuilderCall(name, ...args)])),
  createXssWorkshopDb
};
