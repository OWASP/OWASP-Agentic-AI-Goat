'use strict';

const { withImmediateTransaction } = require('./sqliteTransaction');

const TRACKING_TABLES = [
  'workshop_chat_history',
  'workshop_progress',
  'workshop_achievements',
  'extracted_files',
];

function createSensitiveUserDataReset({ db, restoreSensitiveFiles } = {}) {
  if (!db || typeof db.serialize !== 'function' || typeof db.run !== 'function') {
    throw new TypeError('Sensitive Info user reset requires a SQLite database');
  }
  if (typeof restoreSensitiveFiles !== 'function') {
    throw new TypeError('Sensitive Info user reset requires a sensitive-file restore function');
  }

  const prepare = () => Promise.resolve().then(() => restoreSensitiveFiles());
  const resetUserInTransaction = async (tx, userId) => {
    for (const table of TRACKING_TABLES) {
      await tx.run(`DELETE FROM ${table} WHERE user_id = ?`, [userId]);
    }
  };
  const resetAllInTransaction = async (tx) => {
    for (const table of TRACKING_TABLES) await tx.run(`DELETE FROM ${table}`);
  };

  async function resetUserData(userId) {
    // File restoration is idempotent but not transactional. Complete it before
    // opening the database transaction so a filesystem failure cannot delete
    // any user progress.
    await prepare();
    return withImmediateTransaction(db, (tx) => resetUserInTransaction(tx, userId));
  }

  resetUserData.prepare = prepare;
  resetUserData.resetUserInTransaction = resetUserInTransaction;
  resetUserData.resetAllInTransaction = resetAllInTransaction;
  return resetUserData;
}

module.exports = { createSensitiveUserDataReset };
