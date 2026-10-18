const queues = new WeakMap();

const run = (db, sql, params = []) => new Promise((resolve, reject) => {
  db.run(sql, params, function onRun(error) {
    if (error) return reject(error);
    resolve({ lastID: this.lastID, changes: this.changes });
  });
});

const get = (db, sql, params = []) => new Promise((resolve, reject) =>
  db.get(sql, params, (error, row) => error ? reject(error) : resolve(row)));

const all = (db, sql, params = []) => new Promise((resolve, reject) =>
  db.all(sql, params, (error, rows) => error ? reject(error) : resolve(rows || [])));

function withImmediateTransaction(db, work) {
  const previous = queues.get(db) || Promise.resolve();
  const transaction = previous.catch(() => {}).then(async () => {
    await run(db, 'BEGIN IMMEDIATE');
    try {
      const result = await work({
        run: (sql, params) => run(db, sql, params),
        get: (sql, params) => get(db, sql, params),
        all: (sql, params) => all(db, sql, params),
      });
      await run(db, 'COMMIT');
      return result;
    } catch (error) {
      try {
        await run(db, 'ROLLBACK');
      } catch (rollbackError) {
        error.rollbackError = rollbackError;
      }
      throw error;
    }
  });

  queues.set(db, transaction.catch(() => {}));
  return transaction;
}

module.exports = { run, get, all, withImmediateTransaction };
