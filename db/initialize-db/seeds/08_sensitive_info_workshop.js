'use strict';
// Seeds for sensitive_info_workshop.db — finflow solution content

const sqlite3 = require('sqlite3').verbose();

function openDatabase(dbPath) {
  return new Promise((resolve, reject) => {
    const db = new sqlite3.Database(dbPath, (err) => {
      if (!err) return resolve(db);
      db.close(() => reject(err));
    });
  });
}

function run(db, sql, params = []) {
  return new Promise((resolve, reject) => db.run(sql, params, function onRun(err) {
    if (err) reject(err);
    else resolve(this);
  }));
}

function prepare(db, sql) {
  return new Promise((resolve, reject) => {
    const statement = db.prepare(sql, (err) => err ? reject(err) : resolve(statement));
  });
}

function runStatement(statement, params) {
  return new Promise((resolve, reject) => statement.run(params, function onRun(err) {
    if (err) reject(err);
    else resolve(this);
  }));
}

function finalize(statement) {
  return new Promise((resolve, reject) => statement.finalize(err => err ? reject(err) : resolve()));
}

function close(db) {
  return new Promise((resolve, reject) => db.close(err => err ? reject(err) : resolve()));
}

function combineFailure(current, next, message) {
  return current ? new AggregateError([current, next], message) : next;
}

async function runSeed(dbPath, { loadSolutions = () => require('../../../server/data/sensitiveInfoSolutions') } = {}) {
  if (typeof loadSolutions !== 'function') throw new TypeError('Solution loader must be a function');
  const db = await openDatabase(dbPath);
  let transactionOpen = false;
  let failure = null;
  let count = 0;

  try {
    let solutions;
    try {
      ({ solutions } = loadSolutions());
    } catch (e) {
      throw new Error('Could not load sensitiveInfoSolutions', { cause: e });
    }
    if (!solutions || typeof solutions !== 'object' || Array.isArray(solutions)) {
      throw new TypeError('sensitiveInfoSolutions must export a solutions object');
    }

    await run(db, 'BEGIN TRANSACTION');
    transactionOpen = true;

    const statement = await prepare(db,
      `INSERT INTO finflow_solutions
         (objective_id, title, difficulty, hints, examples, approach, tips, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
       ON CONFLICT(objective_id) DO NOTHING`);

    let statementFailure = null;
    try {
      for (const [objectiveId, sol] of Object.entries(solutions)) {
        await runStatement(statement, [
          objectiveId,
          sol.title,
          sol.difficulty,
          JSON.stringify(sol.hints || []),
          JSON.stringify(sol.examples || []),
          sol.approach || '',
          JSON.stringify(sol.tips || [])
        ]);
      }
    } catch (error) {
      statementFailure = error;
    }
    try {
      await finalize(statement);
    } catch (error) {
      statementFailure = combineFailure(statementFailure, error, 'Sensitive Info seed statement failed');
    }
    if (statementFailure) throw statementFailure;

    await run(db, 'COMMIT');
    transactionOpen = false;
    count = Object.keys(solutions).length;
  } catch (error) {
    failure = error;
    if (transactionOpen) {
      try {
        await run(db, 'ROLLBACK');
        transactionOpen = false;
      } catch (rollbackError) {
        failure = combineFailure(failure, rollbackError, 'Sensitive Info seed and rollback failed');
      }
    }
  }

  try {
    await close(db);
  } catch (closeError) {
    failure = combineFailure(failure, closeError, 'Sensitive Info seed and close failed');
  }
  if (failure) throw failure;
  console.log('   ✓ Seeded finflow_solutions (' + count + ' rows)');
}

module.exports = { runSeed };
