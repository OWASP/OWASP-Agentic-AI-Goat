/**
 * Seed supply chain workshop solutions into sc_solutions table.
 */

const sqlite3 = require('sqlite3').verbose();
const { solutions } = require('../../../server/data/supplyChainSolutions');

async function runSeed(dbPath) {
  return new Promise((resolve, reject) => {
    const db = new sqlite3.Database(dbPath, (err) => {
      if (err) return reject(err);

      db.serialize(() => {
        const stmt = db.prepare(`
          INSERT OR REPLACE INTO sc_solutions
            (objective_id, title, difficulty, hints, examples, approach, tips, updated_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))
        `);

        for (const [objectiveId, sol] of Object.entries(solutions)) {
          stmt.run(
            objectiveId,
            sol.title,
            sol.difficulty,
            JSON.stringify(sol.hints || []),
            JSON.stringify(sol.examples || []),
            sol.approach || '',
            JSON.stringify(sol.tips || [])
          );
        }

        stmt.finalize((err) => {
          if (err) {
            db.close();
            return reject(err);
          }
          db.close(resolve);
        });
      });
    });
  });
}

module.exports = { runSeed };
