'use strict';

/**
 * CSRF Workshop seed
 * -------------------
 * The CSRF workshop has no fixed seed data — wallets, objectives, and the tool
 * activity log are populated as students interact with the lab. We still
 * implement runSeed so run-all.js wiring is uniform with the other workshop
 * databases and so future seed needs (e.g. demo accounts) have a place to land.
 */

const sqlite3 = require('sqlite3').verbose();

async function runSeed(dbPath) {
  return new Promise((resolve, reject) => {
    const db = new sqlite3.Database(dbPath, (err) => {
      if (err) return reject(err);
      db.close((closeErr) => (closeErr ? reject(closeErr) : resolve()));
    });
  });
}

module.exports = { runSeed };
