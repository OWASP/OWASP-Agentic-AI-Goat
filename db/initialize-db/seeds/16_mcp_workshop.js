'use strict';

/**
 * MCP Workshop seed
 * -----------------
 * No fixed seed data — progress and tool logs are populated as students
 * interact with the lab. Stub exists so run-all.js wiring is uniform.
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
