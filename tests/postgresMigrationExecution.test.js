'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { createHash } = require('node:crypto');
const { executionSql, readMigrations } = require('../db/postgres/migrate');

const directory = path.join(__dirname, '../db/postgres/workshop-migrations/ctf');
const name = '0004_system_prompt_default_provenance.sql';
const sql = fs.readFileSync(path.join(directory, name), 'utf8');

test('historical CTF wrapper executes within loader transaction without changing history or function body', async () => {
  const migration = (await readMigrations(directory)).find(row => row.name === name);
  const expected = sql.slice('BEGIN;\n'.length, -'COMMIT;\n'.length);
  assert.equal(executionSql(migration), expected);
  assert.match(expected, /DECLARE field text;\nBEGIN\n/);
  assert.match(expected, /END;\n\$\$;/);
  assert.equal(migration.sql, sql);
  assert.equal(migration.checksum, createHash('sha256').update(sql).digest('hex'));
});

test('execution exception cannot match by supplied checksum, filename alone or content alone', () => {
  assert.equal(executionSql({ name: 'other.sql', sql }), sql);
  const modified = sql + '-- changed\n';
  assert.equal(executionSql({ name, sql: modified,
    checksum: 'a41d0235686dd7e40189ec47c5f65cf06578c9663b3b33751075dd32d5d1112c' }), modified);
  const body = 'DO $$ BEGIN PERFORM 1; END; $$;';
  assert.equal(executionSql({ name, sql: body }), body);
});

test('historical mail purpose migration retains every previously admitted purpose without rewriting history', async () => {
  const agents = path.join(__dirname, '../db/postgres/workshop-migrations/secureshop_agents');
  const migrations = await readMigrations(agents);
  const previous = migrations.find(row => row.name === '0086_idor_lesson_conversation_purpose.sql');
  const current = migrations.find(row => row.name === '0091_mail_summary_conversation_purpose.sql');
  const original = current.sql;
  const purposeList = text => [...text.match(/conversation_purpose IN \(([\s\S]*?)\)/)[1]
    .matchAll(/'([^']+)'/g)].map(match => match[1]);
  const executed = executionSql(current);
  const actual = purposeList(executed);
  for (const purpose of purposeList(previous.sql)) assert.ok(actual.includes(purpose), purpose);
  assert.equal(actual.filter(value => value === 'secureshop_idor_lesson').length, 1);
  assert.ok(actual.includes('secureshop_mail_summary'));
  assert.equal(executed.replace(
    "'secureshop_admin_assistant','secureshop_idor_lesson'", "'secureshop_admin_assistant'"), original);
  assert.equal(current.sql, original);
  assert.equal(current.checksum, createHash('sha256').update(original).digest('hex'));
  assert.equal(executionSql({ ...current, name: 'other.sql' }), original);
  const modified = original + '-- changed\n';
  assert.equal(executionSql({ ...current, sql: modified }), modified);
});
