'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { createXssProfileOriginRepository } = require('../server/database/postgres/xssProfileOriginRepository');
const { randomUUID } = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

test('repository preserves PostgreSQL bigint generations as canonical decimal strings', async () => {
  const large = '9007199254740993';
  const value = 'model-owned';
  const pool = { query: async () => ({ rows: [{
    user_key: '17', value, revision: '3',
    origin_field: 'bio', platform_user_id: 17, origin_revision: '3',
    origin_value_sha256: require('node:crypto').createHash('sha256').update(value).digest('hex'),
    workshop_generation: large, run_id: 'run-ignored', owner_key: '["XSS","17"]',
    durable_generation: large, decision_source: 'model', provider: 'ollama', model: 'llama3.1:8b',
    raw_decision_sha256: 'a'.repeat(64), observation_index: 0, written_at: new Date(),
  }] }) };
  const repository = createXssProfileOriginRepository(pool);
  const snapshot = await repository.readCurrent({ userKey: '17', platformUserId: 17, field: 'bio' });
  assert.equal(snapshot.origin.workshopGeneration, large);
  assert.equal(snapshot.origin.durableGeneration, large);
});

function modelInput(scopeBinding) {
  const runId = scopeBinding?.runId || randomUUID();
  return {
    userKey:'17', platformUserId:17, field:'bio', value:'<b>scoped model value</b>',
    learnerMessage:'Generate an original profile biography.', workshopGeneration:'3',
    execution:{ runId, ownerKey:'["XSS","17"]', durableGeneration:'5', check:async()=>{},
      ...(scopeBinding ? { scopeBinding } : {}) },
    decision:{ modelSucceeded:true, decisionSource:'model', provider:'ollama', model:'llama3.1:8b',
      rawDecisionResponse:'{"action":"updateProfile"}' }, observationIndex:0,
  };
}

function scopedManualInput(overrides = {}) {
  const runId = overrides.runId || randomUUID();
  const ownerKey = '["XSS","17"]';
  const scopeBinding = Object.freeze({
    runId, ownerId:17, ownerKey, scopeKey:'stored_user',
    parentGeneration:'5', childGeneration:'7',
    ...(overrides.scopeBinding || {}),
  });
  return {
    userKey:'17', platformUserId:17, field:'bio', value:'<b>learner value</b>',
    execution:{ runId, ownerKey, durableGeneration:'5', check:overrides.check || (async()=>{}), scopeBinding },
    ...(overrides.input || {}),
  };
}

test('scoped manual writes reject inexact stored-user authority before connecting', async () => {
  let connected = false;
  const repository = createXssProfileOriginRepository({
    query:async()=>{ throw new Error('unused'); },
    connect:async()=>{ connected=true; throw new Error('must not connect'); },
  });
  const invalid = [
    scopedManualInput({scopeBinding:{scopeKey:'stored_llm'}}),
    scopedManualInput({scopeBinding:{ownerId:18}}),
    scopedManualInput({scopeBinding:{parentGeneration:'6'}}),
    scopedManualInput({scopeBinding:{childGeneration:'07'}}),
    scopedManualInput({input:{userKey:'18'}}),
  ];
  const unfrozen = scopedManualInput();
  unfrozen.execution.scopeBinding = {...unfrozen.execution.scopeBinding};
  invalid.push(unfrozen);
  for (const input of invalid) {
    await assert.rejects(async () => repository.writeScopedManualField(input), {code:'OWNER_MISMATCH'});
  }
  assert.equal(connected, false);
});

test('scoped manual write rolls profile and origin changes back when its final authority check is stale', async () => {
  const calls = [];
  let checks = 0;
  const stale = Object.assign(new Error('scope reset won'), {name:'AbortError', code:'XSS_SCOPE_STALE'});
  const client = {
    async query(sql, values) {
      calls.push([sql, values]);
      if (sql === 'BEGIN' || sql === 'ROLLBACK') return {rows:[]};
      if (sql.includes('INSERT INTO xss.profiles')) return {rows:[{revision:'9'}]};
      if (sql.includes('DELETE FROM xss.profile_model_origins')) return {rows:[]};
      throw new Error(`Unexpected SQL: ${sql}`);
    },
    release(error) { calls.push(['release', error]); },
  };
  const repository = createXssProfileOriginRepository({connect:async()=>client,
    query:async()=>{ throw new Error('unused'); }});
  const input = scopedManualInput({check:async()=>{
    checks += 1;
    if (checks === 2) throw stale;
  }});
  await assert.rejects(repository.writeScopedManualField(input), error => error === stale);
  assert.equal(checks, 2);
  assert.equal(calls.some(([sql]) => sql === 'COMMIT'), false);
  assert.equal(calls.filter(([sql]) => sql === 'ROLLBACK').length, 1);
  assert.equal(calls.filter(([sql]) => String(sql).includes('INSERT INTO xss.profiles')).length, 1);
  assert.equal(calls.filter(([sql]) => String(sql).includes('DELETE FROM xss.profile_model_origins')).length, 1);
  assert.deepEqual(calls.at(-1), ['release', undefined]);
});

test('repository writes scoped origin v2 with exact stored_llm child coordinates', async () => {
  const runId = randomUUID();
  const calls = [];
  const client = { query:async(sql, values) => {
    calls.push([sql, values]);
    if (sql === 'BEGIN' || sql === 'COMMIT') return { rows:[] };
    if (sql.includes('INSERT INTO xss.profiles')) return { rows:[{ revision:'4' }] };
    if (sql.includes('INSERT INTO xss.profile_model_origins')) return { rows:[{ written_at:'now' }] };
    throw new Error('Unexpected SQL');
  }, release() {} };
  const repository = createXssProfileOriginRepository({ connect:async()=>client, query:async()=>{ throw new Error('unused'); } });
  const input = modelInput(Object.freeze({ runId, ownerId:17, ownerKey:'["XSS","17"]',
    scopeKey:'stored_llm', parentGeneration:'5', childGeneration:'9007199254740993' }));
  const receipt = await repository.writeModelField(input);
  assert.equal(receipt.version, 'xss-profile-origin-v2');
  assert.equal(receipt.scopeKey, 'stored_llm');
  assert.equal(receipt.childGeneration, '9007199254740993');
  const originInsert = calls.find(([sql]) => sql.includes('INSERT INTO xss.profile_model_origins'));
  assert.deepEqual(originInsert[1].slice(-2), ['stored_llm', '9007199254740993']);
});

test('repository rejects inexact scoped bindings before profile mutation', async () => {
  const runId = randomUUID();
  let connected = false;
  const repository = createXssProfileOriginRepository({ query:async()=>{}, connect:async()=>{ connected=true; } });
  const base = { runId, ownerId:17, ownerKey:'["XSS","17"]', scopeKey:'stored_llm',
    parentGeneration:'5', childGeneration:'7' };
  for (const change of [
    { runId:randomUUID() }, { ownerId:18 }, { ownerKey:'["XSS","18"]' },
    { scopeKey:'stored_user' }, { parentGeneration:'6' }, { childGeneration:'07' }, { extra:true },
  ]) {
    const input = modelInput(base);
    input.execution.scopeBinding = { ...base, ...change };
    await assert.rejects(repository.writeModelField(input), { code:'OWNER_MISMATCH' });
  }
  assert.equal(connected, false);
});

test('repository projects persisted v2 child coordinates without bigint loss', async () => {
  const value = 'scoped-read';
  const childGeneration = '9007199254740993';
  const pool = { query:async()=>({ rows:[{
    user_key:'17', value, revision:'3', origin_field:'bio', platform_user_id:17,
    origin_revision:'3', origin_value_sha256:require('node:crypto').createHash('sha256').update(value).digest('hex'),
    workshop_generation:'3', run_id:randomUUID(), owner_key:'["XSS","17"]', durable_generation:'5',
    decision_source:'model', provider:'ollama', model:'llama3.1:8b', raw_decision_sha256:'a'.repeat(64),
    observation_index:0, scope_key:'stored_llm', child_generation:childGeneration, written_at:new Date(),
  }] }) };
  const snapshot = await createXssProfileOriginRepository(pool)
    .readCurrent({ userKey:'17', platformUserId:17, field:'bio' });
  assert.equal(snapshot.origin.version, 'xss-profile-origin-v2');
  assert.equal(snapshot.origin.scopeKey, 'stored_llm');
  assert.equal(snapshot.origin.childGeneration, childGeneration);
});

test('0010 reserves nullable child provenance and 0011 closes both single-null tuples', () => {
  const initial = fs.readFileSync(path.join(__dirname,
    '../db/postgres/workshop-migrations/xss/0010_profile_origin_child_scope.sql'), 'utf8');
  const repaired = fs.readFileSync(path.join(__dirname,
    '../db/postgres/workshop-migrations/xss/0011_profile_origin_child_scope_not_null.sql'), 'utf8');
  assert.match(initial, /ALTER TABLE xss\.profile_model_origins/);
  assert.match(initial, /ADD COLUMN scope_key text/);
  assert.match(initial, /ADD COLUMN child_generation bigint/);
  assert.match(repaired, /DROP CONSTRAINT profile_model_origins_child_scope/);
  assert.match(repaired, /scope_key IS NULL AND child_generation IS NULL/);
  assert.match(repaired, /scope_key IS NOT NULL AND child_generation IS NOT NULL/);
  assert.match(repaired, /scope_key='stored_llm' AND child_generation>=0/);
  for (const sql of [initial, repaired]) assert.doesNotMatch(sql, /\b(?:UPDATE|DELETE|TRUNCATE)\b/i);
});
