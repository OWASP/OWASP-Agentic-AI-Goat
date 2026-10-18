'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { createXssScopeAuthorityRepository } = require(
  '../server/database/postgres/xssScopeAuthorityRepository');

const RUN = '11111111-1111-4111-8111-111111111111';
const OWNER_ID = 17;
const OWNER_KEY = JSON.stringify(['XSS', String(OWNER_ID)]);

function context(overrides = {}) {
  return {
    runId:RUN, ownerKey:OWNER_KEY, durableGeneration:'4',
    scope:{ userId:OWNER_ID, scopeKey:'stored_user' }, ...overrides,
  };
}

function clientFixture() {
  const state = {
    user:true, parentGeneration:'4', run:true, deletionBlock:false,
    childGeneration:'0', childState:'active', binding:null, queries:[],
  };
  return {
    state,
    async query(sql, params = []) {
      const compact = sql.replace(/\s+/g, ' ').trim();
      state.queries.push([compact, params]);
      if (compact.includes('FROM identity.bind_xss_run_scope(')) {
        const available = state.user && state.parentGeneration === String(params[4]) && state.run
          && !state.deletionBlock && state.childGeneration !== null && state.childState === 'active';
        if (!available) throw Object.assign(new Error('authority unavailable'), { code:'55000' });
        const [runId, ownerId, ownerKey, scopeKey, parentGeneration, childGeneration] = params;
        state.binding = { runId, ownerId, ownerKey, scopeKey, parentGeneration,
          childGeneration:state.childGeneration };
        return { rowCount:1, rows:[state.binding] };
      }
      if (compact.includes('FROM identity.assert_xss_run_scope_current(')) {
        const current = state.binding && state.user && !state.deletionBlock
          && state.parentGeneration === state.binding.parentGeneration
          && state.childState === 'active' && state.childGeneration === state.binding.childGeneration
          && params.every((value, index) => String(value) === String(Object.values(state.binding)[index]));
        return { rowCount:current ? 1 : 0, rows:current ? [{ ...state.binding }] : [] };
      }
      throw new Error(`Unexpected SQL: ${compact}`);
    },
  };
}

test('bindRun uses only its caller transaction and returns exact immutable parent/child coordinates', async () => {
  const client = clientFixture();
  const repository = createXssScopeAuthorityRepository();
  const binding = await repository.bindRun(client, context());
  assert.deepEqual(binding, {
    runId:RUN, ownerId:OWNER_ID, ownerKey:OWNER_KEY, scopeKey:'stored_user',
    parentGeneration:'4', childGeneration:'0',
  });
  assert.equal(Object.isFrozen(binding), true);
  assert.equal(client.state.queries.some(([sql]) => /^(BEGIN|COMMIT|ROLLBACK)$/.test(sql)), false);
  assert.equal('connect' in client, false);
  const inserted = client.state.queries.find(([sql]) => sql.includes('identity.bind_xss_run_scope'));
  assert.deepEqual(inserted[1], [RUN, OWNER_ID, OWNER_KEY, 'stored_user', '4']);
});

test('assertRunCurrent requires the exact returned binding and rejects parent, child, owner and deletion drift', async () => {
  const repository = createXssScopeAuthorityRepository();
  const client = clientFixture();
  const scopeBinding = await repository.bindRun(client, context());
  assert.deepEqual(await repository.assertRunCurrent(client, context({ scopeBinding })), scopeBinding);
  const queryCount = client.state.queries.length;
  for (const mutation of [
    value => { value.childGeneration = '1'; },
    value => { value.parentGeneration = '5'; },
    value => { value.ownerId = 18; },
    value => { value.ownerId = true; },
    value => { value.scopeKey = 'email'; },
  ]) {
    const altered = { ...scopeBinding }; mutation(altered);
    await assert.rejects(repository.assertRunCurrent(client, context({ scopeBinding:altered })),
      { name:'AbortError', code:'XSS_SCOPE_STALE' });
  }
  // A forged child cannot be rejected from the parent context alone; the
  // exact child coordinate is compared by the authoritative SQL function.
  assert.equal(client.state.queries.length, queryCount + 1);
  client.state.childGeneration = '1';
  await assert.rejects(repository.assertRunCurrent(client, context({ scopeBinding })),
    { name:'AbortError', code:'XSS_SCOPE_STALE' });
  client.state.childGeneration = '0'; client.state.parentGeneration = '5';
  await assert.rejects(repository.assertRunCurrent(client, context({ scopeBinding })),
    { name:'AbortError', code:'XSS_SCOPE_STALE' });
  client.state.parentGeneration = '4'; client.state.deletionBlock = true;
  await assert.rejects(repository.assertRunCurrent(client, context({ scopeBinding })),
    { name:'AbortError', code:'XSS_SCOPE_STALE' });
});

test('bindRun fails closed for noncanonical owners, open scopes, deletion, missing runs and unsafe generations', async () => {
  const repository = createXssScopeAuthorityRepository();
  for (const bad of [
    { ownerKey:'["XSS","18"]' },
    { scope:{ userId:OWNER_ID, scopeKey:'caller_scope' } },
    { scope:{ userId:'anon_session', scopeKey:'email' } },
    { scope:{ userId:true, scopeKey:'email' } },
    { durableGeneration:Number.MAX_SAFE_INTEGER + 1 },
    { runId:'not-a-run' },
  ]) await assert.rejects(repository.bindRun(clientFixture(), context(bad)), TypeError);

  const deleted = clientFixture(); deleted.state.user = false;
  await assert.rejects(repository.bindRun(deleted, context()), { name:'AbortError' });
  const blocked = clientFixture(); blocked.state.deletionBlock = true;
  await assert.rejects(repository.bindRun(blocked, context()), { name:'AbortError' });
  const missingRun = clientFixture(); missingRun.state.run = false;
  await assert.rejects(repository.bindRun(missingRun, context()), { name:'AbortError' });
  const closed = clientFixture(); closed.state.childState = 'resetting';
  await assert.rejects(repository.bindRun(closed, context()), { name:'AbortError' });
});

test('0070 authority plus forward-only 0071 conflict correction remain inactive and least privilege', () => {
  const migrations = path.join(__dirname, '../db/postgres/identity-migrations');
  const files = fs.readdirSync(migrations).filter(name => /^\d{4}_.*\.sql$/.test(name)).sort();
  assert.equal(files.includes('0071_xss_scope_bind_conflict_fix.sql'), true);
  assert.equal(files.some(name => name.startsWith('0068_')), false);
  const sql = fs.readFileSync(path.join(migrations, '0070_xss_scope_authority.sql'), 'utf8');
  const correction = fs.readFileSync(path.join(migrations, '0071_xss_scope_bind_conflict_fix.sql'), 'utf8');
  assert.match(sql, /scope_key IN \('reflected','stored_user','stored_llm','email'\)/);
  assert.match(sql, /child_generation bigint NOT NULL DEFAULT 0/);
  assert.match(sql, /state IN \('active','resetting','deleted'\)/);
  assert.match(sql, /REFERENCES graph_runtime\.runs\(run_id\) ON DELETE CASCADE/);
  assert.match(sql, /BEFORE INSERT ON identity\.xss_scope_state/);
  assert.match(sql, /NEW\.child_generation<>0 OR NEW\.state<>'active'/);
  assert.match(sql, /BEFORE INSERT ON identity\.xss_run_bindings/);
  assert.match(sql, /BEFORE UPDATE ON identity\.xss_run_bindings/);
  assert.match(sql, /NOT EXISTS\(SELECT 1 FROM identity\.student_deletion_jobs/);
  assert.match(sql, /SECURITY DEFINER[\s\S]*SET search_path=pg_catalog,identity,graph_runtime/);
  assert.match(sql, /CREATE FUNCTION identity\.assert_xss_run_scope_current/);
  assert.match(sql, /FOR SHARE OF b,u,o,r,s/);
  assert.match(sql, /REVOKE ALL ON identity\.xss_scope_state,identity\.xss_run_bindings[\s\S]*FROM PUBLIC,dvaia_identity_runtime/);
  assert.match(sql, /GRANT EXECUTE ON FUNCTION identity\.bind_xss_run_scope/);
  assert.doesNotMatch(sql, /GRANT (?:SELECT|INSERT|UPDATE|DELETE)[^;]*xss_(?:scope_state|run_bindings)/i);
  assert.doesNotMatch(sql, /GRANT[^;]*(?:UPDATE|DELETE)[^;]*xss_(?:scope_state|run_bindings)/i);
  assert.doesNotMatch(sql, /CREATE TABLE identity\.xss_(?:reset_operations|reset_steps|artifact_bindings|artifact_retirements)/);
  assert.doesNotMatch(sql, /^\s*(?:DROP|TRUNCATE)\b/im);
  assert.match(correction, /CREATE OR REPLACE FUNCTION identity\.bind_xss_run_scope/);
  assert.match(correction, /ON CONFLICT ON CONSTRAINT xss_scope_state_pkey DO NOTHING/);
  assert.doesNotMatch(correction, /ON CONFLICT\s*\(owner_id,scope_key\)/);
  assert.doesNotMatch(correction, /^\s*(?:DROP|TRUNCATE)\b/im);
});
