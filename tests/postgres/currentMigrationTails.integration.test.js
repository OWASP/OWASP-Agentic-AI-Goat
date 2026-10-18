'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { randomUUID } = require('node:crypto');
const { Pool } = require('pg');
const { migrate } = require('../../db/postgres/migrate');
const { hashValue } = require('../../server/database/postgres/ctfStageDefaultProvenance');
const stageSixPrior = require('../fixtures/ctfStage6PriorDefaults');
const stageSixCurrent = require('../../server/data/ctfDefaults').stages[5];

const root = path.join(__dirname, '../..');
const prefix = 'PG_CURRENT_MIGRATION_TAILS_';
const enabledFor = store => process.env.PG_TEST_DISPOSABLE === 'yes'
  && ['MIGRATION', 'RUNTIME'].every(role => process.env[`${prefix}${store}_${role}_URL`]);

function pool(url, applicationName) {
  const parsed = new URL(url);
  assert.equal(parsed.hostname, '127.0.0.1');
  assert.match(parsed.pathname, /^\/dvaia_test_[a-z0-9_]+$/);
  return new Pool({ connectionString: parsed.href, max: 3, application_name: applicationName,
    statement_timeout: 30000, lock_timeout: 5000, idle_in_transaction_session_timeout: 30000 });
}

function copyPrefix(t, migrationDirectory, lastName, label) {
  const workspace = process.env.DVAIA_ISOLATED_TEST_WORKSPACE;
  assert.equal(typeof workspace, 'string');
  const directory = fs.mkdtempSync(path.join(workspace, `${label}-prefix-`));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  for (const name of fs.readdirSync(migrationDirectory).sort()) {
    if (/^[0-9]{4}_/.test(name) && name <= lastName) {
    fs.symlinkSync(path.join(migrationDirectory, name), path.join(directory, name));
    }
  }
  assert.equal(fs.readdirSync(directory).sort().at(-1), lastName);
  return directory;
}

async function snapshot(poolValue, queries) {
  const rows = {};
  for (const [name, sql] of Object.entries(queries)) rows[name] = (await poolValue.query(sql)).rows;
  return rows;
}

test('ctf 0004 to 0005 preserves instructor and learner rows and classifies only exact defaults', {
  skip: !enabledFor('POPULATED_CTF'), timeout: 60000,
}, async t => {
  const migration = pool(process.env[`${prefix}POPULATED_CTF_MIGRATION_URL`], 'ctf-tail-migration');
  const runtime = pool(process.env[`${prefix}POPULATED_CTF_RUNTIME_URL`], 'ctf-tail-runtime');
  t.after(async () => Promise.allSettled([runtime.end(), migration.end()]));
  const directory = path.join(root, 'db/postgres/workshop-migrations/ctf');
  const prefixDirectory = copyPrefix(t, directory,
    '0004_system_prompt_default_provenance.sql', 'ctf-0004');
  assert.equal((await migrate(migration, prefixDirectory)).at(-1),
    '0004_system_prompt_default_provenance.sql');

  const stageOne = Number((await migration.query(`INSERT INTO ctf.ctf_stages
    (stage_number,stage_name,stage_description,ai_guardian_personality,hints,stage_order,defense_style)
    VALUES(1,'Prior default','default description','default guardian','default hints',1,'[]') RETURNING id`)).rows[0].id);
  const stageFive = Number((await migration.query(`INSERT INTO ctf.ctf_stages
    (stage_number,stage_name,stage_description,ai_guardian_personality,hints,stage_order,defense_style)
    VALUES(5,'Instructor stage','instructor description','instructor guardian','instructor hints',5,
      '["instructor_layer"]') RETURNING id`)).rows[0].id);
  const stageSix = Number((await migration.query(`INSERT INTO ctf.ctf_stages
    (stage_number,stage_name,stage_description,ai_guardian_personality,hints,
     system_prompt,success_criteria,stage_order,defense_style,level_score)
    VALUES(6,'Roleplay Warden',$1,'Instructor persona',$2,$3,'FORTRESS_OMEGA_X1',6,$4,500)
    RETURNING id`, [stageSixPrior.stage_description, stageSixPrior.hints,
    stageSixPrior.system_prompt, stageSixPrior.defense_style])).rows[0].id);
  for (const [field, state] of [['stage_description', 'managed'], ['hints', 'custom'],
    ['system_prompt', 'managed']]) {
    await migration.query(`INSERT INTO ctf.stage_default_fields
      (stage_number,field_name,provenance_state,applied_default_sha256,source_default_sha256)
      VALUES(6,$1,$2,$3,$4)`, [field, state,
      state === 'managed' ? hashValue(stageSixPrior[field]) : null,
      hashValue(stageSixPrior[field])]);
  }
  const participant = Number((await migration.query(`INSERT INTO ctf.ctf_participants
    (user_id,username,email,team_name) VALUES(7001,'tail learner','tail@example.test','tail team') RETURNING id`)).rows[0].id);
  await migration.query(`INSERT INTO ctf.ctf_progress
    (participant_id,stage_id,status,attempts_count,final_payload,techniques_used)
    VALUES($1,$2,'completed',1,'retained payload','["retained"]')`, [participant, stageOne]);
  await migration.query(`INSERT INTO ctf.ctf_attempts
    (participant_id,stage_id,attempt_number,payload,ai_response,was_successful,technique_tag)
    VALUES($1,$2,1,'retained attempt','retained response',1,'retained-technique')`,
  [participant, stageOne]);
  const queries = {
    stages: `SELECT stage_number,stage_name,stage_description,ai_guardian_personality,hints,defense_style
      FROM ctf.ctf_stages ORDER BY stage_number`,
    participants: `SELECT user_id,username,email,team_name FROM ctf.ctf_participants ORDER BY user_id`,
    progress: `SELECT participant_id,stage_id,status,attempts_count,final_payload,techniques_used
      FROM ctf.ctf_progress ORDER BY id`,
    attempts: `SELECT participant_id,stage_id,attempt_number,payload,ai_response,was_successful,technique_tag
      FROM ctf.ctf_attempts ORDER BY id`,
  };
  const before = await snapshot(migration, queries);
  const defensePrefix = copyPrefix(t, directory,
    '0005_defense_style_default_provenance.sql', 'ctf-0005');
  assert.deepEqual(await migrate(migration, defensePrefix), ['0005_defense_style_default_provenance.sql']);
  assert.deepEqual(await snapshot(migration, queries), before);
  const provenance = (await migration.query(`SELECT stage_number,provenance_state,
    applied_default_sha256 AS applied_hash
    FROM ctf.stage_default_fields WHERE field_name='defense_style' ORDER BY stage_number`)).rows;
  assert.equal(provenance.find(row => row.stage_number === 1).provenance_state, 'managed');
  assert.match(provenance.find(row => row.stage_number === 1).applied_hash, /^[a-f0-9]{64}$/);
  assert.deepEqual(provenance.find(row => row.stage_number === 5), {
    stage_number: 5, provenance_state: 'custom', applied_hash: null,
  });
  assert.equal(provenance.find(row => row.stage_number === 6).provenance_state, 'managed');
  await assert.rejects(runtime.query(`UPDATE ctf.stage_default_fields SET provenance_state='managed'
    WHERE stage_number=$1 AND field_name='defense_style'`, [stageFive]), error => error.code === '42501');
  const remaining = await migrate(migration, directory);
  assert.equal(remaining.at(-1), '0014_stage6_rotation_handoff_default.sql');
  const stageSixAfter = (await migration.query(`SELECT stage_description,hints,system_prompt,
    defense_style,success_criteria,level_score FROM ctf.ctf_stages WHERE id=$1`, [stageSix])).rows[0];
  assert.equal(stageSixAfter.stage_description, stageSixCurrent.stage_description);
  assert.equal(stageSixAfter.system_prompt, stageSixCurrent.system_prompt);
  assert.equal(stageSixAfter.defense_style, stageSixCurrent.defense_style);
  assert.equal(stageSixAfter.hints, stageSixPrior.hints, 'instructor-owned hints survive');
  assert.equal(stageSixAfter.success_criteria, 'FORTRESS_OMEGA_X1');
  assert.equal(stageSixAfter.level_score, 500);
  const stageSixProvenance = (await migration.query(`SELECT field_name,provenance_state,
    applied_default_sha256,source_default_sha256 FROM ctf.stage_default_fields
    WHERE stage_number=6 ORDER BY field_name`)).rows;
  for (const field of ['stage_description', 'system_prompt', 'defense_style']) {
    const row = stageSixProvenance.find(item => item.field_name === field);
    assert.equal(row.provenance_state, 'managed');
    assert.equal(row.applied_default_sha256, hashValue(stageSixCurrent[field]));
    assert.equal(row.source_default_sha256, hashValue(stageSixCurrent[field]));
  }
  assert.equal(stageSixProvenance.find(row => row.field_name === 'hints').provenance_state, 'custom');
  assert.deepEqual(await migrate(migration, directory), []);
});

test('agents 0016 to 0017 preserves sessions, conversations and run data while adding refund purpose', {
  skip: !enabledFor('POPULATED_AGENTS'), timeout: 60000,
}, async t => {
  const migration = pool(process.env[`${prefix}POPULATED_AGENTS_MIGRATION_URL`], 'agents-tail-migration');
  const runtime = pool(process.env[`${prefix}POPULATED_AGENTS_RUNTIME_URL`], 'agents-tail-runtime');
  t.after(async () => Promise.allSettled([runtime.end(), migration.end()]));
  const directory = path.join(root, 'db/postgres/workshop-migrations/secureshop_agents');
  const prefixDirectory = copyPrefix(t, directory,
    '0016_secureshop_bound_api_keys.sql', 'agents-0016');
  assert.equal((await migrate(migration, prefixDirectory)).at(-1),
    '0016_secureshop_bound_api_keys.sql');

  const launchId = randomUUID();
  const scenarioId = randomUUID();
  const conversationId = randomUUID();
  const personaSessionId = randomUUID();
  await migration.query(`INSERT INTO secureshop_agents.bound_persona_template_catalog
    (singleton,version,template_count,template_sha256) VALUES(true,1,3,$1)`, [Buffer.alloc(32, 1)]);
  await migration.query(`INSERT INTO secureshop_agents.bound_persona_templates
    (username,shop_user_id,email,password_hash,role,full_name,phone,source_sha256)
    VALUES('tail_customer',7001,'tail@example.test',$1,'customer','Tail Learner','555-0100',$2)`,
  [`$2b$12$${'a'.repeat(53)}`, Buffer.alloc(32, 2)]);
  await migration.query(`INSERT INTO secureshop_agents.bound_persona_sessions
    (session_id,jti_sha256,platform_launch_id,platform_scenario_id,platform_launch_generation,
     original_platform_owner_id,original_platform_session_id,shop_user_id,username,role,email,
     full_name,phone,expires_at,ip,user_agent,last_seen_at,credential_version)
    VALUES($1,$2,$3,$4,1,7001,7101,7001,'tail_customer','customer','tail@example.test',
      'Tail Learner','555-0100',clock_timestamp()+interval '1 hour','127.0.0.1','tail-agent',clock_timestamp(),1)`,
  [personaSessionId, Buffer.alloc(32, 3), launchId, scenarioId]);
  await migration.query(`INSERT INTO secureshop_agents.agent_sessions
    (id,user_id,role,messages_json,token_budget_used,authority_mode,binding_state,
     platform_launch_id,platform_scenario_id,platform_launch_generation,
     original_platform_owner_id,original_platform_session_id,conversation_purpose)
    VALUES($1,7001,'customer','[]',0,'launch_bound','pending',$2,$3,1,7001,7101,'review_moderation')`,
  [conversationId, launchId, scenarioId]);
  await migration.query(`UPDATE secureshop_agents.agent_sessions SET binding_state='active' WHERE id=$1`,
    [conversationId]);
  await migration.query(`INSERT INTO secureshop_agents.agent_trace
    (session_id,step,actor,kind,agent_ns,tool_name,params_json,result_json,provider,event_id)
    VALUES($1,1,'supervisor','final','review','moderate','{}','{"ok":true}','controlled',$2)`,
  [conversationId, randomUUID()]);
  const requestId = randomUUID();
  await migration.query(`INSERT INTO secureshop_agents.turn_requests
    (session_id,request_id,request_hash,claim_id) VALUES($1,$2,$3,$4)`,
  [conversationId, requestId, 'a'.repeat(64), randomUUID()]);
  await migration.query(`UPDATE secureshop_agents.turn_requests
    SET status='completed',result_json='{"ok":true}',finished_at=clock_timestamp()
    WHERE session_id=$1 AND request_id=$2`, [conversationId, requestId]);
  const queries = {
    personaSessions: `SELECT session_id,jti_sha256,platform_launch_id,platform_scenario_id,
      platform_launch_generation,original_platform_owner_id,original_platform_session_id,
      shop_user_id,username,role,email,full_name,phone,expires_at,revoked_at,ip,user_agent,
      last_seen_at,credential_version FROM secureshop_agents.bound_persona_sessions ORDER BY session_id`,
    conversations: `SELECT id,user_id,role,messages_json,token_budget_used,authority_mode,binding_state,
      platform_launch_id,platform_scenario_id,platform_launch_generation,original_platform_owner_id,
      original_platform_session_id,conversation_purpose FROM secureshop_agents.agent_sessions ORDER BY id`,
    traces: `SELECT session_id,step,actor,kind,agent_ns,tool_name,params_json,result_json,provider,event_id
      FROM secureshop_agents.agent_trace ORDER BY id`,
    turns: `SELECT session_id,request_id,request_hash,request_version,claim_id,status,result_json,finished_at
      FROM secureshop_agents.turn_requests ORDER BY session_id,request_id`,
  };
  const before = await snapshot(migration, queries);
  assert.deepEqual(await migrate(migration, directory), ['0017_secureshop_refund_conversation_purpose.sql']);
  assert.deepEqual(await snapshot(migration, queries), before);

  await migration.query(`INSERT INTO secureshop_agents.agent_sessions
    (id,user_id,role,messages_json,token_budget_used,authority_mode,binding_state,
     platform_launch_id,platform_scenario_id,platform_launch_generation,
     original_platform_owner_id,original_platform_session_id,conversation_purpose)
    VALUES($1,7001,'customer','[]',0,'launch_bound','pending',$2,$3,1,7001,7101,
      'secureshop_refund_request')`, [randomUUID(), launchId, scenarioId]);
  await assert.rejects(migration.query(`INSERT INTO secureshop_agents.agent_sessions
    (id,user_id,role,messages_json,token_budget_used,authority_mode,binding_state,
     platform_launch_id,platform_scenario_id,platform_launch_generation,
     original_platform_owner_id,original_platform_session_id,conversation_purpose)
    VALUES($1,7002,'customer','[]',0,'launch_bound','pending',$2,$3,1,7001,7101,'invalid')`,
  [randomUUID(), launchId, scenarioId]), error => error.code === '23514');
  assert.deepEqual(await migrate(migration, directory), []);
});
