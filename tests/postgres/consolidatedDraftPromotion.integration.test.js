'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');
const { createHash, randomUUID } = require('node:crypto');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const { migrate, readMigrations } = require('../../db/postgres/migrate');
const { seedWorkshopPlatform } = require('../../server/database/postgres/workshopPlatformSeed');

const PREFIX = 'PG_CONSOLIDATED_DRAFT_PROMOTION_';
const VARIANTS = ['FRESH', 'POPULATED'];
const STORES = ['IDENTITY', 'AGENTS', 'REVIEW', 'NOVA'];
const enabled = process.env.PG_TEST_DISPOSABLE === 'yes' && VARIANTS.every(variant =>
  STORES.every(store => ['MIGRATION', 'RUNTIME'].every(role =>
    process.env[`${PREFIX}${variant}_${store}_${role}_URL`])));
const root = path.join(__dirname, '../..');
const definitions = Object.freeze({
  identity: { baseline: 'db/postgres/identity-migrations', manifestStore: 'identity' },
  agents: { baseline: 'db/postgres/workshop-migrations/secureshop_agents', manifestStore: 'secureshop_agents' },
  review: { baseline: 'db/postgres/workshop-migrations/secureshop_review', manifestStore: 'secureshop_review' },
  nova: { baseline: 'db/postgres/workshop-migrations/nova', manifestStore: 'nova' },
});
const digest = value => createHash('sha256').update(value).digest('hex');
const read = relative => fs.readFile(path.join(root, relative), 'utf8');
function pools(variant) {
  return Object.fromEntries(STORES.map(name => [name.toLowerCase(), {
    migration: new Pool({ connectionString: process.env[`${PREFIX}${variant}_${name}_MIGRATION_URL`], max: 2 }),
    runtime: new Pool({ connectionString: process.env[`${PREFIX}${variant}_${name}_RUNTIME_URL`], max: 3 }),
  }]));
}
async function stage(manifest) {
  const directory = await fs.mkdtemp(path.join(
    process.env.DVAIA_ISOLATED_TEST_WORKSPACE || os.tmpdir(), 'consolidated-promotion-'));
  for (const [store, definition] of Object.entries(definitions)) {
    const destination = path.join(directory, store);
    await fs.mkdir(destination);
    const historical = path.join(directory, `${store}-baseline`);
    await fs.mkdir(historical);
    const baseline = path.join(root, definition.baseline);
    // Reproduce the pre-upgrade state after promotion too. Never alter or
    // truncate the real migration directory to manufacture an old database.
    const baselineRows = (await readMigrations(baseline)).filter(row =>
      row.name <= manifest.baseline[definition.manifestStore]);
    assert.equal(baselineRows.at(-1).name, manifest.baseline[definition.manifestStore]);
    for (const row of baselineRows) {
      await fs.copyFile(path.join(baseline, row.name), path.join(destination, row.name));
      await fs.copyFile(path.join(baseline, row.name), path.join(historical, row.name));
    }
    for (const entry of manifest.order.filter(row => row.store === definition.manifestStore)) {
      assert.equal(entry.readiness, 'ready');
      assert.match(entry.promotionName, /^\d{4}_[a-z0-9_]+\.sql$/);
      const body = await read(`docs/modernization/drafts/${entry.file}`);
      assert.equal(digest(body), entry.sha256);
      try {
        assert.equal(digest(await fs.readFile(path.join(baseline, entry.promotionName))), entry.sha256);
      } catch (error) {
        if (error.code !== 'ENOENT') throw error;
      }
      await fs.copyFile(path.join(root, 'docs/modernization/drafts', entry.file),
        path.join(destination, entry.promotionName));
    }
  }
  return directory;
}
async function assertLedger(pool, directory) {
  const expected = await readMigrations(directory);
  assert.deepEqual((await pool.query(
    'SELECT name,checksum FROM dvaia_migrations.ledger ORDER BY name')).rows,
  expected.map(({ name, checksum }) => ({ name, checksum })));
}
const currentNova = require('../../server/data/postgres/nosqlInjectionWorkshopSolutions')(
  require('../../server/data/nosqlInjectionWorkshopSolutions')).nosqli_9;
async function insertNovaSolution(client, value = currentNova) {
  await client.query(`INSERT INTO nova.nosql_injection_solutions
    (objective_id,title,difficulty,hints,examples,approach,tips)
    VALUES('nosqli_9',$1,$2,$3,$4,$5,$6)`, [value.title, value.difficulty,
    JSON.stringify(value.hints), JSON.stringify(value.examples), value.approach, JSON.stringify(value.tips)]);
}
async function populate(db) {
  await seedWorkshopPlatform(db.identity.migration);
  const userId = 701;
  await db.identity.migration.query(`INSERT INTO identity.users(id,username,email,password)
    VALUES($1,$2,$3,$4)`, [userId, `promotion-${randomUUID()}`,
    `${randomUUID()}@promotion.invalid`, await bcrypt.hash('preserved fixture', 4)]);
  await db.identity.migration.query(`INSERT INTO workshop_platform.user_state(user_id,workshop_key)
    VALUES($1,'direct_prompt_injection')`, [userId]);
  await db.identity.migration.query(`INSERT INTO workshop_platform.completions(user_id,workshop_key,objective_id)
    VALUES($1,'direct_prompt_injection','jailbreak')`, [userId]);
  await db.identity.migration.query(`INSERT INTO workshop_platform.activity_counters
    (user_id,workshop_key,activity_key,activity_count) VALUES($1,'direct_prompt_injection','fixture',9)`, [userId]);
  await db.identity.migration.query(`INSERT INTO workshop_platform.time_tracking
    (user_id,workshop_key,session_start,last_heartbeat,duration_seconds)
    VALUES($1,'direct_prompt_injection',now(),now(),83)`, [userId]);
  const launchId = randomUUID();
  const reviewReservationId = randomUUID();
  await db.identity.migration.query(`INSERT INTO identity.user_sessions
    (id,user_id,session_token_hash,expires_at) VALUES(801,$1,$2,now()+interval '1 hour')`,
  [userId, 'ab'.repeat(32)]);
  await db.identity.migration.query(`INSERT INTO identity.secureshop_launches
    (launch_id,platform_session_id,original_platform_session_id,original_platform_owner_id,
     handle_hash,scenario_id,expires_at) VALUES($1,801,801,$2,decode($3,'hex'),$4,now()+interval '1 hour')`,
  [launchId, userId, 'cd'.repeat(32), randomUUID()]);
  await db.identity.migration.query(`INSERT INTO identity.secureshop_target_reservations
    (target_id,launch_id,generation,target_kind,original_platform_owner_id)
    VALUES($1,$2,1,'reviews',$3)`, [reviewReservationId, launchId, userId]);
  const dpiBody = await read('docs/modernization/drafts/dpi-teaching-scope.sql');
  const pair = dpiBody.match(/SET solution_content=\$json\$([\s\S]*?)\$json\$::jsonb[\s\S]*?objective_id='system_prompt'[\s\S]*?AND solution_content=\$json\$([\s\S]*?)\$json\$::jsonb/);
  assert.ok(pair);
  await db.identity.migration.query(`UPDATE workshop_platform.objectives SET solution_content=$1::jsonb
    WHERE workshop_key='direct_prompt_injection' AND objective_id='system_prompt'`, [pair[2]]);
  const custom = { title: 'Instructor preserved DPI content', approach: 'private custom lesson' };
  await db.identity.migration.query(`UPDATE workshop_platform.objectives SET solution_content=$1::jsonb
    WHERE workshop_key='direct_prompt_injection' AND objective_id='jailbreak'`, [JSON.stringify(custom)]);
  await db.identity.migration.query(`UPDATE workshop_platform.objectives SET label='Extract Author Credentials',
    hint_content=$1::jsonb WHERE workshop_key='nosql_injection_workshop' AND objective_id='nosqli_9'`,
  [JSON.stringify({ title: 'Instructor custom NOVA hint', hints: ['preserve'] })]);

  const sessionId = randomUUID();
  await db.agents.migration.query(`INSERT INTO secureshop_agents.agent_sessions
    (id,user_id,role,messages_json,token_budget_used) VALUES($1,77,'merchant',$2,19)`,
  [sessionId, JSON.stringify([{ role: 'user', content: 'preserve session' }])]);
  await db.agents.migration.query(`INSERT INTO secureshop_agents.agent_trace
    (session_id,step,actor,kind,result_json) VALUES($1,1,'fixture','final',$2)`,
  [sessionId, JSON.stringify({ preserve: true })]);

  const targetId = randomUUID();
  await db.review.migration.query(`INSERT INTO secureshop_review.review_targets
    (target_id,launch_id,scenario_id,generation,original_platform_owner_id,
     original_platform_session_id,seed_count,seed_sha256)
    VALUES($1,$2,$3,1,701,801,1,decode($4,'hex'))`,
  [targetId, randomUUID(), randomUUID(), '12'.repeat(32)]);
  await db.review.migration.query(`INSERT INTO secureshop_review.reviews
    (target_id,product_id,author_id,body,rating) VALUES($1,7,12,'preserve review',4)`, [targetId]);

  const oldNova = { title: 'Extract Author Credentials', difficulty: 'Advanced',
    hints: ['Target the authors collection with regex injection',
      'Try searching authors by email pattern: {"email": {"$regex": ".*@.*"}}'],
    examples: [{ payload: 'find authors {"email": {"$regex": ".*@.*"}}',
      explanation: 'Regex injection against the authors collection returns all author records that have an email field — potentially exposing credentials' }],
    approach: 'This workshop simulates MongoDB-style operators on PostgreSQL; it does not execute MongoDB queries or attacker JavaScript. Apply regex injection to the authors collection to extract email addresses and sensitive profile data. Cross-collection injection demonstrates how a single vulnerability can compromise the entire database.',
    tips: ['Author data may include email, institution, API keys, or password hashes',
      'The injection technique is the same — only the collection/query type changes',
      'Look for fields beyond what is normally returned in API responses'] };
  await insertNovaSolution(db.nova.migration, oldNova);
  await db.nova.migration.query(`INSERT INTO nova.chat_history(user_id,message_type,message)
    VALUES('owner-701','user','preserve NOVA history')`);
  return { userId, sessionId, targetId, launchId, reviewReservationId,
    dpiExpected: JSON.parse(pair[1]), custom };
}

test('consolidated drafts use the real loader and preserve fresh and populated stores', {
  skip: !enabled, timeout: 90000,
}, async () => {
  const manifest = JSON.parse(await read(
    'docs/modernization/drafts/consolidated-forward-promotion-manifest-2026-09-13.json'));
  assert.equal(manifest.order.length, 9);
  assert.deepEqual([...new Set(manifest.order.map(row => row.store))].sort(),
    ['identity', 'nova', 'secureshop_agents', 'secureshop_review']);
  const staged = await stage(manifest);
  try {
    for (const variant of VARIANTS) {
      const db = pools(variant);
      const populated = variant === 'POPULATED';
      try {
        if (populated) for (const [store, definition] of Object.entries(definitions)) {
          await migrate(db[store].migration, path.join(staged, `${store}-baseline`));
        }
        const fixture = populated ? await populate(db) : null;
        for (const [store, definition] of Object.entries(definitions)) {
          const directory = path.join(staged, store);
          const expected = await readMigrations(directory);
          const baselineCount = populated
            ? (await readMigrations(path.join(staged, `${store}-baseline`))).length : 0;
          assert.deepEqual(await migrate(db[store].migration, directory),
            expected.slice(baselineCount).map(row => row.name));
          assert.deepEqual(await migrate(db[store].migration, directory), []);
          await assertLedger(db[store].migration, directory);
        }
        if (!populated) {
          await seedWorkshopPlatform(db.identity.migration);
          await insertNovaSolution(db.nova.migration);
        }
        for (const [store, relation] of Object.entries({
          identity: 'identity.student_deletion_jobs',
          agents: 'secureshop_agents.bound_persona_sessions',
          review: 'secureshop_review.product_targets',
          nova: 'nova.nosql_injection_solutions',
        })) assert.equal((await db[store].runtime.query(
          'SELECT to_regclass($1) IS NOT NULL AS ready', [relation])).rows[0].ready, true);
        assert.equal((await db.identity.runtime.query(`SELECT label FROM workshop_platform.objectives
          WHERE workshop_key='nosql_injection_workshop' AND objective_id='nosqli_9'`)).rows[0].label,
        'Extract Author Contact Data');
        assert.equal((await db.nova.migration.query(`SELECT title FROM nova.nosql_injection_solutions
          WHERE objective_id='nosqli_9'`)).rows[0].title, 'Extract Author Contact Data');
        if (populated) {
          const progress = (await db.identity.runtime.query(`SELECT c.objective_id,t.duration_seconds,
              a.activity_count FROM workshop_platform.completions c
            JOIN workshop_platform.time_tracking t USING(user_id,workshop_key)
            JOIN workshop_platform.activity_counters a USING(user_id,workshop_key)
            WHERE c.user_id=$1`, [fixture.userId])).rows[0];
          assert.deepEqual(progress, { objective_id: 'jailbreak', duration_seconds: 83, activity_count: 9 });
          assert.deepEqual((await db.identity.runtime.query(`SELECT launch_id,target_kind
            FROM identity.secureshop_target_reservations WHERE target_id=$1`,
          [fixture.reviewReservationId])).rows[0], { launch_id: fixture.launchId, target_kind: 'reviews' });
          await db.identity.runtime.query(`INSERT INTO identity.secureshop_target_reservations
            (target_id,launch_id,generation,target_kind,original_platform_owner_id)
            VALUES($1,$2,1,'products',$3)`, [randomUUID(), fixture.launchId, fixture.userId]);
          const contents = (await db.identity.runtime.query(`SELECT objective_id,solution_content,hint_content
            FROM workshop_platform.objectives WHERE workshop_key='direct_prompt_injection'
              AND objective_id IN ('system_prompt','jailbreak') ORDER BY objective_id`)).rows;
          assert.deepEqual(contents.find(row => row.objective_id === 'system_prompt').solution_content,
            fixture.dpiExpected);
          assert.deepEqual(contents.find(row => row.objective_id === 'jailbreak').solution_content,
            fixture.custom);
          assert.deepEqual((await db.identity.runtime.query(`SELECT hint_content FROM workshop_platform.objectives
            WHERE workshop_key='nosql_injection_workshop' AND objective_id='nosqli_9'`)).rows[0].hint_content,
          { title: 'Instructor custom NOVA hint', hints: ['preserve'] });
          assert.deepEqual((await db.agents.runtime.query(`SELECT messages_json,token_budget_used
            FROM secureshop_agents.agent_sessions WHERE id=$1`, [fixture.sessionId])).rows[0],
          { messages_json: JSON.stringify([{ role: 'user', content: 'preserve session' }]), token_budget_used: 19 });
          assert.equal((await db.review.runtime.query(`SELECT body FROM secureshop_review.reviews
            WHERE target_id=$1`, [fixture.targetId])).rows[0].body, 'preserve review');
          assert.equal((await db.nova.runtime.query(`SELECT message FROM nova.chat_history
            WHERE user_id='owner-701'`)).rows[0].message, 'preserve NOVA history');
        }
      } finally {
        await Promise.allSettled(Object.values(db).flatMap(value =>
          [value.runtime.end(), value.migration.end()]));
      }
    }
  } finally {
    await fs.rm(staged, { recursive: true, force: true });
  }
});
