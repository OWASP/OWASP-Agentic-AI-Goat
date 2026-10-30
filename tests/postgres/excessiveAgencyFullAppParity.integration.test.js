'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const { randomUUID, createHash } = require('node:crypto');


function admitMain() {
  const root = fs.realpathSync(path.resolve(__dirname,'../..'));
  assert.equal(fs.realpathSync(process.cwd()),root);
  const file = process.env.EA_PARITY_MANIFEST;
  const fd = fs.openSync(file,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW); let bytes;
  try { const st=fs.fstatSync(fd); assert(st.isFile()&&st.uid===process.getuid()&&st.nlink===1&&(st.mode&0o777)===0o600&&st.size>0&&st.size<16*1024*1024); bytes=fs.readFileSync(fd); } finally { fs.closeSync(fd); }
  const sha=b=>createHash('sha256').update(b).digest('hex'); assert.equal(sha(bytes),process.env.EA_PARITY_MANIFEST_SHA256);
  const manifest=JSON.parse(bytes); assert.equal(sha(fs.readFileSync(path.join(root,'.env'))),manifest.mainEnvSha256); assert.equal(manifest.cohort,'ea-nine-content-main'); assert.equal(manifest.mode,'controlled'); assert.equal(manifest.workspace,root);
  assert(manifest.sourcePins && typeof manifest.sourcePins==='object'&&!Array.isArray(manifest.sourcePins));
  for(const [relative,digest] of Object.entries(manifest.sourcePins)) { assert(!path.isAbsolute(relative)&&!relative.split('/').includes('..')); assert.match(digest,/^[a-f0-9]{64}$/); const file=path.join(root,relative); assert.equal(fs.realpathSync(file),file); assert.equal(sha(fs.readFileSync(file)),digest); }
  for(const relative of ['tests/postgres/excessiveAgencyFullAppParity.integration.test.js','tests/fixtures/excessiveAgencyFullAppParity.js','tests/fixtures/secureshopAnalyticsBrowserOwner.js']) assert(manifest.sourcePins[relative]);
  assert.equal(process.env.ANALYTICS_BROWSER_EXECUTABLE,manifest.browserExecutable);
  assert.equal(sha(fs.readFileSync(manifest.browserExecutable)),process.env.ANALYTICS_BROWSER_SHA256);
  return () => { for(const file of Object.keys(require.cache)) if(file.startsWith(root+path.sep)&&!file.includes(path.sep+'node_modules'+path.sep)) assert(manifest.sourcePins[path.relative(root,file)],'Uncaptured loaded main source'); };
}

test('model-free Excessive Agency learner and instructor full-App parity', {
  skip: process.env.EA_FULL_APP_PARITY !== '1', timeout: process.env.EA_PARITY_MAIN === '1' ? 600000 : 240000,
}, async () => {
  assert.equal(process.env.PG_TEST_DISPOSABLE, 'yes');
  assert.equal(fs.realpathSync(process.cwd()), fs.realpathSync(process.env.OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE));
  assert.notEqual(process.env.EA_ROUTE_LIVE, '1');
  const main = process.env.EA_PARITY_MAIN === '1';
  const assertLoaded = main ? admitMain() : () => {};
  const ports = new Set();
  if (main) {
    const runtime = fs.realpathSync(process.env.EA_PARITY_RUNTIME_ROOT);
    assert.equal(fs.existsSync(path.join(runtime,'.env')),false);
    const Module = require('node:module'), load = Module._load;
    Module._load = function(name) { const value=load.apply(this,arguments); if(name!=='dotenv')return value; return {...value,config(options={}) { const target=path.resolve(options.path||'.env'); assert.equal(path.dirname(target),runtime,'Installed dotenv denied'); return value.config(options); }}; };
    for(const key of ['IDENTITY_DATABASE_URL','IDENTITY_MIGRATION_DATABASE_URL','EXCESSIVE_AGENCY_DATABASE_URL','EXCESSIVE_AGENCY_MIGRATION_DATABASE_URL'])ports.add(Number(new URL(process.env[key]).port));
    require('./ctfStage9MainQualification').installSocketFence(ports);
    require('../fixtures/ownedBrowserCdpAllowance').install({browserExecutable:process.env.ANALYTICS_BROWSER_EXECUTABLE,ownedRoot:runtime,addEndpoint:x=>ports.add(x.port),removeEndpoint:x=>ports.delete(x.port)});
  }
  const { Pool } = require('pg'); const pools = [];
  const pool = (key, role, database) => { const url = new URL(process.env[key]); assert.equal(url.hostname, '127.0.0.1');
    assert.equal(url.pathname, database); assert.equal(url.username, role); const result = new Pool({ connectionString: url.href, max: 6 }); pools.push(result); return result; };
  const identity = pool('IDENTITY_DATABASE_URL', 'dvaia_identity_runtime', '/owasp_ai_goat_test_ea_parity_identity');
  const migration = pool('IDENTITY_MIGRATION_DATABASE_URL', 'dvaia_identity_migration', '/owasp_ai_goat_test_ea_parity_identity');
  const lab = pool('EXCESSIVE_AGENCY_DATABASE_URL', 'dvaia_excessive_agency_runtime', '/owasp_ai_goat_test_ea_parity_lab');
  const labMigration = pool('EXCESSIVE_AGENCY_MIGRATION_DATABASE_URL', 'dvaia_excessive_agency_migration', '/owasp_ai_goat_test_ea_parity_lab');
  let server; let authRouter; let parity; let restore; let proof; let primary;
  try {
    Object.assign(process.env, { PLATFORM_DATABASE_ENGINE: 'postgres', WORKSHOP_DATABASE_ENGINE: 'postgres',
      AI_PROVIDER: 'mock', JUDGE_PROVIDER: 'mock', JWT_SECRET: 'owned-ea-parity-secret-more-than-32-bytes',
      EVENT_GATE_ENABLED: 'false' });
    const identityApi = require('../../server/database/postgres/identityRepository');
    await identityApi.initializeIdentityRepository(identity, migration);
    await require('../../server/database/postgres/workshopPlatformSeed').seedWorkshopPlatform(migration);
    await require('../../server/database/postgres/excessiveAgencyLabDb').createExcessiveAgencyDatabaseManager(lab).initialize(labMigration);
    const repository = identityApi.createIdentityRepository(identity); const adapter = require('../../server/services/postgresIdentityAdapter').getPostgresIdentityAdapter();
    const password = randomUUID(); const passwordHash = await require('bcryptjs').hash(password, 4);
    const learner = await repository.createUser({ username: 'ea-parity-' + randomUUID(), email: randomUUID() + '@example.invalid', passwordHash });
    const sibling = await repository.createUser({ username: 'ea-sibling-' + randomUUID(), email: randomUUID() + '@example.invalid', passwordHash });
    const stores = await require('../../server/services/postgresPlatformStores').getPostgresPlatformStores();
    const express = require('express'); const app = express(); app.use(express.json());
    const pass = (_request, _response, next) => next();
    authRouter = require('../../server/routes/postgresAuth').createPostgresAuthRouter({ adapter, limiters: { loginRateLimiter: pass, registerRateLimiter: pass, passwordResetRateLimiter: pass } });
    app.use('/api/auth', authRouter);
    parity = await require('../fixtures/legacyFileSsiFullAppParity').mountLegacyParityRoutes({ app, adapter, pool: identity, migration,
      progress: stores.progress, config: stores.config, identity: repository });
    app.use('/api/solutions', require('../../server/routes/solutions')); app.use('/api/hints', require('../../server/routes/hints'));
    if (main) app.use('/api/excessive-agency', (req, res, next) => /\/(chat|complete|evaluate|reset)$/.test(req.path) ? res.status(403).json({ error: 'Model-free content qualification' }) : next());
    app.use('/api/excessive-agency', require('../../server/routes/excessiveAgencyLab'));
    if (main) { app.use('/api', (_q, res) => res.sendStatus(404)); app.use(express.static(path.resolve('client/build'))); app.get('/{*path}', (_q, res) => res.sendFile(path.resolve('client/build/index.html'))); }
    server = app.listen(0, '127.0.0.1'); await new Promise(resolve => server.once('listening', resolve)); ports.add(server.address().port);
    const login = async owner => { const response = await fetch(`http://127.0.0.1:${server.address().port}/api/auth/login`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ username: owner.username, password }) }); assert.equal(response.status, 200); return response.json(); };
    const learnerAuth = await login(learner); const siblingAuth = await login(sibling);
    let contentRows;
    if (main) {
      const read = async () => ({
        exercises: (await identity.query('SELECT workshop_key,is_visible,show_hints,show_solutions FROM workshop_platform.exercises ORDER BY workshop_key')).rows,
        objectives: (await identity.query("SELECT objective_id,label,catalog_active,is_enabled,hint_enabled,solution_enabled,hint_content,solution_content FROM workshop_platform.objectives WHERE workshop_key='excessive_agency' ORDER BY objective_id")).rows,
        completions: (await identity.query('SELECT * FROM workshop_platform.completions WHERE user_id=ANY($1::bigint[]) ORDER BY user_id,workshop_key,objective_id', [[learner.id,sibling.id]])).rows,
        progress: (await lab.query('SELECT * FROM excessive_agency.progress WHERE platform_user_id=ANY($1::text[]) ORDER BY platform_user_id,objective_id', [[String(learner.id),String(sibling.id)]])).rows,
        evidence: (await identity.query('SELECT evaluation_id FROM workshop_platform.objective_judgments WHERE user_id=ANY($1::bigint[]) ORDER BY evaluation_id', [[learner.id,sibling.id]])).rows,
      });
      const manager = require('../../server/database/postgres/excessiveAgencyLabDb').createExcessiveAgencyDatabaseManager(lab);
      await manager.forAttendee(String(learner.id)).ensureSeeded(); await manager.forAttendee(String(sibling.id)).ensureSeeded();
      await lab.query('INSERT INTO excessive_agency.progress(platform_user_id,objective_id) VALUES($1,1)', [String(sibling.id)]);
      const before = await read(); assert.equal(before.completions.length,0); assert.equal(before.evidence.length,0); assert.equal(before.progress.length,1);
      restore = async () => {
        await migration.query('DELETE FROM workshop_platform.completions WHERE user_id=$1', [learner.id]);
        await migration.query('DELETE FROM workshop_platform.time_tracking WHERE user_id=ANY($1::bigint[])', [[learner.id,sibling.id]]);
        await lab.query('DELETE FROM excessive_agency.progress WHERE platform_user_id=$1', [String(learner.id)]);
        for (const row of before.exercises) await migration.query('UPDATE workshop_platform.exercises SET is_visible=$2,show_hints=$3,show_solutions=$4 WHERE workshop_key=$1', [row.workshop_key,row.is_visible,row.show_hints,row.show_solutions]);
        for (const row of before.objectives) await migration.query("UPDATE workshop_platform.objectives SET is_enabled=$2,hint_enabled=$3,solution_enabled=$4 WHERE workshop_key='excessive_agency' AND objective_id=$1", [row.objective_id,row.is_enabled,row.hint_enabled,row.solution_enabled]);
        assert.deepEqual(await read(),before);
        if (proof) Object.assign(proof,{configurationRestored:true,projectionRestored:true,immutableEvidencePreserved:true});
      };
      await stores.config.setMasterHintVisibility('excessive_agency',true,learner.id);
      await stores.config.setMasterSolutionVisibility('excessive_agency',true,learner.id);
      await migration.query("UPDATE workshop_platform.objectives SET is_enabled=true WHERE workshop_key='excessive_agency'");
      contentRows = (await read()).objectives; require('../fixtures/excessiveAgencyFullAppParity').admitContent(contentRows);
      for (const row of contentRows) {
        await migration.query("INSERT INTO workshop_platform.completions(user_id,workshop_key,objective_id) VALUES($1,'excessive_agency',$2)", [learner.id,row.objective_id]);
        await lab.query('INSERT INTO excessive_agency.progress(platform_user_id,objective_id) VALUES($1,$2)', [String(learner.id),Number(row.objective_id.slice(10))]);
      }
    } else {
      await migration.query("UPDATE workshop_platform.objectives SET is_enabled=true WHERE workshop_key='excessive_agency'");
      await migration.query("INSERT INTO workshop_platform.completions(user_id,workshop_key,objective_id) VALUES($1,'excessive_agency','objective_9')", [learner.id]);
    }
    await migration.query("UPDATE workshop_platform.exercises SET is_visible=(workshop_key='excessive_agency')");
    await migration.query("INSERT INTO workshop_platform.time_tracking(user_id,workshop_key,session_start,last_heartbeat,duration_seconds) VALUES($1,'excessive_agency',now()-interval '60 seconds',now(),60)", [learner.id]);
    const siblingBefore = await identity.query("SELECT count(*)::int AS completions FROM workshop_platform.completions WHERE user_id=$1 AND workshop_key='excessive_agency'", [sibling.id]);
    const title = (await migration.query("SELECT challenge_name FROM workshop_platform.exercises WHERE workshop_key='excessive_agency'")).rows[0].challenge_name;
    const operation = require('../fixtures/excessiveAgencyFullAppParity').qualifyExcessiveAgencyFullAppParity({ backendPort: server.address().port,
      token: learnerAuth.token, siblingToken: siblingAuth.token, adminToken: parity.adminToken, studentId: learner.id, title,
      runtimeRoot: main ? process.env.EA_PARITY_RUNTIME_ROOT : path.dirname(process.env.EA_PARITY_EVIDENCE_PATH), contentRows });
    proof = await operation;
    assert.equal((await identity.query("SELECT count(*)::int AS completions FROM workshop_platform.completions WHERE user_id=$1 AND workshop_key='excessive_agency'", [sibling.id])).rows[0].completions, siblingBefore.rows[0].completions);
  } catch (error) { primary = error; }
  finally {
    const operations = [['restore',()=>restore?.()],['server',()=>server ? new Promise((resolve,reject)=>server.close(error=>error?reject(error):resolve())) : undefined],['parity',()=>parity?.close?.()],['auth',()=>authRouter?.close?.()],['shared-pools',()=>require('../../server/database/postgres').closePostgresPools()],['pools',()=>Promise.all(pools.map(item=>item.end()))]];
    const cleanup = [];
    for (const [name,operation] of operations) { try { await operation(); cleanup.push({name,status:'fulfilled'}); } catch (error) { cleanup.push({name,status:'rejected'}); primary=primary?new AggregateError([primary,error],'EA cleanup failed'):error; } }
    assertLoaded();
    if (proof) { proof.cleanup=cleanup; if(main&&!primary)require('../fixtures/excessiveAgencyFullAppParity').assertReceipt(proof); fs.writeFileSync(process.env.EA_PARITY_EVIDENCE_PATH, JSON.stringify(proof,null,2),{mode:0o600}); }
  }
  if (primary) throw primary;
});
