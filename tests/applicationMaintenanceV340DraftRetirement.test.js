'use strict';
// Maintained test body: append invocation with the selected generator and root.
function register(api, root) {
  const test = require('node:test'), assert = require('node:assert/strict');
  const fs = require('node:fs'), path = require('node:path'), os = require('node:os');
  const priorBytes = fs.readFileSync(path.join(root, 'server/services/applicationMaintenanceInprocessSources-v339.json'));
  const prior = JSON.parse(priorBytes);
  const names = ['db/postgres/drafts/secureshop_owned_registration.sql', 'db/postgres/drafts/xss_profile_model_origin.sql'];
  const migrations = ['db/postgres/workshop-migrations/xss/0006_profile_model_origin.sql',
    'db/postgres/workshop-migrations/secureshop_agents/0115_owned_mcp_registration_journal.sql'];
  function fixture(t) {
    const scratch = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'maintenance-v340-control-')));
    t.after(() => fs.rmSync(scratch, {recursive: true, force: true}));
    fs.mkdirSync(path.join(scratch, 'db/postgres/drafts'), {recursive: true});
    for (const file of migrations) {
      fs.mkdirSync(path.dirname(path.join(scratch, file)), {recursive: true});
      fs.writeFileSync(path.join(scratch, file), fs.readFileSync(path.join(root, file)));
    }
    return scratch;
  }
  const check = (scratch, version = 339, bytes = priorBytes, manifest = prior, missing = names) =>
    api.reviewedDraftRetirements(scratch, version, bytes, manifest, missing);
  test('v340 exact absent draft retirement records prior hashes without mutating v339', t => {
    const scratch = fixture(t), before = JSON.stringify(prior);
    const rows = check(scratch);
    assert.deepEqual(rows.map(row => row.path), names);
    for (const row of rows) {
      assert.equal(row.priorSha256, prior.files[row.path]);
      assert.equal(row.predecessorVersion, 339); assert.equal(row.successorVersion, 340);
      assert.match(row.justification, /no byte-equivalence claim/);
    }
    assert.equal(JSON.stringify(prior), before);
    assert.deepEqual(fs.readFileSync(path.join(root, 'server/services/applicationMaintenanceInprocessSources-v339.json')), priorBytes);
  });
  test('v340 accepts absent drafts directory without recreating it', t => {
    const scratch = fixture(t), directory = path.join(scratch, 'db/postgres/drafts');
    fs.rmdirSync(directory);
    assert.equal(check(scratch).length, 2);
    assert.equal(fs.existsSync(directory), false);
    fs.symlinkSync(path.join(scratch, 'absent-target'), directory);
    assert.throws(() => check(scratch), /ancestor/);
  });
  test('v340 rejects wrong predecessor hash, version, draft entry or recovery membership', t => {
    const scratch = fixture(t);
    assert.throws(() => check(scratch, 339, Buffer.concat([priorBytes, Buffer.from(' ')])), /predecessor/);
    for (const version of [338, 340, 341]) assert.throws(() => check(scratch, version), /SQL missing/);
    const changed = structuredClone(prior); changed.files[names[0]] = '0'.repeat(64);
    assert.throws(() => check(scratch, 339, priorBytes, changed), /draft predecessor/);
    const recovery = structuredClone(prior); recovery.recoveryFiles = recovery.recoveryFiles.filter(name => name !== names[0]);
    assert.throws(() => check(scratch, 339, priorBytes, recovery), /draft predecessor/);
  });
  test('v340 rejects partial retirement, extra missing SQL and executable migration retirement', t => {
    const scratch = fixture(t);
    for (const missing of [[], names.slice(0, 1), [...names, 'db/postgres/drafts/extra.sql'], [...names, migrations[0]], migrations])
      assert.throws(() => check(scratch, 339, priorBytes, prior, missing), /Exact two/);
  });
  test('v340 rejects present drafts, dangling symlinks and ancestor substitution', t => {
    const scratch = fixture(t), file = path.join(scratch, names[0]);
    fs.writeFileSync(file, 'present');
    assert.throws(() => check(scratch), /still exists/);
    fs.unlinkSync(file); fs.symlinkSync(path.join(scratch, 'absent-target'), file);
    assert.throws(() => check(scratch), /still exists/);
    fs.unlinkSync(file);
    const directory = path.dirname(file); fs.renameSync(directory, directory + '-retained');
    fs.symlinkSync(directory + '-retained', directory);
    assert.throws(() => check(scratch), /ancestor/);
  });
  test('v340 requires unchanged executable XSS and exact separately added registration SQL', t => {
    for (const migration of migrations) {
      const scratch = fixture(t);
      fs.appendFileSync(path.join(scratch, migration), '\n');
      assert.throws(() => check(scratch), /migration/);
    }
    const scratch = fixture(t), changed = structuredClone(prior);
    changed.files[migrations[1]] = 'f02847fa244b35e255208fab9ee5da4325b7e48aea1fe839780e3a0d4245e7f0';
    assert.throws(() => check(scratch, 339, priorBytes, changed), /added registration/);
  });
};

register(require('../scripts/plan-application-maintenance-source-successor'), require('node:path').resolve(__dirname, '..'));
