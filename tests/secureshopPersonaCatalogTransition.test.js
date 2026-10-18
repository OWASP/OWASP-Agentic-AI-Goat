'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const Module = require('node:module');
const candidate = require('../docs/modernization/drafts/secureshopPersonaCatalogSeedCandidate');
const curriculumCandidate = require('../docs/modernization/drafts/secureshopPersonaCatalogCurriculumCandidate');
const activationCandidate = require('../docs/modernization/drafts/secureshopPersonaInboxActivationCandidate');
const { releasePhase } = require('./helpers/workshopCatalogReleasePhase');
const phase = releasePhase();

const ROOT = path.join(__dirname, '..');
const seedPath = path.join(ROOT, 'server/database/postgres/workshopPlatformSeed.js');
const sqlPath = path.join(ROOT, 'docs/modernization/drafts/secureshop-persona-inbox-catalog-transition.sql');

test('catalog seed candidate preserves instructor labels only for the three released persona objectives',
  { skip: phase.generated }, () => {
  const source = fs.readFileSync(seedPath, 'utf8');
  const built = candidate.buildCandidate(source);
  assert.notEqual(built, source);
  assert.match(built, /label=CASE WHEN workshop_platform\.objectives\.workshop_key='secureshop_agent_security'/);
  for (const id of candidate.IDS) assert.match(built, new RegExp(`'${id}'`));
  assert.match(built, /ELSE EXCLUDED\.label END/,
    'other workshops retain canonical source label updates');
  assert.throws(() => candidate.buildCandidate(`${source}\n`), /reviewed frozen version/);
});

test('forward transition changes defaults without mutating instructor controls or labels', () => {
  const sql = fs.readFileSync(sqlPath, 'utf8');
  assert.match(sql, /WHERE workshop_key='secureshop_agent_security' AND route=''/);
  assert.match(sql, /challenge_description=\$old_description\$/);
  for (const id of candidate.IDS) {
    assert.match(sql, new RegExp(`objective_id='${id}'`));
    assert.match(sql, new RegExp(`\\$old_hint_p[123]\\$`));
    assert.match(sql, new RegExp(`\\$old_solution_p[123]\\$`));
  }
  assert.doesNotMatch(sql, /\bSET\s+(?:is_visible|is_enabled|show_hints|show_solutions|hint_enabled|solution_enabled|label)\b/i);
  assert.doesNotMatch(sql,
    /(?:INSERT\s+INTO|DELETE\s+FROM)\s+workshop_platform\.(?:exercises|objectives|user_state|completions|activity_counters|time_tracking)\b/i);
  assert.match(sql, /IF total_affected > 0 THEN/);
  assert.match(sql, /UPDATE workshop_platform\.config_revision/);
  assert.match(sql, /VALUES\('workshop','secureshop_agent_security','workshop_config',1\)/);
  assert.equal((sql.match(/GET DIAGNOSTICS affected = ROW_COUNT/g) || []).length, 8);
});

test('persona solution examples describe the mounted inbox flow', { skip: phase.generated }, () => {
  const activated = activationCandidate.buildCandidates({
    application: fs.readFileSync(path.join(ROOT, 'server/services/secureshopBoundApplication.js'), 'utf8'),
    composition: fs.readFileSync(path.join(ROOT, 'server/services/secureshopBoundReviewComposition.js'), 'utf8'),
    curriculum: fs.readFileSync(path.join(ROOT, 'server/config/secureshopCurriculum.js'), 'utf8'),
  }).curriculum;
  const released = curriculumCandidate.buildCandidate(activated);
  const compiled = new Module(path.join(ROOT, 'server/config/.personaCatalogCurriculum.js'), module);
  compiled.filename = path.join(ROOT, 'server/config/.personaCatalogCurriculum.js');
  compiled.paths = Module._nodeModulePaths(path.dirname(compiled.filename));
  compiled._compile(released, compiled.filename);
  for (const id of candidate.IDS) {
    assert.match(compiled.exports.SOLUTIONS[id].examples[0].action, /Open Persona inbox access/);
    assert.doesNotMatch(compiled.exports.SOLUTIONS[id].examples[0].action, /Product review form/);
  }
  assert.match(fs.readFileSync(sqlPath, 'utf8'),
    /same launch-owned target demonstrates the advisory denial/);
});

test('owned qualifier stages reserved 0047 and cannot use another Docker daemon', () => {
  const source = fs.readFileSync(path.join(ROOT,
    'tests/postgres/run-secureshop-persona-catalog-transition-isolated.py'), 'utf8');
  assert.match(source, /EXPECTED_DOCKER='unix:\/\/\/Users\/averma5\/\.colima\/dvaia-pg-verify\/docker\.sock'/);
  assert.match(source, /0047_secureshop_persona_inbox_catalog\.sql/);
  assert.match(source, /register_owner\(\);prepare\(\);creation_attempted=True/);
  assert.match(source, /docker\+\['ps','-a','--filter',f'name=\^\/\{container\}\$'/);
  assert.match(source, /containerCleanupDebt/);
  assert.doesNotMatch(source, /db\/postgres\/identity-migrations[^'\n]*copy2/);
});
