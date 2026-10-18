'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const manifest = require('../docs/modernization/drafts/workshop-catalog-provenance-integration-manifest-2026-09-14.json');
const provenance = require('../docs/modernization/drafts/catalogDefaultProvenance.candidate');
const configBuilder = require('../docs/modernization/drafts/workshopConfigProvenanceIntegration.candidate');
const activationBuilder = require('../docs/modernization/drafts/secureshopPersonaInboxActivationCandidate');
const curriculumBuilder = require('../docs/modernization/drafts/secureshopPersonaCatalogCurriculumCandidate');
const { releasePhase } = require('./helpers/workshopCatalogReleasePhase');
const phase = releasePhase();

function read(name) { return fs.readFileSync(path.join(ROOT, name), 'utf8'); }
function hash(value) { return crypto.createHash('sha256').update(value).digest('hex'); }

test('release manifest pins every candidate and keeps the verified 0046 before reserved 0047', () => {
  assert.equal(hash(read('db/postgres/identity-migrations/0046_graph_judge_validation_code.sql')),
    'd5b40afc1d3c43c2371ec30fd9d1cc119a935cbc1840ef3b11c8bc4cfa6be936');
  assert.deepEqual(manifest.ordering.slice(0, 2).map(row => row.suffix), ['0046', '0047']);
  assert.equal(manifest.ordering[0].status, 'applied_and_root_audited');
  assert.deepEqual(manifest.ordering.slice(2).map(row=>row.suffix),['0048','0049']);
  assert.ok(manifest.ordering.slice(2).every(row=>row.status==='reserved_draft_only'));
  for (const group of ['qualifiedCandidateBytes', 'integrationCandidates']) {
    for (const [name, expected] of Object.entries(manifest[group])) assert.equal(hash(read(name)), expected, name);
  }
  if (!phase.generated) for (const [name, expected] of Object.entries(manifest.pinnedProductionInputs)) {
    assert.equal(hash(read(name)), expected, name);
  }
  // The draft records the pre-release fixture. The admitted successor uses
  // the historical 116-objective catalog and a bounded migration view.
  assert.equal(manifest.nextIntegrationQualification.testSha256,
    '20bd03198a3e8b4d8958bcd8d27642ba2954232f30e06e9c32f5683e3c0ccb74');
  assert.equal(hash(read(manifest.nextIntegrationQualification.test)), phase.generated
    ? 'aa203c0d9029ffa8cb2f618ae6ff444fd539691dfb353a87154cd7a69d7190ad'
    : manifest.nextIntegrationQualification.testSha256);
  assert.equal(hash(read(manifest.nextIntegrationQualification.launcher)),
    manifest.nextIntegrationQualification.launcherSha256);
  assert.equal(manifest.status, 'draft_unregistered_unpromoted');
});

test('production-shaped seed wrapper preserves the complete fixture contract and exact qualified cores', () => {
  const wrapper = read('docs/modernization/drafts/workshopPlatformSeed.provenance.integration.candidate.js');
  assert.doesNotThrow(() => new Function('require', 'module', 'exports', wrapper));
  assert.match(wrapper, /require\('\.\/catalogDefaultProvenance'\)/);
  assert.match(wrapper, /require\('\.\/workshopPlatformSeedCore'\)/);
  assert.match(wrapper, /secureshop_agent_security/);
  assert.match(wrapper, /sql_injection_workshop/);
  assert.match(wrapper, /nosql_injection_workshop/);
  assert.match(wrapper, /CATALOG_VERSION='workshop-defaults-2026-09-14-v1'/);
  assert.match(wrapper, /catalog=WORKSHOP_OBJECTIVES,hints=hintFixtures/);
  assert.equal(hash(read('docs/modernization/drafts/catalogDefaultProvenance.candidate.js')),
    manifest.generatedProductionOutputs['server/database/postgres/catalogDefaultProvenance.js']);
  assert.equal(hash(read('docs/modernization/drafts/workshopPlatformSeed.provenance.candidate.js')),
    manifest.generatedProductionOutputs['server/database/postgres/workshopPlatformSeedCore.js']);
});

test('generated config and curriculum outputs are source-pinned and match the release manifest',
  { skip: phase.generated }, () => {
  const config = configBuilder.buildCandidate(read('server/database/postgres/workshopConfigRepository.js'));
  assert.equal(hash(config), manifest.generatedProductionOutputs[
    'server/database/postgres/workshopConfigRepository.js']);
  assert.match(config, /markCustomFields/);

  const activated = activationBuilder.buildCandidates({
    application: read('server/services/secureshopBoundApplication.js'),
    composition: read('server/services/secureshopBoundReviewComposition.js'),
    curriculum: read('server/config/secureshopCurriculum.js'),
  }).curriculum;
  const curriculum = curriculumBuilder.buildCandidate(activated);
  assert.equal(hash(curriculum), manifest.generatedProductionOutputs['server/config/secureshopCurriculum.js']);
  assert.match(curriculum, /route: '\/workshop\/secureshop'/);
  assert.match(curriculum, /Open Persona inbox access/);
});

test('Persona adoption hashes describe exact canonical documents and cannot rewrite catalog rows', () => {
  const sql = read('docs/modernization/drafts/workshop-catalog-field-provenance-persona-adoption.sql');
  const pairs = [...sql.matchAll(/\$json\$([\s\S]*?)\$json\$::jsonb,\s*'([a-f0-9]{64})'/g)];
  assert.equal(pairs.length, 8);
  for (const [, encoded, expected] of pairs) {
    const document = JSON.parse(encoded);
    assert.equal(provenance.hashDocument(document), expected);
  }
  assert.match(sql, /p\.provenance_state='legacy_unknown'/);
  assert.match(sql, /c\.current_document=d\.source_document/);
  assert.match(sql, /source_version='workshop-defaults-2026-09-14-v1'/);
  assert.doesNotMatch(sql, /UPDATE\s+workshop_platform\.(?:exercises|objectives)/i);
  assert.doesNotMatch(sql, /INSERT\s+INTO\s+workshop_platform\.(?:exercises|objectives)/i);
});

test('package phase is explicit and generated phase is pinned by the live release manifest', () => {
  assert.equal(fs.existsSync(path.join(ROOT,
    'db/postgres/identity-migrations/0047_secureshop_persona_inbox_catalog.sql')), phase.generated);
  assert.equal(fs.existsSync(path.join(ROOT,
    'server/database/postgres/catalogDefaultProvenance.js')), phase.generated);
  assert.equal(fs.existsSync(path.join(ROOT,
    'server/database/postgres/workshopPlatformSeedCore.js')), phase.generated);
  assert.ok(Object.keys(manifest.generatedProductionOutputs).every(name => !name.startsWith('client/')));
});

test('release launcher verifies grant, copied inputs and generated bytes before Docker', () => {
  const source=read('tests/postgres/run-workshop-catalog-provenance-release-isolated.py');
  assert.match(source,/from native_source_provenance import verify_source_copy/);
  assert.match(source,/verify_source_copy\(SOURCE,workspace,TRACKED,granted=granted_hashes\)/);
  assert.match(source,/not isinstance\(grant\.get\('sourceHashes'\),dict\) or not grant\['sourceHashes'\]/);
  assert.match(source,/'consumerPid':os\.getpid\(\)/);
  assert.match(source,/actual_outputs!=expected_outputs/);
  assert.match(source,/actual_staged!=expected_staged/);
  assert.ok(source.indexOf('prepare(grant[\'sourceHashes\'])')<source.indexOf("docker+['run'"));
  for(const fixture of ['workshopHints.js','xssWorkshopSolutions.js','sqlInjectionWorkshopSolutions.js',
    'nosqlInjectionWorkshopSolutions.js','identity-migrations'])assert.match(source,new RegExp(fixture));
});
