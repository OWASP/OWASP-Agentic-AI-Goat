'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { hashDocument } = require('../docs/modernization/drafts/catalogDefaultProvenance.candidate');
const qualification = require('../scripts/qualify-workshop-catalog-provenance-promotion');
const { createCopyFilter } = require('../scripts/lib/isolated-source-copy');
const { releasePhase, reviewedOutputDigests } = require('./helpers/workshopCatalogReleasePhase');

const ROOT = path.join(__dirname, '..');
const manifest = require('../docs/modernization/drafts/workshop-catalog-provenance-live-promotion-manifest-2026-09-14.json');
const digest = name => crypto.createHash('sha256').update(fs.readFileSync(path.join(ROOT, name))).digest('hex');

test('live package pins applied migrations and immutable reviewed source bytes', () => {
  assert.deepEqual(manifest.migrations.map(row => row.name), [
    '0047_secureshop_persona_inbox_catalog.sql',
    '0048_workshop_catalog_field_provenance.sql',
    '0049_workshop_catalog_persona_adoption.sql',
  ]);
  assert.equal(manifest.prerequisites.identity.fileCount, 45);
  assert.equal(manifest.prerequisites.identity.requiredHead, '0046_graph_judge_validation_code.sql');
  assert.equal(digest('db/postgres/identity-migrations/0046_graph_judge_validation_code.sql'),
    manifest.prerequisites.identity.requiredChecksum);
  for (const entry of manifest.migrations) assert.equal(digest(entry.draft), entry.sha256);
  assert.equal(Object.keys(manifest.generatedProductionOutputs).length, 8);
  const phase = releasePhase();
  if (phase.generated) {
    const reviewed = reviewedOutputDigests();
    for (const [name, expected] of Object.entries(manifest.generatedProductionOutputs)) {
      assert.equal(reviewed[name], expected, `reviewed:${name}`);
    }
    for (const [name, expected] of Object.entries(manifest.sourceInputs)) {
      if (!(name in manifest.generatedProductionOutputs)) assert.equal(digest(name), expected, `input:${name}`);
    }
  } else {
    for (const [name, expected] of Object.entries(manifest.sourceInputs)) {
      assert.equal(digest(name), expected, `input:${name}`);
    }
  }
  assert.equal(manifest.catalogContract.canonicalObjectiveCount, 116);
  assert.deepEqual({ tests: manifest.generatedSourceRegression.tests,
    passed: manifest.generatedSourceRegression.passed,
    failed: manifest.generatedSourceRegression.failed,
    skipped: manifest.generatedSourceRegression.skipped },
  { tests: 2263, passed: 2208, failed: 0, skipped: 55 });
  assert.equal(manifest.generatedSourceRegression.snapshotMetadataSha256,
    '842caf5f9cdcd22ae4af9100cd1c567b544e39dd4e64ac7434974e136ae7f826');
});

test('catalog snapshot hashes fields canonically and excludes visibility from managed content', async () => {
  const exercise = { workshop_key:'demo',challenge_name:'Demo',challenge_description:'Description',
    category:'ai',difficulty:'intro',route:'/demo',is_visible:false,show_hints:true,
    show_solutions:false,catalog_active:true,ordinal:3 };
  const objective = { workshop_key:'demo',objective_id:'one',label:'One',category:'ai',
    hint_content:{z:1,a:2},solution_content:null,is_enabled:false,hint_enabled:true,
    solution_enabled:false,catalog_active:true,ordinal:1 };
  const pool = { end:async()=>{}, query:async sql => {
    if (sql.includes('FROM workshop_platform.exercises ORDER')) return { rows:[exercise] };
    if (sql.includes('FROM workshop_platform.objectives ORDER')) return { rows:[objective] };
    if (sql.includes('SELECT to_jsonb(t)')) return { rows:[] };
    if (sql.includes('config_revision')) return { rows:[{revision:'8'}] };
    if (sql.includes('to_regclass')) return { rows:[{present:false}] };
    throw new Error(`unexpected SQL: ${sql}`);
  } };
  const snapshot = await qualification.catalogSnapshot({ createPool:()=>pool,closePostgresPools:async()=>{} });
  assert.equal(snapshot.fields['objective:demo:one:hint_content'],
    hashDocument({present:true,value:{a:2,z:1}}));
  assert.equal(Object.keys(snapshot.fields).length,9);
  assert.equal(snapshot.revision,8);
  assert.deepEqual(snapshot.provenance,{count:0,managed:0,custom:0,legacy_unknown:0});
  assert.equal(snapshot.learner['workshop_platform.time_tracking'].rows,0);
});

test('promotion runner holds partial release for repair and compares complete catalog/learner state', () => {
  const source=fs.readFileSync(path.join(ROOT,
    'tests/postgres/run-workshop-catalog-provenance-promotion.py'),'utf8');
  assert.match(source,/increment=3 if store=='identity' else 0/);
  assert.match(source,/details\['ledger'\]\[:len\(prior\['ledger'\]\)\]!=prior\['ledger'\]/);
  assert.match(source,/before\['settingsSha256'\]!=after\['settingsSha256'\]/);
  assert.match(source,/before\['learner'\]!=after\['learner'\]/);
  assert.match(source,/allowedCatalogTransitions/);
  assert.match(source,/hold_for_repair = bool\(promote_catalog and state\.get\('promotionStarted'\)/);
  assert.match(source,/assert_agent_host_quiet\(\)/);
  assert.match(source,/pg_isready', '-h', '127\.0\.0\.1'/);
  assert.match(source,/grant\.get\('sourceHashes'\) != preserved_source_sha256/);
  assert.match(source,/catalog promotion source inventory omits a manifest dependency/);
  const preservedSourcesIndex = source.indexOf('assert_preserved_sources()');
  const stopWatcherIndex = source.indexOf('os.kill(args.watcher_pid, signal.SIGSTOP)');
  assert.notEqual(preservedSourcesIndex, -1, 'promotion must verify preserved sources');
  assert.notEqual(stopWatcherIndex, -1, 'promotion must stop the watcher');
  assert.ok(preservedSourcesIndex < stopWatcherIndex);
  for (const dependency of ['run-workshop-catalog-provenance-promotion.py',
    'sensitive_info_recovery_safety.py', 'qualify-workshop-catalog-provenance-promotion.js']) {
    assert.match(source, new RegExp(dependency.replaceAll('.', '\\.'), 'u'));
  }
});

test('shared isolated copy keeps source named uploads and excludes only runtime upload data', () => {
  const include=createCopyFilter(ROOT);
  assert.equal(include(path.join(ROOT,'agent-host/agents/uploads/tools/index.js')),true);
  assert.equal(include(path.join(ROOT,'client/src/App.js')),true);
  assert.equal(include(path.join(ROOT,'sidecars/sandbox-runner/index.js')),true);
  assert.equal(include(path.join(ROOT,'server/uploads/learner.bin')),false);
  assert.equal(include(path.join(ROOT,'node_modules/pkg/index.js')),false);
});
