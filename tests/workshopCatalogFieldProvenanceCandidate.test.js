'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const provenance = require('../docs/modernization/drafts/catalogDefaultProvenance.candidate');
const configCandidate = require('../docs/modernization/drafts/workshopConfigProvenanceIntegration.candidate');
const { releasePhase } = require('./helpers/workshopCatalogReleasePhase');
const phase = releasePhase();
const { createWorkshopPlatformSeed, resolveObjectiveContent } = require(
  '../docs/modernization/drafts/workshopPlatformSeed.provenance.candidate');

const ROOT = path.join(__dirname, '..');

test('canonical documents distinguish missing and null and ignore object key order', () => {
  const left = provenance.document({ z: [2, { b: true, a: null }], a: 'value' });
  const right = provenance.document({ a: 'value', z: [2, { a: null, b: true }] });
  assert.equal(provenance.hashDocument(left), provenance.hashDocument(right));
  assert.notEqual(provenance.hashDocument(provenance.document(null)),
    provenance.hashDocument(provenance.document(undefined, false)));
  assert.notEqual(provenance.hashDocument(provenance.document([1, 2])),
    provenance.hashDocument(provenance.document([2, 1])));
  assert.throws(() => provenance.document(undefined), /explicit missing/);
  assert.throws(() => provenance.document({ value: undefined }), /JSON values/);
  assert.throws(() => provenance.document(Number.NaN), /finite JSON/);
});

test('seed adapter preserves missing, explicit null, SQL/NoSQL hint fallback and legacy XSS paths', () => {
  const missing = resolveObjectiveContent({ workshopKey:'plain',objectiveId:'one',hints:{plain:{}},
    solutions:{plain:{}} });
  assert.deepEqual(missing, { hintPresent:false,hint:undefined,solutionPresent:false,solution:undefined });
  const explicit = resolveObjectiveContent({ workshopKey:'plain',objectiveId:'one',
    hints:{plain:{one:null}},solutions:{plain:{one:null}} });
  assert.deepEqual(explicit, { hintPresent:true,hint:null,solutionPresent:true,solution:null });
  const fallback = resolveObjectiveContent({ workshopKey:'sql_injection_workshop',objectiveId:'one',
    hints:{sql_injection_workshop:{}},solutions:{sql_injection_workshop:{one:{title:'SQL',hints:['safe']}}} });
  assert.deepEqual(fallback.hint, { title:'SQL',hints:['safe'] });
  assert.equal(fallback.hintPresent, true);
  const source = fs.readFileSync(path.join(ROOT,
    'docs/modernization/drafts/workshopPlatformSeed.provenance.candidate.js'), 'utf8');
  assert.match(source, /xss_legacy_solution_visibility/);
  assert.match(source, /xss_legacy_solutions/);
});

test('reconciliation is conservative for legacy/custom and upgrades only an unchanged managed default', () => {
  const oldDocument = provenance.document({ title: 'Old', hints: ['one'] });
  const newDocument = provenance.document({ hints: ['two'], title: 'New' });
  const oldHash = provenance.hashDocument(oldDocument);
  assert.equal(provenance.decideReconciliation({ provenance: null,
    currentDocument: oldDocument, sourceDocument: newDocument }).action, 'preserve_unknown');
  assert.equal(provenance.decideReconciliation({ provenance: { provenance_state: 'legacy_unknown' },
    currentDocument: oldDocument, sourceDocument: newDocument }).action, 'preserve');
  assert.equal(provenance.decideReconciliation({ provenance: { provenance_state: 'custom' },
    currentDocument: oldDocument, sourceDocument: newDocument }).action, 'preserve');
  assert.equal(provenance.decideReconciliation({ provenance: { provenance_state: 'managed',
    applied_default_hash: oldHash }, currentDocument: oldDocument, sourceDocument: newDocument }).action,
  'upgrade');
  assert.equal(provenance.decideReconciliation({ provenance: { provenance_state: 'managed',
    applied_default_hash: oldHash }, currentDocument: provenance.document({ title: 'Instructor' }),
  sourceDocument: newDocument }).action, 'mark_custom');
  assert.equal(provenance.decideReconciliation({ provenance: { provenance_state: 'managed',
    applied_default_hash: oldHash }, currentDocument: oldDocument,
  sourceDocument: provenance.document(undefined, false) }).action, 'no_source');
  assert.match(provenance.reconcileField.toString(),
    /sourceDocument\.value !== null \? encode\(sourceDocument\.value\) : sourceDocument\.value/);
});

test('schema and source candidates preserve legacy rows and tombstone visibility', () => {
  const sql = fs.readFileSync(path.join(ROOT,
    'docs/modernization/drafts/workshop-catalog-field-provenance.sql'), 'utf8');
  assert.match(sql, /provenance_state IN \('managed','custom','legacy_unknown'\)/);
  assert.match(sql, /jsonb_build_object\('present',true,'value',v\.field_value\)/);
  assert.match(sql, /REVOKE ALL ON workshop_platform\.catalog_field_defaults FROM PUBLIC/);
  assert.match(sql, /CREATE TRIGGER catalog_field_default_target/);
  assert.match(sql, /REVOKE ALL ON FUNCTION workshop_platform\.validate_catalog_field_default_target\(\) FROM PUBLIC/);
  assert.doesNotMatch(sql, /UPDATE workshop_platform\.(?:exercises|objectives)\s+SET/);
  const seedSource = fs.readFileSync(path.join(ROOT,
    'docs/modernization/drafts/workshopPlatformSeed.provenance.candidate.js'), 'utf8');
  assert.match(seedSource, /SET catalog_active=false,is_enabled=false/);
  assert.match(seedSource, /SET catalog_active=false,is_visible=false/);
  assert.match(seedSource, /SET catalog_active=true,ordinal=\$2/);
  assert.match(seedSource, /hint === null \? null : JSON\.stringify\(hint\)/);
  assert.doesNotMatch(seedSource, /SET catalog_active=true,ordinal=\$2,is_visible=true/);
  assert.equal(typeof createWorkshopPlatformSeed, 'function');
});

test('admin integration marks only edited default-controlled fields and is source pinned',
  { skip: phase.generated }, () => {
  const source = fs.readFileSync(path.join(ROOT,
    'server/database/postgres/workshopConfigRepository.js'), 'utf8');
  const built = configCandidate.buildCandidate(source);
  assert.match(built, /markCustomFields\(client,\{entityKind:'objective'/);
  assert.match(built, /if\(w\.route!==route\)fields\.push\('route'\)/);
  assert.doesNotMatch(built, /fields\.push\('is_visible'\)|fields\.push\('show_solutions'\)/);
  assert.doesNotThrow(() => new Function('require', 'module', 'exports', built));
  assert.throws(() => configCandidate.buildCandidate(`${source}\n`), /reviewed frozen version/);
});

test('native candidate launcher is single-use, owned and stages only a private test migration', () => {
  const source = fs.readFileSync(path.join(ROOT,
    'tests/postgres/run-workshop-catalog-field-provenance-isolated.py'), 'utf8');
  assert.match(source, /EXPECTED_DOCKER='unix:\/\/\/Users\/averma5\/\.colima\/dvaia-pg-verify\/docker\.sock'/);
  assert.match(source, /9999_workshop_catalog_field_provenance\.sql/);
  assert.match(source, /register_owner\(\);prepare\(\);creation_attempted=True/);
  assert.match(source, /grant\['consumerPid'\]=os\.getpid\(\)/);
  assert.match(source, /containerCleanupDebt/);
  assert.match(source, /PG_CATALOG_PROVENANCE_MIGRATION_URL/);
  assert.doesNotMatch(source, /OLLAMA|11434|--network/);
});
