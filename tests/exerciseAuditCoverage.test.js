'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { validateExerciseAudit, validateSourceHashes, validateEvidenceReferences } = require('../scripts/verify-exercise-audit');
const matrix = require('../docs/modernization/current-exercise-authenticity-matrix-2026-09-15.json');
const { WORKSHOP_OBJECTIVES } = require('../server/config/workshopCatalog');
test('every current workshop and SecureShop objective has an audit disposition', () => {
  assert.deepEqual(validateExerciseAudit(matrix, WORKSHOP_OBJECTIVES).errors, []);
});
test('missing, duplicated and unreviewed objectives cannot pass audit coverage', () => {
  const missing = structuredClone(matrix);
  missing.families[0].objectives.pop();
  assert.ok(validateExerciseAudit(missing, WORKSHOP_OBJECTIVES).errors.some(x => x.startsWith('Missing objective:')));
  const duplicate = structuredClone(matrix);
  duplicate.families[0].objectives.push(duplicate.families[0].objectives[0]);
  assert.ok(validateExerciseAudit(duplicate, WORKSHOP_OBJECTIVES).errors.some(x => x.startsWith('Duplicate objective:')));
  const unreviewed = structuredClone(matrix);
  delete unreviewed.families[0].objectives[0].authoritativeEffectRequirement;
  assert.ok(validateExerciseAudit(unreviewed, WORKSHOP_OBJECTIVES).errors.some(x => x.includes('missing authoritativeEffectRequirement')));
  const extraFamily = structuredClone(matrix);
  extraFamily.families.push({ family: 'unlisted_empty_family', objectives: [] });
  assert.ok(validateExerciseAudit(extraFamily, WORKSHOP_OBJECTIVES).errors.some(x => x.startsWith('Unknown family:')));
});

test('acceptance dimensions are explicit and pending does not imply qualification', () => {
  assert.equal(matrix.acceptanceSchema.statusVocabulary.includes('pending'), true);
  const pending = structuredClone(matrix);
  pending.families[0].objectives[0].acceptance.negative = { status: 'pending', evidenceRefs: [] };
  assert.deepEqual(validateExerciseAudit(pending, WORKSHOP_OBJECTIVES).errors, []);
  assert.equal(pending.families[0].objectives[0].acceptance.negative.status, 'pending');
  const missing = structuredClone(matrix);
  delete missing.families[0].objectives[0].acceptance.negative;
  assert.ok(validateExerciseAudit(missing, WORKSHOP_OBJECTIVES).errors.some(x => x.includes('invalid acceptance negative status')));
});

test('CTF and legacy namespaces require explicit acceptance records', () => {
  const missing = structuredClone(matrix);
  delete missing.ctfStages[0].acceptance;
  assert.ok(validateExerciseAudit(missing, WORKSHOP_OBJECTIVES).errors.some(x => x.includes('ctfStages/stage_1: missing acceptance record')));
  const duplicate = structuredClone(matrix);
  duplicate.legacyExercises.push(structuredClone(duplicate.legacyExercises[0]));
  assert.ok(validateExerciseAudit(duplicate, WORKSHOP_OBJECTIVES).errors.some(x => x.includes('Duplicate exercise: legacyExercises/')));
});

test('CTF stages bind the canonical defaults source and detect deliberate source drift', () => {
  assert.ok(matrix.ctfStages.every(stage => stage.sourceRefs.includes('server/data/ctfDefaults.js')));
  const originalPath = path.join(__dirname, '..', 'server/data/ctfDefaults.js');
  const originalBytes = fs.readFileSync(originalPath);
  const originalHash = matrix.catalogSource['server/data/ctfDefaults.js'];
  const { Module, createRequire } = require('node:module');
  const verifierPath = require.resolve('../scripts/verify-exercise-audit');
  const actualRequire = createRequire(verifierPath);
  const verifier = new Module(verifierPath, module);
  verifier.filename = verifierPath;
  verifier.require = name => name === 'node:fs' ? {
    ...fs,
    readFileSync(file, ...args) {
      if (path.resolve(file) === originalPath) return Buffer.concat([originalBytes, Buffer.from('\n// deliberate audit drift\n')]);
      return fs.readFileSync(file, ...args);
    },
  } : actualRequire(name);
  verifier._compile(fs.readFileSync(verifierPath, 'utf8'), verifierPath);
  const drifted = { catalogSource: { 'server/data/ctfDefaults.js': originalHash } };
  assert.deepEqual(verifier.exports.validateSourceHashes(drifted, path.resolve(__dirname, '..')),
    ['Source drift requires review: server/data/ctfDefaults.js']);
  assert.deepEqual(fs.readFileSync(originalPath), originalBytes);
  const missingRef = structuredClone(matrix);
  missingRef.ctfStages[0].sourceRefs = missingRef.ctfStages[0].sourceRefs.filter(ref => ref !== 'server/data/ctfDefaults.js');
  assert.ok(validateExerciseAudit(missingRef, WORKSHOP_OBJECTIVES).errors.some(error => error === 'ctfStages/stage_1: canonical CTF defaults source is required'));
  const missingHash = structuredClone(matrix);
  delete missingHash.catalogSource['server/data/ctfDefaults.js'];
  assert.ok(validateExerciseAudit(missingHash, WORKSHOP_OBJECTIVES).errors.some(error => error.includes('canonical CTF defaults source hash')));
});


test('namespace coverage is exact and evidence status is truthful', () => {
  const missing = structuredClone(matrix);
  missing.ctfStages.splice(0, 1);
  assert.ok(validateExerciseAudit(missing, WORKSHOP_OBJECTIVES).errors.some(x => x.includes('Missing exercise: ctfStages/stage_1')));
  const unknown = structuredClone(matrix);
  unknown.legacyExercises[0].id = 'legacy_surprise';
  assert.ok(validateExerciseAudit(unknown, WORKSHOP_OBJECTIVES).errors.some(x => x.includes('unknown id')));
  const evidenced = structuredClone(matrix);
  evidenced.ctfStages[0].acceptance.learningTask.status = 'evidenced';
  assert.ok(validateExerciseAudit(evidenced, WORKSHOP_OBJECTIVES).errors.some(x => x.includes('evidenced learningTask requires evidenceRefs')));
  const whitespace = structuredClone(matrix);
  whitespace.legacyExercises[0].acceptance.content.evidenceRefs = ['   '];
  assert.ok(validateExerciseAudit(whitespace, WORKSHOP_OBJECTIVES).errors.some(x => x.includes('invalid acceptance content evidenceRefs')));
});

test('teaching contracts cannot omit a lesson or promote incomplete evidence', () => {
  for (const select of [m => m.families[0].objectives[0], m => m.ctfStages[0], m => m.legacyExercises[0]]) {
    const missing = structuredClone(matrix);
    delete select(missing).pedagogyContract.securityLesson;
    assert.ok(validateExerciseAudit(missing, WORKSHOP_OBJECTIVES).errors.some(x => x.includes('missing pedagogy securityLesson')));
    const conflicting = structuredClone(matrix);
    select(conflicting).pedagogyContract.disposition.recommendation = 'retire';
    assert.ok(validateExerciseAudit(conflicting, WORKSHOP_OBJECTIVES).errors.some(x => x.includes('conflicting pedagogy disposition')));
    const premature = structuredClone(matrix);
    select(premature).pedagogyContract.qualificationStatus = 'accepted';
    select(premature).acceptance.negative = { status: 'pending', evidenceRefs: [] };
    assert.ok(validateExerciseAudit(premature, WORKSHOP_OBJECTIVES).errors.some(x => x.includes('full acceptance requires every acceptance dimension evidenced')));
  }
});


test('public-reference unit check rejects missing or escaping files; private evidence is inventoried and deferred', () => {
  // Unit coverage cannot certify private retained evidence under the OS fence.
  // The actual CLI release gate still validates the complete unchanged matrix.
  const publicRefs = new Set(), privateRefs = new Set();
  function collect(value) {
    if (!value || typeof value !== 'object') return;
    if (Array.isArray(value)) { value.forEach(collect); return; }
    for (const [key, child] of Object.entries(value)) {
      if (key === 'evidenceRefs' && Array.isArray(child)) for (const ref of child) {
        (ref.startsWith('backups/private-recovery/') || ref.startsWith('tasks/') ? privateRefs : publicRefs).add(ref);
      }
      collect(child);
    }
  }
  collect(matrix);
  assert.ok(privateRefs.size > 0, 'private evidence remains explicitly outside unit existence qualification');
  assert.deepEqual(validateEvidenceReferences({evidenceRefs:[...publicRefs]}), []);
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'dvaia-audit-evidence-'));
  try {
    fs.writeFileSync(path.join(root, 'receipt.json'), '{}');
    assert.deepEqual(validateEvidenceReferences({ acceptance:{ positive:{ evidenceRefs:['receipt.json'] } } }, root), []);
    fs.symlinkSync(__filename, path.join(root, 'outside.json'));
    for (const ref of ['missing.json', '../receipt.json', '.', 'outside.json']) {
      assert.deepEqual(validateEvidenceReferences({ evidenceRefs:[ref] }, root), [`Missing or invalid evidence file: ${ref}`]);
    }
    const invalid=structuredClone(matrix);
    invalid.families[0].objectives[0].pedagogyContract.disposition.implementationDisposition='unreviewed';
    assert.ok(validateExerciseAudit(invalid, WORKSHOP_OBJECTIVES).errors.some(error=>error.includes('invalid implementation disposition')));
  } finally { fs.rmSync(root, {recursive:true,force:true}); }
});


test('nested coverage assertions cannot retain stale objective or family totals', () => {
  for (const [field, label] of [['expectedObjectiveCount', 'objective'], ['expectedFamilyCount', 'family']]) {
    const stale = structuredClone(matrix);
    stale.coverageAssertion[field] -= 1;
    assert.ok(validateExerciseAudit(stale, WORKSHOP_OBJECTIVES).errors.includes(`Coverage assertion ${label} count differs from current catalog`));
  }
  const missing = structuredClone(matrix);
  delete missing.coverageAssertion;
  assert.ok(validateExerciseAudit(missing, WORKSHOP_OBJECTIVES).errors.includes('Coverage assertion objective count differs from current catalog'));
});

test('builder canonical aliases reuse exactly four legacy records without duplicate acceptance', () => {
  assert.equal(matrix.canonicalAliases.length, 4);
  assert.equal(validateExerciseAudit(matrix, WORKSHOP_OBJECTIVES).objectiveCount,
    Object.values(WORKSHOP_OBJECTIVES).reduce((count, objectives) => count + objectives.length, 0));
  for (const [mutate, expected] of [
    [m => m.canonicalAliases.pop(), 'Missing canonical alias:'],
    [m => m.canonicalAliases.push({...m.canonicalAliases[0]}), 'Duplicate canonical alias:'],
    [m => {m.canonicalAliases[0].id = 'unknown';}, 'Unknown canonical alias'],
    [m => m.families.push({family:'xss_email_builder', objectives:[{id:'xss_email_level_1'}]}), 'Conflicting canonical alias:'],
    [m => m.legacyExercises.pop(), 'Canonical alias requires one legacy record:'],
  ]) {
    const changed = structuredClone(matrix); mutate(changed);
    assert.ok(validateExerciseAudit(changed, WORKSHOP_OBJECTIVES).errors.some(error => error.startsWith(expected)), expected);
  }
});

test('qualified default-disabled disposition requires paired status, complete evidence and canonical disabled default', () => {
  const select = m => m.families.find(f => f.family === 'secureshop_agent_security').objectives.find(o => o.id === 'ss_mail_cross_persona_read');
  assert.equal(select(matrix).pedagogyContract.qualificationStatus, 'qualified_default_disabled');
  assert.deepEqual(validateExerciseAudit(matrix, WORKSHOP_OBJECTIVES).errors, []);
  for (const mutate of [
    row => {delete row.acceptance.negative;},
    row => {row.acceptance.negative = {status:'pending',evidenceRefs:[]};},
    row => {row.pedagogyContract.disposition.implementationDisposition = 'retain_pending_verification';},
    row => {row.pedagogyContract.qualificationStatus = 'accepted';},
    row => {row.recommendationOverride = 'redesign'; row.pedagogyContract.disposition.recommendation = 'redesign';},
  ]) {
    const changed = structuredClone(matrix); mutate(select(changed));
    assert.ok(validateExerciseAudit(changed, WORKSHOP_OBJECTIVES).errors.length > 0);
  }
  const enabled = structuredClone(WORKSHOP_OBJECTIVES);
  enabled.secureshop_agent_security.find(o => o.id === 'ss_mail_cross_persona_read').defaultEnabled = true;
  assert.ok(validateExerciseAudit(matrix, enabled).errors.some(error => error.includes('requires canonical defaultEnabled false')));
});

test('separate CTF and legacy records cannot claim canonical default-disabled qualification', () => {
  for (const namespace of ['ctfStages', 'legacyExercises']) {
    const forged = structuredClone(matrix), row = forged[namespace][0];
    row.recommendation = 'keep';
    row.pedagogyContract.qualificationStatus = 'qualified_default_disabled';
    row.pedagogyContract.disposition.recommendation = 'keep';
    row.pedagogyContract.disposition.implementationDisposition = 'retain_qualified_default_disabled';
    for (const dimension of Object.values(row.acceptance)) {
      dimension.status = 'evidenced'; dimension.evidenceRefs = ['tasks/release-acceptance.json'];
    }
    assert.ok(validateExerciseAudit(forged, WORKSHOP_OBJECTIVES).errors.includes(
      `${namespace}/${row.id}: qualified default-disabled status requires canonical family record`));
  }
});

test('full evidence validation rejects inaccessible retained evidence instead of certifying it', () => {
  const { Module, createRequire } = require('node:module');
  const verifierPath = require.resolve('../scripts/verify-exercise-audit');
  const actualRequire = createRequire(verifierPath), verifier = new Module(verifierPath, module);
  verifier.filename = verifierPath;
  const root = path.resolve(__dirname, '..'), denied = path.join(root, 'synthetic-denied-evidence.json');
  verifier.require = name => name === 'node:fs' ? {
    ...fs,
    existsSync(file) { if (file === denied) return true; return fs.existsSync(file); },
    realpathSync(file) { if (file === denied) throw Object.assign(new Error('controlled denial'), {code:'EPERM'}); return fs.realpathSync(file); },
  } : actualRequire(name);
  verifier._compile(fs.readFileSync(verifierPath, 'utf8'), verifierPath);
  assert.deepEqual(verifier.exports.validateEvidenceReferences({evidenceRefs:['synthetic-denied-evidence.json']}, root),
    ['Unreadable evidence file: synthetic-denied-evidence.json']);
});


test('scoped seven-dimension verification requires paired canonical disposition and complete evidence', () => {
  const select = m => m.families.find(f => f.family === 'excessive_agency').objectives.find(o => o.id === 'objective_7');
  assert.equal(select(matrix).pedagogyContract.qualificationStatus, 'verified_scoped_seven_dimensions');
  assert.deepEqual(validateExerciseAudit(matrix, WORKSHOP_OBJECTIVES).errors, []);
  for (const mutate of [
    row => {row.pedagogyContract.qualificationStatus = 'accepted';},
    row => {row.pedagogyContract.disposition.implementationDisposition = 'retain_pending_verification';},
    row => {row.recommendationOverride = 'redesign'; row.pedagogyContract.disposition.recommendation = 'redesign';},
    ...Object.keys(select(matrix).acceptance).map(key => row => {row.acceptance[key] = {status:'pending',evidenceRefs:[]};}),
    row => {row.acceptance.positive.evidenceRefs = [];},
  ]) {
    const changed = structuredClone(matrix); mutate(select(changed));
    assert.ok(validateExerciseAudit(changed, WORKSHOP_OBJECTIVES).errors.length > 0);
  }
  const changed = structuredClone(matrix), row = changed.ctfStages[0];
  row.recommendation = 'keep';
  row.pedagogyContract.qualificationStatus = 'verified_scoped_seven_dimensions';
  row.pedagogyContract.disposition.recommendation = 'keep';
  row.pedagogyContract.disposition.implementationDisposition = 'retain_verified';
  assert.ok(validateExerciseAudit(changed, WORKSHOP_OBJECTIVES).errors.some(error => error.includes('scoped verification requires paired status')));
});
