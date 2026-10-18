#!/usr/bin/env node
'use strict';
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const ROOT = path.resolve(__dirname, '..');
const ACCEPTANCE_DIMENSIONS = ['learningTask', 'prerequisites', 'content', 'positive', 'negative', 'resetIsolation', 'parity'];
const ACCEPTANCE_STATUSES = new Set(['pending', 'evidenced', 'unqualified', 'simulation']);
const MATRIX = 'docs/modernization/current-exercise-authenticity-matrix-2026-09-15.json';
const EXPECTED_CTF_IDS = new Set(Array.from({ length: 10 }, (_, i) => `stage_${i + 1}`));
const EXPECTED_LEGACY_IDS = new Set(['xss_email_level_1', 'xss_email_level_2', 'xss_email_level_3', 'xss_email_level_4']);

function validateTeachingContract(record, recommendation, key, errors, canonicalFamily = false) {
  const contract = record?.pedagogyContract;
  if (!contract || typeof contract !== 'object') {
    errors.push(`${key}: missing pedagogy contract`); return;
  }
  for (const field of ['securityLesson', 'prerequisites', 'attackerControlledInput', 'trustBoundary', 'isolatedArtifactOrEffect', 'positiveJudgeProof', 'negativeJudgeProof', 'resetIsolation']) {
    if (typeof contract[field] !== 'string' || !contract[field].trim()) errors.push(`${key}: missing pedagogy ${field}`);
  }
  if (contract.disposition?.recommendation !== recommendation) errors.push(`${key}: conflicting pedagogy disposition`);
  if (typeof contract.disposition?.rationale !== 'string' || !contract.disposition.rationale.trim()) errors.push(`${key}: missing pedagogy disposition rationale`);
  if (!['retain_pending_verification', 'retain_with_required_changes', 'retire', 'retain_qualified_default_disabled', 'retain_verified'].includes(contract.disposition?.implementationDisposition)) errors.push(`${key}: invalid implementation disposition`);
  if (!['pending_full_acceptance', 'accepted', 'qualified_default_disabled', 'verified_scoped_seven_dimensions'].includes(contract.qualificationStatus)) errors.push(`${key}: invalid pedagogy qualification status`);
  // Scoped evidence is not whole-application or all-model release qualification.
  const scopedVerified = contract.qualificationStatus === 'verified_scoped_seven_dimensions';
  const retainedVerified = contract.disposition?.implementationDisposition === 'retain_verified';
  if ((scopedVerified || retainedVerified) && (!scopedVerified || !retainedVerified || recommendation !== 'keep' || !canonicalFamily)) {
    errors.push(`${key}: scoped verification requires paired status, keep recommendation and canonical family record`);
  }
  const qualifiedDisabled = contract.qualificationStatus === 'qualified_default_disabled';
  if (qualifiedDisabled && !canonicalFamily) errors.push(`${key}: qualified default-disabled status requires canonical family record`);
  const retainedDisabled = contract.disposition?.implementationDisposition === 'retain_qualified_default_disabled';
  if ((qualifiedDisabled || retainedDisabled) && (!qualifiedDisabled || !retainedDisabled || recommendation !== 'keep')) {
    errors.push(`${key}: qualified default-disabled disposition requires paired status and keep recommendation`);
  }
  if ((contract.qualificationStatus === 'accepted' || qualifiedDisabled || scopedVerified) && ACCEPTANCE_DIMENSIONS.some(dimension => record.acceptance?.[dimension]?.status !== 'evidenced')) {
    errors.push(`${key}: full acceptance requires every acceptance dimension evidenced`);
  }
}

function validateAcceptanceRecord(record, key, errors) {
  if (!record || typeof record !== 'object') { errors.push(`${key}: missing acceptance record`); return; }
  for (const dimension of ACCEPTANCE_DIMENSIONS) {
    const value = record[dimension];
    if (!value || typeof value !== 'object' || !ACCEPTANCE_STATUSES.has(value.status)) {
      errors.push(`${key}: invalid acceptance ${dimension} status`); continue;
    }
    if (!Array.isArray(value.evidenceRefs) || value.evidenceRefs.some(ref => typeof ref !== 'string' || !ref.trim())) {
      errors.push(`${key}: invalid acceptance ${dimension} evidenceRefs`);
    }
    if (value.status === 'evidenced' && Array.isArray(value.evidenceRefs) && value.evidenceRefs.length === 0) {
      errors.push(`${key}: evidenced ${dimension} requires evidenceRefs`);
    }
  }
}

function validateExerciseAudit(matrix, catalog) {
  const errors = [], expected = new Set(), observed = new Set(), families = new Set();
  for (const [family, objectives] of Object.entries(catalog)) {
    for (const objective of objectives) expected.add(`${family}/${objective.id}`);
  }
  for (const family of matrix.families || []) {
    if (families.has(family.family)) errors.push(`Duplicate family: ${family.family}`);
    families.add(family.family);
    for (const objective of family.objectives || []) {
      const key = `${family.family}/${objective.id}`;
      if (observed.has(key)) errors.push(`Duplicate objective: ${key}`);
      observed.add(key);
      for (const field of ['label', 'scenario', 'authoritativeEffectRequirement', 'remainingVerification']) {
        if (typeof objective[field] !== 'string' || !objective[field].trim()) errors.push(`${key}: missing ${field}`);
      }
      validateAcceptanceRecord(objective.acceptance, key, errors);
      validateTeachingContract(objective, objective.recommendationOverride || family.defaultRecommendation, key, errors, true);
      if (objective.pedagogyContract?.qualificationStatus === 'qualified_default_disabled'
          && catalog[family.family]?.find(entry => entry.id === objective.id)?.defaultEnabled !== false) {
        errors.push(`${key}: qualified default-disabled disposition requires canonical defaultEnabled false`);
      }
      if (!['keep', 'redesign', 'retire'].includes(objective.recommendationOverride || family.defaultRecommendation)) {
        errors.push(`${key}: invalid recommendation`);
      }
    }
  }
  // The four retained acceptance records also describe the canonical builder family.
  // Project identities only: acceptance and history remain in legacyExercises.
  const aliases = matrix.canonicalAliases;
  const aliasIds = new Set();
  if (families.has('xss_email_builder')) errors.push('Conflicting canonical alias family: xss_email_builder');
  if (!Array.isArray(aliases)) errors.push('Missing canonical aliases');
  for (const alias of Array.isArray(aliases) ? aliases : []) {
    if (!alias || Object.keys(alias).sort().join(',') !== 'family,id,namespace'
        || alias.family !== 'xss_email_builder' || alias.namespace !== 'legacyExercises'
        || !EXPECTED_LEGACY_IDS.has(alias.id)) {
      errors.push('Unknown canonical alias'); continue;
    }
    const key = `${alias.family}/${alias.id}`;
    if (aliasIds.has(alias.id)) errors.push(`Duplicate canonical alias: ${key}`);
    aliasIds.add(alias.id);
    if (observed.has(key)) errors.push(`Conflicting canonical alias: ${key}`);
    if ((matrix.legacyExercises || []).filter(record => record?.id === alias.id).length !== 1) {
      errors.push(`Canonical alias requires one legacy record: ${key}`); continue;
    }
    observed.add(key);
    families.add(alias.family);
  }
  for (const id of EXPECTED_LEGACY_IDS) if (!aliasIds.has(id)) errors.push(`Missing canonical alias: xss_email_builder/${id}`);
  for (const key of expected) if (!observed.has(key)) errors.push(`Missing objective: ${key}`);
  for (const key of observed) if (!expected.has(key)) errors.push(`Unknown objective: ${key}`);
  for (const family of Object.keys(catalog)) if (!families.has(family)) errors.push(`Missing family: ${family}`);
  for (const family of families) if (!Object.hasOwn(catalog, family)) errors.push(`Unknown family: ${family}`);
  const namespaceKeys = new Set();
  for (const [namespace, records, expectedIds] of [['ctfStages', matrix.ctfStages, EXPECTED_CTF_IDS], ['legacyExercises', matrix.legacyExercises, EXPECTED_LEGACY_IDS]]) {
    if (!Array.isArray(records) || !records.length) { errors.push(`${namespace}: missing namespace records`); continue; }
    for (const record of records) {
      const key = `${namespace}/${record?.id || '<missing>'}`;
      if (namespaceKeys.has(key)) errors.push(`Duplicate exercise: ${key}`);
      namespaceKeys.add(key);
      if (!record || typeof record.id !== 'string' || !record.id.trim()) errors.push(`${namespace}: missing id`);
      else if (!expectedIds.has(record.id)) errors.push(`${key}: unknown id`);
      if (!['keep', 'redesign', 'retire'].includes(record?.recommendation)) errors.push(`${key}: invalid recommendation`);
      validateAcceptanceRecord(record?.acceptance, key, errors);
      validateTeachingContract(record, record?.recommendation, key, errors);
      if (!Array.isArray(record?.sourceRefs) || record.sourceRefs.some(ref => typeof ref !== 'string' || !ref.trim())) errors.push(`${key}: invalid sourceRefs`);
      if (namespace === 'ctfStages' && !record?.sourceRefs?.includes('server/data/ctfDefaults.js')) {
        errors.push(`${key}: canonical CTF defaults source is required`);
      }
    }
    for (const id of expectedIds) if (!records.some(record => record?.id === id)) errors.push(`Missing exercise: ${namespace}/${id}`);
  }
  const ctfDefaultsHash = matrix.catalogSource?.['server/data/ctfDefaults.js'];
  if (typeof ctfDefaultsHash !== 'string' || !/^[a-f0-9]{64}$/.test(ctfDefaultsHash)) {
    errors.push('ctfStages: canonical CTF defaults source hash is required');
  }
  if (matrix.catalogObjectiveCount !== expected.size) errors.push('Declared objective count differs from current catalog');
  if (matrix.coverageAssertion?.expectedObjectiveCount !== expected.size) errors.push('Coverage assertion objective count differs from current catalog');
  if (matrix.coverageAssertion?.expectedFamilyCount !== Object.keys(catalog).length) errors.push('Coverage assertion family count differs from current catalog');
  if (matrix.catalogFamilyCount !== Object.keys(catalog).length) errors.push('Declared family count differs from current catalog');
  if (!matrix.acceptanceSchema || matrix.acceptanceSchema.statusVocabulary?.join(',') !== [...ACCEPTANCE_STATUSES].join(',')) errors.push('Missing or invalid acceptance schema');
  return { errors, objectiveCount: expected.size, familyCount: Object.keys(catalog).length };
}

// Referenced files must exist, but existence alone never proves exercise success.
function validateEvidenceReferences(matrix, root = ROOT) {
  root = fs.realpathSync(root);
  const errors = [], seen = new Set();
  function visit(value) {
    if (!value || typeof value !== 'object') return;
    if (Array.isArray(value)) { value.forEach(visit); return; }
    for (const [key, child] of Object.entries(value)) {
      if (key === 'evidenceRefs' && Array.isArray(child)) {
        for (const ref of child) {
          if (typeof ref !== 'string' || !ref.trim() || seen.has(ref)) continue;
          seen.add(ref);
          const file = path.resolve(root, ref);
          try {
            if (!file.startsWith(root + path.sep) || !fs.existsSync(file) || !fs.realpathSync(file).startsWith(root + path.sep) || !fs.statSync(file).isFile()) {
              errors.push(`Missing or invalid evidence file: ${ref}`);
            }
          } catch (error) {
            errors.push(`Unreadable evidence file: ${ref}`);
          }
        }
      }
      visit(child);
    }
  }
  visit(matrix);
  return errors;
}

function validateSourceHashes(matrix, root = ROOT) {
  const errors = [];
  const hashes = Object.entries(matrix.catalogSource || {});
  for (const family of matrix.families || []) {
    for (const objective of family.objectives || []) hashes.push(...Object.entries(objective.sourceHashChecks || {}));
  }
  for (const [relative, expected] of hashes) {
    const file = path.resolve(root, relative);
    if (!file.startsWith(root + path.sep) || !fs.existsSync(file)) {
      errors.push(`Missing catalog source: ${relative}`); continue;
    }
    const actual = crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
    if (actual !== expected) errors.push(`Source drift requires review: ${relative}`);
  }
  return errors;
}

if (require.main === module) {
  const matrix = JSON.parse(fs.readFileSync(path.join(ROOT, MATRIX), 'utf8'));
  const { WORKSHOP_OBJECTIVES } = require('../server/config/workshopCatalog');
  const result = validateExerciseAudit(matrix, WORKSHOP_OBJECTIVES);
  result.errors.push(...validateSourceHashes(matrix), ...validateEvidenceReferences(matrix));
  console.log(JSON.stringify({ ...result, scope: 'Catalog audit coverage only; no exercise execution or live enabled-total claim. CTF and legacy namespaces require their separate reviews.' }, null, 2));
  process.exitCode = result.errors.length ? 1 : 0;
}
module.exports = { validateExerciseAudit, validateSourceHashes, validateEvidenceReferences };
