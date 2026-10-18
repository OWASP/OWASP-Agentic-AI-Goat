'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const provenance = require('../server/database/postgres/catalogDefaultProvenance');
// Historical target copy is frozen: future guidance must not rewrite this draft.
const snapshotText = fs.readFileSync(path.join(__dirname, '../docs/modernization/drafts/predecessors/0068_finflow_admin_enum_copy_defaults_names_and_purposes.json'), 'utf8');
if (crypto.createHash('sha256').update(snapshotText).digest('hex') !== '3ac3846942acfc32d59da21307370716bcc3d8ccd4dce2d7beec959658c3036d') {
  throw new Error('identity0068 historical target copy changed');
}
const { hints, solutions } = JSON.parse(snapshotText);

const root = path.resolve(__dirname, '..');
const predecessorPath = path.join(root,
  'docs/modernization/drafts/finflow-recon-scope-managed-defaults.candidate.sql');
const outputPath = path.join(root,
  'docs/modernization/drafts/0068_finflow_admin_enum_copy_defaults.sql');
const namesOnlyPredecessorPath = path.join(root,
  'docs/modernization/drafts/predecessors/0068_finflow_admin_enum_copy_defaults_names_only.sql');
const namesOnlyPredecessorRecordPath = path.join(root,
  'docs/modernization/drafts/predecessors/0068_finflow_admin_enum_copy_defaults_names_only.json');
const seedSourcePath = path.join(root, 'server/database/postgres/workshopPlatformSeed.js');
const predecessorSha256 = '5df10119b77c85b52e72dd08477fa636059e7f192660d349b344f8b972492a2f';
const namesOnlyPredecessorSha256 = '00b934ed0e6bd9d07a6cba18e20d222975ddf613a2dd9713a0a2ee2f51be5fb1';
const seedSource = fs.readFileSync(seedSourcePath, 'utf8');
const sourceVersionMatch = seedSource.match(/const CATALOG_VERSION='([^']+)'/);
if (!sourceVersionMatch) throw new Error('canonical workshop seed catalog version is unavailable');
const sourceVersion = sourceVersionMatch[1];

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}
function clone(value) { return JSON.parse(JSON.stringify(value)); }
function document(value) { return provenance.document(value); }
function hash(value) { return provenance.hashDocument(value); }
function encode(value) { return provenance.encode(value); }
function sqlText(value) {
  const text = encode(value);
  if (text.includes('$document$')) throw new Error('catalog document conflicts with SQL delimiter');
  return `$document$${text}$document$::jsonb`;
}

function parseReserved0067() {
  const source = fs.readFileSync(predecessorPath, 'utf8');
  if (sha256(source) !== predecessorSha256) throw new Error('reserved identity0067 lineage hash changed');
  const rows = new Map();
  const pattern = /\('([^']+)','(label|hint_content|solution_content)',\$document\$([\s\S]*?)\$document\$::jsonb,'([0-9a-f]{64})',\$document\$([\s\S]*?)\$document\$::jsonb,'([0-9a-f]{64})'\)/g;
  for (const match of source.matchAll(pattern)) {
    rows.set(`${match[1]}:${match[2]}`, {
      oldDocument: JSON.parse(match[3]), oldHash: match[4],
      newDocument: JSON.parse(match[5]), newHash: match[6],
    });
  }
  for (const key of ['admin_enum:hint_content', 'admin_enum:solution_content']) {
    if (!rows.has(key)) throw new Error(`reserved identity0067 lacks ${key}`);
  }
  return rows;
}

function buildRows() {
  const namesOnlyPredecessor = fs.readFileSync(namesOnlyPredecessorPath, 'utf8');
  if (sha256(namesOnlyPredecessor) !== namesOnlyPredecessorSha256) {
    throw new Error('identity0068 names-only predecessor artifact changed');
  }
  const reserved = parseReserved0067();
  const adminHint = document(hints.admin_enum);
  const adminSolution = document(solutions.admin_enum);
  const priorToolVersion = clone(solutions.tool_version);
  priorToolVersion.tips[1] = 'The tool manifest at /var/app/tools/manifest.json also contains all versions (readable via path traversal)';
  const toolVersionSolution = document(solutions.tool_version);
  const rows = [
    ['admin_enum', 'hint_content', 'identity0041', reserved.get('admin_enum:hint_content').oldDocument, adminHint],
    ['admin_enum', 'hint_content', 'reserved-identity0067', reserved.get('admin_enum:hint_content').newDocument, adminHint],
    ['admin_enum', 'solution_content', 'identity0041', reserved.get('admin_enum:solution_content').oldDocument, adminSolution],
    ['admin_enum', 'solution_content', 'reserved-identity0067', reserved.get('admin_enum:solution_content').newDocument, adminSolution],
    ['tool_version', 'solution_content', 'canonical-before-0068', document(priorToolVersion), toolVersionSolution],
  ].map(([objectiveId, fieldName, oldLineage, oldDocument, newDocument]) => ({
    objectiveId, fieldName, oldLineage, oldDocument, oldHash: hash(oldDocument),
    newDocument, newHash: hash(newDocument),
  }));
  const expectedOldHashes = [
    '77c500931a70b1ec9530da96a08efe93817454cda78d4fb78c82bd34d32df974',
    '7fadc62e31d6ec553830d9f4ad12a31791699e8a456ff5ff4381e024709c5127',
    '592fc334d732e376bb7216a5be1b1ce3bbfd83d382ddce560ad11b29c4c5d106',
    'e94ef5ca26ef2a1e5b1056bfa87dd12d3753524352257d2acd0dcd0356be48ac',
    'acbc7a6208209683897d454a2e60f0a7159841cbb0a56f0a591e351dba61515c',
  ];
  if (rows.some((row, index) => row.oldHash !== expectedOldHashes[index])) {
    throw new Error('identity0068 predecessor document changed');
  }
  return rows;
}

function isEligible({ row, provenanceRow, currentDocument }) {
  if (!row || !provenanceRow || encode(currentDocument) !== encode(row.oldDocument)) return false;
  if (provenanceRow.provenance_state === 'managed') {
    return provenanceRow.applied_default_hash === row.oldHash
      && encode(provenanceRow.applied_default_document) === encode(row.oldDocument);
  }
  return provenanceRow.provenance_state === 'legacy_unknown'
    && encode(provenanceRow.observed_document) === encode(row.oldDocument);
}

function buildSql() {
  const values = buildRows().map(row => ` ('${row.objectiveId}','${row.fieldName}','${row.oldLineage}',${sqlText(row.oldDocument)},'${row.oldHash}',${sqlText(row.newDocument)},'${row.newHash}')`).join(',\n');
  return `-- DRAFT ONLY: reserved identity0068 FinFlow teaching-copy managed-default reconciliation.
-- Unregistered and intentionally outside db/postgres/identity-migrations until 0063-0067 settle.
-- Generated by scripts/generate-finflow-admin-enum-copy-defaults.js from canonical copy,
-- canonical document hashing, and the hash-bound reserved identity0067 predecessor.
-- Preserve custom, missing-provenance, NULL, byte-drifted and unrecognized legacy fields.
WITH defaults(objective_id,field_name,old_lineage,old_document,old_hash,new_document,new_hash) AS (VALUES
${values}
), candidates AS MATERIALIZED (
 SELECT d.* FROM defaults d
 JOIN workshop_platform.objectives o
   ON o.workshop_key='sensitive_info_disclosure' AND o.objective_id=d.objective_id
 JOIN workshop_platform.catalog_field_defaults p ON p.entity_kind='objective'
   AND p.workshop_key=o.workshop_key AND p.objective_id=o.objective_id AND p.field_name=d.field_name
 WHERE CASE d.field_name
     WHEN 'hint_content' THEN jsonb_build_object('present',true,'value',o.hint_content)
     WHEN 'solution_content' THEN jsonb_build_object('present',true,'value',o.solution_content)
   END = d.old_document
   AND (
     (p.provenance_state='managed' AND p.applied_default_hash=d.old_hash
       AND p.applied_default_document=d.old_document)
     OR (p.provenance_state='legacy_unknown' AND p.observed_document=d.old_document)
   )
), changed AS (
 UPDATE workshop_platform.objectives o SET
   hint_content=COALESCE((SELECT c.new_document->'value' FROM candidates c
     WHERE c.objective_id=o.objective_id AND c.field_name='hint_content'),o.hint_content),
   solution_content=COALESCE((SELECT c.new_document->'value' FROM candidates c
     WHERE c.objective_id=o.objective_id AND c.field_name='solution_content'),o.solution_content),
   updated_at=now()
 WHERE o.workshop_key='sensitive_info_disclosure'
   AND EXISTS(SELECT 1 FROM candidates c WHERE c.objective_id=o.objective_id)
 RETURNING o.objective_id
), synced AS (
 UPDATE workshop_platform.catalog_field_defaults p SET
   provenance_state='managed',source_version='${sourceVersion}',source_hash=c.new_hash,
   source_document=c.new_document,applied_default_version='${sourceVersion}',
   applied_default_hash=c.new_hash,applied_default_document=c.new_document,
   observed_document=c.new_document,updated_at=now()
 FROM candidates c JOIN changed x ON x.objective_id=c.objective_id
 WHERE p.entity_kind='objective' AND p.workshop_key='sensitive_info_disclosure'
   AND p.objective_id=c.objective_id AND p.field_name=c.field_name
 RETURNING 1
)
UPDATE workshop_platform.config_revision SET revision=revision+1,updated_at=now()
WHERE id=1 AND EXISTS(SELECT 1 FROM synced);
`;
}

function checkOrWrite({ check = false } = {}) {
  const generated = buildSql();
  if (check) {
    if (!fs.existsSync(outputPath) || fs.readFileSync(outputPath, 'utf8') !== generated) {
      throw new Error('identity0068 draft is not the canonical generated artifact');
    }
    return;
  }
  fs.writeFileSync(outputPath, generated);
}

if (require.main === module) {
  checkOrWrite({ check: process.argv.includes('--check') });
}

module.exports = { predecessorPath, predecessorSha256, outputPath, namesOnlyPredecessorPath,
  namesOnlyPredecessorRecordPath, namesOnlyPredecessorSha256, seedSourcePath, sourceVersion,
  buildRows, buildSql, checkOrWrite, isEligible };
