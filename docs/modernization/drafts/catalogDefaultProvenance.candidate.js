'use strict';

const crypto = require('node:crypto');

const FIELD = Object.freeze({
  exercise: Object.freeze({
    challenge_name: 'text', challenge_description: 'text', category: 'text', difficulty: 'text', route: 'text',
  }),
  objective: Object.freeze({ label: 'text', category: 'text', hint_content: 'jsonb', solution_content: 'jsonb' }),
});

function stable(value) {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return value;
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new TypeError('catalog defaults must be finite JSON values');
    return value;
  }
  if (typeof value !== 'object') throw new TypeError('catalog defaults must be JSON values');
  if (Array.isArray(value)) return value.map(stable);
  if (Object.getPrototypeOf(value) !== Object.prototype) {
    throw new TypeError('catalog defaults must use plain JSON objects');
  }
  return Object.fromEntries(Object.keys(value).sort().map(key => [key, stable(value[key])]));
}
function document(value, present = true) {
  if (typeof present !== 'boolean' || (present && value === undefined)) {
    throw new TypeError('catalog document requires explicit missing or a JSON value');
  }
  return present ? { present: true, value: stable(value) } : { present: false };
}
function encode(value) { return JSON.stringify(stable(value)); }
function hashDocument(value) { return crypto.createHash('sha256').update(encode(value)).digest('hex'); }
function identity(value) {
  if (!value || !FIELD[value.entityKind]?.[value.fieldName]
      || typeof value.workshopKey !== 'string' || !/^[a-z0-9][a-z0-9_-]{0,99}$/i.test(value.workshopKey)
      || (value.entityKind === 'objective' && (typeof value.objectiveId !== 'string' || !value.objectiveId))) {
    throw new TypeError('invalid catalog field identity');
  }
  return { ...value, objectiveId: value.entityKind === 'exercise' ? '' : value.objectiveId };
}
function decideReconciliation({ provenance, currentDocument, sourceDocument }) {
  const currentHash = hashDocument(currentDocument);
  const sourceHash = hashDocument(sourceDocument);
  if (sourceDocument.present === false) return { action: 'no_source', currentHash, sourceHash };
  if (!provenance) return { action: 'preserve_unknown', currentHash, sourceHash };
  if (provenance.provenance_state !== 'managed') {
    return { action: 'preserve', state: provenance.provenance_state, currentHash, sourceHash };
  }
  if (provenance.applied_default_hash !== currentHash) {
    return { action: 'mark_custom', currentHash, sourceHash };
  }
  return { action: currentHash === sourceHash ? 'record' : 'upgrade', currentHash, sourceHash };
}
function relation(spec) {
  const item = identity(spec);
  return item.entityKind === 'exercise'
    ? { ...item, table: 'workshop_platform.exercises', predicate: 'workshop_key=$1', keys: [item.workshopKey] }
    : { ...item, table: 'workshop_platform.objectives', predicate: 'workshop_key=$1 AND objective_id=$2',
      keys: [item.workshopKey, item.objectiveId] };
}
async function reconcileField(client, spec) {
  if (!client?.query || typeof spec.sourceVersion !== 'string' || !spec.sourceVersion) {
    throw new TypeError('catalog reconciliation dependencies required');
  }
  const item = relation(spec);
  await client.query('SELECT revision FROM workshop_platform.config_revision WHERE id=1 FOR UPDATE');
  const currentResult = await client.query(`SELECT ${item.fieldName} AS value FROM ${item.table}
    WHERE ${item.predicate} FOR UPDATE`, item.keys);
  if (currentResult.rowCount !== 1) throw new Error('catalog entity missing');
  const currentDocument = document(currentResult.rows[0].value);
  const sourceDocument = spec.sourcePresent === false ? document(undefined, false) : document(spec.sourceValue);
  const provenanceResult = await client.query(`SELECT * FROM workshop_platform.catalog_field_defaults
    WHERE entity_kind=$1 AND workshop_key=$2 AND objective_id=$3 AND field_name=$4 FOR UPDATE`,
  [item.entityKind, item.workshopKey, item.objectiveId, item.fieldName]);
  const provenance = provenanceResult.rows[0];
  const decision = decideReconciliation({ provenance, currentDocument, sourceDocument });
  if (decision.action === 'no_source') {
    if (!provenance) {
      await client.query(`INSERT INTO workshop_platform.catalog_field_defaults
        (entity_kind,workshop_key,objective_id,field_name,provenance_state,source_version,source_hash,
         source_document,observed_document) VALUES($1,$2,$3,$4,'legacy_unknown',$5,$6,$7::jsonb,$8::jsonb)`,
      [item.entityKind,item.workshopKey,item.objectiveId,item.fieldName,spec.sourceVersion,
        decision.sourceHash,encode(sourceDocument),encode(currentDocument)]);
    } else {
      await client.query(`UPDATE workshop_platform.catalog_field_defaults SET source_version=$5,
        source_hash=$6,source_document=$7::jsonb,observed_document=$8::jsonb,updated_at=now()
        WHERE entity_kind=$1 AND workshop_key=$2 AND objective_id=$3 AND field_name=$4`,
      [item.entityKind,item.workshopKey,item.objectiveId,item.fieldName,spec.sourceVersion,
        decision.sourceHash,encode(sourceDocument),encode(currentDocument)]);
    }
    return { changed: false, decision: decision.action };
  }
  if (!provenance) {
    await client.query(`INSERT INTO workshop_platform.catalog_field_defaults
      (entity_kind,workshop_key,objective_id,field_name,provenance_state,source_version,source_hash,
       source_document,observed_document) VALUES($1,$2,$3,$4,'legacy_unknown',$5,$6,$7::jsonb,$8::jsonb)`,
    [item.entityKind,item.workshopKey,item.objectiveId,item.fieldName,spec.sourceVersion,
      decision.sourceHash,encode(sourceDocument),encode(currentDocument)]);
    return { changed: false, decision: decision.action };
  }
  if (decision.action === 'mark_custom') {
    await client.query(`UPDATE workshop_platform.catalog_field_defaults SET provenance_state='custom',
      source_version=$5,source_hash=$6,source_document=$7::jsonb,observed_document=$8::jsonb,updated_at=now()
      WHERE entity_kind=$1 AND workshop_key=$2 AND objective_id=$3 AND field_name=$4`,
    [item.entityKind,item.workshopKey,item.objectiveId,item.fieldName,spec.sourceVersion,
      decision.sourceHash,encode(sourceDocument),encode(currentDocument)]);
    return { changed: false, decision: decision.action };
  }
  if (!['upgrade','record'].includes(decision.action)) {
    await client.query(`UPDATE workshop_platform.catalog_field_defaults SET source_version=$5,
      source_hash=$6,source_document=$7::jsonb,observed_document=$8::jsonb,updated_at=now()
      WHERE entity_kind=$1 AND workshop_key=$2 AND objective_id=$3 AND field_name=$4`,
    [item.entityKind,item.workshopKey,item.objectiveId,item.fieldName,spec.sourceVersion,
      decision.sourceHash,encode(sourceDocument),encode(currentDocument)]);
    return { changed: false, decision: decision.action };
  }
  if (sourceDocument.present !== true) throw new Error('missing values require an explicit retirement migration');
  let changed = false;
  if (decision.action === 'upgrade') {
    const cast = FIELD[item.entityKind][item.fieldName] === 'jsonb' ? '::jsonb' : '';
    const value = cast && sourceDocument.value !== null ? encode(sourceDocument.value) : sourceDocument.value;
    const expected = cast && currentDocument.value !== null
      ? encode(currentDocument.value) : currentDocument.value;
    const updated = await client.query(`UPDATE ${item.table} SET ${item.fieldName}=$${item.keys.length + 1}${cast},updated_at=now()
      WHERE ${item.predicate} AND ${item.fieldName} IS NOT DISTINCT FROM $${item.keys.length + 2}${cast}`,
    [...item.keys, value, expected]);
    if (updated.rowCount !== 1) throw new Error('catalog field changed during reconciliation');
    changed = true;
  }
  await client.query(`UPDATE workshop_platform.catalog_field_defaults SET provenance_state='managed',
    source_version=$5,source_hash=$6,source_document=$7::jsonb,applied_default_version=$5,
    applied_default_hash=$6,applied_default_document=$7::jsonb,observed_document=$7::jsonb,updated_at=now()
    WHERE entity_kind=$1 AND workshop_key=$2 AND objective_id=$3 AND field_name=$4`,
  [item.entityKind,item.workshopKey,item.objectiveId,item.fieldName,spec.sourceVersion,
    decision.sourceHash,encode(sourceDocument)]);
  return { changed, decision: decision.action };
}
async function adoptInsertedField(client, spec) {
  if (!client?.query || typeof spec.sourceVersion !== 'string' || !spec.sourceVersion) {
    throw new TypeError('inserted catalog default required');
  }
  const item = relation(spec);
  await client.query('SELECT revision FROM workshop_platform.config_revision WHERE id=1 FOR UPDATE');
  const current = await client.query(`SELECT ${item.fieldName} AS value FROM ${item.table}
    WHERE ${item.predicate} FOR UPDATE`, item.keys);
  if (current.rowCount !== 1) throw new Error('inserted catalog entity missing');
  const currentDocument = document(current.rows[0].value);
  const sourceDocument = spec.sourcePresent === false ? document(undefined, false) : document(spec.sourceValue);
  const sourceHash = hashDocument(sourceDocument);
  const appliedHash = hashDocument(currentDocument);
  if (sourceDocument.present && appliedHash !== sourceHash) {
    throw new Error('inserted catalog field differs from source default');
  }
  const inserted = await client.query(`INSERT INTO workshop_platform.catalog_field_defaults
    (entity_kind,workshop_key,objective_id,field_name,provenance_state,source_version,source_hash,
     source_document,applied_default_version,applied_default_hash,applied_default_document,observed_document)
    VALUES($1,$2,$3,$4,'managed',$5,$6,$7::jsonb,$5,$8,$9::jsonb,$9::jsonb)
    ON CONFLICT DO NOTHING`, [item.entityKind,item.workshopKey,item.objectiveId,item.fieldName,
    spec.sourceVersion,sourceHash,encode(sourceDocument),appliedHash,encode(currentDocument)]);
  if (inserted.rowCount !== 1) throw new Error('inserted catalog field provenance already exists');
}
async function markCustomFields(client, spec, fieldNames) {
  const ids = fieldNames.map(fieldName => identity({ ...spec, fieldName }));
  if (!ids.length) return;
  await client.query('SELECT revision FROM workshop_platform.config_revision WHERE id=1 FOR UPDATE');
  for (const item of ids) {
    const updated = await client.query(`UPDATE workshop_platform.catalog_field_defaults
      SET provenance_state='custom',updated_at=now()
      WHERE entity_kind=$1 AND workshop_key=$2 AND objective_id=$3 AND field_name=$4`,
    [item.entityKind,item.workshopKey,item.objectiveId,item.fieldName]);
    if (updated.rowCount !== 1) throw new Error('catalog field provenance missing');
  }
}

module.exports = { FIELD, stable, document, encode, hashDocument, decideReconciliation,
  reconcileField, adoptInsertedField, markCustomFields };
