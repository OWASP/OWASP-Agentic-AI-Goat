'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const provenance = require('../server/database/postgres/catalogDefaultProvenance');

function clientFor({ current = 'same', source = 'same', state = 'managed', missing = false }) {
  const applied = provenance.hashDocument(provenance.document(current));
  const updates = [];
  return { updates, async query(sql) {
    if (/SELECT revision/.test(sql)) return { rows: [{ revision: 1 }], rowCount: 1 };
    if (/SELECT label AS value/.test(sql)) return { rows: [{ value: current }], rowCount: 1 };
    if (/SELECT \* FROM workshop_platform\.catalog_field_defaults/.test(sql)) return { rows: [{
      provenance_state: state, applied_default_hash: applied,
    }], rowCount: 1 };
    if (/UPDATE workshop_platform\.catalog_field_defaults/.test(sql)) {
      updates.push(sql); return { rows: [], rowCount: 0 };
    }
    throw new Error(`unexpected query: ${sql}`);
  }, source, missing };
}

test('unchanged managed catalog metadata uses a conditional no-op update', async () => {
  const client = clientFor({});
  const result = await provenance.reconcileField(client, { entityKind:'objective', workshopKey:'mcp_workshop',
    objectiveId:'mcp_cmd_injection', fieldName:'label', sourceValue:client.source,
    sourceVersion:'workshop-defaults-2026-09-14-v1' });
  assert.deepEqual(result, { changed:false, decision:'record' });
  assert.equal(client.updates.length, 1);
  assert.match(client.updates[0], /source_version IS DISTINCT FROM \$5/);
  assert.match(client.updates[0], /observed_document IS DISTINCT FROM \$7::jsonb/);
});

test('missing-source provenance transition is conditional and never edits objective content', async () => {
  const client = clientFor({ state:'custom' });
  const result = await provenance.reconcileField(client, { entityKind:'objective', workshopKey:'mcp_workshop',
    objectiveId:'mcp_cmd_injection', fieldName:'label', sourcePresent:false,
    sourceVersion:'workshop-defaults-2026-09-14-v1' });
  assert.deepEqual(result, { changed:false, decision:'no_source' });
  assert.equal(client.updates.length, 1);
  assert.match(client.updates[0], /source_document IS DISTINCT FROM \$7::jsonb/);
  assert.doesNotMatch(client.updates[0], /UPDATE workshop_platform\.objectives/);
});
