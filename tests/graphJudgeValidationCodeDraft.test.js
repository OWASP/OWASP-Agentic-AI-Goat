'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { traceData } = require('../server/agent-runtime/runTraceStore');

const root = path.resolve(__dirname, '..');
const draftPath = path.join(root, 'docs/modernization/drafts/graph-judge-validation-code.sql');

test('reserved 0046 mirrors the bounded trace enum without changing migration 0016', () => {
  const prior = fs.readFileSync(path.join(root,
    'db/postgres/identity-migrations/0016_graph_judge_trace_metadata.sql'));
  assert.equal(crypto.createHash('sha256').update(prior).digest('hex'),
    'ae2abb8d9e0ec6f6fb22672add8a7013a08215d825a8593e542a4d9f4c177d72');

  const sql = fs.readFileSync(draftPath, 'utf8');
  assert.match(sql, /DROP CONSTRAINT events_metadata_keys_check/);
  assert.match(sql, /ADD CONSTRAINT events_metadata_keys_check/);
  assert.match(sql, /ADD CONSTRAINT events_validation_code_check/);
  const codes = [
    'JSON_SYNTAX', 'SCHEMA_SHAPE_OR_TYPE', 'EXACT_FACT_CONTRADICTION',
    'CRITERION_EVIDENCE_INVALID', 'CITATION_NOT_GROUNDED', 'CITATION_REQUIRED',
    'OBSERVABLE_SOURCE_REQUIRED', 'VERDICT_INCONSISTENT',
    'REQUIRED_FACT_CONTRADICTION', 'VALIDATION_REJECTED',
  ];
  for (const code of codes) {
    assert.match(sql, new RegExp(`'${code}'`));
    assert.equal(traceData({ validationCode: code }).validationCode, code);
  }
  assert.deepEqual(traceData({ validationCode: 'UNRECOGNIZED', rawResponse: 'private' }), {});
  const allowedKeys = sql.match(/metadata - ARRAY\[([^\]]+)\]/)?.[1] || '';
  assert.doesNotMatch(allowedKeys, /rawResponse|prompt|evidenceDigest|credential/i);
});
