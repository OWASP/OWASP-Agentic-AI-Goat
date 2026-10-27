'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const { createHash } = require('node:crypto');
const diagnostic = require('./secureshopAuditV15WholeRecordDiagnostic');
const sha = bytes => createHash('sha256').update(bytes).digest('hex');

test('V15 retained adapter is inert and rejects path or pin substitution', () => {
  assert.equal(diagnostic.VERSION, 'secureshop-audit-v15-retained-whole-record-v1');
  assert.equal(diagnostic.ORIGINAL_SHA256.length, 64);
  assert.throws(() => diagnostic.readOriginal({ file: '/tmp/foreign.json' }), /path mismatch/);
  assert.throws(() => diagnostic.readOriginal({ expectedSha256: '0'.repeat(64) }), /pin mismatch/);
  assert.equal(typeof diagnostic.validateOriginal, 'function');
});

test('pinned failed V15 capture retains whole packet, task, source, and two rejected calls', {
  skip: process.env.V15_RETAINED_WHOLE_RECORD_DIAGNOSTIC !== '1',
}, () => {
  assert.equal(fs.existsSync(diagnostic.ORIGINAL), true, 'Requested original capture is missing');
  const capture = diagnostic.readOriginal();
  const value = diagnostic.validateOriginal(capture);
  assert.equal(value.diagnosticOnly, true);
  assert.equal(value.creditAuthorized, false);
  assert.equal(value.originalVerdict, 'unavailable');
  assert.equal(value.originalErrorCode, 'INVALID_JUDGE_OUTPUT');
  assert.equal(value.rejectedSourceAttempts.length, 2);
  assert.equal(sha(value.originalPacket), value.packetSha256);
  const changed = structuredClone(capture);
  changed.observed.judgeTranscripts[0].calls[0].disposition = 'accepted';
  assert.throws(() => diagnostic.validateOriginal(changed), /source rejection mismatch/);
  const changedPacket = structuredClone(capture);
  changedPacket.runs.vuln.judgeInput.packet += ' ';
  assert.throws(() => diagnostic.validateOriginal(changedPacket), /transcript packet mismatch/);
  const changedArtifact = structuredClone(capture);
  changedArtifact.runs.vuln.artifactReads.messages.sha256 = '0'.repeat(64);
  assert.throws(() => diagnostic.validateOriginal(changedArtifact), /actor messages digest reference mismatch/);
  const changedSource = structuredClone(capture);
  changedSource.originalSource.entry.event.params_json += ' ';
  assert.throws(() => diagnostic.validateOriginal(changedSource), /source artifact binding unavailable/);
  const changedPhysical = structuredClone(capture);
  changedPhysical.physicalMerchantSave.original.confirm.body.preview.after.description = 'substituted';
  assert.throws(() => diagnostic.validateOriginal(changedPhysical), /confirmed description mismatch/);
  const changedReceipt = structuredClone(capture);
  changedReceipt.physicalMerchantSave.original.confirm.value.scopeKey = '0'.repeat(64);
  assert.throws(() => diagnostic.validateOriginal(changedReceipt), /receipt scope mismatch/);
});
