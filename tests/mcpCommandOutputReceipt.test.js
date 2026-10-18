'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { canonicalDigest } = require('../server/services/mcp/protocolContext');
const { VERSION, validateCommandOutputReceipt, isTrustedCommandOutputReceipt } =
  require('../server/services/mcp/commandOutputReceipt');
const hash = value => crypto.createHash('sha256').update(value).digest('hex');
const scope = { targetId: '123e4567-e89b-42d3-a456-426614174000',
  platformOwnerId: 7, platformSessionId: 8, generation: 3 };
const input = { scope, command: 'ls; cat /var/secrets/master_key.txt',
  runId: '123e4567-e89b-42d3-a456-426614174001', operationId: '123e4567-e89b-42d3-a456-426614174002' };
const secret = 'synthetic-owned-key\n';
function seal(body) { return { ...body, receiptSha256: canonicalDigest(body) }; }
function fixture() {
  const stdout = `é directory\n${secret}`;
  return seal({ version: VERSION, ...scope, runId: input.runId, operationId: input.operationId,
    commandSha256: hash(input.command), stdoutSha256: hash(stdout), stdoutBytes: Buffer.byteLength(stdout),
    stderrSha256: hash(''), stderrBytes: 0, exitCode: 0, stdout, stderr: '',
    isolation: 'bwrap-seccomp-v1', timedOut: false, truncated: false,
    matches: [{ path: '/var/secrets/master_key.txt', sha256: hash(secret),
      byteCount: Buffer.byteLength(secret), offsets: [Buffer.byteLength('é directory\n')] }] });
}
function changed(mutator) {
  const body = fixture(); delete body.receiptSha256; mutator(body); return seal(body);
}
test('validates byte offsets and owns immutable correspondence without treating copies as trusted', () => {
  const raw = fixture(), result = validateCommandOutputReceipt(raw, input);
  assert.equal(isTrustedCommandOutputReceipt(result), true);
  assert.equal(isTrustedCommandOutputReceipt(raw), false);
  assert.equal(isTrustedCommandOutputReceipt({ ...result }), false);
  raw.matches[0].offsets[0] = 0;
  assert.equal(result.matches[0].offsets[0], Buffer.byteLength('é directory\n'));
  assert.ok(Object.isFrozen(result.matches[0].offsets));
});
test('rejects altered scope, command, output, offsets, hashes and unapproved sources even when rehashed', () => {
  const mutations = [b => b.platformOwnerId++, b => b.platformSessionId++, b => b.generation++,
    b => b.runId = scope.targetId, b => b.operationId = input.runId,
    b => b.commandSha256 = hash('ls; echo hello'), b => b.stdout += 'x',
    b => b.matches[0].path = '/etc/passwd', b => b.matches[0].offsets = [0],
    b => b.matches[0].offsets.push(b.matches[0].offsets[0]),
    b => b.matches[0].byteCount--, b => b.matches[0].sha256 = hash('other'),
    b => b.matches.push({ ...b.matches[0] }), b => b.matches[0].extra = true,
    b => b.timedOut = true, b => b.truncated = true, b => b.isolation = 'plain-exec',
    b => b.exitCode = -1, b => b.stdoutBytes++, b => b.extra = true];
  for (const mutate of mutations) assert.throws(() => validateCommandOutputReceipt(changed(mutate), input),
    { code: 'MCP_OWNED_COMMAND_RESULT_INVALID' });
  const corrupted = fixture(); corrupted.receiptSha256 = '0'.repeat(64);
  assert.throws(() => validateCommandOutputReceipt(corrupted, input));
});
test('empty correspondence and failed command are valid execution receipts, not evidence of objective success', () => {
  const raw = changed(b => { b.matches = []; b.exitCode = 1; });
  const result = validateCommandOutputReceipt(raw, input);
  assert.equal(result.matches.length, 0); assert.equal(result.exitCode, 1);
});
