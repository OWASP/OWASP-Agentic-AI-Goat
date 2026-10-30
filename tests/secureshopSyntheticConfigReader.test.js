'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { readSyntheticConfig, MAX_BYTES } = require('../sidecars/sandbox-runner/owned-system/config-reader');

function fixture(t) {
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), 'owasp-ai-goat-system-config-'));
  const root = path.join(parent, 'target');
  fs.mkdirSync(path.join(root, 'config'), { recursive: true });
  fs.writeFileSync(path.join(root, 'config', 'service.json'), '{"service":"synthetic"}');
  fs.writeFileSync(path.join(root, '.env'), 'API_KEY=synthetic-learning-secret\n');
  fs.writeFileSync(path.join(parent, 'outside.txt'), 'owned sibling fixture');
  t.after(() => fs.rmSync(parent, { recursive: true, force: true }));
  return { root, parent };
}

test('real config read and single-pass traversal retain authentic synthetic disclosure', t => {
  const { root } = fixture(t);
  const benign = readSyntheticConfig(root, 'service.json');
  assert.equal(benign.ok, true);
  assert.equal(benign.targetPath, '/app/config/service.json');
  assert.equal(benign.content, '{"service":"synthetic"}');
  const escaped = readSyntheticConfig(root, '....//.env');
  assert.equal(escaped.ok, true);
  assert.equal(escaped.sanitized, '../.env');
  assert.equal(escaped.targetPath, '/app/.env');
  assert.equal(escaped.content, fs.readFileSync(path.join(root, '.env'), 'utf8'));
  assert.equal(escaped.size, Buffer.byteLength(escaped.content));
  assert.equal(escaped.contentSha256, crypto.createHash('sha256').update(escaped.content).digest('hex'));
  assert.equal(JSON.stringify(escaped).includes(root), false);
});

test('target boundary denies sibling traversal, absolute paths and malformed input', t => {
  const { root } = fixture(t);
  for (const input of ['....//....//outside.txt', '/etc/passwd', 'C:\\private', '\\\\server\\share', '\0', '\ud800', 'x'.repeat(4097)]) {
    const result = readSyntheticConfig(root, input);
    assert.equal(result.ok, false, input);
    assert.equal(Object.hasOwn(result, 'content'), false);
    assert.equal(JSON.stringify(result).includes(root), false);
  }
});

test('symlinks and hardlinks cannot import another synthetic target file', t => {
  const { root, parent } = fixture(t);
  fs.symlinkSync(path.join(parent, 'outside.txt'), path.join(root, 'config', 'alias'));
  fs.symlinkSync(parent, path.join(root, 'config', 'directory-alias'));
  fs.linkSync(path.join(parent, 'outside.txt'), path.join(root, 'config', 'hardlink'));
  for (const input of ['alias', 'directory-alias/outside.txt', 'hardlink']) assert.equal(readSyntheticConfig(root, input).ok, false);
});

test('reader bounds actual bytes and rejects directories, invalid text and missing files', t => {
  const { root } = fixture(t);
  fs.writeFileSync(path.join(root, 'config', 'large'), Buffer.alloc(MAX_BYTES + 1));
  fs.writeFileSync(path.join(root, 'config', 'invalid'), Buffer.from([0xff]));
  for (const input of ['large', 'invalid', 'missing', '.']) assert.equal(readSyntheticConfig(root, input).ok, false);
  fs.writeFileSync(path.join(root, 'config', 'boundary'), 'a'.repeat(MAX_BYTES));
  assert.equal(readSyntheticConfig(root, 'boundary').size, MAX_BYTES);
});


test('UTF-8 BOM is preserved so content, byte count and digest describe the same bytes', t => {
  const { root } = fixture(t);
  const bytes = Buffer.from('\ufeffSETTING=synthetic\n');
  fs.writeFileSync(path.join(root, 'config', 'bom.env'), bytes);
  const result = readSyntheticConfig(root, 'bom.env');
  assert.equal(result.ok, true);
  assert.deepEqual(Buffer.from(result.content), bytes);
  assert.equal(result.size, bytes.length);
  assert.equal(result.contentSha256, crypto.createHash('sha256').update(Buffer.from(result.content)).digest('hex'));
});
