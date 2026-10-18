'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { Module, createRequire } = require('node:module');
const source = path.join(__dirname, '..');
const manifest = require('../docs/modernization/drafts/workshop-catalog-provenance-live-promotion-manifest-2026-09-14.json');
const archivePath = 'docs/modernization/catalog-0049-reviewed-outputs.json';

test('release phase retains exact historical evidence while allowing later application development', () => {
  // Virtual fixture only: compile the actual helper with a private read overlay.
  // No global fs patch, staged migration, archived source copy, or disk mutation.
  const root = path.join(source, '__virtual_catalog_release_fixture__');
  const files = new Map();
  const key = name => { const file = path.resolve(name); assert.ok(file.startsWith(root + path.sep)); return file; };
  const write = (name, bytes) => files.set(key(path.join(root, name)), Buffer.from(bytes));
  const read = (name, encoding) => {
    const file = key(name);
    if (!files.has(file)) throw Object.assign(new Error('Virtual file absent'), { code: 'ENOENT' });
    const bytes = Buffer.from(files.get(file));
    return encoding ? bytes.toString(encoding) : bytes;
  };
  const helper = require.resolve('./helpers/workshopCatalogReleasePhase');
  const actualRequire = createRequire(helper), compiled = new Module(helper, module);
  compiled.filename = helper;
  compiled.require = name => name === 'node:fs'
    ? Object.freeze({ readFileSync: read, existsSync: file => files.has(key(file)) })
    : actualRequire(name);
  compiled._compile(fs.readFileSync(helper, 'utf8'), helper);
  const { releasePhase, reviewedOutputDigests } = compiled.exports;
  assert.deepEqual(releasePhase({ root }), { name: 'candidate', generated: false });
  for (const [index, migration] of manifest.migrations.entries()) {
    write(`db/postgres/identity-migrations/${migration.name}`, fs.readFileSync(path.join(source, migration.draft)));
    if (index < manifest.migrations.length - 1) assert.throws(() => releasePhase({ root }), /partial/);
  }
  write(archivePath, fs.readFileSync(path.join(source, archivePath)));
  for (const name of Object.keys(manifest.generatedProductionOutputs)) write(name, '// Later application implementation; covered by runtime tests.\n');
  assert.deepEqual(releasePhase({ root }), { name: 'generated', generated: true });
  assert.deepEqual(reviewedOutputDigests(root), manifest.generatedProductionOutputs);
  const archive = JSON.parse(read(path.join(root, archivePath)));
  const first = Object.keys(archive.outputs)[0]; archive.outputs[first] += '\n// altered historical evidence';
  write(archivePath, JSON.stringify(archive));
  assert.throws(() => releasePhase({ root }), /immutable reviewed release/);
  write(archivePath, fs.readFileSync(path.join(source, archivePath)));
  files.delete(key(path.join(root, first)));
  assert.throws(() => releasePhase({ root }), /missing after catalog release/);
  write(first, '// restored current implementation');
  write(`db/postgres/identity-migrations/${manifest.migrations[0].name}`, '-- altered applied migration');
  assert.throws(() => releasePhase({ root }), /differs from the reviewed release/);
});
