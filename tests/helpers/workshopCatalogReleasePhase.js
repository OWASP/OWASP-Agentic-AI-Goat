'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '../..');
const manifest = require('../../docs/modernization/drafts/workshop-catalog-provenance-live-promotion-manifest-2026-09-14.json');

function hash(relative, root = ROOT) {
  return crypto.createHash('sha256').update(fs.readFileSync(path.join(root, relative))).digest('hex');
}

function reviewedOutputDigests(root = ROOT) {
  const archive = JSON.parse(fs.readFileSync(path.join(root,
    'docs/modernization/catalog-0049-reviewed-outputs.json'), 'utf8'));
  const names = Object.keys(manifest.generatedProductionOutputs).sort();
  if (archive.version !== 1 || JSON.stringify(Object.keys(archive.outputs || {}).sort()) !== JSON.stringify(names)) {
    throw new Error('reviewed catalog source archive inventory mismatch');
  }
  const digests = {};
  for (const name of names) {
    if (typeof archive.outputs[name] !== 'string') throw new Error('reviewed catalog source archive entry is invalid');
    digests[name] = crypto.createHash('sha256').update(archive.outputs[name], 'utf8').digest('hex');
    if (digests[name] !== manifest.generatedProductionOutputs[name]) {
      throw new Error(`${name} differs from the immutable reviewed release`);
    }
  }
  return Object.freeze(digests);
}

function releasePhase({ root = ROOT } = {}) {
  const migrations = manifest.migrations.map(row =>
    `db/postgres/identity-migrations/${row.name}`);
  const present = migrations.filter(relative => fs.existsSync(path.join(root, relative)));
  if (present.length === 0) return Object.freeze({ name: 'candidate', generated: false });
  if (present.length !== migrations.length) throw new Error('partial workshop catalog release migration set');
  for (const row of manifest.migrations) {
    const target = `db/postgres/identity-migrations/${row.name}`;
    if (hash(target, root) !== row.sha256) throw new Error(`${target} differs from the reviewed release`);
  }
  reviewedOutputDigests(root);
  // The phase follows immutable migrations. The completed release's exact
  // outputs are archived above; later application edits have behavioral tests
  // and must not be mistaken for a rollback into the pre-release candidate.
  for (const relative of Object.keys(manifest.generatedProductionOutputs)) {
    if (!fs.existsSync(path.join(root, relative))) throw new Error(`${relative} is missing after catalog release`);
  }
  return Object.freeze({ name: 'generated', generated: true });
}

module.exports = { releasePhase, reviewedOutputDigests };
