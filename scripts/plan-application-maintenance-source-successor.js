'use strict';
// Read-only successor inventory. A reviewed release change must still add the
// chosen closure, point admission at the new immutable manifest, and test it.
const fs = require('node:fs');
const path = require('node:path');
const { createHash } = require('node:crypto');

const ROOT = path.resolve(__dirname, '..');
const ADMISSION = 'server/services/applicationMaintenanceInprocessAdmission.js';
const ENTRYPOINTS = Object.freeze(['scripts/setup-application.js', 'scripts/start-application.js', 'server/applicationServer.js']);
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const relative = (root, file) => path.relative(root, file).split(path.sep).join('/');

function ownedFile(root, name) {
  const file = path.resolve(root, name);
  if (!file.startsWith(root + path.sep) || fs.realpathSync(file) !== file || !fs.statSync(file).isFile()) {
    throw new Error(`Noncanonical source: ${name}`);
  }
  return fs.readFileSync(file);
}

function sqlInventory(root) {
  const result = [];
  function visit(directory) {
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      const file = path.join(directory, entry.name);
      if (entry.isSymbolicLink()) throw new Error(`Symlink in SQL inventory: ${relative(root, file)}`);
      if (entry.isDirectory()) visit(file);
      else if (entry.name.endsWith('.sql')) result.push(relative(root, file));
    }
  }
  visit(path.join(root, 'db/postgres'));
  return result.sort();
}

function virtualAdmission(bytes, from, to) {
  const oldName = `applicationMaintenanceInprocessSources-v${from}.json`;
  const source = bytes.toString('utf8');
  const count = source.split(oldName).length - 1;
  if (count !== 2) throw new Error(`Expected two active admission references, found ${count}`);
  return Buffer.from(source.split(oldName).join(`applicationMaintenanceInprocessSources-v${to}.json`));
}

function resolveLocal(root, importer, specifier, planned = new Set()) {
  if (!specifier.startsWith('./') && !specifier.startsWith('../')) return null;
  const base = path.resolve(root, path.dirname(importer), specifier);
  if (!base.startsWith(root + path.sep)) throw new Error(`Source import escapes root: ${importer}`);
  for (const candidate of [base, `${base}.js`, `${base}.jsx`, `${base}.cjs`, `${base}.mjs`, `${base}.json`, path.join(base, 'index.js'), path.join(base, 'index.jsx')]) {
    if (planned.has(relative(root, candidate))) return relative(root, candidate);
    try {
      if (fs.statSync(candidate).isFile()) {
        if (fs.realpathSync(candidate) !== candidate) throw new Error(`Symlinked source import: ${relative(root, candidate)}`);
        return relative(root, candidate);
      }
    } catch (error) { if (error.code !== 'ENOENT' && error.code !== 'ENOTDIR') throw error; }
  }
  return null;
}

function staticallyReachableMissing(root, pinned, { sourceOverrides = new Map(), planned = new Set() } = {}) {
  const seen = new Set(), missing = new Set(), unresolved = new Set(), queue = [...ENTRYPOINTS];
  const literal = /\brequire\(\s*['"](\.[^'"]+)['"]\s*\)|\bfrom\s*['"](\.[^'"]+)['"]|\bimport\(\s*['"](\.[^'"]+)['"]\s*\)/g;
  while (queue.length) {
    const name = queue.shift();
    if (seen.has(name)) continue;
    seen.add(name);
    if (!Object.hasOwn(pinned, name) && !planned.has(name)) missing.add(name);
    if (!/\.(?:js|jsx|cjs|mjs)$/.test(name)) continue;
    const source = (sourceOverrides.get(name) || ownedFile(root, name)).toString('utf8');
    for (const match of source.matchAll(literal)) {
      const specifier = match[1] || match[2] || match[3];
      const found = resolveLocal(root, name, specifier, planned);
      if (found) queue.push(found);
      else if (specifier.startsWith('./') || specifier.startsWith('../')) unresolved.add(`${name}: ${specifier}`);
    }
  }
  return { missing: [...missing].sort(), unresolved: [...unresolved].sort(), visited: seen.size };
}

function directMissingFromChanged(root, changed, pinned) {
  const missing = new Set();
  const broadEntrypoints = new Set(ENTRYPOINTS);
  const literal = /\brequire\(\s*['"](\.[^'"]+)['"]\s*\)|\bfrom\s*['"](\.[^'"]+)['"]|\bimport\(\s*['"](\.[^'"]+)['"]\s*\)/g;
  for (const name of changed) {
    if (!/\.(?:js|jsx|cjs|mjs)$/.test(name) || name === ADMISSION || broadEntrypoints.has(name)) continue;
    for (const match of ownedFile(root, name).toString('utf8').matchAll(literal)) {
      const found = resolveLocal(root, name, match[1] || match[2] || match[3]);
      if (found && !Object.hasOwn(pinned, found)) missing.add(found);
    }
  }
  return [...missing].sort();
}

function planSuccessor({ root = ROOT, previousVersion } = {}) {
  root = fs.realpathSync(root);
  if (previousVersion === undefined) {
    const names = [...ownedFile(root, ADMISSION).toString('utf8').matchAll(/applicationMaintenanceInprocessSources-v([1-9][0-9]*)\.json/g)]
      .map(match => Number(match[1]));
    if (names.length !== 2 || names[0] !== names[1]) throw new Error('Active admission pointer unavailable');
    previousVersion = names[0];
  }
  if (!Number.isSafeInteger(previousVersion) || previousVersion < 1) throw new Error('Invalid predecessor version');
  const nextVersion = previousVersion + 1;
  const priorName = `server/services/applicationMaintenanceInprocessSources-v${previousVersion}.json`;
  const prior = JSON.parse(ownedFile(root, priorName));
  if (prior.version !== 1 || prior.profile !== 'canonical16-ctf-inprocess-v1' || !Array.isArray(prior.recoveryFiles) || !prior.files || typeof prior.files !== 'object') throw new Error('Invalid predecessor manifest');
  if (JSON.stringify(prior.recoveryFiles) !== JSON.stringify([...new Set(prior.recoveryFiles)].sort()) ||
      prior.recoveryFiles.some(name => !Object.hasOwn(prior.files, name))) throw new Error('Invalid predecessor recovery inventory');
  const sql = sqlInventory(root), oldSql = Object.keys(prior.files).filter(name => name.startsWith('db/postgres/') && name.endsWith('.sql')).sort();
  const addedSql = sql.filter(name => !Object.hasOwn(prior.files, name));
  const missingSql = oldSql.filter(name => !sql.includes(name));
  if (missingSql.length) throw new Error(`Previously admitted SQL missing: ${missingSql.join(', ')}`);
  const files = { ...prior.files }, changed = [];
  const prospectiveAdmission = virtualAdmission(ownedFile(root, ADMISSION), previousVersion, nextVersion);
  for (const name of Object.keys(files)) {
    const digest = hash(name === ADMISSION ? prospectiveAdmission : ownedFile(root, name));
    if (digest !== files[name]) { changed.push(name); files[name] = digest; }
  }
  for (const name of addedSql) files[name] = hash(ownedFile(root, name));
  const candidate = { version: prior.version, profile: prior.profile, files, recoveryFiles: [...new Set([...prior.recoveryFiles, ...addedSql])].sort() };
  const plannedManifest = `server/services/applicationMaintenanceInprocessSources-v${nextVersion}.json`;
  const reachable = staticallyReachableMissing(root, files, {
    sourceOverrides: new Map([[ADMISSION, prospectiveAdmission]]), planned: new Set([plannedManifest]),
  });
  const directMissing = directMissingFromChanged(root, changed, files).filter(name => name !== priorName);
  return { predecessor: priorName, predecessorSha256: hash(ownedFile(root, priorName)), nextVersion,
    changedPinned: changed.sort(), addedSql, directMissingFromChanged: directMissing,
    staticImportReview: { visited: reachable.visited, missingCount: reachable.missing.length,
      unresolved: reachable.unresolved },
    provisionalManifestSha256: hash(Buffer.from(JSON.stringify(candidate))),
    requiresReview: true, candidate };
}

if (require.main === module) {
  if (process.argv.length !== 2) throw new Error('Usage: node scripts/plan-application-maintenance-source-successor.js');
  const { candidate, ...plan } = planSuccessor();
  process.stdout.write(`${JSON.stringify(plan, null, 2)}\n`);
}

module.exports = { planSuccessor, sqlInventory, virtualAdmission, staticallyReachableMissing, directMissingFromChanged };
