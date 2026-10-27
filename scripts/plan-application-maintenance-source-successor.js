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


// Exactly two nonexecuted drafts retired at the reviewed v339 -> v340 boundary.
// This is historical retirement, not byte equivalence with executable migrations.
function reviewedDraftRetirements(root, previousVersion, priorBytes, prior, missingSql) {
  if (previousVersion !== 339) {
    if (missingSql.length) throw new Error('Previously admitted SQL missing: ' + missingSql.join(', '));
    return [];
  }
  if (hash(priorBytes) !== '36585449ef212b5ae002b31237ba4bcc538b3c64f8e1fc6820b131297e853831') throw new Error('Exact v339 predecessor required');
  const drafts = {
    'db/postgres/drafts/secureshop_owned_registration.sql': '8526dbdb872ece1c6e4493e766c63db0265a4c7822a1f146c5582675466d4e31',
    'db/postgres/drafts/xss_profile_model_origin.sql': 'b00dbc0b6ad7663e339055a4bebad7eb2b9cb522e7c05cb56e8c6f0c704be1d7',
  };
  if (JSON.stringify([...missingSql].sort()) !== JSON.stringify(Object.keys(drafts).sort())) throw new Error('Exact two absent nonexecuted drafts required');
  for (const [name, digest] of Object.entries(drafts)) {
    if (prior.files[name] !== digest || prior.recoveryFiles.filter(value => value === name).length !== 1) throw new Error('Exact draft predecessor entry required');
    // lstat detects dangling links; only ENOENT is evidence of absence.
    for (let parent = path.dirname(path.join(root, name)); parent !== root; parent = path.dirname(parent)) {
      let info;
      try { info = fs.lstatSync(parent); }
      catch (error) { if (error.code === 'ENOENT') continue; throw error; }
      if (!info.isDirectory() || info.isSymbolicLink() || fs.realpathSync(parent) !== parent) throw new Error('Noncanonical retired draft ancestor');
    }
    try { fs.lstatSync(path.join(root, name)); }
    catch (error) { if (error.code === 'ENOENT') continue; throw error; }
    throw new Error('Retired draft still exists: ' + name);
  }
  const xss = 'db/postgres/workshop-migrations/xss/0006_profile_model_origin.sql';
  const registration = 'db/postgres/workshop-migrations/secureshop_agents/0115_owned_mcp_registration_journal.sql';
  const xssSha = '2d22cd959598cd165f80a312d09f582f8ac649e630fce21c840409ecf5adca4f';
  if (prior.files[xss] !== xssSha || hash(ownedFile(root, xss)) !== xssSha) throw new Error('Retained XSS migration changed');
  if (Object.hasOwn(prior.files, registration) || hash(ownedFile(root, registration)) !== 'f02847fa244b35e255208fab9ee5da4325b7e48aea1fe839780e3a0d4245e7f0') throw new Error('Exact added registration migration required');
  return Object.entries(drafts).map(([name, priorSha256]) => ({path: name, priorSha256,
    predecessorVersion: 339, successorVersion: 340,
    justification: 'Explicit retirement of absent nonexecuted draft; executable migrations remain separately admitted; no byte-equivalence claim.'}));
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
  const priorBytes = ownedFile(root, priorName);
  const prior = JSON.parse(priorBytes);
  if (prior.version !== 1 || prior.profile !== 'canonical16-ctf-inprocess-v1' || !Array.isArray(prior.recoveryFiles) || !prior.files || typeof prior.files !== 'object') throw new Error('Invalid predecessor manifest');
  if (JSON.stringify(prior.recoveryFiles) !== JSON.stringify([...new Set(prior.recoveryFiles)].sort()) ||
      prior.recoveryFiles.some(name => !Object.hasOwn(prior.files, name))) throw new Error('Invalid predecessor recovery inventory');
  const sql = sqlInventory(root), oldSql = Object.keys(prior.files).filter(name => name.startsWith('db/postgres/') && name.endsWith('.sql')).sort();
  const addedSql = sql.filter(name => !Object.hasOwn(prior.files, name));
  const missingSql = oldSql.filter(name => !sql.includes(name));
  const retiredDrafts = reviewedDraftRetirements(root, previousVersion, priorBytes, prior, missingSql);
  const retiredNames = new Set(retiredDrafts.map(row => row.path));
  const files = { ...prior.files }, changed = [];
  for (const name of retiredNames) delete files[name];
  const prospectiveAdmission = virtualAdmission(ownedFile(root, ADMISSION), previousVersion, nextVersion);
  for (const name of Object.keys(files)) {
    const digest = hash(name === ADMISSION ? prospectiveAdmission : ownedFile(root, name));
    if (digest !== files[name]) { changed.push(name); files[name] = digest; }
  }
  for (const name of addedSql) files[name] = hash(ownedFile(root, name));
  const candidate = { version: prior.version, profile: prior.profile, files, recoveryFiles: [...new Set([...prior.recoveryFiles.filter(name => !retiredNames.has(name)), ...addedSql])].sort(),
    ...(retiredDrafts.length ? {retiredDrafts} : prior.retiredDrafts ? {retiredDrafts: prior.retiredDrafts} : {}) };
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

module.exports = { reviewedDraftRetirements, planSuccessor, sqlInventory, virtualAdmission, staticallyReachableMissing, directMissingFromChanged };
