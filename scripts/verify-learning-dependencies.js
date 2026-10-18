#!/usr/bin/env node

const fs = require('node:fs');
const path = require('node:path');

const DEFAULT_REPO = path.resolve(__dirname, '..');
const DEFAULT_REGISTRY = 'docs/modernization/learning-dependencies.json';
const ALLOWED_DISPOSITIONS = new Set(['preserve-for-learning', 'investigate', 'current-reviewed']);

function readJson(filename) {
  return JSON.parse(fs.readFileSync(filename, 'utf8'));
}

function packageLockKey(packageName) {
  return `node_modules/${packageName}`;
}

function hasPackageImport(source, packageName) {
  const escaped = packageName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const pattern = new RegExp(`(?:require\\(\\s*['\"]${escaped}(?:/[^'\"]*)?['\"]\\s*\\)|from\\s+['\"]${escaped}(?:/[^'\"]*)?['\"])`);
  return pattern.test(source);
}

function validateRegistry({ repoRoot = DEFAULT_REPO, registryPath = DEFAULT_REGISTRY } = {}) {
  const errors = [];
  const absoluteRegistry = path.resolve(repoRoot, registryPath);
  let registry;

  try {
    registry = readJson(absoluteRegistry);
  } catch (error) {
    return { errors: [`Cannot read registry ${path.relative(repoRoot, absoluteRegistry)}: ${error.message}`], counts: {} };
  }

  if (registry.schemaVersion !== 1) errors.push('Registry schemaVersion must be 1');
  if (!Array.isArray(registry.entries) || registry.entries.length === 0) {
    errors.push('Registry entries must be a non-empty array');
    return { errors, counts: {} };
  }

  const counts = { 'preserve-for-learning': 0, investigate: 0, 'current-reviewed': 0 };
  const identities = new Set();

  for (const [index, entry] of registry.entries.entries()) {
    const label = entry.package || `entry ${index}`;
    const identity = `${entry.manifest || ''}:${entry.scope || ''}:${label}`;
    if (identities.has(identity)) errors.push(`${label}: duplicate registry identity ${identity}`);
    identities.add(identity);

    if (!ALLOWED_DISPOSITIONS.has(entry.disposition)) {
      errors.push(`${label}: unsupported disposition ${JSON.stringify(entry.disposition)}`);
      continue;
    }
    counts[entry.disposition] += 1;

    for (const field of ['manifest', 'lockfile', 'scope', 'declared', 'resolved', 'reviewOwner',
      'whyVersionMatters', 'vulnerableModeExpectation', 'fixedModeExpectation', 'runtimeCompatibility']) {
      if (typeof entry[field] !== 'string' || entry[field].trim() === '') {
        errors.push(`${label}: ${field} must be a non-empty string`);
      }
    }
    for (const field of ['dependencyPaths', 'vulnerabilityIds', 'importingCode', 'proofTests', 'versionSpecificEvidence']) {
      if (!Array.isArray(entry[field])) errors.push(`${label}: ${field} must be an array`);
    }
    if (!Array.isArray(entry.vulnerabilityIds) || entry.vulnerabilityIds.length === 0) {
      errors.push(`${label}: at least one intentional vulnerability id is required`);
    }
    if (!Array.isArray(entry.importingCode) || entry.importingCode.length === 0) {
      errors.push(`${label}: at least one importing code path is required`);
    }
    if (!Array.isArray(entry.proofTests) || entry.proofTests.length === 0) {
      errors.push(`${label}: at least one proof test is required`);
    }
    if (!Array.isArray(entry.dependencyPaths) || entry.dependencyPaths.length === 0) {
      errors.push(`${label}: at least one resolved dependency path is required`);
    }

    if (entry.disposition === 'preserve-for-learning') {
      if (!Array.isArray(entry.versionSpecificEvidence) || entry.versionSpecificEvidence.length === 0) {
        errors.push(`${label}: preserve-for-learning requires versionSpecificEvidence; an advisory or challenge import is insufficient`);
      }
      if (entry.declared !== entry.resolved) {
        errors.push(`${label}: preserve-for-learning must use an exact manifest pin equal to resolved (${entry.resolved})`);
      }
    }
    if (entry.disposition === 'current-reviewed' &&
        (!Array.isArray(entry.qualificationEvidence) || entry.qualificationEvidence.length === 0)) {
      errors.push(`${label}: current-reviewed requires qualificationEvidence`);
    }
    for (const filename of Array.isArray(entry.qualificationEvidence) ? entry.qualificationEvidence : []) {
      if (typeof filename !== 'string' || !filename.trim()) {
        errors.push(`${label}: qualificationEvidence must identify a repository document`);
        continue;
      }
      const absolute = path.resolve(repoRoot, filename);
      const relative = path.relative(repoRoot, absolute);
      if (relative.startsWith(`..${path.sep}`) || relative === '..' || path.isAbsolute(relative)) {
        errors.push(`${label}: qualification evidence must stay inside the repository`);
        continue;
      }
      try {
        if (!fs.readFileSync(absolute, 'utf8').trim()) {
          errors.push(`${label}: qualification evidence ${filename} is empty`);
        }
      } catch {
        errors.push(`${label}: cannot read qualification evidence ${filename}`);
      }
    }

    let manifest;
    const manifestPath = path.resolve(repoRoot, entry.manifest || '');
    try {
      manifest = readJson(manifestPath);
      const actual = manifest[entry.scope]?.[label];
      if (actual !== entry.declared) {
        errors.push(`${label}: ${entry.manifest} ${entry.scope} is ${JSON.stringify(actual)}, expected ${JSON.stringify(entry.declared)}`);
      }
    } catch (error) {
      errors.push(`${label}: cannot read manifest ${entry.manifest}: ${error.message}`);
    }

    let lock;
    const lockPath = path.resolve(repoRoot, entry.lockfile || '');
    try {
      lock = readJson(lockPath);
      const locked = lock.packages?.[packageLockKey(label)]?.version;
      if (locked !== entry.resolved) {
        errors.push(`${label}: ${entry.lockfile} resolves ${JSON.stringify(locked)}, expected ${JSON.stringify(entry.resolved)}`);
      }
      const lockRoot = lock.packages?.[''];
      const lockDeclared = lockRoot?.[entry.scope]?.[label];
      if (lockDeclared !== entry.declared) {
        errors.push(`${label}: ${entry.lockfile} root ${entry.scope} is ${JSON.stringify(lockDeclared)}, expected ${JSON.stringify(entry.declared)}`);
      }
    } catch (error) {
      errors.push(`${label}: cannot read lockfile ${entry.lockfile}: ${error.message}`);
    }

    for (const constraint of entry.transitiveConstraints || []) {
      const parent = lock?.packages?.[packageLockKey(constraint.fromPackage)];
      const actualRange = parent?.dependencies?.[constraint.dependency];
      const actualResolution = lock?.packages?.[packageLockKey(constraint.dependency)]?.version;
      if (actualRange !== constraint.declared) {
        errors.push(`${label}: ${constraint.fromPackage} requires ${constraint.dependency} ${JSON.stringify(actualRange)}, expected ${JSON.stringify(constraint.declared)}`);
      }
      if (actualResolution !== constraint.resolved) {
        errors.push(`${label}: transitive ${constraint.dependency} resolves ${JSON.stringify(actualResolution)}, expected ${JSON.stringify(constraint.resolved)}`);
      }
    }

    let catalog = '';
    const catalogPath = path.resolve(repoRoot, entry.catalogEvidence || '');
    try {
      catalog = fs.readFileSync(catalogPath, 'utf8');
    } catch (error) {
      errors.push(`${label}: cannot read catalog evidence ${entry.catalogEvidence}: ${error.message}`);
    }

    for (const id of entry.vulnerabilityIds || []) {
      if (!catalog.includes(`\`${id}\``)) {
        errors.push(`${label}: catalog ${entry.catalogEvidence} does not identify ${id}`);
      }
    }

    for (const filename of entry.importingCode || []) {
      const absolute = path.resolve(repoRoot, filename);
      try {
        const source = fs.readFileSync(absolute, 'utf8');
        if (!hasPackageImport(source, label)) {
          errors.push(`${label}: ${filename} does not import ${label}`);
        }
        if (!(entry.vulnerabilityIds || []).some((id) => source.includes(`@intentional-vulnerability ${id}`))) {
          errors.push(`${label}: ${filename} lacks a matching intentional-vulnerability annotation`);
        }
      } catch (error) {
        errors.push(`${label}: cannot read importing code ${filename}: ${error.message}`);
      }
    }

    const testEvidence = new Map();
    for (const filename of entry.proofTests || []) {
      try {
        testEvidence.set(filename, fs.readFileSync(path.resolve(repoRoot, filename), 'utf8'));
      } catch (error) {
        errors.push(`${label}: cannot read proof test ${filename}: ${error.message}`);
      }
    }
    for (const id of entry.vulnerabilityIds || []) {
      const provesId = [...testEvidence.values()].some((source) => source.includes(`@intentional-vulnerability ${id}`));
      if (!provesId) errors.push(`${label}: no proof test is annotated for ${id}`);
    }
  }

  return { errors, counts, registry };
}

function parseArgs(argv) {
  const options = {};
  for (let i = 0; i < argv.length; i += 1) {
    if (argv[i] === '--repo-root') options.repoRoot = path.resolve(argv[++i]);
    else if (argv[i] === '--registry') options.registryPath = argv[++i];
    else throw new Error(`Unknown argument: ${argv[i]}`);
  }
  return options;
}

function main() {
  let options;
  try {
    options = parseArgs(process.argv.slice(2));
  } catch (error) {
    console.error(`FAIL: ${error.message}`);
    process.exitCode = 1;
    return;
  }
  const result = validateRegistry(options);
  if (result.errors.length > 0) {
    for (const error of result.errors) console.error(`FAIL: ${error}`);
    process.exitCode = 1;
    return;
  }
  console.log(`PASS: learning dependency registry verified (${result.counts['preserve-for-learning']} protected, ${result.counts.investigate} investigate/frozen, ${result.counts['current-reviewed']} current-reviewed)`);
}

if (require.main === module) main();

module.exports = { validateRegistry, hasPackageImport, parseArgs };
