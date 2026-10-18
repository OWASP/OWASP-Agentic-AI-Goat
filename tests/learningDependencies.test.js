const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { validateRegistry } = require('../scripts/verify-learning-dependencies');

const REPO = path.resolve(__dirname, '..');
const REGISTRY_PATH = path.join(REPO, 'docs/modernization/learning-dependencies.json');

function withRegistryMutation(t, mutate) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'dvaia-learning-deps-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const registry = JSON.parse(fs.readFileSync(REGISTRY_PATH, 'utf8'));
  mutate(registry);
  const filename = path.join(directory, 'registry.json');
  fs.writeFileSync(filename, `${JSON.stringify(registry, null, 2)}\n`);
  return filename;
}

test('repository learning dependency registry matches manifests, lockfiles, imports, catalog and proofs', () => {
  const result = validateRegistry({ repoRoot: REPO });
  assert.deepEqual(result.errors, []);
  assert.deepEqual(result.counts, {
    'preserve-for-learning': 0,
    investigate: 0,
    'current-reviewed': 4,
  });
});

test('an exact pin cannot be promoted to protected without version-specific evidence', (t) => {
  const registryPath = withRegistryMutation(t, (registry) => {
    registry.entries[0].disposition = 'preserve-for-learning';
  });
  const result = validateRegistry({ repoRoot: REPO, registryPath });
  assert.ok(result.errors.some((error) => error.includes('requires versionSpecificEvidence')));
  assert.ok(!result.errors.some((error) => error.includes('must use an exact manifest pin')));
});

test('protected dependencies reject version ranges even when the resolved version is unchanged', (t) => {
  const registryPath = withRegistryMutation(t, (registry) => {
    registry.entries[0].disposition = 'preserve-for-learning';
    registry.entries[0].declared = `^${registry.entries[0].resolved}`;
  });
  const result = validateRegistry({ repoRoot: REPO, registryPath });
  assert.ok(result.errors.some((error) => error.includes('must use an exact manifest pin')));
});

test('lockfile drift in an investigated dependency fails closed', (t) => {
  const registryPath = withRegistryMutation(t, (registry) => {
    registry.entries.find((entry) => entry.package === 'sax').resolved = '9.9.9';
  });
  const result = validateRegistry({ repoRoot: REPO, registryPath });
  assert.ok(result.errors.some((error) => error.includes('package-lock.json resolves "1.6.1", expected "9.9.9"')));
  assert.ok(result.errors.some((error) => error.includes('transitive sax resolves "1.6.0", expected "9.9.9"')) === false);
});

test('transitive dependency re-resolution is checked independently of the direct package entry', (t) => {
  const registryPath = withRegistryMutation(t, (registry) => {
    const sax = registry.entries.find((entry) => entry.package === 'sax');
    sax.transitiveConstraints[0].resolved = '9.9.9';
  });
  const result = validateRegistry({ repoRoot: REPO, registryPath });
  assert.ok(result.errors.some((error) => error.includes('transitive sax resolves "1.6.1", expected "9.9.9"')));
});

test('reviewed dependency cannot rely on missing or out-of-repository qualification evidence', t => {
  for (const evidence of ['docs/modernization/missing-qualification.json', '../outside-qualification.md', null]) {
    const registryPath = withRegistryMutation(t, registry => {
      registry.entries[0].qualificationEvidence = [evidence];
    });
    const result = validateRegistry({ repoRoot: REPO, registryPath });
    assert.ok(result.errors.some(error => /qualification evidence|qualificationEvidence/.test(error)));
  }
});
