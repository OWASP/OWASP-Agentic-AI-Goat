'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const candidate = require('../scripts/install/secureshop-owned-listings-qualified-candidate');
const planner = require('../scripts/install/secureshop-owned-listings');
const managed = require('../server/services/secureshopListingsManagedConfiguration');
const { workspaceId } = require('../scripts/application-data-root');

const ROOT = path.resolve(__dirname, '..');
const ARCHITECTURE = 'arm64';
const PREDECESSOR = Object.freeze({
  source: 'cc8faa6a5afd6533eebbe5885d112324da5c4ea04a583c4a6607adf0dcf19a2f',
  runtime: '514a0b7cc6d2eadcc515ce7a96af139f7161f3c3989a271d931c068a18812e13'
});
const hash = bytes => crypto.createHash('sha256').update(bytes).digest('hex');

function configuration(sourceManifestSha256, runtimeDigest) {
  const id = workspaceId(ROOT);
  return managed.validate({
    version: 1,
    workspaceId: id,
    enabled: true,
    architecture: ARCHITECTURE,
    dockerAuthoritySha256: 'a'.repeat(64),
    imageId: 'sha256:' + 'b'.repeat(64),
    sourceManifestSha256,
    runtimeDigest,
    profile: { name: 'owasp-ai-goat-owned-listings-' + id, sha256: 'c'.repeat(64) },
    manager: {
      container: 'owasp-ai-goat-owned-listings-' + id,
      url: 'http://127.0.0.1:8099',
      token: 'T'.repeat(43)
    }
  });
}

test('current and exact predecessor installations select their own qualified package', () => {
  const current = candidate.qualifiedPackage({ root: ROOT, architecture: ARCHITECTURE });
  const currentConfig = configuration(current.qualifiedSourceSha256, current.runtimeDigest);
  const oldConfig = configuration(PREDECESSOR.source, PREDECESSOR.runtime);
  const selectedCurrent = candidate.qualifiedInstalledPackage({ root: ROOT, architecture: ARCHITECTURE, configuration: currentConfig });
  const selectedOld = candidate.qualifiedInstalledPackage({ root: ROOT, architecture: ARCHITECTURE, configuration: oldConfig });

  assert.deepEqual(selectedCurrent, current);
  assert.deepEqual(selectedOld, {
    architecture: ARCHITECTURE,
    runtimeDigest: PREDECESSOR.runtime,
    qualifiedSourceSha256: PREDECESSOR.source
  });
  assert.equal(candidate.installedSourceFor(selectedCurrent, currentConfig).sha256, current.qualifiedSourceSha256);
  const oldSource = candidate.installedSourceFor(selectedOld, oldConfig);
  assert.equal(oldSource.sha256, PREDECESSOR.source);
  assert.equal(Object.keys(oldSource.files).length, 25);
  assert.throws(() => candidate.installedSourceFor({ ...selectedOld }, oldConfig), { code: 'LISTINGS_INSTALL_CONFIGURATION_CHANGED' });
  assert.throws(() => candidate.installedSourceFor(selectedOld, currentConfig), { code: 'LISTINGS_INSTALL_CONFIGURATION_CHANGED' });
  assert.throws(() => candidate.installedSourceFor(selectedOld, managed.validate({
    ...oldConfig, manager: { ...oldConfig.manager, token: 'U'.repeat(43) }
  })), { code: 'LISTINGS_INSTALL_CONFIGURATION_CHANGED' });
});

test('historical admission requires exact managed workspace, source and runtime pair', () => {
  const oldConfig = configuration(PREDECESSOR.source, PREDECESSOR.runtime);
  for (const changed of [
    { sourceManifestSha256: 'd'.repeat(64) },
    { runtimeDigest: 'e'.repeat(64) },
    { sourceManifestSha256: candidate.qualifiedPackage({ root: ROOT, architecture: ARCHITECTURE }).qualifiedSourceSha256 },
    { workspaceId: 'f'.repeat(12), profile: { name: 'owasp-ai-goat-owned-listings-' + 'f'.repeat(12), sha256: oldConfig.profile.sha256 }, manager: { ...oldConfig.manager, container: 'owasp-ai-goat-owned-listings-' + 'f'.repeat(12) } }
  ]) {
    assert.throws(
      () => candidate.qualifiedInstalledPackage({ root: ROOT, architecture: ARCHITECTURE, configuration: managed.validate({ ...oldConfig, ...changed }) }),
      { code: changed.workspaceId ? 'LISTINGS_INSTALL_CONFIGURATION_CHANGED' : 'LISTINGS_RUNTIME_PACKAGE_CHANGED' }
    );
  }
  assert.throws(() => candidate.qualifiedInstalledPackage({ root: ROOT, architecture: 'x64', configuration: oldConfig }), { code: 'LISTINGS_INSTALL_PLATFORM_UNQUALIFIED' });
});

test('predecessor admission rejects changed retained report and current source drift', t => {
  const oldConfig = configuration(PREDECESSOR.source, PREDECESSOR.runtime);
  const report = path.join(ROOT, 'scripts/install/qualification/secureshop-listings-runtime-independent-review-2026-09-26.json');
  const reportStat = fs.statSync(report);
  const originalRead = fs.readFileSync;
  const changedReport = t.mock.method(fs, 'readFileSync', function(file, ...args) {
    const bytes = originalRead.call(this, file, ...args);
    if (typeof file === 'number') {
      const stat = fs.fstatSync(file);
      if (stat.dev === reportStat.dev && stat.ino === reportStat.ino) return Buffer.concat([bytes, Buffer.from(' ')]);
    }
    return bytes;
  });
  assert.throws(
    () => candidate.qualifiedInstalledPackage({ root: ROOT, architecture: ARCHITECTURE, configuration: oldConfig }),
    { code: 'LISTINGS_PACKAGE_QUALIFICATION_INVALID' }
  );
  changedReport.mock.restore();
  assert.equal(hash(originalRead(report)), '269fae83100961c1c6149a2540b10453b9dc4ac30b7fa2772960c1e537ade59c');

  const originalOpen = fs.openSync;
  const absentReport = t.mock.method(fs, 'openSync', function(file, ...args) {
    if (file === report) throw Object.assign(new Error('controlled missing report'), { code: 'ENOENT' });
    return originalOpen.call(this, file, ...args);
  });
  assert.throws(() => candidate.qualifiedInstalledPackage({ root: ROOT, architecture: ARCHITECTURE, configuration: oldConfig }), { code: 'ENOENT' });
  absentReport.mock.restore();

  const originalManifest = planner.sourceManifest;
  const drift = t.mock.method(planner, 'sourceManifest', root => {
    const source = originalManifest(root);
    return { ...source, sha256: '0'.repeat(64) };
  });
  assert.throws(
    () => candidate.qualifiedInstalledPackage({ root: ROOT, architecture: ARCHITECTURE, configuration: oldConfig }),
    { code: 'LISTINGS_PACKAGE_SOURCE_CHANGED' }
  );
  drift.mock.restore();
});

test('fresh planning cannot use the historical installed qualification', async t => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'listings-installed-qualification-'));
  t.after(() => fs.rmSync(home, { recursive: true, force: true }));
  fs.mkdirSync(path.join(home, '.owasp-ai-goat', workspaceId(ROOT)), { recursive: true, mode: 0o700 });
  assert.throws(() => candidate.qualifiedPackage({ root: ROOT, architecture: 'x64' }), { code: 'LISTINGS_INSTALL_PLATFORM_UNQUALIFIED' });
  await assert.rejects(
    planner.plan({ root: ROOT, home, platform: 'darwin', architecture: ARCHITECTURE,
      runtimeDigest: PREDECESSOR.runtime, qualifiedSourceSha256: PREDECESSOR.source,
      execute: async () => assert.fail('fresh planning must reject before Docker authority') }),
    { code: 'LISTINGS_INSTALL_SOURCE_UNQUALIFIED' }
  );
});

test('runtime loader retains the exact predecessor without changing its private bytes', t => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'listings-installed-runtime-'));
  t.after(() => fs.rmSync(home, { recursive: true, force: true }));
  const directory = path.join(home, '.owasp-ai-goat', workspaceId(ROOT));
  fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
  const file = path.join(directory, managed.FILE);
  const oldConfig = configuration(PREDECESSOR.source, PREDECESSOR.runtime);
  const bytes = managed.encode(oldConfig);
  fs.writeFileSync(file, bytes, { mode: 0o600 });
  const runtime = require('../server/services/secureshopListingsRuntime');
  const loaded = runtime.loadConfiguration({ root: ROOT, home });
  assert.deepEqual(loaded, oldConfig);
  assert.equal(fs.readFileSync(file, 'utf8'), bytes);
});

const RETAINED_GENERATIONS = Object.freeze([
  Object.freeze({ ...PREDECESSOR,
    report: 'scripts/install/qualification/secureshop-listings-runtime-independent-review-2026-09-26.json',
    reportSha256: '269fae83100961c1c6149a2540b10453b9dc4ac30b7fa2772960c1e537ade59c' }),
  Object.freeze({
    source: '1f472adb1d26289a1c22d0a427cc63d0dad50b4ed06c930cac978d0fd185ea21',
    runtime: '73868207bb2ebbd5e345a9bb6f0062eb7dca52592e62a1988755d6e7596f0608',
    report: 'scripts/install/qualification/secureshop-listings-package-2026-10-10.json',
    reportSha256: '8549e769d30ea468ad83129a6118c77a2672348db0378a97ca1448fb7bea0330' }),
  Object.freeze({
    source: 'a7d806b6b4a331f989ed7487c8c62352f1a16ffb6de3a35a0e82237461dd6d8b',
    runtime: '08d5f2cba9dc21d9c99899c73960a64997d8f58122e6b2d71f6ff7ea42804102',
    report: 'scripts/install/qualification/secureshop-listings-package-2026-10-12.json',
    reportSha256: '2328d6bf0026b497f790cb53f485d8e5fdc1352af550fea46e87bc118c3c9937' }),
]);

for (const generation of RETAINED_GENERATIONS) {
  test(`retained generation ${generation.source.slice(0, 8)} has immutable matching package proof`, () => {
    const bytes = fs.readFileSync(path.join(ROOT, generation.report));
    assert.equal(hash(bytes), generation.reportSha256);
    const report = JSON.parse(bytes);
    const files = Object.fromEntries(Object.entries(report.version === 2
      ? report.source.package.files : report.frozenSourceHashes).sort(([a], [b]) => a.localeCompare(b)));
    assert.equal(Object.keys(files).length, 25);
    const source = { files, sha256: hash(JSON.stringify(files)) };
    assert.equal(source.sha256, generation.source);
    assert.equal(candidate._internals.qualifiedReport(report, source, generation.runtime), true);
  });

  test(`retained generation ${generation.source.slice(0, 8)} is installed-only and keeps private bytes`, async t => {
    const config = configuration(generation.source, generation.runtime);
    const qualified = candidate.qualifiedInstalledPackage({ root: ROOT, architecture: ARCHITECTURE, configuration: config });
    assert.deepEqual(qualified, { architecture: ARCHITECTURE, runtimeDigest: generation.runtime,
      qualifiedSourceSha256: generation.source });
    assert.equal(candidate.installedSourceFor(qualified, config).sha256, generation.source);
    assert.throws(() => candidate.installedSourceFor({ ...qualified }, config), { code: 'LISTINGS_INSTALL_CONFIGURATION_CHANGED' });
    const home = fs.mkdtempSync(path.join(os.tmpdir(), 'listings-retained-generation-'));
    t.after(() => fs.rmSync(home, { recursive: true, force: true }));
    const directory = path.join(home, '.owasp-ai-goat', workspaceId(ROOT));
    fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
    const file = path.join(directory, managed.FILE), bytes = managed.encode(config);
    fs.writeFileSync(file, bytes, { mode: 0o600 });
    assert.deepEqual(require('../server/services/secureshopListingsRuntime').loadConfiguration({ root: ROOT, home }), config);
    assert.equal(fs.readFileSync(file, 'utf8'), bytes);
    await assert.rejects(planner.plan({ root: ROOT, home, platform: 'darwin', architecture: ARCHITECTURE,
      runtimeDigest: generation.runtime, qualifiedSourceSha256: generation.source,
      execute: async () => assert.fail('Retained package must not trigger fresh Docker admission') }),
    { code: 'LISTINGS_INSTALL_SOURCE_UNQUALIFIED' });
  });

  test(`retained generation ${generation.source.slice(0, 8)} rejects report-byte substitution`, t => {
    const report = path.join(ROOT, generation.report), originalRead = fs.readFileSync, expected = fs.statSync(report);
    t.mock.method(fs, 'readFileSync', function(file, ...args) {
      const value = originalRead.call(this, file, ...args);
      if (typeof file === 'number') {
        const stat = fs.fstatSync(file);
        if (stat.dev === expected.dev && stat.ino === expected.ino) return Buffer.concat([value, Buffer.from(' ')]);
      }
      return value;
    });
    assert.throws(() => candidate.qualifiedInstalledPackage({ root: ROOT, architecture: ARCHITECTURE,
      configuration: configuration(generation.source, generation.runtime) }), { code: 'LISTINGS_PACKAGE_QUALIFICATION_INVALID' });
  });
}

test('historical source and runtime identities cannot be mixed between retained generations', () => {
  for (const left of RETAINED_GENERATIONS) for (const right of RETAINED_GENERATIONS) {
    if (left === right) continue;
    assert.throws(() => candidate.qualifiedInstalledPackage({ root: ROOT, architecture: ARCHITECTURE,
      configuration: configuration(left.source, right.runtime) }), { code: 'LISTINGS_RUNTIME_PACKAGE_CHANGED' });
  }
});
