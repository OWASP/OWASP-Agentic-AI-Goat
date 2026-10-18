'use strict';

const fs = require('node:fs');
const path = require('node:path');

function isolatedDatabaseGuard(source) {
  source = fs.realpathSync(source);
  const guard = fs.realpathSync(path.join(source, 'scripts/lib/isolated-database-access-guard.cjs'));
  if (!guard.startsWith(`${source}${path.sep}`) || !fs.statSync(guard).isFile() || !path.isAbsolute(guard)) {
    throw new Error('Database guard must be a canonical source file');
  }
  return guard;
}

function selectIsolatedTests(source, mode, requested) {
  const native = require('./native-secureshop-suites');
  const requestedNative = requested.find(file => native.deferredNative.some(row => row.file === file));
  if (requestedNative) throw new Error(`Native PostgreSQL/browser suite ${requestedNative} requires ${native.command}; native-browser-only dispatch cannot provision its PostgreSQL stores`);
  const nativeBrowserFiles = new Set(Object.values(require('./native-browser-suites')).flat().map(row => row.file));
  if (requested.some(file => nativeBrowserFiles.has(file))) throw new Error('Native browser suites require npm run test:native-browser or npm run test:admin-bundle for the admin bundle, or node scripts/test-native-browser.js --secureshop / --xss for the corresponding suites; unit fence is unchanged');
  if (requested.some(file => ['tests/legacyRamRagMaintenanceOperator.test.js','tests/legacyRamRagOperator.test.js','tests/setupLocalProcessIdentity.test.js'].includes(file))) throw new Error('Native operator suite requires npm run test:native-operator; unit fence is unchanged');
  if (requested.includes('tests/transformers43QualificationRunner.test.js')) throw new Error('Native verifier lifecycle requires node --test --test-timeout=15000 tests/transformers43QualificationRunner.test.js; unit fence is unchanged');
  if (!requested.length) return null;
  if (!['unit', 'secureshop'].includes(mode)) throw new Error('Focused files are supported only in controlled test modes');
  const testRoot = fs.realpathSync(path.join(source, 'tests'));
  const selected = new Set();
  for (const filename of requested) {
    if (!/^tests\/[A-Za-z0-9_./-]+\.test\.js$/.test(filename)
        || filename.split('/').some(part => part === '..' || part === '.')) {
      throw new Error('Expected an explicit tests/...test.js path');
    }
    const absolute = fs.realpathSync(path.join(source, filename));
    if (!absolute.startsWith(`${testRoot}${path.sep}`) || !fs.statSync(absolute).isFile()) {
      throw new Error('Focused tests must be files inside the test directory');
    }
    const relative = path.relative(testRoot, absolute).split(path.sep).join('/');
    if (mode === 'unit' && relative.includes('/')) {
      throw new Error('Focused unit tests must be top-level tests/*.test.js files');
    }
    if (mode === 'secureshop' && !relative.startsWith('secureshop/')) {
      throw new Error('Focused SecureShop tests must be below tests/secureshop/');
    }
    selected.add(filename);
  }
  return [...selected];
}

module.exports = { isolatedDatabaseGuard, selectIsolatedTests };
