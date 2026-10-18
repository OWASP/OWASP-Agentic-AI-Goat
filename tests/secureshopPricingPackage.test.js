'use strict';
const test = require('node:test'), assert = require('node:assert/strict');
const fs = require('node:fs'), os = require('node:os'), path = require('node:path');
const { PRICING_PACKAGE_FILES: files, capturePricingPackage } = require('../server/services/secureshopPricingPackage');
test('closed local package digest detects source drift and rejects substituted source links', t => {
 const root = fs.mkdtempSync(path.join(os.tmpdir(), 'pricing-package-'));
 t.after(() => fs.rmSync(root, { recursive: true, force: true }));
 for (const relative of files) { const name = path.join(root, relative); fs.mkdirSync(path.dirname(name), { recursive: true }); fs.writeFileSync(name, `synthetic package fixture: ${relative}\n`); }
 const first = capturePricingPackage(root); assert.equal(first.architecture, 'arm64'); assert.ok(Object.isFrozen(first.files)); assert.deepEqual(Object.keys(first.files), files);
 assert.equal(capturePricingPackage(root).sha256, first.sha256);
 const target = path.join(root, files[0]); fs.appendFileSync(target, '\n# drift\n'); assert.notEqual(capturePricingPackage(root).sha256, first.sha256);
 fs.renameSync(target, target + '.saved'); fs.symlinkSync(target + '.saved', target); assert.throws(() => capturePricingPackage(root));
});
