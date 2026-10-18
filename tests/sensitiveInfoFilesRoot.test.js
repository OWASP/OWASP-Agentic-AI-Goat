'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const modulePath = require.resolve('../server/database/sensitiveInfoFiles');
test('external generated fixture root: import is inert, explicit seed works and reseed preserves edits', () => {
  const parent = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'owned-sensitive-root-')));
  const root = path.join(parent, 'fixtures');
  const previous = process.env.LEGACY_SENSITIVE_FILES_ROOT;
  try {
    process.env.LEGACY_SENSITIVE_FILES_ROOT = root;delete require.cache[modulePath];
    const fixtures = require(modulePath);
    assert.equal(fs.existsSync(root), false);
    assert.equal(fixtures.sensitiveFilesDir, root);
    assert.equal(fixtures.publicDir, path.join(root, 'public'));
    fixtures.createSensitiveFiles();
    const templatePath=path.join(fixtures.secretDir,'ssi_report.shtml');
    const template=fs.readFileSync(templatePath,'utf8');assert.match(template,/<!--#include file="\.\.\/secret\/database_credentials.txt" -->/);
    const tools=require('../server/services/legacySensitiveTools').createLegacySensitiveTools(fixtures);
    const read=tools.readTeachingFile({path:'../secret/ssi_report.shtml'});assert.equal(read.boundary.outsidePublic,true);
    const rendered=tools.renderSsiTemplate({template:read.content});assert.ok(require('../server/config/legacySensitiveFlags').findChallengeFlag(rendered.rendered));
    fs.writeFileSync(templatePath,'owned template edit');
    const target = path.join(fixtures.publicDir, 'welcome.txt');
    assert.ok(fs.readFileSync(target, 'utf8').length > 0);
    fs.writeFileSync(target, 'owned instructor edit');
    fixtures.createSensitiveFiles();
    assert.equal(fs.readFileSync(target, 'utf8'), 'owned instructor edit');
    assert.equal(fs.readFileSync(templatePath,'utf8'),'owned template edit');
    for (const invalid of ['relative', '', path.join(parent, 'a') + '/../b']) {
      process.env.LEGACY_SENSITIVE_FILES_ROOT = invalid;delete require.cache[modulePath];
      assert.throws(() => require(modulePath), /absolute normalized/);
    }
  } finally {
    if (previous === undefined) delete process.env.LEGACY_SENSITIVE_FILES_ROOT;else process.env.LEGACY_SENSITIVE_FILES_ROOT = previous;
    delete require.cache[modulePath];fs.rmSync(parent, { recursive: true, force: true });
  }
});
