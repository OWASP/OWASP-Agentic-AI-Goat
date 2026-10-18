const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

test('DPI lesson metadata exposes browser ESM exports through the development transform', async () => {
  const fs = require('node:fs');
  const { pathToFileURL } = require('node:url');
  const root = path.resolve(__dirname, '../client');
  const { default: configure } = await import(pathToFileURL(path.join(root, 'vite.config.mjs')));
  const config = configure({ command: 'serve', mode: 'development' });
  const compatibility = config.plugins.find(plugin => plugin.name === 'dvaia-local-commonjs-compatibility');
  const filename = path.join(root, 'src/utils/dpiSelectedLesson.js');
  const result = compatibility.transform(fs.readFileSync(filename, 'utf8'), filename + '?t=123');
  assert.ok(result);
  assert.doesNotMatch(result, /module\.exports/);
  const module = await import(`data:text/javascript;base64,${Buffer.from(result).toString('base64')}`);
  assert.equal(typeof module.describeSelectedLesson, 'function');
  assert.equal(typeof module.readSelectedLesson, 'function');
  assert.equal(module.describeSelectedLesson(null), null);
  assert.equal(module.describeSelectedLesson({version:'dpi-selected-lesson-v1',profile:'guided',
    policyVersion:'dpi-guided-v1',objectiveId:'interact',lessonKind:'aws-baseline',mode:'vuln'}),
  'Selected lesson: AWS baseline (vulnerable mode)');
});
