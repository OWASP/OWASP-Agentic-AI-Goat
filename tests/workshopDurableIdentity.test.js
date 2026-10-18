'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.join(__dirname, '..');
const read = (file) => fs.readFileSync(path.join(root, file), 'utf8');

test('all five mode-governed routes authenticate and derive platform owner', () => {
  for (const file of ['sqlWorkshop.js', 'nosqlWorkshop.js', 'sensitiveInfoWorkshop.js', 'supplyChainWorkshop.js', 'excessiveAgencyLab.js']) {
    const source = read(`server/routes/${file}`);
    assert.match(source, /authenticateToken/);
    assert.match(source, /createWorkshopModeHandlers/);
    assert.match(source, /workshopKey:\s*WORKSHOP_KEY/);
  }
});

test('chat execution does not accept durable body identity or body mode', () => {
  for (const file of ['sqlWorkshop.js', 'nosqlWorkshop.js', 'sensitiveInfoWorkshop.js', 'supplyChainWorkshop.js']) {
    const source = read(`server/routes/${file}`);
    assert.doesNotMatch(source, /const \{[^}\n]*(?:userId|mode)[^}\n]*\} = req\.body/);
    assert.match(source, /const userId = String\(req\.user\.id\)/);
  }
});
