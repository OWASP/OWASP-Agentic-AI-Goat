'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.join(__dirname, '..');
const read = (file) => fs.readFileSync(path.join(root, file), 'utf8');

test('mode-governed execution has no process-global LAB_MODE dependency', () => {
  const sources = [
    'server/routes/sqlWorkshop.js', 'server/routes/nosqlWorkshop.js',
    'server/services/ariaAgentService.js', 'server/services/novaAgentService.js',
    'server/database/sqlWorkshopDb.js', 'server/database/nosqlWorkshopDb.js',
    'server/services/excessiveAgencyToolRouter.js',
    'server/index.js',
    'server/applicationServer.js',
  ].map(read).join('\n');
  assert.doesNotMatch(sources, /process\.env\.LAB_MODE/);
});

test('Excessive Agency has no mutable singleton mode', () => {
  const source = read('server/services/excessiveAgencyToolRouter.js');
  assert.doesNotMatch(source, /this\.labMode|setLabMode|getLabMode/);
  assert.match(source, /context\.labMode/);
});

test('all five routes use persisted service and ignore body mode for chat', () => {
  for (const file of ['sqlWorkshop.js', 'nosqlWorkshop.js', 'sensitiveInfoWorkshop.js', 'supplyChainWorkshop.js', 'excessiveAgencyLab.js']) {
    const source = read(`server/routes/${file}`);
    assert.match(source, /createWorkshopModeHandlers/);
    assert.match(source, /workshopKey:\s*WORKSHOP_KEY/);
    assert.doesNotMatch(source, /req\.body\??\.mode|req\.body\.mode/);
  }
});
