'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const source = fs.readFileSync(path.join(__dirname, '../server/services/secureshopBoundUploadGraph.js'), 'utf8').replace(/\s+/g, '');
test('uses the production BoundAgentRunner local tool and its single coordinator receipt', () => {
  assert.match(source, /createBoundAgentRunner/);
  assert.match(source, /createLocalTools:[\s\S]*UPLOAD_TOOL/);
  assert.match(source, /observeLocalTool:[\s\S]*graphReceipt/);
  assert.match(source, /key=\`\$\{requestId\}:\$\{JSON\.stringify/);
  assert.doesNotMatch(source, /file_bytes_base64|user_id|pool\.callTool\([^)]*UPLOAD_TOOL/);
});
test('routes file effects through replay-aware application after genuine closed tool selection', () => {
  assert.match(source, /closedToolCatalog:true/);
  assert.match(source, /uploadApplication\.execute\(\{admission:admitted,file,mode:mode\.mode,execution/);
  assert.match(source, /exactEmpty\(args\)/);
});
