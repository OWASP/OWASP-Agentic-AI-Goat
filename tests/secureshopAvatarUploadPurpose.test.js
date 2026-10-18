'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
test('0102 preserves immediate 0101 purposes and adds only avatar upload', () => {
  const a = fs.readFileSync(path.join(process.cwd(), 'db/postgres/workshop-migrations/secureshop_agents/0101_checkout_audit_jwt_conversation_purpose.sql'), 'utf8'),
    b = fs.readFileSync(path.join(__dirname, '../db/postgres/workshop-migrations/secureshop_agents/0102_avatar_upload_conversation_purpose.sql'), 'utf8');
  const list = s => s.match(/conversation_purpose IN \(([\s\S]*?)\)/)[1].match(/'[^']+'/g);
  const before = list(a),
    after = list(b);
  assert.deepEqual(after, [...before, "'secureshop_avatar_upload'"]);
  assert.match(b, /authority_mode='launch_bound' OR conversation_purpose='general'/);
});
test('canonical ACL exposes only customer avatar tool for avatar workflow', () => {
  const source = fs.readFileSync(path.join(__dirname, '../server/services/secureshopBoundAclRegistry.js'), 'utf8');
  assert.match(source, /\['avatar-upload', \['customer'\], \['uploads\.upload_avatar'\]\]/);
});
