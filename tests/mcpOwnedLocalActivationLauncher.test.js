'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const root = path.resolve(__dirname, '..');
const source = fs.readFileSync(path.join(root, 'tests/postgres/run-mcp-owned-local-activation.py'), 'utf8');

test('activation launcher preserves Mailpit and scopes failure cleanup to newly created runner resources', () => {
  assert.match(source, /MAILPIT='OWASP Agentic AI GOAT-mailpit-1'/);
  assert.match(source, /mail_before\['Id'\].*mail_identity\['id'\]/s);
  assert.match(source, /if created_runner:\n\s+try:run\(docker\+\['rm','--force',RUNNER\]\)/);
  assert.doesNotMatch(source, /docker\+\['rm','--force',MAILPIT\]/);
  assert.match(source, /forceDisabled:true/);
  assert.match(source, /os\.kill\(a\.watcher_pid,signal\.SIGHUP\)/);
  assert.match(source, /select_backend_pid/);
  assert.match(source, /wait_for_exit\(lambda:process_state\(a\.backend_pid\)/);
  assert.match(source, /command-diagnostics\.jsonl/);
});

test('activation launcher consumes only an exact source-bound one-use grant after owner handshake', () => {
  const handshake = source.indexOf("print(f'WAITING_OWNER_HANDLE");
  const consume = source.indexOf("g.update(status='consumed'");
  assert.ok(handshake >= 0 && consume > handshake);
  assert.match(source, /g\.get\('sourceHashes'\)!=current/);
  assert.match(source, /g\.get\('allowedLaunches'\)!=1/);
});
