'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const { renderMcpSandboxAppArmor } = require('../scripts/render-mcp-sandbox-apparmor');

const template = fs.readFileSync(path.join(__dirname, '..', 'sidecars', 'sandbox-runner', 'apparmor', 'owasp-ai-goat-mcp-sandbox.apparmor.in'), 'utf8');

test('renders a unique owned ABI 4 supervisor and local bubblewrap transition', () => {
  const name = 'owasp-ai-goat-mcp-sandbox-012345abcdef';
  const policy = renderMcpSandboxAppArmor(template, name);
  const childStart = policy.indexOf('profile bwrap');
  assert.ok(childStart > 0);
  const parent = policy.slice(0, childStart);
  const child = policy.slice(childStart);
  assert.match(parent, /abi <abi\/4\.0>/);
  assert.match(parent, new RegExp(`profile "${name}"`));
  assert.match(parent, /\/usr\/bin\/bwrap Cx -> bwrap/);
  assert.match(parent, new RegExp(`ptrace \\(read\\) peer="${name}\\/\\/bwrap"`));
  assert.doesNotMatch(parent, /^\s*userns\s*,/m);
  assert.match(parent, /^\s*deny mount,/m);
  assert.match(child, /^\s*userns,/m);
  assert.match(child, /^\s*capability net_admin,/m);
  assert.match(child, /^\s*mount,/m);
  assert.match(child, /^\s*signal \(receive\) peer=unconfined,/m);
  assert.match(child, /^\s*signal \(receive\) peer=runc,/m);
  assert.match(child, /^\s*signal \(receive\) peer=crun,/m);
  assert.match(child, new RegExp(`ptrace \\(readby\\) peer="${name}"`));
  assert.doesNotMatch(policy, /flags=\(unconfined\)/);
  assert.doesNotMatch(policy, /@@/);
});

test('rejects profile injection and unresolved templates', () => {
  assert.throws(() => renderMcpSandboxAppArmor(template, 'owasp-ai-goat-mcp-sandbox; userns,'), /PROFILE_NAME_INVALID/);
  assert.throws(() => renderMcpSandboxAppArmor('profile fixed {}', 'owasp-ai-goat-mcp-sandbox'), /TEMPLATE_INVALID/);
});
