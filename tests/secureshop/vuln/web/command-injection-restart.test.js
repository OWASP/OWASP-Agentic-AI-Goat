/**
 * @intentional-vulnerability command-injection-restart
 * @teaches OWASP-Web:A03
 * @location agent-host/agents/system/tools/index.js
 *
 * system.restart_service builds `systemctl restart ${name}` and shells it.
 * A `name` like `nginx; cat /etc/passwd` runs both commands.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

test('command-injection-restart: `;` in service name lands in shell cmd', async () => {
  delete process.env.SS_SYSTEM_ALLOW_EXEC;
  for (const k of Object.keys(require.cache)) {
    if (k.includes('/agent-host/agents/system/')) delete require.cache[k];
  }
  const { restart_service } = require(path.resolve(__dirname, '../../../../agent-host/agents/system/tools/index.js'));

  const r = await restart_service({ name: 'nginx; cat /etc/passwd' });
  assert.equal(r.executed, false, 'guarded exec — command constructed but not run');
  assert.equal(r.cmd, 'systemctl restart nginx; cat /etc/passwd',
    'injection payload flows verbatim into the constructed cmd string');
});
