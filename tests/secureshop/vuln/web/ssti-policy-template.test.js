/**
 * @intentional-vulnerability ssti-policy-template
 * @teaches OWASP-Web:A03
 * @location agent-host/agents/policy/tools/index.js
 *
 * policy.update_policy renders caller-supplied markdown through the unsafe
 * Nunjucks env (same one that listing.create uses). `process` is exposed,
 * so `{{ process.pid }}` renders to the running PID and
 * `{{ process.mainModule.require('child_process').execSync('id').toString() }}`
 * renders to `id` output. We assert with the safer PID form to avoid
 * spawning subprocesses in CI.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { seedShop } = require('../_fixture.js');

test('ssti-policy-template: {{ process.pid }} renders to real PID', async () => {
  const s = await seedShop();
  try {
    for (const k of Object.keys(require.cache)) {
      if (k.includes('/agent-host/agents/policy/')) delete require.cache[k];
      if (k.includes('/agent-host/agents/listing/')) delete require.cache[k];
    }
    const { update_policy } = require(path.resolve(__dirname, '../../../../agent-host/agents/policy/tools/index.js'));

    const r = await update_policy({
      name: 'test-ssti',
      markdown: 'Store PID marker: {{ process.pid }} / store: {{ store_name }}',
    });
    assert.equal(r.ok, true);
    const pidStr = String(process.pid);
    assert.ok(r.rendered.includes(pidStr), `expected PID ${pidStr} in rendered output: ${r.rendered_preview}`);
    assert.ok(r.rendered.includes('SecureShop'), 'template context variable {{ store_name }} rendered');
  } finally {
    await s.close();
  }
});
