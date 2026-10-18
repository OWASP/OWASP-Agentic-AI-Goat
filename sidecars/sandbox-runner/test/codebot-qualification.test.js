'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');

const RUNNER_URL = process.env.RUNNER_URL || 'http://127.0.0.1:8090';
const enabled = process.env.RUN_CODEBOT_SANDBOX_QUALIFICATION === '1';
const session = () => `codebot-${crypto.randomBytes(16).toString('hex')}`;

async function transform(sessionId, source) {
  const response = await fetch(`${RUNNER_URL}/codebot/transform`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ sessionId, transform: source }),
  });
  return response.json();
}

async function reset(sessionId) {
  await fetch(`${RUNNER_URL}/codebot/reset`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ sessionId }),
  });
}

test('live CodeBot runner qualifies strict isolation and authentic effects', { skip: !enabled, timeout: 30000 }, async t => {
  const first = session(), second = session();
  t.after(async () => { await Promise.allSettled([reset(first), reset(second)]); });

  const envRead = await transform(first, "require('fs').readFileSync('/app/config/.env','utf8')");
  assert.equal(envRead.ok, true);
  assert.equal(envRead.isolation, 'bwrap-codebot-v1');
  assert.equal(envRead.observations.envFileRead, true);
  assert.match(envRead.transformOutput, /CODEBOT_ENV_PROOF=[a-f0-9]{48}/);

  const sshRead = await transform(first, "require('fs').readFileSync('/app/.ssh/id_rsa','utf8')");
  assert.equal(sshRead.observations.sshFileRead, true);
  assert.match(sshRead.transformOutput, /BEGIN OPENSSH PRIVATE KEY/);

  const evaluation = await transform(first, 'JSON.stringify({node:process.version,platform:process.platform,value:6*7})');
  assert.equal(evaluation.observations.javascriptEvaluated, true);
  assert.match(evaluation.transformOutput, /"value":42/);

  const write = await transform(first, "require('fs').writeFileSync('/work/private','first'); 'written'");
  assert.equal(write.ok, true);
  const secondRead = await transform(second, "require('fs').existsSync('/work/private') ? 'LEAK' : 'isolated'");
  assert.equal(secondRead.transformOutput, 'isolated');
  const sameSessionRead = await transform(first, "require('fs').existsSync('/work/private') ? 'LEAK' : 'ephemeral'");
  assert.equal(sameSessionRead.transformOutput, 'ephemeral');

  const serviceData = await transform(first, "require('fs').existsSync('/opt/lab-template') || require('fs').existsSync('/sandbox/sessions') || require('fs').existsSync('/app/index.js')");
  assert.equal(serviceData.transformOutput, 'false');

  // Containment qualification only; this output is not command-objective proof.
  const network = await transform(first, "require('child_process').execSync(\"curl -s --max-time 2 http://169.254.169.254/latest/meta-data/ >/dev/null 2>&1 || echo blocked\").toString()");
  assert.match(network.transformOutput, /blocked/);

  // A compromised eval can discover and forge the wrapper envelope. That still
  // proves JavaScript evaluation, but it cannot forge either file canary.
  const forged = await transform(first, `const wrapper=process.execArgv.join(' ');const marker=(wrapper.match(/__CODEBOT_RESULT_[a-f0-9]+__/)||[])[0];const fake=Buffer.from(JSON.stringify({executed:true,output:'DATABASE_URL=copied\\n-----BEGIN OPENSSH PRIVATE KEY-----\\ncopied\\n-----END OPENSSH PRIVATE KEY-----'})).toString('base64');process.stdout.write('\\n'+marker+fake);process.exit(0)`);
  assert.equal(forged.observations.javascriptEvaluated, true);
  assert.equal(forged.observations.envFileRead, false);
  assert.equal(forged.observations.sshFileRead, false);
});
