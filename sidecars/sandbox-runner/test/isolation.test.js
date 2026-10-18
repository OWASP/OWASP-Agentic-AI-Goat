'use strict';

/**
 * Isolation + authenticity test for the sandbox-runner.
 *
 * Run against a LIVE runner:  RUNNER_URL=http://127.0.0.1:8090 node test/isolation.test.js
 * (docker compose up mcp-sandbox, or `docker run -p 8090:8090 mcp-sandbox-runner`).
 *
 * Proves:
 *   1. commands run as a NON-ROOT uid
 *   2. `cat /var/secrets/master_key.txt` returns the REAL production key bytes
 *   3. `env` genuinely leaks the lab secret env vars
 *   4. when bwrap isolation is active, the command CANNOT reach the network
 *      (169.254.169.254 metadata is unreachable) — proving an empty netns
 *   5. the per-session workdir is where writes land (cwd is the session dir)
 */

const RUNNER_URL = process.env.RUNNER_URL || 'http://127.0.0.1:8090';
let pass = 0, fail = 0;
function ok(name, cond, detail) {
  if (cond) { pass++; console.log(`  ok  - ${name}`); }
  else { fail++; console.log(`  NOT ok - ${name}${detail ? ` :: ${detail}` : ''}`); }
}
async function exec(command, sessionId = 'test-iso') {
  const r = await fetch(`${RUNNER_URL}/exec`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ sessionId, command }),
  });
  return r.json();
}

(async () => {
  console.log(`# sandbox-runner isolation test → ${RUNNER_URL}`);
  const health = await (await fetch(`${RUNNER_URL}/health`)).json();
  console.log(`# isolation mode: ${health.isolation} (bwrap=${health.bwrap}, uid=${health.uid})`);
  ok('health is ok', health.status === 'ok', JSON.stringify(health));

  const idr = await exec('id -u');
  const uid = parseInt((idr.stdout || '').trim(), 10);
  ok('runs as non-root (uid != 0)', Number.isFinite(uid) && uid !== 0, `uid=${uid} stderr=${idr.stderr}`);

  const key = await exec('cat /var/secrets/master_key.txt');
  ok('real file read returns the production master key',
    /MASTER ENCRYPTION KEY|b5g9f3e2d0c8174695bgfe23cd095812/.test(key.stdout), key.stdout.slice(0, 120));

  const chain = await exec('ls; cat /opt/app/config/database.yml');
  ok('command chaining bypasses first-token allowlist (real cat)',
    /McP#Pr0d!2026|acme_production/.test(chain.stdout), chain.stdout.slice(0, 120));

  const envr = await exec('env');
  ok('env genuinely leaks DB_PASSWORD',
    /DB_PASSWORD=McP#Pr0d!2026/.test(envr.stdout), envr.stdout.slice(0, 120));

  const pwd = await exec('pwd');
  ok('cwd is the per-session sandbox workdir',
    /\/sandbox\/sessions\//.test((pwd.stdout || '').trim()), pwd.stdout);

  const net = await exec('curl -s --max-time 3 http://169.254.169.254/latest/meta-data/ 2>&1 || echo NETFAIL');
  if (health.bwrap) {
    ok('bwrap: command CANNOT reach cloud metadata (empty netns)',
      /NETFAIL|could not resolve|failed to connect|timed out|couldn't connect/i.test(net.stdout),
      net.stdout.slice(0, 160));
  } else {
    console.log('  skip - network isolation assertion (plain mode; relies on egress SG / powerless role)');
  }

  console.log(`\n# ${pass} passed, ${fail} failed`);
  process.exit(fail === 0 ? 0 : 1);
})().catch((e) => { console.error(e); process.exit(1); });
