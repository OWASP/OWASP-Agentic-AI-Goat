'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { waitForChild } = require('./fullBackendBootControls');

function port(value) {
  assert.ok(Number.isInteger(value) && value >= 1024 && value <= 65535, 'Explicit unprivileged port required');
  return value;
}
function browserNetworkPolicy({ proxyPort, devtoolsPort }) {
  port(proxyPort); port(devtoolsPort); assert.notEqual(proxyPort, devtoolsPort);
  // Network-only outer restriction: Chromium retains its own process sandbox.
  // SBPL accepts localhost, covering loopback rather than only IPv4. The
  // proxy and browser still bind/connect to 127.0.0.1 explicitly. No arbitrary
  // loopback port, UDP or external TCP exception is granted.
  return `(version 1)\n(allow default)\n(deny network*)\n`
    + `(allow network-outbound (remote tcp "localhost:${proxyPort}"))\n`
    + `(allow network-bind (local tcp "localhost:${devtoolsPort}"))\n`
    + `(allow network-inbound (local tcp "localhost:${devtoolsPort}"))\n`;
}
function cleanBrowserEnvironment(root) {
  assert.ok(typeof root === 'string' && path.isAbsolute(root));
  assert.equal(fs.realpathSync(root), root);
  assert.ok(fs.statSync(root).isDirectory());
  return Object.freeze({ PATH: '/usr/bin:/bin:/usr/sbin:/sbin', HOME: root, TMPDIR: root, TMP: root, TEMP: root });
}
function networkProbeSource({ proxyPort, deniedPort }) {
  port(proxyPort); port(deniedPort); assert.notEqual(proxyPort, deniedPort);
  return `'use strict';const net=require('node:net');
async function connect(port,host='127.0.0.1'){return new Promise(resolve=>{const socket=net.connect({host,port});let settled=false;const done=value=>{if(settled)return;settled=true;socket.destroy();resolve(value)};socket.setTimeout(3000,()=>done('TIMEOUT'));socket.once('connect',()=>done('CONNECTED'));socket.once('error',error=>done(error.code||'ERROR'));});}
(async()=>{const allowed=await connect(${proxyPort});const denied=await connect(${deniedPort});const external=await connect(443,'192.0.2.1');const passed=allowed==='CONNECTED'&&['EPERM','EACCES'].includes(denied)&&['EPERM','EACCES'].includes(external);process.stdout.write(JSON.stringify({allowed:allowed==='CONNECTED',deniedByPolicy:['EPERM','EACCES'].includes(denied),externalDeniedByPolicy:['EPERM','EACCES'].includes(external)})+'\\n');process.exitCode=passed?0:1;})().catch(()=>{process.exitCode=1});\n`;
}
async function qualifyBrowserNetworkPolicy({ root, nodePath, proxyPort, deniedPort, devtoolsPort, owned, signal }) {
  // Callers own the two listening loopback targets and reserve DevTools separately.
  // A refusal/timeout is insufficient proof: the denied probe must get EPERM/EACCES.
  assert.equal(process.platform, 'darwin');
  assert.ok(owned && typeof owned.launch === 'function' && typeof owned.stop === 'function');
  assert.ok(typeof nodePath === 'string' && path.isAbsolute(nodePath));
  assert.equal(fs.realpathSync(nodePath), nodePath); assert.ok(fs.statSync(nodePath).isFile());
  port(deniedPort); assert.notEqual(deniedPort, devtoolsPort);
  const environment = cleanBrowserEnvironment(root);
  const policy = browserNetworkPolicy({ proxyPort, devtoolsPort });
  const probe = networkProbeSource({ proxyPort, deniedPort });
  const profilePath = path.join(root, 'browser-network.sb');
  fs.writeFileSync(profilePath, policy, { flag: 'wx', mode: 0o600 });
  let child;
  try {
    child = owned.launch('/usr/bin/sandbox-exec', ['-f', profilePath, nodePath, '-e', probe],
      { cwd: root, env: environment, stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = ''; let stderr = ''; let stderrBytes = 0;
    child.stdout.on('data', chunk => { if (stdout.length < 1024) stdout += chunk.toString(); });
    child.stderr.on('data', chunk => { stderrBytes += chunk.length; if (stderr.length < 1024) stderr += chunk.toString().slice(0, 1024 - stderr.length); });
    const code = await waitForChild(child, { timeoutMs: 10000, signal });
    if (code !== 0) {
      // Fixed cause labels preserve useful parser/OS diagnosis without leaking
      // command paths or arbitrary child output into qualification reports.
      const cause = /host must be \* or localhost/.test(stderr) ? 'SBPL_HOST_INVALID'
        : /syntax error|unbound variable|unexpected token/i.test(stderr) ? 'SBPL_SYNTAX_INVALID'
        : /Operation not permitted|sandbox_apply.*failed/i.test(stderr) ? 'SANDBOX_APPLY_DENIED'
        : 'PROBE_FAILED';
      throw Object.assign(new Error(`OS browser network policy probe failed: ${cause}; exit=${code}`),
        { code: cause, exitCode: code, stderrBytes });
    }
    assert.ok(stdout.length < 1024 && stderrBytes === 0);
    assert.deepEqual(JSON.parse(stdout), { allowed: true, deniedByPolicy: true, externalDeniedByPolicy: true });
    return Object.freeze({ profilePath, proxyPort, devtoolsPort, qualified: true, externalDeniedByPolicy: true });
  } finally { if (child) await owned.stop(child); }
}
module.exports = { browserNetworkPolicy, cleanBrowserEnvironment, networkProbeSource, qualifyBrowserNetworkPolicy };
