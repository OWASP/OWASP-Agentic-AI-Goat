'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const crypto = require('node:crypto');
const http = require('node:http');
const os = require('node:os');
const { spawn, spawnSync } = require('node:child_process');
const { createMcpTargetStore } = require(process.env.MCP_TARGET_MODULE || '../sidecars/sandbox-runner/mcpTargets');

if (process.env.MCP_TARGET_LINUX_NATIVE !== 'yes' || process.platform !== 'linux') {
  test('native Linux MCP target qualification is explicitly gated', { skip: true }, () => {});
} else {
  const root = process.env.MCP_TARGET_ROOT;
  const fixtureRoot = process.env.MCP_TARGET_FIXTURE_ROOT;
  const bind = (owner, targetId = crypto.randomUUID()) => ({ targetId, ownerId: owner,
    platformSessionId: owner + 100, generation: 9 });
  const allow = async () => true;
  test('actual util-linux flock and strict bubblewrap isolate owner roots and retire durably', async () => {
    assert.equal(process.getuid(), 10001);
    assert.equal(spawnSync('/usr/bin/flock', ['--version']).status, 0);
    assert.equal(spawnSync('/usr/bin/bwrap', ['--version']).status, 0);
    const store = createMcpTargetStore({ root, fixtureRoot });
    const a = bind(1), b = bind(2), c = bind(3);
    const pa = await store.provisionTarget(a, { authorize: allow });
    const pb = await store.provisionTarget(b, { authorize: allow });
    const pc = await store.provisionTarget(c, { authorize: allow });
    const argv = await store.buildBwrapArgv(pa.capability, allow,
      'cat /var/secrets/master_key.txt; printf "\\nENV=%s:%s:%s\\n" "$USER" "$HOME" "${HOST_PRIVATE_SECRET-unset}"; test ! -e /app/index.js');
    assert.equal(argv.join('\0').includes('--ro-bind\0/\0/'), false);
    assert.equal(argv.includes('--unshare-user'), true); assert.equal(argv.includes('--disable-userns'), false);
    assert.deepEqual(argv.slice(argv.indexOf('--seccomp'), argv.indexOf('--seccomp') + 2), ['--seccomp', '3']);
    assert.equal(argv.includes('--proc'), false);
    assert.equal(argv.some(value => String(value).includes(b.targetId)), false);
    process.env.HOST_PRIVATE_SECRET = 'must-not-cross';
    let executed;
    try {
      executed = await store.executeTarget(pa.capability, allow,
        'cat /var/secrets/master_key.txt; printf "\\nENV=%s:%s:%s\\n" "$USER" "$HOME" "${HOST_PRIVATE_SECRET-unset}"; test ! -e /app/index.js');
    } finally { delete process.env.HOST_PRIVATE_SECRET; }
    assert.equal(executed.code, 0, executed.stderr);
    assert.match(executed.stdout, /MASTER ENCRYPTION KEY/);
    assert.match(executed.stdout, /ENV=mcp-admin:\/home\/mcp-admin:unset/);
    const runtime = await store.executeTarget(pa.capability, allow,
      'test -d /proc && test -z "$(ls -A /proc)" && node -p "process.version"');
    assert.equal(runtime.code, 0, runtime.stderr); assert.match(runtime.stdout, /^v26\.8\.2\s*$/);
    const curlRuntime = await store.executeTarget(pa.capability, allow,
      'command -v curl >/dev/null && curl --version | grep -F "curl "');
    assert.equal(curlRuntime.code, 0, curlRuntime.stderr); assert.match(curlRuntime.stdout, /curl \d/);
    const seccompProbe = await store.executeTarget(pa.capability, allow, '/usr/local/libexec/owasp-ai-goat-mcp-seccomp-probe');
    assert.equal(seccompProbe.code, 0, seccompProbe.stderr);
    assert.deepEqual(JSON.parse(seccompProbe.stdout), { clone3Enosys: true, cloneNewuserEperm: true,
      fsopenEnosys: true, mountEperm: true, setnsEperm: true, unshareEperm: true });
    const nodeProcessProbe = await store.executeTarget(pa.capability, allow,
      `node -e 'const {Worker}=require("node:worker_threads");const {spawnSync}=require("node:child_process");const w=new Worker("const {parentPort}=require(\\"node:worker_threads\\");parentPort.postMessage(42)",{eval:true});w.once("message",v=>{const c=spawnSync("/bin/true");if(v!==42||c.status!==0)process.exit(2);console.log("NODE_PROCESS_OK")});w.once("error",()=>process.exit(3))'`);
    assert.equal(nodeProcessProbe.code, 0, nodeProcessProbe.stderr); assert.equal(nodeProcessProbe.stdout, 'NODE_PROCESS_OK\n');

    const sentinel = spawn('/bin/sleep', ['30']);
    try {
      process.kill(sentinel.pid, 0);
      const pidProbe = await store.executeTarget(pa.capability, allow, `! kill -0 ${sentinel.pid} 2>/dev/null`);
      assert.equal(pidProbe.code, 0, pidProbe.stderr);
    } finally { sentinel.kill('SIGKILL'); await new Promise(resolve => sentinel.once('close', resolve)); }

    const address = Object.values(os.networkInterfaces()).flat().find(value => value?.family === 'IPv4' && !value.internal);
    assert.ok(address?.address, 'outer container must expose a non-loopback address for the negative network probe');
    const listener = http.createServer((_request, response) => response.end('outer-network-visible'));
    await new Promise((resolve, reject) => {
      const failed = error => reject(error);
      listener.once('error', failed);
      listener.listen(0, '0.0.0.0', () => { listener.off('error', failed); resolve(); });
    });
    try {
      const port = listener.address().port;
      const reachable = await new Promise((resolve, reject) => {
        http.get(`http://${address.address}:${port}/`, response => {
          let body = ''; response.on('data', chunk => { body += chunk; }); response.on('end', () => resolve(body));
        }).once('error', reject);
      });
      assert.equal(reachable, 'outer-network-visible');
      const networkProbe = await store.executeTarget(pa.capability, allow,
        `curl --connect-timeout 1 --max-time 2 --fail --silent http://${address.address}:${port}/`);
      assert.ok([7, 28].includes(networkProbe.code),
        `private network namespace must fail to connect, received curl exit ${networkProbe.code}: ${networkProbe.stderr}`);
      assert.doesNotMatch(networkProbe.stdout, /outer-network-visible/);
    } finally { await new Promise(resolve => listener.close(resolve)); }
    const siblingBacking = path.join(root, 'targets', b.targetId, 'rootfs', 'var', 'secrets', 'master_key.txt');
    const siblingProbe = await store.executeTarget(pa.capability, allow, `test ! -e '${siblingBacking}'`);
    assert.equal(siblingProbe.code, 0, siblingProbe.stderr);
    const mutation = await store.executeTarget(pa.capability, allow,
      "printf 'OWNER_A_ONLY\\n' > /var/secrets/master_key.txt; cat /var/secrets/master_key.txt");
    assert.equal(mutation.stdout, 'OWNER_A_ONLY\n');
    const sibling = await store.executeTarget(pb.capability, allow, 'cat /var/secrets/master_key.txt');
    assert.match(sibling.stdout, /MASTER ENCRYPTION KEY/); assert.doesNotMatch(sibling.stdout, /OWNER_A_ONLY/);

    const packageRunId = crypto.randomUUID(); const packageOperationId = crypto.randomUUID();
    const packageSource = 'https://cdn.acme-billing-partner.io/pkg/analytics-boost.tgz';
    const packageReceipt = await store.installPackage(pa.capability, allow, {
      source: packageSource, runId: packageRunId, operationId: packageOperationId,
    });
    assert.equal(packageReceipt.targetId, a.targetId); assert.equal(packageReceipt.platformOwnerId, a.ownerId);
    assert.equal(packageReceipt.runId, packageRunId); assert.equal(packageReceipt.changed, true);
    assert.equal(packageReceipt.archiveSha256, '28ad1b38813766bd06c9297a5297440b0a6dcac37dffee83f35167569b0869e1');
    assert.equal(packageReceipt.provenance, 'untrusted_external'); assert.equal(packageReceipt.signatureVerified, false);
    assert.equal(packageReceipt.hiddenToolName, 'exfiltrate_env');
    assert.equal(JSON.parse(packageReceipt.postinstallMetadata).hiddenTool, 'exfiltrate_env');
    assert.equal(packageReceipt.metadataSha256,
      crypto.createHash('sha256').update(packageReceipt.postinstallMetadata).digest('hex'));
    assert.match(packageReceipt.postinstallOutput, /DB_PASSWORD=/);
    assert.deepEqual(await store.installPackage(pa.capability, allow, {
      source: packageSource, runId: packageRunId, operationId: packageOperationId,
    }), packageReceipt);
    const siblingPackageRoot = path.join(root, 'targets', b.targetId, 'rootfs', 'var/tmp/package-installs');
    await assert.rejects(fs.access(siblingPackageRoot), { code: 'ENOENT' });
    const trustedReceipt = await store.installPackage(pc.capability, allow, { source: '@acme/analytics',
      runId: crypto.randomUUID(), operationId: crypto.randomUUID() });
    assert.equal(trustedReceipt.provenance, 'trusted_internal');
    assert.equal(trustedReceipt.signatureVerified, true); assert.equal(trustedReceipt.hiddenToolName, null);

    const restartedActive = createMcpTargetStore({ root, fixtureRoot });
    const recovered = await restartedActive.recoverTarget(a, { authorize: allow });
    const recoveredRun = await restartedActive.executeTarget(recovered.capability, allow, 'cat /var/secrets/master_key.txt');
    assert.equal(recoveredRun.stdout, 'OWNER_A_ONLY\n');
    assert.deepEqual(await restartedActive.installPackage(recovered.capability, allow, {
      source: packageSource, runId: packageRunId, operationId: packageOperationId,
    }), packageReceipt);
    assert.deepEqual(await restartedActive.listInstalledPackages(recovered.capability, allow), [packageReceipt]);
    assert.deepEqual(await store.listInstalledPackages(pb.capability, allow), []);

    const other = createMcpTargetStore({ root, fixtureRoot });
    const executionTmp = path.join(root, 'targets', a.targetId, 'rootfs', 'tmp');
    const held = store.executeTarget(pa.capability, allow,
      "printf READY > /tmp/execution-started; while [ ! -f /tmp/execution-release ]; do sleep 0.05; done");
    const executionDeadline = Date.now() + 5000;
    while (Date.now() < executionDeadline) {
      try { if (await fs.readFile(path.join(executionTmp, 'execution-started'), 'utf8') === 'READY') break; }
      catch (error) { if (error.code !== 'ENOENT') throw error; }
      await new Promise(resolve => setTimeout(resolve, 20));
    }
    assert.equal(await fs.readFile(path.join(executionTmp, 'execution-started'), 'utf8'), 'READY');
    const operationId = crypto.randomUUID();
    let retirementSettled = false;
    const retirement = other.retireTarget(a, { operationId, authorize: allow }).then(value => { retirementSettled = true; return value; });
    await new Promise(resolve => setTimeout(resolve, 200));
    assert.equal(retirementSettled, false, 'retirement must wait for the admitted bubblewrap process');
    await fs.writeFile(path.join(executionTmp, 'execution-release'), 'release');
    const executedHeld = await held;
    assert.equal(executedHeld.code, 0, executedHeld.stderr);
    const receipt = await retirement;
    assert.equal(receipt.status, 'completed');
    const restarted = createMcpTargetStore({ root, fixtureRoot });
    assert.deepEqual(await restarted.readRetirementReceipt(a, { operationId, authorize: allow }), receipt);
    await assert.rejects(store.withTarget(pa.capability, allow, async () => {}), { code: 'TARGET_RETIRED' });
    await assert.rejects(restartedActive.listInstalledPackages(recovered.capability, allow), { code: 'TARGET_RETIRED' });
    assert.equal(await fs.readFile(path.join(root, 'targets', b.targetId, 'rootfs', 'var/secrets/master_key.txt'), 'utf8').then(Boolean), true);
  });
}
