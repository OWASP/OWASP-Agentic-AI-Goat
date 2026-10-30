'use strict';
// Native prerequisite probe only. Never qualifies HTTP topology or objective credit.
// Run only in a disposable Linux container with the packaged enforcing AppArmor
// profile and inner seccomp filter; this script neither installs nor changes them.
const fs = require('node:fs/promises');
const crypto = require('node:crypto');
const assert = require('node:assert/strict');
async function main() {
  assert.equal(process.env.MCP_SSRF_FEASIBILITY_OWNED, 'yes');
  assert.equal(process.platform, 'linux');
  assert.equal(process.getuid(), 10001);
  const label = (await fs.readFile('/proc/self/attr/current', 'utf8')).trim();
  assert.equal(label, 'owasp-ai-goat-mcp-sandbox (enforce)');
  const status = await fs.readFile('/proc/self/status', 'utf8');
  for (const field of ['CapEff', 'CapPrm', 'CapInh', 'CapAmb']) {
    assert.match(status, new RegExp(`^${field}:\\s+0+$`, 'm'));
  }
  const perl = await fs.lstat('/usr/bin/perl');
  assert.ok(perl.isFile() && !perl.isSymbolicLink() && perl.uid === 0 && (perl.mode & 0o6022) === 0);
  assert.equal((await fs.readFile('/proc/sys/kernel/overflowuid','utf8')).trim(),'65534');
  const { createMcpTargetStore } = require('/app/mcpTargets');
  const root = await fs.mkdtemp('/tmp/owned-ssrf-feasibility-');
  const spawn = require('node:child_process').spawn;
  let prototypeSetup = false;
  const store = createMcpTargetStore({ root, fixtureRoot: '/opt/lab-template', spawn(executable, argv, options) {
    if (executable === '/usr/bin/bwrap' && prototypeSetup) {
      argv = [...argv];
      argv.unshift('--uid','0','--gid','0','--cap-add','CAP_NET_ADMIN','--cap-add','CAP_SETPCAP');
    }
    return spawn(executable, argv, options);
  }});
  const binding = { targetId: crypto.randomUUID(), ownerId: 1, platformSessionId: 1, generation: 1 };
  const allow = async () => true;
  let provisioned;
  try {
    const readiness = await store.checkReadiness();
    provisioned = await store.provisionTarget(binding, { authorize: allow });
    const probe = await store.executeTarget(provisioned.capability, allow,
      '/usr/local/libexec/owasp-ai-goat-mcp-seccomp-probe');
    assert.equal(probe.code, 0, JSON.stringify({stdout:probe.stdout,stderr:probe.stderr}));
    const seccomp = JSON.parse(probe.stdout);
    assert.equal(seccomp.unshareEperm, true);
    assert.equal(seccomp.mountEperm, true);
    assert.ok(global.prototypeFixtures);
    const targetTmp = require('node:path').join(root,'targets',binding.targetId,'rootfs','tmp');
    await fs.writeFile(require('node:path').join(targetTmp,'ssrf-setup.pl'),global.prototypeFixtures.setup,{mode:0o400});
    await fs.writeFile(require('node:path').join(targetTmp,'ssrf-worker.pl'),global.prototypeFixtures.worker,{mode:0o400});
    const listener = require('node:http').createServer((_req,res)=>res.end('outside-namespace'));
    await new Promise(resolve=>listener.listen(0,'127.0.0.1',resolve));
    const outerPort=listener.address().port;
    prototypeSetup = true;
    let operation;
    try { operation = await store.executeTarget(provisioned.capability,allow,
      `/usr/bin/perl /tmp/ssrf-setup.pl ${process.arch} ${outerPort}`); }
    finally { await new Promise(resolve=>listener.close(resolve)); }
    return {version:1,productionQualified:false,httpTopologyQualified:false,
      packagedBoundaryProbePassed:true,prototypeChanges:['namespace uid/gid0 avoids devpts second userns','namespaced NET_ADMIN and SETPCAP','proc-free ioctl/netlink/prctl attestation'],
      status:operation.code===0?'partial-prototype-pass':'prototype-failed',
      exitCode:operation.code,stdout:operation.stdout,stderr:operation.stderr,
      modelCalls:0,metadataPort80Qualified:false};
  } finally {
    // The disposable container is the cleanup authority even if target retirement fails.
    await fs.rm(root, { recursive: true, force: true });
  }
}
if (require.main === module) main().then(result => console.log(JSON.stringify(result))).catch(error => {
  console.error(JSON.stringify({ status: 'unavailable', productionQualified: false,
    httpTopologyQualified: false, error: error.code || error.name, detail: error.message })); process.exitCode = 1;
});
module.exports = { main };
