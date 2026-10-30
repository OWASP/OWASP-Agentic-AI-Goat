'use strict';

// Runs only inside the disposable native qualification image. Deliberately
// unsafe templates below are never evaluated by the host application process.

const crypto = require('node:crypto');
const fs = require('node:fs');
const { spawnSync } = require('node:child_process');
const {
  createPolicyRenderExecutor, policyRenderEffectWitnessFor,
  ISOLATION, COMPILER_SHA256, WORKER_SHA256, buildProbeArgv,
} = require('./executor');

const targets = ['admin'];
const EXPECTED_OUTER_BOUNDING = '00000000a80425fb';
const request = markdown => ({ operationId: crypto.randomUUID(), name: 'native-policy', markdown, targets });
const expression = command => `{{ process.mainModule.require('node:child_process').execFileSync('/bin/sh',['-c',${JSON.stringify(command)}]).toString() }}`;

async function main() {
  const outerStatus = fs.readFileSync('/proc/self/status', 'utf8');
  const outerAppArmor = fs.readFileSync('/proc/self/attr/current', 'utf8').trim();
  const outerUid = outerStatus.match(/^Uid:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)$/mi)?.slice(1).map(Number);
  const outerGid = outerStatus.match(/^Gid:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)$/mi)?.slice(1).map(Number);
  const outerCapabilities = Object.fromEntries(['CapEff','CapPrm','CapInh','CapAmb','CapBnd'].map(name =>
    [name, outerStatus.match(new RegExp(`^${name}:\\s+([0-9a-f]+)$`, 'mi'))?.[1] || null]));
  if (outerUid?.length !== 4 || outerUid.some(value => value !== 10001)
      || outerGid?.length !== 4 || outerGid.some(value => value !== 10001)
      || ['CapEff','CapPrm','CapInh','CapAmb'].some(name => !outerCapabilities[name] || !/^0+$/.test(outerCapabilities[name]))
      || outerCapabilities.CapBnd !== EXPECTED_OUTER_BOUNDING
      || outerAppArmor !== 'owasp-ai-goat-mcp-sandbox (enforce)') {
    throw new Error('Qualification process bootstrap identity mismatch');
  }
  const probe = spawnSync('bwrap', buildProbeArgv(), {
    timeout: 5000, env: { PATH: '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin' },
  });
  if (probe.status !== 0) {
    const diagnostic = Buffer.isBuffer(probe.stderr)
      ? probe.stderr.toString('utf8').replace(/[\r\n\t]+/g, ' ').slice(0, 512) : '';
    throw new Error(`Strict policy render namespace unavailable: status=${probe.status}; signal=${probe.signal || ''}; stderr=${diagnostic}`);
  }
  const executor = createPolicyRenderExecutor({ timeoutMs: 1000, drainGraceMs: 2000 });
  const inert = await executor.render(request('Returns for {{ store_name }}.'));
  if (inert.rendered !== 'Returns for SecureShop.' || inert.isolation !== ISOLATION || !inert.drained) {
    throw new Error(`Inert Nunjucks render failed: exit=${inert.exitCode}; error=${String(inert.error || '').replace(/[\r\n\t]+/g, ' ').slice(0, 1024)}`);
  }

  const command = await executor.render(request(`${expression('umask 077 && cp /owned-source/effect-canary /owned-effect/command-effect')}command-effect`));
  const commandWitness = policyRenderEffectWitnessFor(command);
  if (command.rendered !== 'command-effect' || commandWitness?.commandEffectObserved !== true
      || commandWitness?.workerAttested !== true) {
    throw new Error('Owned command effect was not independently observed');
  }

  const privatePaths = await executor.render(request(`${expression('test ! -e /proc/self/status && test ! -e /root/.ssh/id_rsa && test ! -e /app/server/private.env && umask 077 && cp /owned-source/effect-canary /owned-effect/command-effect')}private-paths-absent`));
  if (privatePaths.rendered !== 'private-paths-absent'
      || policyRenderEffectWitnessFor(privatePaths)?.commandEffectObserved !== true
      || policyRenderEffectWitnessFor(privatePaths)?.workerAttested !== true) {
    throw new Error(`Private-path exclusion was not independently observed: exit=${privatePaths.exitCode}; error=${String(privatePaths.error || '').replace(/[\r\n\t]+/g, ' ').slice(0, 1024)}`);
  }

  const networkProbe = [
    'const net=require("node:net")',
    'const s=net.connect({host:"1.1.1.1",port:80})',
    's.on("connect",()=>process.exit(9))',
    's.on("error",e=>process.exit(["ENETUNREACH","EHOSTUNREACH"].includes(e.code)?0:8))',
    'setTimeout(()=>process.exit(7),300)',
  ].join(';');
  const network = await executor.render(request(`${expression(`${process.execPath} -e '${networkProbe}' && umask 077 && cp /owned-source/effect-canary /owned-effect/command-effect`)}network-denied`));
  if (network.rendered !== 'network-denied'
      || policyRenderEffectWitnessFor(network)?.commandEffectObserved !== true) {
    throw new Error('Network exclusion was not independently observed');
  }

  const oversized = await executor.render(request('{% for i in range(0, 70000) %}A{% endfor %}'));
  if (oversized.exitCode === 0 || oversized.truncated || !oversized.drained || oversized.rendered !== '') {
    throw new Error('Rendered-output bound was not enforced');
  }

  const started = Date.now();
  const timeout = await executor.render(request(expression("exec sh -c 'sleep 30 & wait'")));
  const timeoutDurationMs = Date.now() - started;
  if (!timeout.timedOut || !timeout.drained || timeout.exitCode === 0 || timeoutDurationMs > 5000) {
    throw new Error('Timed process-tree drain was not proven');
  }

  process.stdout.write(JSON.stringify({
    version: 1, isolation: ISOLATION, compilerSha256: COMPILER_SHA256,
    workerSha256: WORKER_SHA256, node: process.version,
    namespaces: { mount: true, network: true, pid: true, uts: true, ipc: true, user: true },
    outerIdentity: { uid: outerUid, gid: outerGid, capabilities: outerCapabilities,
      appArmor: outerAppArmor },
    inert: { renderedSha256: inert.renderedSha256, drained: inert.drained },
    commandEffect: { ...commandWitness, renderedSha256: command.renderedSha256 },
    privatePathExclusion: true,
    workerIdentity: { uid: 10001, gid: 10001, capabilities: 'zero',
      boundingCapabilities: 'zero', noNewPrivs: true,
      attestationTransport: 'init-append-only-stdout-prefix' }, networkExclusion: true,
    outputBound: { exitCode: oversized.exitCode, drained: oversized.drained,
      timedOut: oversized.timedOut, truncated: oversized.truncated },
    timeoutDrain: { exitCode: timeout.exitCode, drained: timeout.drained,
      timedOut: timeout.timedOut, durationMs: timeoutDurationMs },
  }));
}

main().catch(error => { process.stderr.write(`${error.stack || error}\n`); process.exitCode = 1; });
