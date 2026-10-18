'use strict';

const fs = require('node:fs/promises');
const path = require('node:path');
const childProcess = require('node:child_process');
const { createMcpTargetStore } = require(process.env.MCP_TARGET_MODULE);

async function main() {
  const root = process.env.MCP_TARGET_ROOT;
  const fixtureRoot = process.env.MCP_TARGET_FIXTURE_ROOT;
  const targetId = process.env.MCP_TARGET_STOP_ID;
  if (!root || !fixtureRoot || !targetId) throw new Error('STOP_PROBE_CONFIG_REQUIRED');
  const binding = { targetId, ownerId: 991, platformSessionId: 992, generation: 1 };
  const allow = async () => true;
  const targetTmp = path.join(root, 'targets', targetId, 'rootfs', 'tmp');
  const spawn = (...args) => {
    const child = childProcess.spawn(...args);
    fs.writeFile(path.join(targetTmp, 'bwrap-outer-pid'), String(child.pid)).catch(() => child.kill('SIGKILL'));
    return child;
  };
  const store = createMcpTargetStore({ root, fixtureRoot, executionTimeoutMs: 300000, spawn });
  const published = await store.provisionTarget(binding, { authorize: allow });
  const running = store.executeTarget(published.capability, allow,
    'printf READY > /tmp/container-stop-ready; while :; do sleep 1; done');
  const deadline = Date.now() + 10000;
  while (Date.now() < deadline) {
    try {
      if (await fs.readFile(path.join(targetTmp, 'container-stop-ready'), 'utf8') === 'READY') {
        const outerPid = (await fs.readFile(path.join(targetTmp, 'bwrap-outer-pid'), 'utf8')).trim();
        process.stdout.write(`BWRAP_READY ${outerPid}\n`);
        await running;
        throw new Error('STOP_PROBE_RETURNED');
      }
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
    }
    await new Promise(resolve => setTimeout(resolve, 25));
  }
  throw new Error('STOP_PROBE_START_TIMEOUT');
}

main().catch(error => { console.error(error); process.exitCode = 1; });
