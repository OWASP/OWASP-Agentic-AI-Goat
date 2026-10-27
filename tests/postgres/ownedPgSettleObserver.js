'use strict';

// One read-only strict-inventory observation. The 15-second work deadline and
// the adapter's guest timeout/retirement are distinct; failure never certifies
// that a remote Lima command was cancelled.
const { spawn } = require('node:child_process');
const crypto = require('node:crypto');

const MAX_INVENTORY_BYTES = 2 * 1024 * 1024;
const RETIREMENT_MS = 185000;

function groupAbsent(pgid) {
  if (!Number.isSafeInteger(pgid) || pgid <= 0) return false;
  try { process.kill(-pgid, 0); return false; }
  catch (error) { return error.code === 'ESRCH'; }
}

async function observe({ execute, launch = spawn, workMs, retirementMs = RETIREMENT_MS,
                         absent = groupAbsent }) {
  if (typeof execute !== 'function' || typeof launch !== 'function' ||
      !Number.isFinite(workMs) || workMs <= 0 || workMs > 15000 ||
      !Number.isFinite(retirementMs) || retirementMs <= 0 || retirementMs > RETIREMENT_MS)
    throw new Error('PG_OBSERVER_BUDGET');
  const controller = new AbortController();
  let nestedPid = null, nestedSpawnCount = 0, nestedChildCloseObserved = false;
  const trackedLaunch = (file, argv, options) => {
    const child = launch(file, argv, options);
    nestedSpawnCount += 1;
    nestedPid = child.pid;
    if (!Number.isSafeInteger(nestedPid) || nestedPid <= 0 ||
        typeof child.once !== 'function' || options?.detached !== true)
      throw new Error('PG_OBSERVER_CHILD_OWNERSHIP');
    child.once('close', () => { nestedChildCloseObserved = true; });
    return child;
  };
  let workExpired = false;
  const timer = setTimeout(() => { workExpired = true; controller.abort(); }, workMs);
  let retirementTimer;
  let completed = false, output = null, failureCode = null;
  const pending = Promise.resolve().then(() => execute(controller.signal, trackedLaunch));
  // Attach the rejection observer before a retirement race can detach pending.
  const settled = pending.then(value => ({ value }), error => ({ error }));
  try {
    const result = await Promise.race([settled, new Promise(resolve => {
      retirementTimer = setTimeout(() => resolve({ debt: true }), workMs + retirementMs);
    })]);
    if (!result.debt) {
      completed = true;
      if (result.error) failureCode = String(result.error.code || 'PG_OBSERVER_PHASE_FAILED').slice(0, 80);
      else output = result.value;
    } else failureCode = 'PG_OBSERVER_RETIREMENT_TIMEOUT';
  } finally { clearTimeout(timer); clearTimeout(retirementTimer); }
  const nestedGroupAbsent = nestedSpawnCount === 1 && nestedChildCloseObserved &&
    completed && absent(nestedPid);
  const validOutput = !workExpired && !failureCode && nestedGroupAbsent &&
    typeof output === 'string' && Buffer.byteLength(output) > 0 &&
    Buffer.byteLength(output) <= MAX_INVENTORY_BYTES;
  return {
    version: 1, workExpired, completed, nestedSpawnCount, nestedPid,
    nestedChildCloseObserved, kernelBirthUnavailable: true,
    nestedGroupAbsent, localRetirementVerified: nestedGroupAbsent,
    failureCode: validOutput ? null : failureCode || 'PG_OBSERVER_OUTPUT_INVALID',
    inventoryBase64: validOutput ? Buffer.from(output).toString('base64') : null,
    inventorySha256: validOutput ? crypto.createHash('sha256').update(output).digest('hex') : null,
  };
}

async function main() {
  if (process.argv.length !== 4 || !/^[0-9a-f]{32}$/.test(process.argv[2]))
    throw new Error('PG_OBSERVER_ARGUMENTS');
  const workMs = Number(process.argv[3]);
  const builder = require('./ownedMcpBoundedBuild');
  const adapter = require('./ownedMcpOriginalBuildAdapter');
  const spec = builder.specification(process.cwd(), process.argv[2]);
  const plan = { spec, commands: { inventory: builder._internals.scripts.inventory } };
  const terminal = await observe({ workMs, execute: async (signal, launch) => {
    await builder._internals.verifyHost(spec);
    if (signal.aborted) throw new Error('PG_OBSERVER_WORK_EXPIRED');
    return adapter._internals.createPhaseExecutor({ launch })(plan, 'inventory', { signal });
  } });
  process.stdout.write(JSON.stringify(terminal) + '\n');
  if (!terminal.localRetirementVerified || terminal.failureCode) process.exitCode = 1;
}

if (require.main === module) main().catch(error => {
  process.stderr.write(String(error.code || 'PG_OBSERVER_FAILED'));
  process.exitCode = 1;
});

module.exports = { observe, groupAbsent };
