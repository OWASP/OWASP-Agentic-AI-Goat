'use strict';

const { spawn } = require('node:child_process');
const { randomBytes } = require('node:crypto');

function main(args = process.argv.slice(2), {
  platform = process.platform, runtime = process, spawnProcess = spawn, retain = setInterval,
} = {}) {
  const failArguments = message => { runtime.stderr.write(`${message}\n`); runtime.exit(2); };
  if (args.length !== 4 || !['ipc', 'plain'].includes(args[2]) || !['shell', 'direct'].includes(args[3])) {
    return failArguments('Invalid owned child guardian arguments');
  }
  const [command, encodedArgs, channel, shellMode] = args;
  let childArgs;
  try { childArgs = JSON.parse(encodedArgs); } catch { return failArguments('Invalid owned child argument encoding'); }
  if (!Array.isArray(childArgs) || childArgs.some(value => typeof value !== 'string' || value.includes('\0'))) {
    return failArguments('Invalid owned child arguments');
  }
  let child;
  let stopped = false;
  const send = message => {
    if (stopped || runtime.connected === false) return;
    try { runtime.send?.(message); } catch { if (platform === 'win32') stop(2); }
  };
  const stop = code => {
    if (stopped) return;
    stopped = true;
    try { child?.kill('SIGTERM'); } catch {}
    // On Windows the independent job owner drains any remaining descendants.
    // This guardian never adopts or terminates a tree by a recorded PID.
    runtime.exit(code);
  };
  const launch = () => {
    if (stopped) return;
    try {
      child = spawnProcess(command, childArgs, {
        env: runtime.env,
        stdio: channel === 'ipc' ? ['inherit', 'inherit', 'inherit', 'ipc'] : 'inherit',
        shell: shellMode === 'shell',
      });
    } catch {
      send({ type: 'owasp-ai-goat-owned-child-outcome', outcome: { type: 'error' } });
      return;
    }
    if (channel === 'ipc') {
      child.on('message', message => {
        if (message?.type === 'owasp-ai-goat-backend-ready') {
          send({ ...message, pid: runtime.pid });
        }
      });
    }
    let reported = false;
    const report = outcome => {
      if (reported) return;
      reported = true;
      send({ type: 'owasp-ai-goat-owned-child-outcome', outcome });
    };
    child.once('error', () => report({ type: 'error' }));
    child.once('exit', (code, signal) => report({ type: 'exit', code, signal }));
  };
  runtime.once('SIGTERM', () => stop(0));
  // Retain the guardian after child outcomes until its owner drains the tree.
  retain(() => {}, 1000);
  if (platform !== 'win32') { launch(); return; }
  if (runtime.connected !== true || typeof runtime.send !== 'function') { stop(2); return; }
  const challenge = randomBytes(32).toString('hex');
  let phase = 'waiting', nonce;
  const exact = (message, fields) => message && typeof message === 'object' && !Array.isArray(message)
    && Object.keys(message).sort().join(',') === fields.slice().sort().join(',');
  runtime.once('disconnect', () => stop(0));
  runtime.on('message', message => {
    if (stopped) return;
    if (exact(message, ['type']) && message.type === 'owasp-ai-goat-owned-guardian-stop') { stop(0); return; }
    if (phase === 'waiting' && exact(message, ['type']) && message.type === 'owasp-ai-goat-owned-guardian-hello') {
      phase = 'ready';
      send({ type: 'owasp-ai-goat-owned-guardian-ready', pid: runtime.pid, challenge });
    } else if (phase === 'ready' && exact(message, ['type', 'challenge', 'nonce'])
      && message.type === 'owasp-ai-goat-owned-guardian-probe' && message.challenge === challenge
      && typeof message.nonce === 'string' && /^[a-f0-9]{64}$/.test(message.nonce)) {
      phase = 'proved'; nonce = message.nonce;
      send({ type: 'owasp-ai-goat-owned-guardian-proof', pid: runtime.pid, challenge, nonce });
    } else if (phase === 'proved' && exact(message, ['type', 'challenge', 'nonce'])
      && message.type === 'owasp-ai-goat-owned-guardian-activate' && message.challenge === challenge && message.nonce === nonce) {
      phase = 'active';
      // The owner activates only after native handle pinning and job assignment.
      // Complete IPC delivery before spawning; loss/error never launches work.
      try {
        runtime.send({ type: 'owasp-ai-goat-owned-guardian-active', pid: runtime.pid, challenge, nonce }, error => {
          if (error) stop(2); else launch();
        });
      } catch { stop(2); }
    } else { stop(2); }
  });
}

if (require.main === module) main();

module.exports = { main };
