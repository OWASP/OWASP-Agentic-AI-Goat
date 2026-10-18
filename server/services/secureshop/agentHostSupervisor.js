const { spawn } = require('node:child_process');
const path = require('node:path');
const http = require('node:http');
const { randomUUID } = require('node:crypto');

const REPO = path.resolve(__dirname, '../../..');

class AgentHostSupervisor {
  constructor({ port = Number(process.env.SS_AGENT_HOST_PORT || 8082), restartLimit = 3,
    spawnProcess = spawn, get = http.get, stopTimeoutMs = 3000, env = process.env,
    onTerminalFailure = () => {} } = {}) {
    if (typeof onTerminalFailure !== 'function') throw new TypeError('Agent host terminal failure handler must be a function');
    this.port = port;
    this.restartLimit = restartLimit;
    this.restartCount = 0;
    this.proc = null;
    this.status = 'stopped';
    this.spawnProcess = spawnProcess;
    this.get = get;
    this.stopTimeoutMs = stopTimeoutMs;
    this.instanceId = randomUUID();
    // Restarts belong to the same supervised instance and must not silently
    // adopt a different provider/model after ambient process.env is changed.
    this.childEnv = Object.freeze({ ...env });
    this.stopPromise = null;
    this.startPromise = null;
    this.childStates = new WeakMap();
    this.onTerminalFailure = onTerminalFailure;
    this.terminalFailure = null;
    this.terminalFailureNotified = false;
  }

  setTerminalFailureHandler(handler) {
    if (typeof handler !== 'function') throw new TypeError('Agent host terminal failure handler must be a function');
    if (this.terminalFailureNotified) throw new Error('Agent host is already terminal');
    this.onTerminalFailure = handler;
  }

  _terminalFailure(error) {
    if (this.terminalFailureNotified || this.status === 'stopping' || this.status === 'stopped') return;
    this.status = 'dead';
    this.terminalFailureNotified = true;
    this.terminalFailure = error;
    Promise.resolve().then(() => this.onTerminalFailure(error)).catch(handlerError => {
      console.error('[agent-host] terminal failure handler failed:', handlerError?.message || 'unknown error');
    });
  }

  async _waitHealthy() {
    for (let i = 0; i < 40; i++) {
      await new Promise(r => setTimeout(r, 200));
      const expectedChild = this.proc;
      const failure = expectedChild && this.childStates.get(expectedChild)?.error;
      if (failure) throw failure;
      try {
        const s = await new Promise((resolve, reject) => {
          const req = this.get(`http://127.0.0.1:${this.port}/health`, (res) => {
            let body = '';
            res.on('data', chunk => { body += chunk; if (body.length > 16384) req.destroy(new Error('Invalid health response')); });
            res.on('error', reject);
            res.on('end', () => {
              try { const health = JSON.parse(body);
                resolve(res.statusCode === 200 && health.ok === true && health.instanceId === this.instanceId); }
              catch (error) { reject(error); }
            });
          });
          req.on('error', reject);
          req.setTimeout(1000, () => req.destroy(new Error('Agent health request timed out')));
        });
        if (s && this.proc === expectedChild && ['starting', 'running'].includes(this.status)) return;
      } catch {}
      if (this.status === 'dead' || this.status === 'stopping' || this.status === 'stopped') break;
    }
    throw new Error(`agent-host never healthy on ${this.port}`);
  }

  _spawn() {
    const proc = this.spawnProcess(process.execPath, ['agent-host/index.js'], {
      cwd: REPO,
      env: { ...this.childEnv, SS_AGENT_HOST_PORT: String(this.port), SS_AGENT_HOST_INSTANCE_ID: this.instanceId },
      stdio: ['ignore','inherit','inherit'],
    });
    const state = { error: null, failedSpawn: false, closed: false, exited: false };
    this.childStates.set(proc, state);
    proc.once('error', error => {
      state.error = error;
      state.failedSpawn = !Number.isInteger(proc.pid) || proc.pid <= 0;
      // An error from an already-spawned child is not proof it terminated.
      if (state.failedSpawn && this.proc === proc) this._terminalFailure(error);
    });
    proc.once('close', () => { state.closed = true; });
    proc.once('exit', (code) => {
      state.exited = true;
      if (this.status === 'stopping' || this.status === 'stopped') return;
      if (this.restartCount >= this.restartLimit) {
        console.error(`[agent-host] exceeded restart limit (${this.restartLimit}); giving up`);
        this._terminalFailure(Object.assign(new Error('SecureShop agent host exceeded its restart limit'), {
          code: 'SS_AGENT_HOST_RESTART_LIMIT', restartLimit: this.restartLimit,
        }));
        return;
      }
      this.restartCount += 1;
      console.warn(`[agent-host] crashed with code ${code}; restart ${this.restartCount}/${this.restartLimit}`);
      this.proc = this._spawn();
    });
    return proc;
  }

  async start() {
    if (this.startPromise) return this.startPromise;
    if (this.proc && this.status === 'running') return;
    if (this.proc || this.stopPromise) throw new Error('Agent host lifecycle transition already in progress');
    this.startPromise = this._start().finally(() => { this.startPromise = null; });
    return this.startPromise;
  }

  async _start() {
    this.status = 'starting';
    try {
      this.proc = this._spawn();
      await this._waitHealthy();
      if (this.status !== 'starting' || !this.proc) throw new Error('Agent host stopped during startup');
      this.status = 'running';
    } catch (error) {
      try { await this.stop(); }
      catch (cleanupError) { error.cleanupError = cleanupError; }
      throw error;
    }
  }

  async stop() {
    if (this.stopPromise) return this.stopPromise;
    this.stopPromise = this._stop().finally(() => { this.stopPromise = null; });
    return this.stopPromise;
  }

  _isTerminal(proc) {
    const state = this.childStates.get(proc);
    if (state?.failedSpawn === true && !(proc.pid > 0)) return state.closed === true;
    return proc.exitCode != null || proc.signalCode != null || state?.exited === true;
  }

  async _signalAndWait(proc, signal) {
    if (this._isTerminal(proc)) return;
    await new Promise((resolve, reject) => {
      const onExit = () => done();
      const onClose = () => { if (this._isTerminal(proc)) done(); };
      const timer = setTimeout(() => done(Object.assign(new Error('agent-host did not exit after signal'), {
        code: 'SS_AGENT_HOST_STOP_TIMEOUT',
      })), this.stopTimeoutMs);
      const done = error => {
        clearTimeout(timer);
        proc.removeListener('exit', onExit);
        proc.removeListener('close', onClose);
        error ? reject(error) : resolve();
      };
      proc.once('exit', onExit);
      proc.on('close', onClose);
      // Failed spawn has no process to signal; wait for Node's close proof.
      if (this.childStates.get(proc)?.failedSpawn && !(proc.pid > 0)) return;
      try { proc.kill(signal); } catch (error) { done(error); }
    });
  }

  async _stop() {
    this.status = 'stopping';
    const p = this.proc;
    try {
      if (p) {
        if (!this._isTerminal(p)) {
          try { await this._signalAndWait(p, 'SIGTERM'); }
          catch {
            if (!this._isTerminal(p)) await this._signalAndWait(p, 'SIGKILL');
          }
        }
        if (this.proc === p) this.proc = null;
      }
      this.status = 'stopped';
    } catch (error) {
      // Retain the handle so a caller or outer owner can retry cleanup.
      this.status = 'dead';
      throw error;
    }
  }
}

module.exports = { AgentHostSupervisor };
