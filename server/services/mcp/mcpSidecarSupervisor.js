'use strict';

/**
 * McpSidecarSupervisor — brings up the MCP lab's real-execution backends so the
 * workshop runs GENUINE exploits by default, not in-memory simulations.
 *
 * The four sidecars (mcp-sandbox, ssrf-target, rogue-mcp, mailpit) provide real
 * command execution, a real internal/metadata HTTP target, a real second MCP
 * server, and a real SMTP sink. They only give authentic behaviour inside
 * containers (sandbox-runner root-seeds /var/secrets and execs /bin/bash;
 * mailpit is a Go image), so Docker is the one portable isolation layer that
 * works identically on Mac/Windows/Linux and matches AWS Fargate byte-for-byte.
 *
 * Behaviour:
 *   - Local host run  → `docker compose up -d` the four services (if not already
 *     reachable and Docker is available), wait for health.
 *   - AWS Fargate / docker-compose full-app → sidecars are sibling containers we
 *     must NOT double-start; detected via TEAM_ID / ECS metadata / non-localhost
 *     runner URL. The supervisor only probes and reports.
 *   - Docker unavailable → we do NOT fake anything: status='error' and the lab
 *     tools return honest "backend unreachable" errors (no simulation).
 *
 * Mirrors server/services/secureshop/agentHostSupervisor.js (spawn + wait-healthy
 * + stop), but drives docker compose instead of a single node child.
 */
const { spawn } = require('node:child_process');
const path = require('node:path');
const cfg = require('./config');
const sandboxRunner = require('./sandboxRunnerClient');
const probes = require('./_probes');
const {
  defaultAuthorityDirectory,
  readLocalDockerAuthority,
  inspectDockerDaemon,
  sanitizeDockerEnvironment,
  isLoopbackServiceUrl,
} = require('../../../scripts/local-docker-authority');
const { workspaceId } = require('../../../scripts/application-data-root');

const REPO = path.resolve(__dirname, '../../..'); // docker-compose.yml lives at repo root
const COMPOSE_SERVICES = ['mcp-sandbox', 'ssrf-target', 'rogue-mcp', 'mailpit'];

class McpSidecarSupervisor {
  constructor(opts = {}) {
    this.status = 'stopped';   // stopped|skipped|starting|running|degraded|error
    this.reason = null;        // human-readable, surfaced on /infra + logs
    this.startedByUs = false;  // only true if WE ran `compose up`
    this.composeCmd = null;    // ['docker','compose'] | ['docker-compose'] | null
    this.healthTimeoutMs = opts.healthTimeoutMs || 60000;
    this.composeStartTimeoutMs = opts.composeStartTimeoutMs || 300000;
    this.composeStopTimeoutMs = opts.composeStopTimeoutMs || 8000;
    this.spawnProcess = opts.spawnProcess || spawn;
    this.environment = opts.environment || process.env;
    this.authorityDirectory = opts.authorityDirectory || defaultAuthorityDirectory({
      workspace: REPO, homeDirectory: opts.homeDirectory,
    });
    this.workspaceId = opts.workspaceId || workspaceId(REPO);
    this.authority = opts.authority || null;
    this.readAuthority = opts.readAuthority || readLocalDockerAuthority;
    this.inspectDaemon = opts.inspectDockerDaemon || inspectDockerDaemon;
    this.commandEnvironment = sanitizeDockerEnvironment(this.environment);
    this.activeCommands = new Set();
    this.stopRequested = false;
    this.cancelHealthWait = null;
  }

  _autostartEnabled() {
    const v = this.environment.MCP_SIDECARS_AUTOSTART;
    return !(v === '0' || v === 'false');
  }

  // AWS Fargate sets TEAM_ID on every app container and runs the sidecars as
  // sibling task containers; docker-compose full-app sets non-localhost URLs.
  // Either way we hand off and never spawn.
  _isManagedExternally() {
    if (this.environment.TEAM_ID) return 'aws-task';
    if (this.environment.ECS_CONTAINER_METADATA_URI_V4) return 'aws-task';
    const url = cfg.SANDBOX_RUNNER_URL || '';
    if (!isLoopbackServiceUrl(url)) return 'external-compose';
    return null;
  }

  async _run(bin, args, { timeoutMs, stdio = 'ignore' } = {}) {
    return new Promise((resolve) => {
      let child;
      let settled = false;
      let timedOut = false;
      let timer = null;
      let killTimer = null;
      const finish = (status, error = null) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        clearTimeout(killTimer);
        if (child) this.activeCommands.delete(child);
        resolve({ status, error, timedOut });
      };
      try {
        child = this.spawnProcess(bin, args, { cwd: REPO, stdio, env: { ...this.commandEnvironment } });
      } catch (error) {
        finish(null, error);
        return;
      }
      this.activeCommands.add(child);
      child.once('error', error => finish(null, error));
      child.once('exit', code => finish(code));
      timer = timeoutMs ? setTimeout(() => {
        timedOut = true;
        try { child.kill('SIGTERM'); } catch {}
        killTimer = setTimeout(() => {
          try { child.kill('SIGKILL'); } catch {}
          finish(null, new Error('command timed out'));
        }, 1000);
        killTimer.unref?.();
      }, timeoutMs) : null;
      timer?.unref?.();
    });
  }

  async _detectComposeCmd() {
    if (this.stopRequested) return null;
    const tryCmd = async (bin, args) => (await this._run(bin, args, { timeoutMs: 5000 })).status === 0;
    if (await tryCmd('docker', ['--host', this.authority.host, 'compose', 'version'])) {
      return ['docker', '--host', this.authority.host, 'compose'];
    }
    if (this.stopRequested) return null;
    if (await tryCmd('docker-compose', ['version'])) return ['docker-compose'];
    return null;
  }

  async _bindAuthority() {
    if (!this.authority) {
      this.authority = await this.readAuthority({
        directory: this.authorityDirectory,
        workspaceId: this.workspaceId,
      });
    }
    if (!this.authority) {
      throw new Error('Local Docker authority is not configured. Run `npm run setup -- --upgrade` before MCP sidecar autostart.');
    }
    await this._verifyAuthority();
    this.commandEnvironment = sanitizeDockerEnvironment(this.environment, this.authority.host);
  }

  async _verifyAuthority() {
    const daemonId = await this.inspectDaemon({ authority: this.authority, environment: this.environment });
    if (daemonId !== this.authority.daemonId) {
      throw new Error('The configured local Docker socket identifies a different daemon; MCP sidecar mutation was refused.');
    }
  }

  async _allReachable() {
    const [runner, ssrf, rogue, mail] = await Promise.all([
      sandboxRunner.health().then((h) => !!(h && h.ok)).catch(() => false),
      probes.http(`${cfg.SSRF_TARGET_URL}/health`),
      probes.http(`${cfg.ROGUE_MCP_URL}/health`),
      probes.http(`${cfg.MAILPIT_API_URL}/api/v1/messages?limit=1`),
    ]);
    return { runner, ssrf, rogue, mail, all: runner && ssrf && rogue && mail };
  }

  async _waitHealthy() {
    const deadline = Date.now() + this.healthTimeoutMs;
    let last = await this._allReachable();
    while (!last.all && !this.stopRequested && Date.now() < deadline) {
      await new Promise(resolve => {
        const timer = setTimeout(resolve, 1500);
        this.cancelHealthWait = () => { clearTimeout(timer); resolve(); };
      });
      this.cancelHealthWait = null;
      if (this.stopRequested) break;
      last = await this._allReachable();
    }
    return last;
  }

  async start() {
    this.stopRequested = false;
    if (!this._autostartEnabled()) {
      this.status = 'skipped';
      this.reason = 'MCP_SIDECARS_AUTOSTART disabled';
      return;
    }

    const external = this._isManagedExternally();
    if (external) {
      const h = await this._allReachable();
      if (this.stopRequested) { this.status = 'stopped'; return; }
      this.status = h.all ? 'running' : 'degraded';
      this.reason = `sidecars managed externally (${external}); not spawning`;
      return;
    }

    // Someone may have already run `docker compose up` by hand.
    const pre = await this._allReachable();
    if (this.stopRequested) { this.status = 'stopped'; return; }
    if (pre.all) {
      this.status = 'running';
      this.reason = 'sidecars already reachable';
      return;
    }

    try { await this._bindAuthority(); }
    catch (error) {
      this.status = 'error';
      this.reason = error.message;
      console.warn(`[mcp-sidecars] ${this.reason}`);
      return;
    }
    this.composeCmd = await this._detectComposeCmd();
    if (this.stopRequested) { this.status = 'stopped'; return; }
    if (!this.composeCmd) {
      this.status = 'error';
      this.reason = 'Docker not available — the MCP lab will not fake results. '
        + 'Start Docker (Rancher/Docker Desktop) to run the real sidecars.';
      console.warn(`[mcp-sidecars] ${this.reason}`);
      return;
    }

    const [bin, ...sub] = this.composeCmd;
    this.status = 'starting';
    try { await this._verifyAuthority(); }
    catch (error) {
      this.status = 'error';
      this.reason = error.message;
      return;
    }
    if (this.stopRequested) { this.status = 'stopped'; return; }
    this.startedByUs = true;
    const r = await this._run(bin, [...sub, 'up', '-d', '--build', ...COMPOSE_SERVICES], {
      stdio: 'inherit', timeoutMs: this.composeStartTimeoutMs,
    });
    if (this.stopRequested) return;
    if (r.status !== 0) {
      this.status = 'error';
      const detail = r.timedOut ? 'timed out' : r.error?.code === 'ENOENT' ? 'was not found' : `failed (exit ${r.status})`;
      this.reason = `\`docker compose up\` ${detail}; is the Docker daemon running?`;
      return;
    }

    const h = await this._waitHealthy();
    if (this.stopRequested) return;
    if (h.all) {
      this.status = 'running';
      this.reason = 'sidecars started via docker compose';
    } else {
      this.status = 'degraded';
      this.reason = `started, but not all healthy in time (runner:${h.runner} ssrf:${h.ssrf} rogue:${h.rogue} mail:${h.mail})`;
    }
  }

  // Only tear down what WE started — leave a dev's manual stack / AWS task
  // containers running. The application lifecycle awaits this bounded cleanup.
  async stop() {
    this.stopRequested = true;
    this.status = 'stopping';
    this.cancelHealthWait?.();
    this.cancelHealthWait = null;
    for (const child of [...this.activeCommands]) {
      try { child.kill('SIGTERM'); } catch {}
    }
    const cancellationDeadline = Date.now() + 1000;
    while (this.activeCommands.size && Date.now() < cancellationDeadline) {
      await new Promise(resolve => setTimeout(resolve, 10));
    }
    for (const child of [...this.activeCommands]) {
      try { child.kill('SIGKILL'); } catch {}
    }
    if (!this.startedByUs || !this.composeCmd) { this.status = 'stopped'; return; }
    try { await this._verifyAuthority(); }
    catch (error) {
      this.status = 'error';
      this.reason = error.message;
      return;
    }
    const [bin, ...sub] = this.composeCmd;
    await this._run(bin, [...sub, 'stop', ...COMPOSE_SERVICES], { timeoutMs: this.composeStopTimeoutMs });
    this.startedByUs = false;
    this.status = 'stopped';
  }

  describe() {
    return {
      status: this.status,
      reason: this.reason,
      startedByUs: this.startedByUs,
      autostart: this._autostartEnabled(),
      managedExternally: this._isManagedExternally(),
    };
  }
}

module.exports = { McpSidecarSupervisor };
