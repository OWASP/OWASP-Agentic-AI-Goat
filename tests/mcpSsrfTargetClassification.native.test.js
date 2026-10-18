'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { spawn } = require('node:child_process');

const enabled = process.env.RUN_MCP_SSRF_TARGET_NATIVE === '1';
const root = path.resolve(__dirname, '..');
const targetEntry = path.join(root, 'sidecars/ssrf-target/index.js');

function waitForStartup(child) {
  return new Promise((resolve, reject) => {
    let stdout = '';
    let stderrBytes = 0;
    const timeout = setTimeout(() => reject(new Error('SSRF target startup timed out')), 5000);
    const finish = (error, port) => {
      clearTimeout(timeout);
      child.stdout.off('data', onData);
      child.off('error', onError);
      child.off('exit', onExit);
      if (error) reject(error); else resolve(port);
    };
    const onError = () => finish(new Error('SSRF target child could not start'));
    const onExit = code => finish(new Error(`SSRF target exited before readiness (${code})`));
    const onData = chunk => {
      stdout += chunk.toString('utf8');
      if (Buffer.byteLength(stdout) > 4096) return finish(new Error('SSRF target readiness output exceeded bound'));
      const match = /(?:^|\n)\[ssrf-target\] listening on 127\.0\.0\.1:(\d+)(?:\n|$)/.exec(stdout);
      if (!match) return;
      const port = Number(match[1]);
      if (!Number.isInteger(port) || port < 1 || port > 65535) {
        finish(new Error('SSRF target reported an invalid bound port'));
      } else finish(null, port);
    };
    child.stderr.on('data', chunk => {
      stderrBytes += chunk.length;
      if (stderrBytes > 4096) child.kill('SIGKILL');
    });
    child.stdout.on('data', onData);
    child.once('error', onError);
    child.once('exit', onExit);
  });
}

function processAlive(pid) {
  try { process.kill(pid, 0); return true; }
  catch (error) {
    if (error.code === 'ESRCH') return false;
    throw error;
  }
}

async function stopOwnedChild(child, closePromise) {
  if (child.exitCode === null && child.signalCode === null) child.kill('SIGTERM');
  let timer;
  const graceful = await Promise.race([
    closePromise.then(() => true),
    new Promise(resolve => { timer = setTimeout(() => resolve(false), 3000); }),
  ]);
  clearTimeout(timer);
  if (!graceful) {
    child.kill('SIGKILL');
    await Promise.race([
      closePromise,
      new Promise((_, reject) => setTimeout(() => reject(new Error('Owned SSRF target did not terminate')), 1000)),
    ]);
  }
  assert.equal(processAlive(child.pid), false, 'owned SSRF target PID remains after close');
}

async function hitInventory(baseUrl) {
  const response = await fetch(`${baseUrl}/_hits`, { signal: AbortSignal.timeout(3000) });
  assert.equal(response.status, 200);
  return response.json();
}

test('real controlled target preserves exact SSRF mapping without minting owned credit',
  { skip: !enabled, timeout: 15000 }, async t => {
    const child = spawn(process.execPath, [targetEntry], {
      cwd: root,
      env: { SSRF_TARGET_HOST: '127.0.0.1', SSRF_TARGET_PORT: '0' },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    const closePromise = new Promise(resolve => child.once('close', (code, signal) => resolve({ code, signal })));
    t.diagnostic(`ownedTargetPid=${child.pid}`);
    const priorTarget = process.env.SSRF_TARGET_URL;
    let primaryError;
    try {
      const port = await waitForStartup(child);
      const baseUrl = `http://127.0.0.1:${port}`;
      process.env.SSRF_TARGET_URL = baseUrl;
      for (const modulePath of [
        '../server/services/mcp/config',
        '../server/services/mcp/targets',
        '../server/services/mcp/sandboxShell',
      ]) delete require.cache[require.resolve(modulePath)];
      const targets = require('../server/services/mcp/targets');
      const { McpSandboxShell } = require('../server/services/mcp/sandboxShell');
      const effects = [];
      const shell = new McpSandboxShell('native-controlled-target', { allowLegacySsrfFixture: true,
        listener: { append: value => effects.push(value), read: () => effects },
      });

      for (const url of [
        'https://example.com/api/token?internal=169.254.169.254',
        'http://169.254.169.254.example.com/latest/meta-data',
        'http://monitoring.internal.example.com/health',
      ]) {
        assert.equal(targets.classifySsrfTarget(url), null);
        const result = await shell.toolFetchUrl(url);
        assert.equal(result.achieved, false);
        assert.equal(result.blocked, true);
      }
      assert.equal((await hitInventory(baseUrl)).count, 0,
        'public and suffix-spoofed URLs reached the controlled target');

      const internal = await shell.toolFetchUrl('http://10.0.1.100/internal/admin');
      assert.equal(internal.achieved, true);
      assert.equal(internal.real, true);
      assert.equal(internal.targetUrl, `${baseUrl}/internal/admin`);
      const internalBody = JSON.parse(internal.output);
      assert.equal(internalBody.service, 'internal-admin-api');
      assert.equal(typeof internalBody.db_password, 'string');
      assert.ok(internalBody.db_password.length > 0);
      assert.equal(typeof internalBody.internal_api_key, 'string');
      assert.ok(internalBody.internal_api_key.length > 0);

      const metadata = await shell.toolFetchUrl(
        'http://169.254.169.254/latest/meta-data/iam/security-credentials/');
      assert.equal(metadata.achieved, true);
      assert.equal(metadata.real, true);
      assert.equal(metadata.targetUrl,
        `${baseUrl}/latest/meta-data/iam/security-credentials/mcp-ops-instance-role`);
      const metadataBody = JSON.parse(metadata.output);
      for (const field of ['AccessKeyId', 'SecretAccessKey', 'Token']) {
        assert.equal(typeof metadataBody[field], 'string');
        assert.ok(metadataBody[field].length > 0);
      }

      const health = await shell.toolFetchUrl('http://169.254.169.254/health');
      assert.equal(health.achieved, false);
      assert.equal(health.real, true);
      assert.equal(health.targetUrl, `${baseUrl}/health`);
      assert.equal(effects.length, 2);
      const hits = await hitInventory(baseUrl);
      assert.equal(hits.count, 2);
      assert.deepEqual(hits.hits.map(hit => hit.url), [
        '/internal/admin',
        '/latest/meta-data/iam/security-credentials/mcp-ops-instance-role',
      ]);
    } catch (error) {
      primaryError = error;
    } finally {
      if (priorTarget === undefined) delete process.env.SSRF_TARGET_URL;
      else process.env.SSRF_TARGET_URL = priorTarget;
      try { await stopOwnedChild(child, closePromise); t.diagnostic('ownedTargetAbsent=true'); }
      catch (error) {
        primaryError = new AggregateError(primaryError ? [primaryError, error] : [error],
          'Owned SSRF target cleanup failed');
      }
    }
    if (primaryError) throw primaryError;
  });
