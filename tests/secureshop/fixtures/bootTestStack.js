const { spawn } = require('node:child_process');
const path = require('node:path');
const http = require('node:http');

const REPO = path.resolve(__dirname, '../../..');
const { McpClientPool, AGENT_NAMES } = require(path.join(REPO, 'server/services/secureshop/mcpClientPool.js'));
const { ToolManifest } = require(path.join(REPO, 'server/services/secureshop/toolManifest.js'));
const { MockProvider } = require(path.join(REPO, 'server/services/secureshop/providers/mockProvider.js'));

async function startTestHost() {
  const proc = spawn(process.execPath, ['agent-host/index.js'], {
    cwd: REPO, env: { ...process.env, SS_AGENT_HOST_PORT: '0' },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let stderr = '', stdout = '', closed = false;
  proc.once('close', () => { closed = true; });
  proc.stderr.on('data', chunk => { stderr = (stderr + chunk).slice(-8192); });
  async function close() {
    if (closed) return;
    proc.kill('SIGTERM');
    let deadline = Date.now() + 3000;
    while (!closed && Date.now() < deadline) await new Promise(r => setTimeout(r, 25));
    if (!closed) proc.kill('SIGKILL');
    deadline = Date.now() + 2000;
    while (!closed && Date.now() < deadline) await new Promise(r => setTimeout(r, 25));
    if (!closed) throw new Error('Owned agent host retirement unproven');
  }
  try {
    const port = await new Promise((resolve, reject) => {
      const timer = setTimeout(() => done(new Error('Agent host readiness deadline: ' + stderr)), 8000);
      const onError = error => done(error);
      const onExit = (code, signal) => done(new Error(`Agent host exited ${code}/${signal}: ${stderr}`));
      const onData = chunk => { stdout = (stdout + chunk).slice(-8192); const match = stdout.match(/agent-host: ready on (\d+)/); if (match) done(null, Number(match[1])); };
      function done(error, value) { clearTimeout(timer); proc.off('error', onError); proc.off('exit', onExit); proc.stdout.off('data', onData); error ? reject(error) : resolve(value); }
      proc.once('error', onError); proc.once('exit', onExit); proc.stdout.on('data', onData);
    });
    await new Promise((resolve, reject) => {
      const req = http.get(`http://127.0.0.1:${port}/health`, res => { res.resume(); res.once('end', () => res.statusCode === 200 ? resolve() : reject(new Error('Agent host health status ' + res.statusCode))); });
      req.on('error', reject); req.setTimeout(1000, () => req.destroy(new Error('Agent host health deadline')));
    });
    return { port, close };
  } catch (error) { await close(); throw error; }
}
async function bootTestStack({ useMock = true } = {}) {
  const host = await startTestHost();
  const baseUrl = `http://127.0.0.1:${host.port}`;
  const pool = new McpClientPool({ baseUrl, agents: AGENT_NAMES });
  try {
    await pool.connect();
    return { pool, manifest: new ToolManifest(pool), provider: useMock ? new MockProvider() : null,
      port: host.port, baseUrl, async close() { try { await pool.close(); } finally { await host.close(); } } };
  } catch (error) { try { await pool.close(); } finally { await host.close(); } throw error; }
}

module.exports = { bootTestStack, startTestHost };
