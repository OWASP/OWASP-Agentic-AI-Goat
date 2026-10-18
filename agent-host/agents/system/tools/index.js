/**
 * system tools — health_check, restart_service, run_diagnostic, read_config.
 *
 * @intentional-vulnerability command-injection-restart
 * @teaches OWASP-Web:A03
 * @location agent-host/agents/system/tools/index.js
 * intentional — restart_service builds `systemctl restart ${name}` and
 * dispatches via child_process.exec. `name = "nginx; cat /etc/passwd"` runs
 * both commands. Guard: SS_SYSTEM_ALLOW_EXEC gates the actual exec; tests
 * assert the constructed cmd string carries the injection payload.
 *
 * @intentional-vulnerability rce-run-diagnostic
 * @teaches OWASP-Web:A03
 * intentional — run_diagnostic accepts a full `cmd_template` from the caller
 * and appends `args`, then exec's it. This is straight RCE.
 * Guard: same SS_SYSTEM_ALLOW_EXEC env gate.
 *
 * @intentional-vulnerability path-traversal-read-config
 * @teaches OWASP-Web:A01
 * intentional — read_config strips `..` from the input in a SINGLE PASS, then
 * resolves against a base directory. Attacker sends `....//.env` — the
 * single-pass strip removes the middle `..`, leaving `../.env`, which
 * escapes the base. Reads .env and platform_secrets.json exfiltrate real
 * material.
 *
 * @intentional-vulnerability mcp06-credential-leak
 * @teaches OWASP-MCP:MCP-01
 * intentional — read_config surfaces raw file contents (including OPENAI_API_KEY,
 * AWS keys, bearers). Wired as an MCP tool, this is a credential-leaking sink.
 */

const os = require('node:os');
const fs = require('node:fs');
const path = require('node:path');
const { exec } = require('node:child_process');

const REPO = path.resolve(__dirname, '../../../..');
const BASE = path.join(REPO, 'server');
const ALLOW_EXEC = process.env.SS_SYSTEM_ALLOW_EXEC === 'true';

function health_check() {
  // Fake /proc/uptime-ish on macOS: use os.uptime().
  const uptime = os.uptime();
  const load = os.loadavg();
  return {
    ok: true,
    hostname: os.hostname(),
    platform: process.platform,
    node: process.version,
    uptime_s: Math.round(uptime),
    loadavg: load,
    freemem_mb: Math.round(os.freemem() / (1024 * 1024)),
    totalmem_mb: Math.round(os.totalmem() / (1024 * 1024)),
    ts: new Date().toISOString(),
  };
}

function restart_service({ name } = {}) {
  return new Promise((resolve) => {
    const svc = String(name == null ? '' : name);
    // intentional — concatenated into shell string, no escaping.
    const cmd = `systemctl restart ${svc}`;
    if (!ALLOW_EXEC) {
      return resolve({
        ok: true,
        service: svc,
        cmd,
        executed: false,
        note: 'exec guarded by SS_SYSTEM_ALLOW_EXEC (test-safe); vuln surface = the constructed cmd string',
      });
    }
    exec(cmd, { timeout: 4000, maxBuffer: 1024 * 200 }, (err, stdout, stderr) => {
      resolve({
        ok: !err,
        service: svc,
        cmd,
        executed: true,
        stdout: String(stdout || '').slice(0, 2000),
        stderr: String(stderr || '').slice(0, 2000),
        error: err ? err.message : null,
      });
    });
  });
}

function run_diagnostic({ cmd_template, args = '' } = {}) {
  return new Promise((resolve) => {
    const tpl = String(cmd_template == null ? '' : cmd_template);
    const ags = String(args == null ? '' : args);
    // intentional — full RCE: cmd_template can be anything (`sh -c "curl ..."`,
    // `rm -rf /`, etc.). args concatenated as-is.
    const cmd = `${tpl} ${ags}`.trim();
    if (!ALLOW_EXEC) {
      return resolve({
        ok: true,
        cmd,
        executed: false,
        // Excessive permissions: even in guarded mode we still perform a
        // read_file "side capability" on the first arg if it looks like a path.
        // That's the MCP-04 excessive-permissions surface.
        side_read: _mayReadFile(ags),
        note: 'exec guarded by SS_SYSTEM_ALLOW_EXEC (test-safe); vuln surface = the constructed cmd string + side_read',
      });
    }
    exec(cmd, { timeout: 4000, maxBuffer: 1024 * 200 }, (err, stdout, stderr) => {
      resolve({
        ok: !err,
        cmd,
        executed: true,
        stdout: String(stdout || '').slice(0, 4000),
        stderr: String(stderr || '').slice(0, 4000),
        error: err ? err.message : null,
      });
    });
  });
}

function _mayReadFile(candidate) {
  // Best-effort: if candidate looks like a file path AND exists on disk, read it.
  // This is the "excessive permissions" side capability accessible via the
  // run_diagnostic tool. Kept deliberately trivial for teaching.
  try {
    const p = String(candidate || '').trim().split(/\s+/)[0];
    if (!p || p.length > 4096) return null;
    const abs = path.isAbsolute(p) ? p : path.resolve(BASE, p);
    if (!fs.existsSync(abs)) return null;
    const st = fs.statSync(abs);
    if (!st.isFile() || st.size > 128 * 1024) return null;
    return { path: abs, size: st.size, content: fs.readFileSync(abs, 'utf8').slice(0, 4000) };
  } catch {
    return null;
  }
}

function read_config({ path: p } = {}) {
  const raw = String(p == null ? '' : p);
  // Wave 5A F7 — reject absolute paths BEFORE the traversal-strip fires. The
  // annotated teaching bypass uses `....//` to defeat the single-pass strip;
  // callers passing `/etc/passwd` directly should not skip the sanitizer
  // entirely, so we reject them here. The `....//` primitive stays intact.
  if (raw.startsWith('/') || /^[A-Za-z]:[\\/]/.test(raw) || raw.startsWith('\\\\')) {
    return {
      ok: false,
      input: raw,
      error: 'absolute paths not allowed',
      note: 'the teaching bypass is `....//`, not absolute paths',
    };
  }
  // intentional — single-pass strip of `..`. `....//` becomes `../` because
  // only the middle two dots get removed. This is the classic double-encoded
  // traversal bypass.
  const stripped = raw.replace(/\.\.\//g, '').replace(/\.\.\\/g, '');
  const abs = path.resolve(BASE, stripped);
  try {
    const st = fs.statSync(abs);
    if (st.isDirectory()) return { ok: false, error: 'is directory', abs };
    if (st.size > 512 * 1024) return { ok: false, error: 'file too large', abs, size: st.size };
    const content = fs.readFileSync(abs, 'utf8');
    return { ok: true, input: raw, sanitized: stripped, abs, size: st.size, content };
  } catch (e) {
    return { ok: false, input: raw, sanitized: stripped, abs, error: e.message };
  }
}

module.exports = { health_check, restart_service, run_diagnostic, read_config, BASE };
