'use strict';

/**
 * Network clients for the two in-task HTTP targets:
 *   - ssrf-target : the app's fetch_url makes a REAL request here after mapping
 *                   the "dangerous" host a student supplies (169.254.169.254,
 *                   10.0.x, *.internal) onto this controlled service.
 *   - rogue-mcp   : register_server performs a REAL MCP discovery handshake
 *                   (GET /mcp/list_tools) here and imports the advertised tools.
 *
 * Both degrade to { ok:false } when the sidecar is unavailable.
 */

const { SSRF_TARGET_URL, ROGUE_MCP_URL, BACKEND_TIMEOUT_MS } = require('./config');

async function fetchWithTimeout(url, opts = {}, timeoutMs = BACKEND_TIMEOUT_MS) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try { return await fetch(url, { ...opts, signal: ctrl.signal }); }
  finally { clearTimeout(t); }
}

/**
 * Map an attacker-supplied URL onto a path against the in-task ssrf-target,
 * preserving the semantics (metadata path vs internal admin/api path).
 */
function classifySsrfTarget(rawUrl) {
  if (typeof rawUrl !== 'string') return null;
  let url;
  try { url = new URL(rawUrl); } catch { return null; }
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password) return null;
  const host = url.hostname.toLowerCase().replace(/\.$/, '');
  const octets = host.split('.').map(Number);
  const ipv4 = /^\d+\.\d+\.\d+\.\d+$/.test(host) && octets.every(n => n >= 0 && n <= 255);
  const privateHost = ipv4 && (octets[0] === 10 || octets[0] === 127
    || (octets[0] === 192 && octets[1] === 168)
    || (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31)
    || (octets[0] === 169 && octets[1] === 254));
  if (!privateHost && !['localhost', '[::1]', 'api.acme-corp.internal', 'monitoring.internal'].includes(host)) return null;
  if (url.pathname === '/health' || (host === 'monitoring.internal' && url.pathname === '/')) {
    return Object.freeze({ targetPath: '/health', benign: true, kind: 'health' });
  }
  if (host === '169.254.169.254') {
    // Preserve the metadata path the student browsed to.
    let p = url.pathname === '/' ? '/latest/meta-data/iam/security-credentials/mcp-ops-instance-role' : url.pathname;
    if (/security-credentials\/?$/.test(p)) p = '/latest/meta-data/iam/security-credentials/mcp-ops-instance-role';
    return Object.freeze({ targetPath: p, benign: false, kind: 'metadata' });
  }
  // Internal admin / service endpoints.
  return Object.freeze({ targetPath: '/internal/admin', benign: false, kind: 'internal' });
}

/**
 * Perform the real SSRF request. @returns {ok, status, body, targetUrl} or {ok:false}.
 */
async function fetchViaSsrfTarget(rawUrl) {
  const target = classifySsrfTarget(rawUrl);
  if (!target) return { ok: false, error: 'URL is not a controlled internal lab target' };
  const targetUrl = `${SSRF_TARGET_URL}${target.targetPath}`;
  try {
    const r = await fetchWithTimeout(targetUrl);
    const body = await r.text();
    return { ok: r.ok, status: r.status, body, targetUrl };
  } catch (e) {
    return { ok: false, error: e.message, targetUrl };
  }
}

/**
 * Courier arbitrary data to the in-task target over a REAL socket (used by the
 * supply-chain postinstall exfil). @returns {ok, status, targetUrl} or {ok:false}.
 */
async function postToTarget(path, body) {
  const targetUrl = `${SSRF_TARGET_URL}${path.startsWith('/') ? path : '/' + path}`;
  try {
    const r = await fetchWithTimeout(targetUrl, {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body || {}),
    });
    return { ok: true, status: r.status, targetUrl };
  } catch (e) {
    return { ok: false, error: e.message, targetUrl };
  }
}

/**
 * Perform the real rogue-MCP discovery handshake and return the imported tools.
 * @returns {ok, tools, server, url} or {ok:false}.
 */
async function discoverRogueServer(rogueUrlOverride) {
  const base = rogueUrlOverride || ROGUE_MCP_URL;
  try {
    const r = await fetchWithTimeout(`${base}/mcp/list_tools`);
    if (!r.ok) return { ok: false, error: `rogue HTTP ${r.status}` };
    const body = await r.json();
    return { ok: true, tools: body.tools || [], server: body.server || {}, url: base };
  } catch (e) {
    return { ok: false, error: e.message, url: base };
  }
}

module.exports = { classifySsrfTarget, fetchViaSsrfTarget, postToTarget, discoverRogueServer };
