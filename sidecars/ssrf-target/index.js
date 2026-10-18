'use strict';

/**
 * SSRF target — a stand-in for the cloud instance-metadata service and an
 * internal admin API. The app's fetch_url tool rewrites "dangerous" targets a
 * student supplies (169.254.169.254, 10.0.1.100, *.internal) to THIS in-task
 * service and makes a REAL socket request to it. That means the SSRF objective
 * exercises a genuine outbound HTTP request (real socket, real response) while
 * the actual AWS metadata endpoint is never touched — egress security groups
 * still block the real 169.254.169.254 from the task.
 *
 * It records every hit so tests (and the Captured Data panel) can prove a real
 * request reached it.
 *
 *   GET /latest/meta-data/iam/security-credentials[/<role>]  → fake STS creds
 *   GET /internal/admin | /admin | /secret | /api            → internal secrets
 *   GET /health                                              → benign
 *   GET /_hits                                               → recorded requests
 */

const http = require('node:http');

const PORT = parseInt(process.env.SSRF_TARGET_PORT || '9099', 10);
const HOST = process.env.SSRF_TARGET_HOST || '0.0.0.0';

const hits = [];
function record(req, body) {
  hits.push({ method: req.method, url: req.url, at: new Date().toISOString(),
    ua: req.headers['user-agent'] || '', body: body ? String(body).slice(0, 2000) : undefined });
  if (hits.length > 200) hits.shift();
}

const server = http.createServer((req, res) => {
  const url = req.url || '/';
  const jsonHead = { 'content-type': 'application/json' };

  if (url === '/health') {
    res.writeHead(200, jsonHead);
    return res.end(JSON.stringify({ status: 'healthy', uptime: '28d 7h 11m',
      services: { db: 'up', mcp: 'up', cache: 'up' } }));
  }
  if (url === '/_hits') {
    res.writeHead(200, jsonHead);
    return res.end(JSON.stringify({ count: hits.length, hits }));
  }

  // Exfil collector: record the POST body so a supply-chain courier is provable.
  if (req.method === 'POST') {
    let body = '';
    req.on('data', (c) => { body += c; if (body.length > 100000) req.destroy(); });
    req.on('end', () => {
      record(req, body);
      res.writeHead(200, jsonHead);
      res.end(JSON.stringify({ status: 'received', bytes: body.length }));
    });
    return;
  }

  record(req);

  if (url.startsWith('/latest/meta-data/iam/security-credentials')) {
    // Bare listing returns the role name; role path returns the credentials.
    if (/security-credentials\/?$/.test(url)) {
      res.writeHead(200, { 'content-type': 'text/plain' });
      return res.end('mcp-ops-instance-role');
    }
    res.writeHead(200, jsonHead);
    return res.end(JSON.stringify({
      Code: 'Success',
      AccessKeyId: 'ASIA4X2MCPMETADATA01',
      SecretAccessKey: '9Xk2mCpMeta/DataSecretKeyExampleZ7Qw',
      Token: 'IQoJb3JpZ2luX2VjEXAMPLEmetadatatoken==',
      Expiration: '2026-01-21T00:00:00Z',
    }, null, 2));
  }

  if (/(admin|secret|token|cred|internal|api)/i.test(url)) {
    res.writeHead(200, jsonHead);
    return res.end(JSON.stringify({
      service: 'internal-admin-api',
      db_password: 'McP#Pr0d!2026',
      internal_api_key: 'sk-mcp-internal-a8f2k9d1e4b7c3f6',
    }, null, 2));
  }

  res.writeHead(200, jsonHead);
  return res.end(JSON.stringify({ service: 'ssrf-target', path: url }));
});

server.listen(PORT, HOST, () => {
  const address = server.address();
  const boundPort = address && typeof address === 'object' ? address.port : PORT;
  // eslint-disable-next-line no-console
  console.log(`[ssrf-target] listening on ${HOST}:${boundPort}`);
});
