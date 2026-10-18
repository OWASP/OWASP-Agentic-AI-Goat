'use strict';

// Candidate protocol worker: not mounted by the application or a credit authority.
const http = require('node:http');
const dns = require('node:dns/promises');
const crypto = require('node:crypto');
const fs = require('node:fs');
const manifest = JSON.parse(fs.readFileSync(require('node:path').join(__dirname, require.main === module ? 'dvaia-owned-pricing-http-manifest.json' : 'network-manifest.json'), 'utf8'));
const hash = value => crypto.createHash('sha256').update(value).digest('hex');
const {
  parseUrl,
  normalizeInput
} = require(require.main === module ? './dvaia-owned-pricing-http-input.js' : './input');
async function fetchHop(url, mode, signal) {
  const resolved = await dns.lookup(url.hostname, {
    family: 4
  });
  const port = Number(url.port || 80);
  // This allowlist is policy only; it never selects a response or substitutes URL.
  if (mode === 'fixed' && !(url.hostname === 'benign.training' && resolved.address === '192.0.2.10' && port === 80)) {
    throw Object.assign(Error('policy_denied'), {
      code: 'policy_denied'
    });
  }
  return new Promise((resolve, reject) => {
    const req = http.request(url, {
      method: 'GET',
      agent: false,
      signal,
      lookup: (_host, options, callback) => options.all ? callback(null, [{
        address: resolved.address,
        family: 4
      }]) : callback(null, resolved.address, 4),
      headers: {
        connection: 'close'
      }
    }, res => {
      const chunks = [];
      let bytes = 0;
      res.on('data', chunk => {
        bytes += chunk.length;
        if (bytes > 32768) req.destroy(Error('response_too_large'));else chunks.push(chunk);
      });
      res.on('error', reject);
      res.on('end', () => resolve({
        effectiveUrl: url.href,
        resolvedAddress: resolved.address,
        port,
        status: res.statusCode,
        location: res.headers.location || null,
        body: Buffer.concat(chunks).toString('utf8')
      }));
    });
    req.on('error', reject);
    req.end();
  });
}
async function run(raw, {
  inherited = true
} = {}) {
  const input = normalizeInput(raw);
  const original = parseUrl(input.url);
  const hits = [];
  const servers = [];
  const signal = AbortSignal.timeout(5000);
  let outcome;
  try {
    for (const [index, definition] of manifest.listeners.entries()) {
      const server = http.createServer((req, res) => {
        if (hits.length >= 16) {
          res.writeHead(429);
          res.end();
          return;
        }
        const body = JSON.stringify(definition.sensitive ? {
          service: definition.id,
          classification: 'protected-training-record',
          canary: input.canary
        } : req.url === '/competitor-manual' ? {
          service: definition.id,
          classification: 'attacker-manual',
          markdown: input.manual
        } : {
          service: definition.id,
          classification: 'public-quote',
          ...input.quote
        });
        let location = null;
        let status = 200;
        if (definition.id === 'benign' && req.url === '/redirect-metadata') {
          status = 302;
          location = 'http://169.254.169.254/latest/meta-data/';
        }
        if (definition.id === 'benign' && req.url === '/redirect-loop') {
          status = 307;
          location = '/redirect-loop';
        }
        hits.push({
          listener: definition.id,
          localAddress: req.socket.localAddress,
          localPort: req.socket.localPort,
          method: req.method,
          host: req.headers.host,
          path: req.url,
          status,
          responseSha256: hash(location ? '' : body)
        });
        res.writeHead(status, location ? {
          location,
          connection: 'close'
        } : {
          'content-type': 'application/json',
          connection: 'close'
        });
        res.end(location ? '' : body);
      });
      server.requestTimeout = 2000;
      server.headersTimeout = 2000;
      servers.push(server);
      await new Promise((resolve, reject) => {
        server.once('error', reject);
        server.listen(inherited ? {
          fd: index + 3
        } : {
          host: definition.address,
          port: definition.port
        }, resolve);
      });
    }
    const hops = [];
    let current = original;
    try {
      for (let i = 0; i <= 3; i++) {
        const hop = await fetchHop(current, input.mode, signal);
        hops.push(hop);
        if (![301, 302, 303, 307, 308].includes(hop.status) || !hop.location) {
          outcome = {
            status: 'completed',
            hops
          };
          break;
        }
        if (i === 3) throw Error('redirect_limit');
        current = parseUrl(new URL(hop.location, current).href);
      }
    } catch (error) {
      outcome = {
        status: 'failed',
        category: ['policy_denied', 'redirect_limit', 'invalid_url', 'response_too_large'].includes(error.message) ? error.message : 'network_failure',
        hops
      };
    }
    return {
      version: 1,
      isolationAttestation: process.env.DVAIA_OWNED_PRICING_HTTP_ATTESTED === '1' ? {
        zeroCapabilities: true,
        noNewPrivileges: true,
        loopbackOnly: true,
        noDefaultRoute: true,
        unshareDenied: true,
        setnsDenied: true,
        cloneNamespaceDenied: true,
        mountDenied: true,
        onlyListenerDescriptors: true,
        udpExternalRouteDenied: true,
        ipv6ExternalRouteDenied: true
      } : null,
      originalUrlSha256: hash(input.url),
      originalUrlBytes: Buffer.byteLength(input.url),
      mode: input.mode,
      ...outcome,
      hits
    };
  } finally {
    await Promise.all(servers.map(server => new Promise(resolve => {
      server.closeAllConnections();
      if (!server.listening) return resolve();
      server.close(resolve);
    })));
  }
}
async function main() {
  if (process.platform !== 'linux' || process.env.DVAIA_OWNED_PRICING_HTTP_ATTESTED !== '1') throw Error('unattested_worker');
  // Bound stdin before parsing; no learner string becomes executable code.
  const chunks = [];
  let bytes = 0;
  for await (const chunk of process.stdin) {
    bytes += chunk.length;
    if (bytes > 32768) throw Error('input_too_large');
    chunks.push(chunk);
  }
  if (fs.existsSync('/proc/self/status')) throw Error('unexpected_proc');
  const result = await run(JSON.parse(Buffer.concat(chunks).toString('utf8')));
  process.stdout.write(JSON.stringify(result) + '\n');
}
if (require.main === module) main().catch(() => {
  process.stderr.write('owned-pricing-http:operation_failed\n');
  process.exitCode = 70;
});
module.exports = {
  parseUrl,
  normalizeInput,
  run
};
