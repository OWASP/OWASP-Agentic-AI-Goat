'use strict';

const {
    isIP
  } = require('node:net'),
  {
    createHash
  } = require('node:crypto');
const UUID = '[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}',
  SHA = '[a-f0-9]{64}';
function isolated(asset, platform) {
  const a = String(asset || '').toLowerCase(),
    p = String(platform || '').toLowerCase();
  const ipv4Loopback = value => /^127\./.test(value) && isIP(value) === 4,
    platformLoopback = value => value === 'localhost' || ipv4Loopback(value);
  return a !== p && ((ipv4Loopback(a) && platformLoopback(p)) || (a === '::1' && platformLoopback(p)));
}
const derive = value => {
  const h = createHash('sha256').update(JSON.stringify(['bound-upload-serve-v1', value])).digest('hex');
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-5${h.slice(13, 16)}-a${h.slice(17, 20)}-${h.slice(20, 32)}`;
};
function createSecureShopUploadAssetService({
  assetHost,
  platformHost,
  platformHosts,
  port,
  origin,
  capability,
  lookup,
  read,
  assertCurrent,
  recordServe,
  createServer
} = {}) {
  const trustedPlatformHosts = platformHosts === undefined ? [platformHost] : platformHosts,
    expectedOrigin = `http://${assetHost === '::1' ? '[::1]' : assetHost}:${port}`;
  if (!Array.isArray(trustedPlatformHosts) || trustedPlatformHosts.length === 0 || trustedPlatformHosts.some(host => !isolated(assetHost, host)) || new Set(trustedPlatformHosts).size !== trustedPlatformHosts.length || origin !== expectedOrigin || !Number.isSafeInteger(port) || port < 1 || port > 65535 || typeof capability?.verify !== 'function' || typeof capability?.read !== 'function' || typeof lookup !== 'function' || typeof read !== 'function' || typeof assertCurrent !== 'function' || typeof recordServe !== 'function' || typeof createServer !== 'function') throw new TypeError('Cookie-isolated upload asset service required');
  const expectedHost = new URL(origin).host;
  let server,
    ready = false;
  const active = new Set(),
    pending = new Set();
  let receiptFailure = null;
  const handleRequest = async (req, res) => {
    let key,
      ownsDelivery = false;
    try {
      if (req.aborted || res.destroyed || res.writableEnded) return;
      if (req.headers?.host !== expectedHost || req.method !== 'GET' || req.headers?.cookie || req.headers?.authorization || req.headers?.origin) {
        res.statusCode = 403;
        return res.end();
      }
      const match = /^\/assets\/([A-Za-z0-9_-]{1,2048})$/.exec(req.url || '');
      const claim = match && capability.read(match[1]);
      key = claim && claim.effectId;
      if (!claim || !capability.verify(claim) || active.has(key)) {
        res.statusCode = 404;
        return res.end();
      }
      active.add(key);
      ownsDelivery = true;
      const receipt = await lookup(claim);
      if (!receipt) throw Error('missing');
      await assertCurrent(receipt.admission);
      const bytes = await read(receipt);
      await assertCurrent(receipt.admission);
      if (req.aborted || res.destroyed || res.writableEnded) return;
      if (!capability.verify(claim)) throw Error('expired');
      res.statusCode = 200;
      res.setHeader('Content-Type', receipt.contentType);
      res.setHeader('Content-Disposition', receipt.contentDisposition);
      res.setHeader('Content-Security-Policy', 'sandbox allow-scripts');
      res.setHeader('Cross-Origin-Resource-Policy', 'cross-origin');
      res.setHeader('Referrer-Policy', 'no-referrer');
      res.setHeader('Cache-Control', 'no-store');
      const finished = new Promise((resolve, reject) => {
        const done = () => {
            res.off('close', closed);
            resolve();
          },
          closed = () => {
            res.off('finish', done);
            reject(Error('closed'));
          };
        res.once('finish', done);
        res.once('close', closed);
      });
      res.end(bytes);
      await finished;
      if (!receipt.canonicalServe) try {
        await recordServe(receipt.admission, {
          serveId: derive([claim.effectId, claim.signature]),
          receiptPath: req.url,
          status: 200,
          contentType: receipt.contentType,
          contentDisposition: receipt.contentDisposition,
          nosniffPresent: false,
          responseByteCount: receipt.responseByteCount,
          responseSha256: receipt.responseSha256
        }, receipt.effect);
      } catch (error) {
        const recovered = await lookup(claim);
        if (!recovered?.canonicalServe) {
          receiptFailure = error;
          ready = false;
          throw error;
        }
      }
    } catch {
      if (!res.headersSent && !res.destroyed && !res.writableEnded) {
        res.statusCode = 404;
        res.end();
      }
    } finally {
      if (ownsDelivery) active.delete(key);
    }
  };
  const handler = (req, res) => {
    const work = handleRequest(req, res);
    pending.add(work);
    work.finally(() => pending.delete(work));
    return work;
  };
  return Object.freeze({
    handler,
    async start() {
      if (server) throw Error('already started');
      const owned = createServer(handler);
      server = owned;
      try {
        await new Promise((ok, no) => owned.once('error', no).listen(port, assetHost, ok));
      } catch (error) {
        server = null;
        let cleanupError = null;
        await new Promise(resolve => owned.close(closeError => {
          if (closeError && closeError.code !== 'ERR_SERVER_NOT_RUNNING') cleanupError = closeError;
          resolve();
        }));
        if (cleanupError) error.cleanupError = cleanupError;
        throw error;
      }
      ready = true;
    },
    async stop() {
      ready = false;
      if (!server) return;
      const owned = server;
      server = null;
      await new Promise((ok, no) => owned.close(e => e ? no(e) : ok()));
      await Promise.all([...pending]);
      if (receiptFailure) throw Error('Upload serve receipt did not persist');
    },
    isReady: () => ready
  });
}
module.exports = {
  createSecureShopUploadAssetService,
  isCookieIsolatedHost: isolated
};
