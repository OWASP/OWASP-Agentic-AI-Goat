'use strict';

const http = require('node:http');
const {
  createSecureShopUploadAssetService,
  isCookieIsolatedHost
} = require('./secureshopUploadAssetService');
const {
  createSecureShopUploadAssetCapability
} = require('./secureshopUploadAssetCapability');
const {
  effectiveSecureShopOrigins
} = require('../middleware/applicationCors');
function platformHosts(environment) {
  const origins = effectiveSecureShopOrigins(environment),
    hosts = origins.map(value => {
      let url;
      try {
        url = new URL(value);
      } catch {
        throw Error('Exact SecureShop platform origins required');
      }
      const host = url.hostname.toLowerCase();
      if (url.origin !== value || !['http:', 'https:'].includes(url.protocol) || url.username || url.password || (host !== 'localhost' && !(/^127\./.test(host) && require('node:net').isIP(host) === 4))) throw Error('Exact SecureShop platform origins required');
      return host;
    });
  const unique = [...new Set(hosts)];
  if (!unique.length) throw Error('Exact SecureShop platform origins required');
  return unique;
}
function activationPolicy(environment = process.env) {
  const raw = environment.SS_BOUND_UPLOAD_ASSETS_ENABLED;
  if (raw === undefined || raw === 'false') return Object.freeze({
    enabled: false,
    origin: null,
    capability: null
  });
  if (raw !== 'true') throw Error('SS_BOUND_UPLOAD_ASSETS_ENABLED must be true or false');
  const assetHost = environment.SS_UPLOAD_ASSET_HOST,
    trustedPlatformHosts = platformHosts(environment),
    configuredPlatformHost = environment.SS_PLATFORM_HOST,
    port = Number(environment.SS_UPLOAD_ASSET_PORT),
    origin = environment.SS_UPLOAD_ASSET_PUBLIC_ORIGIN,
    secret = environment.SS_UPLOAD_ASSET_CAPABILITY_SECRET;
  const expectedOrigin = `http://${assetHost === '::1' ? '[::1]' : assetHost}:${port}`;
  if (configuredPlatformHost && !trustedPlatformHosts.includes(configuredPlatformHost.toLowerCase())) throw Error('Configured platform host is not an allowed SecureShop origin');
  if (trustedPlatformHosts.some(host => !isCookieIsolatedHost(assetHost, host)) || !Number.isSafeInteger(port) || port < 1 || port > 65535 || origin !== expectedOrigin) throw Error('Cookie-isolated upload asset configuration required');
  return Object.freeze({
    enabled: true,
    assetHost,
    platformHosts: Object.freeze(trustedPlatformHosts),
    port,
    origin,
    capability: createSecureShopUploadAssetCapability({
      secret
    })
  });
}
async function startSecureShopUploadAssetProduction({
  lifecycle,
  activation,
  backend,
  createServer = http.createServer,
  reader
} = {}) {
  if (activation?.enabled !== true) return Object.freeze({
    enabled: false,
    isReady: () => false,
    origin: null
  });
  if (typeof lifecycle?.registerFinalizer !== 'function' || typeof backend?.lookup !== 'function' || typeof backend?.assertCurrent !== 'function' || typeof backend?.recordServe !== 'function' || backend.capability !== activation.capability) throw new TypeError('Complete upload asset production composition required');
  const exactReader = reader || require('./secureshopUploadAssetReader').createSecureShopUploadAssetReader();
  const service = createSecureShopUploadAssetService({
    ...activation,
    lookup: backend.lookup,
    assertCurrent: backend.assertCurrent,
    recordServe: backend.recordServe,
    read: exactReader,
    createServer
  });
  await service.start();
  let stopped = false;
  const stop = async () => {
    if (stopped) return;
    stopped = true;
    await service.stop();
  };
  lifecycle.registerFinalizer(stop);
  return Object.freeze({
    enabled: true,
    isReady: service.isReady,
    origin: activation.origin,
    stop
  });
}
module.exports = {
  activationPolicy,
  startSecureShopUploadAssetProduction
};
