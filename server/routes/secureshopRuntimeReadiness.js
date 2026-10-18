'use strict';

const express = require('express');
const { CAPABILITY: SYSTEM_CONFIG_CAPABILITY } = require('../services/secureshopSystemConfigClient');
const { CAPABILITY: SYSTEM_DIAGNOSTIC_CAPABILITY } = require('../services/secureshopSystemDiagnosticClient');
const { SYSTEM_REBUILD_CAPABILITY } = require('../services/secureshopSystemRebuildService');
const { CAPABILITY: SYSTEM_RESTART_CAPABILITY } = require('../services/secureshopSystemRestartClient');
const PANEL_KEYS = Object.freeze(['catalog','review','storedBrowser','personaInbox','mcpTrust','controlledSsrf']);

function mountedReadiness(composition) {
  const panels = Object.freeze({
    catalog: typeof composition?.catalog?.listProducts === 'function',
    review: typeof composition?.router === 'function',
    storedBrowser: typeof composition?.browserRouter === 'function',
    personaInbox: composition?.personaInbox?.ready === true && typeof composition.personaInbox.router === 'function',
    mcpTrust: composition?.mcpTrust?.ready === true && typeof composition.mcpTrust.router === 'function',
    controlledSsrf: composition?.ssrf?.ready === true && typeof composition.ssrf.router === 'function',
  });
  const capabilities = Object.freeze({
    ...(composition?.ownedMcpRegistry?.ready===true&&typeof composition.ownedMcpRegistry.router==='function'?{boundMcpRegistry:'secureshop-owned-mcp-registry.v1'}:{}),
    ...(composition?.mail?.ready===true&&typeof composition.mail.router==='function'?{boundMail:'secureshop-owned-mail.v1'}:{}),
    ...(composition?.listings?.ready===true&&typeof composition.listings.router==='function'?{boundListings:'secureshop-owned-listings.v1'}:{}),
    ...(composition?.pricing?.ready===true&&typeof composition.pricing.router==='function'?{boundPricing:'secureshop-owned-pricing.v1'}:{}),
    ...(composition?.analytics?.ready===true&&typeof composition.analytics.router==='function'?{boundAnalytics:'secureshop-owned-analytics.v1'}:{}),
    ...(composition?.systemDiagnostic?.ready === true && typeof composition.systemDiagnostic.router === 'function'
      ? { boundSystemDiagnostic: SYSTEM_DIAGNOSTIC_CAPABILITY } : {}),
    ...(composition?.systemConfig?.ready === true && typeof composition.systemConfig.router === 'function'
      ? { boundSystemConfigRead: SYSTEM_CONFIG_CAPABILITY } : {}),
    ...(composition?.systemRebuild?.ready === true && typeof composition.systemRebuild.router === 'function'
      ? { boundSystemRebuild: SYSTEM_REBUILD_CAPABILITY } : {}),
    ...(composition?.systemRestart?.ready === true && typeof composition.systemRestart.router === 'function'
      ? { boundSystemRestart: SYSTEM_RESTART_CAPABILITY } : {}),
  });
  const value = Object.freeze({ ready: PANEL_KEYS.every(key => panels[key] === true), panels,
    ...(Object.keys(capabilities).length ? { capabilities } : {}) });
  if (!value.ready) throw new TypeError('Bound SecureShop panel readiness incomplete');
  return value;
}

// Standalone startup proves its own core; it never substitutes for six-panel
// workshop qualification or enables a feature which was not requested.
function standaloneReadiness(composition, { personaInboxFeature = false,
  mcpTrustFeature = false, ssrfFeature = false } = {}) {
  const methods = (value, names) => names.every(name => typeof value?.[name] === 'function');
  const auth = composition?.standaloneAuth;
  const checks = Object.freeze({
    authentication: methods(auth?.service, ['authenticate', 'register', 'login', 'renew', 'logout',
      'changePassword', 'establishTenantContext']) && typeof auth?.bootstrap === 'function',
    reset: methods(auth?.reset, ['readiness', 'reset', 'readRecovery', 'recover'])
      && methods(auth?.registeredAdminReset, ['preview', 'reset', 'read', 'reveal', 'acknowledge']),
    settings: methods(auth?.mode, ['get', 'set'])
      && methods(auth?.assessmentObjectives, ['list', 'set'])
      && methods(auth?.assessmentRecovery, ['list', 'retry']),
    publicCatalog: methods(composition?.publicCatalog, ['browse', 'product', 'related', 'categories', 'reviews']),
    catalog: methods(composition?.catalog, ['listProducts', 'getProduct', 'listMerchantProducts', 'categories',
      'createMerchantProduct', 'updateMerchantProduct', 'archiveMerchantProduct']),
    commerce: methods(composition?.commerce, ['cart', 'add', 'update', 'remove', 'summary', 'checkout', 'orders', 'order'])
      && typeof auth?.cartImport === 'function',
    account: methods(composition?.account, ['profile', 'updateProfile', 'addresses', 'createAddress', 'updateAddress', 'deleteAddress']),
    administration: methods(composition?.admin, ['users', 'kpis']),
    authority: typeof composition?.personaAuth?.authenticatePersona === 'function'
      && typeof composition?.router === 'function' && typeof composition?.browserRouter === 'function',
    requestedPanels: [[personaInboxFeature, composition?.personaInbox], [mcpTrustFeature, composition?.mcpTrust],
      [ssrfFeature, composition?.ssrf]].every(([requested, panel]) => !requested
        || (panel?.ready === true && typeof panel.router === 'function')),
  });
  if (!Object.values(checks).every(value => value === true)) throw new TypeError('Standalone SecureShop core readiness incomplete');
  return Object.freeze({ ready: true, scope: 'standalone', checks });
}

function createRouter({ authenticateToken, requireAdminLevel, getReadiness } = {}) {
  if (typeof authenticateToken !== 'function' || typeof requireAdminLevel !== 'function'
      || typeof getReadiness !== 'function') throw new TypeError('SecureShop readiness dependencies required');
  const router = express.Router();
  router.use(authenticateToken, requireAdminLevel(1));
  router.get('/', (req, res) => {
    res.set('Cache-Control', 'no-store');
    const readiness = getReadiness();
    if (!readiness || readiness.ready !== true || !readiness.panels
        || !PANEL_KEYS.every(key => readiness.panels[key] === true)) {
      return res.status(503).json({ error: 'Bound SecureShop application unavailable' });
    }
    return res.json(readiness);
  });
  return router;
}

module.exports = { PANEL_KEYS, mountedReadiness, standaloneReadiness, createRouter };
