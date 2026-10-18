'use strict';

const path = require('node:path');

const ROOT = path.resolve(__dirname, '../../..');
const COMMERCE_MODULE = path.join(ROOT, 'server/database/postgres/secureshopCommerceDb.js');
const AGENTS_MODULE = path.join(ROOT, 'server/database/postgres/secureshopAgentsDb.js');
const EAGER_ROOTS = Object.freeze([
  path.join(ROOT, 'agent-host/agents') + path.sep,
  path.join(ROOT, 'server/services/secureshop') + path.sep,
]);

// These names are the non-SQL portion of createSecureShopCommerceDb's public
// interface. SQL interpretation belongs to disposable PostgreSQL tests.
const COMMERCE_METHODS = new Set([
  'product_search_personalizedFeed_1', 'product_search_similar_1', 'product_search_similar_2',
  'summarizer_summarizeProduct_1', 'summarizer_summarizeReviews_1',
  'price_advisor_priceHistory_1', 'price_advisor_findDeals_2', 'price_advisor_compareCompetitor_3',
  'cart_add_1', 'cart_remove_2', 'cart_view_3',
  'support_openTicket_2', 'support_refundRequest_3',
  'listing_create_1', 'listing_import_bulk_1', 'listing_import_bulk_2', 'listing_optimize_images_1',
  'inventory_stock_levels_1', 'inventory_reorder_suggestion_2', 'inventory_set_stock_3',
  'pricing_strategy__retrievePoisonedDoc_1', 'pricing_strategy__retrievePoisonedDoc_2',
  'pricing_strategy_suggest_price_3', 'pricing_strategy_run_pricing_experiment_4',
  'review_moderator_approve_1', 'review_moderator_reject_2', 'review_moderator_moderate_pending_3',
  'email_send_1', 'email_send_2', 'email_read_inbox_3', 'email_read_inbox_4',
  'email_summarize_thread_5', 'email_auto_reply_6',
  'policy_read_policy_1', 'policy_update_policy_2', 'policy_update_policy_3',
  'policy_update_policy_4', 'policy_apply_policy_to_agents_5',
  'listProducts', 'listReviews', 'listPolicies', 'listProductManuals', 'getProductManual',
  'updateProduct', 'analyticsTopProducts', 'analyticsCategories', 'analyticsStatuses',
  'userAction', 'deliverAudit', 'flushAuditOutbox', 'upsertPolicy', 'sendEmail',
]);

const AGENTS_METHODS = new Set([
  'createSession', 'getSession', 'appendMessage', 'getMessages', 'getTokens', 'addTokens',
  'appendTraces', 'getTrace', 'appendAudit', 'getEnforcement', 'getPermission',
  'listPermissions', 'setPermission', 'setEnforcement', 'replaceNativeManifest',
  'externalTools', 'listServers', 'registerServer', 'removeServer', 'describeTools',
  'schemaHistory', 'recentAudit', 'summaryAudit',
]);

let active = false;

function snapshot(value) {
  if (value === undefined) return undefined;
  try { return structuredClone(value); } catch {}
  if (typeof value === 'function') return Object.freeze({ type: 'function', name: value.name || null });
  if (Array.isArray(value)) return value.map(snapshot);
  if (value && Object.getPrototypeOf(value) === Object.prototype) {
    return Object.fromEntries(Object.entries(value).map(([key, child]) => [key, snapshot(child)]));
  }
  return Object.freeze({ type: value?.constructor?.name || typeof value });
}

function makeRepository(kind, allowed, state, implementations, calls) {
  if (!state || typeof state !== 'object' || Array.isArray(state)) {
    throw new TypeError(`${kind} state must be an object`);
  }
  if (!implementations || typeof implementations !== 'object' || Array.isArray(implementations)) {
    throw new TypeError(`${kind} methods must be an object`);
  }
  const repository = {};
  for (const [name, implementation] of Object.entries(implementations)) {
    if (!allowed.has(name)) throw new TypeError(`${kind} repository method is not an admitted non-SQL method: ${name}`);
    if (typeof implementation !== 'function') throw new TypeError(`${kind}.${name} must be a function`);
    repository[name] = async (...args) => {
      const record = { sequence: calls.length + 1, repository: kind, method: name,
        args: snapshot(args), status: 'pending' };
      calls.push(record);
      try {
        const result = await implementation({ state, calls }, ...args);
        record.status = 'fulfilled';
        record.result = snapshot(result);
        return result;
      } catch (error) {
        record.status = 'rejected';
        record.error = Object.freeze({ name: error?.name || 'Error', code: error?.code || null,
          message: String(error?.message || error) });
        throw error;
      } finally {
        Object.freeze(record);
      }
    };
  }
  return Object.freeze(repository);
}

function cacheEntry(filename, exports) {
  return { id: filename, filename, loaded: true, exports, children: [], paths: [] };
}

function resolveFromRoot(relative) {
  if (typeof relative !== 'string' || !relative || path.isAbsolute(relative)) {
    throw new TypeError('loadFresh requires a non-empty repository-relative module path');
  }
  const resolved = require.resolve(path.join(ROOT, relative));
  if (!(resolved === ROOT || resolved.startsWith(ROOT + path.sep))) {
    throw new TypeError('loadFresh path escapes the repository');
  }
  return resolved;
}

async function withPostgresRepositoryDoubles(options, operation) {
  if (active) throw new Error('PostgreSQL repository-double scopes cannot overlap');
  if (!options || typeof options !== 'object' || typeof operation !== 'function') {
    throw new TypeError('Repository-double options and operation are required');
  }
  const calls = [];
  const commerceState = options.commerce?.state || {};
  const agentsState = options.agents?.state || {};
  const commerce = makeRepository('commerce', COMMERCE_METHODS, commerceState,
    options.commerce?.methods || {}, calls);
  const agents = makeRepository('agents', AGENTS_METHODS, agentsState,
    options.agents?.methods || {}, calls);
  active = true;
  const displaced = new Map();
  try {
    for (const [filename, entry] of Object.entries(require.cache)) {
      if (filename === COMMERCE_MODULE || filename === AGENTS_MODULE
        || EAGER_ROOTS.some(root => filename.startsWith(root))) {
        displaced.set(filename, entry);
        delete require.cache[filename];
      }
    }
    displaced.set(COMMERCE_MODULE, displaced.get(COMMERCE_MODULE) || null);
    displaced.set(AGENTS_MODULE, displaced.get(AGENTS_MODULE) || null);
    require.cache[COMMERCE_MODULE] = cacheEntry(COMMERCE_MODULE,
      { getSecureShopCommerceDb: () => commerce });
    require.cache[AGENTS_MODULE] = cacheEntry(AGENTS_MODULE,
      { getSecureShopAgentsDb: () => agents });
    const context = Object.freeze({
      commerce, agents, commerceState, agentsState, calls,
      loadFresh(relative) {
        const filename = resolveFromRoot(relative);
        delete require.cache[filename];
        return require(filename);
      },
    });
    return await operation(context);
  } finally {
    for (const filename of Object.keys(require.cache)) {
      if (filename === COMMERCE_MODULE || filename === AGENTS_MODULE
        || EAGER_ROOTS.some(root => filename.startsWith(root))) delete require.cache[filename];
    }
    for (const [filename, entry] of displaced) {
      if (entry) require.cache[filename] = entry;
    }
    active = false;
  }
}

module.exports = { withPostgresRepositoryDoubles };
