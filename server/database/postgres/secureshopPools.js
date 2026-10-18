'use strict';

// One pool per challenge database per process, shared by all seventeen tools.
// These roles/databases are isolated from platform identity and workshops.
const { createPool } = require('./index');
let commercePool;
let agentsPool;
function getCommercePool() {
  return commercePool ||= createPool(process.env, 'SECURESHOP_DATABASE_URL');
}
function getAgentsPool() {
  return agentsPool ||= createPool(process.env, 'SECURESHOP_AGENTS_DATABASE_URL');
}
async function closeSecureShopPools() {
  const closing = [commercePool, agentsPool].filter(Boolean);
  commercePool = undefined;
  agentsPool = undefined;
  const outcomes = await Promise.allSettled(closing.map(pool => pool.end()));
  const errors = outcomes.filter(item => item.status === 'rejected').map(item => item.reason);
  if (errors.length) throw new AggregateError(errors, 'Failed to close SecureShop PostgreSQL pools');
}
module.exports = { getCommercePool, getAgentsPool, closeSecureShopPools };
