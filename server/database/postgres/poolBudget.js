'use strict';

const DEFAULTS = Object.freeze({ control: 8, workshop: 2, lease: 4, provision: 1, teaching: 2, protected: 2, migration: 1 });

function integer(env, name, fallback, max = 100) {
  const raw = env[name];
  if (raw === undefined || raw === '') return fallback;
  if (!/^\d+$/.test(String(raw)) || Number(raw) < 1 || Number(raw) > max) {
    throw new Error(`${name} must be an integer from 1 to ${max}`);
  }
  return Number(raw);
}

function poolBudget(env, key, purpose) {
  purpose ||= /MIGRATION/.test(key) ? 'migration'
    : key === 'IDENTITY_DATABASE_URL' ? 'control' : 'workshop';
  if (!Object.hasOwn(DEFAULTS, purpose)) throw new Error('Unknown PostgreSQL pool purpose');
  const budget = integer(env, 'PG_POOL_BUDGET', 78);
  // One provisioning connection serializes advisory waiters before they can
  // occupy the control pool that the advisory holder needs for nested work.
  const max = integer(env, `PG_POOL_MAX_${purpose.toUpperCase()}`, DEFAULTS[purpose],
    purpose === 'provision' ? 1 : 100);
  if (max > budget) throw new Error('PostgreSQL pool exceeds process connection budget');
  return { purpose, max, budget };
}

module.exports = { DEFAULTS, poolBudget };
