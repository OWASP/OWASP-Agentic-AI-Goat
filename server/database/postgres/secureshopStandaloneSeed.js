'use strict';
const crypto = require('node:crypto');
const bcrypt = require('bcryptjs');

// Synthetic local teaching accounts, independent of all workshop identities.
const DEFAULTS = Object.freeze(['customer', 'merchant', 'admin'].map(role => Object.freeze({
  username: `student_${role}`, email: `student_${role}@secureshop.local`, role,
})));
const DEFAULTS_SHA256 = crypto.createHash('sha256')
  .update(JSON.stringify({ version: 1, accounts: DEFAULTS, password: 'student123' })).digest('hex');

async function seedSecureShopStandaloneDefaults(pool, {
  repository = require('./secureshopStandaloneAuthRepository').createSecureShopStandaloneAuthRepository({ pool }),
  hashPassword = password => bcrypt.hash(password, 12),
  randomUUID = crypto.randomUUID,
} = {}) {
  const principals = await Promise.all(DEFAULTS.map(async entry => ({ ...entry,
    principalId: randomUUID(), passwordHash: await hashPassword('student123'),
  })));
  // The repository performs this batch and its durable marker atomically.
  // A completed marker prevents deleted defaults from returning on reseed.
  return repository.seedDefaultsOnce({ defaultsSha256: DEFAULTS_SHA256, principals });
}

module.exports = { seedSecureShopStandaloneDefaults, DEFAULTS, DEFAULTS_SHA256 };
