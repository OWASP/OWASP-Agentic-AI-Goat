'use strict';

const { createHash } = require('node:crypto');
const bcrypt = require('bcryptjs');
const { createLaunchScope } = require('./secureshopConversationBinding');
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const BCRYPT12 = /^\$2[aby]\$12\$[./A-Za-z0-9]{53}$/;
const failure = (code, message) => Object.assign(new Error(message), { code });

function registrationInput(input) {
  const invalid = () => { throw failure('SHOP_REGISTRATION_INVALID', 'Invalid shop registration'); };
  if (!input || typeof input.username !== 'string' || typeof input.email !== 'string'
    || typeof input.password !== 'string' || typeof input.requestId !== 'string' || !UUID.test(input.requestId)) invalid();
  const username = input.username.trim().toLowerCase();
  const email = input.email.trim().toLowerCase();
  const role = input.role ?? 'customer';
  const full_name = input.full_name == null || input.full_name === '' ? null : input.full_name;
  if (!/^[a-z][a-z0-9_.-]{2,63}$/.test(username) || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)
    || Buffer.byteLength(email) > 254 || /[\x00-\x1f\x7f]/.test(email)
    || !['customer', 'merchant'].includes(role)
    || Buffer.byteLength(input.password) < 8 || Buffer.byteLength(input.password) > 72
    || input.password.includes('\0')
    || (full_name !== null && (typeof full_name !== 'string' || Buffer.byteLength(full_name) > 256
      || /[\x00-\x1f\x7f]/.test(full_name)))) invalid();
  const metadataSha256 = createHash('sha256').update(JSON.stringify([
    'owned-persona-registration-v1', username, email, role, full_name,
  ])).digest('hex');
  return Object.freeze({ scope: createLaunchScope(input.scope), requestId: input.requestId.toLowerCase(),
    username, email, role, full_name, metadataSha256 });
}

function createSecureShopBoundRegistration({ repository, launches, login,
  hashPassword = bcrypt.hash, comparePassword = bcrypt.compare } = {}) {
  if (typeof repository?.findRequest !== 'function' || typeof repository?.register !== 'function'
    || typeof launches?.assertCurrent !== 'function' || typeof login !== 'function'
    || typeof hashPassword !== 'function' || typeof comparePassword !== 'function') {
    throw new TypeError('Owned shop registration dependencies required');
  }
  return Object.freeze({
    async register(input) {
      const admitted = registrationInput(input);
      await launches.assertCurrent(admitted.scope);
      let identity = await repository.findRequest(admitted.scope, admitted.requestId);
      if (identity && identity.metadataSha256 !== admitted.metadataSha256) {
        throw failure('SHOP_REGISTRATION_CONFLICT', 'Registration request conflicts with an existing request');
      }
      if (!identity) {
        const passwordHash = await hashPassword(input.password, 12);
        if (typeof passwordHash !== 'string' || !BCRYPT12.test(passwordHash)) {
          throw failure('SHOP_REGISTRATION_UNAVAILABLE', 'Shop registration unavailable');
        }
        await launches.assertCurrent(admitted.scope);
        identity = await repository.register({ ...admitted, passwordHash });
      }
      // Exact request replay does not prove possession of its original password.
      // Compare bcrypt after insert too: a concurrent replay may have won first.
      if (!await comparePassword(input.password, identity.passwordHash)) {
        throw failure('SHOP_REGISTRATION_CONFLICT', 'Registration request conflicts with an existing request');
      }
      await launches.assertCurrent(admitted.scope);
      const authenticated = await login({ scope: admitted.scope, username: admitted.username,
        password: input.password, ip: input.ip ?? null, userAgent: input.userAgent ?? null });
      await launches.assertCurrent(admitted.scope);
      if (!authenticated || authenticated.ok !== true || !authenticated.token
        || authenticated.user?.id !== identity.id || authenticated.user?.username !== identity.username) {
        throw failure('SHOP_REGISTRATION_UNAVAILABLE', 'Created shop account could not be authenticated');
      }
      return Object.freeze({ ...authenticated, registrationRequestId: admitted.requestId });
    },
  });
}

module.exports = { createSecureShopBoundRegistration, registrationInput };
