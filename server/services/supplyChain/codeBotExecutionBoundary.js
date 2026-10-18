'use strict';

const crypto = require('node:crypto');
const { OwnerWorkflowHttpError } = require('../../agent-runtime/ownerWorkflowHttpError');

const positive = value => Number.isSafeInteger(Number(value)) && Number(value) > 0;
const fail = (code, message) => { const error = new Error(message); error.code = code; throw error; };

function bearer(request) {
  const value = request?.headers?.authorization;
  if (typeof value !== 'string' || !/^Bearer [^\s]+$/.test(value)) {
    fail('CODEBOT_PLATFORM_SESSION_REQUIRED', 'A current platform bearer session is required');
  }
  return value.slice(7);
}

function createCodeBotRequestAuthority({ validateSession, postgres = true } = {}) {
  if (postgres && typeof validateSession !== 'function') throw new TypeError('validateSession is required');
  return Object.freeze({
    async resolve(request) {
      const token = bearer(request);
      if (!postgres) {
        if (!positive(request?.user?.id)) fail('CODEBOT_PLATFORM_SESSION_REQUIRED', 'Authenticated platform owner is required');
        return Object.freeze({ platformOwnerId: Number(request.user.id), platformSessionId: `legacy-${crypto.createHash('sha256').update(token).digest('hex').slice(0, 24)}`, assertCurrent: async () => true });
      }
      const found = await validateSession(token, request);
      const ownerId = Number(found?.user?.id), sessionId = Number(found?.session?.id);
      if (!positive(ownerId) || !positive(sessionId)) fail('CODEBOT_PLATFORM_SESSION_REQUIRED', 'The durable platform session is unavailable');
      if (Number(request?.user?.id) !== ownerId) fail('CODEBOT_PLATFORM_OWNER_MISMATCH', 'Authenticated platform owner changed');
      if (Number(request?.identitySession?.id) !== sessionId) fail('CODEBOT_PLATFORM_SESSION_MISMATCH', 'Authenticated platform session changed');
      const identity = { platformOwnerId: ownerId, platformSessionId: sessionId };
      Object.defineProperty(identity, 'assertCurrent', { enumerable: false, value: async () => {
        const current = await validateSession(token, request);
        if (Number(current?.user?.id) !== ownerId || Number(current?.session?.id) !== sessionId) {
          fail('CODEBOT_PLATFORM_SESSION_REQUIRED', 'The bound platform session is no longer current');
        }
        return true;
      } });
      return Object.freeze(identity);
    },
  });
}

function createCodeBotExecutionBoundary({ authority, runtime } = {}) {
  if (typeof authority?.resolve !== 'function' || typeof runtime?.executeTransform !== 'function') {
    throw new TypeError('CodeBot authority and sandbox runtime are required');
  }
  const effects = new WeakMap();
  return Object.freeze({
    resolveRequest: request => authority.resolve(request),
    bind(scope, run) {
      if (!positive(scope?.platformOwnerId) || scope.platformSessionId == null || typeof scope.assertCurrent !== 'function') {
        fail('CODEBOT_PLATFORM_SESSION_REQUIRED', 'Bound CodeBot session authority is required');
      }
      if (!run || typeof run.check !== 'function') fail('CODEBOT_RUN_REQUIRED', 'Owner run authority is required');
      const durable = typeof run.effectWithReceipt === 'function' && run.durableGeneration != null;
      const identity = Object.freeze({
        platformOwnerId: Number(scope.platformOwnerId), platformSessionId: String(scope.platformSessionId),
        ownerKey: run.ownerKey, generation: String(run.durableGeneration ?? run.generation), runId: run.runId,
      });
      const check = async () => {
        await run.check();
        try { await scope.assertCurrent(); }
        catch { throw new OwnerWorkflowHttpError(409, 'The CodeBot platform session is no longer current'); }
        await run.check();
      };
      const executeCodeBotTransform = async transform => {
        await check();
        if (!durable) {
          const value = await runtime.executeTransform({ scope: identity, transform, signal: run.signal });
          await check();
          return value;
        }
        // The coordinator prefixes this stable node with the session-scoped
        // Idempotency-Key (or run id). One request can attempt one transform;
        // changing the payload cannot evade replay protection.
        const completed = await run.effectWithReceipt('codebot-transform', async () => {
          await check();
          return runtime.executeTransform({ scope: identity, transform, signal: run.signal });
        });
        await check();
        const receipt = completed?.receipt;
        if (!receipt || receipt.status !== 'completed' || receipt.runId !== run.runId || receipt.ownerKey !== run.ownerKey
            || String(receipt.generation) !== String(run.durableGeneration)) {
          fail('CODEBOT_EFFECT_RECEIPT_INVALID', 'CodeBot sandbox effect receipt is unavailable');
        }
        if (completed.value && typeof completed.value === 'object') effects.set(completed.value, Object.freeze({ receipt, identity }));
        return completed.value;
      };
      const adoptCodeBotEffect = (source, target) => {
        const effect = source && typeof source === 'object' ? effects.get(source) : null;
        if (effect && target && typeof target === 'object') effects.set(target, effect);
        return target;
      };
      const verifyCodeBotEffect = value => {
        const effect = value && typeof value === 'object' ? effects.get(value) : null;
        return Boolean(effect && effect.identity === identity && effect.receipt.runId === identity.runId
          && effect.receipt.ownerKey === identity.ownerKey && String(effect.receipt.generation) === identity.generation);
      };
      return Object.freeze({ ...run, check, codeBotIdentity: identity, executeCodeBotTransform,
        adoptCodeBotEffect, verifyCodeBotEffect });
    },
  });
}

let configured;
function getConfiguredCodeBotExecutionBoundary() {
  if (configured) return configured;
  const postgres = process.env.PLATFORM_DATABASE_ENGINE === 'postgres';
  const validateSession = postgres
    ? (...args) => require('../postgresIdentityAdapter').getPostgresIdentityAdapter().validateSession(...args)
    : undefined;
  configured = createCodeBotExecutionBoundary({
    authority: createCodeBotRequestAuthority({ validateSession, postgres }),
    runtime: require('./codeBotSandboxRuntime'),
  });
  return configured;
}

module.exports = { createCodeBotRequestAuthority, createCodeBotExecutionBoundary, getConfiguredCodeBotExecutionBoundary,
  _internals: { bearer } };
