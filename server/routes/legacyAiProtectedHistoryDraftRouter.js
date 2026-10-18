'use strict';

const express = require('express');
const { projectLegacyAiExperimentResult } = require('../services/legacyAiExperimentPresenter');

const {
  createLegacyPlatformAuthorityResolver,
} = require('../services/legacyPlatformAuthorityResolver');

const DEFAULT_CONTEXT_STUFFING = 'A'.repeat(50000);
const MAX_CONTEXT_STUFFING_BYTES = 65536;
const MAX_MULTI_TURN_HISTORY_BYTES = 192 * 1024;

const POST_ROUTES = Object.freeze({
  '/prompt-injection': Object.freeze({
    sourceRoute: 'prompt_injection',
  }),
  '/chain-of-thought': Object.freeze({
    sourceRoute: 'chain_of_thought',
  }),
  '/context-stuffing': Object.freeze({
    sourceRoute: 'context_stuffing',
  }),
  '/multi-turn-jailbreak': Object.freeze({
    sourceRoute: 'multi_turn_jailbreak',
  }),
});

function badRequest(message = 'Invalid protected history request') {
  return Object.assign(new TypeError(message), { code: 'BAD_REQUEST' });
}

function requireDependencies({ identityAdapter, historyService, experimentAccess } = {}) {
  if (typeof experimentAccess !== 'function') throw new TypeError('Exercise availability middleware required');
  if (typeof identityAdapter?.validateSession !== 'function') {
    throw new TypeError('Identity adapter validateSession required');
  }
  if (typeof historyService?.runAuthenticated !== 'function'
      || typeof historyService?.runAnonymous !== 'function'
      || typeof historyService?.listOwner !== 'function'
      || typeof historyService?.listAdmin !== 'function') {
    throw new TypeError('Legacy AI history request service required');
  }
}

function requestBody(value) {
  if (!value || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) {
    throw badRequest();
  }
  return value;
}

function optionalString(body, key, maxBytes) {
  if (!Object.hasOwn(body, key) || body[key] === undefined) return undefined;
  if (typeof body[key] !== 'string' || Buffer.byteLength(body[key]) > maxBytes) {
    throw badRequest();
  }
  return body[key];
}

function optionsFor(sourceRoute, body) {
  if (sourceRoute === 'prompt_injection') {
    const model = optionalString(body, 'model', 256);
    return model === undefined ? {} : { model };
  }
  if (sourceRoute === 'chain_of_thought') {
    if (!Object.hasOwn(body, 'temperature') || body.temperature === undefined) return {};
    if (typeof body.temperature !== 'number' || !Number.isFinite(body.temperature)) {
      throw badRequest();
    }
    return { temperature: body.temperature };
  }
  if (sourceRoute === 'context_stuffing') {
    const stuffingContent = Object.hasOwn(body, 'stuffing_content')
      ? body.stuffing_content
      : DEFAULT_CONTEXT_STUFFING;
    if (typeof stuffingContent !== 'string'
        || Buffer.byteLength(stuffingContent) > MAX_CONTEXT_STUFFING_BYTES) {
      throw badRequest();
    }
    return { stuffing_content: stuffingContent };
  }
  if (sourceRoute === 'multi_turn_jailbreak') {
    const history = Object.hasOwn(body, 'conversation_history')
      ? body.conversation_history
      : [];
    if (!Array.isArray(history) || history.some(turn => !turn || Array.isArray(turn)
        || Object.getPrototypeOf(turn) !== Object.prototype
        || Object.keys(turn).some(key => !['user', 'assistant'].includes(key))
        || typeof turn.user !== 'string' || typeof turn.assistant !== 'string')
        || Buffer.byteLength(JSON.stringify(history)) > MAX_MULTI_TURN_HISTORY_BYTES) {
      throw badRequest();
    }
    return { conversation_history: history };
  }
  throw badRequest();
}

function pageFromQuery(query = {}) {
  const allowed = new Set(['limit', 'beforeCursor']);
  for (const key of Object.keys(query)) {
    if (!allowed.has(key)) throw badRequest('Invalid protected history page');
  }

  let limit = 100;
  if (query.limit !== undefined) {
    if (typeof query.limit !== 'string' || !/^[1-9][0-9]*$/.test(query.limit)) {
      throw badRequest('Invalid protected history page');
    }
    limit = Number(query.limit);
    if (!Number.isSafeInteger(limit) || limit > 200) throw badRequest('Invalid protected history page');
  }
  if (query.beforeCursor !== undefined && typeof query.beforeCursor !== 'string') {
    throw badRequest('Invalid protected history page');
  }
  return Object.freeze({ limit, beforeCursor: query.beforeCursor });
}

function successPayload(result, sourceRoute, authenticated) {
  if (!result || typeof result.response !== 'string') {
    throw badRequest('Invalid protected inference result');
  }
  if (Object.hasOwn(result, 'teaching')) {
    const projected = projectLegacyAiExperimentResult(result, { sourceRoute });
    const history = { persisted: false };
    if (authenticated) {
      if (typeof result.requestId !== 'string'
          || !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(result.requestId)
          || result.replayed !== false) {
        throw new Error('Invalid private history receipt');
      }
      history.persisted = true;
      history.requestId = result.requestId;
      history.replayed = false;
    }
    return Object.freeze({ response: projected.response, model: projected.modelUsed,
      provider: projected.provider, teaching: projected.teaching,
      creditAwarded: false, history: Object.freeze(history) });
  }
  const model = typeof result.model === 'string'
    ? result.model
    : (typeof result.modelUsed === 'string' ? result.modelUsed : undefined);
  return model === undefined
    ? Object.freeze({ response: result.response })
    : Object.freeze({ response: result.response, model });
}

function failureResponse(res, error, { write = false } = {}) {
  if (error?.statusCode === 401) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  if (error?.statusCode === 423) {
    return res.status(423).json({ error: 'Account unavailable' });
  }
  if (error?.code === 'BAD_REQUEST' || error?.code === '22023') {
    return res.status(400).json({ error: 'Invalid protected history request' });
  }
  if (error?.code === '42501') {
    return res.status(403).json({ error: 'Private history access denied' });
  }
  if (error?.code === '55000') {
    return res.status(write ? 409 : 401).json({
      error: write ? 'Protected history no longer accepts this result' : 'Authentication required',
    });
  }
  return res.status(503).json({ error: 'Protected history unavailable' });
}

// Draft-only and deliberately unmounted. Its success envelope preserves the
// live AI handlers' common response/model fields and strictly projected new
// experiment diagnostics. Legacy numeric conversation IDs and offline fallback
// text are not synthesized. Experiment results never imply durable credit.
// The stored prompt is the user prompt. It is never silently replaced with a
// provider-only context expansion. Fixed route options carry the normal legacy
// context-stuffing default and bounded multi-turn transport, while append
// persists only the submitted user prompt and inference response.
function createLegacyAiProtectedHistoryDraftRouter({ identityAdapter, historyService, experimentAccess } = {}) {
  requireDependencies({ identityAdapter, historyService, experimentAccess });
  const resolveAuthority = createLegacyPlatformAuthorityResolver(identityAdapter);
  const router = express.Router();
  const authorityKey = Symbol('protectedHistoryAuthority');
  const authenticateExperiment = async (req, res, next) => {
    try { req[authorityKey] = await resolveAuthority(req); return next(); }
    catch (error) { return failureResponse(res, error); }
  };

  for (const [path, definition] of Object.entries(POST_ROUTES)) {
    router.post(path, authenticateExperiment, experimentAccess, async (req, res) => {
      let authority;
      let body;
      const controller = new AbortController();
      const onClose = () => {
        if (!res.writableEnded) controller.abort(Object.assign(new Error('History client disconnected'), { code: 'CLIENT_DISCONNECTED' }));
      };
      res.once('close', onClose);
      if (req.aborted || res.destroyed) onClose();
      try {
        authority = req[authorityKey];
        body = requestBody(req.body);
        const input = {
          sourceRoute: definition.sourceRoute,
          prompt: body.prompt,
          options: optionsFor(definition.sourceRoute, body),
        };
        const result = authority
          ? await historyService.runAuthenticated({
            ...input,
            ownerId: authority.ownerId,
            sessionId: authority.sessionId,
          }, { signal: controller.signal })
          : await historyService.runAnonymous(input, { signal: controller.signal });
        return res.status(200).json(successPayload(result, definition.sourceRoute, Boolean(authority)));
      } catch (error) {
        if (res.destroyed) return;
        return failureResponse(res, error, { write: Boolean(authority) });
      } finally {
        res.removeListener('close', onClose);
      }
    });
  }

  router.get('/history', async (req, res) => {
    try {
      const authority = await resolveAuthority(req);
      if (!authority) return res.status(401).json({ error: 'Authentication required' });
      const page = pageFromQuery(req.query);
      const history = await historyService.listOwner({
        ownerId: authority.ownerId,
        sessionId: authority.sessionId,
        ...page,
      });
      return res.status(200).json({ history });
    } catch (error) {
      return failureResponse(res, error);
    }
  });

  router.get('/history/admin', async (req, res) => {
    try {
      const authority = await resolveAuthority(req);
      if (!authority) return res.status(401).json({ error: 'Authentication required' });
      const page = pageFromQuery(req.query);
      const history = await historyService.listAdmin({
        adminId: authority.ownerId,
        sessionId: authority.sessionId,
        ...page,
      });
      return res.status(200).json({ history });
    } catch (error) {
      return failureResponse(res, error);
    }
  });

  return router;
}

module.exports = {
  POST_ROUTES,
  createLegacyAiProtectedHistoryDraftRouter,
};
