'use strict';

const express = require('express');
const {
  SUPPORTED_TARGETS,
  normalizePolicyName,
  normalizePolicyTargets,
  normalizeRenderRequest,
} = require('../../services/secureshopPromptPolicyContract');
const {
  normalizeTaskMutationRequest,
} = require('../../services/secureshopPromptPolicyTaskMutation');
const { RECIPIENTS } = require('../../services/secureshopPromptPolicyTaskSnapshot');

const TASK_TARGETS = Object.freeze(['summarizer', 'review-moderator', 'listing']);

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const VERSION = /^[1-9][0-9]{0,18}$/;
const MAX_INT64 = 9223372036854775807n;
const fail = code => Object.assign(new Error('Bound prompt policies unavailable'), { code });

function exactBody(req, keys) {
  return req.is('application/json') && req.body && typeof req.body === 'object'
    && !Array.isArray(req.body)
    && Object.keys(req.body).sort().join(',') === [...keys].sort().join(',');
}

function version(value) {
  if (typeof value !== 'string' || !VERSION.test(value) || BigInt(value) > MAX_INT64) {
    throw fail('INVALID_ARGUMENT');
  }
  return value;
}

function operationId(value) {
  if (typeof value !== 'string' || !UUID.test(value)) throw fail('INVALID_ARGUMENT');
  return value.toLowerCase();
}

function configuredTaskTargets(value) {
  if (!Array.isArray(value) || new Set(value).size !== value.length
      || value.some(target => !TASK_TARGETS.includes(target))) {
    throw new TypeError('Bound prompt policy task targets invalid');
  }
  return Object.freeze([...value].sort());
}

function request(name, markdown, targets, id, supportedTaskTargets) {
  try {
    const normalizedId = operationId(id);
    const normalizedName = normalizePolicyName(name);
    const allowed = new Set([...SUPPORTED_TARGETS, ...supportedTaskTargets]);
    if (!Array.isArray(targets) || targets.some(target => !allowed.has(target))) throw fail('INVALID_ARGUMENT');
    if (targets.some(target => supportedTaskTargets.includes(target))) {
      return normalizeTaskMutationRequest({
        contractVersion: 2,
        operationId: normalizedId,
        name: normalizedName,
        markdown,
        targets,
      });
    }
    return normalizeRenderRequest({
      operationId: normalizedId,
      name: normalizedName,
      markdown,
      targets: normalizePolicyTargets(targets),
    });
  } catch (error) {
    if (!error.code) error.code = 'INVALID_ARGUMENT';
    throw error;
  }
}

function policyName(value) {
  try { return normalizePolicyName(value); } catch (error) {
    if (!error.code) error.code = 'INVALID_ARGUMENT';
    throw error;
  }
}

function context(req) {
  return Object.freeze({
    scope: req.ssLaunch,
    persona: Object.freeze({ id: req.ssUser.id, role: req.ssUser.role }),
    personaSession: Object.freeze({
      sessionId: req.ssPersonaSession.sessionId,
      authorityVersion: req.ssPersonaSession.authorityVersion,
    }),
  });
}

function mapPolicies(value, supportedTaskTargets) {
  if (!value || !Array.isArray(value.policies) || typeof value.version !== 'string'
      || !VERSION.test(value.version) || BigInt(value.version) > MAX_INT64) {
    throw fail('POLICY_RESULT_INVALID');
  }
  // Retained policy rows remain readable when editable capabilities narrow.
  // The request() write path above still accepts only configured targets.
  const allowed = new Set([...SUPPORTED_TARGETS, ...Object.keys(RECIPIENTS)]);
  return {
    ok: true,
    version: value.version,
    ...(value.administration ? { administration: value.administration } : {}),
    supported_targets: [...SUPPORTED_TARGETS],
    ...(supportedTaskTargets.length ? { supported_task_targets: [...supportedTaskTargets] } : {}),
    policies: value.policies.map(policy => {
      if (!policy || typeof policy !== 'object') throw fail('POLICY_RESULT_INVALID');
      if (!Array.isArray(policy.targets) || policy.targets.length === 0
          || new Set(policy.targets).size !== policy.targets.length
          || policy.targets.some(target => !allowed.has(target))) throw fail('POLICY_RESULT_INVALID');
      const targets = [...policy.targets].sort();
      return {
        ...(policy.id === undefined ? {} : { id: policy.id }),
        name: (() => {
          try { return normalizePolicyName(policy.name); }
          catch { throw fail('POLICY_RESULT_INVALID'); }
        })(),
        markdown_source: policy.markdown,
        markdown_rendered: policy.rendered,
        injected_into_json: JSON.stringify(targets),
        supported_targets: [...SUPPORTED_TARGETS],
        ...(supportedTaskTargets.length ? { supported_task_targets: [...supportedTaskTargets] } : {}),
        ...(policy.version === undefined ? {} : { policy_version: policy.version }),
        ...(policy.updated_at === undefined ? {} : { updated_at: policy.updated_at }),
      };
    }),
  };
}

function completed(value) {
  const receipt = value?.receipt || value;
  const renderResult = receipt?.renderResult || value?.renderResult;
  if (!receipt || !renderResult || typeof renderResult.rendered !== 'string') throw fail('POLICY_RESULT_INVALID');
  return {
    ok: true,
    receipt,
    rendered: renderResult.rendered,
    rendered_length: Buffer.byteLength(renderResult.rendered, 'utf8'),
  };
}

function createBoundPromptPoliciesRouter({ service, authenticatePersona, supportedTaskTargets = [] } = {}) {
  if (typeof authenticatePersona !== 'function'
      || ['list', 'render', 'remove', 'operation'].some(name => typeof service?.[name] !== 'function')) {
    throw new TypeError('Bound prompt policy route dependencies required');
  }
  const taskTargets = configuredTaskTargets(supportedTaskTargets);
  const router = express.Router();
  router.use('/admin/policies', (req, res, next) => {
    res.set('Cache-Control', 'no-store');
    next();
  });
  const guarded = [authenticatePersona, (req, res, next) => {
    if (!req.ssLaunch || !req.ssPersonaSession?.sessionId) return res.status(401).json({ error: 'Shop authentication required' });
    if (req.ssUser?.role !== 'admin') return res.status(403).json({ error: 'Shop admin required' });
    return next();
  }];
  const handle = work => async (req, res) => {
    try { return await work(req, res); } catch (error) {
      const code = error?.code;
      let status = 503;
      if (['SHOP_AUTH_INVALID', 'STALE_AUTHORITY', 'SESSION_UNAVAILABLE'].includes(code)) status = 401;
      else if (code === 'ADMIN_REQUIRED') status = 403;
      else if (['REVISION_CONFLICT', 'OPERATION_CONFLICT'].includes(code)) status = 409;
      else if (['POLICY_NOT_FOUND', 'RESET_OPERATION_NOT_FOUND'].includes(code)) status = 404;
      else if (code === 'POLICY_QUOTA_EXCEEDED') status = 429;
      else if (['INVALID_ARGUMENT', 'INVALID_INPUT'].includes(code)) status = 400;
      const body = { error: status === 409 ? 'Bound prompt policy conflict' : 'Bound prompt policy unavailable' };
      if (code === 'POLICY_RENDER_BUSY') { body.code = code; res.set('Retry-After', '1'); }
      else if (['POLICY_OUTCOME_UNCERTAIN', 'POLICY_RECEIPT_OUTCOME_UNCERTAIN', 'PERSONA_EFFECT_OUTCOME_UNCERTAIN'].includes(code)) body.code = code;
      else if ([409, 429].includes(status)) body.code = code;
      return res.status(status).json(body);
    }
  };
  router.get('/admin/policies', ...guarded, handle(async (req, res) => {
    if (Object.keys(req.query).length) return res.status(400).json({ error: 'Invalid policy request' });
    return res.json(mapPolicies(await service.list(context(req)), taskTargets));
  }));
  router.get('/admin/policies/operations/:operationId', ...guarded, handle(async (req, res) => {
    if (Object.keys(req.query).length || !UUID.test(req.params.operationId)) return res.status(400).json({ error: 'Invalid policy operation' });
    const value = await service.operation({ ...context(req), operationId: operationId(req.params.operationId) });
    if (!value) return res.status(404).json({ error: 'Operation not observed' });
    if (value.state === 'pending') return res.status(202).json({ ok: false, state: 'pending', operationId: value.operationId });
    return res.json({ ok: true, receipt: value });
  }));
  router.post('/admin/policies', ...guarded, handle(async (req, res) => {
    if (Object.keys(req.query).length || !exactBody(req, ['name', 'markdown', 'injected_into', 'operationId', 'expectedVersion'])) return res.status(400).json({ error: 'Invalid policy request' });
    const body = req.body;
    const value = await service.render({ ...context(req), action: 'upsert', expectedVersion: version(body.expectedVersion), request: request(body.name, body.markdown, body.injected_into, body.operationId, taskTargets) });
    if (value?.state === 'pending') return res.status(202).json({ ok: false, state: 'pending', operationId: value.operationId });
    return res.json(completed(value));
  }));
  router.post('/admin/policies/:name/render', ...guarded, handle(async (req, res) => {
    if (Object.keys(req.query).length || !exactBody(req, ['markdown', 'injected_into', 'operationId', 'expectedVersion'])) return res.status(400).json({ error: 'Invalid policy render request' });
    const body = req.body;
    const value = await service.render({ ...context(req), action: 'preview', expectedVersion: version(body.expectedVersion), request: request(req.params.name, body.markdown, body.injected_into, body.operationId, taskTargets) });
    if (value?.state === 'pending') return res.status(202).json({ ok: false, state: 'pending', operationId: value.operationId });
    return res.json(completed(value));
  }));
  router.post('/admin/policies/:name', ...guarded, handle(async (req, res) => {
    if (Object.keys(req.query).length || !exactBody(req, ['markdown', 'injected_into', 'operationId', 'expectedVersion'])) return res.status(400).json({ error: 'Invalid policy request' });
    const body = req.body;
    const value = await service.render({ ...context(req), action: 'upsert', expectedVersion: version(body.expectedVersion), request: request(req.params.name, body.markdown, body.injected_into, body.operationId, taskTargets) });
    if (value?.state === 'pending') return res.status(202).json({ ok: false, state: 'pending', operationId: value.operationId });
    return res.json(completed(value));
  }));
  router.delete('/admin/policies/:name', ...guarded, handle(async (req, res) => {
    if (Object.keys(req.query).length || !exactBody(req, ['operationId', 'expectedVersion'])) return res.status(400).json({ error: 'Invalid policy delete request' });
    const body = req.body;
    const value = await service.remove({ ...context(req), name: policyName(req.params.name), operationId: operationId(body.operationId), expectedVersion: version(body.expectedVersion) });
    return res.json({ ok: true, receipt: value });
  }));
  return router;
}

module.exports = { createBoundPromptPoliciesRouter };
