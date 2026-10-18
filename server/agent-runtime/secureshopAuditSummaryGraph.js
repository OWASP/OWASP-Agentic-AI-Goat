'use strict';
const { createSupervisorGraph } = require('./secureshopSupervisorGraph');
const { createSecureShopAuditExecutionConfig } = require('../services/secureshopAuditExecutionConfig');
const { isQualifiedSecureShopModelTrace } = require('../services/secureshopRealModelTrace');
const { validatePolicySnapshot } = require('../services/secureshopPromptPolicySnapshot');
const { validateAuditSummaryObservation } = require('../services/secureshopAuditSummaryObservation');
const { createAuditSummaryTaskPrompt } = require('../services/secureshopAuditSummaryTaskPrompt');

// Execution core for an owned audit job. Its host supplies private persistence,
// source/authority closures and effect receipts; none are model arguments.
function createSecureShopAuditSummaryGraph({ store, Trace, provider, qualifyModel, readObservation, admitTool,
  promptPolicySnapshot, taskRequestVersion = 1 } = {}) {
  if (!store || typeof Trace !== 'function' || typeof provider?.chat !== 'function'
      || typeof provider?.finalResponse !== 'function' || typeof qualifyModel !== 'function'
      || typeof readObservation !== 'function') throw new TypeError('Audit graph dependencies required');
  if (admitTool !== undefined && typeof admitTool !== 'function') throw new TypeError('Invalid audit policy admission');
  const config = createSecureShopAuditExecutionConfig({enableFocus:taskRequestVersion===2});
  createAuditSummaryTaskPrompt({ version: taskRequestVersion, requestedCount: 1 });
  const taskPrompt = requestedCount => createAuditSummaryTaskPrompt({ version: taskRequestVersion, requestedCount });
  const admittedPolicy = promptPolicySnapshot === undefined ? undefined : validatePolicySnapshot(promptPolicySnapshot);
  if (admittedPolicy && admittedPolicy.role !== 'admin') throw new TypeError('Audit administrator prompt policy required');
  const checkToolAcl = admitTool ? async (role, agent, tool, context) => {
    const base = await config.checkToolAcl(role, agent, tool);
    if (!base.allowed) return base;
    const admission = await admitTool(context);
    return { allowed: admission.allowed, enforcement: admission.enforcement, action: admission.action,
      policyViolation: admission.policyViolation, admission };
  } : config.checkToolAcl;
  const unavailable = () => Object.assign(new Error('Audit summary model evidence unavailable'), { code: 'AUDIT_SUMMARY_UNAVAILABLE' });
  return async function run({ sessionId, requestedCount, persona, check, effectWithReceipt, signal } = {}) {
    if (typeof sessionId !== 'string' || !sessionId || !Number.isSafeInteger(requestedCount) || requestedCount < 1
        || !Number.isSafeInteger(persona?.id) || persona.id < 1 || persona.role !== 'admin'
        || typeof check !== 'function' || typeof effectWithReceipt !== 'function') throw new TypeError('Bound administrator audit execution required');
    let accepted = null, finalIdentity = null;
    const verify = async () => { signal?.throwIfAborted(); await check(); signal?.throwIfAborted(); };
    const checked = method => async args => {
      await verify();
      // Only the witnessed unbounded task needs a compact final report. Keep
      // the full observation and decision budget; provider repairs share this
      // one allowance rather than receiving a second output budget.
      const input = method === 'finalResponse' && taskRequestVersion === 2
        ? { ...args, max_tokens: Math.min(args.max_tokens, 256) } : args;
      const result = await provider[method](input);
      await verify();
      if (!isQualifiedSecureShopModelTrace({ provider: result?.provider,
        result_json: JSON.stringify({ model: result?.model, mocked: result?.mocked, fallback: result?.fallback }),
        kind: 'model_decision', step: null }, qualifyModel)) throw unavailable();
      if (method === 'finalResponse') finalIdentity = Object.freeze({ provider: result.provider, model: result.model });
      return result;
    };
    const tool = 'audit.summarize_anomalies';
    const graph = createSupervisorGraph({ store, Trace, ...config, checkToolAcl,
      ...(admittedPolicy ? { buildBasePrompt: (role, options) => `${config.buildBasePrompt(role, { ...options, extra: '' })}\n\n${options.extra}` } : {}),
      ...(admittedPolicy ? { buildPolicyBlock: async role => {
        await verify();
        if (role !== 'admin') throw unavailable();
        const trace = new Trace(sessionId);
        trace.record({ step: 0, actor: 'supervisor', kind: 'prompt_policy_snapshot',
          result_json: JSON.stringify({ policyVersion: admittedPolicy.policyVersion, sha256: admittedPolicy.sha256,
            role: admittedPolicy.role, policyCount: admittedPolicy.policies.length }) });
        await trace.flush(); await verify();
        return admittedPolicy.text;
      } } : {}),
    });
    const result = await graph(sessionId, taskPrompt(requestedCount), {
      role: 'admin', callerRole: 'admin', callerId: persona.id, ownerId: sessionId,
      signal, check: verify, effectWithReceipt,
      provider: { chat: checked('chat'), finalResponse: checked('finalResponse') },
      manifest: config.manifest,
      pool: { async callTool() { throw unavailable(); } },
      localTools: new Map([[tool, async args => {
        const focused=Object.hasOwn(args||{},'focus_action');
        if (!args || Object.getPrototypeOf(args) !== Object.prototype
            || Object.keys(args).length !== (focused?2:1) || args.limit !== requestedCount
            ||(focused&&(taskRequestVersion!==2||typeof args.focus_action!=='string'||!/^[A-Za-z0-9_.:-]{1,100}$/.test(args.focus_action)))) {
          throw Object.assign(new Error('Audit arguments differ from requested snapshot'), { code: 'INVALID_TOOL_ARGUMENTS' });
        }
        await verify();
        const observation = await readObservation({ requestedCount, signal,
          ...(focused?{focusAction:args.focus_action}:{}) });
        await verify();
        try {
          const version=validateAuditSummaryObservation(observation, { requestedCount });
          if(focused?(version!==3||observation.focus.action!==args.focus_action):version===3)throw unavailable();
        }
        catch { throw unavailable(); }
        const text = JSON.stringify(observation);
        accepted = text;
        return { content: [{ type: 'text', text }] };
      }]]),
      shouldEnterFinalResponse(observation) {
        if (observation.result?.isError === true) return false;
        if (observation.tool !== tool || !accepted || observation.effectReceipt?.status !== 'completed'
            || observation.result?.content?.length !== 1 || observation.result.content[0]?.text !== accepted) throw unavailable();
        return true;
      },
    }, { maxSteps: 4, maxParallelTools: 1 });
    await verify();
    if (!accepted || !finalIdentity || result.stopReason !== 'end_turn' || !result.text?.trim()) throw unavailable();
    // Final narrative is model output, not a Judge verdict. Credit is separate.
    return Object.freeze({ summary: result.text, ...finalIdentity, steps: result.steps });
  };
}
module.exports = { createSecureShopAuditSummaryGraph };
