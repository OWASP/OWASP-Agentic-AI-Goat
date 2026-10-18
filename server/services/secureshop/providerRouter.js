class ProviderRouter {
  constructor({ ollama, anthropic, openai, bedrock, mock }) {
    this.providers = { ollama, anthropic, openai, bedrock, mock };
    this.capabilities=Object.freeze({pricingFinalDecision:true,decisionRoutingV1:true,
      idorFinalAnswerContract:true});
  }

  _order() {
    const override = (process.env.AI_PROVIDER || '').toLowerCase();
    if (override && this.providers[override]) {
      return [override, 'ollama', 'anthropic', 'openai', 'bedrock', 'mock']
        .filter((v, i, a) => a.indexOf(v) === i)
        .filter(name => this.providers[name]);
    }
    return ['ollama', 'anthropic', 'openai', 'bedrock', 'mock'].filter(name => this.providers[name]);
  }

  async selectProvider() {
    for (const name of this._order()) {
      const p = this.providers[name];
      if (!p) continue;
      let reachable = false;
      try { reachable = await p.isReachable(); } catch { reachable = false; }
      if (reachable) return p;
    }
    // If nothing reachable, return mock as absolute last resort
    return this.providers.mock;
  }

  async chat(args) {
    const pinned=args.pricingProviderIdentity;
    if(pinned&&(!args.pricingFinalDecision||typeof pinned.provider!=='string'||typeof pinned.model!=='string'))throw Object.assign(new Error('Invalid typed Pricing provider identity'),{code:'SECURESHOP_PRICING_FINAL_UNSUPPORTED'});
    const order = pinned?[pinned.provider]:this._order();
    let lastErr;
    for (const name of order) {
      const p = this.providers[name];
      if (!p){if(pinned)throw Object.assign(new Error('Typed Pricing provider unavailable'),{code:'SECURESHOP_PRICING_FINAL_UNSUPPORTED'});continue;}
      if(pinned&&(p?.config?.model||p?.model||p?.modelId||null)!==pinned.model)throw Object.assign(new Error('Typed Pricing model unavailable'),{code:'SECURESHOP_PRICING_FINAL_UNSUPPORTED'});
      let reachable = false;
      args.signal?.throwIfAborted();
      try { reachable = await p.isReachable({ signal: args.signal }); } catch (error) {
        args.signal?.throwIfAborted();
        reachable = false;
      }
      args.signal?.throwIfAborted();
      if (!reachable){if(pinned)throw Object.assign(new Error('Typed Pricing provider unavailable'),{code:'SECURESHOP_PRICING_FINAL_UNSUPPORTED'});continue;}
      if(args.pricingFinalDecision!==undefined&&p.capabilities?.pricingFinalDecision!==true)throw Object.assign(new Error(`${name} typed Pricing final decision unavailable`),{code:'SECURESHOP_PRICING_FINAL_UNSUPPORTED'});
      try {
        const result = await p.chat(args);
        const configuredModel = p?.config?.model || p?.model || p?.modelId || null;
        // Attribution comes from the provider instance that actually returned,
        // not from the requested order. Keep the provider response otherwise
        // untouched, including raw text and tool arguments.
        return { ...result, provider: name, model: configuredModel, mocked: name === 'mock' || result.mocked === true };
      } catch (e) {
        args.signal?.throwIfAborted();
        if(args.pricingFinalDecision!==undefined)throw e;
        lastErr = e;
      }
    }
    throw lastErr || new Error('no provider available');
  }

  async routeWorkflow(args) {
    const { parseWorkflowRoute } = require('../../agent-runtime/providers/workflowRouteContract');
    for (const name of this._order()) {
      const provider = this.providers[name];
      args.signal?.throwIfAborted();
      let reachable = false;
      try { reachable = await provider.isReachable({ signal: args.signal }); }
      catch { args.signal?.throwIfAborted(); }
      args.signal?.throwIfAborted();
      if (!reachable) continue;
      const identity = { provider: name,
        model: provider?.config?.model || provider?.model || provider?.modelId || (name === 'mock' ? 'mock' : null),
        mocked: name === 'mock' };
      if (provider.capabilities?.decisionRoutingV1 !== true || typeof provider.routeWorkflow !== 'function') {
        throw Object.assign(new Error(`${name} workflow routing unavailable`), { code: 'SECURESHOP_ROUTE_UNSUPPORTED', ...identity });
      }
      // Once a provider is selected, routing failure is observable. Do not
      // replace a failed or malformed decision with a different model's route.
      let result;
      try { result = await provider.routeWorkflow(args); }
      catch (error) {
        try {
          Object.assign(error, identity);
        } catch { /* Preserve immutable provider failures. */ }
        throw error;
      }
      if (args.signal?.aborted) {
        const error = args.signal.reason instanceof Error ? args.signal.reason : new DOMException('Aborted', 'AbortError');
        try { Object.assign(error, identity, { usage: result?.usage }); } catch { /* Preserve cancellation. */ }
        throw error;
      }
      const decision = parseWorkflowRoute(result?.decision);
      if (result?.responseMode !== 'decision_routing_v1' || !decision
          || result.tool_uses !== undefined || result.stop_reason !== undefined || result.text !== undefined) {
        throw Object.assign(new Error('Invalid workflow routing response'),
          { code: 'SECURESHOP_INVALID_DECISION', usage: result?.usage, ...identity });
      }
      return { ...result, decision, provider: name,
        model: provider?.config?.model || provider?.model || provider?.modelId || (name === 'mock' ? 'mock' : null),
        mocked: name === 'mock' || result.mocked === true };
    }
    throw Object.assign(new Error('Workflow routing provider unavailable'), { code: 'SECURESHOP_ROUTE_UNSUPPORTED' });
  }

  async finalResponse(args) {
    if(args.pricingFinalDecision!==undefined||args.pricingProviderIdentity!==undefined)throw Object.assign(new Error('Typed Pricing answer-only final capability unsupported'),{code:'SECURESHOP_PRICING_FINAL_UNSUPPORTED'});
    if(args.idorFinalAnswerContract!==undefined
      && !require('../secureshopIdorFinalAnswerContract').isIdorFinalAnswerContract(args.idorFinalAnswerContract))
      throw Object.assign(new Error('Owned lesson final contract required'),{code:'SECURESHOP_FINAL_RESPONSE_UNSUPPORTED'});
    const order = this._order();
    for (const name of order) {
      const p = this.providers[name];
      if (!p) continue;
      args.signal?.throwIfAborted();
      let reachable = false;
      try { reachable = await p.isReachable({ signal: args.signal }); } catch {
        args.signal?.throwIfAborted(); reachable = false;
      }
      args.signal?.throwIfAborted();
      if (!reachable) continue;
      if(args.idorFinalAnswerContract!==undefined&&p.capabilities?.idorFinalAnswerContract!==true)
        throw Object.assign(new Error(`${name} lesson final response capability unavailable`),{
          code:'SECURESHOP_FINAL_RESPONSE_UNSUPPORTED'});
      if (typeof p.finalResponse !== 'function') {
        throw Object.assign(new Error(`${name} final response capability unavailable`), {
          code: 'SECURESHOP_FINAL_RESPONSE_UNSUPPORTED',
        });
      }
      const result = await p.finalResponse(args);
      args.signal?.throwIfAborted();
      if (result?.responseMode !== 'structured_final') {
        throw Object.assign(new Error(`${name} returned an invalid final response mode`), {
          code: 'SECURESHOP_INVALID_DECISION',
        });
      }
      const configuredModel = p?.config?.model || p?.model || p?.modelId || null;
      return { ...result, provider: name, model: configuredModel, mocked: name === 'mock' || result.mocked === true };
    }
    throw Object.assign(new Error('no provider supports structured final responses'), {
      code: 'SECURESHOP_FINAL_RESPONSE_UNSUPPORTED',
    });
  }
}

module.exports = { ProviderRouter };
