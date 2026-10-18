class MockProvider {
  constructor() {
    this.capabilities = Object.freeze({ decisionRoutingV1: true });
    this._steps = [];
    this._roleSteps = new Map();
    this._unexpected = 0;
  }

  script(steps) {
    this._steps = [...steps];
  }

  scriptFor(role, steps) {
    this._roleSteps.set(role, [...steps]);
  }

  reset() {
    this._steps = [];
    this._roleSteps.clear();
    this._unexpected = 0;
  }

  getUnexpectedCallCount() {
    return this._unexpected;
  }

  async isReachable() { return true; }

  _takeStep(role) {
    let step;
    if (role && this._roleSteps.get(role) && this._roleSteps.get(role).length) {
      step = this._roleSteps.get(role).shift();
    } else if (this._steps.length) {
      step = this._steps.shift();
    } else {
      this._unexpected++;
      return null;
    }
    return step;
  }

  async chat({ messages, tools, role, pricingFinalDecision } = {}) {
    if(pricingFinalDecision!==undefined)throw Object.assign(new Error('Typed Pricing final decision unsupported'),{code:'SECURESHOP_PRICING_FINAL_UNSUPPORTED'});
    const step = this._takeStep(role);
    if (!step) return { stop_reason: 'end_turn', text: '[mock: no scripted response]' };

    if (step.stop === 'tool_use') {
      return {
        stop_reason: 'tool_use',
        tool_uses: (step.tool_uses || []).map((t, i) => ({
          id: t.id || `mock_${Date.now()}_${i}`,
          name: t.name,
          args: t.args,
        })),
      };
    }

    if (step.stop === 'end_turn') {
      return { stop_reason: 'end_turn', text: step.text || '' };
    }

    if (step.stop === 'end_turn_reactive') {
      const msgs = messages || [];
      const lastTool = [...msgs].reverse().find(m => m.role === 'tool');
      const content = lastTool ? (typeof lastTool.content === 'string' ? lastTool.content : JSON.stringify(lastTool.content)) : '';
      const text = step.textMatcher ? step.textMatcher(content) : '';
      return { stop_reason: 'end_turn', text };
    }

    return { stop_reason: 'end_turn', text: '[mock: unknown step]' };
  }

  async routeWorkflow({ role, signal } = {}) {
    signal?.throwIfAborted();
    const step = this._takeStep(role);
    const decision = step?.stop === 'route'
      ? require('../../../agent-runtime/providers/workflowRouteContract').parseWorkflowRoute(step.decision) : null;
    if (!decision) throw Object.assign(new Error('Scripted workflow route unavailable'), { code: 'SECURESHOP_INVALID_DECISION' });
    return { responseMode: 'decision_routing_v1', decision, mocked: true,
      provider: 'mock', model: 'mock',
      usage: Object.freeze({ inputTokens: null, outputTokens: null, totalTokens: null, attempts: 1 }) };
  }

  async finalResponse({ messages, role,pricingFinalDecision,pricingProviderIdentity } = {}) {
    if(pricingFinalDecision!==undefined||pricingProviderIdentity!==undefined)throw Object.assign(new Error('Typed Pricing final decision unsupported'),{code:'SECURESHOP_PRICING_FINAL_UNSUPPORTED'});
    const step = this._takeStep(role);
    let text;
    if (step?.stop === 'end_turn') text = step.text || '';
    else if (step?.stop === 'end_turn_reactive') {
      const lastTool = [...(messages || [])].reverse().find(message => message.role === 'tool');
      const content = lastTool ? (typeof lastTool.content === 'string'
        ? lastTool.content : JSON.stringify(lastTool.content)) : '';
      text = step.textMatcher ? step.textMatcher(content) : '';
    }
    if (typeof text !== 'string' || !text.trim()) {
      throw Object.assign(new Error('Mock structured final response unavailable'), {
        code: 'SECURESHOP_INVALID_DECISION',
      });
    }
    return { stop_reason: 'end_turn', text, responseMode: 'structured_final', mocked: true,
      usage: Object.freeze({ inputTokens: null, outputTokens: null, totalTokens: null, attempts: 1 }) };
  }
}

module.exports = { MockProvider };
