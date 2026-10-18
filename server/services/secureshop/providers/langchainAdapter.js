'use strict';
const { createLangChainProvider } = require('../../../agent-runtime/providers/langchainProvider');
const wireName = name => String(name).replace('.', '__');
const toolName = name => String(name).replace('__', '.');

class LangChainAdapter {
  constructor(config, dependencies) {
    this.config = config;
    this.capabilities = Object.freeze({ decisionRoutingV1: true });
    this.transport = createLangChainProvider(config, dependencies);
  }
  async chat({ system, messages = [], tools = [], max_tokens, signal, ownerId, pricingFinalDecision }) {
    if(pricingFinalDecision!==undefined)throw Object.assign(new Error('Typed Pricing final decision unsupported'),{code:'SECURESHOP_PRICING_FINAL_UNSUPPORTED'});
    const history = messages.map(message => ({ ...message,
      ...(message.tool_calls ? { tool_calls: message.tool_calls.map(call => ({ ...call,
        function: { ...call.function, name: wireName(call.function.name) },
      })) } : {}),
    }));
    if (system) history.unshift({ role: 'system', content: system });
    const schemas = tools.map(tool => ({ type: 'function', function: {
      name: wireName(`${tool.agent}.${tool.tool}`), description: tool.description || '',
      parameters: tool.inputSchema && Object.keys(tool.inputSchema).length
        ? tool.inputSchema : { type: 'object', properties: {} },
    } }));
    let result;
    try {
      result = await this.transport.chat(history, schemas, { max_tokens: max_tokens || 2048, signal, ownerId });
    } catch (cause) {
      signal?.throwIfAborted();
      const status = cause.status || cause.$metadata?.httpStatusCode;
      const error = new Error(`${this.config.provider} ${status ? `HTTP ${status}` : 'request failed'}`);
      error.status = status;
      error.retryable = status === 429 || status >= 500;
      throw error;
    }
    if (result.tool_calls?.length) return { stop_reason: 'tool_use', tool_uses: result.tool_calls.map(call => ({
      id: call.id, name: toolName(call.function.name), args: call.function.arguments,
    })) };
    return { stop_reason: 'end_turn', text: result.response };
  }
  async routeWorkflow({ system, messages = [], max_tokens, signal, ownerId }) {
    const { parseWorkflowRoute } = require('../../../agent-runtime/providers/workflowRouteContract');
    signal?.throwIfAborted();
    if (typeof this.transport?.routeWorkflow !== 'function') throw Object.assign(
      new Error('Workflow routing capability unavailable'), { code: 'SECURESHOP_ROUTE_UNSUPPORTED' });
    const result = await this.transport.routeWorkflow([
      { role: 'system', content: `${system || ''}\nSelect only a workflow or ask a clarification question. This decision cannot invoke a tool or answer from unobserved data.` },
      ...messages,
    ], { max_tokens, signal, ownerId });
    if (signal?.aborted) {
      const error = signal.reason instanceof Error ? signal.reason : new DOMException('Aborted', 'AbortError');
      try { error.usage = result?.usage; } catch { /* Preserve cancellation. */ }
      throw error;
    }
    const decision = parseWorkflowRoute(result?.decision);
    if (!decision || result.mocked === true || result.fallback === true) throw Object.assign(
      new Error('Invalid workflow routing decision'), { code: 'SECURESHOP_INVALID_DECISION', usage: result?.usage });
    return { responseMode: 'decision_routing_v1', decision,
      provider: this.config.provider, model: this.config.model, mocked: false, usage: result.usage };
  }

  async finalResponse({ system, messages = [], max_tokens, signal, ownerId,pricingFinalDecision,pricingProviderIdentity }) {
    if(pricingFinalDecision!==undefined||pricingProviderIdentity!==undefined)throw Object.assign(new Error('Typed Pricing final decision unsupported'),{code:'SECURESHOP_PRICING_FINAL_UNSUPPORTED'});
    const history = messages.map(message => ({ ...message,
      ...(message.tool_calls ? { tool_calls: message.tool_calls.map(call => ({ ...call,
        function: { ...call.function, name: wireName(call.function.name) },
      })) } : {}),
    }));
    if (system) history.unshift({ role: 'system', content: system });
    let result;
    try {
      if (typeof this.transport?.finalResponse !== 'function') {
        throw Object.assign(new Error('Structured final response transport unavailable'), {
          code: 'SECURESHOP_FINAL_RESPONSE_UNSUPPORTED',
        });
      }
      result = await this.transport.finalResponse(history, { max_tokens: max_tokens || 2048, signal, ownerId });
    } catch (cause) {
      signal?.throwIfAborted();
      const status = cause.status || cause.$metadata?.httpStatusCode;
      const error = new Error(`${this.config.provider} ${status ? `HTTP ${status}` : 'structured final response failed'}`);
      error.status = status;
      error.retryable = status === 429 || status >= 500;
      error.code = ['SECURESHOP_FINAL_RESPONSE_UNSUPPORTED', 'SECURESHOP_INVALID_DECISION'].includes(cause?.code)
        ? cause.code : undefined;
      throw error;
    }
    if (typeof result?.response !== 'string' || !result.response.trim()
        || result.mocked === true || result.fallback === true) {
      throw Object.assign(new Error(`${this.config.provider} returned an invalid structured final response`), {
        code: 'SECURESHOP_INVALID_DECISION',
      });
    }
    return { provider: this.config.provider, model: this.config.model, mocked: false,
      stop_reason: 'end_turn', text: result.response, responseMode: 'structured_final',
      usage: result.usage || null };
  }
}
module.exports = { LangChainAdapter };
