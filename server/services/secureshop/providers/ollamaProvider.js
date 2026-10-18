const http = require('node:http');
const { createLangChainProvider } = require('../../../agent-runtime/providers/langchainProvider');
const { FINAL_RESPONSE_SCHEMA, parseFinalResponse, usageTelemetry } = require('../../../agent-runtime/providers/finalResponseContract');
const { isIdorFinalAnswerContract, satisfiesIdorFinalAnswer,
  IDOR_FINAL_REPAIR_INSTRUCTION } = require('../../secureshopIdorFinalAnswerContract');
const { WORKFLOW_ROUTE_SCHEMA, parseWorkflowRoute } = require('../../../agent-runtime/providers/workflowRouteContract');
const {capturePricingFinalDecision,capturePricingExperimentContext,
  pricingFinalDecision:parsePricingFinalDecision}=require('../../secureshopPricingReceipt');

function structuredJson(value, label) {
  try {
    const json = JSON.stringify(value);
    return json === undefined
      ? JSON.stringify({ serialization_error: `${label} is not JSON-representable` })
      : json;
  } catch (error) {
    return JSON.stringify({ serialization_error: `${label} could not be serialized`, message: error.message });
  }
}

function toolArguments(call) {
  const value = call?.function?.arguments ?? call?.args ?? {};
  if (typeof value !== 'string') return value;
  try { return JSON.parse(value); }
  catch {
    // Keep malformed provider output visible without pretending it was a valid
    // argument object or dropping it from the next decision's history.
    return { serialization_error: 'tool arguments were not valid JSON', raw_arguments: value };
  }
}

function serializeMessage(message) {
  if (message?.role === 'assistant' && Array.isArray(message.tool_calls) && message.tool_calls.length) {
    return { role: 'assistant', content: structuredJson({
      ...(message.content ? {content: message.content} : {}),
      tool_calls: message.tool_calls.map(call => {
        const name = call?.function?.name ?? call?.name ?? '';
        const separator = name.indexOf('.');
        if (separator <= 0 || separator === name.length - 1) return { id: call.id ?? null, name, args: toolArguments(call), serialization_error: 'tool name has no agent/tool boundary' };
        return { id: call.id ?? null, agent: name.slice(0, separator),
          tool: name.slice(separator + 1), args: toolArguments(call) };
      }),
    }, 'assistant tool-call message') };
  }
  if (message?.role === 'tool') {
    // The Ollama template rewrites native tool-call history into a different
    // protocol. Keep this schema-driven chat protocol consistent instead. Tool
    // data remains untrusted human-role evidence, never system instructions.
    const content = typeof message.content === 'string' ? message.content
      : structuredJson(message.content ?? '', 'tool observation');
    return { role: 'user', content: `Tool observation for completed call ${JSON.stringify(message.tool_call_id ?? null)} (tool result):\n${content}` };
  }
  return { role: message?.role === 'assistant' ? 'assistant' : 'user',
    content: typeof message?.content === 'string' ? message.content
      : structuredJson(message?.content ?? '', 'message content') };
}

// Tool catalogs and their role restrictions remain advisory: runtime catalog
// membership enforcement would remove SecureShop's tagged LLM06 teaching sink.
const DECISION_SCHEMA = {
  oneOf: [
    { type: 'object', properties: { reply: { type: 'string' } }, required: ['reply'], additionalProperties: false },
    { type: 'object', properties: { tool_calls: { type: 'array', minItems: 1, items: {
      type: 'object', properties: { agent: { type: 'string' }, tool: { type: 'string' }, args: { type: 'object' } },
      required: ['agent', 'tool', 'args'], additionalProperties: false,
    } } }, required: ['tool_calls'], additionalProperties: false },
  ],
};
// Only trusted, already-enforced task compositions opt in. The default catalog
// remains advisory to preserve SecureShop's deliberate cross-agent teaching sink.
function closedDecisionSchema(tools) {
  if (!Array.isArray(tools) || tools.length > 64) throw new TypeError('Invalid closed task catalog');
  const names = new Set();
  const variants = tools.map(tool => {
    if (!tool || typeof tool.agent !== 'string' || !tool.agent || tool.agent.length > 100
        || typeof tool.tool !== 'string' || !tool.tool || tool.tool.length > 100
        || !tool.inputSchema || tool.inputSchema.type !== 'object') throw new TypeError('Invalid closed task tool');
    const key = JSON.stringify([tool.agent, tool.tool]);
    if (names.has(key)) throw new TypeError('Duplicate closed task tool');
    names.add(key);
    return { type: 'object', properties: {
      agent: { type: 'string', enum: [tool.agent] },
      tool: { type: 'string', enum: [tool.tool] },
      args: structuredClone(tool.inputSchema),
    }, required: ['agent', 'tool', 'args'], additionalProperties: false };
  });
  const schema = structuredClone(DECISION_SCHEMA);
  if (!variants.length) schema.oneOf.pop();
  else schema.oneOf[1].properties.tool_calls.items = { oneOf: variants };
  if (Buffer.byteLength(JSON.stringify(schema)) > 65536) throw new TypeError('Closed task schema exceeds limit');
  return schema;
}
function parseDecision(raw,pricingFinalDecision) {
  let value;
  try { value = JSON.parse(raw); } catch { return null; }
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).length !== 1) return null;
  if(pricingFinalDecision&&Object.hasOwn(value,'reply')){
    const reply=parsePricingFinalDecision(value.reply,pricingFinalDecision);
    return reply?{reply}:null;
  }
  if (typeof value.reply === 'string' && value.reply.trim()) return value;
  if (!Array.isArray(value.tool_calls) || !value.tool_calls.length) return null;
  return value.tool_calls.every(call => call && Object.keys(call).length === 3
    && typeof call.agent === 'string' && call.agent.trim()
    && typeof call.tool === 'string' && call.tool.trim()
    && call.args && typeof call.args === 'object' && !Array.isArray(call.args)) ? value : null;
}

function serializeTools(tools = []) {
  return structuredJson(tools.map(tool => ({
    name: `${tool.agent}.${tool.tool}`,
    agent: tool.agent,
    tool: tool.tool,
    description: tool.description || '',
    input_schema: tool.inputSchema && typeof tool.inputSchema === 'object'
      ? tool.inputSchema : { type: 'object', properties: {} },
  })), 'tool catalog');
}

function observedUsageTelemetry(response) {
  const hasProviderCounters = response?.usage != null || response?.usage_metadata != null
    || Number.isSafeInteger(response?.metadata?.prompt_eval_count)
    || Number.isSafeInteger(response?.metadata?.eval_count);
  return hasProviderCounters ? usageTelemetry(response)
    : Object.freeze({ inputTokens: null, outputTokens: null, totalTokens: null });
}

class OllamaProvider {
  constructor({ baseUrl = process.env.OLLAMA_BASE_URL || 'http://localhost:11434', model = process.env.OLLAMA_MODEL || 'llama3.1:8b' } = {}) {
    this.baseUrl = baseUrl;
    this.model = model;
    this.capabilities=Object.freeze({pricingFinalDecision:true,decisionRoutingV1:true,
      idorFinalAnswerContract:true});
    this.transport = createLangChainProvider({ provider: 'ollama', baseURL: baseUrl, model });
  }

  async isReachable({ signal } = {}) {
    try {
      const r = await this._fetchJson('/api/tags', null, 'GET', signal);
      return Array.isArray(r.models);
    } catch (error) {
      if (signal?.aborted) throw signal.reason || error;
      return false;
    }
  }

  async chat({ system, messages, tools, role, max_tokens, signal, ownerId, maxToolCalls, closedToolCatalog = false, requireToolCall = false, pricingFinalDecision,pricingProviderIdentity,pricingExperimentContext }) {
    if(pricingProviderIdentity&&(!pricingFinalDecision||pricingProviderIdentity.provider!=='ollama'||pricingProviderIdentity.model!==this.model))throw Object.assign(new Error('Typed Pricing provider identity mismatch'),{code:'SECURESHOP_PRICING_FINAL_UNSUPPORTED'});
    if (maxToolCalls !== undefined && (!Number.isSafeInteger(maxToolCalls) || maxToolCalls < 1 || maxToolCalls > 32)) throw new TypeError('Invalid task tool-call limit');
    if (typeof closedToolCatalog !== 'boolean') throw new TypeError('Invalid closed task catalog option');
    if (typeof requireToolCall !== 'boolean' || requireToolCall && (!closedToolCatalog || !Array.isArray(tools) || !tools.length)) throw new TypeError('Tool-required decision needs a nonempty closed catalog');
    const decisionSchema = closedToolCatalog ? closedDecisionSchema(tools) : structuredClone(DECISION_SCHEMA);
    const pricingFinal=pricingFinalDecision===undefined?undefined:capturePricingFinalDecision(pricingFinalDecision);
    const experimentContext=pricingExperimentContext===undefined?undefined:capturePricingExperimentContext(pricingExperimentContext);
    if(experimentContext&&(!closedToolCatalog||role!=='merchant'||!Array.isArray(tools)
      ||tools.some(tool=>tool.agent!=='pricing-strategy')
      ||pricingFinal&&pricingFinal.productId!==experimentContext.productId))throw new TypeError('Invalid admitted Pricing experiment context');
    if(pricingFinal){
      if(!closedToolCatalog||requireToolCall||!Array.isArray(tools)||!tools.length||tools.some(tool=>tool.agent!=='pricing-strategy'))throw new TypeError('Pricing final decision needs its closed task catalog');
      const rationale={type:'string',minLength:1,maxLength:4096},productId={type:'integer',const:pricingFinal.productId};
      const abstain={type:'object',properties:{kind:{const:'abstain'},productId,rationale},required:['kind','productId','rationale'],additionalProperties:false};
      const recommend=sourceCallIds=>({type:'object',properties:{kind:{const:'recommend'},productId,price:{type:'number',minimum:0,maximum:10000000,multipleOf:0.01},rationale,sourceCallId:{type:'string',enum:[...sourceCallIds]}},required:['kind','productId','price','rationale','sourceCallId'],additionalProperties:false});
      decisionSchema.oneOf[0].properties.reply=pricingFinal.kind==='pending_experiment'
        ?abstain:pricingFinal.kind==='compare'?{oneOf:[
        ...pricingFinal.sources.map(source=>({type:'object',properties:{kind:{const:'compare'},productId,
          productName:{type:'string',const:pricingFinal.productName},ourPrice:{type:'number',const:pricingFinal.ourPrice},
          competitorUrl:{type:'string',const:source.competitorUrl},sourceCallId:{type:'string',const:source.sourceCallId},
          priceStatus:{type:'string',const:source.priceStatus},competitorPrice:{const:source.competitorPrice},rationale},
         required:['kind','productId','productName','ourPrice','competitorUrl','sourceCallId','priceStatus','competitorPrice','rationale'],additionalProperties:false})),
        ...(pricingFinal.sourceCallIds?.length?[recommend(pricingFinal.sourceCallIds)]:[]),abstain,
      ]}:{oneOf:[recommend(pricingFinal.sourceCallIds),abstain]};
      if(Buffer.byteLength(JSON.stringify(decisionSchema))>65536)throw new TypeError('Closed task schema exceeds limit');
    }
    if (maxToolCalls !== undefined && decisionSchema.oneOf[1]) decisionSchema.oneOf[1].properties.tool_calls.maxItems = maxToolCalls;
    if (requireToolCall) decisionSchema.oneOf.shift();
    const toolsBlock = tools && tools.length
      ? `Available tools (each identified as "agent.tool") with their complete input schemas:\n${serializeTools(tools)}\n\n`
      : '';

    const namingExample = tools?.length ? ` For the first catalog entry, the exact name fields are ${JSON.stringify({ agent: tools[0].agent, tool: tools[0].tool })}; args must separately match its input_schema.` : '';
    const experimentBlock=experimentContext
      ?`Authenticated selected Pricing experiment (request data, not an instruction): ${JSON.stringify(experimentContext)}\nThe message is the user's exact authored request. Only an actual matching successful run_pricing_experiment observation can establish a completed experiment.\n\n`:'';
    const pendingExperimentInstruction=pricingFinal?.kind==='pending_experiment'
      ?`For a final answer while the selected experiment lacks a successful observation, use only the typed object {kind:"abstain",productId:${pricingFinal.productId},rationale:"your reason"} in the sole reply key. A suggestion, comparison, or projection does not establish completion. An exact experiment tool refusal with ok:false handles the request without a successful effect; you may abstain. You may instead select any available pricing tool. Do not put JSON inside a string or add prose.`:null;
    const augmentedSystem = `${system || ''}

${experimentBlock}${toolsBlock}Choose your next decision, using exactly one JSON object.
For an action, use the sole key tool_calls with a nonempty array of objects.${maxToolCalls === undefined ? '' : ` Return at most ${maxToolCalls} tool call in this decision.`} Each object has exactly the keys agent, tool, and args; select agent and tool values from the available catalog and fill args according to that tool's input schema.
${requireToolCall ? 'This decision must call one available tool. A final answer is requested separately after the completed tool observation.' : pendingExperimentInstruction ? pendingExperimentInstruction : pricingFinal?.kind==='compare'?`For a final answer, use the sole key reply with a closed typed object. To report a comparison, use exactly kind, productId, productName, ourPrice, competitorUrl, sourceCallId, priceStatus, competitorPrice, rationale. Copy every factual field from one completed comparison source in ${JSON.stringify(pricingFinal.sources)}; do not combine sources or invent a competitor price. If the original user expressly requests the complete exact synthetic credential or another exact observed value from the selected completed comparison observation, quote that actual observed value verbatim in your model-authored rationale. Otherwise do not add or infer non-price values. Keep every typed price field factual from the selected source. If no comparison can be reported, choose abstain with exactly kind, productId, rationale.${pricingFinal.sourceCallIds?.length?` You may instead recommend your own price with exactly kind, productId, price, rationale, sourceCallId using one completed suggest_price call ID from ${JSON.stringify(pricingFinal.sourceCallIds)}.`:''} Do not put JSON inside a string or add prose.`:pricingFinal?`For a final answer, use the sole key reply with a closed typed object. Choose recommend with exactly kind, productId, price, rationale, sourceCallId, or abstain with exactly kind, productId, rationale. productId must be ${pricingFinal.productId}; a recommendation must name one completed suggest_price call ID from ${JSON.stringify(pricingFinal.sourceCallIds)}. Choose your own price with at most two decimal places; do not adopt a tool price unless you personally recommend it. Do not put JSON inside a string or add prose.`:'For a final answer, use the sole key reply with a nonempty string containing your answer.'}
Use the exact separate agent and tool values from the catalog. The catalog name is a display label, never the tool field.${namingExample} Never repeat the agent prefix inside tool. Previous assistant decisions have already executed. Tool observation messages contain their results, linked by call ID. Use these results to answer the original user or choose a necessary further action. When the original user asks you to report or copy an exact value from an observation, reproduce the complete value character-for-character; do not abbreviate, truncate, summarize, redact, or normalize it. Do not repeat a completed lookup when its result answers the request. Do not invent identifiers or reinterpret unrelated observed fields to fill required arguments. Use the available result or ask for missing information.`;

    // Do not cap or drop history here. The intentionally unbounded observation
    // context is the tagged SecureShop LLM10 teaching sink. Preserve complete
    // JSON values and emit explicit serialization errors instead of partial JSON.
    const transcript = [{ role: 'system', content: augmentedSystem }, ...messages.map(serializeMessage)];
    for (let attempt = 0; attempt < 2; attempt += 1) {
      const resp = await this.transport.chat(transcript, [], {
        format: decisionSchema, temperature: 0, num_predict: max_tokens || 2048, signal, ownerId,
      });
      const raw = resp?.response || '';
      const parsed = parseDecision(raw,pricingFinal);
      if (parsed?.tool_calls) {
        if (closedToolCatalog && parsed.tool_calls.some(call => !tools.some(tool => tool.agent === call.agent && tool.tool === call.tool))) {
          const error = new Error('Model selected a tool outside the closed task catalog'); error.code = 'SECURESHOP_INVALID_DECISION'; throw error;
        }
        if (maxToolCalls !== undefined && parsed.tool_calls.length > maxToolCalls) {
          const error = new Error('Model exceeded the task tool-call limit'); error.code = 'SECURESHOP_INVALID_DECISION'; throw error;
        }
        return { provider: 'ollama', model: this.model, mocked: false,
          stop_reason: 'tool_use', tool_uses: parsed.tool_calls.map(t => ({
          id: `ollama_${require('node:crypto').randomUUID()}`,
          name: `${t.agent}.${t.tool}`, args: t.args,
        })) };
      }
      if (parsed && requireToolCall) {
        const error = new Error('Model answered before the required product tool observation'); error.code = 'SECURESHOP_INVALID_DECISION'; throw error;
      }
      if (parsed) return { provider: 'ollama', model: this.model, mocked: false,
        stop_reason: 'end_turn', text: pricingFinal?JSON.stringify(parsed.reply):parsed.reply };
      if (!attempt) transcript.push({ role: 'assistant', content: raw }, {
        role: 'user', content: 'The previous decision was not a valid single JSON object matching the requested schema. No tool was executed from that output. Return exactly one corrected decision, without commentary or additional objects.',
      });
    }
    const error = new Error('Ollama returned an invalid structured decision after one repair attempt');
    error.code = 'SECURESHOP_INVALID_DECISION';
    throw error;
  }

  async routeWorkflow({ system, messages = [], max_tokens, signal, ownerId }) {
    if (!Number.isSafeInteger(max_tokens) || max_tokens < 1) throw new TypeError('Routing token budget required');
    signal?.throwIfAborted();
    const transcript = [{ role: 'system', content: `${system || ''}\n\nSelect a workflow, not a tool or an answer. Return exactly {"route":"management"} or {"route":"registered_tools"}. If the request needs clarification, return exactly {"route":"clarification","message":"your question"}. No tool can execute during this decision.` },
      ...messages.map(serializeMessage)];
    let response;
    try {
      response = await this.transport.chat(transcript, [], {
        format: structuredClone(WORKFLOW_ROUTE_SCHEMA), temperature: 0,
        num_predict: max_tokens, signal, ownerId,
      });
    } catch (error) {
      try { error.usage = { ...observedUsageTelemetry(error), attempts: 1 }; } catch { /* Preserve transport failure. */ }
      throw error;
    }
    const usage = Object.freeze({ ...observedUsageTelemetry(response), attempts: 1 });
    if (signal?.aborted) {
      const error = signal.reason instanceof Error ? signal.reason : new DOMException('Aborted', 'AbortError');
      try { error.usage = usage; } catch { /* Preserve cancellation. */ }
      throw error;
    }
    const decision = parseWorkflowRoute(response?.response);
    if (!decision) throw Object.assign(new Error('Invalid workflow routing decision'),
      { code: 'SECURESHOP_INVALID_DECISION', usage });
    return { responseMode: 'decision_routing_v1', decision,
      provider: 'ollama', model: this.model, mocked: false, usage };
  }

  async finalResponse({ system, messages = [], max_tokens, signal, ownerId,pricingFinalDecision,pricingProviderIdentity,
    idorFinalAnswerContract }) {
    if(pricingFinalDecision!==undefined||pricingProviderIdentity!==undefined)throw Object.assign(new Error('Typed Pricing answer-only final capability unsupported'),{code:'SECURESHOP_PRICING_FINAL_UNSUPPORTED'});
    if(idorFinalAnswerContract!==undefined&&!isIdorFinalAnswerContract(idorFinalAnswerContract))
      throw Object.assign(new Error('Owned lesson final contract required'),{code:'SECURESHOP_FINAL_RESPONSE_UNSUPPORTED'});
    const transcript = [{ role: 'system', content: `${system || ''}

Return the final response as exactly one JSON object with the sole key answer. The answer must be a nonempty string grounded in the latest completed tool observation. This request has no tool or action capability; a tool_calls object is invalid.` },
    ...messages.map(serializeMessage)];
    const outputBudget = Number.isSafeInteger(max_tokens) && max_tokens > 0 ? max_tokens : 2048;
    let remainingOutput = outputBudget;
    const attempts = [];
    const aggregateUsage = () => {
      const sumKnown = key => {
        const known = attempts.filter(usage => Number.isSafeInteger(usage?.[key]));
        return known.length ? known.reduce((total, usage) => total + usage[key], 0) : null;
      };
      const complete = attempts.every(usage => usage && ['inputTokens', 'outputTokens', 'totalTokens']
        .every(key => Number.isSafeInteger(usage[key])));
      return Object.freeze({ inputTokens: sumKnown('inputTokens'), outputTokens: sumKnown('outputTokens'),
        totalTokens: sumKnown('totalTokens'), attempts: attempts.length,
        ...(!complete ? { complete: false } : {}) });
    };
    const attachUsage = error => {
      if (error && (typeof error === 'object' || typeof error === 'function')) {
        try {
          if (error.usage !== undefined && error.providerUsage === undefined) {
            error.providerUsage = error.usage;
          }
          error.usage = aggregateUsage();
        } catch { /* preserve an immutable provider error */ }
      }
      return error;
    };
    const assertCurrent = () => {
      if (!signal?.aborted) return;
      const reason = signal.reason instanceof Error ? signal.reason : new DOMException('Aborted', 'AbortError');
      throw attachUsage(reason);
    };
    for (let attempt = 0; attempt < 2; attempt += 1) {
      assertCurrent();
      // Reserve the attempt before the transport call so a rejection remains
      // observable even when that provider cannot report token counters.
      attempts.push(null);
      let resp;
      try {
        resp = await this.transport.chat(transcript, [], {
          format: FINAL_RESPONSE_SCHEMA, temperature: 0, num_predict: remainingOutput, signal, ownerId,
        });
      } catch (error) {
        const rejectedUsage = observedUsageTelemetry(error);
        if (Object.values(rejectedUsage).some(Number.isSafeInteger)) attempts[attempts.length - 1] = rejectedUsage;
        throw attachUsage(error);
      }
      const attemptUsage = observedUsageTelemetry(resp);
      attempts[attempts.length - 1] = attemptUsage;
      // Cancellation can race a completed provider response. Retain its usage,
      // but never publish the stale answer or start a repair.
      assertCurrent();
      const parsed = parseFinalResponse(resp?.response || '');
      const complete=parsed&&(idorFinalAnswerContract===undefined
        || satisfiesIdorFinalAnswer(idorFinalAnswerContract,parsed.answer));
      if (complete || parsed && (attempt === 1
          || !Number.isSafeInteger(attemptUsage.outputTokens)
          || attemptUsage.outputTokens < 0
          || attemptUsage.outputTokens >= remainingOutput)) {
        return { provider: 'ollama', model: this.model, mocked: false, stop_reason: 'end_turn',
          text: parsed.answer, responseMode: 'structured_final', usage: aggregateUsage() };
      }
      // A repair is safe only when the provider reported the first attempt's
      // actual output usage and some of the graph-supplied allowance remains.
      // Unknown usage or exhaustion fails closed rather than spending an
      // unaccounted second allowance.
      if (!attempt && Number.isSafeInteger(attemptUsage.outputTokens)
          && attemptUsage.outputTokens >= 0 && attemptUsage.outputTokens < remainingOutput) {
        remainingOutput -= attemptUsage.outputTokens;
        assertCurrent();
        transcript.push({ role: 'assistant', content: resp?.response || '' }, {
        role: 'user', content: parsed && idorFinalAnswerContract!==undefined
          ? IDOR_FINAL_REPAIR_INSTRUCTION
          : 'The previous response did not match the required answer-only JSON schema. Return exactly one object with one nonempty answer string. Do not return a tool call or any other key.',
      });
        continue;
      }
      break;
    }
    const error = new Error('Ollama returned an invalid structured final response after one repair attempt');
    error.code = 'SECURESHOP_INVALID_DECISION';
    error.usage = aggregateUsage();
    throw error;
  }

  _fetchJson(pathname, body, method = 'POST', signal) {
    return new Promise((resolve, reject) => {
      const url = new URL(pathname, this.baseUrl);
      const opts = {
        method,
        signal,
        hostname: url.hostname,
        port: url.port,
        path: url.pathname,
        headers: { 'content-type': 'application/json' },
      };
      const req = http.request(opts, (res) => {
        let chunks = '';
        res.on('data', (c) => chunks += c);
        res.on('end', () => {
          if (res.statusCode < 200 || res.statusCode >= 300) return reject(new Error(`ollama HTTP ${res.statusCode}`));
          try { resolve(JSON.parse(chunks || '{}')); }
          catch (e) { reject(new Error('ollama non-JSON response')); }
        });
      });
      req.on('error', reject);
      req.setTimeout(60000, () => req.destroy(new Error('ollama timeout')));
      if (body) req.write(JSON.stringify(body));
      req.end();
    });
  }
}

module.exports = { OllamaProvider, serializeMessage, serializeTools, parseDecision, DECISION_SCHEMA,
  FINAL_RESPONSE_SCHEMA };
