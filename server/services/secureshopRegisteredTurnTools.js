'use strict';
const { randomUUID } = require('node:crypto');
const C = require('./secureshopOwnedMcpInvocationContract');
const { currentEffectAdmission } = require('../agent-runtime/effectAdmissionContext');
const protocol = require('../../sidecars/sandbox-runner/owned-mcp-registry/invoke-protocol');
const denied = () => Object.assign(new Error('Registered tool invocation unavailable'),
  { code: 'MCP_REGISTRY_INVOCATION_DENIED', executionBoundary: true, automaticRetry: false });

const STATUS_TOOL = C.freeze({ agent: 'registry', tool: 'status',
  description: 'Read counts of owned registered tools and their approval availability. This does not approve or invoke tools.',
  inputSchema: { type: 'object', properties: {}, additionalProperties: false } });
// Descriptive schema annotations are registry content, not assistant instructions.
// Preserve property names and validation constraints, including literal enums.
function schemaForModel(schema) {
  if (Array.isArray(schema)) return schema.map(schemaForModel);
  if (!schema || typeof schema !== 'object') return schema;
  const annotations = ['description', 'title', '$comment', 'examples', 'default'];
  const maps = ['properties', 'patternProperties', '$defs', 'definitions', 'dependentSchemas', 'dependencies'];
  const children = ['items', 'additionalItems', 'additionalProperties', 'contains', 'propertyNames',
    'not', 'if', 'then', 'else', 'allOf', 'anyOf', 'oneOf', 'prefixItems',
    'unevaluatedItems', 'unevaluatedProperties'];
  return Object.fromEntries(Object.entries(schema).filter(([key]) => !annotations.includes(key))
    .map(([key, value]) => [key, maps.includes(key)
      ? Object.fromEntries(Object.entries(value).map(([name, child]) => [name, schemaForModel(child)]))
      : children.includes(key) ? schemaForModel(value) : value]));
}

// A single immutable snapshot supplies both the model manifest and dispatcher.
// The supplied dispatch must durably admit and settle the remote operation; a
// raw HTTP client is deliberately not a production composition for this seam.
async function createRegisteredTurnTools({ snapshots, binding, execution, requestId,
  mode, instanceId, readApproval, dispatch, makeId = randomUUID } = {}) {
  if (typeof snapshots?.read !== 'function' || typeof snapshots?.withCurrentEntry !== 'function'
      || typeof execution?.check !== 'function' || typeof dispatch !== 'function'
      || typeof readApproval !== 'function' || !['vuln', 'fixed'].includes(mode)) throw denied();
  await execution.check();
  const entries = C.freeze(C.bounded(await snapshots.read(), 131072));
  await execution.check();
  const selected = new Map(), calls = new Set();
  const approvals = new Map();
  if (mode === 'fixed') {
    for (const entry of entries) {
      approvals.set(entry.entryId, (await readApproval(entry)) === true);
      await execution.check();
    }
  }
  const offeredEntries = entries.filter(entry => mode !== 'fixed' || approvals.get(entry.entryId));
  const tools = offeredEntries.flatMap(entry => entry.tools.map((tool, index) => {
    const agent = 'owned_' + entry.entryId.replaceAll('-', '');
    const alias = 'tool_' + index;
    selected.set(`${agent}.${alias}`, { entry, tool });
    return { agent, tool: alias, description: mode === 'fixed' ? 'Invoke this approved registered tool with its validated arguments.' : tool.description,
      inputSchema: mode === 'fixed' ? schemaForModel(tool.inputSchema) : tool.inputSchema,
      isExternalMcp: true };
  }));
  if (mode === 'fixed') tools.push(STATUS_TOOL);
  C.freeze(tools);
  // Optional private provenance, from the same immutable catalog used below.
  // This digest is not a claim that a provider received a particular wire body;
  // qualification must separately join its original serialized request.
  let descriptionCapture = null;
  try {
    const ids = new Set();
    const references = offeredEntries.map(entry => {
      if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(entry.entryId)
          || ids.has(entry.entryId) || typeof entry.registryVersion !== 'string'
          || !/^[1-9][0-9]{0,18}$/.test(entry.registryVersion)
          || BigInt(entry.registryVersion) > 9223372036854775807n
          || !/^[a-f0-9]{64}$/.test(entry.schemaSha256)) throw denied();
      ids.add(entry.entryId);
      return { entryId: entry.entryId, registryVersion: entry.registryVersion,
        schemaSha256: entry.schemaSha256 };
    });
    descriptionCapture = C.freeze(C.bounded({ version: 1, entries: references,
      manifestSha256: C.digest(tools) }, 65536));
  } catch {
    // Missing or oversized optional proof cannot invalidate ordinary execution.
    // A description assessment must treat absent capture as ineligible.
  }
  const manifest = Object.freeze({
    getForRole: role => role === 'admin' ? tools : Object.freeze([]),
    buildExternalMcpPromptBlock: () => mode === 'fixed' ? '' : tools.length ?
      // Preserve the existing registered-description prompt injection lesson.
      '\n## Additional MCP tools (registered via mcp-registry)\n'
        + tools.map(tool => `- ${tool.agent}.${tool.tool}: ${tool.description}`).join('\n') : '',
  });
  return Object.freeze({ manifest, descriptionCapture, async status(args) {
    if (mode !== 'fixed' || !args || typeof args !== 'object' || Array.isArray(args)
        || Object.keys(args).length) throw denied();
    await execution.check();
    const result = C.freeze({ registrationCount: entries.length,
      registeredToolCount: entries.reduce((sum, entry) => sum + entry.tools.length, 0),
      approvedRegistrationCount: [...approvals.values()].filter(Boolean).length,
      availableExternalToolCount: tools.filter(tool => tool.isExternalMcp).length,
      policy: 'Only approved registered tools are available; status does not approve or invoke them.' });
    await execution.check();
    return result;
  }, async callTool(agent, alias, args, context) {
    const chosen = selected.get(`${agent}.${alias}`);
    if (!chosen || typeof context?.callId !== 'string'
        || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(context.callId)
        || calls.has(context.callId) || calls.size >= 64) throw denied();
    calls.add(context.callId);
    const { name, ...entry } = chosen.entry;
    const request = C.freeze(protocol.request({ version: 1, instanceId, operationId: makeId(),
      entry, toolName: chosen.tool.name, args }));
    const effect = currentEffectAdmission(execution);
    await execution.check();
    const approval = await readApproval(chosen.entry);
    if (typeof approval !== 'boolean' || (mode === 'fixed' && !approval)) throw denied();
    await execution.check();
    // The dispatch owns durable admission before any network effect and exact
    // terminal drain before resolving. It calls withCurrentEntry for the held
    // registry/persona fence, without recursively acquiring persona locks.
    const raw = await dispatch(Object.freeze({ request, binding, execution, requestId,
      callId: context.callId, effect, mode, approved: approval, snapshots,
      entry: chosen.entry }));
    const receipt = C.freeze(protocol.receipt(raw, request));
    await execution.check();
    return C.freeze({ ...receipt.result, _meta: {
      ...receipt.result?._meta,
      ownedRegistryInvocation: { request, receipt, runId: execution.runId,
        effectKey: effect.ledgerEffectKey },
    } });
  } });
}
module.exports = { createRegisteredTurnTools };
