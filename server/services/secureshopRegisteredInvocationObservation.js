'use strict';
const C = require('./secureshopOwnedMcpInvocationContract');
const fail = () => Object.assign(new Error('Registered invocation evidence unavailable'),
  { code: 'MCP_REGISTRY_EVIDENCE_INVALID', executionBoundary: true });
function createRegisteredInvocationObserver({ journal } = {}) {
  if (typeof journal?.readCompleted !== 'function') throw new TypeError('Invocation journal required');
  return async function observe({ run, binding, requestId, observation }, fence) {
    const receipt = observation?.effectReceipt;
    const meta = observation?.result?._meta?.ownedRegistryInvocation;
    if (!meta || !receipt || receipt.version !== 1 || receipt.status !== 'completed'
        || receipt.runId !== run.runId || receipt.ownerKey !== run.ownerKey
        || receipt.generation !== String(run.durableGeneration)
        || meta.runId !== run.runId || meta.effectKey !== receipt.effectKey
        || typeof fence?.assertRemoteAdmission !== 'function') throw fail();
    await run.check(); await fence.assertRemoteAdmission();
    const stored = await journal.readCompleted({ scope: binding, invocationId: meta.request.operationId });
    const envelope = stored.envelope;
    const toolIndex = envelope.snapshot.tools.findIndex(tool => tool.name === envelope.request.toolName);
    const expectedTool = `owned_${envelope.request.entryId.replaceAll('-', '')}.tool_${toolIndex}`;
    if (envelope.request.runId !== run.runId || envelope.request.requestId !== requestId
        || envelope.request.callId !== observation.callId || envelope.effectKey !== receipt.effectKey
        || C.digest(envelope.request.binding) !== C.digest(binding)
        || C.digest(envelope.executorMapping.request) !== C.digest(meta.request)
        || C.digest(stored.receipt) !== C.digest(meta.receipt)
        || C.digest(envelope.request.args) !== C.digest(observation.args)
        || observation.tool !== expectedTool) throw fail();
    // The tool result may contain its own metadata; remove only our envelope
    // before comparing the exact SDK result recorded in the durable journal.
    const result = C.bounded(observation.result, 196608);
    delete result._meta.ownedRegistryInvocation;
    if (!Object.keys(result._meta).length && !Object.hasOwn(stored.receipt.result, '_meta')) delete result._meta;
    if (C.digest(result) !== C.digest(stored.receipt.result)) throw fail();
    await fence.assertRemoteAdmission(); await run.check();
    return Object.freeze({ invocationId: meta.request.operationId, runId: run.runId,
      effectKey: receipt.effectKey, state: 'completed', drained: true });
  };
}
module.exports = { createRegisteredInvocationObserver };
