'use strict';

const { createConversationBinding } = require('./secureshopConversationBinding');
const { validateAuditUnboundedWitness } = require('./secureshopAuditUnboundedEvidence');

const unavailable = code => Object.assign(new Error('Audit unbounded witness is unavailable'), { code });

function sameRef(left, right) {
  return Number.isSafeInteger(left?.bytes) && left.bytes >= 0 && typeof left.sha256 === 'string'
    && left.bytes === right?.bytes && left.sha256 === right?.sha256;
}

function configuredText(value, max) {
  if (typeof value !== 'string' || !value || Buffer.byteLength(value) > max || /[\r\n]/.test(value)) {
    throw new TypeError('Invalid owned audit witness configuration');
  }
  return value;
}

// The owner-scoped V36 fixture registers this descriptor before starting the
// audit run. It selects an exact persisted source event, rather than a
// convenient arbitrary line supplied by a browser, model, or audit response.
function createSecureShopAuditUnboundedOwnedWitnessSelector(value = {}) {
  if (!value || Object.getPrototypeOf(value) !== Object.prototype
      || Object.keys(value).length !== 5 || !['sourceEventId', 'actor', 'action', 'target', 'paramsJson'].every(key => Object.hasOwn(value, key))) {
    throw new TypeError('Invalid owned audit witness configuration');
  }
  const sourceEventId = configuredText(value.sourceEventId, 512);
  if (!/^(agents|review):[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(sourceEventId)) {
    throw new TypeError('Invalid owned audit witness configuration');
  }
  const actor = configuredText(value.actor, 256);
  const action = configuredText(value.action, 256);
  const target = configuredText(value.target, 1024);
  const paramsJson = configuredText(value.paramsJson, 16384);
  let parsed;
  try { parsed = JSON.parse(paramsJson); } catch { throw new TypeError('Invalid owned audit witness configuration'); }
  if (JSON.stringify(parsed) !== paramsJson) throw new TypeError('Invalid owned audit witness configuration');
  const suffix = `actor=${actor} action=${action} target=${target} params=${paramsJson}`;
  return async function selectWitness({ logText, sourcesText } = {}) {
    if (typeof logText !== 'string' || typeof sourcesText !== 'string') throw unavailable('AUDIT_UNBOUNDED_WITNESS_INVALID');
    let sources;
    try { sources = JSON.parse(sourcesText); } catch { throw unavailable('AUDIT_UNBOUNDED_WITNESS_INVALID'); }
    const lines = logText.split('\n');
    if (!Array.isArray(sources) || sources.length !== lines.length) throw unavailable('AUDIT_UNBOUNDED_WITNESS_INVALID');
    const indexes = sources.flatMap((source, index) => source?.id === sourceEventId ? [index] : []);
    if (indexes.length !== 1 || !lines[indexes[0]].endsWith(suffix)) throw unavailable('AUDIT_UNBOUNDED_WITNESS_INVALID');
    return Object.freeze({ version: 1, line: lines[indexes[0]],
      sha256: require('node:crypto').createHash('sha256').update(lines[indexes[0]]).digest('hex') });
  };
}

// This reader is the only intended producer of a V36 witness. `selectWitness`
// is server configuration for the owned qualification fixture; it receives the
// verified saved log, never a model argument or browser-provided value.
function createSecureShopAuditUnboundedWitnessReader({ openAuditRun, selectWitness } = {}) {
  if (typeof openAuditRun !== 'function' || typeof selectWitness !== 'function') {
    throw new TypeError('Protected audit witness reader dependencies required');
  }
  return async function readWitness({ binding: input, execution, evidence } = {}) {
    const binding = createConversationBinding(input, { id: input?.shopUserId, role: input?.role });
    if (binding.role !== 'admin' || typeof execution?.check !== 'function' || typeof execution.runId !== 'string'
        || !execution.runId || evidence?.runId !== execution.runId) {
      throw unavailable('AUDIT_UNBOUNDED_WITNESS_INVALID');
    }
    await execution.check();
    const saved = await openAuditRun({ scope: binding, persona: { id: binding.shopUserId, role: binding.role },
      runId: execution.runId, ...(execution.signal ? { signal: execution.signal } : {}) });
    if (!saved || saved.runId !== execution.runId || saved.summary !== evidence.summary
        || saved.provider !== evidence.provider || saved.model !== evidence.model
        || saved.requestedCount !== evidence.requestedCount || saved.rowCount !== evidence.rowCount
        || !sameRef(saved.artifacts?.log, evidence.artifacts?.log)
        || !sameRef(saved.artifacts?.sources, evidence.artifacts?.sources)
        || typeof saved.readArtifact !== 'function') {
      throw unavailable('AUDIT_UNBOUNDED_WITNESS_MISMATCH');
    }
    const read = async name => {
      const chunks = []; let bytes = 0, expected = saved.artifacts[name];
      for await (const part of saved.readArtifact(name)) {
        await execution.check();
        if (!Buffer.isBuffer(part) || bytes + part.length > expected.bytes) throw unavailable('AUDIT_UNBOUNDED_WITNESS_INVALID');
        bytes += part.length; chunks.push(part);
      }
      if (bytes !== expected.bytes) throw unavailable('AUDIT_UNBOUNDED_WITNESS_INVALID');
      return Buffer.concat(chunks).toString('utf8');
    };
    const log = await read('log');
    const sources = await read('sources');
    const selected = await selectWitness(Object.freeze({ runId: saved.runId, requestedCount: saved.requestedCount,
      rowCount: saved.rowCount, logSha256: saved.artifacts.log.sha256, sourcesSha256: saved.artifacts.sources.sha256,
      logText: log, sourcesText: sources }));
    await execution.check();
    return validateAuditUnboundedWitness(selected, log);
  };
}

module.exports = { createSecureShopAuditUnboundedWitnessReader, createSecureShopAuditUnboundedOwnedWitnessSelector };
