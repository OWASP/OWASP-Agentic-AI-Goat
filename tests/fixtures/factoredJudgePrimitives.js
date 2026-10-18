'use strict';
// Unmounted diagnostic plumbing. No semantic validator, provider or credit authority.
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const sha = value => createHash('sha256').update(value).digest('hex');
const STAGES = Object.freeze(['classification', 'extraction', 'coverage', 'task_relation', 'response', 'contrary']);
const PROTOCOL = 'factored-judge-primitives.v1';
function freeze(value) { if (value && typeof value === 'object') { Object.values(value).forEach(freeze); Object.freeze(value); } return value; }
function text(value, max) { assert.equal(typeof value, 'string'); assert(value.isWellFormed()); assert(value.length > 0 && Buffer.byteLength(value) <= max); return value; }
function catalogue(source, maxBytes = 8192) {
  assert([8192,16384].includes(maxBytes)); text(source, maxBytes);
  const scalars = Array.from(source), entries = []; let utf16 = 0, utf8 = 0;
  for (let i = 0; i < scalars.length; i += 128) {
    const value = scalars.slice(i, i + 128).join('');
    entries.push({ id: 'S' + String(entries.length).padStart(3, '0'), text: value,
      utf16Start: utf16, utf16End: utf16 + value.length, utf8Start: utf8, utf8End: utf8 + Buffer.byteLength(value) });
    utf16 += value.length; utf8 += Buffer.byteLength(value);
  }
  assert(entries.length <= maxBytes / 128); assert.equal(entries.map(x => x.text).join(''), source);
  return freeze({ version: 'lossless-unicode128.v1', sourceSha256: sha(source), identityOnly: true, semanticCoverageVerified: false, exactOutputLiteralResolved: false, entries });
}
function resolveIds(source, ids) {
  const c = catalogue(source); assert(Array.isArray(ids) && ids.length > 0 && ids.length <= 64);
  assert.equal(new Set(ids).size, ids.length);
  const selected = ids.map(id => { assert.equal(typeof id, 'string'); const entry = c.entries.find(x => x.id === id); assert(entry, 'Unknown source ID'); return entry; });
  for (let i = 1; i < selected.length; i++) assert(selected[i].utf16Start > selected[i - 1].utf16Start, 'Source order required');
  return freeze({ sourceSha256: c.sourceSha256, entries: selected, identityOnly: true, semanticCoverageVerified: false, exactOutputLiteralResolved: false });
}
function envelope(stage, evidence, previous = []) {
  assert(STAGES.includes(stage)); assert(evidence && Object.getPrototypeOf(evidence) === Object.prototype);
  assert(Array.isArray(previous)); assert.equal(previous.length, STAGES.indexOf(stage));
  previous.forEach((row, i) => {
    assert(row && Object.getPrototypeOf(row) === Object.prototype);
    assert.deepEqual(Object.keys(row).sort(), ['stage','requestSha256','responseSha256','status'].sort());
    assert.equal(row.stage, STAGES[i]);
    if (row.status === 'skipped-negative-requires-coverage') {
      assert.equal(row.stage, 'extraction'); assert.equal(row.requestSha256, null); assert.equal(row.responseSha256, null);
    } else {
      assert.equal(row.status, 'observed-unvalidated');
      for (const key of ['requestSha256','responseSha256']) assert(typeof row[key] === 'string' && /^[a-f0-9]{64}$/.test(row[key]));
    }
  });
  const sourceOnly = STAGES.indexOf(stage) < 3;
  const keys = stage === 'task_relation' ? ['source', 'task'] : sourceOnly ? ['source'] : ['source', 'task', 'response', 'responseComplete', 'effects'];
  assert.deepEqual(Object.keys(evidence).sort(), keys.sort());
  const source = text(evidence.source, 8192), value = { protocol: PROTOCOL, stage, source, catalogue: catalogue(source), previous: JSON.parse(JSON.stringify(previous)) };
  if (!sourceOnly) value.task = text(evidence.task, 8192);
  if (!sourceOnly && stage !== 'task_relation') {
    assert.equal(evidence.responseComplete, true, 'Completed response required');
    value.response = text(evidence.response, 16384); value.responseComplete = true;
    assert(evidence.effects === null || (typeof evidence.effects === 'object' && !Array.isArray(evidence.effects)));
    value.effects = JSON.parse(JSON.stringify(evidence.effects));
  }
  const serialized = JSON.stringify(value); assert(Buffer.byteLength(serialized) <= 32768, 'Expanded request budget exceeded; no truncation');
  return freeze({ ...value, requestSha256: sha(serialized) });
}
function createDiagnostic({ source, timeoutMs = 60000, signal, classificationParser } = {}) {
  assert(classificationParser === undefined || typeof classificationParser === 'function');
  text(source, 8192); assert(Number.isSafeInteger(timeoutMs) && timeoutMs > 0 && timeoutMs <= 360000);
  const deadline = performance.now() + timeoutMs, controller = new AbortController();
  const combined = AbortSignal.any([controller.signal, ...(signal ? [signal] : [])]);
  let attempts = 0, index = 0, pending = false, running = false, terminal = false, sourceDecision = null;
  const sourceHash = sha(source); let taskHash = null, responseHash = null, effectsHash = null;
  const records = [];
  const check = () => { if (performance.now() >= deadline) controller.abort(); combined.throwIfAborted(); };
  function snapshot() { return freeze(JSON.parse(JSON.stringify({ protocol: PROTOCOL, diagnosticOnly: true, creditAuthorized: false,
    semanticAccepted: null, attempts, physicallyPending: pending, terminal, sourceSha256: sourceHash, records }))); }
  async function run(stage, evidence, transport) {
    assert(!running && !pending && !terminal, 'Diagnostic closed or transport physically pending'); assert.equal(typeof transport, 'function');
    assert.equal(stage, STAGES[index], 'Stage order or retry forbidden'); assert.equal(evidence.source, source, 'Source changed'); check();
    const request = envelope(stage, evidence, records.map(r => ({ stage: r.stage, requestSha256: r.requestSha256, responseSha256: r.responseSha256, status: r.status })));
    if (request.task !== undefined) { const h = sha(request.task); assert(taskHash === null || taskHash === h, 'Task changed'); taskHash = h; }
    if (request.response !== undefined) {
      const h = sha(request.response), e = sha(JSON.stringify(request.effects));
      assert(responseHash === null || responseHash === h, 'Response changed'); assert(effectsHash === null || effectsHash === e, 'Effects changed'); responseHash = h; effectsHash = e;
    }
    const started = performance.now(), row = { stage, requestSha256: request.requestSha256, sourceSha256: sourceHash, status: 'admitted', responseSha256: null, raw: null, elapsedMs: null };
    records.push(row); index++; pending = true; running = true; let timer, listener;
    const end = Math.min(deadline, started + 60000);
    const stageCheck = () => { if (performance.now() >= end) controller.abort(); check(); };
    const physical = Promise.resolve().then(() => { stageCheck(); assert(attempts < 6); attempts++; row.status = 'in-flight'; return transport(request, { signal: combined, timeoutMs: Math.max(1, Math.floor(end - performance.now())) }); });
    physical.finally(() => { pending = false; }).catch(() => {});
    try {
      const abort = new Promise((_, reject) => { listener = () => reject(Error('Diagnostic cancelled')); combined.addEventListener('abort', listener, { once: true }); });
      timer = setTimeout(() => controller.abort(), Math.max(1, end - performance.now()));
      const raw = await Promise.race([physical, abort]); stageCheck();
      text(raw, 16384); row.raw = raw; row.responseSha256 = sha(raw);
      // Only existing elementary classification is interpreted. Other outputs are
      // unvalidated observations, never semantic passes or authentic effect proof.
      if (stage === 'classification') {
        if (classificationParser) {
          const parsed = classificationParser(raw);
          assert(parsed && Object.getPrototypeOf(parsed) === Object.prototype && Object.keys(parsed).length);
          const serialized = JSON.stringify(parsed); assert(Buffer.byteLength(serialized) <= 16384);
          const copy = JSON.parse(serialized); assert.deepEqual(copy, parsed, 'Parser must return plain JSON');
          stageCheck(); row.parsed = freeze(copy); row.parserMode = 'custom-single-stage'; terminal = true;
        } else { const v = JSON.parse(raw); assert.deepEqual(Object.keys(v), ['decision']); assert(['directive', 'no_directive', 'uncertain'].includes(v.decision)); sourceDecision = v.decision; if (sourceDecision === 'uncertain') terminal = true; }
      }
      stageCheck(); row.status = 'observed-unvalidated'; if (index === 6) terminal = true;
    } catch (error) { row.status = combined.aborted ? 'cancelled-or-deadline' : 'unavailable'; row.errorType = error instanceof SyntaxError ? 'SyntaxError' : 'Error'; terminal = true; }
    finally { clearTimeout(timer); if (listener) combined.removeEventListener('abort', listener); row.elapsedMs = performance.now() - started; running = false; }
    return snapshot();
  }
  function skipNegativeExtraction() { assert(!running && !pending && !terminal && index === 1 && sourceDecision === 'no_directive'); index = 2; records.push({ stage: 'extraction', status: 'skipped-negative-requires-coverage', requestSha256: null, responseSha256: null }); }
  return Object.freeze({ run, skipNegativeExtraction, snapshot });
}
module.exports = { catalogue, resolveIds, envelope, createDiagnostic, STAGES };
