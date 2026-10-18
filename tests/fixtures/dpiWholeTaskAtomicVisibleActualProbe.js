'use strict';
// Bounded, local-only diagnostic. No application startup, databases, or objective credit.
const fs = require('node:fs');
const path = require('node:path');
const { createHash } = require('node:crypto');
const { performance } = require('node:perf_hooks');
const ROOT = path.resolve(__dirname, '../..');
const MODEL = 'llama3.1:8b';
const DIGEST = '46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e';
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const ensure = (condition, message) => { if (!condition) throw Error(message); };

async function main() {
  const [inputArg, inputSha] = process.argv.slice(2);
  ensure(inputArg && /^[a-f0-9]{64}$/.test(inputSha || ''), 'Provide input file and frozen SHA-256');
  const inputPath = path.resolve(inputArg);
  ensure(inputPath.startsWith(ROOT + path.sep), 'Input must be in main checkout');
  const inputBytes = fs.readFileSync(inputPath);
  ensure(sha(inputBytes) === inputSha, 'Input hash mismatch');
  const input = JSON.parse(inputBytes);
  ensure(input.version === 'dpi-whole-task-intent-qualification8-v1' && input.actorProof === false && input.creditProof === false && Array.isArray(input.cases) && input.cases.length === 8, 'Exact fixed-eight diagnostic required');
  ensure(inputSha === 'd9dddf09ed7fc58c39a11aa953f518cc3b85f3ab1022d094d83d5a7f14d5853c', 'Frozen original eight required');
  const seen = new Set();
  for (const row of input.cases) {
    ensure(Object.keys(row).sort().join(',') === 'evidence,id,objective,policyIdentity', 'Unexpected input fields');
    ensure(typeof row.id === 'string' && row.id && !seen.has(row.id), 'Duplicate/invalid case ID');
    seen.add(row.id);
    ensure(['virtualization', 'obfuscation'].includes(row.objective) && Array.isArray(row.evidence), 'Unsupported objective/evidence');
  }
  const { createDpiWholeTaskAtomicVisibleCandidate: createCandidate, VERSION } = require('../../server/agent-runtime/dpiWholeTaskAtomicVisibleCandidate');
  const candidates = input.cases.map(row => createCandidate({ objective: row.objective, evidence: row.evidence }));
  // Pin the loaded local dependency closure after complete evidence admission.
  const pins = Object.fromEntries(Object.keys(require.cache).filter(file => file.startsWith(ROOT + path.sep)).sort().map(file => [path.relative(ROOT, file), sha(fs.readFileSync(file))]));
  const parent = path.join(ROOT, 'backups/private-recovery/dpi-whole-task-atomic-visible-v3-probe');
  fs.mkdirSync(parent, { recursive: true, mode: 0o700 });
  const stat = fs.lstatSync(parent);
  ensure(stat.isDirectory() && !stat.isSymbolicLink() && stat.uid === process.getuid(), 'Invalid evidence parent');
  const directory = fs.mkdtempSync(path.join(parent, 'run-'));
  fs.chmodSync(directory, 0o700);
  const resultPath = path.join(directory, 'result.json');
  const result = { version: 1, candidateVersion: VERSION, pid: process.pid, inputPath: path.relative(ROOT, inputPath), inputSha256: inputSha,
    model: MODEL, digest: DIGEST, runtimePath: process.execPath, runtimeSha256: sha(fs.readFileSync(process.execPath)), sourcePins: pins,
    complete: false, sourceUnchanged: false, exerciseQualification: false, creditAuthorized: false, maximumCalls: 64, physicalPending: 0, calls: [], cases: [] };
  const save = () => fs.writeFileSync(resultPath, JSON.stringify(result, null, 2) + '\n', { mode: 0o600 });
  const runAbort = new AbortController();
  const wallTimer = setTimeout(() => runAbort.abort(Error('Diagnostic wall deadline')), 1200000);
  const onSignal = () => runAbort.abort(Error('Diagnostic interrupted'));
  process.on('SIGTERM', onSignal); process.on('SIGINT', onSignal);
  async function request(endpoint, body, timeoutMs = 60000) {
    const signal = AbortSignal.any([runAbort.signal, AbortSignal.timeout(Math.max(1, Math.floor(timeoutMs)))]);
    ensure(['/api/tags', '/api/chat'].includes(endpoint), 'Endpoint outside diagnostic');
    result.physicalPending += 1; save();
    try {
    const response = await fetch('http://127.0.0.1:11434' + endpoint, { signal, ...(body ? { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) } : {}) });
    if (!response.ok) {
      const text = await response.text();
      result.transportError = { endpoint, status: response.status, response: text.slice(0, 4096) }; save();
      throw Error('Ollama HTTP ' + response.status);
    }
    const reader = response.body.getReader(); const chunks = []; let size = 0;
    try {
      for (;;) {
        const next = await reader.read(); if (next.done) break;
        size += next.value.byteLength;
        ensure(size <= 1024 * 1024, 'Ollama response limit');
        chunks.push(Buffer.from(next.value));
      }
    } finally { await reader.cancel(); }
    return JSON.parse(Buffer.concat(chunks).toString('utf8'));
    } finally { result.physicalPending -= 1; save(); }
  }
  save();
  try {
    const metadata = await request('/api/tags');
    ensure(metadata.models.some(row => row.name === MODEL && row.digest === DIGEST), 'Installed model identity changed');
    result.modelIdentityBefore = { model: MODEL, digest: DIGEST };
    for (const [caseIndex, row] of input.cases.entries()) {
      runAbort.signal.throwIfAborted();
      const started = performance.now();
      const candidate = candidates[caseIndex];
      ensure(candidate.policy.maximumCalls === 18 && candidate.policy.maxOutput === 900 && candidate.policy.contextTokens === 32768, 'Candidate budget changed');
      const entry = { id: row.id, objective: row.objective, policy: candidate.policy, stages: [] };
      result.cases.push(entry); const values = []; save();
      for (const stage of candidate.stages) {
        ensure(values.length < candidate.policy.maximumCalls, 'Candidate call budget exceeded');
        ensure(performance.now() - started < 300000, 'Case wall deadline');
        const wire = stage.messages();
        const body = { model: MODEL, messages: wire.messages, format: wire.format, stream: false,
          options: { temperature: 0, num_predict: 900, num_ctx: 32768 } };
        ensure(Buffer.byteLength(JSON.stringify(wire.messages)) + Buffer.byteLength(JSON.stringify(wire.format)) + 900 + 1024 <= 32768, 'Diagnostic context guard');
        const call = { case: row.id, stage: stage.id, request: body, requestSha256: sha(JSON.stringify(body)) };
        ensure(result.calls.length < 64, 'Global diagnostic call budget exceeded');
        result.calls.push(call); save();
        const response = await request('/api/chat', body, Math.min(60000, 300000 - (performance.now() - started))); call.response = response; save();
        ensure(response.model === MODEL && response.done === true && response.done_reason === 'stop', 'Incomplete/model-mismatched generation');
        ensure(typeof response.message?.content === 'string', 'Missing model output');
        try {
          const value = stage.validate(response.message.content);
          values.push(value); entry.stages.push({ id: stage.id, value });
        } catch (error) {
          entry.validationError = { stage: stage.id, message: error.message };
          break; // No repair or retry. Preserve the invalid response and continue the diagnostic set.
        }
        save();
      }
      if (!entry.validationError) entry.decision = candidate.combine(...values);
      entry.elapsedMs = Math.round(performance.now() - started); save();
    }
    const finalMetadata = await request('/api/tags');
    ensure(finalMetadata.models.some(row => row.name === MODEL && row.digest === DIGEST), 'Installed model identity changed after run');
    result.modelIdentityAfter = { model: MODEL, digest: DIGEST };
    result.complete = true;
  } catch (error) {
    result.error = { name: error.name, message: error.message }; process.exitCode = 1;
  } finally {
    clearTimeout(wallTimer); process.off('SIGTERM', onSignal); process.off('SIGINT', onSignal);
    result.sourceUnchanged = Object.entries(pins).every(([file, digest]) => sha(fs.readFileSync(path.join(ROOT, file))) === digest);
    if (!result.sourceUnchanged) process.exitCode = 1;
    save();
    console.log(JSON.stringify({ resultPath, complete: result.complete, sourceUnchanged: result.sourceUnchanged, calls: result.calls.length, cases: result.cases.map(row => ({ id: row.id, verdict: row.decision?.verdict, invalid: row.validationError?.stage })) }));
  }
}
main().catch(error => { console.error(error.message); process.exitCode = 1; });
