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
  ensure(Array.isArray(input.cases) && input.cases.length > 0 && input.cases.length <= 32, 'Invalid case count');
  const seen = new Set();
  for (const row of input.cases) {
    ensure(Object.keys(row).sort().join(',') === 'id,objective,request,response', 'Unexpected input fields');
    ensure(typeof row.id === 'string' && row.id && !seen.has(row.id), 'Duplicate/invalid case ID');
    seen.add(row.id);
    ensure(['jailbreak', 'role_playing'].includes(row.objective), 'Unsupported objective');
    for (const field of ['request', 'response']) ensure(typeof row[field] === 'string' && row[field].trim() && row[field].isWellFormed() && Buffer.byteLength(row[field]) < 262144, 'Invalid evidence');
  }
  const { createDpiTaskBoundAssessmentV2Candidate: createDpiTaskBoundAssessmentCandidate, VERSION } = require('../../server/agent-runtime/dpiTaskBoundAssessmentV2Candidate');
  // Pin the loaded local dependency closure, not unrelated changes in the checkout.
  const pins = Object.fromEntries(Object.keys(require.cache).filter(file => file.startsWith(ROOT + path.sep)).sort().map(file => [path.relative(ROOT, file), sha(fs.readFileSync(file))]));
  const parent = path.join(ROOT, 'backups/private-recovery/dpi-task-bound-v2-probe');
  fs.mkdirSync(parent, { recursive: true, mode: 0o700 });
  const stat = fs.lstatSync(parent);
  ensure(stat.isDirectory() && !stat.isSymbolicLink() && stat.uid === process.getuid(), 'Invalid evidence parent');
  const directory = fs.mkdtempSync(path.join(parent, 'run-'));
  fs.chmodSync(directory, 0o700);
  const resultPath = path.join(directory, 'result.json');
  const result = { version: 1, candidateVersion: VERSION, pid: process.pid, inputPath: path.relative(ROOT, inputPath), inputSha256: inputSha,
    model: MODEL, digest: DIGEST, runtimePath: process.execPath, runtimeSha256: sha(fs.readFileSync(process.execPath)), sourcePins: pins,
    complete: false, sourceUnchanged: false, exerciseQualification: false, creditAuthorized: false, calls: [], cases: [] };
  const save = () => fs.writeFileSync(resultPath, JSON.stringify(result, null, 2) + '\n', { mode: 0o600 });
  const runAbort = new AbortController();
  const wallTimer = setTimeout(() => runAbort.abort(Error('Diagnostic wall deadline')), 4400000);
  const onSignal = () => runAbort.abort(Error('Diagnostic interrupted'));
  process.on('SIGTERM', onSignal); process.on('SIGINT', onSignal);
  async function request(endpoint, body, timeoutMs = 180000) {
    const signal = AbortSignal.any([runAbort.signal, AbortSignal.timeout(Math.max(1, Math.floor(timeoutMs)))]);
    const response = await fetch('http://127.0.0.1:11434' + endpoint, { signal, ...(body ? { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) } : {}) });
    ensure(response.ok, 'Ollama HTTP ' + response.status);
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
  }
  save();
  try {
    const metadata = await request('/api/tags');
    ensure(metadata.models.some(row => row.name === MODEL && row.digest === DIGEST), 'Installed model identity changed');
    result.modelIdentityBefore = { model: MODEL, digest: DIGEST };
    for (const row of input.cases) {
      runAbort.signal.throwIfAborted();
      const started = performance.now();
      const candidate = createDpiTaskBoundAssessmentCandidate({ objective: row.objective, evidence: [
        { id: 'request', source: 'student_input', content: row.request },
        { id: 'response', source: 'assistant_response', content: row.response },
      ] });
      ensure(candidate.policy.maximumCalls === 4 && candidate.policy.maxOutput === 900 && candidate.policy.contextTokens === 20480, 'Candidate budget changed');
      const entry = { id: row.id, objective: row.objective, policy: candidate.policy, stages: [] };
      result.cases.push(entry); const values = []; save();
      for (const stage of candidate.stages) {
        ensure(performance.now() - started < 300000, 'Case wall deadline');
        const wire = stage.messages();
        const body = { model: MODEL, messages: wire.messages, format: wire.format, stream: false,
          options: { temperature: 0, num_predict: 900, num_ctx: 20480 } };
        ensure(Buffer.byteLength(JSON.stringify(wire.messages)) + Buffer.byteLength(JSON.stringify(wire.format)) + 900 + 1024 <= 20480, 'Diagnostic context guard');
        const call = { case: row.id, stage: stage.id, request: body, requestSha256: sha(JSON.stringify(body)) };
        result.calls.push(call); save();
        const response = await request('/api/chat', body, Math.min(180000, 300000 - (performance.now() - started))); call.response = response; save();
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
