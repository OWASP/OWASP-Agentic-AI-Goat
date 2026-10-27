'use strict';

// A one-call, transport-only V36 diagnostic. This is not a qualification run:
// it does not invoke the application, an actor, or a Judge, and grants no credit.
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const http = require('node:http');
const path = require('node:path');

const ROOT = path.resolve(__dirname, '../..');
const EVIDENCE = path.join(ROOT, 'tasks/qualification/run-uxjs8scp/audit-collection-v36-original-evidence.json');
const EVIDENCE_SHA256 = '888b695c4e3359f42d796c5cf4f359734a48f8e143741037d454090a6063488c';
const REQUEST_SHA256 = '032cc1a14e17cdfe69c6e7ca6bd2eea93772d7f1b759c5f226034bfef03c540c';
const MODEL = 'llama3.1:8b';
const MODEL_DIGEST = '46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e';
const ORIGIN = 'http://127.0.0.1:11434';
const REQUEST_BYTES = 146726;
const CHAT_TIMEOUT_MS = 180000;
const TAGS_TIMEOUT_MS = 10000;
const RESPONSE_LIMIT = 8 * 1024 * 1024;
const TAGS_LIMIT = 1024 * 1024;
const RESULT_NAME = 'audit-collection-v36-retained-transport-diagnostic.json';
const JOURNAL_NAME = 'audit-collection-v36-retained-transport-attempt.jsonl';
const hash = bytes => crypto.createHash('sha256').update(bytes).digest('hex');

function loadPinnedRequest(file = EVIDENCE) {
  const info = fs.lstatSync(file);
  assert.ok(info.isFile() && !info.isSymbolicLink() && info.uid === process.getuid()
    && (info.mode & 0o777) === 0o600 && info.size <= 32 * 1024 * 1024,
  'Private, owned original evidence required');
  const raw = fs.readFileSync(file);
  assert.equal(hash(raw), EVIDENCE_SHA256, 'Original evidence must match retained capture');
  const evidence = JSON.parse(raw);
  const wire = evidence?.wires?.[2];
  assert.equal(wire?.path, '/api/chat');
  assert.equal(wire?.requestBytes, REQUEST_BYTES);
  assert.equal(wire?.complete, false);
  assert.equal(wire?.terminationReason, 'downstream_closed');
  assert.equal(typeof wire.requestText, 'string');
  const body = Buffer.from(wire.requestText, 'utf8');
  assert.equal(body.length, REQUEST_BYTES);
  assert.equal(hash(body), REQUEST_SHA256, 'Exact captured request bytes required');
  const parsed = JSON.parse(body.toString('utf8'));
  assert.deepEqual(parsed, wire.request);
  assert.equal(parsed.model, MODEL);
  assert.equal(parsed.stream, true);
  assert.deepEqual(parsed.options, { num_ctx: 32768, num_predict: 256, temperature: 0 });
  assert.deepEqual(Object.keys(parsed).sort(), ['format', 'messages', 'model', 'options', 'stream']);
  assert.equal(parsed.messages.length, 4);
  return body;
}

function boundedHttp({ origin, method, pathname, body, timeoutMs, byteLimit }) {
  const url = new URL(origin);
  assert.equal(url.protocol, 'http:');
  assert.equal(url.hostname, '127.0.0.1');
  assert.equal(url.username, '');
  assert.equal(url.password, '');
  assert.equal(url.pathname, '/');
  assert.equal(url.search, '');
  assert.equal(url.hash, '');
  assert.ok(Number.isSafeInteger(timeoutMs) && timeoutMs > 0 && timeoutMs <= CHAT_TIMEOUT_MS);
  assert.ok(Number.isSafeInteger(byteLimit) && byteLimit > 0 && byteLimit <= RESPONSE_LIMIT);
  return new Promise(resolve => {
    const started = performance.now();
    let settled = false, status = null, responseBytes = 0;
    let requestClosed = false, socketAssigned = false, socketClosed = false, observeRetirement = null;
    const parts = [];
    const request = http.request({ hostname: url.hostname, port: url.port, method, path: pathname,
      agent: false, headers: body ? { 'content-type': 'application/json', 'content-length': body.length }
        : { accept: 'application/json' } });
    request.once('socket', socket => {
      socketAssigned = true;
      if (socket.destroyed) socketClosed = true;
      else socket.once('close', () => { socketClosed = true; observeRetirement?.(); });
      observeRetirement?.();
    });
    request.once('close', () => { requestClosed = true; observeRetirement?.(); });
    const finish = (termination, complete = false) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (!complete) request.destroy();
      // This proves only local socket retirement. A remote Ollama computation
      // may continue after a deadline and is not claimed to be cancelled.
      new Promise(done => {
        const retirementTimer = setTimeout(() => done(false), 5000);
        observeRetirement = () => {
          if (requestClosed && (!socketAssigned || socketClosed)) {
            clearTimeout(retirementTimer);
            done(true);
          }
        };
        observeRetirement();
      }).then(localSocketRetired => {
        resolve({ status, responseBytes, termination, elapsedMs: Math.round(performance.now() - started),
          socketAssigned, localSocketRetired, body: complete ? Buffer.concat(parts) : null });
      });
    };
    const timer = setTimeout(() => finish('deadline'), timeoutMs);
    request.once('response', response => {
      status = response.statusCode;
      response.on('data', part => {
        responseBytes += part.length;
        if (responseBytes > byteLimit) finish('response_limit');
        else parts.push(part);
      });
      response.once('end', () => finish(response.complete ? 'complete' : 'incomplete', response.complete));
      response.once('error', () => finish('response_error'));
      response.once('close', () => { if (!response.complete) finish('response_closed'); });
    });
    request.once('error', () => finish('request_error'));
    request.end(body);
  });
}

async function checkModel(origin = ORIGIN, timeoutMs = TAGS_TIMEOUT_MS) {
  const result = await boundedHttp({ origin, method: 'GET', pathname: '/api/tags',
    timeoutMs, byteLimit: TAGS_LIMIT });
  const observation = { status: result.status, termination: result.termination,
    bytes: result.responseBytes, elapsedMs: result.elapsedMs,
    socketAssigned: result.socketAssigned,
    localSocketRetired: result.localSocketRetired, identityMatched: false };
  if (result.termination !== 'complete' || result.status !== 200) return observation;
  try {
    const models = JSON.parse(result.body).models;
    observation.identityMatched = Array.isArray(models)
      && models.filter(row => row && row.name === MODEL && row.digest === MODEL_DIGEST).length === 1
      && models.filter(row => row && row.name === MODEL).length === 1;
  } catch { observation.termination = 'invalid_json'; }
  return observation;
}

function summarizeChat(result) {
  const report = { status: result.status, termination: result.termination,
    responseBytes: result.responseBytes, elapsedMs: result.elapsedMs,
    socketAssigned: result.socketAssigned,
    localSocketRetired: result.localSocketRetired,
    responseSha256: result.body ? hash(result.body) : null,
    frames: 0, terminalDone: false, doneReason: null, promptEvalCount: null, evalCount: null };
  if (!result.body) return report;
  const lines = result.body.toString('utf8').trim().split('\n');
  if (lines.length > 4096 || lines.some(line => Buffer.byteLength(line) > 1024 * 1024)) {
    report.frameParse = 'bounded_limit'; return report;
  }
  try {
    const frames = lines.map(line => JSON.parse(line));
    report.frames = frames.length;
    const last = frames.at(-1);
    report.terminalDone = last?.done === true && last?.model === MODEL;
    report.doneReason = ['stop', 'length'].includes(last?.done_reason) ? last.done_reason : null;
    report.promptEvalCount = Number.isSafeInteger(last?.prompt_eval_count) ? last.prompt_eval_count : null;
    report.evalCount = Number.isSafeInteger(last?.eval_count) ? last.eval_count : null;
    report.frameParse = frames.every(frame => frame?.model === MODEL) ? 'valid_json_model' : 'model_mismatch';
  } catch { report.frameParse = 'invalid_json'; }
  return report;
}

async function runDiagnostic({ origin = ORIGIN, tagsTimeoutMs = TAGS_TIMEOUT_MS,
  chatTimeoutMs = CHAT_TIMEOUT_MS, responseLimit = RESPONSE_LIMIT,
  probeModel = checkModel, beforeChat = () => {} } = {}) {
  const body = loadPinnedRequest();
  const report = { version: 1, kind: 'v36-retained-transport-only', qualificationCredit: false,
    actorCalls: 0, judgeCalls: 0, requestCount: 0,
    evidenceSha256: EVIDENCE_SHA256, requestSha256: REQUEST_SHA256, requestBytes: body.length,
    model: MODEL, expectedModelDigest: MODEL_DIGEST, preModel: null, chat: null, postModel: null };
  report.preModel = await probeModel(origin, tagsTimeoutMs);
  if (!report.preModel.identityMatched || !report.preModel.localSocketRetired) return report;
  try {
    await beforeChat();
    report.requestCount = 1;
    const result = await boundedHttp({ origin, method: 'POST', pathname: '/api/chat', body,
      timeoutMs: chatTimeoutMs, byteLimit: responseLimit });
    report.chat = summarizeChat(result);
  } finally {
    report.postModel = await probeModel(origin, tagsTimeoutMs);
  }
  return report;
}

function admittedOutput(file) {
  assert.equal(path.basename(file), RESULT_NAME);
  const root = fs.realpathSync.native(path.join(ROOT, 'tasks/qualification'));
  const run = fs.realpathSync.native(path.dirname(file));
  assert.equal(path.dirname(run), root);
  assert.match(path.basename(run), /^run-[A-Za-z0-9_-]+$/);
  const stat = fs.statSync(run);
  assert.ok(stat.isDirectory() && stat.uid === process.getuid()
    && (stat.mode & 0o777) === 0o700, 'Private repository run directory required');
  return path.join(run, RESULT_NAME);
}

function safeFailure(error) {
  const name = ['Error', 'AssertionError', 'TypeError', 'SyntaxError'].includes(error?.name)
    ? error.name : 'Error';
  const code = typeof error?.code === 'string' && /^[A-Z_]{1,40}$/.test(error.code)
    ? error.code : null;
  return { name, code };
}

async function main(argv = process.argv.slice(2), { diagnostic = runDiagnostic } = {}) {
  if (argv.length === 0 || argv[0] === '--plan') {
    assert.ok(argv.length === 0 || argv.length === 1);
    process.stdout.write(JSON.stringify({ kind: 'v36-retained-transport-only', nativeStarted: false,
      qualificationCredit: false, evidenceSha256: EVIDENCE_SHA256,
      requestSha256: REQUEST_SHA256, requestBytes: REQUEST_BYTES,
      model: MODEL, expectedModelDigest: MODEL_DIGEST, chatTimeoutMs: CHAT_TIMEOUT_MS,
      responseLimit: RESPONSE_LIMIT }) + '\n');
    return;
  }
  assert.deepEqual(argv.slice(0, 2), ['--run', '--output']);
  assert.equal(argv.length, 3);
  const output = admittedOutput(argv[2]);
  // Exclusive reservation is the one-attempt lock. It precedes even model
  // inventory reads, so an accidental duplicate cannot send a second POST.
  const handle = fs.openSync(output, 'wx', 0o600);
  let journal = null, chatStarted = false;
  const append = event => {
    fs.writeFileSync(journal, JSON.stringify({ version: 1, ...event }) + '\n');
    fs.fsyncSync(journal);
  };
  try {
    journal = fs.openSync(path.join(path.dirname(output), JOURNAL_NAME), 'wx', 0o600);
    append({ event: 'started', evidenceSha256: EVIDENCE_SHA256, requestSha256: REQUEST_SHA256 });
    const report = await diagnostic({ beforeChat: () => {
      append({ event: 'chat_started', requestSha256: REQUEST_SHA256 });
      chatStarted = true;
    } });
    append({ event: 'finished', requestCount: report.requestCount,
      termination: report.chat?.termination || null });
    fs.writeFileSync(handle, JSON.stringify(report) + '\n');
    fs.fsyncSync(handle);
    process.stdout.write(JSON.stringify({ report: output, requestCount: report.requestCount,
      termination: report.chat?.termination || null, qualificationCredit: false }) + '\n');
    if (!report.preModel.identityMatched || !report.preModel.localSocketRetired
        || !report.postModel?.identityMatched || !report.postModel?.localSocketRetired
        || report.chat?.localSocketRetired === false) process.exitCode = 1;
  } catch (error) {
    const failure = safeFailure(error);
    try { if (journal !== null) append({ event: 'failed', chatStarted, failure }); } catch {}
    try {
      fs.writeFileSync(handle, JSON.stringify({ version: 1, kind: 'v36-retained-transport-only',
        qualificationCredit: false, chatStarted, failure }) + '\n');
      fs.fsyncSync(handle);
    } catch {}
    throw error;
  } finally {
    if (journal !== null) fs.closeSync(journal);
    fs.closeSync(handle);
  }
}

if (require.main === module) main().catch(error => {
  process.stderr.write(`V36 retained diagnostic failed: ${error?.name || 'Error'}\n`);
  process.exitCode = 1;
});

module.exports = { main, loadPinnedRequest, boundedHttp, checkModel, summarizeChat, runDiagnostic,
  admittedOutput, EVIDENCE_SHA256, REQUEST_SHA256, MODEL_DIGEST, REQUEST_BYTES };
