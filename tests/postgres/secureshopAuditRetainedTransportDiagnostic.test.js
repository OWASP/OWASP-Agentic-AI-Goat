'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const crypto = require('node:crypto');
const path = require('node:path');
const fs = require('node:fs');
const diagnostic = require('./secureshopAuditRetainedTransportDiagnostic');

const sha = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const validTags = () => JSON.stringify({ models: [{ name: 'llama3.1:8b', digest: diagnostic.MODEL_DIGEST }] });

async function withServer(handler, run) {
  const server = http.createServer(handler);
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try { return await run(`http://127.0.0.1:${server.address().port}`); }
  finally {
    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
  }
}

test('retained V36 body is pinned raw bytes, and import/plan never invokes a model', async () => {
  const body = diagnostic.loadPinnedRequest();
  assert.equal(body.length, diagnostic.REQUEST_BYTES);
  assert.equal(sha(body), diagnostic.REQUEST_SHA256);
  const stdout = process.stdout.write;
  const lines = [];
  process.stdout.write = value => { lines.push(value); return true; };
  try { await diagnostic.main(['--plan']); }
  finally { process.stdout.write = stdout; }
  assert.equal(lines.length, 1);
  const plan = JSON.parse(lines[0]);
  assert.equal(plan.nativeStarted, false);
  assert.equal(plan.qualificationCredit, false);
  assert.equal(plan.requestSha256, diagnostic.REQUEST_SHA256);
  assert.equal(lines[0].includes('Tool observation'), false);
});

test('output is restricted to an existing private repository qualification run', () => {
  const retainedRun = path.resolve(__dirname, '../../tasks/qualification/run-uxjs8scp');
  const name = 'audit-collection-v36-retained-transport-diagnostic.json';
  assert.equal(diagnostic.admittedOutput(path.join(retainedRun, name)), path.join(retainedRun, name));
  assert.throws(() => diagnostic.admittedOutput(path.join('/tmp', name)));
  assert.throws(() => diagnostic.admittedOutput(path.join(retainedRun, 'other.json')));
});

test('exclusive output reservation prevents a duplicate attempt before any model call', async () => {
  const run = fs.mkdtempSync(path.resolve(__dirname, '../../tasks/qualification/run-v36-unit-'));
  const output = path.join(run, 'audit-collection-v36-retained-transport-diagnostic.json');
  const journal = path.join(run, 'audit-collection-v36-retained-transport-attempt.jsonl');
  let calls = 0;
  const stdout = process.stdout.write;
  process.stdout.write = () => true;
  try {
    await diagnostic.main(['--run', '--output', output], { diagnostic: async ({ beforeChat }) => {
      calls++;
      await beforeChat();
      return { requestCount: 1, preModel: { identityMatched: true, localSocketRetired: true },
        postModel: { identityMatched: true, localSocketRetired: true },
        chat: { termination: 'complete', localSocketRetired: true } };
    } });
    await assert.rejects(diagnostic.main(['--run', '--output', output], {
      diagnostic: async () => { calls++; throw new Error('must never be reached'); },
    }), error => error?.code === 'EEXIST');
    assert.equal(calls, 1);
    assert.deepEqual(fs.readFileSync(journal, 'utf8').trim().split('\n').map(line => JSON.parse(line).event),
      ['started', 'chat_started', 'finished']);
    assert.equal(JSON.parse(fs.readFileSync(output, 'utf8')).requestCount, 1);
  } finally {
    process.stdout.write = stdout;
    fs.unlinkSync(output);
    fs.unlinkSync(journal);
    fs.rmdirSync(run);
  }
});

test('failed attempted call leaves a private started/failed journal without error text', async () => {
  const run = fs.mkdtempSync(path.resolve(__dirname, '../../tasks/qualification/run-v36-failure-'));
  const output = path.join(run, 'audit-collection-v36-retained-transport-diagnostic.json');
  const journal = path.join(run, 'audit-collection-v36-retained-transport-attempt.jsonl');
  try {
    await assert.rejects(diagnostic.main(['--run', '--output', output], {
      diagnostic: async ({ beforeChat }) => {
        await beforeChat();
        throw new Error('secret prompt text must not be copied');
      },
    }), /secret prompt text/);
    const events = fs.readFileSync(journal, 'utf8').trim().split('\n').map(line => JSON.parse(line));
    assert.deepEqual(events.map(event => event.event), ['started', 'chat_started', 'failed']);
    assert.equal(events[2].chatStarted, true);
    const saved = fs.readFileSync(output, 'utf8');
    assert.equal(saved.includes('secret prompt'), false);
    assert.equal(JSON.parse(saved).failure.name, 'Error');
  } finally {
    fs.unlinkSync(output);
    fs.unlinkSync(journal);
    fs.rmdirSync(run);
  }
});

test('matching model identity with unretired preflight socket cannot start the POST', async () => {
  let probes = 0, beforeChats = 0;
  const report = await diagnostic.runDiagnostic({
    probeModel: async () => { probes++; return { identityMatched: true, localSocketRetired: false }; },
    beforeChat: () => { beforeChats++; },
  });
  assert.equal(probes, 1);
  assert.equal(beforeChats, 0);
  assert.equal(report.requestCount, 0);
  assert.equal(report.chat, null);
});

test('one exact POST, unchanged bytes, bounded metadata and pre/post model identity', async () => {
  let posts = 0, tags = 0, observedHash = null, observedBytes = 0;
  await withServer((request, response) => {
    if (request.url === '/api/tags') { tags++; response.writeHead(200).end(validTags()); return; }
    assert.equal(request.url, '/api/chat');
    assert.equal(request.method, 'POST');
    posts++;
    const chunks = [];
    request.on('data', chunk => chunks.push(chunk));
    request.on('end', () => {
      const body = Buffer.concat(chunks);
      observedHash = sha(body); observedBytes = body.length;
      response.writeHead(200, { 'content-type': 'application/x-ndjson' });
      response.end(JSON.stringify({ model:'llama3.1:8b', done:true,
        done_reason:'stop', prompt_eval_count:12000, eval_count:20,
        message:{role:'assistant',content:'{"answer":"synthetic"}' } }) + '\n');
    });
  }, async origin => {
    const report = await diagnostic.runDiagnostic({ origin, tagsTimeoutMs: 1000,
      chatTimeoutMs: 1000 });
    assert.equal(report.requestCount, 1);
    assert.equal(report.qualificationCredit, false);
    assert.equal(report.preModel.identityMatched, true);
    assert.equal(report.postModel.identityMatched, true);
    assert.equal(report.chat.status, 200);
    assert.equal(report.chat.termination, 'complete');
    assert.equal(report.chat.localSocketRetired, true);
    assert.equal(report.chat.terminalDone, true);
    assert.equal(report.chat.promptEvalCount, 12000);
    assert.equal(report.chat.evalCount, 20);
    assert.equal(JSON.stringify(report).includes('synthetic'), false);
  });
  assert.equal(posts, 1); assert.equal(tags, 2);
  assert.equal(observedHash, diagnostic.REQUEST_SHA256);
  assert.equal(observedBytes, diagnostic.REQUEST_BYTES);
});

test('wrong model digest prevents the only generation POST', async () => {
  let posts = 0;
  await withServer((request, response) => {
    if (request.url === '/api/tags') {
      response.writeHead(200).end(JSON.stringify({models:[{name:'llama3.1:8b',digest:'0'.repeat(64)}]}));
    } else { posts++; response.writeHead(500).end(); }
  }, async origin => {
    const report = await diagnostic.runDiagnostic({ origin, tagsTimeoutMs: 1000,
      chatTimeoutMs: 1000 });
    assert.equal(report.requestCount, 0);
    assert.equal(report.preModel.identityMatched, false);
    assert.equal(report.chat, null);
  });
  assert.equal(posts, 0);
});

test('never-ending stream hits wall deadline, closes socket, and still checks model afterward', async () => {
  let posts = 0, tags = 0;
  let releaseClosed;
  const closed = new Promise(resolve => { releaseClosed = resolve; });
  await withServer((request, response) => {
    if (request.url === '/api/tags') { tags++; response.writeHead(200).end(validTags()); return; }
    posts++;
    request.on('data', () => {});
    request.on('end', () => {
      response.once('close', releaseClosed);
      response.writeHead(200);
      response.write('{"model":"llama3.1:8b","done":false}\n');
    });
  }, async origin => {
    const report = await diagnostic.runDiagnostic({ origin, tagsTimeoutMs: 1000,
      chatTimeoutMs: 30 });
    assert.equal(report.chat.termination, 'deadline');
    assert.equal(report.chat.localSocketRetired, true);
    assert.equal(report.chat.status, 200);
    assert.equal(report.chat.responseSha256, null);
    assert.equal(report.postModel.identityMatched, true);
    await Promise.race([closed, new Promise((_, reject) => setTimeout(() => reject(new Error('socket remained live')), 1000))]);
  });
  assert.equal(posts, 1); assert.equal(tags, 2);
});

test('oversized response is cancelled; malformed frames and postflight drift never become credit', async () => {
  let posts = 0, tags = 0;
  await withServer((request, response) => {
    if (request.url === '/api/tags') {
      tags++;
      response.writeHead(200).end(tags === 1 ? validTags()
        : JSON.stringify({models:[{name:'llama3.1:8b',digest:'f'.repeat(64)}]}));
      return;
    }
    posts++;
    request.on('data', () => {});
    request.on('end', () => { response.writeHead(200).end('x'.repeat(100)); });
  }, async origin => {
    const report = await diagnostic.runDiagnostic({ origin, tagsTimeoutMs: 1000,
      chatTimeoutMs: 1000, responseLimit: 32 });
    assert.equal(report.chat.termination, 'response_limit');
    assert.equal(report.chat.responseSha256, null);
    assert.equal(report.postModel.identityMatched, false);
    assert.equal(report.qualificationCredit, false);
  });
  assert.equal(posts, 1); assert.equal(tags, 2);
  const malformed = diagnostic.summarizeChat({ status: 200, termination: 'complete',
    body: Buffer.from('not-json\n'), responseBytes: 9, elapsedMs: 1 });
  assert.equal(malformed.frameParse, 'invalid_json');
  assert.equal(malformed.terminalDone, false);
});

test('truncated stream is not reported as complete and does not prompt a second POST', async () => {
  let posts = 0, tags = 0;
  await withServer((request, response) => {
    if (request.url === '/api/tags') { tags++; response.writeHead(200).end(validTags()); return; }
    posts++;
    request.on('data', () => {});
    request.on('end', () => {
      response.writeHead(200);
      response.write('{"model":"llama3.1:8b","done":false}\n');
      response.destroy();
    });
  }, async origin => {
    const report = await diagnostic.runDiagnostic({ origin, tagsTimeoutMs: 1000,
      chatTimeoutMs: 1000 });
    assert.equal(report.requestCount, 1);
    assert.notEqual(report.chat.termination, 'complete');
    assert.equal(report.chat.responseSha256, null);
    assert.equal(report.postModel.identityMatched, true);
  });
  assert.equal(posts, 1); assert.equal(tags, 2);
});
