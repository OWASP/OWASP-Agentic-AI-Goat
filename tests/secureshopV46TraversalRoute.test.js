'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { Readable } = require('node:stream');
const { EventEmitter } = require('node:events');
const { createBoundAvatarUploadRouter } = require('../server/routes/secureshop/boundAvatarUpload');

const id = suffix => `46000000-0000-4000-8000-${String(suffix).padStart(12, '0')}`;

function response() {
  let body;
  return Object.assign(new EventEmitter(), {
    destroyed: false,
    writableEnded: false,
    status(code) { this.statusCode = code; return this; },
    json(value) { body = value; return this; },
    value: () => body
  });
}

function router(overrides = {}) {
  return createBoundAvatarUploadRouter({
    launches: { resolveCapability() {} },
    authenticatePersona() {},
    graph: { createSession() {}, run() {} },
    traversalGraph: {
      async createSession() { return { id: id(1) }; },
      async run() { throw Error('Traversal graph work required'); }
    },
    saved: { read() {}, asset() {} },
    assessment: { runAttempt() {}, readOutcome() {} },
    traversalAssessment: { runAttempt() {}, readOutcome() {} },
    svgAssessment: { runAttempt() {}, readOutcome() {} },
    ...overrides
  });
}

function multipart(fields) {
  const boundary = 'v46-controlled-boundary';
  const parts = Object.entries(fields).map(([name, value]) =>
    `--${boundary}\r\nContent-Disposition: form-data; name="${name}"\r\n\r\n${value}\r\n`);
  parts.push(`--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="source.txt"\r\nContent-Type: text/plain\r\n\r\nowned-v46\r\n--${boundary}--\r\n`);
  const bytes = Buffer.from(parts.join(''));
  return Object.assign(Readable.from([bytes]), {
    headers: {
      'content-type': `multipart/form-data; boundary=${boundary}`,
      'content-length': String(bytes.length)
    },
    ssLaunch: {},
    ssUser: { id: 46, role: 'customer' },
    ssPersonaSession: { sessionId: id(2), authorityVersion: '1' },
    query: {},
    aborted: false
  });
}

test('V46 physical multipart route passes distinct source and logical filenames and returns no asset capability', async () => {
  const sessionId = id(3), requestId = id(4), operationId = id(5);
  let observed;
  const app = router({
    traversalGraph: {
      createSession() {},
      async run(input) {
        observed = input;
        return {
          text: 'Stored traversal attachment.',
          replayed: false,
          taskMetadata: { boundUpload: {
            version: 2,
            variant: 'path_traversal_upload',
            operationId,
            uploadRequestId: requestId,
            outcome: 'completed',
            operationRelativePath: 'avatars/escaped.txt',
            escapedAvatarSubdirectory: true,
            graphEffect: { private: true }
          } }
        };
      }
    }
  });
  const req = multipart({
    sessionId,
    requestId,
    message: 'Store this avatar using the supplied filename.',
    public: 'true',
    logicalFilename: '....//escaped.txt'
  });
  const res = response();
  const handler = app.stack.find(layer => layer.route?.path === '/agents/customer/avatar-upload/path-traversal/run')
    .route.stack.at(-1).handle;
  await handler(req, res);
  assert.equal(res.statusCode, 200);
  assert.equal(observed.attachment.filename, 'source.txt');
  assert.equal(observed.attachment.logicalFilename, '....//escaped.txt');
  assert.equal(observed.attachment.bytes.toString(), 'owned-v46');
  assert.deepEqual(res.value(), {
    operationId,
    uploadRequestId: requestId,
    status: 'completed',
    text: 'Stored traversal attachment.',
    sourceFilename: 'source.txt',
    filename: '....//escaped.txt',
    byteCount: 9,
    replayed: false,
    operationRelativePath: 'avatars/escaped.txt',
    escapedAvatarSubdirectory: true
  });
  assert.equal(JSON.stringify(res.value()).includes('asset'), false);
  assert.equal(JSON.stringify(res.value()).includes('private'), false);
});

test('V46 route rejects fabricated, mismatched or denied traversal destinations', async () => {
  for (const boundUpload of [
    { outcome: 'completed', operationRelativePath: 'avatars/../foreign.txt', escapedAvatarSubdirectory: true },
    { outcome: 'completed', operationRelativePath: 'avatars/.', escapedAvatarSubdirectory: true },
    { outcome: 'completed', operationRelativePath: 'avatars/..', escapedAvatarSubdirectory: true },
    { outcome: 'completed', operationRelativePath: 'avatars/escape\\name.txt', escapedAvatarSubdirectory: true },
    { outcome: 'completed', operationRelativePath: 'avatars/escape\nname.txt', escapedAvatarSubdirectory: true },
    { outcome: 'completed', operationRelativePath: 'avatars/escaped.txt', escapedAvatarSubdirectory: false },
    { outcome: 'denied', operationRelativePath: 'avatars/escaped.txt', escapedAvatarSubdirectory: true }
  ]) {
    const requestId = id(11), operationId = id(12);
    const app = router({ traversalGraph: { createSession() {}, async run() { return {
      text: 'bounded', replayed: false, taskMetadata: { boundUpload: {
        version: 2, variant: 'path_traversal_upload', operationId, uploadRequestId: requestId,
        ...boundUpload
      } }
    }; } } });
    const req = multipart({ sessionId: id(10), requestId, message: 'owned', public: 'false',
      logicalFilename: '....//escaped.txt' });
    const res = response();
    await app.stack.find(layer => layer.route?.path === '/agents/customer/avatar-upload/path-traversal/run')
      .route.stack.at(-1).handle(req, res);
    assert.equal(res.statusCode, 400);
    assert.deepEqual(res.value(), { error: 'Avatar upload unavailable' });
  }
});

test('V46 multipart route rejects extra fields before graph execution', async () => {
  let calls = 0;
  const app = router({ traversalGraph: { createSession() {}, async run() { calls++; } } });
  const req = multipart({
    sessionId: id(6), requestId: id(7), message: 'owned', public: 'false',
    logicalFilename: '....//escaped.txt', evidence: 'client supplied'
  });
  const res = response();
  const handler = app.stack.find(layer => layer.route?.path === '/agents/customer/avatar-upload/path-traversal/run')
    .route.stack.at(-1).handle;
  await handler(req, res);
  assert.equal(res.statusCode, 400);
  assert.equal(calls, 0);
  assert.deepEqual(res.value(), { error: 'Avatar upload unavailable' });
});

test('V46 assessment and saved GET dispatch only exact canonical identifiers', async () => {
  const sessionId = id(8), requestId = id(9), evaluationId = id(10);
  let assessed, saved;
  const app = router({
    saved: {
      async read(input) { saved = input; return { status: 'completed', traversal: true }; },
      asset() {}
    },
    traversalAssessment: {
      async runAttempt(input) {
        assessed = input;
        return { completed: true, replayed: false,
          judgment: { verdict: 'pass', evaluationId, canRetry: false } };
      },
      readOutcome() {}
    }
  });
  const base = () => Object.assign(new EventEmitter(), {
    ssLaunch: {}, ssUser: { id: 46, role: 'customer' },
    ssPersonaSession: { sessionId: id(2), authorityVersion: '1' },
    query: {}, params: {}, body: {}, aborted: false, is: () => true
  });
  const post = base();
  post.body = { sessionId, requestId };
  const postRes = response();
  await app.stack.find(layer => layer.route?.path === '/agents/customer/avatar-upload/path-traversal/assess')
    .route.stack.at(-1).handle(post, postRes);
  assert.equal(postRes.statusCode, 200);
  assert.equal(assessed.sessionId, sessionId);
  assert.equal(assessed.requestId, requestId);
  assert.equal(assessed.signal instanceof AbortSignal, true);
  assert.deepEqual(postRes.value(), { completed: true, replayed: false,
    judgment: { verdict: 'pass', evaluationId, canRetry: false } });

  const get = base();
  get.params = { requestId };
  const getRes = response();
  await app.stack.find(layer => layer.route?.path === '/agents/customer/avatar-upload/path-traversal/requests/:requestId')
    .route.stack.at(-1).handle(get, getRes);
  assert.equal(getRes.statusCode, 200);
  assert.equal(saved.uploadRequestId, requestId);
  assert.equal(saved.persona.id, 46);
  assert.deepEqual(getRes.value(), { status: 'completed', traversal: true });
});
