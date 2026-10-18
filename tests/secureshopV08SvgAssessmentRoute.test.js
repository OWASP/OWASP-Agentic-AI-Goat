'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const {
  EventEmitter
} = require('node:events');
const {
  createBoundAvatarUploadRouter
} = require('../server/routes/secureshop/boundAvatarUpload');
const id = '30000000-0000-4000-8000-000000000091';
function setup(work) {
  let calls = 0;
  const router = createBoundAvatarUploadRouter({
    launches: {
      resolveCapability() {}
    },
    authenticatePersona() {},
    graph: {
      createSession() {},
      run() {}
    },
    saved: {
      read() {},
      asset() {}
    },
    assessment: { async runAttempt(){ throw Error('V06 assessment must not execute'); },
      async readOutcome(){ throw Error('V06 assessment must not execute'); } },
    svgAssessment: {
      async runAttempt(input) { calls++; return work(input); },
      async readOutcome(input) { calls++; return work(input); }
    }
  });
  const handler = method => router.stack.find(layer => layer.route?.methods[method] && layer.route.path === (method === 'post' ? '/agents/customer/avatar-upload/svg-assess' : '/agents/customer/avatar-upload/svg-assess/:sessionId/:requestId')).route.stack.at(-1).handle;
  const req = () => Object.assign(new EventEmitter(), {
    ssLaunch: {},
    ssUser: {
      id: 1,
      role: 'customer'
    },
    ssPersonaSession: {
      sessionId: id,
      authorityVersion: '1'
    },
    body: {
      sessionId: id,
      requestId: id
    },
    params: {
      sessionId: id,
      requestId: id
    },
    query: {},
    is: () => true,
    aborted: false
  });
  const res = () => Object.assign(new EventEmitter(), {
    destroyed: false,
    writableEnded: false,
    writes: [],
    status(code) {
      this.code = code;
      return this;
    },
    json(value) {
      this.writes.push(value);
      return this;
    }
  });
  return {
    handler,
    req,
    res,
    calls: () => calls
  };
}
for (const method of ['post', 'get']) {
  test(`SVG assessment ${method} preabort reaches no service`, async () => {
    const f = setup(() => {
        throw Error('must not execute');
      }),
      req = f.req(),
      res = f.res();
    req.aborted = true;
    if (method === 'get') req.body = {};
    await f.handler(method)(req, res);
    assert.equal(f.calls(), 0);
    assert.deepEqual(res.writes, []);
  });
  test(`SVG assessment ${method} close fences a late result`, async () => {
    let resolve, entered;
    const ready = new Promise(r => {
      entered = r;
    });
    const f = setup(input => {
      entered();
      return new Promise(r => {
        resolve = () => {
          assert.equal(input.signal.aborted, true);
          r({
            completed: false,
            status: 'ineligible',
            modelEvaluated: false
          });
        };
      });
    });
    const req = f.req(),
      res = f.res();
    if (method === 'get') req.body = {};
    const pending = f.handler(method)(req, res);
    await ready;
    res.emit('close');
    resolve();
    await pending;
    assert.equal(f.calls(), 1);
    assert.deepEqual(res.writes, []);
  });
}
test('SVG assessment rejects client evidence and projects no private fields', async () => {
  const f = setup(() => ({
    completed: true,
    replayed: false,
    judgment: {
      verdict: 'pass',
      evaluationId: id,
      canRetry: false,
      privatePacket: 'secret'
    }
  }));
  const bad = f.req(),
    badRes = f.res();
  bad.body.evidence = 'client';
  await f.handler('post')(bad, badRes);
  assert.equal(badRes.code, 400);
  assert.equal(f.calls(), 0);
  const response = f.res();
  await f.handler('post')(f.req(), response);
  assert.equal(response.code, 200);
  assert.deepEqual(response.writes[0], {
    completed: true,
    replayed: false,
    judgment: {
      verdict: 'pass',
      evaluationId: id,
      canRetry: false
    }
  });
});
