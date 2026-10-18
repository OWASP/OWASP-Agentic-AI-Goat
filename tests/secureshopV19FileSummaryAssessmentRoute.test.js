'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const {
  EventEmitter
} = require('node:events');
const {
  createBoundFileSummaryRouter
} = require('../server/routes/secureshop/boundFileSummary');
const id = '30000000-0000-4000-8000-000000000091';
function setup(work) {
  let calls = 0;
  const router = createBoundFileSummaryRouter({
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
    modeAuthority: { capture() {}, assertToken() {} },
    assessment: {
      async runAttempt(input) {
        calls++;
        return work(input);
      },
      async readOutcome(input) {
        calls++;
        return work(input);
      }
    }
  });
  const handler = method => router.stack.find(layer => layer.route?.methods[method] && layer.route.path === (method === 'post' ? '/agents/customer/file-summary/assess' : '/agents/customer/file-summary/assess/:sessionId/:requestId')).route.stack.at(-1).handle;
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
  test(`assessment ${method} preabort reaches no service`, async () => {
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
  test(`assessment ${method} close fences a late result`, async () => {
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
test('assessment rejects client evidence and projects no private fields', async () => {
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

test('file-summary route truthfully exposes an evidence size limit without a Judge result', async () => {
  const value = { completed: false, status: 'unavailable', modelEvaluated: false, reason: 'evidence_size_limit' };
  const f = setup(async () => value), req = f.req(), res = f.res();
  await f.handler('post')(req, res);
  assert.deepEqual(res.writes, [value]);
  assert.equal(f.calls(), 1);
});
