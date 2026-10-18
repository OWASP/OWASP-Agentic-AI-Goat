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
function setup(work, additional={}) {
  let calls = 0;
  const router = createBoundAvatarUploadRouter({
    ...additional,
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
    svgAssessment: {
      runAttempt() { throw Error("Unexpected SVG assessment"); },
      readOutcome() { throw Error("Unexpected SVG saved outcome"); }
    },
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
  const handler = method => router.stack.find(layer => layer.route?.methods[method] && layer.route.path === (method === 'post' ? '/agents/customer/avatar-upload/assess' : '/agents/customer/avatar-upload/assess/:sessionId/:requestId')).route.stack.at(-1).handle;
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
    handler,router,
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

test('V07 protected preview routes preserve exact closed DTOs and pending assessment GET distinction',async()=>{
 let previews=0,reads=0,grades=0;const result={operationId:id,uploadOperationId:id,status:'executed',sourceSha256:'a'.repeat(64),text:'Original final preview response.',replayed:false};
 const f=setup(()=>{throw Error('V06 must remain separate');},{polyglotPreview:{async readiness(){return{ready:true};},async run(input){assert.deepEqual(Object.keys(input).sort(),['persona','personaSession','requestId','scope','sessionId','signal']);previews++;return result;},async read(){reads++;return{...result,replayed:true};}},polyglotAssessment:{async runAttempt(){grades++;return{completed:false,status:'ineligible',modelEvaluated:false};},async readOutcome(){return{completed:false,status:'pending',modelEvaluated:false};}}});
 async function call(method,suffix,mutate=()=>{}){const req=f.req(),res=f.res();if(method==='get')req.body={};mutate(req);const route=f.router.stack.find(x=>x.route?.methods[method]&&x.route.path===`/agents/customer/avatar-upload/${suffix}`);await route.route.stack.at(-1).handle(req,res);return res;}
 assert.deepEqual((await call('post','polyglot-preview')).writes,[result]);assert.deepEqual((await call('get','polyglot-preview/:sessionId/:requestId')).writes,[{...result,replayed:true}]);
 assert.equal((await call('get','polyglot-assess/:sessionId/:requestId')).writes[0].status,'pending');assert.equal(grades,0);
 assert.equal((await call('post','polyglot-preview',r=>r.body.bytes='forged')).code,400);assert.equal(previews,1);assert.equal(reads,1);
 const bad={...result,text:null};Object.assign(result,bad);assert.equal((await call('post','polyglot-preview')).code,400);
});
test('V07 readiness is false without configured worker while old upload routes stay mounted',async()=>{
 const f=setup(()=>{}),req=f.req(),res=f.res();req.body={};const route=f.router.stack.find(x=>x.route?.path==='/agents/customer/avatar-upload/polyglot-readiness');await route.route.stack.at(-1).handle(req,res);assert.deepEqual(res.writes,[{ready:false}]);assert.equal(f.router.stack.some(x=>x.route?.path==='/agents/customer/avatar-upload/polyglot-preview'),false);
});
