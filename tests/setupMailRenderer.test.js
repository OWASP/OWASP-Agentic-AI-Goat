'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {ensureMailRenderer}=require('../scripts/setup-application');
const renderer=()=>({component:{id:'SecureShop.MailMessageBody',sourceSha256:'a'.repeat(64),artifactSha256:'b'.repeat(64)}});
test('setup mail build uses admitted Node/npm/environment and validates artifact without browser launch',async()=>{const calls=[],environment={PATH:'/owned'},admittedNpm={command:'/owned/node',prefix:['/owned/npm.cjs'],environment};const result=await ensureMailRenderer({root:'/owned/repo',admittedNpm,runCommand:async(command,args,cwd,env)=>{calls.push('build');assert.equal(command,admittedNpm.command);assert.deepEqual(args,['/owned/npm.cjs','run','build:mail-renderer']);assert.equal(cwd,'/owned/repo/client');assert.equal(env,environment);},loadMailRenderer:()=>{calls.push('load');return renderer();}});assert.deepEqual(calls,['build','load']);assert.equal(result.artifactReady,true);assert.equal(result.ready,undefined);});
test('failed mail build and invalid artifact stop setup',async()=>{await assert.rejects(ensureMailRenderer({root:'/owned',runCommand:async()=>{throw Error('failed build');},loadMailRenderer:()=>assert.fail('must not load')}),/failed build/);await assert.rejects(ensureMailRenderer({root:'/owned',runCommand:async()=>{},loadMailRenderer:()=>({component:{id:'Other'}})}),/verification failed/);});

const { ensureTicketRenderer, prepareInstalledRuntime } = require('../scripts/setup-application');
const ticketArtifact = () => ({ component: { id: 'SecureShop.AdminTicketBody',
  sourceSha256: 'a'.repeat(64), artifactSha256: 'b'.repeat(64) } });

test('ticket setup builds through admitted npm before validating the exact client artifact without browser execution', async () => {
  const calls = [], environment = { PATH: '/owned' };
  const admittedNpm = { command: '/owned/node', prefix: ['/owned/npm.cjs'], environment };
  const result = await ensureTicketRenderer({ root: '/owned/repo', admittedNpm,
    runCommand: async (command, args, cwd, env) => {
      calls.push('build'); assert.equal(command, admittedNpm.command);
      assert.deepEqual(args, ['/owned/npm.cjs', 'run', 'build:ticket-renderer']);
      assert.equal(cwd, '/owned/repo/client'); assert.equal(env, environment);
    }, loadTicketRenderer: () => { calls.push('load'); return ticketArtifact(); } });
  assert.deepEqual(calls, ['build', 'load']);
  assert.deepEqual(result, { artifactReady: true, ...ticketArtifact().component });
  assert.equal(result.ready, undefined, 'artifact admission is not browser/Judge qualification');
});

test('ticket build and artifact failures stop setup before runtime readiness', async t => {
  await assert.rejects(ensureTicketRenderer({ root: '/owned',
    runCommand: async () => { throw Error('ticket build failed'); },
    loadTicketRenderer: () => assert.fail('must not load after failed build') }), /ticket build failed/);
  const prepare = loadTicketRenderer => prepareInstalledRuntime({ root: '/owned', install: false,
    env: {}, runCommand: async () => {}, loadTicketRenderer,
    loadRenderer: () => ({ renderReviewCard: async p => p.body }), loadMailRenderer: renderer,
    loadProductRenderer: () => ({ componentId: 'SecureShop.Product.Description',
      sourceSha256: 'a'.repeat(64), artifactSha256: 'b'.repeat(64),
      renderProductDescription: async p => p.description_html }),
    verifyRuntime: () => assert.fail('must not advance model/browser readiness') });
  for (const [name, change] of Object.entries({ component: r => { r.component.id = 'Other'; },
    source: r => { r.component.sourceSha256 = 'bad'; },
    artifact: r => { r.component.artifactSha256 = 'bad'; } })) {
    await t.test(name, async () => {
      const artifact = ticketArtifact(); change(artifact);
      await assert.rejects(prepare(() => artifact), /ticket renderer verification failed/);
    });
  }
  const failure = Object.assign(new Error('source admission failed'), { code: 'SECURESHOP_TICKET_RENDERER_UNAVAILABLE' });
  await assert.rejects(prepare(() => { throw failure; }), error => error === failure);
});

const { ensureSearchEchoRenderer } = require('../scripts/setup-application');
const searchEchoArtifact = () => ({ component: { id: 'SecureShop.SearchEcho',
  sourceSha256: 'a'.repeat(64), artifactSha256: 'b'.repeat(64) } });

test('search-echo setup builds through admitted npm before validating the exact client artifact without browser execution', async () => {
  const calls = [], environment = { PATH: '/owned' };
  const admittedNpm = { command: '/owned/node', prefix: ['/owned/npm.cjs'], environment };
  const result = await ensureSearchEchoRenderer({ root: '/owned/repo', admittedNpm,
    runCommand: async (command, args, cwd, env) => {
      calls.push('build'); assert.equal(command, admittedNpm.command);
      assert.deepEqual(args, ['/owned/npm.cjs', 'run', 'build:search-echo-renderer']);
      assert.equal(cwd, '/owned/repo/client'); assert.equal(env, environment);
    }, loadSearchEchoRenderer: () => { calls.push('load'); return searchEchoArtifact(); } });
  assert.deepEqual(calls, ['build', 'load']);
  assert.deepEqual(result, { artifactReady: true, ...searchEchoArtifact().component });
  assert.equal(result.ready, undefined, 'artifact admission is not browser/Judge qualification');
});

test('search-echo build and artifact failures stop setup before runtime readiness', async t => {
  await assert.rejects(ensureSearchEchoRenderer({ root: '/owned',
    runCommand: async () => { throw Error('search-echo build failed'); },
    loadSearchEchoRenderer: () => assert.fail('must not load after failed build') }), /search-echo build failed/);
  const prepare = loadSearchEchoRenderer => prepareInstalledRuntime({ root: '/owned', install: false,
    env: {}, runCommand: async () => {}, loadSearchEchoRenderer, loadTicketRenderer: ticketArtifact,
    loadRenderer: () => ({ renderReviewCard: async p => p.body }), loadMailRenderer: renderer,
    loadProductRenderer: () => ({ componentId: 'SecureShop.Product.Description',
      sourceSha256: 'a'.repeat(64), artifactSha256: 'b'.repeat(64),
      renderProductDescription: async p => p.description_html }),
    verifyRuntime: () => assert.fail('must not advance model/browser readiness') });
  for (const [name, change] of Object.entries({ component: r => { r.component.id = 'Other'; },
    source: r => { r.component.sourceSha256 = 'bad'; },
    artifact: r => { r.component.artifactSha256 = 'bad'; } })) {
    await t.test(name, async () => {
      const artifact = searchEchoArtifact(); change(artifact);
      await assert.rejects(prepare(() => artifact), /search-echo renderer verification failed/);
    });
  }
  const failure = Object.assign(new Error('source admission failed'), { code: 'SECURESHOP_SEARCH_ECHO_RENDERER_UNAVAILABLE' });
  await assert.rejects(prepare(() => { throw failure; }), error => error === failure);
});


const { ensurePolicyOutputRenderer } = require('../scripts/setup-application');
test('V27 setup admits the exact reply artifact through existing npm build without browser execution', async () => {
  const calls = [], environment = { PATH: '/owned' };
  const admittedNpm = { command: '/owned/node', prefix: ['/owned/npm.cjs'], environment };
  const artifact = { component: { id: 'SecureShop.PolicyFinalResponse',
    sourceSha256: 'a'.repeat(64), artifactSha256: 'b'.repeat(64) } };
  const result = await ensurePolicyOutputRenderer({ root: '/owned/repo', admittedNpm,
    runCommand: async (command, args, cwd, env) => {
      calls.push('build'); assert.equal(command, admittedNpm.command);
      assert.deepEqual(args, ['/owned/npm.cjs', 'run', 'build:policy-output-renderer']);
      assert.equal(cwd, '/owned/repo/client'); assert.equal(env, environment);
    }, loadPolicyOutputRenderer: () => { calls.push('load'); return artifact; } });
  assert.deepEqual(calls, ['build', 'load']);
  assert.deepEqual(result, { artifactReady: true, ...artifact.component });
  assert.equal(result.ready, undefined);
  await assert.rejects(ensurePolicyOutputRenderer({ root: '/owned', runCommand: async () => {},
    loadPolicyOutputRenderer: () => ({ component: { ...artifact.component, id: 'Other' } }) }),
  /policy-output renderer verification failed/);
});
