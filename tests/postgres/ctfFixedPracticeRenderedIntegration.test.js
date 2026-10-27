'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const integration=require('./support/ctfFixedPracticeRenderedIntegration');
const facet=require('./support/ctfFixedPracticeRenderedCases');

test('mounted prelude calls the actual learner export and limits API mutations',()=>{
  const origin='http://127.0.0.1:12345';
  const allowed=(method,url)=>integration.preludeRequestAllowed(method,new URL(url,origin),origin);
  for(const route of ['/ctf','/ctf/challenge','/static/js/main.js',
    '/api/auth/status','/api/ctf/stages',
    '/api/ctf/operations/11111111-1111-4111-8111-111111111111'])
    assert.equal(allowed('GET',route),true,route);
  for(const route of ['/api/ctf/register','/api/ctf/stage/1/start'])
    assert.equal(allowed('POST',route),true,route);
  for(const [method,url] of [['GET','https://example.invalid/ctf'],
    ['GET','/api/ctf/admin/stages'],['GET','/api/ctf/config?override=true'],
    ['GET','/ctf#foreign'],['POST','/api/ctf/stage/1/attempt'],
    ['POST','/api/ctf/stage/1/practice'],['POST','/api/ctf/stage/1/hint'],
    ['DELETE','/api/ctf/register'],['POST','/static/js/main.js']])
    assert.equal(allowed(method,url),false,`${method} ${url}`);
});

test('both browser gates admit only the existing exact read-only revision poll query',()=>{
  const origin='http://127.0.0.1:12345';
  for(const query of ['?workshops=*','?workshops=%2A']){
    const url=new URL('/api/changes/revisions'+query,origin);
    assert.equal(facet.fixedPracticeQueryAllowed('GET',url),true);
    assert.equal(integration.preludeRequestAllowed('GET',url,origin),true);
  }
  for(const [method,route] of [
    ['GET','/api/changes/revisions?workshops=ctf'],
    ['GET','/api/changes/revisions?workshops=*&workshops=*'],
    ['GET','/api/changes/revisions?workshops=*&override=true'],
    ['GET','/api/changes/revisions?workshops=*#extra'],
    ['POST','/api/changes/revisions?workshops=*'],
    ['GET','/api/ctf/config?workshops=*'],
    ['GET','/static/js/main.js?workshops=*']]){
    const url=new URL(route,origin);
    assert.equal(facet.fixedPracticeQueryAllowed(method,url),false,route);
    assert.equal(integration.preludeRequestAllowed(method,url,origin),false,route);
  }
});

test('Fixed Practice owns a distinct exact four-store name and rejects cross-cohort names',()=>{
  const nonce='012345abcdef';
  for(const state of ['FRESH','POPULATED'])for(const kind of ['IDENTITY','CTF']){
    const name=`/dvaia_test_ctf_fixed_practice_${state[0].toLowerCase()}_${kind[0].toLowerCase()}_${nonce}`;
    assert.equal(integration.assertDatabaseName(name,state,kind,nonce),nonce);
    assert.throws(()=>integration.assertDatabaseName(name,state,kind,'ffffffffffff'));
    assert.throws(()=>integration.assertDatabaseName(name,state==='FRESH'?'POPULATED':'FRESH',kind));
  }
  for(const bad of ['/dvaia_test_ctf_learner_attempt_gate_f_i_012345abcdef',
    '/dvaia_test_ctf_fixed_practice_f_i_012345abcdef_extra',
    '/dvaia_test_ctf_fixed_practice_f_i_012345ABCDEf'])
    assert.throws(()=>integration.assertDatabaseName(bad,'FRESH','IDENTITY'));
});

test('Fixed provider reserves before body work and cannot spend a third call or Judge route',()=>{
  const ledger=[];
  assert.equal(integration.reserveFixedPracticeProvider(ledger,'/api/generate','fail'),ledger[0]);
  assert.equal(integration.reserveFixedPracticeProvider(ledger,'/api/generate','fail'),ledger[1]);
  assert.equal(ledger.length,facet.LIMITS.providerCalls);
  assert.throws(()=>integration.reserveFixedPracticeProvider(ledger,'/api/generate','fail'));
  assert.throws(()=>integration.reserveFixedPracticeProvider([], '/api/chat','fail'));
});

test('shared mounted fixture has separate selector and a real stage-authority interleave',()=>{
  const source=fs.readFileSync(path.join(__dirname,'ctfAuthorityApplication.integration.test.js'),'utf8');
  const owned=fs.readFileSync(path.join(__dirname,'support/ctfFixedPracticeRenderedIntegration.js'),'utf8');
  assert(source.includes("const fixedPracticeOnly=process.env.CTF_FIXED_PRACTICE_RENDERED_ISOLATED==='1'"));
  assert(source.includes('Number(attemptGateOnly)+Number(fixedPracticeOnly)===1'));
  assert(source.includes('practiceBarrier.wrap(physical)'));
  assert(source.includes('closePracticeCaptureStale:()=>practiceBarrier.close()'));
  assert(source.includes("if(fixedPracticeOnly){\n   await require('./support/ctfFixedPracticeRenderedIntegration').runFixedPracticeCohort"));
  assert(owned.includes("await mutate(admin,'catalog_mutation',{action:'update',stageId:'1'"));
  assert(owned.includes("holdTransport(1)"));
  assert(owned.includes("postProviderStale++"));
  assert(owned.includes("learner.outboxFor(i,c,beforeRegister,'register'"));
  assert(owned.includes("learner.outboxFor(i,c,beforeStart,'start'"));
  assert(owned.includes('facet.runCtfFixedPracticeRenderedCases({page,origin'));
  assert(!owned.includes('practiceCapture=async'));
  assert(!owned.includes('practiceRevalidate=async'));
});

test('practice stale edit runs only after real identity COMMIT and physical release', async()=>{
  const owner={ownerKey:JSON.stringify(['CTF','2403'])};
  let current=owner, held=true, releases=0, edits=0;
  const barrier=integration.createCommittedPracticeBarrier({
    currentExecution:()=>current,actorId:2403,stageId:1});
  const physical={async query(sql){if(sql==='COMMIT')assert.equal(held,true);
    return {command:sql};},release(){assert.equal(held,true);held=false;releases++;}};
  const wrapped=barrier.wrap(physical);
  const settled=barrier.arm(async()=>{assert.equal(held,false);
    edits++;return {operationId:'canonical-stage-edit'};});
  const query='SELECT g.revision::text AS global_revision FROM identity.ctf_authority g';
  await wrapped.query(query,[2403,1]);
  assert.equal(edits,0);
  assert.deepEqual(await wrapped.query('COMMIT'),{command:'COMMIT'});
  assert.deepEqual(await settled,{operationId:'canonical-stage-edit'});
  wrapped.release();
  assert.equal(releases,1);
  assert.equal(edits,1);
  await assert.rejects(wrapped.query('SELECT 1'),/cannot be queried again/);
  await barrier.close();
});

test('practice barrier rejects foreign owner and failed COMMIT without editing or reusing client', async()=>{
  const owner={ownerKey:JSON.stringify(['CTF','2403'])};
  let current={ownerKey:JSON.stringify(['CTF','1001'])},edits=0,releases=0;
  const barrier=integration.createCommittedPracticeBarrier({
    currentExecution:()=>current,actorId:2403,stageId:1});
  const first=barrier.wrap({async query(sql){return {command:sql};},
    release(){releases++;}});
  const settled=barrier.arm(async()=>{edits++;});
  const query='SELECT g.revision::text AS global_revision FROM identity.ctf_authority g';
  await first.query(query,[2403,1]);
  await first.query('COMMIT');first.release();
  assert.equal(edits,0);
  current=owner;
  const broken=barrier.wrap({async query(sql){if(sql==='COMMIT')throw Error('commit failed');
    return {command:sql};},release(){releases++;}});
  await broken.query(query,[2403,1]);
  await assert.rejects(broken.query('COMMIT'),/commit failed/);
  await assert.rejects(settled,/commit failed/);
  broken.release();broken.release();
  assert.equal(releases,2);
  assert.equal(edits,0);
  await barrier.close();
});

test('late identity SELECT after transaction abort cannot claim or dispatch a stale ticket', async()=>{
  const owner={ownerKey:JSON.stringify(['CTF','2403'])};
  let resolveSql,releases=0,edits=0;
  const barrier=integration.createCommittedPracticeBarrier({
    currentExecution:()=>owner,actorId:2403,stageId:1});
  const wrapped=barrier.wrap({query:()=>new Promise(resolve=>{resolveSql=resolve;}),
    release(){releases++;}});
  const settled=barrier.arm(async()=>{edits++;});
  const pending=wrapped.query('SELECT g.revision::text AS global_revision FROM identity.ctf_authority g',[2403,1]);
  wrapped.release(true);wrapped.release(true);
  resolveSql({rows:[{global_revision:'1'}]});
  await assert.rejects(pending,{code:'CTF_PRACTICE_BARRIER_ABORTED'});
  await barrier.close();
  await assert.rejects(settled,{code:'CTF_PRACTICE_BARRIER_UNREACHED'});
  assert.equal(releases,1);assert.equal(edits,0);
});

test('late COMMIT after transaction abort cannot double-release or run canonical mutation', async()=>{
  const owner={ownerKey:JSON.stringify(['CTF','2403'])};
  let resolveCommit,releases=0,edits=0;
  const barrier=integration.createCommittedPracticeBarrier({
    currentExecution:()=>owner,actorId:2403,stageId:1});
  const wrapped=barrier.wrap({query:sql=>sql==='COMMIT'
    ?new Promise(resolve=>{resolveCommit=resolve;}):Promise.resolve({command:sql}),
    release(){releases++;}});
  const settled=barrier.arm(async()=>{edits++;});
  await wrapped.query('SELECT g.revision::text AS global_revision FROM identity.ctf_authority g',[2403,1]);
  const pending=wrapped.query('COMMIT');
  wrapped.release(true);wrapped.release(true);
  resolveCommit({command:'COMMIT'});
  await assert.rejects(pending,{code:'CTF_PRACTICE_BARRIER_ABORTED'});
  await assert.rejects(settled,{code:'CTF_PRACTICE_BARRIER_ABORTED'});
  await barrier.close();
  assert.equal(releases,1);assert.equal(edits,0);
});

test('unreached and context-changed barriers settle without a hook or client reuse', async()=>{
  const owner={ownerKey:JSON.stringify(['CTF','2403'])};
  let current=owner,releases=0,edits=0;
  const barrier=integration.createCommittedPracticeBarrier({
    currentExecution:()=>current,actorId:2403,stageId:1});
  const unreached=barrier.arm(async()=>{edits++;});
  const wrapped=barrier.wrap({query:async sql=>({command:sql}),release(){releases++;}});
  await wrapped.query('SELECT 1');
  await barrier.close();
  await assert.rejects(unreached,{code:'CTF_PRACTICE_BARRIER_UNREACHED'});
  wrapped.release();
  assert.equal(releases,1);assert.equal(edits,0);

  const second=integration.createCommittedPracticeBarrier({
    currentExecution:()=>current,actorId:2403,stageId:1});
  const selected=second.arm(async()=>{edits++;});
  const client=second.wrap({query:async sql=>({command:sql}),release(){releases++;}});
  await client.query('SELECT g.revision::text AS global_revision FROM identity.ctf_authority g',[2403,1]);
  current={ownerKey:owner.ownerKey};
  await assert.rejects(client.query('COMMIT'),{code:'CTF_PRACTICE_BARRIER_ABORTED'});
  await assert.rejects(selected,{code:'CTF_PRACTICE_BARRIER_ABORTED'});
  client.release();
  await second.close();
  assert.equal(releases,2);assert.equal(edits,0);
});

test('release-queued close vetoes the hook before its microtask can invoke it', async()=>{
  const owner={ownerKey:JSON.stringify(['CTF','2403'])};
  let closing,releases=0,edits=0;
  const barrier=integration.createCommittedPracticeBarrier({
    currentExecution:()=>owner,actorId:2403,stageId:1});
  const wrapped=barrier.wrap({query:async sql=>({command:sql}),release(){
    releases++;
    queueMicrotask(()=>{closing=barrier.close();});
  }});
  const settled=barrier.arm(async()=>{edits++;return {operationId:'must-not-publish'};});
  await wrapped.query('SELECT g.revision::text AS global_revision FROM identity.ctf_authority g',[2403,1]);
  await assert.rejects(wrapped.query('COMMIT'),{code:'CTF_PRACTICE_BARRIER_ABORTED'});
  await assert.rejects(settled,{code:'CTF_PRACTICE_BARRIER_ABORTED'});
  await closing;
  assert.equal(releases,1);assert.equal(edits,0);
});

test('close after hook invocation drains work but cannot publish its late success', async()=>{
  const owner={ownerKey:JSON.stringify(['CTF','2403'])};
  let enter,finish,releases=0,edits=0;
  const entered=new Promise(resolve=>{enter=resolve;});
  const held=new Promise(resolve=>{finish=resolve;});
  const barrier=integration.createCommittedPracticeBarrier({
    currentExecution:()=>owner,actorId:2403,stageId:1});
  const wrapped=barrier.wrap({query:async sql=>({command:sql}),release(){releases++;}});
  const settled=barrier.arm(async()=>{edits++;enter();await held;
    return {operationId:'must-not-publish'};});
  await wrapped.query('SELECT g.revision::text AS global_revision FROM identity.ctf_authority g',[2403,1]);
  const committed=wrapped.query('COMMIT');
  const rejected=assert.rejects(committed,{code:'CTF_PRACTICE_BARRIER_ABORTED'});
  await entered;
  const closing=barrier.close();
  finish();
  await rejected;
  await assert.rejects(settled,{code:'CTF_PRACTICE_BARRIER_ABORTED'});
  await closing;
  assert.equal(releases,1);assert.equal(edits,1);
});
