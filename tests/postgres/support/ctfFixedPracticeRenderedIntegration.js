'use strict';
// Separate, controlled-only native fixture for the real mounted Fixed practice route.
// It never treats a synthetic provider reply as an actual-model or scoring result.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const facet = require('./ctfFixedPracticeRenderedCases');

function createCommittedPracticeBarrier({ currentExecution, actorId, stageId }) {
  assert.equal(typeof currentExecution, 'function');
  assert(Number.isSafeInteger(actorId) && actorId > 0);
  assert(Number.isSafeInteger(stageId) && stageId > 0);
  let armed = null, closed = false;
  const running = new Map();
  const selectedTickets = new Set();
  const aborted = reason => Object.assign(Error(reason),
    { code: 'CTF_PRACTICE_BARRIER_ABORTED' });
  const abandon = (ticket, reason) => {
    if (armed === ticket) armed = null;
    if (!ticket.done) {
      ticket.done = true; ticket.failure = reason;
      clearTimeout(ticket.timer);
      ticket.reject(reason);
    }
  };
  return Object.freeze({
    arm(hook) {
      assert.equal(typeof hook, 'function');
      assert.equal(closed, false, 'Closed practice barrier cannot arm a stale boundary');
      assert.equal(armed, null, 'Only one physical practice capture may arm a stale boundary');
      assert.equal(selectedTickets.size + running.size, 0,
        'A prior physical stale boundary must settle first');
      let resolve, reject;
      const settled = new Promise((yes, no) => { resolve = yes; reject = no; });
      settled.catch(() => {});
      const ticket = { hook, resolve, reject, done: false, execution: null,
        failure: null, timer: null };
      ticket.timer = setTimeout(() => abandon(ticket,
        Object.assign(Error('Practice stale boundary did not settle within 12 seconds'),
          { code: 'CTF_PRACTICE_BARRIER_TIMEOUT' })), 12000);
      armed = ticket;
      return settled;
    },
    wrap(physical) {
      assert.equal(typeof physical?.query, 'function');
      assert.equal(typeof physical?.release, 'function');
      let released = false, selected = null;
      const clearSelected = reason => {
        if (!selected) return;
        const ticket = selected; selected = null;
        selectedTickets.delete(ticket);
        if (reason) abandon(ticket, reason);
      };
      return Object.freeze({
        async query(sql, args) {
          assert.equal(released, false, 'Committed identity client cannot be queried again');
          let result;
          try { result = await physical.query(sql, args); }
          catch (error) {
            clearSelected(error);
            throw error;
          }
          // The transaction can time out and release the physical client while
          // its SQL promise is pending. Never act on a late result from that client.
          if (released) throw aborted('Practice identity query settled after client release');
          if (armed && typeof sql === 'string' &&
            sql.includes('SELECT g.revision::text AS global_revision') &&
            sql.includes('FROM identity.ctf_authority g')) {
            const execution = currentExecution();
            if (!closed && !armed.done &&
              execution?.ownerKey === JSON.stringify(['CTF', String(actorId)]) &&
              String(args?.[0]) === String(actorId) &&
              String(args?.[1]) === String(stageId)) {
              assert.equal(selected, null);
              selected = armed; selected.execution = execution; armed = null;
              selectedTickets.add(selected);
            }
          }
          if (sql === 'COMMIT' && selected) {
            const ticket = selected;
            if (closed || ticket.done || currentExecution() !== ticket.execution) {
              const error = ticket.failure || aborted(
                'Practice capture execution changed before committed stale boundary');
              clearSelected(error);
              released = true;
              physical.release();
              throw error;
            }
            clearSelected();
            released = true;
            try { physical.release(); }
            catch (error) { abandon(ticket, error); throw error; }
            const work = Promise.resolve().then(() => {
              if (closed || ticket.done || currentExecution() !== ticket.execution)
                throw ticket.failure || aborted(
                  'Practice stale boundary closed before canonical mutation began');
              return ticket.hook();
            });
            running.set(work, ticket);
            work.then(() => running.delete(work), () => running.delete(work));
            try {
              const operation = await work;
              if (ticket.done) throw ticket.failure;
              ticket.done = true; clearTimeout(ticket.timer); ticket.resolve(operation);
            } catch (error) { abandon(ticket, error); throw error; }
          }
          return result;
        },
        release(discard) {
          if (released) return;
          released = true;
          clearSelected(aborted('Practice capture ended before committed stale boundary'));
          physical.release(discard);
        },
      });
    },
    async close() {
      closed = true;
      if (armed) abandon(armed,
        Object.assign(Error('Practice stale boundary was not reached'),
          { code: 'CTF_PRACTICE_BARRIER_UNREACHED' }));
      for (const ticket of selectedTickets)
        abandon(ticket, aborted('Practice stale boundary closed before identity client release'));
      for (const ticket of running.values())
        abandon(ticket, aborted('Practice stale boundary closed before canonical mutation settled'));
      let timer;
      const drained = await Promise.race([
        Promise.allSettled([...running.keys()]).then(() => true),
        new Promise(resolve => { timer = setTimeout(() => resolve(false), 12000); }),
      ]);
      clearTimeout(timer);
      assert(drained && running.size === 0,
        'Committed practice barrier has unresolved canonical mutation');
      assert.equal(selectedTickets.size, 0,
        'Selected practice capture has not released its identity client');
    },
  });
}
const learner = require('./ctfLearnerEntryHintRenderedCases');
const content = require('./ctfRecoveryRenderedCases');

function preludeRequestAllowed(method, url, origin) {
  if (url.origin !== origin || !facet.fixedPracticeQueryAllowed(method, url)) return false;
  if (method === 'GET') return !url.pathname.startsWith('/api/') ||
    learner.learnerBrowserAllowed(method, url.pathname);
  return method === 'POST' && ['/api/ctf/register', '/api/ctf/stage/1/start']
    .includes(url.pathname);
}

function assertDatabaseName(pathname, state, kind, nonce = null) {
  assert(['FRESH','POPULATED'].includes(state));
  assert(['IDENTITY','CTF'].includes(kind));
  const match = pathname.match(new RegExp(
    `^/dvaia_test_ctf_fixed_practice_${state[0].toLowerCase()}_${kind[0].toLowerCase()}_([a-f0-9]{12})$`));
  assert(match, 'Exact disposable Fixed-practice database name required');
  if(nonce !== null) assert.equal(match[1],nonce);
  return match[1];
}

function reserveFixedPracticeProvider(ledger, route, mode) {
  assert.equal(route, '/api/generate', 'Fixed practice can only dispatch one guardian endpoint');
  assert(Array.isArray(ledger) && ledger.length < facet.LIMITS.providerCalls,
    'Fixed-practice provider cap must reserve before request-body read');
  const entry = {route,mode,model:null,settlement:'started'};
  ledger.push(entry);
  return entry;
}

const rawRows = async (pool, table, where = '', args = []) =>
  (await pool.query(`SELECT to_jsonb(t) AS row FROM ${table} t ${where} ORDER BY to_jsonb(t)::text`,args))
    .rows.map(value=>value.row);
const outboxRows = async pool => (await pool.query(`SELECT operation_id::text,
  sequence::text,kind,actor_id::text,session_id::text,canonical_command
  FROM identity.ctf_outbox ORDER BY sequence`)).rows;

async function runFixedPracticeCohort({state,i,c,ledger,web,origin,jwtSecret,
  contentHttp,userRequest,admin,mutate,holdTransport,serverCounts,
  armPracticeCaptureStale,closePracticeCaptureStale,practiceStatus}) {
  assert.equal(process.env.CTF_FIXED_PRACTICE_RENDERED_ISOLATED,'1');
  assert.equal(typeof armPracticeCaptureStale,'function');
  assert.equal(typeof closePracticeCaptureStale,'function');
  assert.equal(typeof practiceStatus,'function');
  const runtime = fs.realpathSync(process.env.CTF_CONTENT_RUNTIME_DIRECTORY);
  const receiptPath=path.resolve(process.env.CTF_FIXED_PRACTICE_Q05_RECEIPT);
  assert.equal(receiptPath,path.join(runtime,'ctf-fixed-practice-q05-result.json'));
  if(state==='POPULATED') {
    learner.assertPrivateReceipt(receiptPath);
    facet.assertFixedPracticeReceipt(JSON.parse(fs.readFileSync(receiptPath,'utf8')));
    assert.equal(ledger.length,2,'POPULATED migration cannot repeat Fixed-practice provider calls');
    return;
  }
  assert.equal(state,'FRESH');assert.equal(fs.existsSync(receiptPath),false);
  const evidence=fs.realpathSync(process.env.CTF_RENDERED_EVIDENCE);
  const previous={};
  for(const [key,value] of Object.entries({
    IDENTITY_DATABASE_URL:process.env.PG_CTF_AUTHORITY_APPLICATION_FRESH_IDENTITY_RUNTIME_URL,
    IDENTITY_MIGRATION_DATABASE_URL:process.env.PG_CTF_AUTHORITY_APPLICATION_FRESH_IDENTITY_MIGRATION_URL,
    JWT_SECRET:jwtSecret,
  })){previous[key]=process.env[key];process.env[key]=value;}
  let mounted,browser,pages,page,primary,receipt;
  const unexpected=[];let postProviderStale=0;
  const providerCounts=()=>({physicalStarted:ledger.length,
    completed:ledger.filter(entry=>entry.settlement==='completed').length-postProviderStale,
    staleAfterDispatch:postProviderStale});
  const snapshotStores=async()=>({
    attempts:await rawRows(c.runtime,'ctf.ctf_attempts'),
    progress:await rawRows(c.runtime,'ctf.ctf_progress'),
    judgments:await rawRows(c.runtime,'ctf.ctf_judgments'),
    leaderboard:await rawRows(c.runtime,'ctf.ctf_leaderboard'),
    outbox:await outboxRows(i.runtime),
    sibling:await rawRows(c.runtime,'ctf.ctf_sessions','WHERE participant_id=1001'),
  });
  for(const table of ['ctf_progress','ctf_attempts','ctf_sessions'])
    assert.equal((await c.runtime.query(`SELECT count(*)::int AS n FROM ctf.${table} WHERE participant_id=1001`)).rows[0].n>0,
      true,`Nonempty sibling ${table} required`);
  const stageName=(await c.runtime.query('SELECT stage_name FROM ctf.ctf_stages WHERE id=1')).rows[0]?.stage_name;
  assert.equal(typeof stageName,'string');
  const stageDigest=require('../../../server/agent-runtime/ctfStageJudge').stageDigest;
  const initialStage=(await c.runtime.query('SELECT * FROM ctf.ctf_stages WHERE id=1')).rows[0];
  const originalStageDigest=stageDigest(initialStage);
  const siblingStageBefore=await rawRows(c.runtime,'ctf.ctf_stages','WHERE id=2');
  assert.equal(siblingStageBefore.length,1,'Fixed-practice sibling stage must exist');
  const stageUpdate=async(phase,name)=>{
    const before=(await i.runtime.query('SELECT COALESCE(max(sequence),0)::text AS value FROM identity.ctf_outbox')).rows[0].value;
    const response=await mutate(admin,'catalog_mutation',{action:'update',stageId:'1',fields:{stage_name:name}});
    assert.equal(response.status,200,'Canonical stage edit must reach applied projection');
    const rows=(await i.runtime.query(`SELECT operation_id::text AS operation_id,sequence::text,
      actor_id::text,session_id::text,kind,canonical_command,state FROM identity.ctf_outbox
      WHERE sequence>$1 ORDER BY sequence`,[before])).rows;
    assert.equal(rows.length,1,'One phase must produce one canonical stage edit');
    const row=rows[0];assert.equal(row.kind,'catalog_mutation');assert.equal(row.state,'applied');
    assert.equal(row.actor_id,String(admin.user.id));
    assert.equal(row.session_id,String(admin.identitySession.id));
    const command=JSON.parse(row.canonical_command);
    assert.equal(command.operationId,row.operation_id);
    assert.equal(String(command.actorId),row.actor_id);
    assert.equal(String(command.scope.stageId),'1');
    assert.equal(command.body.action,'update');
    assert.deepEqual(command.body.fields,{stage_name:name});
    assert.equal((await c.runtime.query('SELECT stage_name FROM ctf.ctf_stages WHERE id=1')).rows[0].stage_name,name);
    assert.equal((await c.runtime.query('SELECT count(*)::int AS n FROM ctf.projection_receipts WHERE operation_id=$1',[row.operation_id])).rows[0].n,1);
    return {phase,operationId:row.operation_id,sequence:row.sequence,
      actorId:row.actor_id,sessionId:row.session_id,stageId:1};
  };
  const beforeApi=contentHttp.apiRequests;
  try {
    await require('../../../server/database/postgres/workshopPlatformSeed').seedWorkshopPlatform(i.migration);
    const adapter=require('../../../server/services/postgresIdentityAdapter').getPostgresIdentityAdapter();
    const stores=require('../../../server/services/postgresPlatformStores').getPostgresPlatformStores();
    mounted=await require('../../fixtures/legacyFileSsiFullAppParity').mountLegacyParityRoutes({
      app:web,adapter,pool:i.runtime,migration:i.migration,progress:stores.progress,
      config:stores.config,identity:adapter.repository});
    assert.equal((await i.runtime.query("SELECT count(*)::int AS n FROM identity.users WHERE id=2403 AND role='student'")).rows[0].n,1,
      'Dedicated learner must have been seeded before bootstrap');
    const actor=await userRequest(2403);
    const auth=await adapter.validateSession(actor.headers.authorization.slice(7));
    assert.equal(String(auth.user.id),'2403');
    assert.equal(String(auth.session.id),String(actor.identitySession.id));
    const report=JSON.parse(fs.readFileSync(process.env.CTF_CONTENT_BUILD_REPORT,'utf8'));
    const root=path.resolve(__dirname,'../../..');
    const build=fs.realpathSync(process.env.CTF_CONTENT_BUILD_DIRECTORY);
    assert.equal(build,report.inputMode==='private-external-v1'
      ?fs.realpathSync(report.outputRoot):path.join(root,'client/build'));
    assert(fs.existsSync(path.join(build,'index.html')));
    web.use('/api',(_request,response)=>response.status(404).json({error:'Unmapped Fixed-practice API'}));
    web.use(require('express').static(build));
    web.get('/{*path}',(_request,response)=>response.sendFile(path.join(build,'index.html')));
    browser=await require('../../fixtures/ctfTenContentBrowserAdmission')
      .launchCtfFixedPracticeBrowser(evidence,'fixedPractice');
    pages=content.contentActorPages(browser);page=await pages.newPage();
    await page.setViewport({width:1280,height:900});
    await page.setRequestInterception(true);
    const prelude=[];
    const preludeRequest=request=>{
      const url=new URL(request.url());
      if(['data:','blob:','about:'].includes(url.protocol))return request.continue();
      if(!preludeRequestAllowed(request.method(),url,origin)){
        unexpected.push(`${request.method()} ${url.pathname}`);return request.abort();}
      if(request.method()==='POST')prelude.push({path:url.pathname,
        authorization:request.headers().authorization||null,body:request.postData()||''});
      return request.continue();
    };
    page.on('request',preludeRequest);
    await page.evaluateOnNewDocument(token=>localStorage.setItem('token',token),actor.headers.authorization.slice(7));
    await page.goto(origin+'/ctf',{waitUntil:'domcontentloaded'});
    const wait=fn=>page.waitForFunction(fn,{timeout:15000,polling:100});
    const pointer=async handle=>{try{await content.contentPointerClick(page,handle,fn=>fn());}finally{await handle.dispose();}};
    const beforeRegister=(await i.runtime.query('SELECT COALESCE(max(sequence),0)::text AS value FROM identity.ctf_outbox')).rows[0].value;
    const registeredReply=page.waitForResponse(response=>new URL(response.url()).pathname===
      '/api/ctf/register'&&response.request().method()==='POST',{timeout:15000});
    registeredReply.catch(()=>{});
    await pointer(await wait(learner.joinButton));
    assert([200,202].includes((await registeredReply).status()));
    const registration=await learner.outboxFor(i,c,beforeRegister,'register','2403',
      String(actor.identitySession.id));
    const participantRows=(await c.runtime.query('SELECT id::text FROM ctf.ctf_participants WHERE user_id=2403 AND is_active=1')).rows;
    assert.equal(participantRows.length,1);
    const beforeStart=(await i.runtime.query('SELECT COALESCE(max(sequence),0)::text AS value FROM identity.ctf_outbox')).rows[0].value;
    const startedReply=page.waitForResponse(response=>new URL(response.url()).pathname===
      '/api/ctf/stage/1/start'&&response.request().method()==='POST',{timeout:15000});
    startedReply.catch(()=>{});
    await pointer(await wait(learner.stageOneCard));
    assert([200,202].includes((await startedReply).status()));
    const started=await learner.outboxFor(i,c,beforeStart,'start','2403',
      String(actor.identitySession.id),participantRows[0].id,1);
    assert.notEqual(registration.operation_id,started.operation_id);
    const progress=(await c.runtime.query("SELECT status FROM ctf.ctf_progress WHERE participant_id=$1 AND stage_id=1",[participantRows[0].id])).rows;
    assert.deepEqual(progress,[{status:'in_progress'}]);
    assert.deepEqual(prelude.map(value=>value.path),['/api/ctf/register','/api/ctf/stage/1/start']);
    assert(prelude.every(value=>value.authorization===actor.headers.authorization));
    assert.deepEqual(JSON.parse(prelude[1].body),{});
    assert.deepEqual(unexpected,[]);
    page.off('request',preludeRequest);
    const resolveAuthorization=async bearer=>{
      const principal=await adapter.validateSession(bearer.slice(7));
      const owner=(await c.runtime.query('SELECT id::text FROM ctf.ctf_participants WHERE user_id=$1 AND is_active=1',[principal.user.id])).rows;
      assert.equal(owner.length,1);
      return {actorId:String(principal.user.id),sessionId:String(principal.session.id),
        participantId:owner[0].id};
    };
    const authority={
      beforeProvider:async()=>{
        const settled=armPracticeCaptureStale(() =>
          stageUpdate('pre-provider-stale','Fixed stale pre-provider'));
        return { settled };
      },
      afterDispatch:async()=>{
        const gate=holdTransport(1);
        const settled=(async()=>{try{await gate.entered;
          const operation=await stageUpdate('post-provider-stale','Fixed stale post-provider');
          postProviderStale++;return operation;
        }finally{gate.release();}})();settled.catch(()=>{});
        return {settled};
      },
      restoreCurrent:phase=>stageUpdate(phase,stageName),
      beforeDispatch:async()=>{await page.evaluate(()=>localStorage.setItem('token','owned-stale-client-token'));},
    };
    const drain=async()=>{
      assert.equal(practiceStatus().active,0,'Real practice handler must drain');
      assert(ledger.every(value=>value.settlement==='completed'),
        'Both controlled provider replies must physically settle');
    };
    const cleanup=async()=>{
      const failures=[];
      for(const close of [async()=>{await pages?.close();pages=null;},
        async()=>{await browser?.close();browser=null;},
        async()=>{await mounted?.close();mounted=null;}])
        try{await close();}catch(error){failures.push(error);}
      if(failures.length)throw new AggregateError(failures,'Fixed-practice owned cleanup failed');
      return {providerDrained:true,ownedBrowserHandles:0,ownedStoreHandles:0};
    };
    receipt=await facet.runCtfFixedPracticeRenderedCases({page,origin,actorId:2403,
      sessionId:actor.identitySession.id,participantId:participantRows[0].id,
      siblingOwnerId:1001,serverCounts,providerCounts,snapshotStores,
      resolveAuthorization,authority,drain,cleanup});
    assert.equal(stageDigest((await c.runtime.query('SELECT * FROM ctf.ctf_stages WHERE id=1')).rows[0]),
      originalStageDigest,'Canonical restores must recover exact stage policy content');
    assert.deepEqual(await rawRows(c.runtime,'ctf.ctf_stages','WHERE id=2'),siblingStageBefore);
    assert.equal(contentHttp.apiRequests-beforeApi<=facet.LIMITS.apiRequests,true);
    assert.deepEqual(unexpected,[]);
  }catch(error){primary=error;throw error;}finally{
    const failures=[];
    try{await closePracticeCaptureStale();}catch(error){failures.push(error);}
    for(const close of [()=>pages?.close(),()=>browser?.close(),()=>mounted?.close()])
      try{await close();}catch(error){failures.push(error);}
    for(const [key,value] of Object.entries(previous))
      if(value===undefined)delete process.env[key];else process.env[key]=value;
    if(failures.length)throw new AggregateError(primary?[primary,...failures]:failures,
      'Fixed-practice fixture cleanup incomplete',{cause:primary});
  }
  assert(receipt && receipt.stage==='complete');
  fs.writeFileSync(receiptPath,JSON.stringify(receipt,null,2),{flag:'wx',mode:0o600});
  learner.assertPrivateReceipt(receiptPath);
  facet.assertFixedPracticeReceipt(JSON.parse(fs.readFileSync(receiptPath,'utf8')));
}

module.exports={assertDatabaseName,reserveFixedPracticeProvider,preludeRequestAllowed,
  createCommittedPracticeBarrier,runFixedPracticeCohort};
