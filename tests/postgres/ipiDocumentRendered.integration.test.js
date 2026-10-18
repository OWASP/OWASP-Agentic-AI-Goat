'use strict';
const test = require('node:test'), assert = require('node:assert/strict');
const fs = require('node:fs'), path = require('node:path'), os = require('node:os');
const { randomUUID } = require('node:crypto');
const { Pool } = require('pg');
const { migrate } = require('../../db/postgres/migrate');

test('rendered durable IPI restore replacement and interrupted reset retry', {
  skip: process.env.WORKSHOP_RAG_ROUTES_NATIVE !== '1', timeout: 120000,
}, async () => {
  assert.equal(process.env.PG_TEST_DISPOSABLE, 'yes');
  assert.equal(fs.realpathSync(process.env.DVAIA_ISOLATED_TEST_WORKSPACE), fs.realpathSync(process.cwd()));
  const url = role => {
    const u = new URL(process.env['WORKSHOP_RAG_' + role.toUpperCase() + '_URL']);
    assert.equal(u.hostname, '127.0.0.1'); assert.match(u.pathname, /^\/dvaia_test_workshop_rag_[a-f0-9]+$/);
    assert.equal(u.username, 'dvaia_identity_' + role); return u.href;
  };
  process.env.PLATFORM_DATABASE_ENGINE = 'postgres';
  process.env.IDENTITY_DATABASE_URL = url('runtime');
  process.env.IDENTITY_MIGRATION_DATABASE_URL = url('migration');
  process.env.JWT_SECRET = 'owned-native-route-qualification-secret-32bytes';
  const migration = new Pool({ connectionString: url('migration'), max: 2 });
  let directory, server, vite, browser;
  const evidence = { status: 'incomplete', scope: 'Mounted production IPI read/delete routes and canonical auth; controlled embeddings; no model or Judge call' };
  const evidencePath = process.env.WORKSHOP_RAG_EVIDENCE_PATH;
  assert.ok(path.isAbsolute(evidencePath) && !path.resolve(evidencePath).startsWith(process.cwd() + path.sep));
  const save = () => fs.writeFileSync(evidencePath, JSON.stringify(evidence, null, 2) + '\n', { mode: 0o600 });
  save();
  try {
    directory = fs.mkdtempSync(path.join(os.tmpdir(), 'rag-route-migrations-'));
    const base = path.resolve(__dirname, '../../db/postgres/identity-migrations');
    for (const name of fs.readdirSync(base)) if (name.endsWith('.sql')) fs.copyFileSync(path.join(base, name), path.join(directory, name));
    fs.copyFileSync(path.resolve(__dirname, '../../docs/modernization/drafts/workshop-rag/0082_workshop_rag_sources.candidate.sql'), path.join(directory, '0082_workshop_rag_sources.sql'));
    await migrate(migration, directory); assert.deepEqual(await migrate(migration, directory), []);
    await require('../../server/database/postgres/workshopPlatformSeed').seedWorkshopPlatform(migration);
    const adapter = require('../../server/services/postgresIdentityAdapter').getPostgresIdentityAdapter();
    const identity = require('../../server/database/postgres/identityRepository').createIdentityRepository(adapter.pool);
    const password = await require('bcryptjs').hash(randomUUID(), 4);
    const composition = require('../../server/services/workshopRagComposition').createWorkshopRagComposition({
      pool: adapter.pool, identityAdapter: adapter,
      assertReady: pool => require('../../server/services/workshopRagReadiness').assertWorkshopRagReadiness({ pool, expectedDatabase: new URL(url('runtime')).pathname.slice(1) }),
      embedder: { getRuntimeFingerprint: () => ({ fingerprint: 'a'.repeat(64) }),
        embed: async text => { if(text.includes('controlled-embedding-failure')) throw Error('Controlled embedding failure'); return ({ embeddingDimension: 384, embedding: Array.from({ length: 384 }, (_, i) => i === 0 ? 1 : 0) }); } },
    });
    await composition.initialize();
    let failResetContinuation = false;
    const router = require('../../server/routes/ragInjection');
    router.configureDurableRag({ ...composition, async resolveRequest(req) {
      const scope = await composition.resolveRequest(req);
      return { ...scope, async reset(...args) {
        try {
          const [execution, options] = args;
          return await scope.reset(execution, { ...options, afterErase: async () => {
            if (failResetContinuation) { failResetContinuation = false; throw new Error('Controlled progress continuation interruption'); }
            return options.afterErase?.();
          } });
        }
        catch (error) { evidence.resetError = { code: error.code, message: error.message }; save(); throw error; }
      } };
    } });
    const express = require('express'); const app = express(); app.use(express.json());
    app.use(require('express-session')({secret:'isolated-rendered-session-secret',resave:false,saveUninitialized:false}));
    app.use('/api/auth',require('../../server/routes/auth'));
    app.use('/api/workshop/config',require('../../server/routes/workshopConfig').createWorkshopConfigRouter());
    app.use('/api/solutions',require('../../server/routes/solutions'));
    app.get('/api/workshop/rag-injection/health',(_req,res)=>res.json({embeddingReady:true,llmReady:false,modelReady:true,ollamaAvailable:false,status:'degraded'}));
    app.get('/api/email-agent/health',(_req,res)=>res.json({available:false}));
    app.get('/api/email-agent/scenarios',(_req,res)=>res.json({scenarios:[]}));
    app.get('/api/email-agent/progress',(_req,res)=>res.json({objectives:{}}));
    app.use('/api/workshop/rag-injection',router); app.use('/api/workshop',require('../../server/routes/workshop')); app.use('/rag', router);
    server = await new Promise(resolve => { const s = app.listen(0, '127.0.0.1', () => resolve(s)); });
    const origin = `http://127.0.0.1:${server.address().port}`;
    async function owner() {
      const user = await identity.createUser({ username: 'route-' + randomUUID(), email: randomUUID() + '@example.invalid', passwordHash: password });
      const session = await adapter.createSession({ ...user, password }, {});
      const req = { user: { id: user.id }, identitySession: { id: session.internalSessionId }, headers: { authorization: `Bearer ${session.token}` } };
      return { user, session, scope: await composition.resolveRequest(req) };
    }
    const a = await owner(), b = await owner();
    const coordinator = require('../../server/agent-runtime/runCoordinator').createRunCoordinator({ family: 'RAG' });
    async function ingest(o, filename) {
      const documentId = randomUUID();
      await coordinator.run(String(o.user.id), {}, async execution => {
        const store = await o.scope.bind(execution);
        await store.ingestAndSelect({ documentId, operationId: randomUUID(), filename,
          ingestionKind: 'upload', sourceBuffer: Buffer.from('Exact learner source for ' + filename) });
      }); return documentId;
    }
    const first = await ingest(a, 'restored-current.txt'), sibling = await ingest(b, 'sibling.txt');
    const artifacts=path.dirname(evidencePath);
    const {spawn}=require('node:child_process');const net=require('node:net');
    const listener=net.createServer();await new Promise(resolve=>listener.listen(0,'127.0.0.1',resolve));const port=listener.address().port;await new Promise(resolve=>listener.close(resolve));
    const workspace=process.cwd(),client=path.join(workspace,'client'),viteEntry=fs.realpathSync(path.join(client,'node_modules/vite/dist/node/index.js'));
    const script=`import {createServer} from ${JSON.stringify(require('node:url').pathToFileURL(viteEntry).href)};const server=await createServer({root:${JSON.stringify(client)},configFile:${JSON.stringify(path.join(client,'vite.config.mjs'))},configLoader:'native',cacheDir:${JSON.stringify(path.join(artifacts,'vite-cache'))},server:{host:'127.0.0.1',port:${port},strictPort:true}});await server.listen();process.on('SIGTERM',async()=>{await server.close();process.exit(0)});`;
    vite=spawn(process.execPath,['--input-type=module','-e',script],{cwd:client,env:{...process.env,PORT:String(server.address().port),DVAIA_CLIENT_PORT:String(port)},stdio:['ignore','pipe','pipe']});
    let viteLog='';for(const stream of [vite.stdout,vite.stderr])stream.on('data',chunk=>{viteLog+=chunk;});
    const pageBase='http://127.0.0.1:'+port;let up=false;for(let n=0;n<100;n++){try{if((await fetch(pageBase)).ok){up=true;break;}}catch{}await new Promise(resolve=>setTimeout(resolve,100));}assert.ok(up,viteLog);
    browser=await require('puppeteer').launch({headless:true});evidence.browserPid=browser.process().pid;save();
    const page=await browser.newPage();await page.setViewport({width:1440,height:1000});page.setDefaultTimeout(30000);
    let failCommitRead=false,failNextResetRead=false;
    page.on('response',response=>{if(failNextResetRead&&response.url().includes('/rag-injection/progress/reset')&&response.status()===200){failNextResetRead=false;failCommitRead=true;}});
    await page.setRequestInterception(true);page.on('request',req=>{if(failCommitRead&&req.url().includes('/rag-injection/current-session')){failCommitRead=false;req.abort();return;}const u=req.url();if(u.startsWith(pageBase+'/')||/^(data|blob|about):/.test(u))req.continue();else req.abort();});
    const errors=[];page.on('pageerror',error=>errors.push(error.message));
    const resetIds=[];page.on('request',req=>{if(req.url().includes('/rag-injection/progress/reset'))resetIds.push(req.headers()['x-reset-operation-id']);});
    await page.evaluateOnNewDocument(token=>localStorage.setItem('token',token),a.session.token);
    await page.goto(pageBase+'/vulnerabilities/indirect-prompt-injection',{waitUntil:'networkidle2'});
    async function text(value){try{await page.waitForFunction(value=>document.body.innerText.includes(value),{},value);}catch(error){evidence.failureDom=await page.$eval('body',e=>e.innerText);evidence.errors=errors;evidence.pageUrl=page.url();save();await page.screenshot({path:path.join(artifacts,'ipi-failure.png'),fullPage:true});throw error;}}
    await text('restored-current.txt');await page.screenshot({path:path.join(artifacts,'ipi-restored.png'),fullPage:true});evidence.restored=true;save();
    const click=async(label,dialog=false)=>{const found=await page.evaluateHandle(({label,dialog})=>[...(dialog?document.querySelector('[role=alertdialog]'):document).querySelectorAll('button')].find(x=>x.textContent.trim()===label),{label,dialog});const button=found.asElement();assert.ok(button,label);await button.click();};
    const failFile=path.join(artifacts,'rejected.txt');fs.writeFileSync(failFile,'controlled-embedding-failure');
    const input=await page.$('input[type=file]');assert.ok(input);await input.uploadFile(failFile);await click('Upload');await text('Durable document operation unavailable; retry');
    const selected=async owner=>(await (await fetch(origin+'/rag/current-session',{headers:{authorization:'Bearer '+owner.session.token}})).json()).session_id;
    assert.equal(await selected(a),first);await page.reload({waitUntil:'networkidle2'});await text('restored-current.txt');evidence.failedReplacementPreserved=true;save();
    const goodFile=path.join(artifacts,'replacement.txt');fs.writeFileSync(goodFile,'Public fictional training replacement document');await (await page.$('input[type=file]')).uploadFile(goodFile);await Promise.all([page.waitForResponse(response=>response.url().includes('/rag-injection/upload')&&response.status()===200),click('Upload')]);await text('replacement.txt');
    const replacement=await selected(a);assert.ok(replacement&&replacement!==first);await page.reload({waitUntil:'networkidle2'});await text('replacement.txt');

    failResetContinuation=true;await click('Reset Progress');await page.waitForSelector('[role=alertdialog]');
    evidence.dialog=await page.$eval('[role=alertdialog]',e=>e.innerText);
    evidence.dialogAboveNavigation=await page.$eval('[role=alertdialog]',e=>{const heading=e.querySelector('h2'),r=heading.getBoundingClientRect();const hit=document.elementFromPoint(r.x+r.width/2,r.y+r.height/2);return !!hit&&e.contains(hit)&&e.parentElement.parentElement===document.body;});assert.equal(evidence.dialogAboveNavigation,true);save();
    await click('Confirm reset',true);
    await page.waitForFunction(()=>{const e=document.querySelector('[role=alertdialog]');return e&&/retry|failed|interrupted|could not/i.test(e.innerText);});
    await page.screenshot({path:path.join(artifacts,'ipi-reset-interrupted.png'),fullPage:true});assert.equal(resetIds.length,1);assert.match(resetIds[0],/^[a-f0-9-]{36}$/);
    await page.reload({waitUntil:'networkidle2'});await text('Reset Progress');await click('Reset Progress');await page.waitForSelector('[role=alertdialog]');await click('Confirm reset',true);
    await page.waitForFunction(()=>!document.querySelector('[role=alertdialog]'));assert.equal(resetIds.length,2);assert.equal(resetIds[0],resetIds[1]);assert.equal(await selected(a),null);assert.equal(await selected(b),sibling);
    await page.screenshot({path:path.join(artifacts,'ipi-reset-recovered.png'),fullPage:true});
    await ingest(a,'before-replay.txt');await page.reload({waitUntil:'networkidle2'});await text('before-replay.txt');
    failNextResetRead=true;await click('Reset Progress');await page.waitForSelector('[role=alertdialog]');await click('Confirm reset',true);
    await page.waitForFunction(()=>{const e=document.querySelector('[role=alertdialog]');return e&&/retry|failed|error|network/i.test(e.innerText);});
    const newer=await ingest(a,'newer-after-committed-reset.txt');await page.reload({waitUntil:'networkidle2'});await text('newer-after-committed-reset.txt');
    await click('Reset Progress');await page.waitForSelector('[role=alertdialog]');await click('Confirm reset',true);await page.waitForFunction(()=>!document.querySelector('[role=alertdialog]'));
    await text('newer-after-committed-reset.txt');assert.equal(await selected(a),newer);assert.equal(resetIds[2],resetIds[3]);assert.notEqual(resetIds[0],resetIds[2]);assert.equal(await selected(b),sibling);
    evidence.completedReplayPreservesNewSelection=true;await page.screenshot({path:path.join(artifacts,'ipi-replay-newer-selection.png'),fullPage:true});
    evidence.status='passed';evidence.controlledEmbeddings=true;evidence.actualModel=false;evidence.resetOperationId=resetIds[0];evidence.sameOperationAfterReload=true;evidence.siblingPreserved=true;evidence.errors=errors;save();
  } finally {
    if(browser)await browser.close();
    if(vite){vite.kill('SIGTERM');await new Promise(resolve=>vite.once('close',resolve));}
    if (server) await new Promise(resolve => server.close(resolve));
    await require('../../server/database/postgres').closePostgresPools();
    await migration.end(); if (directory) fs.rmSync(directory, { recursive: true, force: true });
  }
});
