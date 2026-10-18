'use strict';
// Generated preload integration with genuine lifecycle/target sources and a
// harmless HTTP/IPC agent substitute. No database, model, or 17-agent proof.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const crypto = require('node:crypto');
const net = require('node:net');
const { fork } = require('node:child_process');
const { waitForChild } = require('./fixtures/fullBackendBootControls');
const { secureShopPreloadSource } = require('./fixtures/secureShopQualificationPreload');
const sha = b => crypto.createHash('sha256').update(b).digest('hex');
async function reserve() {
  const server = net.createServer();
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  const port = server.address().port;
  await new Promise(resolve => server.close(resolve));
  return port;
}
function freeze(dir) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const file = path.join(dir, e.name);
    if (e.isDirectory()) freeze(file); else fs.chmodSync(file, 0o444);
  }
  fs.chmodSync(dir, 0o555);
}
function remove(dir) {
  fs.chmodSync(dir, 0o700);
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) if (e.isDirectory()) remove(path.join(dir, e.name));
  fs.rmSync(dir, { recursive: true, force: true });
}
function groupExists(child) {
  assert.ok(Number.isSafeInteger(child.pid) && child.pid > 0, 'Direct detached child identity required');
  try { process.kill(-child.pid,0); return true; }
  catch(error) { if(error.code==='ESRCH')return false;throw error; }
}
async function probeOwnedGroup(child, deadline, probe = groupExists, now = Date.now, pause = () => new Promise(resolve => setTimeout(resolve, 20))) {
  for (;;) {
    try { return probe(child); }
    catch (error) {
      // Darwin can temporarily deny a group probe while signalled members exit.
      // Unknown is never absence: persistent uncertainty retains the fixture.
      if (error.code !== 'EPERM' || now() >= deadline) throw error;
      await pause();
    }
  }
}
async function stopOwnedGroup(child) {
  // detached:true on this outer fork establishes PGID=PID. Inner Supervisor
  // children stay detached:false and are covered even before a PID report.
  for (const signal of ['SIGTERM', 'SIGKILL']) {
    if (!await probeOwnedGroup(child, Date.now() + 1200)) break;
    try { process.kill(-child.pid, signal); } catch (error) { if (error.code !== 'ESRCH') throw error; }
    const deadline = Date.now() + 1200;
    while (await probeOwnedGroup(child, deadline) && Date.now() < deadline) await new Promise(resolve => setTimeout(resolve, 20));
  }
  assert.equal(await probeOwnedGroup(child, Date.now() + 1200), false, 'Owned process group survived cleanup');
  await waitForChild(child, { timeoutMs: 1000 });
}
// Closed test-local virtual module mapping. No source is copied or rewritten.
function installMainModules({main,source,files}) {
  const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),Module=require('node:module');
  const marker=Symbol.for('dvaia.test.mainModuleLoader');
  if(globalThis[marker])throw Error('SecureShop preload already initialized');
  globalThis[marker]=true;
  const rows=new Map(files.map(row=>[path.join(source,row.relative),row]));
  const resolve=Module._resolveFilename,extension=Module._extensions['.js'];
  Module._resolveFilename=function(request,parent,...rest){
    if(request==='puppeteer')return path.join(source,'node_modules/puppeteer/index.js');
    const absolute=path.isAbsolute(request)?request:request.startsWith('.')&&parent?.filename?path.resolve(path.dirname(parent.filename),request):null;
    if(absolute){for(const candidate of [absolute,absolute+'.js',path.join(absolute,'index.js')])if(rows.has(candidate))return candidate;}
    if(parent?.filename&&rows.has(parent.filename)){
      const actual=path.join(main,rows.get(parent.filename).relative);
      const resolved=Module.createRequire(actual).resolve(request);
      const virtual=path.join(source,path.relative(main,resolved));
      if(rows.has(virtual))return virtual;
      if(resolved.startsWith(main+path.sep)&&!resolved.includes(path.sep+'node_modules'+path.sep)&&request.startsWith('.'))throw Error('Unregistered main module dependency');
      return resolved;
    }
    return resolve.call(this,request,parent,...rest);
  };
  Module._extensions['.js']=function(module,filename){
    const row=rows.get(filename);if(!row)return extension(module,filename);
    const bytes=fs.readFileSync(path.join(main,row.relative));
    if(crypto.createHash('sha256').update(bytes).digest('hex')!==row.sha256)throw Error('Main module drift');
    module._compile(bytes.toString('utf8'),filename);
  };
}
for (const forceParentFailure of [false, true]) test(forceParentFailure
  ? 'owned outer group cleans an unreported worker after forced parent failure'
  : 'generated single guard carries concurrent genuine targets through inherited IPC and fences retired scopes', { timeout: 20000 }, async () => {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'ss-preload-')));
  let child, assessment;
  const observedPids = [], observedPorts = [];
  try {
    const source = path.join(root, 'source'), fixtures = path.join(root, 'fixtures');
    const renderer = path.join(root, 'renderer');
    fs.mkdirSync(fixtures, { mode: 0o700 });
    fs.mkdirSync(renderer, { mode: 0o700 });
    const files = ['server/services/secureshop/agentHostSupervisor.js', 'server/services/secureshopSsrfTargetPool.js',
      'server/services/secureshopSsrfOwnedTarget.js', 'server/services/secureshopReviewCardRenderer.js',
      'server/services/xssBrowserQualification.js'];
    const main=path.resolve(__dirname,'..'), closure=new Map();
    function retain(file) {
      file=fs.realpathSync(file);if(closure.has(file))return;
      assert.ok(file.startsWith(main+path.sep));
      const bytes=fs.readFileSync(file);closure.set(file,{relative:path.relative(main,file),sha256:sha(bytes)});
      for(const match of bytes.toString().matchAll(/require\(['"](\.[^'"]+)['"]\)/g))retain(require.resolve(path.resolve(path.dirname(file),match[1])));
    }
    for(const file of files)retain(path.join(main,file));
    retain(require.resolve('./fixtures/secureShopQualificationPreload'));
    // This frozen sentinel validates synthetic-layout metadata only. Genuine
    // main helper/module bytes are loaded in memory and independently hashed.
    const helperSentinel=path.join(source,'tests/fixtures/secureShopQualificationPreload.js');
    fs.mkdirSync(path.dirname(helperSentinel),{recursive:true});fs.writeFileSync(helperSentinel,'// synthetic layout sentinel; not source qualification\n');
    fs.mkdirSync(path.join(source, 'server/routes/secureshop'), { recursive: true });
    fs.writeFileSync(path.join(source, 'server/routes/secureshop/boundBrowser.js'), `
      module.exports={createBoundBrowserRouter(options){return{emit:event=>options.observeLifecycle(event)}}};
    `);
    const artifact = `'use strict';const {parentPort,workerData}=require('node:worker_threads');
      (async()=>{let socketDenied=false;try{const socket=require('node:net').connect({host:'127.0.0.1',port:1});socket.on('error',()=>{});}catch(error){socketDenied=error?.code==='QUALIFICATION_ENDPOINT_BLOCKED';}
      let fetchDenied=false;try{await fetch('http://127.0.0.1:1/');}catch(error){fetchDenied=error?.message==='QUALIFICATION_PROVIDER_BLOCKED';}
      parentPort.postMessage({ok:socketDenied&&fetchDenied,markup:'<article>'+workerData.review.body+'</article>'});})();`;
    fs.writeFileSync(path.join(renderer, 'renderer.cjs'), artifact);
    fs.writeFileSync(path.join(renderer, 'manifest.json'), JSON.stringify({ version: 1,
      component: 'SecureShop.ReviewCard', source: 'client/src/pages/secureshop/components/ReviewCard.jsx',
      sourceSha256: 'a'.repeat(64), artifact: 'renderer.cjs', artifactSha256: sha(artifact) }));
    fs.mkdirSync(path.join(source, 'agent-host'));
    fs.writeFileSync(path.join(source, 'agent-host/index.js'), `
      const http=require('node:http'),net=require('node:net'),assert=require('node:assert/strict');
      assert.throws(()=>net.connect({host:'127.0.0.1',port:Number(process.env.CONTROLLED_ASSESSMENT_PORT)}),/QUALIFICATION_ENDPOINT_BLOCKED/);
      const server=http.createServer((req,res)=>res.end(JSON.stringify({ok:true,instanceId:process.env.SS_AGENT_HOST_INSTANCE_ID})));
      server.listen(Number(process.env.SS_AGENT_HOST_PORT),'127.0.0.1');
      process.on('message',m=>{if(m.kind==='fetch'){
        let req;try{req=http.get(m.url,res=>{res.resume();res.on('end',()=>process.send({kind:'fetched',id:m.id,status:res.statusCode}));});req.on('error',()=>process.send({kind:'fetched',id:m.id,status:0}));}catch{process.send({kind:'fetched',id:m.id,status:0});}
      }});
      process.on('SIGTERM',()=>{server.close(()=>process.exit(0));});
    `);
    fs.mkdirSync(path.join(source, 'node_modules/puppeteer'), { recursive: true });
    fs.writeFileSync(path.join(source, 'node_modules/puppeteer/index.js'), `
      const net=require('node:net');module.exports={connect({browserWSEndpoint,protocolTimeout}){
        if(protocolTimeout!==15000)throw Error('controlled protocol timeout');const url=new URL(browserWSEndpoint);
        return new Promise((resolve,reject)=>{const socket=net.connect({host:url.hostname,port:Number(url.port)});
          socket.once('error',reject);socket.once('connect',()=>{socket.end();resolve({
            createBrowserContext:async()=>{throw Error('controlled qualification stop');},disconnect(){}
          });});});
      }};
    `);
    fs.writeFileSync(path.join(source, 'server/index.js'), `
      const assert=require('node:assert/strict'),crypto=require('node:crypto');
      const {AgentHostSupervisor}=require('./services/secureshop/agentHostSupervisor');
      const {createSecureShopSsrfTargetPool}=require('./services/secureshopSsrfTargetPool');
      const {loadSecureShopReviewCardRenderer}=require('./services/secureshopReviewCardRenderer');
      const {createBoundBrowserRouter}=require('./routes/secureshop/boundBrowser');
      const {Worker}=require('node:worker_threads');
      const net=require('node:net');
      const preloadText=require('node:fs').readFileSync(process.env.NODE_OPTIONS.slice('--require='.length),'utf8');
      assert.throws(()=>require('node:vm').runInThisContext('(function(require){'+preloadText+'})')(require),/already initialized/);
      const host=new AgentHostSupervisor({stopTimeoutMs:500,restartLimit:1});
      const pool=createSecureShopSsrfTargetPool({root:${JSON.stringify(fixtures)}});
      const binding=owner=>({targetId:crypto.randomUUID(),launchId:crypto.randomUUID(),scenarioId:crypto.randomUUID(),generation:0,platformOwnerId:owner,platformSessionId:owner});
      const input=()=>({requestId:crypto.randomUUID(),resourceKind:'public-policy'});
      function fetched(url){return new Promise((resolve,reject)=>{const id=crypto.randomUUID(),c=host.proc;const timer=setTimeout(()=>done(Error('fetch deadline')),1500);function done(e,v){clearTimeout(timer);c.off('message',on);e?reject(e):resolve(v);}function on(m){if(m.kind==='fetched'&&m.id===id)done(null,m.status);}c.on('message',on);c.send({kind:'fetch',id,url});});}
      (async()=>{let failed, disconnected=false;
        try{
          const rejectWorker=data=>new Promise((resolve,reject)=>{const worker=new Worker('0',{eval:true,workerData:data});
            let observed=false;worker.once('error',error=>{observed=true;resolve(error);});worker.once('exit',code=>{if(!observed)reject(Error('Foreign renderer worker was admitted: '+code));});});
          assert.match((await rejectWorker({review:{}})).message,/renderer worker admission/);
          assert.match((await rejectWorker({review:{},qualificationPreload:{version:1,purpose:'secureshop_review_renderer',token:'0'.repeat(64)}})).message,/renderer worker admission/);
          const markup=await loadSecureShopReviewCardRenderer().renderReviewCard({body:'owned-renderer-worker'});
          assert.equal(markup,'<article>owned-renderer-worker</article>');
          const xss=require('./services/xssBrowserQualification');
          assert.throws(()=>xss.createXssBrowserQualification({connectBrowser:async()=>null}),/override/);
          const qualified=xss.createXssBrowserQualification({timeoutMs:500});
          assert.equal((await qualified.qualify('<b>controlled</b>')).reason,'qualification_error');
          await qualified.close();
          assert.throws(()=>net.connect({host:'127.0.0.1',port:Number(process.env.CONTROLLED_FOREIGN_PORT)}),/QUALIFICATION_ENDPOINT_BLOCKED/);
          const lifecycle=[];const browser=createBoundBrowserRouter({observeLifecycle:event=>lifecycle.push(event)});
          browser.emit({type:'assessment_start',body:'never-record'});
          browser.emit({type:'assessment_settled',outcome:'rejected',errorName:'Error',errorCode:'SECURESHOP_REVIEW_RENDERER_UNAVAILABLE',message:'never-record',requestId:'never-record'});
          browser.emit({type:'assessment_settled',outcome:'fulfilled',body:'never-record'});
          browser.emit({type:'assessment_settled',outcome:'rejected',errorName:'Payload123',errorCode:'PAYLOAD_123',message:'never-record'});
          browser.emit({type:'unknown',message:'never-record'});
          for(let index=0;index<80;index++)browser.emit({type:'transport_abort',source:'response_close',headersSent:false,writableEnded:false,body:'never-record'});
          assert.equal(lifecycle[1].message,'never-record');
          assert.throws(()=>createSecureShopSsrfTargetPool({root:${JSON.stringify(fixtures)}}),/single owned pool/);
          const starting=host.start();
          if(process.env.CONTROLLED_PARENT_FAILURE==='1')setTimeout(()=>process.exit(3),20);
          await starting;process.send({pid:host.proc.pid});
          const a=binding(1),b=binding(2);
          const issued=await Promise.all([pool.issue(a,input()),pool.issue(b,input())]);
          for(const item of issued)process.send({port:Number(new URL(item.url).port)});
          assert.notEqual(issued[0].targetId,issued[1].targetId);
          assert.deepEqual(await Promise.all(issued.map(v=>fetched(v.url))),[200,200]);
          await assert.rejects(pool.issue({...a,platformOwnerId:2},input()),/scope mismatch/);
          await pool.retireRecovered({...a,operationId:crypto.randomUUID()});assert.equal(await fetched(issued[0].url),0);assert.equal(await fetched((await pool.issue(b,input())).url),200);
          await assert.rejects(pool.issue(a,input()),/retired/);
          await pool.retire(b);
          const c=binding(3), last=await pool.issue(c,input());process.send({port:Number(new URL(last.url).port)});
          const old=host.proc;await new Promise(resolve=>{old.once('exit',resolve);old.kill('SIGTERM');});
          disconnected=true;await host._waitHealthy();process.send({pid:host.proc.pid});assert.notEqual(host.proc,old);
          let touched=false;const unsafe={get requestId(){touched=true;return crypto.randomUUID();},resourceKind:'public-policy'};
          await assert.rejects(pool.issue(c,unsafe),/retired/);assert.equal(touched,false);
          const d=binding(4),fresh=await pool.issue(d,input());process.send({port:Number(new URL(fresh.url).port)});assert.equal(await fetched(fresh.url),200);await pool.retire(d);
          await assert.rejects(pool.close(),/cleanup failed/);
        }catch(e){failed=e;}finally{
          const errors=[];try{await pool.close();}catch(e){if(!disconnected||!e.message.includes('cleanup failed'))errors.push(e);}try{await host.stop();}catch(e){errors.push(e);}
          if(failed||errors.length){console.error(failed||errors[0]);process.exitCode=1;}else process.send({passed:true});
          process.disconnect();
        }
      })();
    `);
    freeze(source);
    const port = await reserve(); observedPorts.push(port);
    assessment = net.createServer(socket => socket.end());
    await new Promise((resolve, reject) => { assessment.once('error', reject);assessment.listen(0, '127.0.0.1', resolve); });
    const assessmentPort = assessment.address().port;
    const config = { version: 1, sourceRoot: source, fixtureRoot: fixtures,
      database: { host: '127.0.0.1', port: await reserve() },
      network: { version: 1, services: [{ name: 'agent_host', host: '127.0.0.1', port }] },
      assessmentBrowserEndpoint: `ws://127.0.0.1:${assessmentPort}/devtools/browser/01234567-89ab-cdef-0123-456789abcdef` };
    assert.throws(() => secureShopPreloadSource({ ...config, sourceRoot: root }), /source writable/);
    for (const assessmentBrowserEndpoint of [
      'ws://127.0.0.1:443/devtools/browser/01234567-89ab-cdef-0123-456789abcdef',
      `ws://localhost:${assessmentPort}/devtools/browser/01234567-89ab-cdef-0123-456789abcdef`,
      `ws://127.0.0.1:${assessmentPort}/devtools/browser/not-a-capability`,
      `ws://127.0.0.1:${assessmentPort}/devtools/browser/01234567-89ab-cdef-0123-456789abcdef?foreign=1`,
    ]) assert.throws(() => secureShopPreloadSource({ ...config, assessmentBrowserEndpoint }), /assessment browser endpoint/);
    assert.throws(() => secureShopPreloadSource({ ...config,
      assessmentBrowserEndpoint: `ws://127.0.0.1:${port}/devtools/browser/01234567-89ab-cdef-0123-456789abcdef` }),
    /endpoint collision/);
    const preload = path.join(root, 'preload.cjs');
    const loaderConfig={main,source,files:[...closure.values()]};
    const preloadBody=`(${installMainModules.toString()})(${JSON.stringify(loaderConfig)});\n${secureShopPreloadSource(config)}`;
    fs.writeFileSync(preload,preloadBody,{mode:0o600});
    const { spawnSync } = require('node:child_process');
    for (const args of [['--require', preload, '-e', ''], ['--require', preload, path.join(source, 'agent-host/index.js')]]) {
      const denied = spawnSync(process.execPath, args, { cwd: source, env: {}, encoding: 'utf8', timeout: 2000 });
      assert.equal(denied.status, 1);assert.match(denied.stderr, /SecureShop preload (entry|child admission)/);
    }
    child = fork(path.join(source, 'server/index.js'), [], { cwd: source, execArgv: [], env: {
      NODE_OPTIONS: `--require=${preload}`, SECURESHOP_REVIEW_RENDERER_ROOT: renderer,
      CONTROLLED_ASSESSMENT_PORT: String(assessmentPort), CONTROLLED_FOREIGN_PORT: String(await reserve()),
      CONTROLLED_PARENT_FAILURE: forceParentFailure ? '1' : '0' }, silent: true, detached: true });
    // Retain the actual returned handle before any health/readiness/exit wait.
    assert.ok(Number.isSafeInteger(child.pid));
    assert.ok(groupExists(child));
    let output = '', passed = false;
    child.stdout.on('data', b => { output += b; }); child.stderr.on('data', b => { output += b; });
    child.on('message', m => { if (m.pid) observedPids.push(m.pid); if (m.port) observedPorts.push(m.port); if (m.passed) passed = true; });
    assert.equal(await waitForChild(child, { timeoutMs: 12000 }), forceParentFailure ? 3 : 0, output); assert.equal(passed, !forceParentFailure, output);if(forceParentFailure){assert.deepEqual(observedPids, []);assert.ok(groupExists(child),'Exited direct parent must leave an unreported worker group for cleanup');}
    if (!forceParentFailure) {
      const diagnostic = fs.readFileSync(path.join(fixtures, '.browser-lifecycle.ndjson'), 'utf8')
        .trim().split('\n').map(line => JSON.parse(line));
      assert.equal(diagnostic.length, 64);
      assert.deepEqual(diagnostic.slice(0, 3), [
        { version: 1, sequence: 0, type: 'assessment_start', category: 'started' },
        { version: 1, sequence: 1, type: 'assessment_settled', category: 'renderer_unavailable',
          outcome: 'rejected', errorName: 'Error', errorCode: 'SECURESHOP_REVIEW_RENDERER_UNAVAILABLE' },
        { version: 1, sequence: 2, type: 'assessment_settled', category: 'fulfilled',
          outcome: 'fulfilled', errorName: null, errorCode: null },
      ]);
      assert.deepEqual(diagnostic[3], { version: 1, sequence: 3, type: 'assessment_settled',
        category: 'unclassified_internal', outcome: 'rejected', errorName: null, errorCode: null });
      assert.ok(diagnostic.slice(4).every(row => row.type === 'transport_abort'
        && row.category === 'transport_abort' && row.source === 'response_close'));
      assert.ok(!fs.readFileSync(path.join(fixtures, '.browser-lifecycle.ndjson'), 'utf8').includes('never-record'));
    }
    await new Promise((resolve, reject) => assessment.close(error => error ? reject(error) : resolve()));
    assessment = undefined;
  } finally {
    const errors = [];
    if (assessment) try {
      assessment.closeAllConnections?.();
      await new Promise((resolve, reject) => assessment.close(error => error ? reject(error) : resolve()));
    } catch (e) { errors.push(e); }
    if (child) {
      try { await stopOwnedGroup(child);assert.throws(() => process.kill(child.pid, 0), e => e.code === 'ESRCH'); } catch (e) { errors.push(e); }
    }
    for (const pid of observedPids) try { assert.throws(() => process.kill(pid, 0), e => e.code === 'ESRCH'); } catch (e) { errors.push(e); }
    for (const port of observedPorts) try {
      await new Promise((resolve, reject) => { const s = net.connect({ host: '127.0.0.1', port }); s.setTimeout(500, () => { s.destroy(); reject(Error('port deadline')); }); s.once('connect', () => { s.destroy(); reject(Error('listener survived')); }); s.once('error', e => { s.destroy(); e.code === 'ECONNREFUSED' ? resolve() : reject(e); }); });
    } catch (e) { errors.push(e); }
    // Preserve all failure artifacts until complete group/listener absence is proven.
    if (!errors.length) try { remove(root); } catch (e) { errors.push(e); }
    if (errors.length) throw new AggregateError(errors, 'Generated preload cleanup failed');
  }
});


test('cleanup retries unknown probes but never treats permission denial as absence', async () => {
  const denied = Object.assign(new Error('probe denied'), { code: 'EPERM' });
  let now = 0, calls = 0;
  const pause = async () => { now += 20; };
  assert.equal(await probeOwnedGroup({}, 100, () => { if (++calls < 3) throw denied; return false; }, () => now, pause), false);
  assert.equal(calls, 3);
  now = 0;
  await assert.rejects(probeOwnedGroup({}, 40, () => { throw denied; }, () => now, pause), error => error === denied);
  assert.equal(now, 40);
  assert.equal(await probeOwnedGroup({}, 40, () => true, () => 0, pause), true);
  const other = Object.assign(new Error('unexpected'), { code: 'EINVAL' });
  await assert.rejects(probeOwnedGroup({}, 40, () => { throw other; }, () => 0, pause), error => error === other);
});
