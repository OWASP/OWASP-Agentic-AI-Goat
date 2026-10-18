'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { createHash } = require('node:crypto');
const net = require('node:net');
const { once } = require('node:events');
const { createBrowserForwardProxy } = require('./fullBackendBrowserForwardProxy');
const { cleanBrowserEnvironment } = require('./fullBackendBrowserNetworkPolicy');
const { waitForChild } = require('./fullBackendBootControls');
const { createFullBackendBrowserProxy } = require('./fullBackendBrowserProxy');
const { qualifyFullBackendRenderedAuth } = require('./fullBackendRenderedAuth');
const { captureBrowserProcessIdentity } = require('./browserProcessOwnership');
const BROWSER_SHA = '51083e7cf58ba060a0160b8f447ea04c0e9bada00c30a047259bcfe1217b82c3';
const PROTOCOL_TIMEOUT_MARGIN_MS = 30000;
function describeCleanupFailure(error) {
  const safeCode = value => typeof value?.code==='string'&&/^[A-Z0-9_]{1,64}$/.test(value.code)?{code:value.code}:{};
  const safePhase = value => ['active','denied','closing','admitted','partial','browser-teardown'].includes(value?.phase)?{phase:value.phase}:{};
  return {name:error?.name||'Error',message:String(error?.message||error).slice(0,2000),
    ...safeCode(error),...safePhase(error),
    ...(Array.isArray(error?.errors)?{errors:error.errors.slice(0,16).map(nested=>({name:nested?.name||'Error',
      ...safeCode(nested),...safePhase(nested)}))}:{})};
}
function admitRendered(env, platform, io = fs) {
  if (env.PG_FULL_BACKEND_RENDERED === undefined) return null;
  assert.equal(env.PG_FULL_BACKEND_RENDERED, '1');
  const executable = env.PG_FULL_BACKEND_BROWSER;
  assert.ok(executable && path.isAbsolute(executable));
  assert.equal(io.realpathSync(executable), executable);
  let expected = BROWSER_SHA;
  if (env.PG_MAIN_RENDERED_PLATFORM !== undefined || env.PG_MAIN_RENDERED_STANDALONE !== undefined) {
    assert.ok(!(env.PG_MAIN_RENDERED_PLATFORM !== undefined && env.PG_MAIN_RENDERED_STANDALONE !== undefined),
      'Rendered owner profiles are exclusive');
    const standalone = env.PG_MAIN_RENDERED_STANDALONE === '1';
    assert.equal(standalone ? env.PG_MAIN_RENDERED_STANDALONE : env.PG_MAIN_RENDERED_PLATFORM, '1');
    assert.equal(env.PG_MAIN_BACKEND_AUTH, '1');
    assert.equal(platform?.profile, standalone ? 'standalone-core-rendered' : 'rendered-platform');
    assert.equal(platform.browser, executable);
    assert.match(platform.browserSha256, /^[a-f0-9]{64}$/);
    expected = platform.browserSha256;
  } else assert.equal(platform, undefined);
  assert.equal(env.PG_FULL_BACKEND_BROWSER_SHA256, expected);
  assert.equal(createHash('sha256').update(io.readFileSync(executable)).digest('hex'), expected);
  return { executable, sha256: expected };
}
function browserEndpoint(child, signal, timeoutMs = 30000, expectedPort) {
  return new Promise((resolve,reject)=>{
    let text='';
    const finish=(error,value)=>{clearTimeout(timer);child.stderr.removeListener('data',data);child.removeListener('exit',exit);child.removeListener('error',exit);signal?.removeEventListener('abort',abort);error?reject(error):resolve(value);};
    const exit=()=>finish(Error('Browser exited before endpoint'));
    const abort=()=>finish(Error('Browser admission aborted'));
    const data=chunk=>{text+=chunk.toString();if(text.length>65536)return finish(Error('Browser endpoint output exceeded bound'));
      const match=text.match(/DevTools listening on (ws:\/\/[^\s]+)/);if(!match)return;
      const url=new URL(match[1]);if(url.hostname!=='127.0.0.1'||!url.port||(expectedPort!==undefined&&Number(url.port)!==expectedPort)||!url.pathname.startsWith('/devtools/browser/')||url.username||url.password||url.search||url.hash)return finish(Error('Foreign browser endpoint'));
      finish(null,url.href);
    };
    const timer=setTimeout(()=>finish(Error('Browser endpoint deadline')),timeoutMs);
    child.stderr.on('data',data);child.once('exit',exit);child.once('error',exit);signal?.addEventListener('abort',abort,{once:true});
    if(signal?.aborted)abort();
  });
}
function admitRenderedScenario({ mcp, secureShop } = {}) {
  assert.ok(mcp === undefined || secureShop === undefined, 'Rendered semantic cohorts must be exclusive');
  if (mcp !== undefined) {
    assert.equal(mcp?.mode, 'public_indirect');
    assert.ok(mcp.nativeEvidence && typeof mcp.nativeEvidence === 'object');
  }
  if (secureShop !== undefined) {
    assert.equal(secureShop?.mode, 'all_objectives');
    assert.ok(secureShop.nativeEvidence && typeof secureShop.nativeEvidence === 'object');
  }
  return Object.freeze({ mcpChatTimeoutMs: mcp ? 420000 : 10000,
    secureShopTimeoutMs: secureShop ? 420000 : 10000 });
}
function renderedProtocolTimeout(timeouts) {
  assert.ok(timeouts && typeof timeouts === 'object');
  for (const value of [timeouts.mcpChatTimeoutMs, timeouts.secureShopTimeoutMs]) {
    assert.ok(Number.isSafeInteger(value) && value >= 1000 && value <= 420000);
  }
  return Math.max(timeouts.mcpChatTimeoutMs, timeouts.secureShopTimeoutMs)
    + PROTOCOL_TIMEOUT_MARGIN_MS;
}
function ownedBrowserArgs({profile,devtoolsPort,proxyOrigin,netLog}) {
  return require('puppeteer').defaultArgs({headless:true,userDataDir:profile,args:[`--remote-debugging-port=${devtoolsPort}`,`--proxy-server=${proxyOrigin}`,'--proxy-bypass-list=<-loopback>',
      '--disable-quic','--force-webrtc-ip-handling-policy=disable_non_proxied_udp',`--log-net-log=${netLog}`,'--net-log-capture-mode=Default','--disable-background-networking','--disable-component-update','--disable-default-apps',
      '--disable-sync','--no-first-run','--disable-domain-reliability','--disable-extensions',
      '--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1']});
}
async function runRenderedBranch({ source, root, backendOrigin, admission, owned, signal, admin,
  students, password, runId, foreignRunId, verifySession, identityPool,
  mcp, secureShop, sqlNoSqlCatalog, platform, standalone }) {
  assert.ok(!sqlNoSqlCatalog||(!mcp&&!secureShop&&!standalone),'Exclusive SQL/NOVA catalog cohort');
  const timeouts = admitRenderedScenario({ mcp, secureShop });
  assert.ok(!platform||(!mcp&&!secureShop&&!sqlNoSqlCatalog&&!standalone),'Exclusive platform profile');
  assert.ok(!standalone||(!mcp&&!secureShop&&!sqlNoSqlCatalog&&!platform),'Exclusive standalone profile');
  const prebuilt = platform || standalone;
  const buildRoot = prebuilt ? prebuilt.buildRoot : path.join(root, 'frontend-build'), profile = path.join(root, 'browser-profile');
  if(prebuilt){assert.equal(buildRoot,path.join(source,'client/build'));assert.equal(fs.realpathSync(buildRoot),buildRoot);
    assert.equal(prebuilt.profile,standalone?'standalone-core-rendered':'rendered-platform');}
  else assert.equal(fs.existsSync(buildRoot), false);assert.equal(fs.existsSync(profile), false);
  fs.mkdirSync(profile, { mode: 0o700 });
  const log = fs.openSync(path.join(root, 'frontend-build.log'), 'wx', 0o600);
  let browser, proxy, forwardProxy, browserChild, deniedListener, devtoolsReservation, primaryFailure;
  let canaryConnections = 0;
  const bounded = promise => { let timer;return Promise.race([promise,new Promise((_,reject)=>{timer=setTimeout(()=>reject(Error('Browser cleanup deadline')),10000);})]).finally(()=>clearTimeout(timer)); };
  try {
    if(!prebuilt){const child = owned.launch(process.execPath, [path.join(source, 'client/node_modules/vite/bin/vite.js'),
      'build','--config',path.join(source,'client/vite.config.mjs'),'--configLoader','native','--outDir',buildRoot,'--emptyOutDir'], {
      cwd:path.join(source,'client'),env:{PATH:process.env.PATH,HOME:root,CI:'false',BROWSERSLIST_IGNORE_OLD_DATA:'1'},stdio:['ignore',log,log],
    });
    assert.equal(await waitForChild(child,{timeoutMs:120000,signal}),0);await owned.stop(child);}
    assert.ok(fs.statSync(path.join(buildRoot,'index.html')).isFile());
    proxy = await createFullBackendBrowserProxy({buildRoot,backendOrigin,port:admission.port,...timeouts});
    forwardProxy = await createBrowserForwardProxy({appOrigin:proxy.origin,...timeouts});
    deniedListener=net.createServer(socket=>{canaryConnections++;socket.end();});deniedListener.listen(0,'127.0.0.1');await once(deniedListener,'listening');
    devtoolsReservation=net.createServer();devtoolsReservation.listen(0,'127.0.0.1');await once(devtoolsReservation,'listening');
    const devtoolsPort=devtoolsReservation.address().port;
    const netLog=path.join(root,'browser-netlog.json');fs.writeFileSync(netLog,'',{flag:'wx',mode:0o600});
    await new Promise(resolve=>devtoolsReservation.close(resolve));devtoolsReservation=null;
    browserChild = owned.launch(admission.executable, await ownedBrowserArgs({profile,devtoolsPort,proxyOrigin:forwardProxy.origin,netLog}),
      {cwd:root,env:cleanBrowserEnvironment(root),stdio:['ignore','ignore','pipe']});
    const stderrPath=path.join(root,'browser-stderr.log');fs.writeFileSync(stderrPath,'',{flag:'wx',mode:0o600});
    let stderrBytes=0;browserChild.stderr.on('data',chunk=>{if(stderrBytes<10*1024*1024)fs.appendFileSync(stderrPath,chunk.subarray(0,10*1024*1024-stderrBytes));stderrBytes+=chunk.length;});
    const browserIdentity=captureBrowserProcessIdentity(browserChild.pid);
    fs.writeFileSync(path.join(root,'browser-process.json'),JSON.stringify({...browserIdentity,profile,executableSha256:admission.sha256}),{flag:'wx',mode:0o600});
    const endpoint = await browserEndpoint(browserChild,signal,30000,devtoolsPort);
    browser = await require('puppeteer').connect({ browserWSEndpoint: endpoint,
      protocolTimeout: renderedProtocolTimeout(timeouts) });
    const smoke=await browser.newPage();
    try {
      const before=forwardProxy.counters();
      for (const target of [`http://127.0.0.1:${deniedListener.address().port}/`, 'http://external.invalid/']) {
        const response=await smoke.goto(target,{waitUntil:'domcontentloaded',timeout:10000});
        assert.equal(response.status(),403,'forward proxy must explicitly deny smoke destination');
      }
      assert.equal(canaryConnections,0,'other owned loopback listener must remain untouched');
      assert.ok(forwardProxy.counters().denied>=before.denied+2);
      fs.writeFileSync(path.join(root,'browser-http-routing.json'),JSON.stringify({scope:'authenticated_admin_student_http_routing',
        osEgressQualified:false,maliciousChallengeQualified:false,canaryUntouched:true,deniedSmokeDestinations:2,counters:forwardProxy.counters()}),{mode:0o600});
    } finally {await smoke.close();}
    const abort=()=>{void browser.close().catch(()=>{});};signal.addEventListener('abort',abort,{once:true});
    try {
      if (sqlNoSqlCatalog) return await require('./sqlNoSqlCatalogParity').qualifySqlNoSqlCatalog({browser,origin:proxy.origin,admin,students,password,verifySession,projection:sqlNoSqlCatalog.projection,root,httpBudget:sqlNoSqlCatalog.httpBudget});
      if (mcp) return await require('./fullBackendRenderedMcp').qualifyFullBackendRenderedMcp({
        browser,origin:proxy.origin,admin,students,password,verifySession,
        nativeEvidence:mcp.nativeEvidence,timeoutMs:420000,
      });
      if (secureShop) return await require('./fullBackendRenderedSecureShop').qualifyFullBackendRenderedSecureShop({
        browser,origin:proxy.origin,admin,students,password,verifySession,
        nativeEvidence:secureShop.nativeEvidence,timeoutMs:420000,
      });
      if (standalone) return await require('./fullBackendRenderedStandalone').qualifyFullBackendRenderedStandalone({
        browser, origin:proxy.origin, workshop:{username:admin.username,password}, shop:standalone.shop,
        productId:standalone.productId, identityPool, signal, evidenceRoot:root,
        beginBrowserTeardown:()=>forwardProxy.beginBrowserTeardown(),
      });
      return await qualifyFullBackendRenderedAuth({browser,origin:proxy.origin,admin,students,password,runId,foreignRunId,verifySession,platform});
    }
    finally {signal.removeEventListener('abort',abort);}
  } catch (error) {
    primaryFailure = error;
    const describe = value => ({ name: value?.name || 'Error', message: String(value?.message || value).slice(0, 4000),
      stack: String(value?.stack || '').slice(0, 6000),
      ...(Array.isArray(value?.errors) ? { errors: value.errors.map(describe) } : {}) });
    fs.writeFileSync(path.join(root, 'browser-primary-failure.json'), JSON.stringify(describe(error)), { mode: 0o600 });
    throw error;
  } finally {
    fs.closeSync(log);
    const results=await Promise.allSettled([browser?bounded(browser.close()):Promise.resolve(),proxy?.close(),forwardProxy?.close(),
      deniedListener?new Promise(resolve=>deniedListener.close(resolve)):Promise.resolve(),
      devtoolsReservation?new Promise(resolve=>devtoolsReservation.close(resolve)):Promise.resolve()]);
    if(forwardProxy)fs.writeFileSync(path.join(root,'browser-proxy-counters.json'),JSON.stringify(forwardProxy.counters()),{mode:0o600});
    // Browser process was registered before endpoint discovery; launch failures
    // and close timeouts are still covered by exact owned child cleanup.
    let browserPidAbsent=browserChild===undefined;
    if (browserChild) {
      await owned.stop(browserChild);
      let absent=false;try{process.kill(browserChild.pid,0);}catch(error){if(error.code==='ESRCH')absent=true;else throw error;}
      assert.ok(absent,'owned browser PID must be absent');
      browserPidAbsent=absent;
    }
    // Preserve profile as owned evidence on unverified browser cleanup.
    if(results.every(row=>row.status==='fulfilled'))fs.rmSync(profile,{recursive:true,force:true});
    const failures = results.filter(row => row.status === 'rejected').map(row => row.reason);
    fs.writeFileSync(path.join(root,'browser-cleanup.json'),JSON.stringify({browserPid:browserChild?.pid||null,pidAbsent:browserPidAbsent,profileAbsent:!fs.existsSync(profile),closed:failures.length === 0,
      failures: failures.map(describeCleanupFailure)}),{mode:0o600});
    if (failures.length) throw new AggregateError([...(primaryFailure ? [primaryFailure] : []), ...failures], 'browser/proxy cleanup must complete');
  }
}
module.exports={admitRendered,admitRenderedScenario,renderedProtocolTimeout,
  runRenderedBranch,BROWSER_SHA,browserEndpoint,ownedBrowserArgs,describeCleanupFailure};
