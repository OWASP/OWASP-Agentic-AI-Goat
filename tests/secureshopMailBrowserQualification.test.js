'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm'),{createHash}=require('node:crypto');
const {createXssBrowserQualification,projectTargetHtml}=require('../server/services/xssBrowserQualification');
const sha=x=>createHash('sha256').update(x).digest('hex');
function adapterFixture(change=()=>{}){
 const root=path.resolve(__dirname,'..'),source='client/src/pages/secureshop/components/MailMessageBody.jsx',entry='client/src/pages/secureshop/components/mailMessageClientRenderer.jsx',artifactRoot=path.join(root,'client/build/secureshop-mail-renderer');
 const script='trusted client fixture',manifest={version:1,component:'SecureShop.MailMessageBody',source,sourceSha256:sha(fs.readFileSync(path.join(root,source))),entry,entrySha256:sha(fs.readFileSync(path.join(root,entry))),artifact:'renderer.js',artifactSha256:sha(script)};
 const files=new Map([[path.join(root,source),fs.readFileSync(path.join(root,source))],[path.join(root,entry),fs.readFileSync(path.join(root,entry))],[path.join(artifactRoot,'renderer.js'),Buffer.from(script)]]);change({manifest,files,root});files.set(path.join(artifactRoot,'manifest.json'),Buffer.from(JSON.stringify(manifest)));
 let options,qualifications=0;const fakeFs={constants:fs.constants,openSync(p,flags){assert(flags&fs.constants.O_NOFOLLOW);if(!files.has(p))throw Error('missing');return p;},fstatSync(p){return {isFile:()=>true,size:files.get(p).length};},readFileSync:p=>files.get(p),closeSync(){}};
 const mod={exports:{}};const code=fs.readFileSync(path.join(root,'server/services/secureshopMailBrowserQualification.js'),'utf8');vm.runInThisContext('(function(require,module,__dirname){'+code+'\n})')(name=>name==='node:fs'?fakeFs:name==='./xssBrowserQualification'?{MAX_HTML_BYTES:20000,createXssBrowserQualification:o=>{options=o;return {qualifyClient:async(html,config)=>{qualifications++;await o.clientMount({addScriptTag:async({content})=>assert.equal(content,script),evaluate:async(fn,arg)=>{assert.equal(typeof fn,'function');assert.equal(arg,html);assert(!fn.toString().includes(html));}}, {html,signal:config.signal});return {executed:false};},close:async()=>{}};}}:require(name),mod,path.join(root,'server/services'));
 return {api:mod.exports,getOptions:()=>options,files,manifest,root,source,entry,artifactRoot,qualifications:()=>qualifications};
}
test('pinned client artifact mounts through trusted script and data argument, never caller markup renderer',async()=>{const f=adapterFixture(),adapter=f.api.createSecureShopMailBrowserQualification();const result=await adapter.qualifyMail({html:'<b>owned message</b>',messageId:4});assert.equal(result.component.id,'SecureShop.MailMessageBody');assert.equal(result.executed,false);await assert.rejects(adapter.qualifyMail({html:'x',messageId:4,renderer:'forged'}));await assert.rejects(adapter.qualifyMail({html:'x'.repeat(20001),messageId:4}));const controller=new AbortController();controller.abort();await assert.rejects(adapter.qualifyMail({html:'x',messageId:4,signal:controller.signal}));});
// Native DOM qualification is opt-in; the remaining tests use controlled adapters.
// DVAIA_VERIFY_MAIL_RENDERER=1 node --test --test-name-pattern='production mail renderer structurally' tests/secureshopMailBrowserQualification.test.js
test('production mail renderer structurally mounts mixed prose raw HTML and rejects escaped markup', {
 skip: process.env.DVAIA_VERIFY_MAIL_RENDERER !== '1' ? 'Native Chrome/renderer qualification requires DVAIA_VERIFY_MAIL_RENDERER=1 outside the unit sandbox' : false,
 timeout: 30000 }, async t=>{
 const adapter=createSecureShopMailBrowserQualificationForTest();t.after(()=>adapter.close());
 const learner='A normal merchant greeting.\n\n<iframe title="V09 structural marker"></iframe>';
 const raw='<p>A normal merchant greeting.</p>\n<iframe title="V09 structural marker"></iframe>';
 const mounted=await adapter.qualifyInjection({html:raw,learnerHtml:learner,messageId:41});
 assert.equal(mounted.component.id,'SecureShop.MailMessageBody');assert.equal(mounted.learnerElementPreserved,true,JSON.stringify({reason:mounted.reason,learnerElementTag:mounted.learnerElementTag}));assert.equal(mounted.learnerElementTag,'iframe');
 const escaped=await adapter.qualifyInjection({html:'<p>A normal merchant greeting.</p>\n&lt;iframe title="V09 structural marker"&gt;&lt;/iframe&gt;',learnerHtml:learner,messageId:42});
 assert.equal(escaped.component.id,'SecureShop.MailMessageBody');assert.equal(escaped.learnerElementPreserved,false);assert.equal(escaped.learnerElementTag,'iframe');
});
function createSecureShopMailBrowserQualificationForTest(){
 const {createSecureShopMailBrowserQualification}=require('../server/services/secureshopMailBrowserQualification');
 return createSecureShopMailBrowserQualification({puppeteer:{launch:options=>require('puppeteer').launch({...options,timeout:15000,protocolTimeout:15000})}});
}
test('component, entry, artifact and manifest mismatches fail before browser construction',()=>{for(const mutate of [x=>x.manifest.sourceSha256='0'.repeat(64),x=>x.manifest.entrySha256='0'.repeat(64),x=>x.manifest.artifactSha256='0'.repeat(64),x=>x.manifest.component='Other',x=>x.manifest.artifact='../renderer.js']){const f=adapterFixture(mutate);assert.throws(()=>f.api.createSecureShopMailBrowserQualification(),/unavailable/);assert.equal(f.getOptions(),undefined);}});
function fakeBrowser(){const calls=[],page={createCDPSession:async()=>({send:async()=>({result:[]}),on(){},detach:async()=>{}}),on(){},setRequestInterception:async()=>calls.push('interception'),setCookie:async()=>calls.push('cookie'),goto:async()=>calls.push('navigation'),evaluate:async()=>({cookie:'qualification_session=synthetic-fixture-only',elementCount:1,eventAttributes:[]}),$eval:async()=>calls.push('innerHTML'),$$:async()=>[],close:async()=>calls.push('page-close')};const context={newPage:async()=>page,close:async()=>calls.push('context-close')};return {calls,page,browser:{createBrowserContext:async()=>context,disconnect(){}}};}
test('trusted client seam runs after isolation and never substitutes existing innerHTML/document modes',async()=>{const f=fakeBrowser();const runner=createXssBrowserQualification({connectBrowser:async()=>f.browser,clientMount:async(page,{html})=>{assert.equal(page,f.page);assert.equal(html,'<b>x</b>');f.calls.push('client');}});try{await runner.qualifyClient('<b>x</b>');assert.deepEqual(f.calls.slice(0,4),['interception','cookie','navigation','client']);assert(!f.calls.includes('innerHTML'));f.calls.length=0;await runner.qualify('<b>x</b>');assert(f.calls.includes('innerHTML'));assert(!f.calls.includes('client'));f.calls.length=0;const documentResult=await runner.qualifyDocument('<b>x</b>');assert.equal(documentResult.renderingMode,'document');assert(!f.calls.includes('client'));assert(!f.calls.includes('innerHTML'));await assert.rejects(runner.qualifyClient('x',{clientMount:()=>{}}));}finally{await runner.close();}});
test('source projection strips uninstrumented active attributes and inerts scripts without executing them',()=>{const {JSDOM}=require('../client/node_modules/jsdom');const dom=new JSDOM();const fn=vm.runInNewContext('('+projectTargetHtml.toString()+')',{document:dom.window.document});const result=fn({candidate:'<img onerror="proof();alert(1)"><iframe srcdoc="bad"></iframe><a href="javascript:alert(2)">x</a><script>alert(3)</script>',proof:'proof();'});assert(result.includes('proof();alert(1)'));assert(!result.includes('srcdoc'));assert(!result.includes('javascript:'));assert(result.includes('type="application/json"'));dom.window.close();});

test('client mode never attributes covered bootstrap token without the target runtime binding',async()=>{
 const f=fakeBrowser(),listeners=new Map();let token,scriptReads=0;
 f.page.createCDPSession=async()=>({on:(name,cb)=>listeners.set(name,cb),send:async(name)=>{if(name==='Profiler.takePreciseCoverage'){listeners.get('Debugger.scriptParsed')?.({scriptId:'trusted-bootstrap',url:'http://xss-qualification.invalid/',startLine:0,startColumn:0});return {result:[{scriptId:'trusted-bootstrap',functions:[{ranges:[{count:1}]}]}]};}if(name==='Debugger.getScriptSource'){scriptReads++;return {scriptSource:token};}return {};},detach:async()=>{}});
 f.page.evaluate=async(fn,arg)=>arg?.candidate?arg.candidate:{cookie:'qualification_session=synthetic-fixture-only',elementCount:1,eventAttributes:[]};
 const runner=createXssBrowserQualification({connectBrowser:async()=>f.browser,clientMount:async(_page,{html})=>{token=html.match(/0x([a-f0-9]+)n/)[1];}});
 try{const html='<img onerror="alert(1)">';const result=await runner.qualifyClient(html,{eventSource:html});assert.equal(result.targetEventExecuted,false);assert.equal(result.targetEffectObserved,false);assert.equal(scriptReads,0);assert(f.calls.includes('context-close'));}finally{await runner.close();}
});
test('client abort retains cancellation and closes owned context without calling another renderer',async()=>{const f=fakeBrowser(),controller=new AbortController();const runner=createXssBrowserQualification({connectBrowser:async()=>f.browser,clientMount:async()=>controller.abort(new DOMException('stopped','AbortError'))});try{await assert.rejects(runner.qualifyClient('<b>x</b>',{signal:controller.signal}),{name:'AbortError'});await new Promise(resolve=>setImmediate(resolve));assert(f.calls.includes('context-close'));assert(!f.calls.includes('innerHTML'));}finally{await runner.close();}});

test('supported build and setup command graph includes mail artifact without runtime compiler imports',()=>{const root=path.resolve(__dirname,'..');const scripts=JSON.parse(fs.readFileSync(path.join(root,'client/package.json'))).scripts;assert(scripts.build.includes('npm run build:review-renderer'));assert.equal(scripts['build:review-renderer'],'vite build --config vite.review-renderer.config.mjs');assert(scripts.build.includes('npm run build:mail-renderer'));assert.equal(scripts['build:mail-renderer'],'vite build --config vite.mail-renderer.config.mjs');assert(fs.readFileSync(path.join(root,'scripts/setup-application.js'),'utf8').includes("'run', 'build:mail-renderer'"));const adapter=fs.readFileSync(path.join(root,'server/services/secureshopMailBrowserQualification.js'),'utf8');assert(!adapter.includes("require('vite')"));assert(!adapter.includes("require('react')"));});

test('readComponent verifies immutable current binding without browser execution and denies closed adapter',async()=>{const f=adapterFixture(),adapter=f.api.createSecureShopMailBrowserQualification();const component=adapter.readComponent();assert(Object.isFrozen(component));assert.equal(component.id,'SecureShop.MailMessageBody');assert.equal(f.qualifications(),0);assert.equal(adapter.readComponent(),component);await adapter.close();assert.throws(()=>adapter.readComponent(),/unavailable/);await assert.rejects(adapter.qualifyMail({html:'x',messageId:4}),/unavailable/);assert.equal(f.qualifications(),0);});
test('readComponent rejects source, artifact and self-consistent manifest drift from loaded identity',()=>{for(const kind of ['source','artifact','consistent-entry']){const f=adapterFixture(),adapter=f.api.createSecureShopMailBrowserQualification();if(kind==='source')f.files.set(path.join(f.root,f.source),Buffer.from('changed'));if(kind==='artifact')f.files.set(path.join(f.artifactRoot,'renderer.js'),Buffer.from('changed'));if(kind==='consistent-entry'){const bytes=Buffer.from('new entry');f.files.set(path.join(f.root,f.entry),bytes);f.manifest.entrySha256=sha(bytes);f.files.set(path.join(f.artifactRoot,'manifest.json'),Buffer.from(JSON.stringify(f.manifest)));}assert.throws(()=>adapter.readComponent(),/unavailable/);assert.equal(f.qualifications(),0);}});

test('cancelled mount retains queue ownership until underlying mount and cleanup retire',async()=>{
 const f=fakeBrowser(),stop=new AbortController();let release,entered;const mounted=new Promise(r=>entered=r);let mounts=0;
 const runner=createXssBrowserQualification({connectBrowser:async()=>f.browser,retirementTimeoutMs:500,clientMount:async()=>{mounts++;if(mounts===1){entered();await new Promise(r=>release=r);}}});
 const first=runner.qualifyClient('first',{signal:stop.signal});const firstRejected=assert.rejects(first,{name:'AbortError'});await mounted;stop.abort();
 const next=runner.qualifyClient('second');await new Promise(r=>setImmediate(r));assert.equal(mounts,1);
 release();await firstRejected;await next;assert.equal(mounts,2);assert(f.calls.includes('context-close'));await runner.close();
});
test('unretired cancelled mount fails bounded close and permanently denies subsequent work',async()=>{
 const f=fakeBrowser(),stop=new AbortController();let entered;const mounted=new Promise(r=>entered=r);let mounts=0;
 const runner=createXssBrowserQualification({connectBrowser:async()=>f.browser,retirementTimeoutMs:100,clientMount:async()=>{mounts++;entered();await new Promise(()=>{});}});
 const first=runner.qualifyClient('first',{signal:stop.signal});const rejected=assert.rejects(first,error=>error.name==='AbortError'&&error.cleanupErrorCode==='BROWSER_RETIREMENT_INCOMPLETE');await mounted;stop.abort();
 const next=runner.qualifyClient('next');const nextRejected=assert.rejects(next,{code:'BROWSER_RETIREMENT_INCOMPLETE'});
 await rejected;await nextRejected;assert.equal(mounts,1);await assert.rejects(runner.close(),{code:'BROWSER_RETIREMENT_INCOMPLETE'});
});
test('close aborts active work and awaits deferred physical retirement before reporting success',async()=>{
 const f=fakeBrowser();let entered,release;const mounted=new Promise(r=>entered=r);
 const runner=createXssBrowserQualification({connectBrowser:async()=>f.browser,retirementTimeoutMs:500,clientMount:async()=>{entered();await new Promise(r=>release=r);}});
 const first=runner.qualifyClient('first');const rejected=assert.rejects(first,/qualification_closed/);await mounted;let done=false;const closing=runner.close().then(()=>done=true);await new Promise(r=>setImmediate(r));assert.equal(done,false);release();await rejected;await closing;assert.equal(done,true);await assert.rejects(runner.qualifyClient('later'),/qualification_closed/);
});
test('cancelled context cleanup must settle before next mount even when mount already returned',async()=>{
 const f=fakeBrowser(),stop=new AbortController();let release,entered;const cleanupStarted=new Promise(r=>entered=r),cleanup=new Promise(r=>release=r);let contexts=0,mounts=0;
 f.browser.createBrowserContext=async()=>{const index=++contexts;return {newPage:async()=>f.page,close:async()=>{if(index===1){entered();await cleanup;}}};};
 const runner=createXssBrowserQualification({connectBrowser:async()=>f.browser,retirementTimeoutMs:500,clientMount:async()=>{if(++mounts===1)stop.abort();}});
 const first=runner.qualifyClient('first',{signal:stop.signal});const rejected=assert.rejects(first,{name:'AbortError'});await cleanupStarted;const next=runner.qualifyClient('next');await new Promise(r=>setImmediate(r));assert.equal(contexts,1);release();await rejected;await next;assert.equal(contexts,2);await runner.close();
});
test('abort and finally share ordered page/context close and tolerate already closed page',async()=>{
 const f=fakeBrowser(),stop=new AbortController();let pageCloses=0,contextCloses=0;
 f.page.close=async()=>{pageCloses++;throw Error('Target closed');};
 f.browser.createBrowserContext=async()=>({newPage:async()=>f.page,close:async()=>{assert.equal(pageCloses,1);contextCloses++;}});
 const runner=createXssBrowserQualification({connectBrowser:async()=>f.browser,clientMount:async()=>stop.abort()});
 await assert.rejects(runner.qualifyClient('first',{signal:stop.signal}),{name:'AbortError'});assert.equal(pageCloses,1);assert.equal(contextCloses,1);await runner.close();
});
test('hanging owned browser close retains its exact hard-stop target',async()=>{
 let killed=0;const f=fakeBrowser();f.browser.close=async()=>new Promise(()=>{});f.browser.process=()=>({kill(){killed++;}});
 const runner=createXssBrowserQualification({puppeteer:{launch:async()=>f.browser},retirementTimeoutMs:100});await runner.qualify('x');await assert.rejects(runner.close(),{code:'BROWSER_RETIREMENT_INCOMPLETE'});await new Promise(r=>setImmediate(r));assert.equal(killed,1);
});
test('late browser connection after cancellation is retired without allowing replacement work',async()=>{
 let release,entered,killed=0;const began=new Promise(r=>entered=r);const f=fakeBrowser();f.browser.process=()=>({kill(){killed++;}});
 const runner=createXssBrowserQualification({puppeteer:{launch:()=>{entered();return new Promise(r=>release=r);}},retirementTimeoutMs:100});const stop=new AbortController();const pending=runner.qualify('x',{signal:stop.signal});const rejected=assert.rejects(pending,{name:'AbortError'});await began;stop.abort();await rejected;release(f.browser);await new Promise(r=>setImmediate(r));assert.equal(killed,1);await assert.rejects(runner.close(),{code:'BROWSER_RETIREMENT_INCOMPLETE'});
});
test('new work waits for deferred idle browser closure before launching another owner',async()=>{
 let release,entered,launches=0;const began=new Promise(r=>entered=r),f=fakeBrowser();f.browser.process=()=>null;f.browser.close=async()=>{entered();await new Promise(r=>release=r);};
 const next=fakeBrowser();next.browser.process=()=>null;next.browser.close=async()=>{};
 const runner=createXssBrowserQualification({puppeteer:{launch:async()=>++launches===1?f.browser:next.browser},retirementTimeoutMs:500,idleCloseMs:10});await runner.qualify('x');await new Promise(r=>setTimeout(r,20));await began;const pending=runner.qualify('y');await new Promise(r=>setImmediate(r));assert.equal(launches,1);release();await pending;assert.equal(launches,2);await runner.close();
});
