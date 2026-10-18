'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {EventEmitter}=require('node:events');
const {browserEndpoint,admitRendered,admitRenderedScenario,renderedProtocolTimeout}=require('./fixtures/fullBackendRenderedBranch');
test('semantic cohorts have separate explicit budgets and reject mixed or partial admission',()=>{
 assert.deepEqual(admitRenderedScenario(),{mcpChatTimeoutMs:10000,secureShopTimeoutMs:10000});
 assert.deepEqual(admitRenderedScenario({mcp:{mode:'public_indirect',nativeEvidence:{}}}),{mcpChatTimeoutMs:420000,secureShopTimeoutMs:10000});
 assert.deepEqual(admitRenderedScenario({secureShop:{mode:'all_objectives',nativeEvidence:{}}}),{mcpChatTimeoutMs:10000,secureShopTimeoutMs:420000});
 for(const options of [{secureShop:null},{secureShop:{mode:'all_objectives'}},{secureShop:{mode:'partial',nativeEvidence:{}}},{mcp:{mode:'public_indirect',nativeEvidence:{}},secureShop:{mode:'all_objectives',nativeEvidence:{}}}])assert.throws(()=>admitRenderedScenario(options));
});
test('browser protocol deadline exceeds every admitted rendered workflow deadline',()=>{
 for(const options of [undefined,{mcp:{mode:'public_indirect',nativeEvidence:{}}},
   {secureShop:{mode:'all_objectives',nativeEvidence:{}}}]){
  const timeouts=admitRenderedScenario(options),protocolTimeout=renderedProtocolTimeout(timeouts);
  assert.equal(protocolTimeout,Math.max(timeouts.mcpChatTimeoutMs,timeouts.secureShopTimeoutMs)+30000);
  assert.ok(protocolTimeout>timeouts.mcpChatTimeoutMs);
  assert.ok(protocolTimeout>timeouts.secureShopTimeoutMs);
 }
 for(const value of [null,{}, {mcpChatTimeoutMs:999,secureShopTimeoutMs:10000},
   {mcpChatTimeoutMs:10000,secureShopTimeoutMs:420001}])assert.throws(()=>renderedProtocolTimeout(value));
});
test('rendered mode is explicit and rejects missing pinned browser',()=>{
 assert.equal(admitRendered({}),null);assert.throws(()=>admitRendered({PG_FULL_BACKEND_RENDERED:'true'}));assert.throws(()=>admitRendered({PG_FULL_BACKEND_RENDERED:'1'}));
});
test('browser endpoint accepts owned loopback, rejects foreign, exits and deadlines with clean listeners',async()=>{
 for(const scenario of ['valid','foreign','wrong-port','exit','timeout','abort']){
  const child=new EventEmitter();child.stderr=new EventEmitter();const controller=new AbortController();
  const waiting=browserEndpoint(child,controller.signal,10,4321);
  if(scenario==='valid')child.stderr.emit('data','DevTools listening on ws://127.0.0.1:4321/devtools/browser/owned\n');
  if(scenario==='foreign')child.stderr.emit('data','DevTools listening on ws://example.invalid:4321/devtools/browser/owned\n');
  if(scenario==='wrong-port')child.stderr.emit('data','DevTools listening on ws://127.0.0.1:4322/devtools/browser/owned\n');
  if(scenario==='exit')child.emit('exit');if(scenario==='abort')controller.abort();
  if(scenario==='valid')assert.match(await waiting,/127.0.0.1/);else await assert.rejects(waiting);
  assert.equal(child.listenerCount('exit'),0);assert.equal(child.stderr.listenerCount('data'),0);
 }
});

test('owned browser uses installed automation defaults and exactly one closed routing/profile authority',async()=>{
 const {ownedBrowserArgs}=require('./fixtures/fullBackendRenderedBranch');
 const args=await ownedBrowserArgs({profile:'/owned/profile',devtoolsPort:4321,proxyOrigin:'http://127.0.0.1:4322',netLog:'/owned/netlog.json'});
 for(const flag of ['--password-store=basic','--use-mock-keychain','--proxy-bypass-list=<-loopback>','--disable-quic','--force-webrtc-ip-handling-policy=disable_non_proxied_udp','--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1','--net-log-capture-mode=Default'])assert.ok(args.includes(flag),flag);
 for(const [prefix,value] of [['--user-data-dir=','/owned/profile'],['--remote-debugging-port=','4321'],['--proxy-server=','http://127.0.0.1:4322'],['--log-net-log=','/owned/netlog.json']])assert.deepEqual(args.filter(a=>a.startsWith(prefix)),[prefix+value]);
 assert.equal(args.filter(a=>a.startsWith('--headless')).length,1);
 assert.ok(!args.includes('--no-sandbox'));
});
test('cleanup receipt retains only bounded nested socket code and phase',()=>{
 const {describeCleanupFailure}=require('./fixtures/fullBackendRenderedBranch');
 const socket=Object.assign(Error('postgresql://private:secret@host/db'),{code:'EIO',phase:'browser-teardown'});
 const summary=describeCleanupFailure(new AggregateError([socket],'Owned forward proxy socket failure'));
 assert.deepEqual(summary,{name:'AggregateError',message:'Owned forward proxy socket failure',errors:[{name:'Error',code:'EIO',phase:'browser-teardown'}]});
 assert.ok(!JSON.stringify(summary).includes('secret'));
});
test('standalone helper marks browser teardown before context close and preserves primary failure',async()=>{
 const {qualifyFullBackendRenderedStandalone}=require('./fixtures/fullBackendRenderedStandalone');
 for(const closeFails of [false,true]){
  const events=[],primary=Error('controlled primary assertion'),closeError=Error('controlled close failure');
  const page={setDefaultTimeout(){},on(){},async setRequestInterception(){},async setCacheEnabled(){},
   async goto(){events.push('primary');throw primary;}};
  const context={async newPage(){return page;},async close(){events.push('close');if(closeFails)throw closeError;}};
  const browser={async createBrowserContext(){return context;}};
  await assert.rejects(qualifyFullBackendRenderedStandalone({browser,origin:'http://127.0.0.1:43210',
   workshop:{},shop:{},productId:1,beginBrowserTeardown(){events.push('marker');}}),error=>
   closeFails?error instanceof AggregateError&&error.errors[0]===primary&&error.errors[1]===closeError:error===primary);
  assert.deepEqual(events,['primary','marker','close']);
 }
});
