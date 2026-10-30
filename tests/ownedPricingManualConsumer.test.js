'use strict';
// In-memory transports only. No listener, model, database or Docker execution.
const test = require('node:test'), assert = require('node:assert/strict');
const fs = require('node:fs'), path = require('node:path'), crypto = require('node:crypto');
const { performance } = require('node:perf_hooks');
const M = require('./postgres/ownedPricingManualConsumer');
const helperPath = require.resolve('./fixtures/secureshopPricingActual');
const original = require(helperPath);
const E = require('./postgres/secureshopCustomerPricingActual.integration.test');
const root = path.resolve(__dirname, '..');
const health = () => new Response(JSON.stringify({version:'secureshop-owned-pricing-http.v1',ready:true,
  isolation:'bwrap-owned-pricing-http-v1',pricingCapability:'secureshop-owned-pricing-http.v1'}));
const defer = () => { let resolve, reject; const promise = new Promise((a,b) => { resolve=a; reject=b; }); return {promise,resolve,reject}; };
const tick = () => new Promise(resolve => setImmediate(resolve));

function setup(t) {
  const directory = fs.mkdtempSync(path.join(root, 'tasks/qualification/v25-controlled-'));
  fs.chmodSync(directory, 0o700);
  const prior = Object.fromEntries(['PERSONA_PRICING_MANUAL_ONLY','PERSONA_PRICING_ACTUAL_REMAINING',
    'PERSONA_PRICING_COHORT','OWASP_AI_GOAT_PRICING_OWNED_OUTPUT_ROOT','OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE'].map(k=>[k,process.env[k]]));
  Object.assign(process.env,{PERSONA_PRICING_MANUAL_ONLY:'1',PERSONA_PRICING_ACTUAL_REMAINING:'0',
    PERSONA_PRICING_COHORT:'baseline',OWASP_AI_GOAT_PRICING_OWNED_OUTPUT_ROOT:directory,OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE:root});
  const descriptor = {version:1,ownerId:'10000000-0000-4000-8000-000000000001',
    workspaceId:require('../scripts/application-data-root').workspaceId(root),qualificationNonce:'b'.repeat(12),
    containerId:'c'.repeat(64),imageId:'sha256:'+'d'.repeat(64),packageSha256:'e'.repeat(64),
    profile:'owasp-ai-goat-owned-pricing-http-'+'b'.repeat(12),origin:'http://127.0.0.1:18093',token:'t'.repeat(43)};
  const file=path.join(directory,'private-executor.json'),raw=JSON.stringify(descriptor);
  fs.writeFileSync(file,raw,{mode:0o600});
  const expected=Object.fromEntries(Object.entries(descriptor).filter(([k])=>!['version','token'].includes(k)));
  const dependencies=Object.fromEntries(['identity','im','agents','review','launches','conversations',
    'conversationRepository','turns','journal','coordinator','catalog','products','authority','owner','auth'].map(k=>[k,{}]));
  const controller=new AbortController(), requests=[];
  const fetch=global.fetch;
  global.fetch=async (url,options)=>{ requests.push({url:String(url),options});
    assert.equal(String(url),descriptor.origin+'/secureshop/pricing/health');
    assert.equal(options.method,'GET');assert.equal(options.redirect,'error');
    assert.equal(options.headers.authorization,'Bearer '+descriptor.token);return health(); };
  t.after(()=>{ global.fetch=fetch;require.cache[helperPath].exports=original;
    for(const [k,v] of Object.entries(prior)){if(v===undefined)delete process.env[k];else process.env[k]=v;}
    fs.rmSync(directory,{recursive:true,force:true}); });
  return {directory,descriptor,requests,controller,dependencies,
    options:{descriptorPath:file,descriptorSha256:crypto.createHash('sha256').update(raw).digest('hex'),
      expected,dependencies,startedAt:performance.now(),signal:controller.signal}};
}
function replaceHelper(fn) { require.cache[helperPath].exports=Object.assign(fn,{actualPricingBudget:original.actualPricingBudget}); }

test('closed public entry and original manual budget are exact, with no native claim',()=>{
  assert.equal(M.LIVE_ENABLED,false);assert.throws(()=>M.run(),{code:'V25_MANUAL_NOT_ADMITTED'});
  const c=M.contract();assert.equal(c.fixtureMs,840000);assert.equal(c.helperMs,780000);
  assert.deepEqual(c.budget,original.actualPricingBudget(true,false,'baseline').budget);
  for(const [phase,caseId,max] of [['actor','manual_clean',8],['actor','manual_upload',4],['actor','manual_override',8],['judge','manual_clean',6],['judge','manual_override',6]]){
    const b=original.actualPricingBudget(true,false,'baseline');
    assert(b.allows(Array.from({length:max-1},()=>({phase,caseId})),phase,caseId));
    assert(!b.allows(Array.from({length:max},()=>({phase,caseId})),phase,caseId));
  }
  assert.equal(c.qualificationComplete,false);assert.equal(c.builderReleaseAllowed,false);
  assert(c.blockers.includes('composed-v25-native-qualification-not-run'));
});

test('actual private descriptor/client readiness precedes fixed helper delegation and local join',async t=>{
  const x=setup(t), observation={controlled:true};let used;
  replaceHelper(async d=>{used=d;assert.equal(x.requests.length,1);await d.client.assertReady({signal:x.controller.signal});return observation;});
  const result=await M._consume(x.options);
  for(const key of Object.keys(x.dependencies))assert.equal(used[key],x.dependencies[key]);
  assert.equal(result.observation,observation);assert.equal(x.requests.length,2);
  assert.equal(result.receipt.helperJoined,true);assert.equal(result.receipt.localClientClosed,true);
  assert.equal(result.receipt.builderReleaseAllowed,false);assert.equal(result.receipt.qualificationComplete,false);
  assert.equal(result.receipt.transportRetirementProven,false);
  assert(!JSON.stringify(result.receipt).includes(x.descriptor.token));
  assert.throws(()=>used.client.assertReady({signal:x.controller.signal}));
});

test('malformed selectors, supplied client, expired/future start and aborted signal have zero requests',async t=>{
  const x=setup(t);replaceHelper(async()=>assert.fail('helper must not run'));
  for(const patch of [{startedAt:NaN},{startedAt:-1},{startedAt:performance.now()+10000},
    {startedAt:performance.now()-840001},{dependencies:{...x.dependencies,client:{}}}])
    await assert.rejects(()=>M._consume({...x.options,...patch}));
  for(const [key,value] of [['PERSONA_PRICING_MANUAL_ONLY','0'],['PERSONA_PRICING_ACTUAL_REMAINING','1'],['PERSONA_PRICING_COHORT','near-market-v1']]){
    const old=process.env[key];process.env[key]=value;await assert.rejects(()=>M._consume(x.options),{code:'V25_MANUAL_SELECTOR'});process.env[key]=old;
  }
  x.controller.abort();await assert.rejects(()=>M._consume(x.options));assert.equal(x.requests.length,0);
});

test('V25 native selector cannot bypass inherited branded admission through controlled consumer',async t=>{
  const x=setup(t),prior=process.env.SECURESHOP_PRICING_V25_MANUAL_NATIVE;
  process.env.SECURESHOP_PRICING_V25_MANUAL_NATIVE='1';
  t.after(()=>{if(prior===undefined)delete process.env.SECURESHOP_PRICING_V25_MANUAL_NATIVE;
    else process.env.SECURESHOP_PRICING_V25_MANUAL_NATIVE=prior;});
  await assert.rejects(()=>M._consume(x.options),{code:'V25_MANUAL_OWNER_ADMISSION'});
  await assert.rejects(()=>M._consume({...x.options,admitted:Object.freeze({...x.options,deadline:performance.now()+840000})}),
    {code:'V25_MANUAL_OWNER_ADMISSION'});
  assert.equal(x.requests.length,0);
});

test('real descriptor hash/owner/path validation rejects without transport and claims no join',async t=>{
  const x=setup(t);replaceHelper(async()=>assert.fail('helper must not run'));
  for(const patch of [{descriptorSha256:'0'.repeat(64)},{expected:{...x.options.expected,ownerId:'20000000-0000-4000-8000-000000000002'}},
    {descriptorPath:path.join(root,'private-executor.json')}]){
    await assert.rejects(()=>M._consume({...x.options,...patch}),e=>{assert.equal(e.manualConsumer.localClientClosed,false);return true;});
  }
  assert.equal(x.requests.length,0);
});

test('delayed readiness consumes startup allowance instead of renewing helper deadline',async t=>{
  const x=setup(t);let now=100;t.mock.method(performance,'now',()=>now);x.options.startedAt=now;
  global.fetch=async()=>{now=60100;return health();};replaceHelper(async()=>assert.fail('late helper'));
  await assert.rejects(()=>M._consume(x.options),e=>{assert.equal(e.code,'V25_MANUAL_HELPER_RESERVE');
    assert.equal(e.manualConsumer.helperStarted,false);assert.equal(e.manualConsumer.localClientClosed,true);return true;});
});

test('abort cannot settle consumer or release private client while original work is pending',async t=>{
  const x=setup(t), entered=defer(), pending=defer();let client,settled=false;
  replaceHelper(async d=>{client=d.client;entered.resolve();return pending.promise;});
  const work=M._consume(x.options);work.then(()=>{settled=true;},()=>{settled=true;});
  t.after(async()=>{pending.resolve({controlled:true});await work.catch(()=>{});});
  await Promise.race([entered.promise,work]);x.controller.abort();await tick();assert.equal(settled,false);
  assert.throws(()=>client.assertReady({signal:x.controller.signal}));
  pending.resolve({controlled:true});
  await assert.rejects(()=>work,e=>{assert.equal(e.manualConsumer.helperJoined,true);assert.equal(e.manualConsumer.localClientClosed,true);return true;});
});

test('late helper completion fails original endpoint, even with a returned observation',async t=>{
  const x=setup(t);let now=100;t.mock.method(performance,'now',()=>now);x.options.startedAt=now;
  replaceHelper(async()=>{now=840100;return {controlled:true};});
  await assert.rejects(()=>M._consume(x.options),{code:'V25_MANUAL_EXPIRED'});
});

for (const earlierFailure of [false,true]) test(`joined close after840s vetoes success; prior failure=${earlierFailure}`,async t=>{
  const x=setup(t),primary=Object.assign(Error('controlled earlier failure'),{code:'CONTROLLED_PRIMARY'});
  let now=100,closeJoined=false;t.mock.method(performance,'now',()=>now);x.options.startedAt=now;
  replaceHelper(async()=>{now=840099;if(earlierFailure)throw primary;return {controlled:true};});
  const real=E.openAdmittedPricingExecutor;
  t.mock.method(E,'openAdmittedPricingExecutor',async options=>{
    const e=await real(options);
    return {...e,close:async()=>{await e.close();await tick();now=840100;closeJoined=true;}};
  });
  await assert.rejects(()=>M._consume(x.options),e=>{
    assert.equal(closeJoined,true);
    if(earlierFailure)assert.equal(e,primary);else assert.equal(e.code,'V25_MANUAL_EXPIRED');
    assert.equal(e.manualConsumer.helperJoined,true);assert.equal(e.manualConsumer.localClientClosed,true);
    assert.equal(e.manualConsumer.transportRetirementProven,false);assert.equal(e.manualConsumer.builderReleaseAllowed,false);
    assert.deepEqual(e.manualConsumer.cleanupErrors,[]);return true;
  });
});

test('close rejection/pending preserves primary and never manufactures resource release',async t=>{
  const x=setup(t), primary=Object.assign(Error('controlled helper failure'),{code:'CONTROLLED'});
  replaceHelper(async()=>{throw primary;});
  const real=E.openAdmittedPricingExecutor;let close=defer(),entered=defer(),settled=false;
  t.mock.method(E,'openAdmittedPricingExecutor',async opts=>{const e=await real(opts);return {...e,close:async()=>{await e.close();entered.resolve();await close.promise;}};});
  const work=M._consume(x.options);work.catch(()=>{settled=true;});await Promise.race([entered.promise,work]);await tick();assert.equal(settled,false);
  close.reject(Error('controlled close rejection'));
  await assert.rejects(()=>work,e=>{assert.equal(e,primary);assert.deepEqual(e.manualConsumer.cleanupErrors,['private-client']);
    assert.equal(e.manualConsumer.localClientClosed,false);assert.equal(e.manualConsumer.builderReleaseAllowed,false);return true;});
});

test('actual original helper rejects repository output: no model call or fake store admission',async t=>{
  const x=setup(t);
  await assert.rejects(()=>M._consume(x.options),e=>{assert.match(e.message,/outside source/);
    assert.equal(e.manualConsumer.helperStarted,true);assert.equal(e.manualConsumer.helperJoined,true);
    assert.equal(e.manualConsumer.localClientClosed,true);return true;});
  assert.equal(x.requests.length,1);assert(!fs.existsSync(path.join(x.directory,'pricing-actual-result.json')));
});

test('actual original helper startup uses original20/12 and schedules780s; output is explicitly doubled',async t=>{
  const x=setup(t), stop=Error('controlled stop before store effects');
  t.mock.method(require('./fixtures/pricingOwnedOutput'),'pricingOwnedOutputRoot',()=>x.directory);
  x.dependencies.im={query:async()=>{throw stop;},connect:async()=>{throw stop;}};
  let tagReads=0;
  const privateFetch=global.fetch;
  const timers=[],set=global.setTimeout;
  t.mock.method(global,'setTimeout',(callback,delay,...args)=>{timers.push(delay);return set(callback,delay,...args);});
  global.fetch=async(url,opts)=>{
    if(String(url)==='http://127.0.0.1:11434/api/tags'){
      tagReads++;return new Response(JSON.stringify({models:[{name:'llama3.1:8b',digest:'46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e'}]}));
    }
    return privateFetch(url,opts);
  };
  await assert.rejects(()=>M._consume(x.options),e=>{assert.equal(e,stop);assert.equal(e.manualConsumer.localClientClosed,true);return true;});
  assert.equal(tagReads,1);
  assert.equal(timers.filter(ms=>ms===780000).length,1);
  const saved=JSON.parse(fs.readFileSync(path.join(x.directory,'pricing-actual-result.json'),'utf8'));
  assert.deepEqual(saved.budget,M.contract().budget);assert.deepEqual(saved.calls,[]);
  assert.equal(saved.cohort,'baseline');assert.equal(saved.status,'running');
});

test('actual helper model-only fetch guard cannot intercept admitted private client; admission stays closed',async t=>{
  const x=setup(t), stop=Error('controlled stop before store effects');let opened,inside=false,tagReads=0;
  const real=E.openAdmittedPricingExecutor;
  t.mock.method(E,'openAdmittedPricingExecutor',async options=>{opened=await real(options);return opened;});
  t.mock.method(require('./fixtures/pricingOwnedOutput'),'pricingOwnedOutputRoot',()=>x.directory);
  const privateFetch=global.fetch;
  global.fetch=async(url,opts)=>{
    if(String(url)==='http://127.0.0.1:11434/api/tags'){
      tagReads++;return new Response(JSON.stringify({models:[{name:'llama3.1:8b',digest:'46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e'}]}));
    }
    return privateFetch(url,opts);
  };
  const insideOriginal=async()=>{inside=true;await opened.client.assertReady({signal:x.controller.signal});throw stop;};
  x.dependencies.im={query:insideOriginal,connect:insideOriginal};
  await assert.rejects(()=>M._consume(x.options),e=>{assert.equal(e,stop);
    assert.equal(e.manualConsumer.helperJoined,true);assert.equal(e.manualConsumer.localClientClosed,true);
    assert.equal(e.manualConsumer.builderReleaseAllowed,false);return true;});
  assert.equal(inside,true);assert.equal(tagReads,1);assert.equal(x.requests.length,2);
  assert(x.requests.every(request=>request.url===x.descriptor.origin+'/secureshop/pricing/health'));
  assert(x.requests.every(request=>request.options.headers.authorization==='Bearer '+x.descriptor.token));
  assert(x.requests.every(request=>request.options.signal instanceof AbortSignal));
  assert.throws(()=>opened.client.assertReady({signal:x.controller.signal}));
  assert.throws(()=>M.run(),{code:'V25_MANUAL_NOT_ADMITTED'});
});

test('admitted private request observes caller abort, joins close and cannot retry after close',async t=>{
  const x=setup(t), entered=defer();let opened;
  const admittedFetch=global.fetch;
  global.fetch=async(url,options)=>{
    if(x.requests.length===0)return admittedFetch(url,options);
    x.requests.push({url:String(url),options});entered.resolve();
    return new Promise((_,reject)=>options.signal.addEventListener('abort',()=>reject(options.signal.reason),{once:true}));
  };
  opened=await E.openAdmittedPricingExecutor({descriptorPath:x.options.descriptorPath,
    descriptorSha256:x.options.descriptorSha256,expected:x.options.expected,signal:x.controller.signal});
  const pending=opened.client.assertReady({signal:x.controller.signal});
  await entered.promise;
  x.controller.abort();
  await assert.rejects(pending);
  await opened.close();
  assert.deepEqual(opened.retirement(),{localClientClosed:true,executorRetirementOwnedByLauncher:true});
  assert.equal(x.requests.length,2);
  assert.equal(x.requests[1].url,x.descriptor.origin+'/secureshop/pricing/health');
  assert.equal(x.requests[1].options.headers.authorization,'Bearer '+x.descriptor.token);
  assert(x.requests[1].options.signal.aborted);
  assert.throws(()=>opened.client.assertReady({signal:x.controller.signal}));
  assert.equal(x.requests.length,2);
});
