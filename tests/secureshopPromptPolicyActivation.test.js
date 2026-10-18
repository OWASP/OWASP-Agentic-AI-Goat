'use strict';
const test=require('node:test');const assert=require('node:assert/strict');
const {activationPolicy,preparePromptPolicyRenderer}=require('../server/services/secureshopPromptPolicyActivation');
const env={SS_BOUND_PROMPT_POLICIES_ENABLED:'true',SS_ENABLE:'true',SS_BOUND_REVIEWS_ENABLED:'true',PLATFORM_DATABASE_ENGINE:'postgres',WORKSHOP_DATABASE_ENGINE:'postgres',SS_POLICY_RENDERER_BASE_URL:'http://127.0.0.1:9090/'};
const healthy={policyRenderer:{enabled:true,available:true,isolation:'bwrap-policy-template-v1'}};
test('absent and explicit-false configuration neither resolve renderer nor probe network',async()=>{
 const fetchImpl=()=>{throw Error('Must not probe');};
 assert.deepEqual(activationPolicy({}),{requested:false});
 assert.equal(await preparePromptPolicyRenderer({env:{},fetchImpl}),undefined);
 assert.deepEqual(activationPolicy({SS_BOUND_PROMPT_POLICIES_ENABLED:'false'}),{requested:false});
 assert.equal(await preparePromptPolicyRenderer({env:{SS_BOUND_PROMPT_POLICIES_ENABLED:'false'},fetchImpl}),undefined);
});
test('explicit feature rejects invalid flags, storage, app state and ambiguous origins',()=>{
 for(const change of [{SS_BOUND_PROMPT_POLICIES_ENABLED:'1'},{SS_ENABLE:'false'},{SS_BOUND_REVIEWS_ENABLED:'false'},{PLATFORM_DATABASE_ENGINE:'sqlite'},{WORKSHOP_DATABASE_ENGINE:'sqlite'},{SS_POLICY_RENDERER_BASE_URL:undefined},{SS_POLICY_RENDERER_BASE_URL:'http://user:secret@localhost'},{SS_POLICY_RENDERER_BASE_URL:'http://localhost/path'},{SS_POLICY_RENDERER_BASE_URL:'http://localhost/?secret=yes'},{SS_POLICY_RENDERER_BASE_URL:'file:///tmp/renderer'}])assert.throws(()=>activationPolicy({...env,...change}),{code:'INVALID_CONFIGURATION'});
 assert.deepEqual(activationPolicy(env),{requested:true,baseUrl:'http://127.0.0.1:9090'});
});
test('strict readiness constructs renderer only after verified isolated health',async()=>{
 let calls=0;const renderer=await preparePromptPolicyRenderer({env,fetchImpl:async(url,options)=>{calls++;assert.equal(url,'http://127.0.0.1:9090/health');assert.equal(options.redirect,'error');assert.ok(options.signal);return Response.json(healthy);}});assert.equal(calls,1);assert.equal(typeof renderer.render,'function');
});
test('missing, disabled, nonisolated or oversized health fails without downgrade',async()=>{
 for(const health of [{},{policyRenderer:{...healthy.policyRenderer,enabled:false}},{policyRenderer:{...healthy.policyRenderer,available:false}},{policyRenderer:{...healthy.policyRenderer,isolation:'plain'}}])await assert.rejects(preparePromptPolicyRenderer({env,fetchImpl:async()=>Response.json(health)}),{code:'POLICY_RENDER_UNAVAILABLE'});
 await assert.rejects(preparePromptPolicyRenderer({env,fetchImpl:async()=>new Response('x'.repeat(600000))}),{code:'POLICY_RENDER_UNAVAILABLE'});
});
test('readiness deadline aborts the request and preserves categorical failure',async()=>{
 let aborted=false;await assert.rejects(preparePromptPolicyRenderer({env,timeoutMs:100,fetchImpl:async(_url,{signal})=>new Promise((_resolve,reject)=>signal.addEventListener('abort',()=>{aborted=true;reject(Error('Private network details'));},{once:true}))}),{code:'POLICY_RENDER_UNAVAILABLE',message:'Requested strict policy renderer is unavailable'});assert.equal(aborted,true);
});

test('prepared renderer readiness rechecks current isolation and availability without invoking render',async()=>{
 let healthyNow=true;const calls=[];
 const renderer=await preparePromptPolicyRenderer({env,fetchImpl:async(url,options)=>{
  calls.push({url,options});return Response.json(healthyNow?healthy:{policyRenderer:{...healthy.policyRenderer,isolation:'host'}});
 }});
 assert.equal(await renderer.checkReadiness(),true);
 healthyNow=false;await assert.rejects(renderer.checkReadiness(),{code:'POLICY_RENDER_UNAVAILABLE'});
 assert.equal(calls.length,3);assert.ok(calls.every(call=>call.url.endsWith('/health')&&call.options.method===undefined&&call.options.redirect==='error'));
});
