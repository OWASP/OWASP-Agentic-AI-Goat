'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const {createLangChainProvider}=require('../server/agent-runtime/providers/langchainProvider');
const calibration=require('./fixtures/secureshopPersonaCrossV2JudgeCalibration');
const LIVE=process.env.RUN_LIVE_SECURESHOP_PERSONA_CROSS_V2_CALIBRATION==='1';
test('local llama3.1:8b grounds authenticated cross-persona v2 disclosures',{skip:!LIVE,timeout:660000},async t=>{
 assert.equal(process.env.JUDGE_PROVIDER,'ollama');assert.equal(process.env.JUDGE_MODEL,calibration.MODEL);
 const url=new URL(process.env.OLLAMA_BASE_URL);assert.equal(url.hostname,'127.0.0.1');
 const provider=createLangChainProvider({provider:'ollama',model:calibration.MODEL,baseURL:url.toString().replace(/\/$/,'')});
 const controller=new AbortController(),timer=setTimeout(()=>controller.abort(Error('deadline')),600000);timer.unref?.();
 try{const output=await calibration.runCalibration({classify:async({messages,tools,options})=>provider.chat(messages,tools,options),
  recordAttempt:async row=>t.diagnostic(JSON.stringify({scope:'secureshop_persona_cross_v2_attempt',attempt:row})),
  recordResult:async row=>t.diagnostic(JSON.stringify({scope:'secureshop_persona_cross_v2_result',result:row})),
  qualification:true,signal:controller.signal});
  t.diagnostic(JSON.stringify({scope:'secureshop_persona_cross_v2_summary',qualification:output.qualified,
    expectedProviderCalls:calibration.EXPECTED_PROVIDER_CALLS,maximumProviderCalls:calibration.MAX_PROVIDER_CALLS,calls:output.calls}));
  assert.equal(output.qualified,true);assert.equal(output.calls,calibration.EXPECTED_PROVIDER_CALLS);
 }finally{clearTimeout(timer);}
});
