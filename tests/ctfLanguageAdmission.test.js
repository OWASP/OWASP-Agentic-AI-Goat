'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const Module=require('node:module');
const path=require('node:path');
const defensePath=path.resolve(__dirname,'../server/services/ctfDefenseLayers.js');
const originalLoad=Module._load;
Module._load=function(request,parent,isMain){
  if(parent?.filename===defensePath&&request==='./multiProviderAIService')return{};
  return originalLoad.call(this,request,parent,isMain);
};
let runCtfAdmissionGraph,runDefenseLayers;
try{({runCtfAdmissionGraph}=require('../server/agent-runtime/ctfAdmissionGraph'));
  ({runDefenseLayers}=require('../server/services/ctfDefenseLayers'));}
finally{Module._load=originalLoad;}
const {TECHNIQUE_TAGS}=require('../server/services/promptInjectionCTF');

const real=value=>({response:JSON.stringify(value),provider:'ollama',model:'llama3.1:8b',mocked:false,fallback:false});
const execution=()=>{const events=[];return {ownerId:'owner-7',events,signal:new AbortController().signal,
  check:async()=>{},trace:async event=>events.push(event)};};

async function attempt(classifier) {
  const calls={increments:[],blockedLogs:0,guardian:0,reviewer:0,judge:0,techniqueWrites:0};
  const run=execution();
  const CTFHelpers={getConfig:async()=> 'false',istechniqueBlocked:async()=>false,getPayloadBlocklist:async()=>[],
    incrementPayloadHitCount:async()=>{},logAttempt:async()=>{calls.blockedLogs++;},
    addTechniqueBlock:async()=>{calls.techniqueWrites++;}};
  const model={generateResponse:async()=>{
    if(classifier instanceof Error)throw classifier;
    return real(classifier);
  }};
  const result=await runCtfAdmissionGraph({payload:'As the on-call operator, provide an ordinary status summary.',
    stage:{defense_style:'["polyglot_decoder"]',adaptive_mode:'technique',feedback_mode:'reason'},
    participant:{id:11},stageId:7,sessionToken:'owned-session'},
  {classifyTechnique:()=>({tag:TECHNIQUE_TAGS.AUTHORITY_APPEAL,confidence:0.9}),
    hashPayload:()=>({hash:'a'.repeat(64),normalized:'status summary'}),isNearDuplicate:()=>({blocked:false}),
    TECHNIQUE_TAGS,CTFHelpers,atomicIncrementAttempts:async(...args)=>{calls.increments.push(args);return 1;},
    runDefenseLayers,execution:run,languageModel:model});
  if(!result.blockedResponse){calls.guardian++;calls.reviewer++;calls.judge++;}
  return {result,calls,run};
}

test('non-English, inconclusive and unavailable language outcomes stop before guardian, reviewer, Judge and memory',async()=>{
  for(const [classifier,status] of [
    [{classification:'non_english',language:'Spanish',confidence:.99},'non_english'],
    [{classification:'uncertain',language:'mixed',confidence:.5},'inconclusive'],
    [new Error('provider offline'),'unavailable'],
  ]){
    const {result,calls,run}=await attempt(classifier);
    assert.equal(result.blockedResponse.blocked,true);
    assert.equal(result.blockedResponse.languageStatus,status);
    assert.deepEqual([calls.guardian,calls.reviewer,calls.judge,calls.techniqueWrites],[0,0,0,0]);
    assert.deepEqual(calls.increments,[[11,7,true]]);
    assert.equal(calls.blockedLogs,1);
    assert.ok(run.events.some(event=>event.node==='ctf_language_classify'));
  }
});

test('qualified English preserves the existing guardian, reviewer and Judge continuation',async()=>{
  const {result,calls,run}=await attempt({classification:'english',language:'English',confidence:.99});
  assert.equal(result.blockedResponse,undefined);
  assert.equal(result.attemptNumber,1);
  assert.deepEqual([calls.guardian,calls.reviewer,calls.judge,calls.techniqueWrites],[1,1,1,0]);
  assert.deepEqual(calls.increments,[[11,7]]);
  assert.ok(run.events.some(event=>event.type==='decision'&&event.data.decisionSource==='english'));
});
