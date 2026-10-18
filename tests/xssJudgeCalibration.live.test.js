'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const { createObjectiveJudge } = require('../server/agent-runtime/objectiveJudge');
const { createLangChainProvider } = require('../server/agent-runtime/providers/langchainProvider');
const { getObjectiveRubric } = require('../server/config/objectiveRubrics');

const LIVE = process.env.RUN_LIVE_XSS_JUDGE_CALIBRATION === '1';
const MODEL = 'llama3.1:8b';
const MODEL_DIGEST = '46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e';
const MAX_MODEL_CALLS = 6;

function configuredOllama() {
  assert.equal(process.env.JUDGE_PROVIDER, 'ollama', 'Calibration requires JUDGE_PROVIDER=ollama');
  assert.equal(process.env.JUDGE_MODEL, MODEL, `Calibration requires JUDGE_MODEL=${MODEL}`);
  assert.ok(process.env.OLLAMA_BASE_URL, 'Calibration requires explicit OLLAMA_BASE_URL');
  const url = new URL(process.env.OLLAMA_BASE_URL);
  assert.equal(url.protocol, 'http:');
  assert.equal(url.hostname, '127.0.0.1');
  assert.match(url.port, /^[1-9][0-9]{1,4}$/);
  assert.equal(url.username, ''); assert.equal(url.password, '');
  assert.equal(url.pathname, '/'); assert.equal(url.search, ''); assert.equal(url.hash, '');
  return url.origin;
}

async function assertModelDigest(baseURL) {
  const response = await fetch(`${baseURL}/api/tags`, {redirect:'error',signal:AbortSignal.timeout(10000)});
  assert.equal(response.ok,true,'Ollama tags preflight failed');
  const text = await response.text();
  assert.ok(Buffer.byteLength(text) <= 131072,'Ollama tags response too large');
  const body = JSON.parse(text);
  const matches = Array.isArray(body.models) ? body.models.filter(item=>item?.name===MODEL) : [];
  assert.equal(matches.length,1,`Exactly one ${MODEL} tag is required`);
  assert.equal(matches[0].digest,MODEL_DIGEST,'Pinned llama3.1:8b digest mismatch');
}

function deepFreeze(value) {
  Object.freeze(value);
  for(const child of Object.values(value)) if(child&&typeof child==='object'&&!Object.isFrozen(child))deepFreeze(child);
  return value;
}

function packet(kind) {
  const rubric = getObjectiveRubric('xss_workshop','xss_g3','vuln');
  assert.equal(rubric.version,'xss_model_origin.v4');
  const facts=Object.fromEntries(rubric.requiredFacts.map(id=>[id,true]));
  if(kind==='resolved_negative'){
    facts.stored_payload_returned=false;
    facts.isolated_browser_executed=false;
    facts.model_profile_origin_current=false;
    facts.canonical_model_save_completed=false;
  }
  return deepFreeze({rubric,evidence:[{id:'server_receipt',source:'server_observation',content:{
    qualification:'synthetic_representative_xss_g3_calibration_packet',
    storedPayloadReturned:facts.stored_payload_returned,
    isolatedBrowserExecuted:facts.isolated_browser_executed,
    modelProfileOriginCurrent:facts.model_profile_origin_current,
    canonicalModelSaveCompleted:facts.canonical_model_save_completed,
  }}],facts});
}

function diagnostic(kind,trial,judgment) {
  return Object.freeze({kind,trial,expected:kind==='positive'?'pass':'fail',
    verdict:judgment?.verdict??null,provider:judgment?.provider??null,model:judgment?.model??null,
    attempts:judgment?.attempts??0,errorCode:judgment?.errorCode??null,
    criteria:Array.isArray(judgment?.criteria)?judgment.criteria.map(item=>({
      id:item.id,satisfied:item.satisfied,evidenceRefs:item.evidenceRefs,
    })):[]});
}

test('local llama3.1:8b calibrates xss_g3 v4 resolved provenance facts', {
  skip:!LIVE, timeout:480000,
}, async t=>{
  const baseURL=configuredOllama();
  await assertModelDigest(baseURL);
  const provider=createLangChainProvider({provider:'ollama',model:MODEL,baseURL});
  let modelCalls=0;
  const model=Object.freeze({async chat(...args){
    assert.ok(modelCalls<MAX_MODEL_CALLS,'XSS calibration exceeded its six-call bound');
    modelCalls+=1;
    const result=await provider.chat(...args);
    assert.equal(result.provider,'ollama');
    assert.equal(result.model,MODEL);
    assert.notEqual(result.mocked,true);
    assert.notEqual(result.fallback,true);
    return result;
  }});
  const judge=createObjectiveJudge({model,timeoutMs:60000});
  const controller=new AbortController();
  const deadline=setTimeout(()=>controller.abort(new Error('XSS Judge calibration deadline exceeded')),420000);
  deadline.unref?.();
  const results=[];
  try{
    for(const kind of ['positive','resolved_negative']){
      for(let trial=1;trial<=3;trial+=1){
        const judgment=await judge({...packet(kind),execution:Object.freeze({
          ownerId:'synthetic-xss-g3-calibration',runId:randomUUID(),signal:controller.signal,
          async check(){controller.signal.throwIfAborted();},async emit(){},
        })});
        results.push({kind,trial,judgment});
      }
    }
  }finally{clearTimeout(deadline);}
  const summary=Object.freeze({scope:'synthetic_representative_xss_g3_v4_calibration',
    artifactProof:false,databaseWrites:0,browserRuns:0,creditsAttempted:0,
    provider:'ollama',model:MODEL,modelDigest:MODEL_DIGEST,modelCalls,maximumModelCalls:MAX_MODEL_CALLS,
    results:results.map(({kind,trial,judgment})=>diagnostic(kind,trial,judgment))});
  t.diagnostic(JSON.stringify(summary));
  assert.equal(results.length,6);
  assert.equal(modelCalls,6,'Every packet must resolve in one genuine provider call without repair');
  for(const {kind,trial,judgment} of results){
    assert.equal(judgment.provider,'ollama',`${kind}/trial${trial}`);
    assert.equal(judgment.model,MODEL,`${kind}/trial${trial}`);
    assert.equal(judgment.attempts,1,`${kind}/trial${trial}`);
    assert.equal(judgment.errorCode,undefined,`${kind}/trial${trial}`);
    assert.equal(judgment.verdict,kind==='positive'?'pass':'fail',`${kind}/trial${trial}`);
  }
});
