'use strict';
const Module=require('node:module'),load=Module._load;Module._load=function(r,p,m){if(/(?:^|\/)(authDb|ctfDb|sensitiveInfoDb)(?:\.js)?$/.test(r))throw Error('Database initializer forbidden');return load.call(this,r,p,m);};
const {test}=require('node:test'),assert=require('node:assert/strict');
const {cases}=require('./fixtures/legacySensitiveJudgeCases');
const {CRITERIA,buildPacket}=require('../server/agent-runtime/legacySensitiveJudge');
const packetFor=item=>buildPacket(item.objectiveId,item,{check:async()=>{}});
test('Legacy sensitive10 fixtures cover5 route-shaped objectives with production-derived evidence facts',()=>{
 assert.equal(cases.length,10);assert.deepEqual([...new Set(cases.map(c=>c.objectiveId))].sort(),Object.keys(CRITERIA).sort());
 for(const item of cases){const packet=packetFor(item);assert.equal(packet.rubric.requiredFacts.every(key=>packet.facts[key]===true),item.label==='positive');assert.equal(packet.evidence.find(e=>e.id==='returned_content').content,item.result.rendered??item.result.content);if(item.result.original)assert.equal(packet.evidence.find(e=>e.id==='original_template').content,item.result.original);assert.equal(item.expected,item.label==='positive'?'pass':'not_pass');}
});
test('Local8B legacy sensitive5 objectives10 verdict qualification (evidence only)',{skip:process.env.RUN_LIVE_JUDGE!=='1',timeout:600000},async t=>{
 const {createObjectiveJudge}=require('../server/agent-runtime/objectiveJudge'),{createLangChainProvider}=require('../server/agent-runtime/providers/langchainProvider');
 const model=createLangChainProvider({provider:'ollama',model:'llama3.1:8b',baseURL:process.env.OLLAMA_BASE_URL||'http://localhost:11434'});
 if(process.env.TRACE_FIXTURE_JUDGE==='1'){const chat=model.chat.bind(model);model.chat=async(...args)=>{const result=await chat(...args);console.log('[Synthetic fixture raw judge]',result.response);return result;};}
 const judge=createObjectiveJudge({model});const failures=[];
 for(const item of cases.filter(item=>!process.env.LEGACY_JUDGE_CASE||`${item.objectiveId}:${item.label}`===process.env.LEGACY_JUDGE_CASE)){const packet=packetFor(item);const result=await judge(packet);const completed=result.verdict==='pass'&&packet.rubric.requiredFacts.every(key=>packet.facts[key]===true);const diagnostic={family:'LegacySensitive',durationMs:result.durationMs??null,attempts:result.attempts??null,objectiveId:item.objectiveId,label:item.label,expected:item.expected,verdict:result.verdict,completed,explanation:result.explanation,criteria:result.criteria,provider:result.provider,model:result.model,judgeVersion:result.judgeVersion,judgePolicyDigest:result.judgePolicyDigest,rubricVersion:result.rubricVersion,evidenceDigest:result.evidenceDigest};console.log(`[Legacy sensitive qualification] ${item.objectiveId} ${item.label}: ${result.verdict}`);t.diagnostic(JSON.stringify(diagnostic));if((item.label==='positive'?result.verdict!=='pass'||!completed:result.verdict==='pass'||completed)||result.provider!=='ollama'||result.model!=='llama3.1:8b')failures.push(diagnostic);}
 assert.deepEqual(failures,[]);
});
