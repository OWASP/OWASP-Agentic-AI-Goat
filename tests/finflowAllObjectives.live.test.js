'use strict';
// Static packets and the optional live run both target the documented Ollama
// FinFlow deployment, independent of the broad suite's default mock provider.
process.env.AI_PROVIDER='ollama';
const Module=require('node:module'),load=Module._load;Module._load=function(r,p,m){if(process.env.LIVE_OLLAMA_TEST!=='1'&&/(?:^|\/)multiProviderAIService(?:\.js)?$/.test(r))return {getActiveProviderInfo:()=>({provider:'ollama',model:process.env.OLLAMA_MODEL||'llama3.1:8b'})};if(/(?:^|\/)authDb(?:\.js)?$/.test(r))throw Error('authDb forbidden');return load.call(this,r,p,m);};
const {test}=require('node:test'),assert=require('node:assert/strict');
const {buildFinflowJudgeInputs,FINFLOW_RUBRICS}=require('../server/services/sensitiveInfoWorkshopAgent');const {cases}=require('./fixtures/finflowJudgeCases');
function packetFor(fixture){return buildFinflowJudgeInputs(fixture.request,fixture.toolCalls,fixture.response,{activeObjectiveId:fixture.id}).find(p=>p.rubric.objectiveId===fixture.id);}
// Historical text-only effect fixtures lack private receipts. Keep them as
// negative authority controls; real positive effects have separate owned tests.
const receiptRequired = new Set(['error_leak','traversal_secrets','traversal_passwd','traversal_llm','admin_enum',
 'admin_backup','admin_dl_backup','admin_read_logs','admin_llm_logs','admin_modify_logs','admin_secrets','admin_dirlist']);
// The retained tool_enum fixture predates the split catalog contract and lists
// both user and admin tools. Preserve those historical bytes as an overbroad
// negative control instead of treating them as exact user-tool enumeration.
const expectedObservation = fixture => fixture.label==='positive'
 && !receiptRequired.has(fixture.id) && fixture.id!=='tool_enum';
const expectedVerdict = fixture => expectedObservation(fixture) ? 'pass' : 'fail';
test('FinFlow historical fixture corpus rejects unsigned effects while retaining explicit supplied-evidence controls',()=>{
 assert.equal(cases.length,36);assert.deepEqual([...new Set(cases.map(f=>f.id))].sort(),Object.keys(FINFLOW_RUBRICS).sort());
 for(const fixture of cases){const packet=packetFor(fixture);assert.equal(packet.facts.required_observation,expectedObservation(fixture),fixture.id);if(fixture.id.startsWith('ssrf_'))assert.equal(packet.evidence.find(e=>e.id==='tool_0').content.realRequest,fixture.label==='positive');}
});
test(`Local8B evaluates historical supplied-evidence fixtures ${process.env.FINFLOW_OBJECTIVES ? 'for: '+process.env.FINFLOW_OBJECTIVES : 'across18 identities; not live exercise qualification'}`,{skip:process.env.LIVE_OLLAMA_TEST!=='1',timeout:600000},async t=>{
 const {createLangChainProvider}=require('../server/agent-runtime/providers/langchainProvider'),{createObjectiveJudge}=require('../server/agent-runtime/objectiveJudge');const judge=createObjectiveJudge({model:createLangChainProvider({provider:'ollama',model:'llama3.1:8b',baseURL:process.env.OLLAMA_BASE_URL||'http://localhost:11434'}),timeoutMs:60000});const failures=[];
 for(const fixture of cases.filter(item=>!process.env.FINFLOW_OBJECTIVES||process.env.FINFLOW_OBJECTIVES.split(',').includes(item.id))){const result=await judge(packetFor(fixture));console.log(`[FinFlow qualification] ${fixture.id} ${fixture.label}: ${result.verdict} (${result.judgeVersion})`);const correct=result.verdict===expectedVerdict(fixture);t.diagnostic(JSON.stringify(require('./fixtures/judgeDiagnostic').judgeDiagnostic({family:'FinFlow',id:fixture.id,label:fixture.label,expected:expectedVerdict(fixture),judgment:result})));if(!correct)failures.push({id:fixture.id,label:fixture.label,verdict:result.verdict});}
 assert.deepEqual(failures,[]);
});
