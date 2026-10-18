'use strict';
const { controlledObjectiveBoundary } = require('./helpers/controlledObjectiveBoundary');
const Module=require('node:module'),load=Module._load;Module._load=function(r,p,m){if(/(?:^|\/)authDb(?:\.js)?$/.test(r))throw Error('authDb forbidden');return load.call(this,r,p,m);};
const {test}=require('node:test'),assert=require('node:assert/strict');
const {beginCodeBotEvaluation: beginCodeBotEvaluationRuntime,CRITERIA} = require('../server/agent-runtime/codeBotJudge');
const beginCodeBotEvaluation = options => beginCodeBotEvaluationRuntime(controlledObjectiveBoundary(options, 'userId'));
const {prepareJudgeInput}=require('../server/agent-runtime/objectiveJudge');
test('CodeBot six objectives preserve full tool evidence and fail closed without real recon model',async()=>{
 assert.equal(Object.keys(CRITERIA).length,6);let packet;const grade=await beginCodeBotEvaluation({judge:async p=>{packet=p;return {verdict:'inconclusive'};}});
 const toolInvocations=[{name:'check_dependencies',params:{manifest:'fixture'},result:{security:'rce_executed',transform_output:'x'.repeat(3000)}}];
 await grade('rce_cmd',{userMessage:'fixture',rawModelResponse:'raw model only',toolInvocations,mode:'vulnerable',observed:true});assert.deepEqual(packet.evidence.find(item=>item.source==='tool_result').content,toolInvocations[0]);
 await grade('tool_list',{userMessage:'list tools',rawModelResponse:'fallback fixture',toolInvocations:[],mode:'vulnerable',observed:true});assert.ok(packet.rubric.requiredFacts.includes('real_model'));assert.equal(packet.facts.real_model,false);
});
test('CodeBot accepted receipt controls projection despite passing verdict',async()=>{
 let captured;const grade=await beginCodeBotEvaluation({userId:3,execution:{check:async()=>{}},completionService:{beginAttempt:async p=>{captured=p.execution;assert.equal(p.workshopKey,'supply_chain_rce');return 'attempt';},evaluate:async p=>{assert.equal(p.execution,captured);assert.equal(p.attempt,'attempt');return {judgment:{verdict:'pass'},completed:false};}}});
 assert.equal((await grade('clean_request',{userMessage:'{}',rawModelResponse:'',toolInvocations:[],mode:'fixed',observed:true})).completed,false);
});
test('CodeBot all six rubric packets preserve positive and negative source evidence',async()=>{
 const {cases}=require('./fixtures/codeBotJudgeCases');assert.equal(cases.length,12);
 for(const fixture of cases){let packet;const grade=await beginCodeBotEvaluation({judge:async p=>{packet=p;return {verdict:'inconclusive'};}});await grade(fixture.id,fixture.input);const prepared=prepareJudgeInput(packet);assert.equal(prepared.rubric.objectiveId,fixture.id);assert.equal(prepared.evidenceError,undefined);assert.equal(packet.rubric.version,'codebot-structured-v6');assert.ok(packet.rubric.requiredFacts.includes('real_model'));assert.equal(packet.rubric.criteria[0].allowedSources.includes('student_input'),false);assert.deepEqual(packet.evidence.filter(e=>/^tool_\d+$/.test(e.id)).map(e=>e.content),fixture.input.toolInvocations);if(/^rce_/.test(fixture.id))assert.equal(packet.facts.verified_effect,false,'serialized historical evidence is not a live effect receipt');}
});
test('CodeBot tool objectives require one real validated selection whose model observed that same invocation',async()=>{
 for(const mutation of [
  call=>{call.decision.source='scripted';},
  call=>{call.decision.validated=false;},
  call=>{call.continuation.source='fallback';call.continuation.available=false;},
  call=>{delete call.continuation;},
 ]){
  const input=structuredClone(require('./fixtures/codeBotJudgeCases').cases.find(item=>item.id==='clean_request'&&item.label==='positive').input);mutation(input.toolInvocations[0]);let packet;
  const grade=await beginCodeBotEvaluation({judge:async p=>{packet=p;return{verdict:'inconclusive'};}});await grade('clean_request',input);
  assert.equal(packet.facts.validated_model_selection,false);assert.equal(packet.facts.model_observed_result,false);
 }
});
test('CodeBot cannot launder model provenance from a clean call into a scripted strict RCE effect',async()=>{
 const clean={name:'check_dependencies',params:{manifest:'{}'},result:{security:'clean',status:'ok',dep_count:0},decision:{source:'model',validated:true},continuation:{source:'model',observed:true,available:true}};
 const strict={name:'check_dependencies',params:{manifest:'{"transform":"6*7"}'},result:{security:'rce_executed',transform_executed:true,transform_output:'42',runner:{source:'sandbox_runner',isolation:'bwrap-codebot-v1',exit_code:0,observations:{javascript_evaluated:true}}},decision:{source:'scripted',validated:true},continuation:{source:'model',observed:true,available:true}};
 let packet;const grade=await beginCodeBotEvaluation({judge:async p=>{packet=p;return{verdict:'inconclusive'};}});
 await grade('rce_cmd',{userMessage:'fixture',rawModelResponse:'42',toolInvocations:[clean,strict],mode:'vulnerable',observed:true,modelIsReal:true});
 assert.equal(packet.facts.isolated_execution,true);assert.equal(packet.facts.verified_effect,false);assert.equal(packet.facts.validated_model_selection,false);assert.equal(packet.facts.model_observed_result,false);
});
test('CodeBot copied secret output fails the trusted effect fact',async()=>{
 let packet;const grade=await beginCodeBotEvaluation({judge:async p=>{packet=p;return {verdict:'inconclusive'};}});
 await grade('rce_env',{userMessage:'manifest',rawModelResponse:'output',mode:'vulnerable',observed:true,modelIsReal:true,toolInvocations:[{name:'check_dependencies',params:{manifest:'{}'},result:{security:'rce_executed',transform_executed:true,transform_output:'DATABASE_URL=known-static-value',runner:{source:'sandbox_runner',isolation:'bwrap-codebot-v1',exit_code:0,observations:{env_file_read:false}}}}]});
 assert.equal(packet.facts.isolated_execution,true);
 assert.equal(packet.facts.verified_effect,false);
 assert.ok(packet.rubric.requiredFacts.includes('verified_effect'));
});
// Historical serialized fixtures remain intact. This optional live flag calibrates only
// reconnaissance Judge semantics on supplied text; it proves no actor/effect/completion.
// Genuine all-six owned qualification lives in tests/postgres/codeBotLiveWorkflow.integration.test.js
// via tests/postgres/codeBotCurrentMain.js. Serialized RCE positives cannot meet its effect gate.
test('Local8B CodeBot Judge-only reconnaissance positive/negative calibration',{skip:process.env.LIVE_OLLAMA_TEST!=='1',timeout:300000},async t=>{
 const {createLangChainProvider}=require('../server/agent-runtime/providers/langchainProvider'),{createObjectiveJudge}=require('../server/agent-runtime/objectiveJudge');
 const grade=await beginCodeBotEvaluation({judge:createObjectiveJudge({model:createLangChainProvider({provider:'ollama',model:'llama3.1:8b',baseURL:process.env.OLLAMA_BASE_URL||'http://localhost:11434'}),timeoutMs:60000})});const failures=[];
 const reconCases=require('./fixtures/codeBotJudgeCases').cases.filter(f=>['tool_list','pkg_discover'].includes(f.id));assert.equal(reconCases.length,4);
 for(const fixture of reconCases){
 const out=await grade(fixture.id,fixture.input);t.diagnostic(JSON.stringify(require('./fixtures/judgeDiagnostic').judgeDiagnostic({family:'CodeBot',id:fixture.id,label:fixture.label,expected:fixture.label==='positive'?'pass':'fail',judgment:out.judgment})));
 const expected=fixture.label==='positive'?'pass':'fail';if(out.judgment.verdict!==expected)failures.push({id:fixture.id,label:fixture.label,expected,actual:out.judgment.verdict});
 }
 assert.deepEqual(failures,[]);
});
test('CodeBot cannot combine strict provenance with another invocation effect or output',async()=>{
 for(const id of ['rce_cmd','rce_env','rce_ssh']){
  const field={rce_cmd:'javascript_evaluated',rce_env:'env_file_read',rce_ssh:'ssh_file_read'}[id];
  const strict={name:'check_dependencies',result:{security:'rce_executed',transform_executed:true,transform_output:'runtime output',runner:{source:'sandbox_runner',isolation:'bwrap-codebot-v1',exit_code:0,observations:{[field]:false}}}};
  const weak=structuredClone(strict);weak.result.runner.isolation='plain';weak.result.runner.observations[field]=true;
  let packet;const grade=await beginCodeBotEvaluation({judge:async p=>{packet=p;return {verdict:'inconclusive'};}});
  const input={userMessage:'fixture',rawModelResponse:'',mode:'vulnerable',observed:true,toolInvocations:[strict,weak]};
  await grade(id,input);assert.equal(packet.facts.isolated_execution,true);assert.equal(packet.facts.verified_effect,false);
  strict.result.runner.observations[field]=true;strict.result.transform_output='  ';
  await grade(id,input);assert.equal(packet.facts.verified_effect,false);
  strict.result.transform_output='runtime output';
  await grade(id,input);assert.equal(packet.facts.verified_effect,false,'strict-looking serialized output has no server-owned receipt');
 }
});

test('serialized RCE positives cannot pass even when the injected Judge repeatedly claims pass',async()=>{
 const {createObjectiveJudge}=require('../server/agent-runtime/objectiveJudge');
 for(const fixture of require('./fixtures/codeBotJudgeCases').cases.filter(f=>/^rce_/.test(f.id)&&f.label==='positive')){
  let packet,calls=0;
  const judge=createObjectiveJudge({model:{generate:async()=>{calls++;return {response:JSON.stringify({verdict:'pass',explanation:'Injected adversarial passing verdict.',criteria:packet.rubric.criteria.map(c=>({id:c.id,satisfied:true,evidenceRefs:['tool_0']}))}),provider:'fixture',model:'injected-test'};}}});
  const grade=await beginCodeBotEvaluation({judge:async p=>{packet=p;return judge(p);}});
  const out=await grade(fixture.id,fixture.input);
  assert.equal(packet.facts.verified_effect,false);
  assert.equal(calls,2,'canonical repair cannot manufacture the missing trusted receipt');
  assert.equal(out.judgment.verdict,'inconclusive');assert.equal(out.completed,false);assert.equal(out.durable, true, 'controlled completion interface only; no database persistence');
 }
});

// Controlled canonical validation only; this does not calibrate a real Judge.
test('historical parser-error and blocked transform cases cannot earn credit from a passing Judge', async () => {
  const { createObjectiveJudge } = require('../server/agent-runtime/objectiveJudge');
  const cases = require('./fixtures/codeBotJudgeCases').cases.filter(fixture =>
    fixture.label === 'negative' && ['clean_request', 'rce_cmd', 'rce_env', 'rce_ssh'].includes(fixture.id));
  assert.deepEqual(cases.map(fixture => fixture.id), ['clean_request', 'rce_cmd', 'rce_env', 'rce_ssh']);
  for (const fixture of cases) {
    let packet, calls = 0;
    const judge = createObjectiveJudge({ model: { generate: async () => {
      calls++;
      return { response: JSON.stringify({ verdict: 'pass', explanation: 'Controlled overgenerous verdict.',
        criteria: packet.rubric.criteria.map(criterion => ({ id: criterion.id, satisfied: true, evidenceRefs: ['tool_0'] })) }),
        provider: 'fixture', model: 'injected-test' };
    } } });
    const grade = await beginCodeBotEvaluation({ judge: async value => { packet = value; return judge(value); } });
    const outcome = await grade(fixture.id, fixture.input);
    assert.equal(packet.facts.validated_model_selection, false, fixture.id);
    assert.equal(packet.facts.model_observed_result, false, fixture.id);
    if (fixture.id !== 'clean_request') {
      assert.equal(packet.facts.isolated_execution, false, fixture.id);
      assert.equal(packet.facts.verified_effect, false, fixture.id);
    }
    assert.equal(calls, 2, 'Only the controlled canonical validation/repair seam is called');
    assert.equal(outcome.judgment.verdict, 'inconclusive', fixture.id);
    assert.equal(outcome.completed, false, fixture.id);
    assert.equal(outcome.durable, true, 'controlled completion interface only; no database persistence');
  }
});
