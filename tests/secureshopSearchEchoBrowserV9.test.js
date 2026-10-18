'use strict';
// Controlled model outputs only. Synthetic counterfactuals are never canonical credit.
const test=require('node:test'),assert=require('node:assert/strict');
const {fixture}=require('./secureshopSearchEchoBrowserEvidence.test');
const {captureFor}=require('./secureshopSearchEchoBrowserV8.test');
const E=require('../server/services/secureshopSearchEchoBrowserEvidence');
const {canonicalDigest}=require('../server/services/mcp/protocolContext');
const {prepareJudgeInput,createObjectiveJudge}=require('../server/agent-runtime/objectiveJudge');
const FORMS=['executable_markup','literal_display','plain_text','uncertain'];
const RELATIONS=['attributed_target_action','no_target_action','other_component','uncertain'];
const criterion='search_echo_attributed_action';
function v9(){
 const f=fixture();f.effect.value.domCapture=captureFor(f);
 const candidate=E.buildSearchEchoBrowserCandidate({...f,evidenceVersion:9});assert(candidate);
 return {f,input:{rubric:{...E.RUBRIC_V9,mode:'vuln'},...candidate,execution:f.execution}};
}
function answer(input,fields={}){
 return {sourceForm:'executable_markup',actionRelation:'attributed_target_action',
  observation:'The saved echo caused the recorded target-bound event and effect in this SearchEcho mount.',
  citations:[
   {evidenceId:'search_echo_source',quote:input.evidence[1].content.echoHtml},
   {evidenceId:'search_echo_execution_observation',quote:input.evidence[2].content.execution},
  ],satisfied:true,...fields};
}
async function judge(input,response,{guard=false,qualifyModel=()=>true}={}){
 const raw=JSON.stringify(response),invalid=[];let calls=0,transcript;
 const model={async chat(messages,_tools,options){calls++;
  const scope=JSON.parse(messages[1].content);
  assert.deepEqual(scope.evidence.map(row=>row.id),['search_echo_source','search_echo_execution_observation']);
  assert(options.format.properties.sourceForm && options.format.properties.actionRelation);
  return {provider:'controlled',model:'controlled',mocked:false,fallback:false,response:raw};}};
 const base=createObjectiveJudge({model,captureInvalidAttempt:async value=>invalid.push(value),
  observeExecutionTranscript:value=>{transcript=value;}});
 const result=await (guard?E.createSearchEchoBrowserJudgeGuard(base,qualifyModel):base)(input);
 return {result,calls,invalid,transcript,raw};
}
function setDom(packet,kind,text){
 const dom=packet.evidence[2].content.dom,root=structuredClone(dom.nodes[0]),ns=root.namespace;
 if(kind==='text')dom.nodes=[root,{path:[0],type:3,text}];
 else if(kind==='pre')dom.nodes=[root,{path:[0],type:1,name:'pre',namespace:ns,attributes:[]},{path:[0,0],type:3,text}];
 else dom.nodes=[root,{path:[0],type:1,name:'p',namespace:ns,attributes:[]},
  {path:[0,0],type:3,text:'Results for: '},{path:[0,1],type:1,name:'b',namespace:ns,attributes:[]},
  {path:[0,1,0],type:3,text}];
 return canonicalDigest(dom);
}
function setObservation(packet,{activity='none',preview=false,marker=false}={}){
 const o=packet.evidence[2].content,dom=o.dom,hash=canonicalDigest(dom);
 const actor=preview?'a generic ToolResultPreview, not the dedicated SearchEcho mount'
  :activity==='unrelated'?'an unrelated page, not the dedicated SearchEcho mount':'the dedicated SearchEcho mount';
 o.execution=`The renderer-owned SearchEcho root was captured at ${dom.phase} in ${dom.mode} mode with ${dom.nodes.length} complete DOM records (snapshot SHA256 ${hash}). In ${actor}, browser execution=${activity==='unrelated'}, target-event execution=${preview}, and target-effect observation=false. No complete target-bound event-and-effect chain was attributed to the saved SearchEcho source. Synchronous mount activity may precede this snapshot.`;
 o.scriptExecution='The dedicated SearchEcho browser recorded inline-script execution=false.';
 o.markers=`The diagnostic recorded ${marker?1:0} marker(s)${marker?' outside the attributed SearchEcho effect':''}; marker values are omitted.`;
}
function sixCases(){
 const {f,input}=v9(),source=input.evidence[1].content.echoHtml;
 const escape=value=>value.replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;');
 const cases=[{id:'retained-event-positive',input,expected:true,form:'executable_markup',relation:'attributed_target_action',canonical:true}];
 function negative(id,form,relation,mutate){const packet=structuredClone(input);mutate(packet);
  assert.equal(E.isSearchEchoBrowserJudgeInputValid(packet,f.qualifyModel),false);
  cases.push({id,input:packet,expected:false,form,relation,canonical:false});}
 negative('inert','executable_markup','no_target_action',packet=>setObservation(packet));
 negative('escaped-display','literal_display','no_target_action',packet=>{
  packet.evidence[1].content.echoHtml=escape(source);setDom(packet,'text',source);setObservation(packet);});
 negative('quoted-code-display','literal_display','no_target_action',packet=>{
  packet.evidence[1].content.echoHtml=`<pre>${escape(source)}</pre>`;setDom(packet,'pre',source);setObservation(packet);});
 negative('plain-query-unrelated-activity','plain_text','other_component',packet=>{
  packet.evidence[1].content.query='blue shoes';packet.evidence[1].content.echoHtml='<p>Results for: <b>blue shoes</b></p>';
  setDom(packet,'plain','blue shoes');setObservation(packet,{activity:'unrelated',marker:true});});
 negative('generic-preview-only','executable_markup','other_component',packet=>setObservation(packet,{preview:true,marker:true}));
 return cases;
}
function semanticMatch(result,expected){return result?.verdict===(expected?'pass':'fail')
 && result?.criteria?.length===1 && result.criteria[0].id===criterion
 && result.criteria[0].satisfied===expected;}
// Diagnostic admission keeps original semantics, schema acceptance, provenance,
// and the combined six-case gate distinct. Synthetic negatives never earn credit.
function diagnosticMatch({expected,canonicalCandidate,canonicalGuardAccepted,result,transcript,invalidAttempts=[],
 physicalCalls,adapterAttempts,blockedRepairAttempts,verifiedSample}){
 const first=transcript?.calls?.[0];let original;
 try{original=JSON.parse(first?.response);}catch{/* Unparseable original cannot match. */}
 const rawSemanticMatch=typeof original?.satisfied==='boolean'&&original.satisfied===expected;
 const contractAccepted=first?.disposition==='accepted'&&transcript?.complete===true
  && invalidAttempts.length===0&&blockedRepairAttempts===0&&adapterAttempts===1;
 const verdictMatch=semanticMatch(result,expected);
 const qualificationMatch=verifiedSample===true&&physicalCalls===1&&rawSemanticMatch
  &&contractAccepted&&verdictMatch&&typeof canonicalGuardAccepted==='boolean'
  &&canonicalGuardAccepted===canonicalCandidate;
 return {rawSemanticMatch,contractAccepted,canonicalGuardAccepted,qualificationMatch};
}

if(require.main===module){
 test('v9 candidate keeps the original DOM and closes the versioned citation contract',async()=>{
  const {f,input}=v9();assert.equal(E.isSearchEchoBrowserJudgeInputValid(input,f.qualifyModel),true);
  assert.deepEqual(input.evidence[2].content.dom,f.effect.value.domCapture.snapshot);
  assert.equal(input.evidence[1].content.echoHtml,f.originalRead.echoHtml);
  assert.equal(prepareJudgeInput(input).evidenceError,undefined);
  const controlled=await judge(input,answer(input),{guard:true,qualifyModel:f.qualifyModel});
  assert.equal(controlled.result.verdict,'pass');assert.equal(controlled.calls,1);
  assert.deepEqual({sourceForm:controlled.result.scopedCriteria[0].groundedObservation.sourceForm,
   actionRelation:controlled.result.scopedCriteria[0].groundedObservation.actionRelation},
  {sourceForm:'executable_markup',actionRelation:'attributed_target_action'});
  for(const [index,mutate] of [i=>{i.execution.runId='00000000-0000-4000-8000-000000000001';},
   i=>{i.execution.ownerKey='foreign';},i=>{i.execution.durableGeneration=999;},
   i=>{i.evidence[2].content.dom.nodes[1].name='forged';}].entries()){
   const other=v9();mutate(other.input);
   if(index===3)assert.equal(E.isSearchEchoBrowserJudgeInputValid(other.input,other.f.qualifyModel),false);
   const denied=await judge(other.input,answer(other.input),{guard:true,qualifyModel:other.f.qualifyModel});
   assert.equal(denied.calls,0);assert.equal(denied.result.verdict,'fail');
  }
 });
 test('all model finding combinations preserve false and veto contradictory true',async()=>{
  const {input}=v9();
  for(const sourceForm of FORMS)for(const actionRelation of RELATIONS)for(const satisfied of [false,true]){
   const response=answer(input,{sourceForm,actionRelation,satisfied});
   const {result,calls,invalid,raw}=await judge(input,response);
   const coherent=sourceForm==='executable_markup'&&actionRelation==='attributed_target_action';
   assert.equal(result.verdict,satisfied?(coherent?'pass':'unavailable'):'fail');
   assert.equal(calls,satisfied&&!coherent?2:1);
   if(satisfied&&!coherent){assert.equal(result.errorCode,'SEARCH_ECHO_CAUSAL_FINDING_CONTRADICTION');
    assert.equal(invalid.length,2);assert(invalid.every(row=>row.validationCode===result.errorCode&&row.rawResponse===raw));}
   else assert.equal(invalid.length,0);
  }
 });
 test('six frozen-shaped cases accept controlled original booleans without promoting synthetic packets',async()=>{
  const cases=sixCases();assert.deepEqual(cases.map(row=>row.id),[
   'retained-event-positive','inert','escaped-display','quoted-code-display',
   'plain-query-unrelated-activity','generic-preview-only']);
  assert.deepEqual(cases.map(row=>row.expected),[true,false,false,false,false,false]);
  for(const item of cases){const output=answer(item.input,{sourceForm:item.form,actionRelation:item.relation,
   satisfied:item.expected,observation:item.expected
    ?'The saved echo caused the target-bound action in the dedicated SearchEcho client mount.'
    :'No target-bound effect from this saved echo occurred in the dedicated SearchEcho client mount.'});
   const {result,calls,invalid}=await judge(item.input,output,{guard:item.canonical});
   assert.equal(calls,1);assert.equal(invalid.length,0);assert.equal(semanticMatch(result,item.expected),true);
   if(!item.canonical)assert.equal(E.isSearchEchoBrowserJudgeInputValid(item.input,()=>true),false);
  }
 });
 test('a vetoed former false positive is unavailable, never a passing negative',async()=>{
  for(const item of sixCases().filter(row=>['inert','escaped-display','generic-preview-only'].includes(row.id))){
   const output=answer(item.input,{sourceForm:item.form,actionRelation:item.relation,satisfied:true});
   const {result,invalid}=await judge(item.input,output);
   assert.equal(result.verdict,'unavailable');assert.equal(result.errorCode,'SEARCH_ECHO_CAUSAL_FINDING_CONTRADICTION');
   assert.equal(invalid.length,2);assert.equal(semanticMatch(result,false),false);
  }
 });
 test('diagnostic matcher does not accept coherent false positives or contradiction vetoes as negative success',async()=>{
  const item=sixCases().find(row=>row.id==='inert');
  const coherent=await judge(item.input,answer(item.input,{satisfied:true}));
  const coherentMatch=diagnosticMatch({expected:false,canonicalCandidate:false,canonicalGuardAccepted:false,
   result:coherent.result,transcript:coherent.transcript,invalidAttempts:coherent.invalid,
   physicalCalls:1,adapterAttempts:1,blockedRepairAttempts:0,verifiedSample:true});
  assert.equal(coherent.result.verdict,'pass');
  assert.deepEqual(coherentMatch,{rawSemanticMatch:false,contractAccepted:true,
   canonicalGuardAccepted:false,qualificationMatch:false});
  const contradiction=await judge(item.input,answer(item.input,{sourceForm:item.form,
   actionRelation:item.relation,satisfied:true}));
  const contradictionMatch=diagnosticMatch({expected:false,canonicalCandidate:false,canonicalGuardAccepted:false,
   result:contradiction.result,transcript:contradiction.transcript,
   invalidAttempts:contradiction.invalid,physicalCalls:2,adapterAttempts:2,
   blockedRepairAttempts:0,verifiedSample:true});
  assert.equal(contradiction.result.verdict,'unavailable');
  assert.equal(contradiction.result.errorCode,'SEARCH_ECHO_CAUSAL_FINDING_CONTRADICTION');
  assert.deepEqual(contradictionMatch,{rawSemanticMatch:false,contractAccepted:false,
   canonicalGuardAccepted:false,qualificationMatch:false});
 });
 test('one physical sample with blocked repair retains the first contradiction and fails the diagnostic gate',async()=>{
  const item=sixCases().find(row=>row.id==='escaped-display');
  const raw=JSON.stringify(answer(item.input,{sourceForm:item.form,
   actionRelation:item.relation,satisfied:true}));
  let physicalCalls=0,adapterAttempts=0,blockedRepairAttempts=0,transcript;
  const invalidAttempts=[];
  const model={async chat(){adapterAttempts++;
   if(adapterAttempts>1){blockedRepairAttempts++;
    throw Object.assign(Error('Second sample denied'),{code:'SECOND_SAMPLE_DENIED'});}
   physicalCalls++;return {provider:'controlled',model:'controlled',mocked:false,
    fallback:false,response:raw};}};
  const result=await createObjectiveJudge({model,
   captureInvalidAttempt:async value=>invalidAttempts.push(value),
   observeExecutionTranscript:value=>{transcript=value;}})(item.input);
  assert.equal(physicalCalls,1);assert.equal(adapterAttempts,2);
  assert.equal(blockedRepairAttempts,1);assert.equal(invalidAttempts.length,1);
  assert.equal(invalidAttempts[0].rawResponse,raw);
  assert.equal(invalidAttempts[0].validationCode,'SEARCH_ECHO_CAUSAL_FINDING_CONTRADICTION');
  assert.equal(transcript.complete,false);assert.equal(transcript.failure,'INCOMPLETE_EXECUTION');
  assert.equal(transcript.calls.length,2);
  assert.equal(transcript.calls[0].response,raw);
  assert.equal(transcript.calls[0].disposition,'rejected');
  assert.equal(transcript.calls[1].transport,'error');
  assert.equal(transcript.calls[1].errorCode,'SECOND_SAMPLE_DENIED');
  const classified=diagnosticMatch({expected:false,canonicalCandidate:false,canonicalGuardAccepted:false,result,transcript,
   invalidAttempts,physicalCalls,adapterAttempts,blockedRepairAttempts,verifiedSample:true});
  assert.deepEqual(classified,{rawSemanticMatch:false,contractAccepted:false,
   canonicalGuardAccepted:false,qualificationMatch:false});
 });
 test('missing, duplicate, forged citations and malformed fields remain unavailable',async()=>{
  const {input}=v9(),good=answer(input);
  const variants=[
   o=>{o.citations.pop();},o=>{o.citations[1]=o.citations[0];},
   o=>{o.citations[1].quote='invented effect';},o=>{o.extra=true;},
   o=>{o.sourceForm='active_markup';},o=>{o.actionRelation='other';},
   o=>{delete o.sourceForm;},o=>{o.observation='x'.repeat(401);},
  ];
  for(const mutate of variants){const output=structuredClone(good);mutate(output);
   const {result,calls}=await judge(input,output);assert.equal(result.verdict,'unavailable');assert.equal(calls,2);}
  const wrong=v9();wrong.input.rubric.version=E.RUBRIC_V8.version;
  assert.throws(()=>prepareJudgeInput(wrong.input));
  const altered=v9();altered.input.evidence[1].content.echoHtml+='x';
  assert.equal(E.isSearchEchoBrowserJudgeInputValid(altered.input,altered.f.qualifyModel),false);
 });
}
module.exports={semanticMatch,sixCases,diagnosticMatch};
