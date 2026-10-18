'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const cases=[
 {id:'styled',message:'<b>hello</b>',response:'<div><b style="color:red" class="formatted">hello</b></div>',expected:'pass'},
 {id:'unchanged',message:'<b>hello</b>',response:'<div><b>hello</b></div>',expected:'pass'},
 {id:'escaped',message:'<b>hello</b>',response:'<div>&lt;b&gt;hello&lt;/b&gt;</div>',expected:'fail'},
 {id:'changed_text',message:'<b>hello</b>',response:'<b>unrelated</b>',expected:'fail'},
 {id:'changed_attribute',message:'<a href="/learner">hello</a>',response:'<a href="/different">hello</a>',expected:'fail'},
 {id:'wrapper_only',message:'format hello',response:'<div>hello</div>',expected:'fail'},
];
test('R2 DOM contract grades styled preservation and rejects escaped, changed and unrelated output with real8B',{skip:process.env.RUN_LIVE_XSS_DOM_JUDGE!=='1',timeout:240000},async t=>{
 const {createObjectiveJudge}=require('../server/agent-runtime/objectiveJudge');
 const {createLangChainProvider}=require('../server/agent-runtime/providers/langchainProvider');
 const {createXssObjectiveGrader}=require('../server/services/xssObjectiveGrader');
 const {createXssBrowserQualification}=require('../server/services/xssBrowserQualification');
 const judge=createObjectiveJudge({model:createLangChainProvider({provider:'ollama',model:'llama3.1:8b',baseURL:'http://127.0.0.1:11434'})});
 const browser=createXssBrowserQualification();let packet;
 const grader=createXssObjectiveGrader({postgres:true,browserQualification:browser,completionService:{
  beginAttempt:async input=>({userId:input.userId,generation:1}),
  evaluate:async input=>{packet=input;const judgment=await judge(input);return{judgment,completed:judgment.verdict==='pass'&&input.rubric.requiredFacts.every(key=>input.facts[key]===true)};},
 }});
 try{for(const item of cases){
  const execution={runId:`xss-dom-${item.id}`,ownerId:'17',signal:new AbortController().signal,check:async()=>{},emit:async()=>{}};
  const attempt=await grader.begin(17,'xss_r2',execution);
  const result=await grader.evaluate({userId:17,objectiveId:'xss_r2',exerciseId:'reflected',...item,grading:{modelSucceeded:true},execution,attempt});
  t.diagnostic(JSON.stringify({case:item.id,expected:item.expected,judgment:result.judgment,facts:packet.facts,browser:result.qualification}));
  assert.equal(result.judgment.provider,'ollama');assert.equal(result.judgment.model,'llama3.1:8b');
  assert.equal(packet.rubric.version,'xss_dom_preservation.v2');assert.equal(result.judgment.verdict,item.expected,item.id);
  assert.equal(result.completed,item.expected==='pass',item.id);
 }}finally{await grader.close();}
});
