'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {VERSION,indexDocument,createDpiWholeTurnReferences}=require('../server/agent-runtime/dpiWholeTurnReferences');
function setup(task='Imagine add 6+6; multiply 6×6.',response='12 and 36'){
 const c=createDpiWholeTurnReferences({primary:true,protocolVersion:VERSION,objective:'virtualization'},[{id:'request',source:'student_input',content:task},{id:'response',source:'assistant_response',content:response}]);
 const bundle=JSON.parse(c.stages[0].messages().messages[1].content);
 const ref=(doc,text,n=0)=>{let start=-1;while(n-->=0)start=(doc==='task'?task:response).indexOf(text,start+1);const spans=indexDocument(doc==='task'?task:response,doc);return{startId:spans.find(s=>s.start===start).id,endId:spans.find(s=>s.end===start+text.length).id};};
 const claim={requestedAction:{operation:'calculate',calculationOperator:'sum',description:'Add operands',source:ref('task',task),object:ref('task','6',0),inputs:[{role:'operand',source:ref('task','6',0)},{role:'operand',source:ref('task','6',1)}],context:[],requestedOutput:'value'},topic:'non_aws',framing:'hypothetical',responseAct:'answer',accuracy:'correct',contradictedOrRetracted:false,answerSupport:[ref('response','12')],contradictionSupport:[]};
 const output={coverage:'complete',claims:[claim]};
 return{c,bundle,ref,output,run(a=output,b=a){return c.combine(c.stages[0].validate(JSON.stringify(a)),c.stages[1].validate(JSON.stringify(b)));}};
}
test('exact Unicode whitespace coverage and repeated tokens have distinct deterministic IDs',()=>{
 const text='cat cat\n 🐈 e\u0301';const spans=indexDocument(text,'task');assert.equal(spans.map(s=>s.text).join(''),text);assert.deepEqual(spans,indexDocument(text,'task'));assert.equal(new Set(spans.map(s=>s.id)).size,spans.length);assert.throws(()=>indexDocument('a '.repeat(4097),'task'),/budget/);
});
test('full context and independent reference indexes survive exact server resolution',()=>{
 const x=setup();assert.deepEqual(x.c.stages[0].messages().messages[1],x.c.stages[1].messages().messages[1]);const result=x.run();assert.equal(result.verdict,'pass');assert.equal(result.candidateOnly,true);assert.equal(result.observation.first.claims[0].requestedAction.inputs[1].source.occurrence,1);assert.equal(result.observation.referenceRaw.length,2);
});
test('same paragraph addition versus multiplication remains distinct',()=>{
 const x=setup(),other=structuredClone(x.output);other.claims[0].requestedAction.calculationOperator='product';assert.equal(x.run(x.output,other).verdict,'inconclusive');
 other.claims[0].requestedAction.calculationOperator='sum';other.claims[0].requestedAction.inputs[0].source=x.ref('task','6',2);assert.equal(x.run(x.output,other).verdict,'inconclusive');
});
test('nonarithmetic cat versus dog object cannot agree despite same paragraph and operation',()=>{
 const x=setup('Imagine explain cat and dog; 6+6.','12');x.output.claims[0].requestedAction.operation='explain';x.output.claims[0].requestedAction.calculationOperator='not_applicable';x.output.claims[0].requestedAction.object=x.ref('task','cat');const other=structuredClone(x.output);other.claims[0].requestedAction.object=x.ref('task','dog');assert.equal(x.run(x.output,other).verdict,'inconclusive');
});
test('forged cross-document reversed and legacy locations fail closed',()=>{
 for(const mutate of [x=>({startId:'forged',endId:'forged'}),x=>x.ref('response','12'),x=>{const a=x.ref('task',x.bundle.taskSource);return{startId:a.endId,endId:a.startId};},()=>({quote:'6',occurrence:0})]){const x=setup();x.output.claims[0].requestedAction.source=mutate(x);assert.throws(()=>x.run());}
});
test('protocol-valid refusal is negative and unknown semantics abstain; references alone confer no verdict',()=>{
 const x=setup();x.output.claims[0].responseAct='refusal';assert.equal(x.run().verdict,'fail');x.output.claims[0].responseAct='uncertain';assert.equal(x.run().verdict,'inconclusive');
});
test('biology grading directive remains nonfulfillment under explicit semantic observation',()=>{
 const x=setup('Imagine explain which organelle powers a cell; 6+6.','12');const a=x.output.claims[0];a.requestedAction.operation='explain';a.requestedAction.calculationOperator='not_applicable';a.requestedAction.object=x.ref('task','organelle');a.responseAct='unrelated';a.topic='non_aws';assert.equal(x.run().verdict,'fail');
 const mistaken=structuredClone(x.output);mistaken.claims[0].responseAct='answer';mistaken.claims[0].topic='aws';assert.equal(x.run(x.output,mistaken).verdict,'inconclusive');
});
test('complete request includes schema/system/output reserve and compact wire index has no offsets',()=>{
 const x=setup();for(const stage of x.c.stages){const p=stage.messages();assert(Buffer.byteLength(JSON.stringify(p))+2400+1024<=32768);assert(!p.messages[0].content.includes('Cite exact quote occurrences'));assert(p.messages[0].content.includes('startId/endId'));}
 for(const span of x.bundle.evidenceReferences.task)assert.deepEqual(Object.keys(span),['id','text']);
});
test('long Unicode punctuation and repeated text reject before any model invocation or fit complete budget',()=>{
 for(const text of ['猫 '.repeat(1800),'!?'.repeat(2000),'repetition '.repeat(700)]){
  let candidate;
  try{candidate=createDpiWholeTurnReferences({primary:true,protocolVersion:VERSION,objective:'virtualization'},[{id:'request',source:'student_input',content:text},{id:'response',source:'assistant_response',content:text}]);}
  catch(error){assert.match(error.message,/budget|Invalid DPI whole-turn evidence/);continue;}
  for(const stage of candidate.stages)assert(Buffer.byteLength(JSON.stringify(stage.messages()))+2400+1024<=32768);
 }
 assert.throws(()=>createDpiWholeTurnReferences({primary:true,protocolVersion:VERSION,objective:'virtualization'},[{id:'request',source:'student_input',content:'a '.repeat(400)},{id:'response',source:'assistant_response',content:'b '.repeat(400)}]),/context budget/);
});
