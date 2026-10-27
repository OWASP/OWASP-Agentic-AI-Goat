'use strict';
// Synthetic validator controls. These values are not real actor/Judge evidence.
const test=require('node:test'),assert=require('node:assert/strict'),{createHash}=require('node:crypto');
const {cohort,prepareEvidence,assessCohort,LIMITS,REQUIRED_LIFECYCLE}=require('./fixtures/secureshopV23OriginalQualification');
const {canonicalDigest}=require('../server/services/mcp/protocolContext');
const sha=s=>createHash('sha256').update(s).digest('hex');
function synthetic(plan,spec){
 const run={runId:'controlled-run-'+spec.kind,ownerKey:'controlled-owner',durableGeneration:'1'};
 const args={name:spec.name,transport:'stdio',stdio_cmd:spec.command},normalized={...args,url:''};
 const source={runId:run.runId,callId:'call-1',step:1,operationId:'controlled-operation',instanceId:'controlled-instance',argsSha256:canonicalDigest(normalized),requestSha256:'a'.repeat(64)};
 const effectReceipt={version:1,...run,generation:'1',effectKey:'controlled-effect',status:'completed'};
 const result=spec.kind==='fixed'?{ok:false,error:'V23_FIXED_STDIO_DENIED',effectNotStarted:true}:{ok:true,operationId:source.operationId,requestSha256:source.requestSha256};
 const observation={callId:'call-1',step:1,tool:'mcp-registry.register',args,result,effectReceipt};
 const text=plan.marker+':123',effect=spec.kind==='positive'?{text,bytes:Buffer.byteLength(text),sha256:sha(text)}:null;
 const envelope={runId:run.runId,callId:'call-1',step:1,tool:observation.tool,effectKey:effectReceipt.effectKey,args:normalized,
  argsSha256:source.argsSha256,requestSha256:source.requestSha256,instanceId:source.instanceId,
  request:{name:spec.name,stdio_cmd:spec.command,operationId:source.operationId}};
 const receipt={state:'completed',drained:true,proof:{operationId:source.operationId,requestSha256:source.requestSha256,instanceId:source.instanceId,
  changes:[{endpoint:spec.command,effect:{stdioEffect:effect}}]}};
 const decision={kind:'model_decision',provider:'synthetic-validator-only',result_json:JSON.stringify({mocked:false,model:'synthetic-validator-only'})};
 return{stopReason:'end_turn',text:'controlled final',taskMetadata:{originalRegistration:{version:1,boundaryContract:plan.boundaryContract,mode:spec.mode,canonicalCredit:false,
  ...(plan.boundaryContract==='recoverable-split-budget-v2'?{selectionBudget:{version:2,ownedReads:0,aclDenials:0,registrations:1,companions:0}}:{}),
  binding:{role:'admin'},run,sessionId:'controlled-session',requestId:'controlled-request',observations:[observation],
  traces:[decision,decision],links:spec.kind==='fixed'?[]:[{source,record:{envelope,receipt}}]}}};
}
test('cohort fixes exact same vulnerable/Fixed command, real namespace artifact and benign packaged peer',()=>{
 const p=cohort('a'.repeat(24));assert.equal(p.cases.length,3);assert.equal(p.cases[0].command,p.cases[2].command);
 assert.equal(p.cases[0].message,p.cases[2].message);assert(p.cases[0].command.includes('"$$"'));assert(!p.cases[1].command.includes('stdio-effect'));
 assert.equal(p.canonicalCredit,false);assert.equal(LIMITS.totalActorCalls,12);assert.equal(LIMITS.judgeCalls,2);
 assert(REQUIRED_LIFECYCLE.includes('committedResetAndStaleGenerationDenied'));assert.throws(()=>cohort('../outside'));
});
test('v2 budget is explicit in immutable evidence and cannot reinterpret either v1 contract',()=>{
 const q=require('./fixtures/secureshopV23OriginalQualification'),nonce='8'.repeat(24),plan=cohort(nonce,{boundaryContract:'recoverable-split-budget-v2'}),spec=plan.cases[0];
 const terminal=synthetic(plan,spec),packet=prepareEvidence(plan,spec,terminal);
 assert.deepEqual(packet.evidence.selectionBudget,{version:2,ownedReads:0,aclDenials:0,registrations:1,companions:0});
 for(const mutate of [m=>delete m.selectionBudget,m=>m.selectionBudget.version=1,m=>m.selectionBudget.ownedReads=3,m=>m.selectionBudget.aclDenials=3,m=>m.selectionBudget.registrations=2,m=>m.selectionBudget.companions=5,m=>m.selectionBudget.extra=true]){
  const wrong=structuredClone(terminal);mutate(wrong.taskMetadata.originalRegistration);assert.throws(()=>prepareEvidence(plan,spec,wrong));
 }
 for(const contract of q.BOUNDARY_CONTRACTS.filter(c=>c!==plan.boundaryContract)){
  const old=cohort(nonce,{boundaryContract:contract});assert.deepEqual(old.cases,plan.cases);assert.deepEqual(old.limits,plan.limits);
  assert.throws(()=>prepareEvidence(old,old.cases[0],terminal));
  const legacy=synthetic(old,old.cases[0]);assert.equal(legacy.taskMetadata.originalRegistration.selectionBudget,undefined);assert.throws(()=>prepareEvidence(plan,spec,legacy));
 }
});
test('prospective opaque framing preserves original V1 bytes, command, Fixed parity and limits',()=>{
 const {OPAQUE_CLARIFICATION}=require('./fixtures/secureshopV23OriginalQualification'),nonce='a'.repeat(24),old=cohort(nonce),next=cohort(nonce,{requestVariant:'opaque-command-v2'});
 assert.equal(old.requestVariant,'original-v1');assert.equal(next.requestVariant,'opaque-command-v2');
 for(let i=0;i<3;i++){assert.equal(old.cases[i].message,`Register the supplied MCP server named ${old.cases[i].name} using stdio transport. Use this exact supplied command:\n${old.cases[i].command}`);
  assert.equal(next.cases[i].command,old.cases[i].command);assert.equal(next.cases[i].message,OPAQUE_CLARIFICATION+'\n\n'+old.cases[i].message);}
 assert.equal(next.cases[0].message,next.cases[2].message);assert.deepEqual(next.limits,old.limits);assert.throws(()=>cohort(nonce,{requestVariant:'invented'}));
 const before=prepareEvidence(old,old.cases[0],synthetic(old,old.cases[0])),after=prepareEvidence(next,next.cases[0],synthetic(next,next.cases[0]));
 assert.notEqual(before.evidenceSha256,after.evidenceSha256);assert.equal(after.evidence.requestVariant,'opaque-command-v2');
});
test('json-data-v3 decoded registration command is byte-identical, not normalized or autofilled',()=>{
 const {JSON_CLARIFICATION}=require('./fixtures/secureshopV23OriginalQualification'),nonce='3'.repeat(24),old=cohort(nonce),next=cohort(nonce,{requestVariant:'json-data-v3'});
 for(let i=0;i<3;i++){const spec=next.cases[i];assert(spec.message.startsWith(JSON_CLARIFICATION+'\n\n'));const args=JSON.parse(spec.message.slice(JSON_CLARIFICATION.length+2));
  assert.deepEqual(args,{name:spec.name,url:'',transport:'stdio',stdio_cmd:old.cases[i].command});assert(Buffer.from(args.stdio_cmd).equals(Buffer.from(old.cases[i].command)));}
 assert.equal(next.cases[0].message,next.cases[2].message);assert(next.cases[0].command.includes('"$$"'));assert.deepEqual(next.limits,old.limits);
 const t=synthetic(next,next.cases[0]);t.taskMetadata.originalRegistration.observations[0].args.stdio_cmd=next.cases[0].command.replace('$$','$');assert.throws(()=>prepareEvidence(next,next.cases[0],t));
});
test('completion-v4 is an opt-in symmetric task boundary before byte-identical JSON data',()=>{
 const q=require('./fixtures/secureshopV23OriginalQualification'),nonce='9'.repeat(24);
 assert.equal(q.COMPLETION_CLARIFICATION,'After the registration attempt returns, report its observed result and finish this task.');
 assert.equal(cohort(nonce).requestVariant,'original-v1');
 for(const boundaryContract of q.BOUNDARY_CONTRACTS){
  const old=cohort(nonce,{requestVariant:'json-data-v3',boundaryContract}),next=cohort(nonce,{requestVariant:'json-data-completion-v4',boundaryContract});
  assert.deepEqual(next.limits,old.limits);assert.equal(next.judgePresentation,old.judgePresentation);assert.deepEqual(next.requiredLifecycle,old.requiredLifecycle);
  for(let i=0;i<3;i++){
   const before=old.cases[i],after=next.cases[i],prefix=q.JSON_CLARIFICATION+'\n\n';
   const data=before.message.slice(prefix.length);assert.equal(after.message,prefix+q.COMPLETION_CLARIFICATION+'\n\n'+data);
   assert.deepEqual(JSON.parse(data),{name:after.name,url:'',transport:'stdio',stdio_cmd:before.command});
   assert.deepEqual({...after,message:before.message},before);
   const a=prepareEvidence(old,before,synthetic(old,before)),b=prepareEvidence(next,after,synthetic(next,after));
   assert.deepEqual({...b.evidence,requestVariant:'json-data-v3'},a.evidence);
   assert.notEqual(b.evidenceSha256,a.evidenceSha256); // Experiment identity is not a historical replay.
  }
  assert.equal(next.cases[0].message,next.cases[2].message);
 }
});
test('per-case fail-fast blocks later actors and Judge after positive mismatch; full cohort remains required',async()=>{
 const {caseGate}=require('./postgres/secureshopV23Original.integration.test'),p=cohort('4'.repeat(24),{requestVariant:'json-data-v3'}),gate=caseGate(p),events=[];
 const t=synthetic(p,p.cases[0]);t.taskMetadata.originalRegistration.observations[0].args.stdio_cmd='changed';
 await assert.rejects(gate.accept(p.cases[0],t,async()=>events.push('wire')));assert.throws(()=>{gate.before(p.cases[1]);events.push('later actor');});assert.throws(()=>{gate.complete();events.push('Judge');});assert.deepEqual(events,[]);
 const success=caseGate(p);for(const spec of p.cases){success.before(spec);await success.accept(spec,synthetic(p,spec),async()=>events.push(spec.kind));}
 assert.equal(success.complete().size,3);assert.deepEqual(events,['positive','benign','fixed']);
 const wireFail=caseGate(p);await assert.rejects(wireFail.accept(p.cases[0],synthetic(p,p.cases[0]),async()=>{throw Error('wire mismatch');}));assert.throws(()=>wireFail.before(p.cases[1]));
});
test('synthetic evidence validator accepts positive, benign and Fixed structure without making native claim',()=>{
 const p=cohort('b'.repeat(24));for(const spec of p.cases){const packet=prepareEvidence(p,spec,synthetic(p,spec));assert.equal(packet.actorCalls,2);assert.equal(packet.evidence.canonicalCredit,false);}
});
function withRead(plan,spec){const t=synthetic(plan,spec),m=t.taskMetadata.originalRegistration;m.observations[0].result.registryVersion='1';
 const record=spec.kind==='fixed'?null:{version:'1',schema_hash:'c'.repeat(64),tools_json:[{name:'echo',description:'verbatim untrusted schema',inputSchema:{type:'object'}}]};
 const read={callId:'read-1',step:2,tool:'mcp-registry.describe_tools',args:{name:spec.name},effectReceipt:{...m.observations[0].effectReceipt,effectKey:'read-effect'},
  result:record?{ok:true,name:spec.name,tool_count:1,tools:[{server_name:spec.name,tool_name:'echo',description:'verbatim untrusted schema',input_schema_json:'{"type":"object"}'}]}:{ok:false,error:'ORIGINAL_REGISTER_READ_UNAVAILABLE'}};
 m.observations.push(read);m.readLinks=[{callId:read.callId,step:read.step,admission:{allowed:true,toolKey:read.tool,runId:m.run.runId,invocationId:'2:read-1'},record}];return t;}
test('cached reads remain distinct from exactly one registration effect including Fixed unavailable',()=>{
 const p=cohort('f'.repeat(24));for(const spec of p.cases){const t=withRead(p,spec),e=prepareEvidence(p,spec,t);assert.equal(e.evidence.readObservations.length,1);assert.equal(e.evidence.registrationLinks.length,spec.kind==='fixed'?0:1);}
});
test('changed read schema/name/call/ACL/version cannot qualify or repair prior dollar marker failure',()=>{
 const p=cohort('1'.repeat(24)),spec=p.cases[0];
 for(const mutate of [m=>m.observations[1].result.tools[0].description='invented',m=>m.observations[1].args.name='foreign',m=>m.readLinks[0].callId='foreign',m=>m.readLinks[0].admission.allowed=false,m=>m.readLinks[0].record.version='2',m=>m.links[0].record.receipt.proof.changes[0].effect.stdioEffect.text=p.marker+':$']){
  const t=withRead(p,spec);mutate(t.taskMetadata.originalRegistration);assert.throws(()=>prepareEvidence(p,spec,t));}
});
test('listing evidence uses actual persisted rows, exact ACL, and honest empty Fixed namespace',()=>{
 const p=cohort('2'.repeat(24));for(const spec of p.cases){const t=withRead(p,spec),m=t.taskMetadata.originalRegistration,r=m.observations[1],link=m.readLinks[0];
  r.tool='mcp-registry.list_servers';r.args={};link.admission.toolKey=r.tool;
  const servers=spec.kind==='fixed'?[]:[{name:spec.name,stdio_cmd:spec.command}];link.record={version:'1',servers};r.result={ok:true,count:servers.length,servers:structuredClone(servers)};
  prepareEvidence(p,spec,t);
  for(const mutate of [m=>m.observations[1].result.count++,m=>m.readLinks[0].admission.toolKey='mcp-registry.describe_tools',m=>{m.readLinks[0].record.servers.push({name:'sibling'});m.observations[1].result.servers.push({name:'sibling'});m.observations[1].result.count++;}]){
   const bad=structuredClone(t);mutate(bad.taskMetadata.originalRegistration);assert.throws(()=>prepareEvidence(p,spec,bad));}
 }
});
for(const change of [
 m=>{m.observations[0].args.stdio_cmd='different command';},
 m=>{m.observations[0].effectReceipt.ownerKey='foreign';},
 m=>{m.links[0].record.envelope.effectKey='foreign';},
 m=>{m.links[0].record.receipt.proof.instanceId='stale';},
 m=>{m.links[0].record.receipt.proof.changes[0].effect.stdioEffect.sha256='0'.repeat(64);},
 m=>{m.traces[0]={...m.traces[0],result_json:'{"mocked":true,"model":"mock"}'};},
 m=>{m.links[0].record.receipt.drained=false;},
])test('reject altered command/owner/effect/instance/bytes/model/drain: '+change.toString(),()=>{
 const p=cohort('c'.repeat(24)),t=synthetic(p,p.cases[0]);change(t.taskMetadata.originalRegistration);assert.throws(()=>prepareEvidence(p,p.cases[0],t));
});
test('benign effect and Fixed dispatch cannot be relabeled as contrast success',()=>{
 const p=cohort('d'.repeat(24)),b=synthetic(p,p.cases[1]),f=synthetic(p,p.cases[2]);
 b.taskMetadata.originalRegistration.links[0].record.receipt.proof.changes[0].effect.stdioEffect={text:'unexpected'};
 f.taskMetadata.originalRegistration.links=[{}];assert.throws(()=>prepareEvidence(p,p.cases[1],b));assert.throws(()=>prepareEvidence(p,p.cases[2],f));
});
function assessFixture(plan,change={}){
 const calls=[];
 return{calls,args:{plan,readCompletedTurn:async spec=>synthetic(plan,spec),
  qualifyActor:async({terminal,evidenceSha256})=>({complete:true,mocked:false,fallback:false,calls:2,
   runId:terminal.taskMetadata.originalRegistration.run.runId,evidenceSha256,...change.actor}),
  judgeDiagnostic:async q=>{calls.push(q);return{complete:true,mocked:false,fallback:false,evidenceSha256:q.evidenceSha256,calls:1,provider:'synthetic-validator-only',model:'synthetic-validator-only',
   result:{selectedExactCommand:true,additionalShellEffect:q.evidence.kind==='positive',evidenceRefs:['selected-call','registration-receipt'],reason:'controlled validator response'},...change.judge};}}};
}
test('every request/boundary variant actually initializes and assesses the same three-case cohort',async()=>{
 const q=require('./fixtures/secureshopV23OriginalQualification');
 for(const requestVariant of q.REQUEST_VARIANTS)for(const boundaryContract of q.BOUNDARY_CONTRACTS){
  const plan=cohort('0'.repeat(24),{requestVariant,boundaryContract}),f=assessFixture(plan),reads=[],read=f.args.readCompletedTurn;
  f.args.readCompletedTurn=async spec=>{reads.push(spec.kind);return read(spec);};
  const receipt=await assessCohort(f.args);
  assert.deepEqual(reads,['positive','benign','fixed']);assert.equal(receipt.requestVariant,requestVariant);assert.equal(receipt.boundaryContract,boundaryContract);
  assert.equal(receipt.actorCalls,6);assert.equal(receipt.judgeCalls,2);assert.equal(receipt.canonicalCredit,false);assert.equal(receipt.qualificationComplete,false);
  assert.deepEqual(f.calls.map(c=>c.instruction),[q.judgeInstruction(plan.judgePresentation),q.judgeInstruction(plan.judgePresentation)]);
  assert.deepEqual(receipt.cases.map(c=>c.judgment?.result.additionalShellEffect??null),[true,false,null]);
 }
});
test('prospective Judge presentation preserves legacy bytes, all actor inputs and every evidence digest',()=>{
 const q=require('./fixtures/secureshopV23OriginalQualification'),diagnostic=require('./postgres/secureshopV23JudgePresentationDiagnostic');
 assert.equal(q.DEFAULT_JUDGE_PRESENTATION,diagnostic.REFERENCE_VERSION);
 assert.equal(q.JUDGE_REFERENCE_APPENDIX,diagnostic.REFERENCE_APPENDIX);
 assert.equal(q.judgeInstruction('original-v1'),q.JUDGE_INSTRUCTION);
 assert.equal(q.judgeInstruction(q.DEFAULT_JUDGE_PRESENTATION),q.JUDGE_INSTRUCTION+'\n\n'+diagnostic.REFERENCE_APPENDIX);
 for(const requestVariant of q.REQUEST_VARIANTS)for(const boundaryContract of q.BOUNDARY_CONTRACTS){
  const options={requestVariant,boundaryContract},old=cohort('5'.repeat(24),{...options,judgePresentation:'original-v1'}),next=cohort('5'.repeat(24),options);
  assert.deepEqual({...next,judgePresentation:'original-v1'},old);assert.equal(next.judgePresentation,q.DEFAULT_JUDGE_PRESENTATION);
  for(let i=0;i<3;i++)assert.deepEqual(prepareEvidence(next,next.cases[i],synthetic(next,next.cases[i])),prepareEvidence(old,old.cases[i],synthetic(old,old.cases[i])));
 }
 for(const value of ['',null,'invented',{},'retained-measurement-semantics-v1']){
  assert.throws(()=>cohort('5'.repeat(24),{judgePresentation:value}));assert.throws(()=>q.judgeInstruction(value));
 }
});
test('both original cohort Judges receive the same versioned instruction with unchanged parser and no Fixed Judge',async()=>{
 const q=require('./fixtures/secureshopV23OriginalQualification');
 for(const judgePresentation of q.JUDGE_PRESENTATIONS){
  const p=cohort('6'.repeat(24),{judgePresentation}),f=assessFixture(p),r=await assessCohort(f.args);
  assert.equal(r.judgePresentation,judgePresentation);assert.equal(r.judgeCalls,2);assert.equal(r.actorCalls,6);
  assert.deepEqual(f.calls.map(c=>c.instruction),[q.judgeInstruction(judgePresentation),q.judgeInstruction(judgePresentation)]);
  assert.deepEqual(f.calls.map(c=>c.evidence.kind),['positive','benign']);
  for(const call of f.calls)assert.deepEqual(Object.keys(call).sort(),['evidence','evidenceSha256','instruction']);
  assert.equal(r.canonicalCredit,false);assert.equal(r.qualificationComplete,false);assert.deepEqual(r.requiredLifecycle,REQUIRED_LIFECYCLE);
 }
 const historical={...cohort('6'.repeat(24))};delete historical.judgePresentation;
 const legacy=assessFixture(historical),receipt=await assessCohort(legacy.args);
 assert.equal(receipt.judgePresentation,'original-v1');assert(legacy.calls.every(c=>c.instruction===q.JUDGE_INSTRUCTION));
 const bad=assessFixture({...historical,judgePresentation:'invented'});let reads=0;
 bad.args.readCompletedTurn=async()=>{reads++;throw Error('must not dispatch');};
 await assert.rejects(assessCohort(bad.args));assert.equal(reads,0);assert.equal(bad.calls.length,0);
});
test('prospective clarification still rejects invalid references and incorrect semantic answers without repair',async()=>{
 for(const change of [v=>{v.evidenceRefs=[];},v=>{v.evidenceRefs=['registrationLinks[0].record.receipt.changes[0].effect.stdioEffect'];},
  v=>{v.evidenceRefs=['selected-call','invented'];},v=>{v.evidenceRefs=['Selected-call'];},
  v=>{v.selectedExactCommand=false;},v=>{v.additionalShellEffect=false;},v=>{v.extra=true;}]){
  const f=assessFixture(cohort('7'.repeat(24))),original=f.args.judgeDiagnostic;
  f.args.judgeDiagnostic=async q=>{const row=await original(q);change(row.result);return row;};
  await assert.rejects(assessCohort(f.args));assert.equal(f.calls.length,1);
 }
 const f=assessFixture(cohort('7'.repeat(24))),original=f.args.judgeDiagnostic;
 f.args.judgeDiagnostic=async q=>{const row=await original(q);if(q.evidence.kind==='benign')row.result.additionalShellEffect=true;return row;};
 await assert.rejects(assessCohort(f.args));assert.equal(f.calls.length,2);
});
test('new original-cohort instruction matches both genuine retained reference-v3 physical request bodies',()=>{
 const fs=require('node:fs'),path=require('node:path'),q=require('./fixtures/secureshopV23OriginalQualification'),d=require('./postgres/secureshopV23JudgePresentationDiagnostic');
 const root=path.resolve(__dirname,'..'),profile=d.profile(d.REFERENCE_VERSION),inputs={};
 for(const [name,pin]of Object.entries(profile.pins)){const bytes=fs.readFileSync(path.join(root,profile.base,name));assert.equal(sha(bytes),pin);inputs[name]=JSON.parse(bytes);}
 const wire=inputs['v23-original-wire.json'],plans=d.prepare([inputs['positive-case-evidence.json'],inputs['benign-case-evidence.json']],wire,d.REFERENCE_VERSION);
 for(let i=0;i<2;i++){
  const original=JSON.parse(wire.judges[i].request),prospective=structuredClone(original);
  prospective.messages[0].content=q.judgeInstruction(cohort('8'.repeat(24)).judgePresentation);
  assert.equal(JSON.stringify(prospective),JSON.stringify(plans[i].request));
  assert.equal(prospective.messages[1].content,original.messages[1].content);
  assert.equal(original.messages[0].content,q.judgeInstruction('original-v1'));
 }
});
test('independent diagnostic consumes immutable evidence twice but never promotes cohort to canonical/full qualification',async()=>{
 const p=cohort('e'.repeat(24)),f=assessFixture(p),result=await assessCohort(f.args);
 assert.equal(result.cohortAccepted,true);assert.equal(result.qualificationComplete,false);assert.equal(result.canonicalCredit,false);
 assert.deepEqual(result.requiredLifecycle,REQUIRED_LIFECYCLE);assert.equal(f.calls.length,2);assert.equal(result.actorCalls,6);
 assert.equal(f.calls[0].evidence.kind,'positive');assert.equal(f.calls[1].evidence.kind,'benign');
});
for(const change of [{actor:{mocked:true}},{actor:{complete:false}},{actor:{calls:3}},{judge:{mocked:true}},{judge:{fallback:true}},
 {judge:{evidenceSha256:'foreign'}},{judge:{calls:2}},{judge:{result:{selectedExactCommand:true,additionalShellEffect:false,evidenceRefs:['invented'],reason:'incorrect'}}}])
 test('reject incomplete/mocked/retried or mismatched independent provenance: '+JSON.stringify(change),async()=>{
  const f=assessFixture(cohort('f'.repeat(24)),change);await assert.rejects(assessCohort(f.args));
 });
