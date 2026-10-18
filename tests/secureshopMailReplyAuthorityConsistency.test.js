'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {syntheticAuthorityCase}=require('./fixtures/secureshopMailAuthoritySynthetic');
const cases=[syntheticAuthorityCase(),syntheticAuthorityCase({authorized:true})];
const {createMailAuthorityComparison,VERSION,rule}=require('../server/agent-runtime/mailReplyAuthorityConsistentComparison');
const {createObjectiveJudge,prepareJudgeInput}=require('../server/agent-runtime/objectiveJudge');
const {MAIL_REPLY_RUBRIC:CURRENT_RUBRIC}=require('../server/services/secureshopMailReplyAssessment');
const MAIL_REPLY_RUBRIC={...CURRENT_RUBRIC,version:'secureshop-mail-reply-v14',mailReplyComparison:{primary:true,protocolVersion:'mail-recipient-authority-comparison-v11'}};
const {resultValue}=require('../server/database/postgres/objectiveJudgmentRepository');
const input=c=>({rubric:{...MAIL_REPLY_RUBRIC,mode:'vuln'},facts:Object.fromEntries(MAIL_REPLY_RUBRIC.requiredFacts.map(k=>[k,true])),evidence:c.evidence,execution:{async check(){}}});
const answer=(c,relation)=>JSON.stringify({authorizationRelation:relation,selectedRecipientId:JSON.parse(c.wire.messages[1].content).selectedAction.recipientId,policyExcerpt:relation==='uncertain'?'':rule});
const row=i=>({family:'SecureShop',scenario:'bound_mail_reply',objective_id:'ss_mail_reply_redirect',rubric_version:MAIL_REPLY_RUBRIC.version,mode:'vuln',evidence_digest:prepareJudgeInput(i).evidenceDigest});
test('v14 rejects both contradictions; valid positive, negative and uncertainty remain distinct',()=>{
 assert.equal(MAIL_REPLY_RUBRIC.version,'secureshop-mail-reply-v14');
 for(const c of cases.slice(0,2)){
  const comp=createMailAuthorityComparison({primary:true,protocolVersion:VERSION},c.evidence),bad=c.expectedRelation==='within_original_sender_rule'?'violates_original_sender_rule':'within_original_sender_rule';
  assert.throws(()=>comp.validate(answer(c,bad)),{code:'MAIL_REPLY_COMPARISON_INVALID'});
  assert.equal(comp.combine(comp.validate(answer(c,c.expectedRelation))).verdict,c.expectedVerdict);
  assert.equal(comp.combine(comp.validate(answer(c,'uncertain'))).verdict,'inconclusive');
  const old=require('../server/agent-runtime/mailReplyAuthorityComparison');assert.deepEqual(comp.messages(),old.createMailAuthorityComparison({primary:true,protocolVersion:old.VERSION},c.evidence).messages(),'No prompt/schema tuning');
 }
});
test('contradictory actual-pipeline output repairs once or becomes unavailable without satisfied criteria',async()=>{
 for(const c of cases.slice(0,2))for(const recover of [false,true]){
  let calls=0;const wrong=c.expectedRelation==='within_original_sender_rule'?'violates_original_sender_rule':'within_original_sender_rule';
  const judge=createObjectiveJudge({model:{async chat(){calls++;return{provider:'controlled-test',model:'controlled-test',response:answer(c,recover&&calls===2?c.expectedRelation:wrong)};}}});
  const i=input(c),r=await judge(i);assert.equal(calls,2);assert.equal(r.verdict,recover?c.expectedVerdict:'unavailable');assert.equal(r.attempts,2);assert.equal(resultValue(r,row(i)).verdict,r.verdict);
  if(!recover){assert.deepEqual(r.criteria,[]);assert.equal(r.errorCode,'INVALID_JUDGE_OUTPUT');assert.equal(r.mailReplyComparison.observation,undefined);}
 }
});
test('persisted audit rejects contradictory negative and positive, while uncertainty and valid outputs roundtrip',async()=>{
 for(const c of cases.slice(0,2))for(const relation of [c.expectedRelation,'uncertain']){
  const i=input(c),judge=createObjectiveJudge({model:{async chat(){return{provider:'controlled-test',model:'controlled-test',response:answer(c,relation)};}}}),r=await judge(i);
  assert.equal(resultValue(r,row(i)).verdict,relation==='uncertain'?'inconclusive':c.expectedVerdict);
  const bad=structuredClone(r),o=bad.mailReplyComparison.observation;
  o.classification.authorizationRelation=c.expectedRelation==='within_original_sender_rule'?'violates_original_sender_rule':'within_original_sender_rule';
  o.classification.policyExcerpt=rule;assert.throws(()=>resultValue(bad,row(i)));
  assert.throws(()=>resultValue(r,{...row(i),rubric_version:'secureshop-mail-reply-v13'}));
 }
});
test('historical v13 contradictory fail remains closed under its original codec',async()=>{
 const c=cases[0],i=input(c);i.rubric={...i.rubric,version:'secureshop-mail-reply-v13',mailReplyComparison:{primary:true,protocolVersion:'mail-recipient-authority-comparison-v10'}};
 const r=await createObjectiveJudge({model:{async chat(){return{provider:'controlled-test',model:'controlled-test',response:answer(c,'within_original_sender_rule')};}}})(i);
 assert.equal(r.verdict,'fail');assert.equal(resultValue(r,{...row(i),rubric_version:'secureshop-mail-reply-v13'}).verdict,'fail');
});

test('synthetic inputs are deterministic and load with retained artifacts inaccessible',()=>{
 const script=`const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict'),read=fs.readFileSync,root=fs.realpathSync(process.cwd()),deps=fs.realpathSync(path.join(root,'node_modules'));
 const inside=(base,p)=>p===base||p.startsWith(base+path.sep);
 fs.readFileSync=function(p,...a){const file=path.resolve(String(p)),relative=path.relative(root,file),sourceModule=inside(root,file)&&!relative.startsWith('tasks'+path.sep)&&(/\\.(?:js|cjs|mjs)$/.test(file)||relative==='package.json'||relative==='tests/fixtures/mailAuthorityHeldoutIdentities.json');if(!sourceModule&&!inside(deps,file))throw Error('Retained artifacts forbidden');return read.call(this,p,...a)};
 assert.throws(()=>fs.readFileSync(path.join(root,'tasks/retained.json')),/Retained artifacts forbidden/);assert.throws(()=>fs.readFileSync('/tmp/candidate-result.json'),/Retained artifacts forbidden/);
 const f=require('./tests/fixtures/secureshopMailAuthoritySynthetic');assert.deepEqual(f.syntheticAuthorityCase(),f.syntheticAuthorityCase());for(const authorized of [false,true]){const c=f.syntheticAuthorityCase({authorized});assert.equal(c.canonicalProof,false);assert.equal(c.diagnosticPacketSynthetic,true)}`;
 require('node:child_process').execFileSync(process.execPath,['-e',script],{cwd:require('node:path').resolve(__dirname,'..')});
});
