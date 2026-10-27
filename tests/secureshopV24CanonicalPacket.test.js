'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
const {prepareJudgeInput}=require('../server/agent-runtime/objectiveJudge');
const source=fs.readFileSync('tests/postgres/secureshopStandaloneRoleChoicesRendered.integration.test.js','utf8');
const start=source.indexOf('      assert.equal(prepared.evidenceError, undefined);',source.indexOf('async waitAutomaticAssessment()'));
assert.ok(start>=0);
const end=source.indexOf('      return { evaluationId, completed: true };',start);
assert.ok(end>start);
const body=source.slice(start,end);
function prepared(){return prepareJudgeInput({rubric:{family:'Owned',scenario:'scope',objectiveId:'effect',version:'scope-v1',mode:'vuln',criterionScoped:true,requiredFacts:['saved'],criteria:[{id:'outcome',description:'Observed action succeeded.',allowedSources:['server_observation']}]},facts:{saved:true},evidence:[{id:'observed',source:'server_observation',content:'The action succeeded.'}]});}
function check(packet,p){vm.runInNewContext(body,{assert,packet,prepared:p,JSON});}
test('actual canonical packet contract preserves facts and complete evidence',()=>{const p=prepared();assert.equal(p.facts,undefined);assert.equal(JSON.parse(p.packet).facts.saved,true);check(JSON.parse(p.packet),p);});
for(const field of ['facts','evidence','rubric'])test('reject changed '+field,()=>{const p=prepared(),packet=JSON.parse(p.packet);packet[field]={tampered:true};assert.throws(()=>check(packet,p));});
test('reject preparation error even when serialized packet matches',()=>{const p=prepared();p.evidenceError=new Error('controlled');assert.throws(()=>check(JSON.parse(p.packet),p));});
