'use strict';
const test=require('node:test'),assert=require('node:assert/strict');const {declaredCases,budget,summarize}=require('./fixtures/ragDefenseAlignmentCohort'),spec=require('../tests/release-inputs/rag-defense-alignment-cohort-design-2026-09-27.json');
test('ten exact paired sources/task and policy objectives',()=>{const rows=declaredCases(spec);assert.equal(rows.length,10);for(let i=0;i<10;i+=2){assert.equal(rows[i].text,rows[i+1].text);assert.equal(rows[i].question,spec.trustedTask);assert.equal(rows[i+1].objective,'rag_injected_doc');}assert.throws(()=>declaredCases({...spec,cases:spec.cases.map((c,i)=>i?c:{...c,source:c.source+'x'})}));});
test('case budgets do not borrow, count failed attempts and cap140',()=>{const b=budget();for(const c of declaredCases(spec)){for(let i=0;i<8;i++)b.admit(c.id,'actor');assert.throws(()=>b.admit(c.id,'actor'));for(let i=0;i<6;i++)b.admit(c.id,'judge');assert.throws(()=>b.admit(c.id,'judge'));}assert.equal(b.total,140);assert.throws(()=>b.admit('extra','actor'));});
test('complete transport does not manufacture semantic acceptance; missing/invalid and false benign credit fail',()=>{const rows=declaredCases(spec).map(c=>({...c,objectiveId:c.objective,runId:'owned',answer:'retained',retrievalReceipts:[{}],retrievedChunks:[{}],judgments:[{verdict:'fail'}],persistedJudgments:[{verdict:'fail'}],completedObjectiveIds:[],completionReadback:{completed:false,generation:0}}));const r=summarize(rows);assert(r.technicalComplete);assert.equal(r.semanticAcceptance,false);assert(r.records.some(c=>c.semantics==='failed'));rows[0].failure={code:'timeout'};assert.equal(summarize(rows).technicalComplete,false);rows[1].completedObjectiveIds=[rows[1].objectiveId];rows[1].completionReadback.completed=true;assert.equal(summarize(rows).records[1].semantics,'failed');});

test('trusted task mutation and duplicate case records cannot qualify',()=>{assert.throws(()=>declaredCases({...spec,trustedTask:spec.trustedTask+' changed'}));assert.equal(summarize(Array(10).fill({id:'duplicate'})).technicalComplete,false);});

test('retained raw transport is exact and bounded',async()=>{const {readRaw}=require('./fixtures/ragDefenseAlignmentNative');assert.equal(await readRaw(new Response('first\nsecond\n')),'first\nsecond\n');await assert.rejects(readRaw(new Response('x'.repeat(4*1024*1024+1))),/exceeds limit/);});

test('summary rejects wrong source, task, mode and invented ten identities',()=>{
 const rows=declaredCases(spec).map(c=>({...c,objectiveId:c.objective,runId:'owned',answer:'answer',retrievalReceipts:[{}],retrievedChunks:[{}],judgments:[{verdict:'fail'}],persistedJudgments:[{verdict:'fail'}],completedObjectiveIds:[],completionReadback:{completed:false,generation:0}}));
 assert(summarize(rows).technicalComplete);
 for(const key of ['id','text','question','mode','sourceSha256']){const changed=structuredClone(rows);changed[0][key]='changed';assert.equal(summarize(changed).technicalComplete,false);}
 const changed=structuredClone(rows);changed[0].completionReadback.completed=true;assert.equal(summarize(changed).technicalComplete,false);
});
