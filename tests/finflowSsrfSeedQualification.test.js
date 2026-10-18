'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),crypto=require('node:crypto');
const {IDS,KEY,assertRefresh,qualify}=require('./fixtures/finflowSsrfSeedQualification');
test('prior SSRF objective defaults project exactly to current reviewed content',()=>{
 const prior=require('./fixtures/finflowSsrfPriorDefaults.json'),report=require('./release-inputs/finflow-ssrf-content-source-v1.json'),sha=x=>crypto.createHash('sha256').update(x).digest('hex');
 assert.equal(prior.authority.report,'tasks/main-workspace-preservation-2026-09-28/finflow-ssrf-content-source-v1.json');
 assert.equal(sha(fs.readFileSync(require.resolve('./release-inputs/finflow-ssrf-content-source-v1.json'))),prior.authority.sha256);assert.deepEqual(prior.objectiveIds,IDS);
 for(const [file,row]of Object.entries(report.files)){
 // These immutable hashes identify historical whole modules, not current unrelated-family bytes.
 // Whole-file historical reconstruction is a separate pending evidence task.
 assert.equal(prior.sources[file],row.beforeSha256);
 assert.match(row.afterSha256,/^[a-f0-9]{64}$/);
 const text=fs.readFileSync(file,'utf8');
 for(const pair of row.replacements)assert.equal(text.split(pair.after).length,2);
 const actual=require('../'+file),kind=file.includes('Hints')?'hints':'solutions',map=kind==='hints'?actual[KEY]:actual.solutions;
 function restore(value){if(typeof value==='string'){for(const pair of row.replacements)value=value.replace(pair.before,pair.after);return value;}if(Array.isArray(value))return value.map(restore);return value&&typeof value==='object'?Object.fromEntries(Object.entries(value).map(([k,v])=>[k,restore(v)])):value;}
 assert.deepEqual(Object.keys(prior[kind]),IDS);for(const id of IDS){assert(prior[kind][id]);assert.deepEqual(restore(prior[kind][id]),map[id]);assert.notDeepEqual(prior[kind][id],map[id]);}}
});
test('custom observation refresh permits only exact provenance refresh and rejects sibling/gate/content/default tampering',()=>{
 const field='hint_content',id=IDS[0],row={workshop_key:KEY,objective_id:id,hint_content:null,hint_enabled:false};
 const old={entity_kind:'objective',workshop_key:KEY,objective_id:id,field_name:field,provenance_state:'custom',observed_document:{old:true},updated_at:'2026-01-01T00:00:00Z',default_document:{kept:true}};
 const before={objectives:[row,{workshop_key:KEY,objective_id:'admin_backup',hint_content:{hints:['sibling']}}],exercises:[{show_hints:true}],revision:[{revision:1}],defaults:[old]};
 const after=structuredClone(before);after.defaults[0].observed_document=require('../server/database/postgres/catalogDefaultProvenance').document(null);after.defaults[0].updated_at='2026-01-02T00:00:00Z';assertRefresh(before,after,[id+':'+field]);
 for(const change of [x=>x.objectives[0].hint_enabled=true,x=>x.objectives[1].hint_content=null,x=>x.exercises[0].show_hints=false,x=>x.revision[0].revision++,x=>x.defaults[0].default_document={},x=>x.defaults[0].provenance_state='managed',x=>x.defaults[0].observed_document={value:'wrong'},x=>x.defaults.pop()]){const bad=structuredClone(after);change(bad);assert.throws(()=>assertRefresh(before,bad,[id+':'+field]));}
});
test('seed probe refuses configured stores and previously seeded targets before mutation',async()=>{
 const old=process.env.PG_TEST_DISPOSABLE;let writes=0;const migration={connect:async()=>{throw Error('Unexpected connect');},query:async()=>{writes++;throw Error('Unexpected write');}},identity={query:async()=>({rows:[{n:1}]})};
 try{delete process.env.PG_TEST_DISPOSABLE;await assert.rejects(qualify({identity,migration}));process.env.PG_TEST_DISPOSABLE='yes';await assert.rejects(qualify({identity,migration}));assert.equal(writes,0);}finally{if(old===undefined)delete process.env.PG_TEST_DISPOSABLE;else process.env.PG_TEST_DISPOSABLE=old;}
});
