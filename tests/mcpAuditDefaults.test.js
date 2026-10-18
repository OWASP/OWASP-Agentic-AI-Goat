'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const provenance=require('../server/database/postgres/catalogDefaultProvenance');
const prior=require('./fixtures/mcpAuditPriorDefaults.json');
const hints=require('../server/data/workshopHints'),solutions=require('../server/data/mcpWorkshopSolutions');
const {resolveObjectiveContent}=require('../server/database/postgres/workshopPlatformSeedCore');
const label=require('../server/config/workshopCatalog').WORKSHOP_OBJECTIVES.mcp_workshop.find(x=>x.id===prior.objectiveId).text;
const next=resolveObjectiveContent({workshopKey:'mcp_workshop',objectiveId:prior.objectiveId,hints,solutions:{mcp_workshop:solutions}});
function client(current,applied,state='managed'){
 const writes=[];return{writes,async query(sql,params=[]){
 if(/SELECT revision/.test(sql))return{rows:[{revision:1}]};
 if(/SELECT (label|hint_content|solution_content) AS value/.test(sql))return{rows:[{value:current}],rowCount:1};
 if(/SELECT \* FROM workshop_platform.catalog_field_defaults/.test(sql))return{rows:[{provenance_state:state,applied_default_hash:provenance.hashDocument(provenance.document(applied))}]};
 if(/UPDATE workshop_platform\.(objectives|catalog_field_defaults)/.test(sql)){writes.push({sql,params});return{rows:[],rowCount:1};}
 throw Error('Unexpected controlled SQL');
 }};
}
for(const [field,old,value]of[['label',prior.label,label],['hint_content',prior.hint,next.hint],['solution_content',prior.solution,next.solution]]){
 const spec={entityKind:'objective',workshopKey:'mcp_workshop',objectiveId:prior.objectiveId,fieldName:field,sourceValue:value,sourceVersion:'mcp-audit-accuracy'};
 test(field+' managed prior defaults advance; second seed leaves content unchanged',async()=>{
 const db=client(old,old);assert.equal((await provenance.reconcileField(db,spec)).changed,true);
 const updates=db.writes.filter(x=>/UPDATE workshop_platform.objectives/.test(x.sql));assert.equal(updates.length,1);assert.deepEqual(field==='label'?updates[0].params[2]:JSON.parse(updates[0].params[2]),value);
 const again=client(value,value);assert.equal((await provenance.reconcileField(again,spec)).changed,false);assert(!again.writes.some(x=>/UPDATE workshop_platform.objectives/.test(x.sql)));
 });
 test(field+(field==='label'?' instructor label preserved':' instructor edits and explicit null preserved'),async()=>{for(const state of ['managed','custom'])for(const current of (field==='label'?['Instructor-owned label']:[null,{title:'Instructor-owned',hints:['Keep my text']}])){const db=client(current,old,state);assert.equal((await provenance.reconcileField(db,spec)).changed,false);assert(!db.writes.some(x=>/UPDATE workshop_platform.objectives/.test(x.sql)));}});
}
test('eleven lessons remain and audit copy distinguishes target telemetry from platform evidence',()=>{
 assert.equal(Object.keys(solutions).length,11);assert(next.hintPresent&&next.solutionPresent);
 assert.match(label,/target-private/);assert.match(label,/platform evidence remains retained/);
 for(const value of [next.hint,next.solution]){const text=JSON.stringify(value);assert.match(text,/without authorization/);assert.match(text,/platform/);assert.match(text,/retains|retained/);assert.doesNotMatch(text,/not itself recorded|never records|no observability|whole trail can vanish/);}
});
