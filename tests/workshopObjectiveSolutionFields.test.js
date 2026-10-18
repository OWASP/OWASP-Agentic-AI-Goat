'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const {createWorkshopConfigRepository}=require('../server/database/postgres/workshopConfigRepository');
const families=[['xss_workshop','reflected_xss_llm','xssWorkshopSolutions'],['csrf_workshop','csrf_prompt_injection','csrfWorkshopSolutions']];
function fixture(canonical,alias,initial,initialHint={title:'hint',hints:['keep']}){
 const calls=[];let content=structuredClone(initial),hint=structuredClone(initialHint),revision=0;
 const row={workshop_key:canonical,challenge_key:alias,is_visible:true,show_hints:true,show_solutions:false};
 const metadata={label:'Original objective',description:'',category:'AI'};
 const client={async query(sql,params=[]){
  calls.push({sql,params});
  if(['BEGIN','COMMIT','ROLLBACK'].includes(sql))return {rows:[]};
  if(sql.startsWith('SELECT * FROM workshop_platform.exercises'))return {rows:[row]};
  if(sql.startsWith('SELECT * FROM workshop_platform.objectives'))return {rows:[{...metadata,solution_content:content,hint_content:hint}]};
  if(sql.startsWith('SELECT revision'))return {rows:[{revision}]};
  if(sql.startsWith('SELECT w.*'))return {rows:[]};
  if(sql.startsWith('UPDATE workshop_platform.objectives SET solution_content=')){
   assert.match(sql,/solution_content=(?:solution_content|COALESCE\(solution_content,'\{\}'::jsonb\))\|\|\$1::jsonb/);assert.match(sql,/IS DISTINCT FROM/);
   const merged={...content,...JSON.parse(params[0])};const changed=!require('node:util').isDeepStrictEqual(merged,content);content=merged;return {rowCount:Number(changed),rows:[]};
  }
  if(sql.startsWith('UPDATE workshop_platform.objectives SET hint_content=')){
   assert.match(sql,/hint_content=COALESCE\(hint_content,'\{\}'::jsonb\)\|\|\$1::jsonb/);
   const merged={...hint,...JSON.parse(params[0])};const changed=!require('node:util').isDeepStrictEqual(merged,hint);hint=merged;return {rowCount:Number(changed),rows:[]};
  }
  if(sql.startsWith('UPDATE workshop_platform.objectives SET label=')){
   const changed=!require('node:util').isDeepStrictEqual([metadata.label,metadata.description,metadata.category],params.slice(0,3));
   [metadata.label,metadata.description,metadata.category]=params.slice(0,3);
   return {rowCount:Number(changed),rows:[]};
  }
  if(sql.startsWith('UPDATE workshop_platform.config_revision')){revision++;return {rowCount:1,rows:[]};}
  if(sql.includes("provenance_state='custom'"))return {rowCount:1,rows:[]};
  if(sql.startsWith('INSERT INTO workshop_platform.revisions'))return {rows:[{revision}]};
  throw Error('Unexpected controlled query: '+sql);
 },release(){}};
 return {service:createWorkshopConfigRepository({connect:async()=>client}),calls,content:()=>content,hint:()=>hint,metadata:()=>metadata,revision:()=>revision};
}
function invoke(f,method,key,patch){return f.service[method](key,'owned-objective',patch);}
for(const method of ['updateSolutionContent','saveSolutionEditor']){
 test(method+' admits current XSS/CSRF objective fields after canonical alias resolution, preserving merge/gates/no-op',async()=>{
  for(const [key,alias,file] of families){
   const authored=require('../server/data/'+file).objectiveSolutions[0];
   const initial={...authored,instructorExtension:{retain:['nested']}};
   const f=fixture(key,alias,initial),patch={title:'Instructor title',hint:'',example:'<img src=x onerror=alert(1)>',explanation:'Owned synthetic teaching example'};
   const changed=await invoke(f,method,alias,patch);assert.equal(changed.changed,true);
   assert.deepEqual(f.content(),{...initial,...patch});assert.equal(f.revision(),1);
   assert(f.calls.some(c=>c.sql.includes("provenance_state='custom'")&&c.params[1]===key&&c.params[3]==='solution_content'));
   assert(!f.calls.some(c=>/SET (show_|hint_enabled|solution_enabled|is_enabled)/.test(c.sql)));
   const customWrites=f.calls.filter(c=>c.sql.includes("provenance_state='custom'")).length;
   assert.equal((await invoke(f,method,key,patch)).changed,false);assert.equal(f.revision(),1);
   assert.equal(f.calls.filter(c=>c.sql.includes("provenance_state='custom'")).length,customWrites);
  }
 });
 test(method+' denies singular fields for other resolved families even when request names an allowed key',async()=>{
  for(const canonical of ['mcp_workshop','direct_prompt_injection','xss_workshop_extra']){
   const f=fixture(canonical,'xss_workshop',{title:'original'});
   await assert.rejects(async()=>invoke(f,method,'xss_workshop',{hint:'text'}),{code:'BAD_REQUEST'});
   assert(!f.calls.some(c=>c.sql.startsWith('UPDATE')));assert(f.calls.some(c=>c.sql==='ROLLBACK'));
  }
 });
 test(method+' rejects unknown keys, invalid title and nonstring singular values before any transaction',async()=>{
  for(const patch of [{unknown:'x'},{title:''},...['hint','example','explanation'].flatMap(key=>[null,42,[],{}].map(value=>({[key]:value})))]){
   const f=fixture('xss_workshop','reflected_xss_llm',{title:'original'});
   await assert.rejects(async()=>invoke(f,method,'reflected_xss_llm',patch),{code:'BAD_REQUEST'});assert.equal(f.calls.length,0);
  }
 });
}
test('hint content does not acquire solution-only singular fields',async()=>{
 const f=fixture('xss_workshop','reflected_xss_llm',{title:'original'});
 await assert.rejects(async()=>f.service.updateHintContent('xss_workshop','owned',{hint:'not admitted'}),{code:'BAD_REQUEST'});assert.equal(f.calls.length,0);
});

test('Excessive Agency vulnerability explanation is editable only in its canonical family',async()=>{
 const owned=fixture('excessive_agency','excessive_agency',{title:'Owned lesson',vulnerability:'Prior text'});
 assert.equal((await owned.service.updateSolutionContent('excessive_agency','owned',{vulnerability:'Instructor explanation'},71)).changed,true);
 assert.equal(owned.content().vulnerability,'Instructor explanation');
 const other=fixture('mcp_workshop','excessive_agency',{title:'MCP lesson'});
 await assert.rejects(async()=>other.service.updateSolutionContent('excessive_agency','owned',{vulnerability:'Cross-family field'},71),{code:'BAD_REQUEST'});
});

for(const method of ['updateSolutionContent','saveSolutionEditor'])test(method+' preserves generic SSI optional empty Steps/Tags and rejects malformed lists',async()=>{
 const original=require('../server/config/legacyFileSsiCurriculum').SOLUTIONS.path_traversal;
 const {genericSolutionPatch}=require('./fixtures/codeBotRenderedParityV1');
 const body=genericSolutionPatch(original,false);
 assert.deepEqual(body.solution_steps,[]);assert.deepEqual(body.tags,[]);
 // Exact production postgresAdmin generic editor field mapping.
 const patch={title:body.solution_title,description:body.solution_description,hints:body.solution_steps,code:body.solution_code,approach:body.explanation,references:body.reference_links,difficulty:body.difficulty_level,estimatedTime:body.estimated_time,prerequisites:body.prerequisites,tips:body.tags};
 const f=fixture('legacy_sensitive_file_ssi','legacy_sensitive_file_ssi',{...original,hints:['Prior optional step'],tips:['Prior optional tag'],instructorExtra:{kept:true}});
 assert.equal((await invoke(f,method,'legacy_sensitive_file_ssi',patch)).changed,true);
 assert.deepEqual(f.content().hints,[]);assert.deepEqual(f.content().tips,[]);assert.deepEqual(f.content().instructorExtra,{kept:true});
 assert.equal((await invoke(f,method,'legacy_sensitive_file_ssi',patch)).changed,false);
 for(const key of ['hints','tips'])for(const value of [null,'',{},[null],[1],[''],['  '],['valid','']]){
  const denied=fixture('legacy_sensitive_file_ssi','legacy_sensitive_file_ssi',original);
  await assert.rejects(async()=>invoke(denied,method,'legacy_sensitive_file_ssi',{[key]:value}),{code:'BAD_REQUEST'});assert.equal(denied.calls.length,0);
 }
});
test('required hint_content list remains nonempty, typed and closed',async()=>{
 for(const patch of [{hints:[]},{hints:null},{hints:['']},{hints:['valid',42]},{tips:[]},{unknown:[]}]){
  const f=fixture('legacy_sensitive_file_ssi','legacy_sensitive_file_ssi',{title:'original'});
  await assert.rejects(async()=>f.service.updateHintContent('legacy_sensitive_file_ssi','path_traversal',patch),{code:'BAD_REQUEST'});assert.equal(f.calls.length,0);
 }
});

for(const method of ['updateSolutionContent','saveSolutionEditor'])test(method+' retains nonempty examples boundary independently of optional Steps/Tags',async()=>{
 const f=fixture('legacy_sensitive_file_ssi','legacy_sensitive_file_ssi',{title:'original'});
 await assert.rejects(async()=>invoke(f,method,'legacy_sensitive_file_ssi',{examples:[]}),{code:'BAD_REQUEST'});assert.equal(f.calls.length,0);
});

test('NULL teaching content can be authored without enabling hint or solution gates',async()=>{
 const f=fixture('xss_workshop','reflected_xss_llm',null,null);
 await assert.rejects(f.service.updateHintContent('xss_workshop','owned',{title:'Only a title'}),{code:'BAD_REQUEST'});
 await assert.rejects(f.service.updateSolutionContent('xss_workshop','owned',{title:'Only a title'}),{code:'BAD_REQUEST'});
 assert.equal((await f.service.updateHintContent('xss_workshop','owned',{title:'Instructor hint',hints:['A safe teaching step']},71)).changed,true);
 assert.deepEqual(f.hint(),{title:'Instructor hint',hints:['A safe teaching step']});
 assert.equal((await f.service.updateSolutionContent('xss_workshop','owned',{title:'Instructor solution',description:'Explain the synthetic lesson'},71)).changed,true);
 assert.deepEqual(f.content(),{title:'Instructor solution',description:'Explain the synthetic lesson'});
 const writes=f.calls.filter(call=>call.sql.startsWith('UPDATE workshop_platform.objectives SET'));
 assert(writes.every(call=>call.params[1]===71));
 assert(!f.calls.some(call=>/SET (show_|hint_enabled|solution_enabled|is_enabled)/.test(call.sql)));
 assert(f.calls.filter(call=>call.sql.includes("provenance_state='custom'")).map(call=>call.params[3]).includes('hint_content'));
 assert(f.calls.filter(call=>call.sql.includes("provenance_state='custom'")).map(call=>call.params[3]).includes('solution_content'));
});

test('content authoring rejects oversized JSON before allocating a transaction',async()=>{
 const f=fixture('xss_workshop','reflected_xss_llm',null,null);
 assert.throws(()=>f.service.updateHintContent('xss_workshop','owned',{title:'Large',hints:['x'.repeat(65536)]}),{code:'BAD_REQUEST'});
 assert.equal(f.calls.length,0);
});

test('objective teaching metadata saves with provenance without changing identity or gates',async()=>{
 const f=fixture('xss_workshop','reflected_xss_llm',null);
 const patch={label:'Instructor title',description:'A bounded learner-facing description',category:'Prompt security'};
 assert.equal((await f.service.updateObjectiveMetadata('xss_workshop','owned',patch,71)).changed,true);
 assert.deepEqual(f.metadata(),patch);
 const writes=f.calls.filter(call=>call.sql.startsWith('UPDATE workshop_platform.objectives SET label='));
 assert.equal(writes.length,1);
 assert.equal(writes[0].params[3],71);
 assert.equal(writes[0].params[5],'owned');
 assert(!f.calls.some(call=>/SET (show_|hint_enabled|solution_enabled|is_enabled)/.test(call.sql)));
 assert.deepEqual(f.calls.filter(call=>call.sql.includes("provenance_state='custom'")).map(call=>call.params[3]).sort(),['category','description','label']);
 assert.equal((await f.service.updateObjectiveMetadata('xss_workshop','owned',patch,71)).changed,false);
 assert.equal(f.revision(),1);
 for(const invalid of [{objectiveId:'new-id'},{description:'x'.repeat(4001)},{label:' '},{category:42}]){
  assert.throws(()=>f.service.updateObjectiveMetadata('xss_workshop','owned',invalid,71),{code:'BAD_REQUEST'});
 }
});
