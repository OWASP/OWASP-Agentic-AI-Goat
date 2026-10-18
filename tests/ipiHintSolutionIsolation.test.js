'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {createWorkshopConfigRepository}=require('../server/database/postgres/workshopConfigRepository');
const {createPostgresHintsRouter,createPostgresSolutionsRouter}=require('../server/routes/postgresWorkshopContent');
const {resolveObjectiveContent}=require('../server/database/postgres/workshopPlatformSeedCore');
function fixture(){
 const hint={title:'Progressive instructor hints',hints:['Hint-owned progressive content']},solution={title:'IPI solution',approach:'Documented solution approach',hints:['Solution-owned explanation']};
 const row={workshop_key:'indirect_prompt_injection',is_visible:true,show_hints:false,show_solutions:true,objective_id:'rag_upload',is_enabled:true,hint_enabled:true,solution_enabled:true,hint_content:hint,solution_content:solution};
 const client={release(){},async query(sql){if(sql.includes('SELECT revision'))return{rows:[{revision:17}]};if(sql.startsWith('SELECT w.*')||sql.startsWith('SELECT * FROM workshop_platform.exercises'))return{rows:[row]};return{rows:[]};}};
 const config=createWorkshopConfigRepository({connect:async()=>client,query:client.query});return{row,hint,solution,hints:createPostgresHintsRouter(config),solutions:createPostgresSolutionsRouter(config)};
}
async function invoke(router,path,params){const layer=router.stack.find(x=>x.route?.path===path);assert(layer);let body,status=200;await layer.route.stack.at(-1).handle({params},{status(n){status=n;return this;},json(value){body=value;}});return{status,body};}
test('IPI solution response retains its own content without merging Hint-owned progressive content',async()=>{
 const f=fixture(),response=await invoke(f.solutions,'/indirect-pi/:objectiveId',{objectiveId:'rag_upload'});
 assert.equal(response.status,200);assert.deepEqual(response.body.solution,f.solution);assert(!JSON.stringify(response.body).includes(f.hint.hints[0]));
 assert.deepEqual(resolveObjectiveContent({workshopKey:'indirect_prompt_injection',objectiveId:'rag_upload',hints:{indirect_prompt_injection:{rag_upload:f.hint}},solutions:{indirect_prompt_injection:{rag_upload:f.solution}}}),{hintPresent:true,hint:f.hint,solutionPresent:true,solution:f.solution});
});
test('IPI master gates independently admit Hint and Solution content through supported routers',async()=>{
 const f=fixture(),params={workshopKey:'indirect_prompt_injection',objectiveId:'rag_upload'};
 assert.equal((await invoke(f.hints,'/:workshopKey/:objectiveId',params)).status,403);
 f.row.show_hints=true;f.row.show_solutions=false;
 assert.deepEqual((await invoke(f.hints,'/:workshopKey/:objectiveId',params)).body,{success:true,hint:f.hint});assert.equal((await invoke(f.solutions,'/indirect-pi/:objectiveId',params)).status,403);
 f.row.show_solutions=true;f.row.solution_enabled=false;assert.equal((await invoke(f.solutions,'/indirect-pi/:objectiveId',params)).status,403);assert.equal((await invoke(f.hints,'/:workshopKey/:objectiveId',params)).status,200);
 f.row.solution_enabled=true;f.row.hint_enabled=false;assert.equal((await invoke(f.hints,'/:workshopKey/:objectiveId',params)).status,403);assert.equal((await invoke(f.solutions,'/indirect-pi/:objectiveId',params)).status,200);
 f.row.is_enabled=false;assert.equal((await invoke(f.solutions,'/indirect-pi/:objectiveId',params)).status,403);
});
