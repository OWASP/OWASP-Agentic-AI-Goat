'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),Module=require('node:module');
const {stageMailReplyCandidateCatalog:stage}=require('./fixtures/secureshopMailReplyCandidateCatalog');
const file=require.resolve('../server/config/secureshopCurriculum'),source=fs.readFileSync(file,'utf8'),id='ss_mail_reply_redirect';
const pendingSource=source.replace("id: 'ss_mail_reply_redirect', text: 'Cause a real assistant to save a reply outside its original-sender authorization', qualification: 'native-model'","id: 'ss_mail_reply_redirect', text: 'Cause a real assistant to save a reply outside its original-sender authorization', qualification: 'pending'");
function load(filename,text,override){const m=new Module(filename,module);m.filename=filename;m.paths=Module._nodeModulePaths(path.dirname(filename));const original=m.require.bind(m);m.require=name=>override?.[name]||original(name);m._compile(text,filename);return m.exports;}
test('private candidate adds only reply to every derived eligibility view without changing defaults or shared source',()=>{const before=load(file,pendingSource),after=load(file,stage(pendingSource));assert.equal(before.isQualifiedObjective(id),false);assert.equal(after.isQualifiedObjective(id),true);assert.deepEqual(after.QUALIFIED_OBJECTIVE_IDS.filter(x=>!before.QUALIFIED_OBJECTIVE_IDS.includes(x)),[id]);assert.deepEqual(after.PENDING_OBJECTIVE_IDS,before.PENDING_OBJECTIVE_IDS.filter(x=>x!==id));assert.deepEqual(after.EXERCISES,before.EXERCISES);assert.deepEqual(after.CHALLENGE,before.CHALLENGE);assert.equal(after.CHALLENGE.defaultVisible,true);assert.equal(after.OBJECTIVES.find(x=>x.id===id).defaultEnabled,false);assert.deepEqual(after.OBJECTIVES.map(x=>({...x,qualification:null})),before.OBJECTIVES.map(x=>({...x,qualification:null})));assert.equal(fs.readFileSync(file,'utf8'),source);assert.equal(stage(source),source);assert.equal(stage(stage(pendingSource)),source);assert.throws(()=>stage(source.replace("qualification: 'native-model', evidence: 'Exact owned source read", "qualification: 'unknown', evidence: 'Exact owned source read")));});
async function cascade(catalog){
 const state={workshop_key:'secureshop_agent_security',is_visible:true,show_hints:true,show_solutions:true,objective_id:id,label:'controlled',is_enabled:true,hint_enabled:true,solution_enabled:true,hint_content:{hints:['controlled']},solution_content:{description:'controlled'}};
 const query=async(sql,args=[])=>{
  if(sql.startsWith('UPDATE workshop_platform.exercises SET show_')){state[sql.includes('show_hints')?'show_hints':'show_solutions']=args[0];return{rowCount:1,rows:[]};}
  if(sql.startsWith('UPDATE workshop_platform.objectives SET ')){const gate=sql.includes('hint_enabled')?'hint_enabled':'solution_enabled';if(!args[0]||args[3].includes(id))state[gate]=args[0];return{rowCount:1,rows:[]};}
  if(sql.includes('RETURNING revision'))return{rows:[{revision:1}],rowCount:1};
  if(sql.startsWith('SELECT revision'))return{rows:[{revision:1}]};
  if(sql.includes('FROM workshop_platform.exercises'))return{rows:[{...state}]};
  return{rows:[],rowCount:1};
 };
 const filename=require.resolve('../server/database/postgres/workshopConfigRepository'),repo=load(filename,fs.readFileSync(filename,'utf8'),{'../../config/secureshopCurriculum':catalog}).createWorkshopConfigRepository({query,connect:async()=>({query,release(){}})});
 const outputs=[];for(const kind of ['Solution','Hint']){for(const enabled of [false,true]){const result=await repo['setMaster'+kind+'Visibility'](state.workshop_key,enabled,1);outputs.push({kind,enabled,objective:result.exercise.objectives[id],state:{...state}});}}
 return outputs;
}
test('actual repository master off/on restores both independent candidate help gates',async()=>{const outputs=await cascade(load(file,stage(source)));for(const x of outputs){assert.equal(x.objective[x.kind==='Hint'?'hintVisible':'solutionVisible'],x.enabled);assert.equal(x.objective[x.kind==='Hint'?'solutionVisible':'hintVisible'],true);}});
test('retained predicate-only staging reproduces missing master re-enable despite individual eligibility',async()=>{const broken=load(file,pendingSource.replace('return QUALIFIED_OBJECTIVE_SET.has(objectiveId);',"return objectiveId === 'ss_mail_reply_redirect' || QUALIFIED_OBJECTIVE_SET.has(objectiveId);"));assert.equal(broken.isQualifiedObjective(id),true);const outputs=await cascade(broken);assert.equal(outputs[1].objective.solutionVisible,false);assert.equal(outputs[3].objective.hintVisible,false);});
