'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),Module=require('node:module');
const routePath=require.resolve('../server/routes/ctf');
const actualCoordinator=require('../server/agent-runtime/runCoordinator');
const helpers={},ai={},events=[];let judge,current={user:{id:701},session:{id:11,user_id:701}};
const originalLoad=Module._load;
function controlledLoad(request,parent,isMain){
 if(parent?.filename===routePath){
  if(request==='../agent-runtime/runCoordinator')return{createRunCoordinator:options=>actualCoordinator.createRunCoordinator({...options,ledger:null})};
  if(request==='../database/ctfDb')return{engine:'postgres',CTFHelpers:helpers};
  if(request==='../agent-runtime/ctfStageJudge')return{stageDigest:()=> 'fixture-digest',judgeCtfStage:args=>judge(args)};
  if(request==='../services/postgresIdentityAdapter')return{getPostgresIdentityAdapter:()=>({async validateSession(token){assert.equal(token,'canonical-token');return current;}})};
  if(request==='../services/multiProviderAIService')return ai;
  if(request==='../utils/contextLogger')return{error(){}};
 }
 if(request==='./multiProviderAIService')return ai;
 return originalLoad.call(this,request,parent,isMain);
}
Module._load=controlledLoad;let loaded;try{delete require.cache[routePath];loaded=require(routePath);}finally{Module._load=originalLoad;delete require.cache[routePath];}
const {router,leaderboardRefresh}=loaded;
leaderboardRefresh.requestRefresh=()=>events.push('refresh_requested');
helpers.getConfig=async()=> 'true';
async function invoke(path,method,params={},body={},user={id:701,role:'admin'}){
 const route=router.stack.find(x=>x.route?.path===path&&x.route.methods[method]);assert(route,path);
 const req={user,identitySession:{id:11},headers:{authorization:'Bearer canonical-token'},params,body,ip:'127.0.0.1',get:()=> 'controlled-agent'};
 let resolve,reject;const done=new Promise((a,b)=>{resolve=a;reject=b;});const res={statusCode:200,status(n){this.statusCode=n;return this;},json(value){this.body=value;resolve(this);return this;}};
 let i=0;const next=error=>{if(error)return reject(error);const layer=route.route.stack[i++];if(!layer)return reject(Error('Route did not respond'));try{Promise.resolve(layer.handle(req,res,next)).catch(reject);}catch(e){reject(e);}};
 Module._load=controlledLoad;try{next();return await done;}finally{Module._load=originalLoad;}
}
test('registration publishes invalidation after admitted participant mutation even if PG session write fails',async()=>{
 events.length=0;helpers.admitParticipant=async(owner,name,email)=>{assert.equal(owner,701);assert.equal(name,'Student');assert.equal(email,'student@example.test');events.push('participant_mutated');return{admitted:true,participantId:77};};
 helpers.createSession=async(participant,token)=>{assert.equal(participant,77);assert.match(token,/^[a-f0-9-]{36}$/);events.push('session_write');throw Error('Controlled unavailable');};
 const old=console.error;console.error=()=>{};try{const res=await invoke('/register','post',{}, {displayName:'Student'},{id:701,username:'student',email:'student@example.test'});assert.equal(res.statusCode,500);assert.deepEqual(events,['participant_mutated','refresh_requested','session_write']);}finally{console.error=old;}
});
test('attempt evidence is judged then passed to PostgreSQL atomic commit; failed commit cannot publish credit',async()=>{
 events.length=0;helpers.getConfig=async key=>key==='ctf_time_limit'?'-1':key==='ctf_show_technique_feedback'?'false':'true';helpers.findActiveParticipant=async owner=>{assert.equal(owner,701);return{id:11,user_id:701,started_at:'2026-10-06T00:00:00Z'};};helpers.isBanned=async()=>false;
 helpers.getActiveStage=async()=>({id:1,stage_number:1,stage_name:'Doorway',system_prompt:'Guard WIN_CODE',success_criteria:'WIN_CODE',defense_style:'[]',adaptive_mode:'none',feedback_mode:'reason',level_score:100});
 helpers.getProgress=async()=>({id:44,status:'in_progress',started_at:'2026-10-06T00:00:00Z',techniques_used:'[]'});
 helpers.incrementAttempts=async(...args)=>{assert.deepEqual(args,[11,1,false,44]);events.push('attempt_count_mutated');return 2;};
 judge=async args=>{assert.equal(args.processedResponse,'WIN_CODE');assert.equal(args.realModel,true);events.push('judged');return{verdict:'pass'};};
 helpers.commitAttempt=async args=>{assert.equal(args.judgment.verdict,'pass');assert.equal(args.studentResponse,'WIN_CODE');assert.equal(args.participant.user_id,701);assert.equal(args.guardianEvidence.provider,'ollama');assert.equal(args.guardianEvidence.rawResponseSha256,require('node:crypto').createHash('sha256').update('WIN_CODE').digest('hex'));events.push('atomic_commit');throw Error('Controlled rollback');};
 ai.generateResponse=async()=>({response:'WIN_CODE',provider:'ollama',model:'llama3.1:8b',mocked:false,fallback:false});
 const old=console.error;console.error=()=>{};try{const res=await invoke('/stage/:stageId/attempt','post',{stageId:'1'},{payload:'hello guardian',sessionToken:'challenge-session'});assert.equal(res.statusCode,500);assert.deepEqual(events,['attempt_count_mutated','refresh_requested','judged','atomic_commit']);assert.equal(res.body.success,undefined);}finally{console.error=old;}
});
test('direct admin route stack rejects ambiguous stage IDs before mutation',async()=>{
 events.length=0;helpers.getConfig=async()=> 'true';helpers.updateStage=async id=>{events.push(['update',id]);return true;};helpers.deleteStage=async id=>{events.push(['delete',id]);return true;};
 for(const method of['put','delete'])for(const id of['1junk','1.5','1e2','0','-1','2147483648'])assert.equal((await invoke('/admin/stages/:id',method,{id})).statusCode,400);
 assert.deepEqual(events,[]);for(const method of['put','delete'])assert.equal((await invoke('/admin/stages/:id',method,{id:'2'})).statusCode,200);
 assert.deepEqual(events,[['update',2],'refresh_requested',['delete',2],'refresh_requested']);
});
test('direct participant action stacks reject ambiguous IDs before lookup, ban or unban',async()=>{
 events.length=0;for(const name of['findParticipant','banUser','unbanUser'])helpers[name]=async id=>{events.push([name,id]);return null;};
 for(const action of['reset','remove','ban','unban'])for(const id of['1junk','1.5','1e2','0','-1','2147483648'])assert.equal((await invoke('/admin/participants/:userId/'+action,'post',{userId:id})).statusCode,400);
 assert.deepEqual(events,[]);for(const action of['ban','unban'])assert.equal((await invoke('/admin/participants/:userId/'+action,'post',{userId:'2'})).statusCode,200);
 assert.deepEqual(events,[['banUser',2],['unbanUser',2]]);
});
test('fractional hint indices reject before progress or scoring work',async()=>{
 for(const hintIndex of[0.5,1.5,NaN,Infinity,'1']){const res=await invoke('/stage/:stageId/hint','post',{stageId:'1'},{hintIndex});assert.equal(res.statusCode,400);assert.match(res.body.error,/hintIndex/);}
});
test('stage configuration rejects unrecognizable secrets before writes and retains valid partial updates',async()=>{
 events.length=0;helpers.createStage=async body=>{events.push(['create',body]);return 9;};helpers.updateStage=async(id,body)=>{events.push(['update',body]);return true;};
 for(const method of['post','put'])for(const secret of['',' \n ','---!_','🔐',null,{},42])assert.equal((await invoke(method==='post'?'/admin/stages':'/admin/stages/:id',method,{id:'9'},{success_criteria:secret})).statusCode,400);
 assert.equal((await invoke('/admin/stages','post')).statusCode,400);assert.deepEqual(events,[]);
 const secret=' 🔐 SECRET-42! ';assert.equal((await invoke('/admin/stages','post',{}, {success_criteria:secret})).statusCode,200);assert.equal((await invoke('/admin/stages/:id','put',{id:'9'},{stage_name:'Renamed stage'})).statusCode,200);
 assert.deepEqual(events,[['create',{success_criteria:secret}],'refresh_requested',['update',{stage_name:'Renamed stage'}],'refresh_requested']);
});
test('retired time bonus rejects before writes or leaderboard invalidation',async()=>{
 events.length=0;for(const method of['post','put'])for(const value of[0,300,null,'600']){const res=await invoke(method==='post'?'/admin/stages':'/admin/stages/:id',method,{id:'9'},{success_criteria:'CONTROLLED_SECRET',time_bonus_seconds:value});assert.equal(res.statusCode,400);assert.match(res.body.error,/legacy inactive/);}
 assert.deepEqual(events,[]);assert.equal((await invoke('/admin/stages/:id','put',{id:'9'},{stage_name:'Retained scoring'})).statusCode,200);assert.deepEqual(events,[['update',{stage_name:'Retained scoring'}],'refresh_requested']);
});
