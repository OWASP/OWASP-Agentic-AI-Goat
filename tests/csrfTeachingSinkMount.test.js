'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),express=require('express');
const {CSRF_TEACHING_SINK_PATH:PATH,createCsrfTeachingSinkMount}=require('../server/services/csrfTeachingSinkMount');
async function fixture({early=true}={}){
 const app=express(),calls=[];
 app.use(express.json());
 const get=[(req,_res,next)=>{calls.push('get-admission');assert.equal(req.headers.cookie,'teaching=owned');next();},(_req,res)=>{calls.push('get-effect');res.json({sink:'get'});}];
 const post=(_req,res)=>{calls.push('post-effect');res.json({sink:'post'});};
 if(early)app.use(createCsrfTeachingSinkMount({get,post}));
 const authenticateToken=(req,res,next)=>{calls.push('platform-gate');if(req.headers.authorization!=='Bearer canonical')return res.status(401).json({error:'Bearer required'});req.user={id:1,role:'student',adminLevel:0};next();};
 const umbrella=require('../server/routes/postgresWorkshop').createPostgresWorkshopRouter({
  stores:{pool:{query:async()=>assert.fail('Unexpected database query')},progress:{getVisibleUserProgress:async()=>[],recordHeartbeat:async()=>assert.fail('Unexpected heartbeat')}},
  authenticateToken,accountRepository:{},requirePermission:()=> (_req,res)=>res.status(403).end(),
 });
 app.use('/api/workshop',umbrella);
 app.use('/api/workshop',(req,res,next)=>{if(req.path.startsWith('/csrf/agent-action'))return next();res.json({platform:true});});
 if(!early)app.use(createCsrfTeachingSinkMount({get,post}));
 app.use((req,res)=>res.status(404).json({unhandled:true,method:req.method}));
 const server=await new Promise(resolve=>{const s=app.listen(0,'127.0.0.1',()=>resolve(s));});
 return{calls,request:(suffix='',method='GET',bearer=false)=>fetch(`http://127.0.0.1:${server.address().port}${suffix||PATH}`,{method,headers:{cookie:'teaching=owned',...(bearer?{authorization:'Bearer canonical'}:{})}}),close:()=>new Promise(resolve=>server.close(resolve))};
}
test('existing umbrella order intercepts cookie-only sink; narrow early mount admits only composed handlers',async()=>{
 const before=await fixture({early:false});try{assert.equal((await before.request()).status,401);assert.deepEqual(before.calls,['platform-gate']);}finally{await before.close();}
 const after=await fixture();try{const get=await after.request();assert.equal(get.status,200);assert.deepEqual(await get.json(),{sink:'get'});assert.equal((await after.request(PATH,'POST')).status,200);assert.deepEqual(after.calls,['get-admission','get-effect','post-effect']);}finally{await after.close();}
});
test('HEAD never inherits the mutating GET handler',async()=>{
 const f=await fixture();try{for(const bearer of [false,true]){const response=await f.request(PATH,'HEAD',bearer);assert.equal(response.status,405);assert.equal(response.headers.get('allow'),'GET, POST');assert.equal(await response.text(),'');}assert.deepEqual(f.calls,[]);}finally{await f.close();}
});
test('case and one trailing slash follow the existing default Express route conventions',async()=>{
 const f=await fixture();try{for(const path of [PATH+'/',PATH.toUpperCase(),PATH.toUpperCase()+'/?action=teaching',PATH+'?action=teaching'])assert.equal((await f.request(path)).status,200);assert.equal(f.calls.filter(c=>c==='get-effect').length,4);assert.ok(!f.calls.includes('platform-gate'));}finally{await f.close();}
});
test('other methods retain umbrella authentication, including automatic OPTIONS',async()=>{
 const f=await fixture();try{for(const method of ['PUT','PATCH','DELETE','OPTIONS']){assert.equal((await f.request(PATH,method)).status,401);assert.equal((await f.request(PATH,method,true)).status,404);}assert.ok(f.calls.every(c=>c==='platform-gate'));}finally{await f.close();}
});
test('subpaths, sibling routes and encoded suffixes never dispatch the teaching sink',async()=>{
 const f=await fixture();try{for(const path of [PATH+'/child',PATH+'//',PATH+'-other',PATH+'%2Fchild','/api/workshop/csrf/state','/api/workshop/csrf/reset','/api/workshop/csrf/rag','/api/workshop/csrf/mail','/api/workshop/progress','/api/workshop/instructor/students']){assert.equal((await f.request(path)).status,401);assert.ok([200,403,404].includes((await f.request(path,'GET',true)).status));}assert.ok(f.calls.every(c=>c==='platform-gate'));}finally{await f.close();}
});
test('handler dependencies are mandatory and snapshotted',()=>{
 for(const input of [undefined,{}, {get:()=>{},post:[]},{get:[null],post:()=>{}}])assert.throws(()=>createCsrfTeachingSinkMount(input),/Composed/);
 const get=[(_req,_res,next)=>next()],post=()=>{};const router=createCsrfTeachingSinkMount({get,post});get[0]=null;assert.ok(router);
});
