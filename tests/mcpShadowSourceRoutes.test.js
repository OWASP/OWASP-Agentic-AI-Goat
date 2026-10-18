'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),express=require('express'),{randomUUID,createHash}=require('node:crypto');
const {createMcpShadowSourceRouter,validate}=require('../server/routes/mcpShadowSourceRoutes');
const sha=text=>createHash('sha256').update(text).digest('hex');
test('source requests accept only exact owned edit shape and bounded lossless UTF8',()=>{
 const value={text:'Synthetic policy',operationId:randomUUID(),expectedSha256:sha('old')};
 assert.equal(validate(value,true),true);assert.equal(validate({},false),true);
 for(const bad of [{...value,path:'approved.txt'},{...value,ownerId:2},{...value,text:'é'.repeat(8193)},
  {...value,text:'\ud800'},{...value,operationId:[value.operationId]},{...value,expectedSha256:[value.expectedSha256]}])assert.equal(validate(bad,true),false);
});
test('mounted source editor preserves owner scope, denies hidden exercise and projects no private receipt or credit',async()=>{
 const calls=[];let visible=true;const values=new Map();
 const app=express();app.use(express.json());
 app.use(createMcpShadowSourceRouter({
  coordinator:{run:async(owner,_options,work)=>{calls.push(['owner',owner]);return work({check:async()=>{},effect:async(_key,fn)=>fn()});}},
  requireUser:(req,res,next)=>{if(!req.headers.authorization)return res.status(401).json({error:'Sign in'});req.user={id:7};next();},
  requireRuntime:(_req,_res,next)=>next(),ownerId:req=>String(req.user.id),visible:async()=>visible,
  getResources:async(req)=>{calls.push(['admit',req.user.id]);return{
   readShadowSource:async()=>({text:values.get(req.user.id)||'Initial policy',sha256:sha(values.get(req.user.id)||'Initial policy')}),
   writeShadowSource:async body=>{if(body.expectedSha256!==sha(values.get(req.user.id)||'Initial policy'))throw Object.assign(Error('conflict'),{code:'SHADOW_SOURCE_CONFLICT'});values.set(req.user.id,body.text);return{...body,sha256:sha(body.text),binding:{targetId:'private'},capability:'private'};},
  };},
 }));
 const server=app.listen(0,'127.0.0.1');await new Promise(resolve=>server.once('listening',resolve));
 const request=async(path,body,auth=true)=>{const r=await fetch(`http://127.0.0.1:${server.address().port}${path}`,{method:'POST',headers:{'content-type':'application/json',...(auth?{authorization:'controlled-auth'}:{})},body:JSON.stringify(body)});return{status:r.status,body:await r.json()};};
 try{
  assert.equal((await request('/read',{},false)).status,401);assert.equal(calls.length,0);
  const initial=await request('/read',{});assert.equal(initial.status,200);
  const body={text:'Learner policy <script>kept as source text</script> ✓',operationId:randomUUID(),expectedSha256:initial.body.sha256};
  const written=await request('/write',body);assert.equal(written.status,200);assert.deepEqual(Object.keys(written.body).sort(),['operationId','sha256','success']);
  assert.equal((await request('/read',{})).body.text,body.text);
  assert.equal((await request('/write',{...body,text:'stale'})).status,409);
  const admissions=calls.filter(c=>c[0]==='admit').length;
  assert.equal((await request('/write',{...body,ownerId:8})).status,400);
  visible=false;assert.equal((await request('/read',{})).status,403);
  assert.equal(calls.filter(c=>c[0]==='admit').length,admissions);
  assert.ok(calls.filter(c=>c[0]==='owner').every(c=>c[1]==='7'));
 }finally{await new Promise(resolve=>server.close(resolve));}
});
