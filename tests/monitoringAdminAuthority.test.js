'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm'),path=require('node:path');
const {createIdentityRepository}=require('../server/database/postgres/identityRepository');
const {hasAdminLevel}=require('../server/middleware/postgresAdminAuth');
const routeFile=path.resolve(__dirname,'../server/routes/monitoring.js');
function fixture(user,{present=true}={}){
 const effects={config:0,logs:0,lookups:0};
 const repository=createIdentityRepository({query:async(sql,params)=>{
  effects.lookups++;assert.match(sql,/u\.id=\$1|id=\$1/);assert.match(sql,/is_active=1/);assert.match(sql,/account_locked_until/);assert.match(sql,/s\.user_id=u\.id/);assert.deepEqual(Array.from(params).slice(0,1),[7]);
  return {rows:present&&user?.is_active===1?[{user,session:{user_id:7}}]:[]};
 }});
 const m={exports:{}};
 const req=request=>{
  if(request==='express')return require('express');
  if(request==='jsonwebtoken')return {verify:()=>({userId:7})};
  if(request==='../middleware/postgresAdminAuth')return {hasAdminLevel};
  if(request==='../middleware/performanceMonitor')return {getSystemStats:()=>({memoryUsage:{percentage:1},activeConnections:0})};
  if(request==='../services/ollamaService')return {updateConcurrencyLimits(){effects.config++;},getStats:()=>({}),healthCheck:async()=>({status:'healthy'})};
  if(request==='../services/postgresIdentityAdapter')return {getPostgresIdentityAdapter:()=>({repository})};
  if(request==='../views/monitoringHealthPage')return ()=>'<h1>Health</h1>';
  if(request==='fs')return {existsSync:()=>false,readFileSync(){effects.logs++;return '';}};
  if(['path','util'].includes(request))return require(request);
  throw Error('Unexpected dependency '+request);
 };
 vm.runInNewContext(fs.readFileSync(routeFile,'utf8'),{module:m,exports:m.exports,require:req,process:{env:{PLATFORM_DATABASE_ENGINE:'postgres',JWT_SECRET:'controlled'}},console,__dirname:path.dirname(routeFile)});
 async function invoke(url,{auth=true,body={maxConcurrent:2}}={}){
  const route=m.exports.stack.find(x=>x.route?.path===url).route;
  return new Promise((resolve,reject)=>{let status=200,index=0;const request={headers:auth?{authorization:'Bearer controlled'}:{},body,query:{}},response={status(n){status=n;return this;},json(result){resolve({status,result});},send(result){resolve({status,result});},setHeader(){},type(){return this;}};const next=error=>{if(error)return reject(error);const layer=route.stack[index++];if(!layer)return reject(Error('No response'));Promise.resolve(layer.handle(request,response,next)).catch(reject);};next();});
 }
 return {invoke,effects};
}
for(const role of ['student','admin','super_admin'])for(const admin_level of [0,1,2])test(`mounted monitoring respects canonical ${role}/${admin_level}`,async()=>{
 // Expected policy is independent of the production predicate under test.
 const user={id:7,role,admin_level,is_active:1},f=fixture(user),allowed=role!=='student'&&admin_level>0;
 const r=await f.invoke('/ollama/config');assert.equal(r.status,allowed?200:403);assert.equal(f.effects.config,allowed?1:0);
 if(!allowed){for(const url of ['/logs/recent','/llm/recent','/stress-test'])assert.equal((await f.invoke(url)).status,403);assert.equal(f.effects.logs,0);assert.equal(f.effects.config,0);}
});
for(const state of ['inactive','missing-session','missing-bearer'])test(`monitoring ${state} denied before operational effects`,async()=>{
 const f=fixture({id:7,role:'super_admin',admin_level:2,is_active:state==='inactive'?0:1},{present:state!=='missing-session'});
 for(const url of ['/ollama/config','/logs/recent','/llm/recent','/stress-test'])assert.equal((await f.invoke(url,{auth:state!=='missing-bearer'})).status,403);
 assert.equal(f.effects.logs,0);assert.equal(f.effects.config,0);if(state==='missing-bearer')assert.equal(f.effects.lookups,0);
});
