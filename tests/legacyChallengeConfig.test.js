'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict'),Module=require('node:module');
test('classic challenge routes await isolated config and preserve raw reflected HTML without SQLite imports',async()=>{
 const original=Module._load;let enabled=false;const handlers={};
 const router={get:(p,f)=>handlers['GET '+p]=f,post:(p,f)=>handlers['POST '+p]=f,all:()=>{}};
 Module._load=function(request,parent,main){
  if(request==='express')return{Router:()=>router};
  if(request.endsWith('/legacyChallengeConfigStore'))return{getSolutionsEnabled:async()=>enabled,setSolutionsEnabled:async value=>{await Promise.resolve();enabled=value;}};
  if(request.endsWith('/multiProviderAIService'))return{};
  if(['sqlite3','better-sqlite3','mysql2/promise'].includes(request)||/\/authDb$/.test(request))throw Error('Working DB import forbidden');
  return original.call(this,request,parent,main);
 };
 const file=require.resolve('../server/routes/challenges');delete require.cache[file];
 const res=()=>({statusCode:200,status(code){this.statusCode=code;return this;},json(body){this.body=body;return this;}});
 try{
  require(file);let r=res();await handlers['GET /solutions/:challengeId']({params:{challengeId:'unknown'}},r);assert.equal(r.statusCode,403);
  r=res();await handlers['POST /solutions/toggle']({body:{enabled:true}},r);assert.equal(r.body.enabled,true);assert.equal(enabled,true);
  r=res();await handlers['GET /solutions/:challengeId']({params:{challengeId:'unknown'}},r);assert.equal(r.body.enabled,true);
  r=res();const raw='<img src=x onerror=alert(1)>';await handlers['POST /xss/process']({body:{message:raw,type:'direct'}},r);assert.ok(JSON.stringify(r.body).includes(raw));
 }finally{Module._load=original;delete require.cache[file];}
});
test('PostgreSQL config selection never imports a SQLite driver',()=>{
 const original=Module._load,prior=process.env.PLATFORM_DATABASE_ENGINE;process.env.PLATFORM_DATABASE_ENGINE='postgres';
 Module._load=function(request,parent,main){if(request==='./postgres/xssWorkshopDb')return{getSolutionsEnabled:()=>false,setSolutionsEnabled:()=>{}};if(request==='sqlite3')throw Error('SQLite forbidden');return original.call(this,request,parent,main);};
 const file=require.resolve('../server/database/legacyChallengeConfigStore');delete require.cache[file];
 try{assert.equal(require(file).getSolutionsEnabled(),false);}finally{Module._load=original;delete require.cache[file];if(prior===undefined)delete process.env.PLATFORM_DATABASE_ENGINE;else process.env.PLATFORM_DATABASE_ENGINE=prior;}
});
