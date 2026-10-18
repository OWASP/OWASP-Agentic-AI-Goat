'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const path = require('node:path');

test('PostgreSQL DPI, RAG and rate-limit paths do not import SQLite', () => {
  const script = String.raw`
    const Module=require('node:module');
    const original=Module._load;
    const events=[];
    const progress={
      getWorkshopProgress:async()=>({objectives:[]}),syncObjectiveComplete:async()=>{},
      syncWorkshopStarted:async()=>{},resetWorkshopProgress:async()=>{},checkAndMarkWorkshopComplete:async()=>false
    };
    const config={getSnapshot:async()=>({exercises:{direct_prompt_injection:{isVisible:true,objectives:{interact:{isVisible:true}}}}})};
    const pool={query:async()=>({rows:[{activity_count:1}]})};
    Module._load=function(request,parent,main){
      if(/authDb|sqlite3|better-sqlite3/.test(request))throw Error('SQLite import forbidden: '+request);
      if(request.endsWith('/postgresPlatformStores')||request==='./postgresPlatformStores'||request==='../services/postgresPlatformStores')
        return {getPostgresPlatformStores:()=>({progress,config,pool})};
      if(request.endsWith('/postgresIdentityAdapter')||request==='../services/postgresIdentityAdapter')
        return {getPostgresIdentityAdapter:()=>({repository:{getConfig:async()=> 'true',recordAudit:async event=>events.push(event)}})};
      return original.call(this,request,parent,main);
    };
    process.env.PLATFORM_DATABASE_ENGINE='postgres';
    require('./server/routes/promptInjectionWorkshop');
    require('./server/routes/ragInjection');
    const limiter=require('./server/middleware/rateLimiter');
    (async()=>{
      await limiter.refreshRateLimitConfig();
      const express=require('express'),app=express();
      app.post('/login',limiter.loginRateLimiter,(_req,res)=>res.status(401).json({error:"Invalid credentials"}));
      const server=await new Promise(resolve=>{const value=app.listen(0,'127.0.0.1',()=>resolve(value));});
      try{
        let response;
        for(let attempt=0;attempt<21;attempt++)response=await fetch('http://127.0.0.1:'+server.address().port+'/login',{method:'POST'});
        if(response.status!==429)throw Error('Exceeded handler did not run');
        await new Promise(setImmediate);
        if(events.length!==1||events[0].details.url!=='/api/auth/login')throw Error('PostgreSQL audit not used by exceeded handler');
      }finally{await new Promise(resolve=>server.close(resolve));}
    })().catch(error=>{console.error(error);process.exitCode=1;});
  `;
  assert.doesNotThrow(() => execFileSync(process.execPath, ['-e', script], {
    cwd: path.join(__dirname, '..'),
    env: { ...process.env, PLATFORM_DATABASE_ENGINE: 'postgres' },
    stdio: 'pipe',
  }));
});
