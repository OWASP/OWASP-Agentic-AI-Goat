'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),{execFileSync}=require('node:child_process');
function qualify(scenario){
 const script=`
 const assert=require('node:assert/strict'),Module=require('node:module'),original=Module._load;let enabled=true;const audits=[];
 Module._load=function(name,...args){if(name==='../services/postgresIdentityAdapter')return {getPostgresIdentityAdapter:()=>({repository:{getConfig:async()=>String(enabled),recordAudit:async e=>audits.push(e)}})};if(/authDb|sqlite/.test(name))throw Error('Unexpected legacy store');return original.call(this,name,...args);};
 process.env.PLATFORM_DATABASE_ENGINE='postgres';const limiter=require('./server/middleware/rateLimiter');const express=require('express'),app=express();app.use(express.json());app.set('trust proxy',1);
 let held=[],entered=0;app.post(['/login','/secure-login'],limiter.loginRateLimiter,(req,res)=>{entered++;if(req.body.hold)held.push(res);else res.status(req.body.status||200).json({ok:true});});
 (async()=>{await limiter.refreshRateLimitConfig();const server=await new Promise(r=>{const s=app.listen(0,'127.0.0.1',()=>r(s));});const base='http://127.0.0.1:'+server.address().port;const send=(username,extra={},ip='198.51.100.11',route='/login')=>fetch(base+route,{method:'POST',headers:{'content-type':'application/json','x-forwarded-for':ip},body:JSON.stringify({username,...extra})});
 try{${scenario}}finally{for(const res of held)if(!res.writableEnded)res.end();server.closeAllConnections();await new Promise(r=>server.close(r));}})().catch(e=>{console.error(e);process.exitCode=1;});`;
 assert.doesNotThrow(()=>execFileSync(process.execPath,['-e',script],{cwd:require('node:path').join(__dirname,'..'),timeout:30000,stdio:'pipe'}));
}
test('enabled shared IP admits 200 distinct concurrent successful learners; repeated successful account slots release',()=>qualify(`
 const responses=await Promise.all(Array.from({length:200},(_,i)=>send('student'+i)));assert.ok(responses.every(r=>r.status===200));
 for(let i=0;i<30;i++)assert.equal((await send('repeat')).status,200);assert.equal(audits.length,0);
`));
test('failed account budget shares login aliases, preserves exact account names and generic audit',()=>qualify(`
 for(let i=0;i<20;i++)assert.equal((await send('Student',{status:401})).status,401);
 const denied=await send('Student',{},undefined,'/secure-login');assert.equal(denied.status,429);assert.equal(denied.headers.get('ratelimit-limit'),'20');
 assert.equal((await send('student')).status,200);assert.equal((await send(' Student')).status,200);await new Promise(setImmediate);
 assert.equal(audits[0].details.limit,20);assert.equal(JSON.stringify(audits).includes('Student'),false);
`));
test('in-flight reservations deny concurrent same-account overflow before handlers run',()=>qualify(`
 const pending=Array.from({length:20},()=>send('held',{hold:true}));for(let i=0;i<200&&held.length<20;i++)await new Promise(r=>setTimeout(r,5));assert.equal(held.length,20);
 assert.equal((await send('held')).status,429);assert.equal(entered,20);held.forEach(r=>r.json({ok:true}));assert.ok((await Promise.all(pending)).every(r=>r.status===200));await new Promise(setImmediate);assert.equal((await send('held')).status,200);
`));
test('aggregate 1000 budget limits distinct-account spraying and disabled toggle bypasses both layers',()=>qualify(`
 for(let batch=0;batch<10;batch++){const responses=await Promise.all(Array.from({length:100},(_,i)=>send('spray'+batch+'-'+i,{status:401})));assert.ok(responses.every(r=>r.status===401));}
 const denied=await send('new');assert.equal(denied.status,429);assert.equal(denied.headers.get('ratelimit-limit'),'1000');await new Promise(setImmediate);assert.equal(audits[0].details.limit,1000);
 enabled=false;await limiter.refreshRateLimitConfig();assert.equal((await send('new')).status,200);
`));
test('malformed usernames share bounded anonymous bucket and IPv6 subnet rotation does not evade account limit',()=>qualify(`
 for(let i=0;i<20;i++)assert.equal((await send(i%2?{}:undefined,{status:400})).status,400);assert.equal((await send('x'.repeat(51),{status:400})).status,429);
 for(let i=0;i<20;i++)assert.equal((await send('v6',{status:401},'2001:db8:1234:5600::'+(i+1).toString(16))).status,401);
 assert.equal((await send('v6',{},'2001:db8:1234:56ff::ffff')).status,429);assert.equal((await send('v6',{},'2001:db8:1234:5700::1')).status,200);
`));
