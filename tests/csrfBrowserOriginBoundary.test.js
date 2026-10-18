'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const crypto = require('node:crypto');
const express = require('express');
const session = require('express-session');

// Browser-policy experiment, not qualification of the application's actor,
// route, database or Judge. All cookies, listeners and state belong to this test.
test('real browser distinguishes same-origin, same-site cross-origin and cross-site POST with explicit Lax cookies', {timeout:30000}, async t => {
  let browser;
  const servers=[];
  t.after(async()=>{
    try { await browser?.close(); }
    finally { await Promise.all(servers.map(server=>new Promise(resolve=>{
      server.closeAllConnections(); server.close(resolve);
    }))); }
  });
  const listen=async app=>{
    const server=http.createServer(app);servers.push(server);
    await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(0,'127.0.0.1',resolve);});
    return server.address().port;
  };
  const victim=express(),attacker=express();
  const observations=[],fetchObservations=[],preflights=[];let balance=100;
  victim.use((req,_res,next)=>{if(req.method==='OPTIONS')preflights.push(req.headers.origin);next();});
  victim.use(require('../server/middleware/applicationCors').createApplicationCors());
  victim.use(session({secret:crypto.randomBytes(32).toString('hex'),resave:false,saveUninitialized:false,
    cookie:{sameSite:'lax',secure:false,httpOnly:true}}));
  victim.use(express.urlencoded({extended:false,limit:'1kb'}));
  victim.use(express.json({limit:'1kb'}));
  victim.get('/login',(req,res)=>{req.session.owner=17;res.send('owned fixture session');});
  victim.post('/transfer',(req,res)=>{
    const authenticated=req.session.owner===17;
    observations.push({origin:req.get('origin'),site:req.get('sec-fetch-site'),authenticated});
    if(authenticated)balance-=1;
    res.status(authenticated?200:401).send(authenticated?'fixture transfer':'no session');
  });
  victim.post('/api/workshop/csrf/agent-action',(req,res)=>{
    const authenticated=req.session.owner===17;
    fetchObservations.push({origin:req.get('origin'),site:req.get('sec-fetch-site'),authenticated});
    if(authenticated)balance-=1;
    res.status(authenticated?200:401).json({fixtureEffect:authenticated});
  });
  const victimPort=await listen(victim),attackerPort=await listen(attacker);
  const victimOrigin=`http://127.0.0.1:${victimPort}`;
  const sameSiteOrigin=`http://127.0.0.1:${attackerPort}`;
  const crossSiteOrigin=`http://localhost:${attackerPort}`;
  const form=(_req,res)=>res.type('html').send(`<form action="${victimOrigin}/transfer" method="POST"><button id="submit">Send fixture request</button></form>`);
  victim.get('/form',form);attacker.get('/form',form);
  browser=await require('puppeteer').launch({headless:true});
  const page=await browser.newPage();
  const allowed=new Set([victimOrigin,sameSiteOrigin,crossSiteOrigin]);
  await page.setRequestInterception(true);
  page.on('request',request=>{
    let origin;try{origin=new URL(request.url()).origin;}catch{}
    return allowed.has(origin)?request.continue():request.abort();
  });
  await page.goto(`${victimOrigin}/login`);
  for(const origin of [victimOrigin,sameSiteOrigin,crossSiteOrigin]){
    await page.goto(`${origin}/form`);
    await Promise.all([page.waitForNavigation(),page.click('#submit')]);
  }
  assert.deepEqual(observations,[
    {origin:victimOrigin,site:'same-origin',authenticated:true},
    {origin:sameSiteOrigin,site:'same-site',authenticated:true},
    {origin:crossSiteOrigin,site:'cross-site',authenticated:false},
  ]);
  assert.equal(balance,98,'Only the two requests carrying the owned session mutate fixture state');
  for(const [origin,expectedStatus] of [[sameSiteOrigin,200],[crossSiteOrigin,401]]){
    await page.goto(`${origin}/form`);
    const result=await page.evaluate(async target=>{
      const response=await fetch(target,{method:'POST',credentials:'include',headers:{'Content-Type':'application/json'},body:JSON.stringify({fixture:true})});
      return {status:response.status,body:await response.json()};
    },`${victimOrigin}/api/workshop/csrf/agent-action`);
    assert.deepEqual(result,{status:expectedStatus,body:{fixtureEffect:expectedStatus===200}},'Actual challenge CORS permits reading the response');
  }
  assert.deepEqual(preflights,[sameSiteOrigin,crossSiteOrigin]);
  assert.deepEqual(fetchObservations,[
    {origin:sameSiteOrigin,site:'same-site',authenticated:true},
    {origin:crossSiteOrigin,site:'cross-site',authenticated:false},
  ]);
  assert.equal(balance,97);
  t.diagnostic(JSON.stringify({browser:await browser.version(),observations:observations.map(({site,authenticated})=>({site,authenticated})),jsonFetch:'preflight accepted and responses readable by actual challenge CORS; cross-site Lax cookie withheld',boundary:'owned HTTP/session fixture plus application CORS; no application actor/Judge qualification'}));
});
