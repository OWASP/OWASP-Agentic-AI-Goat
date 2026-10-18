'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),{randomUUID}=require('node:crypto');
const {createAnalyticsApplication}=require('../server/services/secureshopAnalyticsApplication');
function fixture(){const input={scope:{launchId:randomUUID(),scenarioId:randomUUID(),generation:1,platformOwnerId:1,platformSessionId:2},persona:{id:3,role:'merchant'},personaSession:{sessionId:randomUUID(),authorityVersion:'1'},signal:undefined};let queries=0,reads=0,charts=0,checks=0;
 const app=createAnalyticsApplication({foundation:{query:async()=>{queries++;return{ok:true,question:'original'};},recover:async x=>{reads++;return {status:'uncertain',requestId:x.requestId,question:'original'};}},requests:{history:async()=>({requests:[{requestId:randomUUID(),createdAt:'2026-09-20T01:01:01.000001Z'}],nextCursor:null})},ownedQuery:{topProducts:async()=>{charts++;return{rows:[]};}},launches:{assertCurrent:async()=>{checks++;}},personaAuthority:{capture:async x=>({binding:{...x.scope,personaId:x.personaId,role:x.role,sessionId:x.sessionId,authorityVersion:x.authorityVersion},assertRemoteAdmission:async()=>{checks++;}})}});
 return {app,input,counts:()=>({queries,reads,charts,checks})};}
test('descriptor keys the exact original persona credential without exposing it',async()=>{
 const f=fixture(),first=await f.app.describe(f.input);assert.equal(first.analytics.capability,'secureshop-owned-analytics.v1');assert.match(first.analytics.scopeKey,/^[a-f0-9]{64}$/);assert.ok(!JSON.stringify(first).includes(f.input.personaSession.sessionId));
 for(const change of [{personaSession:{...f.input.personaSession,sessionId:randomUUID()}},{personaSession:{...f.input.personaSession,authorityVersion:'2'}},{scope:{...f.input.scope,generation:2}}])assert.notEqual((await f.app.describe({...f.input,...change})).analytics.scopeKey,first.analytics.scopeKey);
 assert.equal(f.counts().queries,0);
});
test('history and fixed chart read never call model execution',async()=>{
 const f=fixture(),history=await f.app.history({...f.input,limit:20,cursor:null});assert.equal(history.entries[0].question,'original');assert.equal(history.entries[0].status,'uncertain');await f.app.topProducts({...f.input,limit:8});assert.equal(f.counts().queries,0);assert.equal(f.counts().reads,1);assert.equal(f.counts().charts,1);
});
