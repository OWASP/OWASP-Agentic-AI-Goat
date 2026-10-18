'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {QUALIFIED_OBJECTIVE_IDS,WORKSHOP_KEY}=require('../server/config/secureshopCurriculum');
const {assertCanonicalSecureShopChallenge:check,pendingSecureShopCoverage,openRenderedSecureShopSession}=require('./fixtures/renderedSecureShopSession');
const body=()=>({success:true,challenges:[{id:WORKSHOP_KEY,workshopKey:WORKSHOP_KEY,
 challengeKey:WORKSHOP_KEY,objectiveCount:QUALIFIED_OBJECTIVE_IDS.length,totalObjectives:QUALIFIED_OBJECTIVE_IDS.length,
 objectives:QUALIFIED_OBJECTIVE_IDS.map(id=>({id,label:id,text:id,completed:false}))}]});
test('entry catalog requires all exact qualified canonical IDs, with no duplicate or partial coverage',()=>{
 assert.equal(check(body()).totalObjectives,QUALIFIED_OBJECTIVE_IDS.length);
 for(const mutate of [b=>b.challenges[0].objectives.pop(),b=>b.challenges[0].objectives[0].id='fabricated',b=>b.challenges[0].objectives[0].id=b.challenges[0].objectives[1].id,b=>b.challenges.push(b.challenges[0]),b=>b.challenges[0].totalObjectives=9]){const value=body();mutate(value);assert.throws(()=>check(value));}
});
test('rendered entry report leaves every objective pending and cannot claim qualification',()=>{
 const value=pendingSecureShopCoverage();assert.equal(value.qualified,false);assert.equal(value.objectives.length,QUALIFIED_OBJECTIVE_IDS.length);assert.ok(value.objectives.every(row=>row.status==='pending'));
});
test('failed real-browser entry closes its own context without injecting tokens',async()=>{
 let closed=0;const page={setDefaultTimeout(){},async setRequestInterception(){},on(){},async goto(){throw Error('controlled navigation failure');}};
 const browser={async createBrowserContext(){return{async newPage(){return page;},async close(){closed++;}};}};
 await assert.rejects(openRenderedSecureShopSession({browser,origin:'http://127.0.0.1:35001',user:{id:1,username:'owned'},password:'controlled',verifySession:async()=>{}}),/navigation failure/);assert.equal(closed,1);
});
