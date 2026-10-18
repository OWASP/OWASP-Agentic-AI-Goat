'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {createSecureShopBoundReviewRepository}=require('../server/database/postgres/secureshopBoundReviewRepository');
const scope={targetId:'30000000-0000-4000-8000-000000000061',launchId:'10000000-0000-4000-8000-000000000061',scenarioId:'20000000-0000-4000-8000-000000000061',generation:1,platformOwnerId:1,platformSessionId:1};
for(const operation of ['provision','submit'])test(`${operation} deadline precedes review locks and rolls back failure`,async()=>{
 const calls=[];let connects=0,released=0;
 const pool={query:async()=>{},async connect(){connects++;return{async query(sql,args){calls.push([sql,args]);if(/INSERT INTO|FROM secureshop_review.review_targets/.test(sql))throw Object.assign(Error('controlled lock failure'),{code:'55P03'});return{rows:[]};},release(){released++;}};}};
 const repository=createSecureShopBoundReviewRepository(pool,{checkCurrent:async()=>{},checkRetirement:async()=>{},checkCleanup:async()=>{},enableLearnerSubmissions:true});
 const invoke=deadline=>operation==='provision'?repository.provision(scope,{effectTimeoutMs:deadline}):repository.submitReview(scope,{id:1,role:'customer'},{submissionId:'40000000-0000-4000-8000-000000000061',productId:7,authorId:999,body:'<script>owned()</script>',rating:1},{effectTimeoutMs:deadline});
 await assert.rejects(invoke(0),{code:'INVALID_ARGUMENT'});assert.equal(connects,0);
 await assert.rejects(invoke(3000),{code:'55P03'});
 const configured=calls.findIndex(([sql])=>sql.includes('set_config'));const mutation=calls.findIndex(([sql])=>/INSERT INTO|FROM secureshop_review.review_targets/.test(sql));
 assert.ok(configured>=0&&configured<mutation);assert.deepEqual(calls[configured][1],['3000']);assert.ok(calls.some(([sql])=>sql==='ROLLBACK'));assert.equal(released,1);
 calls.length=0;await assert.rejects(invoke(undefined),{code:'55P03'});assert.equal(calls.some(([sql])=>sql.includes('set_config')),false);
});
