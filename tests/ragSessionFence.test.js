'use strict';
const test=require('node:test');const assert=require('node:assert/strict');const fs=require('node:fs');const path=require('node:path');const Module=require('node:module');
const root=path.resolve(__dirname,'..');
const {RagVectorStore}=require(path.join(root,'server/services/ragVectorStore'));
const {createRunCoordinator}=require('../server/agent-runtime/runCoordinator');
const route=fs.readFileSync(path.join(root,'server/routes/ragInjection.js'),'utf8');
function deferred(){let resolve;const promise=new Promise(r=>{resolve=r});return{promise,resolve};}
function chunk(text='stored'){return[{text,embedding:new Float32Array([1,0]),chunkIndex:0}];}
function seed(store,owner,id,text=id){const key=store._userSessionKey(owner,id);store.sessions.set(key,chunk(text));store.sessionMetadata.set(key,{filename:id+'.txt'});}
const originalLoad=Module._load;
Module._load=function(request,parent,isMain){if(request==='./indirectObjectiveJudge')return{beginIpiEvaluation:async()=>async()=>{throw Error('Judge must not run in cancellation test')}};return originalLoad.call(this,request,parent,isMain);};
const {runRagIngestGraph}=require(path.join(root,'server/agent-runtime/ragIngestGraph'));
const {runRagQueryGraph}=require(path.join(root,'server/agent-runtime/ragQueryGraph'));

test('baseline direct delete can remove a session while an already-started embedding search still returns its chunks',async()=>{
 const entered=deferred(),release=deferred();const store=new RagVectorStore();store.embedder=async()=>{entered.resolve();await release.promise;return{data:new Float32Array([1,0])}};seed(store,'owner-a','target','stale target');
 const search=store.similaritySearch('owner-a','target','question',1);await entered.promise;
 assert.equal(store.deleteSession('owner-a','target'),true);release.resolve();
 assert.deepEqual((await search).map(x=>x.text),['stale target']);assert.equal(store.getSessionInfo('owner-a','target').exists,false);
});

test('fenced delete cancels an older query before model, Judge, or credit and preserves sibling owner state',async()=>{
 const entered=deferred(),release=deferred();const runs=createRunCoordinator({family:'RAG-fence-query',ledger:null});
 const sessions=new Map([['owner-a::target',chunk('target')],['owner-a::sibling',chunk('same owner')],['owner-b::target',chunk('other owner')]]);let modelCalls=0,judgeCalls=0,creditCalls=0;
 const query=runs.run('owner-a',{},execution=>runRagQueryGraph({userKey:'owner-a',sessionId:'target',question:'question',active_objective:'rag_query',sessionFilename:'target.txt'},
  {ragVectorStore:{similaritySearch:async()=>{entered.resolve();await release.promise;return sessions.get('owner-a::target')}},aiService:{chatWithMessages:async()=>{modelCalls++;return{response:'unexpected'}}},getRagSystemPrompt:()=>'',judgeInjectionDetection:async()=>false,detectInjectionSuccess:()=>false,detectBypassSuccess:()=>false,buildOffTopicBypassAnswer:()=>'',markRagObjectiveComplete:async()=>{creditCalls++},execution,objectiveJudge:async()=>{judgeCalls++;return{verdict:'pass'}}}));
 await entered.promise;const deletion=runs.reset('owner-a',async()=>{sessions.delete('owner-a::target')});release.resolve();
 await assert.rejects(query,{name:'AbortError'});await deletion;
 assert.equal(modelCalls,0);assert.equal(judgeCalls,0);assert.equal(creditCalls,0);assert.equal(sessions.has('owner-a::target'),false);assert.equal(sessions.has('owner-a::sibling'),true);assert.equal(sessions.has('owner-b::target'),true);
});

test('delete-old during upload compensates only the cancelled new session and preserves stored siblings',async()=>{
 const entered=deferred(),release=deferred();const runs=createRunCoordinator({family:'RAG-fence-upload',ledger:null});const store=new RagVectorStore();
 store.embedder=async()=>{entered.resolve();await release.promise;return{data:new Float32Array([1,0])}};seed(store,'owner-a','old');seed(store,'owner-a','sibling');seed(store,'owner-b','other');
 const upload=runs.run('owner-a',{},execution=>runRagIngestGraph({userKey:'owner-a',sessionId:'new-upload',buffer:Buffer.from('New document content long enough to form a chunk.'),filename:'new.txt',displayFilename:'new.txt'},
  {ragVectorStore:store,markRagObjectiveComplete:async()=>{throw Error('credit must not run')},execution}));
 await entered.promise;const deletion=runs.reset('owner-a',async()=>store.deleteSession('owner-a','old'));release.resolve();
 await assert.rejects(upload,{name:'AbortError'});await deletion;
 assert.equal(store.getSessionInfo('owner-a','old').exists,false);assert.equal(store.getSessionInfo('owner-a','new-upload').exists,false);assert.equal(store.getSessionInfo('owner-a','sibling').exists,true);assert.equal(store.getSessionInfo('owner-b','other').exists,true);
});

test('progress reset drains a blocked upload, clears every target-owner session, and preserves another owner',async()=>{
 const entered=deferred(),release=deferred();const runs=createRunCoordinator({family:'RAG-progress-reset',ledger:null});const store=new RagVectorStore();
 store.embedder=async()=>{entered.resolve();await release.promise;return{data:new Float32Array([1,0])}};seed(store,'owner-a','older-one');seed(store,'owner-a','older-two');seed(store,'owner-b','other');
 const upload=runs.run('owner-a',{},execution=>runRagIngestGraph({userKey:'owner-a',sessionId:'new-upload',buffer:Buffer.from('New document content long enough to form a chunk.'),filename:'new.txt',displayFilename:'new.txt'},
  {ragVectorStore:store,markRagObjectiveComplete:async()=>{throw Error('credit must not run')},execution}));
 await entered.promise;const reset=runs.reset('owner-a',async()=>store.clearUserSessions('owner-a'));release.resolve();
 await assert.rejects(upload,{name:'AbortError'});await reset;
 assert.equal(store.getActiveSessionsCount('owner-a'),0);assert.equal(store.getSessionInfo('owner-b','other').exists,true);
});

test('abort compensation preserves the original exception and marks cleanup uncertainty',async()=>{
 const original=Object.assign(new Error('reset invalidated upload'),{name:'AbortError'});let checks=0;
 const store={storeDocument:async()=>({chunksStored:1}),setCurrentSession:async()=>{},deleteSession:async()=>{throw Error('cleanup storage unavailable')}};
 await assert.rejects(runRagIngestGraph({userKey:'owner-a',sessionId:'new-upload',buffer:Buffer.from('document'),filename:'x.txt',displayFilename:'x.txt'},
  {ragVectorStore:store,markRagObjectiveComplete:async()=>{},execution:{check:async()=>{if(++checks===2)throw original}}}),error=>error===original&&error.cleanupUncertain===true&&/cleanup storage unavailable/.test(error.cleanupError.message));
});

test('session DELETE validates existence before taking the owner reset fence and reports uncertain reset as 503',()=>{
 assert.match(route,/router\.delete\('\/session\/:sessionId', authenticateToken, async/);
 const existence=route.indexOf('if (!ragVectorStore.getSessionInfo(userKey, sessionId).exists)');const fence=route.indexOf('await ragRuns.reset(userKey',existence);
 assert.ok(existence>0&&fence>existence);assert.match(route,/Session deletion incomplete; retry to reconcile state/);
 assert.match(route,/err\.cleanupUncertain === true \? \{ cleanup_uncertain: true \}/);
});
