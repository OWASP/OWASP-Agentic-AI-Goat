'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {RagVectorStore}=require('../server/services/ragVectorStore');
const {createCsrfRagResources}=require('../server/services/csrfRagResources');
function fixture(){const root=new RagVectorStore();let calls=0;root.embedText=async()=>{calls++;return new Float32Array([1,0]);};const csrf=root.forFamily('CSRF');const resources=createCsrfRagResources({store:csrf,cleanText:'Canonical clean banking knowledge base with enough text to form a chunk.'});return{root,csrf,resources,calls:()=>calls};}
test('same owner/session and sibling documents stay separate by family while inference is shared',async()=>{
 const {root,csrf,calls}=fixture();for(const store of[root,csrf])for(const owner of['1','2'])await store.storeDocument(owner,'same',Buffer.from('A sufficiently long document that retains its own exact family content.'));
 root.setCurrentSession('1','same','ipi.txt',1);csrf.setCurrentSession('1','same','csrf.txt',1);
 assert.equal(calls(),4);assert.equal(root.clearUserSessions('1'),1);assert.equal(root.getSessionInfo('1','same').exists,false);assert.equal(csrf.getSessionInfo('1','same').exists,true);
 assert.equal(csrf.getCurrentSession('1').filename,'csrf.txt');assert.equal(root.getSessionInfo('2','same').exists,true);assert.equal(csrf.getSessionInfo('2','same').exists,true);
 csrf.clearUserSessions('1');assert.equal(csrf.getSessionInfo('2','same').exists,true);assert.throws(()=>root.forFamily('unknown'));
});
test('hydrated flags cannot replace corpus; canonical clean reseeds but retained poison stays unavailable',async()=>{
 const {resources,csrf}=fixture();const tab={ragCleanSessionId:'clean-old',ragCleanSeeded:true,ragSessionId:'poison-old',ragPoisoned:true,ragDocText:'owned malicious source',ragFiredQuestions:['prior']};
 await resources.ensureClean('1',tab);assert.equal(csrf.getSessionInfo('1','clean-old').exists,true);
 assert.deepEqual(resources.state('1',tab),{cleanReady:true,poisonRecorded:true,poisonReady:false,available:false});
 assert.throws(()=>resources.assertPoisonAvailable('1',tab),{code:'CSRF_RAG_RESOURCE_UNAVAILABLE',statusCode:503});
 assert.equal(tab.ragDocText,'owned malicious source');assert.equal(tab.ragPoisoned,true);assert.deepEqual(tab.ragFiredQuestions,['prior']);assert.equal(csrf.getSessionInfo('1','poison-old').exists,false);
});
test('clean embedding failure fails closed without claiming seed success',async()=>{
 const {root,resources}=fixture();root.embedder=null;const scoped=root.forFamily('CSRF');scoped.storeDocument=async()=>{throw Error('model unavailable');};
 const tab={ragCleanSeeded:true};await assert.rejects(resources.ensureClean('1',tab),{code:'CSRF_RAG_RESOURCE_UNAVAILABLE'});assert.equal(tab.ragCleanSeeded,false);
});
test('explicit poison reset clears only poison and never hides failed removal',async()=>{
 const {resources,csrf,root}=fixture();const text=Buffer.from('Owned poison document contains enough text for the controlled chunk.');
 await csrf.storeDocument('1','poison',text);await csrf.storeDocument('2','poison',text);await root.storeDocument('1','poison',text);
 const tab={ragSessionId:'poison',ragPoisoned:true,ragDocText:'original',ragFiredQuestions:['q']};
 await resources.resetPoison('1',tab);assert.equal(tab.ragDocText,null);assert.equal(root.getSessionInfo('1','poison').exists,true);assert.equal(csrf.getSessionInfo('2','poison').exists,true);
 const saved={ragSessionId:'lost',ragPoisoned:true,ragDocText:'retain'};csrf.deleteSession=()=>{throw Error('cleanup failed');};await assert.rejects(resources.resetPoison('1',saved),/cleanup failed/);assert.equal(saved.ragDocText,'retain');assert.equal(saved.ragPoisoned,true);
});
test('graph retrieval failure propagates before model or Judge',async()=>{
 const {runCsrfRagGraph}=require('../server/agent-runtime/csrfRagGraph');let modelCalls=0;
 await assert.rejects(runCsrfRagGraph({userKey:'1',userId:1,t:{},message:'question',lower:'question',sandbox:{}},{ensureCleanKb:async()=> 'clean',ragVectorStore:{similaritySearch:async()=>{throw Error('missing persisted corpus');}},summarizeWithHtml:async()=>{modelCalls++;},execution:{check:async()=>{}}}),/missing persisted corpus/);assert.equal(modelCalls,0);
});

test('missing retained poison is repairable only by explicit replacement or reset, without grading',async()=>{
 const {resources,csrf}=fixture();const tab={ragSessionId:'lost',ragPoisoned:true,ragDocText:'retained original',ragFiredQuestions:['historic']};
 await resources.ensureClean('1',tab);assert.throws(()=>resources.assertPoisonAvailable('1',tab),{code:'CSRF_RAG_RESOURCE_UNAVAILABLE'});
 // Model the explicit upload publication after successful ingestion, never GET hydration.
 const replacement='Explicit owner replacement source with sufficient length to produce a chunk.';
 await csrf.storeDocument('1','replacement',Buffer.from(replacement));
 Object.assign(tab,{ragSessionId:'replacement',ragPoisoned:true,ragDocText:replacement});
 assert.doesNotThrow(()=>resources.assertPoisonAvailable('1',tab));assert.deepEqual(tab.ragFiredQuestions,['historic']);
 csrf.clearUserSessions('1');await resources.resetPoison('1',tab);await resources.ensureClean('1',tab);
 assert.equal(resources.state('1',tab).available,true);assert.equal(tab.ragDocText,null);
});
