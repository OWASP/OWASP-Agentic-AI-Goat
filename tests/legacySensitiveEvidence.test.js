'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict'),path=require('node:path');
const {fileBoundary}=require('../server/agent-runtime/legacySensitiveEvidence');
const {FILE_FLAGS,SSI_FLAG,findChallengeFlag}=require('../server/config/legacySensitiveFlags');
test('Protection proof follows resolved boundary, not words or shared path prefix',()=>{
 for(const file of ['config-guide.txt','admin-guide.txt','secret-examples.txt'])assert.equal(fileBoundary(`/fixture/public/${file}`,'/fixture/public',path.resolve).outsidePublic,false);
 assert.equal(fileBoundary('/fixture/public/../secret/file','/fixture/public',path.resolve).outsidePublic,true);
 assert.equal(fileBoundary('/fixture/public-copy/file','/fixture/public',path.resolve).outsidePublic,true);
 const symlinks=name=>name==='/fixture/public/link'?'/fixture/secret/target':path.resolve(name);
 assert.equal(fileBoundary('/fixture/public/link','/fixture/public',symlinks).outsidePublic,true);
 assert.equal(fileBoundary('/missing','/fixture/public',()=>{throw Error('missing');}).outsidePublic,false);
});
test('Only configured fixture flags qualify; tutorial markers and partial values do not',()=>{
 for(const flag of [...FILE_FLAGS,SSI_FLAG])assert.equal(findChallengeFlag(`Returned value: ${flag}`),flag);
 for(const text of ['FLAG: DEMO_EXAMPLE_NOT_A_CHALLENGE_FLAG','FLAG{DEMO_NOT_REAL}','FLAG: SENSITIVE_DATA_FLAG_1{WRONG}',FILE_FLAGS[0].slice(0,-1)])assert.equal(findChallengeFlag(text),null);
});
test('Production facts distinguish protected target and known flag from mere output/marker presence',()=>{
 const {observedFacts}=require('../server/agent-runtime/legacySensitiveEvidence');
 assert.deepEqual(observedFacts('path_traversal',{content:'FLAG: DEMO',boundary:{outsidePublic:false}}),{observed_effect:true,protected_path:false,known_flag:false,real_model:false});
 assert.equal(observedFacts('ai_assisted_ssi',{original:`${SSI_FLAG} <!--#echo var="REMOTE_ADDR" -->`,rendered:`${SSI_FLAG} 127.0.0.1`},{realModel:true}).known_flag,false,'Learner-supplied known flag is not a substituted disclosure');
 assert.equal(observedFacts('ai_assisted_ssi',{original:'<!--#echo var="SECRET_FLAG" -->',rendered:SSI_FLAG},{realModel:true}).known_flag,true);
});
test('Judge evidence exposes resolved symlink target and full output as separate citeable strings',()=>{
 const {evidenceFor}=require('../server/agent-runtime/legacySensitiveJudge');
 const result={path:'public/link',content:'Full output\n'+FILE_FLAGS[0],boundary:{resolvedTarget:'/fixture/secret/file',publicRoot:'/fixture/public',outsidePublic:true}};
 const evidence=evidenceFor('fixture',result);
 assert.equal(evidence.find(e=>e.id==='accessed_path').content,'/fixture/secret/file');
 assert.equal(evidence.find(e=>e.id==='returned_content').content,result.content);
 assert.deepEqual(evidence.find(e=>e.id==='tool_metadata').content,{path:result.path,boundary:result.boundary});
});
