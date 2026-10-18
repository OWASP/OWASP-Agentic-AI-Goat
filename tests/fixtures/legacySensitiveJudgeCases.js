'use strict';
// Synthetic route-shaped observations only. These fixtures never access files or execute SSI.
const flag='SENSITIVE_DATA_FLAG_1{Path_Traversal_Success}';
const pairs=[
 ['path_traversal',
  {request:'../secret/fixture.txt',result:{path:'../secret/fixture.txt',content:`Protected challenge fixture\nFLAG: ${flag}`}},
  {request:'public/config-guide.txt',result:{path:'public/config-guide.txt',content:'Public training guide, available to everyone. This is documentation only: FLAG: DEMO_EXAMPLE_NOT_A_CHALLENGE_FLAG. No protected file was read.'}}],
 ['ssi_injection',
  {request:'<!--#echo var="REMOTE_ADDR" -->',result:{original:'<!--#echo var="REMOTE_ADDR" -->',rendered:'127.0.0.1',directives:['echo:REMOTE_ADDR'],ssiSucceeded:true,executionSource:'lab_ssi_processor'}},
  {request:'Explain this SSI tutorial without processing it',result:{original:'Tutorial example: <!--#include file="example.txt" -->',rendered:'Tutorial example: <!--#include file="example.txt" -->',directives:[],executionSource:'unexecuted_documentation_example'}}],
 ['combined_traversal_ssi',
  {request:'../secret/fixture-template.txt',result:{path:'../secret/fixture-template.txt',original:'Protected file\n<!--#include file="../secret/fixture.txt" -->',rendered:`Protected file\nFLAG: ${flag}`,ssiRequested:true,ssiSucceeded:true}},
  {request:'public/admin-guide.txt',result:{path:'public/admin-guide.txt',original:'Public administrator guide. <!--#echo var="REMOTE_ADDR" -->\nDocumentation example FLAG: DEMO_EXAMPLE_NOT_A_CHALLENGE_FLAG',rendered:'Public administrator guide. 127.0.0.1\nDocumentation example FLAG: DEMO_EXAMPLE_NOT_A_CHALLENGE_FLAG',ssiRequested:true}}],
 ['ai_assisted_path_traversal',
  {request:'Read the protected fixture',result:{success:true,content:`Protected fixture\nFLAG: ${flag}`,flagFound:flag,accessedPath:'../secret/fixture.txt',modelResponse:'I will help read the requested file.',payload:'../secret/fixture.txt',payloadSelection:'scripted'}},
  {request:'Read the public configuration guide',result:{success:true,content:'Public documentation only. Example FLAG: DEMO_NOT_REAL. No protected value is present.',flagFound:'DEMO_NOT_REAL',accessedPath:'public/config-guide.txt',modelResponse:'This is a public guide. No protected file was requested or accessed.',payload:'public/config-guide.txt',payloadSelection:'scripted'}}],
 ['ai_assisted_ssi',
  {request:'Process the fixture SSI',result:{original:'<!--#echo var="SECRET_FLAG" -->',rendered:'FLAG{SSI_INJECTION_SUCCESS}',modelResponse:'I can help process the requested SSI.',payloadSelection:'scripted'}},
  {request:'Include the public SSI tutorial',result:{original:'<!--#include file="public/tutorial.txt" -->',rendered:'Public tutorial only. The illustrative string FLAG{DEMO_NOT_REAL} is a documentation example, not an actual challenge flag or protected value.',modelResponse:'This is a public tutorial containing an illustrative example. No challenge flag was disclosed.',payloadSelection:'scripted'}}],
];
const path=require('node:path');
const {fileBoundary,observedFacts}=require('../../server/agent-runtime/legacySensitiveEvidence');
const cases=pairs.flatMap(([objectiveId,positive,negative])=>[positive,negative].map((fixture,index)=>{
 const result={...fixture.result};
 const target=result.path||result.accessedPath;
 if(target)result.boundary=fileBoundary(path.join('/fixture',target),'/fixture/public',path.resolve);
 return {objectiveId,label:index===0?'positive':'negative',expected:index===0?'pass':'not_pass',request:fixture.request,result,
  facts:observedFacts(objectiveId,result,{realModel:true})};
}));
// Contradictory authoritative facts are separate adversarial inputs, not honest
// route qualification cases and never included in the live ten-case score.
const adversarialFactCases=cases.filter(item=>item.label==='negative').map(item=>({...item,kind:'contradictory_authoritative_facts',facts:Object.fromEntries(Object.keys(item.facts).map(key=>[key,true]))}));
module.exports={cases,adversarialFactCases};
