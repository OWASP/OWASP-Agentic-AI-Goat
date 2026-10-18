'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
process.env.AI_PROVIDER='mock';
const service={getActiveProviderInfo:()=>({provider:'mock'})};
let httpBehavior=async()=>{throw Error('Unexpected controlled HTTP call');},httpCalls=0;
const http={get:async(...args)=>{httpCalls++;return httpBehavior(...args);}};
const Module=require('node:module'),originalLoad=Module._load;let api;
try{Module._load=function(request,parent,main){if(request==='axios')return http;if(/(?:^|\/)multiProviderAIService(?:\.js)?$/.test(request))return service;return originalLoad.call(this,request,parent,main);};api=require('../server/services/sensitiveInfoWorkshopAgent');}finally{Module._load=originalLoad;}
const {detectObjectives,buildFinflowJudgeInputs,getConfiguredSsrfExamples}=api;
const prior=service.getActiveProviderInfo,envKeys=['FINFLOW_INTERNAL_HEALTH_URL','OLLAMA_BASE_URL','AWS_REGION','BEDROCK_REGION'];
const env=Object.fromEntries(envKeys.map(k=>[k,process.env[k]]));
test.afterEach(()=>{service.getActiveProviderInfo=prior;httpCalls=0;httpBehavior=async()=>{throw Error('Unexpected controlled HTTP call');};for(const k of envKeys)env[k]===undefined?delete process.env[k]:process.env[k]=env[k];});
function observed(url){return detectObjectives('check_credit_score',{}, {realRequest:true,success:true,ssrfTarget:url,result:'HTTP 200 fixture'},'').filter(x=>x.startsWith('ssrf_'));}
test('configured local endpoints require exact parsed authority/path/query and use the same examples',()=>{
 service.getActiveProviderInfo=()=>({provider:'ollama'});process.env.FINFLOW_INTERNAL_HEALTH_URL='https://internal.fixture.invalid:9443/ready?scope=lab';process.env.OLLAMA_BASE_URL='https://models.fixture.invalid/runtime/';
 assert.deepEqual(observed(process.env.FINFLOW_INTERNAL_HEALTH_URL),['ssrf_internal']);assert.deepEqual(observed('https://models.fixture.invalid/runtime/api/tags'),['ssrf_ollama']);
 const examples=getConfiguredSsrfExamples({ssrf_internal:true,ssrf_ollama:true});assert.deepEqual(observed(examples.ssrf_ollama.url),['ssrf_ollama']);assert.equal(examples.ssrf_internal,undefined,'credential-free metadata still suppresses query URLs');
 for(const url of ['https://internal.fixture.invalid:9443/ready','https://internal.fixture.invalid:9443/ready?scope=foreign','https://models.fixture.invalid/runtime/api/ps','https://models.fixture.invalid/runtime/api/tags?extra=1','https://models.fixture.invalid.attacker.invalid/runtime/api/tags','https://attacker.invalid/?target=https://models.fixture.invalid/runtime/api/tags'])assert.deepEqual(observed(url),['ssrf_oob']);
 for(const url of ['https://user@models.fixture.invalid/runtime/api/tags','https://models.fixture.invalid/runtime/api/tags#fragment','file:///runtime/api/tags','invalid'])assert.deepEqual(observed(url),[]);
});
test('only configured Bedrock region and exact paths classify as dedicated targets; host text cannot borrow authority',()=>{
 service.getActiveProviderInfo=()=>({provider:'bedrock',region:'us-west-2'});
 const examples=getConfiguredSsrfExamples({ssrf_internal:true,ssrf_ollama:true});for(const id of ['ssrf_internal','ssrf_ollama'])assert.deepEqual(observed(examples[id].url),[id]);
 assert.deepEqual(observed('https://BEDROCK-RUNTIME.US-WEST-2.AMAZONAWS.COM:443'),['ssrf_internal']);
 for(const url of ['https://bedrock-runtime.us-east-1.amazonaws.com/','https://bedrock.us-east-1.amazonaws.com/foundation-models','https://bedrock-runtime.us-west-2.amazonaws.com/other','https://bedrock.us-west-2.amazonaws.com/other?x=foundation-models','https://bedrock.us-west-2.amazonaws.com/foundation-models?x=1','https://bedrock-runtime.us-west-2.amazonaws.com.attacker.invalid/','https://attacker.invalid/bedrock-runtime.us-west-2.amazonaws.com','https://attacker.invalid/?target=bedrock.us-west-2.amazonaws.com/foundation-models','http://bedrock-runtime.us-west-2.amazonaws.com/','http://localhost:11434/api/tags'])assert.deepEqual(observed(url),['ssrf_oob']);
 for(const url of ['https://user:pass@bedrock-runtime.us-west-2.amazonaws.com/','https://bedrock.us-west-2.amazonaws.com/foundation-models#fragment'])assert.deepEqual(observed(url),[]);
 service.getActiveProviderInfo=()=>({provider:'bedrock',region:'bad.example/path'});assert.deepEqual(observed('https://bedrock-runtime.us-west-2.amazonaws.com/'),['ssrf_oob']);
});
test('canonical required observation rejects lookalike dedicated-target claims and preserves exact target admission',()=>{
 service.getActiveProviderInfo=()=>({provider:'bedrock',region:'us-west-2'});
 for(const [url,expected] of [['https://attacker.invalid/?x=bedrock-runtime.us-west-2.amazonaws.com',false],['https://bedrock-runtime.us-west-2.amazonaws.com/',true]]){
  const packets=buildFinflowJudgeInputs('fixture',[{name:'check_credit_score',params:{api_endpoint:url},success:true,realRequest:true,ssrfTarget:url,result:'HTTP 200 fixture'}],'fixture',{activeObjectiveId:'ssrf_internal'});
  assert.equal(packets.find(p=>p.rubric.objectiveId==='ssrf_internal').facts.required_observation,expected);
 }
 assert.deepEqual(detectObjectives('check_credit_score',{}, {realRequest:false,ssrfTarget:'https://bedrock-runtime.us-west-2.amazonaws.com/',result:'No network'},''),[]);
});

test('HTTP exceptions never establish any SSRF required observation, while returned non-2xx responses do',async()=>{
 service.getActiveProviderInfo=()=>({provider:'ollama'});process.env.FINFLOW_INTERNAL_HEALTH_URL='http://internal.fixture.invalid/ready';process.env.OLLAMA_BASE_URL='http://models.fixture.invalid';
 const state=api.createSensitiveInfoWorkshopStateStore().getUserState('1');
 const ids=['ssrf_oob','ssrf_internal','ssrf_ollama'],urls=['http://listener.fixture.invalid/callback',process.env.FINFLOW_INTERNAL_HEALTH_URL,'http://models.fixture.invalid/api/tags'];
 const errors=['ENETUNREACH','EHOSTUNREACH','ECONNABORTED','ETIMEDOUT','ECONNREFUSED','ECONNRESET','ENOTFOUND','EAI_AGAIN','EPROTO','CERT_HAS_EXPIRED','DEPTH_ZERO_SELF_SIGNED_CERT',null];
 for(const code of errors)for(const url of urls){
  httpBehavior=async()=>{throw Object.assign(Error(code?'Controlled request failure':'timeout without code'),code?{code}:{});};
  const value=await api.executeVaultCorpTool('check_credit_score',{api_endpoint:url},'vulnerable',state);assert.equal(value.success,false);assert.equal(value.realRequest,false);assert.equal(value.securityFlag,'safe');assert.match(value.result,/no HTTP response was observed/);assert.doesNotMatch(value.result,/No request left|request was forwarded|reached the network/);
  const packets=buildFinflowJudgeInputs('fixture',[{name:'check_credit_score',params:{api_endpoint:url},...value}],'fixture',{candidateIds:ids});for(const id of ids)assert.equal(packets.find(p=>p.rubric.objectiveId===id).facts.required_observation,false);
 }
 for(const [index,url] of urls.entries()){
  httpBehavior=async target=>{assert.equal(target,url);return {status:403,statusText:'Forbidden',headers:{'content-type':'text/plain'},data:'Controlled endpoint reached'};};
  const value=await api.executeVaultCorpTool('check_credit_score',{api_endpoint:url},'vulnerable',state);assert.equal(value.success,true);assert.equal(value.realRequest,true);assert.match(value.result,/HTTP 403 Forbidden/);const packets=buildFinflowJudgeInputs('fixture',[{name:'check_credit_score',params:{api_endpoint:url},...value}],'fixture',{candidateIds:ids});for(const id of ids)assert.equal(packets.find(p=>p.rubric.objectiveId===id).facts.required_observation,id===ids[index]);
 }
 const before=httpCalls;for(const [params,mode]of [[{api_endpoint:urls[0]},'fixed'],[{api_endpoint:'https://api.creditbureau.com/v1/check'},'vulnerable']]){const value=await api.executeVaultCorpTool('check_credit_score',params,mode,state);assert.notEqual(value.realRequest,true);assert.deepEqual(detectObjectives('check_credit_score',params,value,''),[]);}assert.equal(httpCalls,before);
});
