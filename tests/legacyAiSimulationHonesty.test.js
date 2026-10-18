'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const vm=require('node:vm');

function handlers({ollama}={}){
 const routes=new Map();
 const router=Object.fromEntries(['get','post'].map(method=>[method,(route,...callbacks)=>routes.set(`${method} ${route}`,callbacks.at(-1))]));
 const denied=new Proxy({}, {get(){throw new Error('A simulation must not claim or perform a model/database effect');}});
 const dependencies={express:{Router:()=>router},'../services/ollamaService':ollama||denied,
  '../services/multiProviderAIService':denied,'../database/legacyChallengeStore':denied,
  '../services/legacyPlatformMutationLifecycle':{legacyPlatformMutationMiddleware:()=>{}},
  '../middleware/workshopMode':{checkVulnerabilityAccess:()=>()=>{}}};
 const filename=path.resolve(__dirname,'../server/routes/ai.js');
 vm.runInNewContext(fs.readFileSync(filename,'utf8'),{module:{exports:{}},console:{log(){}},require(name){
  if(!Object.hasOwn(dependencies,name))throw new Error(`Unexpected dependency ${name}`);
  return dependencies[name];
 }},{filename});
 return routes;
}
function invoke(handler,body){
 let result;const response={statusCode:200,status(code){this.statusCode=code;return this;},json(value){result={status:this.statusCode,body:value};}};
 handler({body},response);return result;
}
test('mounted legacy AI simulations never claim model training, inference or measured confidence',()=>{
 const routes=handlers();
 for(const trainingData of ['ordinary example','<script>malicious example</script>']){
  const result=invoke(routes.get('post /model-poisoning'),{trainingData,label:'example'});
  assert.equal(result.status,200);assert.equal(result.body.simulation,true);assert.equal(result.body.modelUpdated,false);
  assert.match(result.body.message,/No training data was persisted and no model was updated/);
 }
 for(const input of ['ordinary request','carefully crafted input']){
  const result=invoke(routes.get('post /adversarial'),{input});
  assert.equal(result.status,200);assert.equal(result.body.simulation,true);assert.equal(result.body.modelInvoked,false);
  assert.match(result.body.warning,/confidence is illustrative/);
 }
 for(const text of ['Hello world, this is a test message','a sample absent from the fixture']){
  const result=invoke(routes.get('post /membership-inference'),{text});
  assert.equal(result.status,200);assert.equal(result.body.simulation,true);assert.equal(result.body.modelInvoked,false);
  assert.match(result.body.warning,/not inference about any model training data/);
 }
});
test('model information comes from service configuration and health without fictional training or secret claims',async()=>{
 const routes=handlers({ollama:{healthCheck:async()=>({status:'healthy',available_models:['fixture-model:8b']}),
  getStats:()=>({model:'fixture-model:8b',base_url:'http://owned-model.invalid:11434',concurrent_requests:2,max_concurrent:4,queue_length:1})}});
 let result;
 await routes.get('get /model/info')({}, {json(value){result=value;}});
 assert.equal(result.actualModel,'fixture-model:8b');assert.equal(result.ollamaEndpoint,'http://owned-model.invalid:11434');
 assert.equal(result.ollama_status,'healthy');assert.equal(result.performance.queue_length,1);
 assert.equal(result.parameters,null);assert.equal(result.version,null);assert.equal(result.architecture,null);
 assert.equal(result.internalPrompts.length,0);assert.match(result.trainingData,/Unknown/);
 assert.doesNotMatch(JSON.stringify(result),/config\.json|128k|Scraped from internet/);
});
test('malformed simulation inputs return a client error instead of throwing or accepting fake score values',()=>{
 const routes=handlers();
 for(const body of [undefined,{}, {input:4}, {input:[]}, {input:'  '}])assert.equal(invoke(routes.get('post /adversarial'),body).status,400);
 for(const confidence of ['0.99',null,-1,2,NaN,Infinity])assert.equal(invoke(routes.get('post /adversarial'),{input:'example',confidence}).status,400);
 for(const body of [undefined,{}, {trainingData:3}, {trainingData:[]}, {trainingData:' '}])assert.equal(invoke(routes.get('post /model-poisoning'),body).status,400);
 for(const body of [undefined,{}, {text:3}, {text:[]}, {text:' '}])assert.equal(invoke(routes.get('post /membership-inference'),body).status,400);
});

test('model capability disclosure separates requested configuration from unmeasured behavior',async()=>{
 const {OllamaService}=require('../server/services/ollamaService');
 const service=new OllamaService('http://owned-capabilities.invalid',{
  providerFactory(){throw new Error('Capability metadata must not fabricate an inference result');},
 });
 service.modelName='owned-non-llama-model';
 const capabilities=service.getModelCapabilities();
 assert.equal(capabilities.model,'owned-non-llama-model');
 assert.equal(capabilities.context_window,null);assert.equal(capabilities.max_tokens,null);
 for(const key of ['supports_reasoning','supports_large_context','enhanced_instruction_following'])assert.equal(capabilities[key],null);
 assert.deepEqual(capabilities.capabilities,[]);assert.deepEqual(capabilities.vulnerabilities,[]);
 assert.equal(capabilities.verification,'unverified');
 assert.equal(typeof capabilities.requested_defaults.context_window,'number');
 assert.match(capabilities.configuration_note,/overridden per call/);
 const routes=handlers({ollama:{getModelCapabilities:()=>capabilities,
  healthCheck:async()=>({status:'healthy',available_models:['owned-non-llama-model']})}});
 let result;await routes.get('get /model/capabilities')({}, {json(value){result=value;}});
 assert.equal(result.status,'healthy');assert.equal(result.verification,'unverified');
 assert.match(result.warning,/do not establish model capabilities/);
 assert.doesNotMatch(result.warning,/Llama 3\.1/);
});
