'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {resolveJudgeProviderConfig}=require('../server/agent-runtime/judgeProviderConfiguration');
const {createLegacyAiExperimentConfiguredInference}=require('../server/services/legacyAiExperimentConfiguredInference');
const variants=[{CLAUDE_API_KEY:'synthetic-alias',expected:'synthetic-alias'},{ANTHROPIC_API_KEY:'synthetic-primary',CLAUDE_API_KEY:'synthetic-alias',expected:'synthetic-primary'},{ANTHROPIC_API_KEY:'',CLAUDE_API_KEY:'synthetic-alias',expected:'synthetic-alias'}];
test('canonical Judge aliases preserve primary precedence, independent model and immutable environment',()=>{
 for(const provider of ['claude','anthropic'])for(const {expected,...keys} of variants){const env=Object.freeze({JUDGE_PROVIDER:provider,JUDGE_MODEL:'judge-model',ANTHROPIC_MODEL:'actor-model',...keys}),before={...env};assert.deepEqual(resolveJudgeProviderConfig(env),{provider:'anthropic',model:'judge-model',apiKey:expected});assert.deepEqual(env,before);}
 assert.equal(resolveJudgeProviderConfig({JUDGE_PROVIDER:'claude',JUDGE_MODEL:'judge-model'}).apiKey,undefined);
 assert.deepEqual(resolveJudgeProviderConfig({JUDGE_PROVIDER:'openai',JUDGE_MODEL:'judge-model',OPENAI_API_KEY:'synthetic-openai',CLAUDE_API_KEY:'synthetic-alias'}),{provider:'openai',model:'judge-model',apiKey:'synthetic-openai'});
});
test('legacy actor and Judge aliases resolve without provider calls; missing key still denies',async()=>{
 for(const provider of ['claude','anthropic'])for(const {expected,...keys} of variants){const env=Object.freeze({AI_PROVIDER:provider,JUDGE_PROVIDER:provider,ANTHROPIC_MODEL:'actor-model',JUDGE_MODEL:'judge-model',...keys}),before={...env};let captured;
 const run=createLegacyAiExperimentConfiguredInference({getEnvironment:()=>env,createProduction:config=>{captured=config;return{run:async()=>({controlled:true})};}});
 assert.deepEqual(await run({},{}),{controlled:true});assert.equal(captured.inferenceConfig.apiKey,expected);assert.equal(captured.judgeConfig.apiKey,expected);assert.equal(captured.inferenceConfig.model,'actor-model');assert.equal(captured.judgeConfig.model,'judge-model');assert.deepEqual(env,before);}
 let created=0;const run=createLegacyAiExperimentConfiguredInference({getEnvironment:()=>({JUDGE_PROVIDER:'anthropic',JUDGE_MODEL:'judge-model'}),createProduction:()=>{created++;throw Error('must not create');}});await assert.rejects(run({},{}),{code:'LEGACY_AI_EXPERIMENT_CONFIGURATION_UNAVAILABLE'});assert.equal(created,0);
});
