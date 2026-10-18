'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createSecureShopModelQualifier } = require('../server/services/secureshopModelQualification');
const { ProviderRouter } = require('../server/services/secureshop/providerRouter');
const { OllamaProvider } = require('../server/services/secureshop/providers/ollamaProvider');
const { AnthropicProvider } = require('../server/services/secureshop/providers/anthropicProvider');
const { OpenAIProvider } = require('../server/services/secureshop/providers/openaiProvider');
const { BedrockProvider } = require('../server/services/secureshop/providers/bedrockProvider');
const { MockProvider } = require('../server/services/secureshop/providers/mockProvider');

const identity = (provider,model,patch={}) => ({ provider,model,mocked:false,kind:'model_decision',step:1,...patch });
const dependencies = { modelFactory() { throw new Error('Qualification must not create or call a model'); } };

test('qualifies concrete supported direct adapters by their captured configured identity', () => {
  const adapters = [
    [new OllamaProvider({ baseUrl:'http://127.0.0.1:1', model:'owned-ollama' }), 'ollama', 'owned-ollama'],
    [new AnthropicProvider({ apiKey:'owned', model:'owned-anthropic' },dependencies), 'anthropic','owned-anthropic'],
    [new OpenAIProvider({ apiKey:'owned', model:'owned-openai' },dependencies), 'openai','owned-openai'],
    [new BedrockProvider({ modelId:'owned-bedrock', region:'us-test-1' },dependencies), 'bedrock','owned-bedrock'],
  ];
  for (const [adapter,name,model] of adapters) {
    const qualifies=createSecureShopModelQualifier(adapter);
    assert.equal(qualifies(identity(name,model)),true,name);
    assert.equal(qualifies(identity(name,`${model}-other`)),false,`${name} wrong model`);
    assert.equal(qualifies(identity(name,model,{mocked:true})),false,`${name} mock trace`);
    assert.equal(qualifies(identity(name,model,{fallback:true})),false,`${name} fallback trace`);
  }
});

test('router qualification includes only concrete supported adapters registered in matching slots', () => {
  const ollama=new OllamaProvider({ baseUrl:'http://127.0.0.1:1',model:'router-ollama' });
  const openai=new OpenAIProvider({ apiKey:'owned',model:'router-openai' },dependencies);
  const router=new ProviderRouter({ ollama,openai,mock:new MockProvider(),
    anthropic:{config:{provider:'anthropic',model:'claimed-anthropic'},chat(){},isReachable(){return true;}},
    bedrock:openai });
  const qualifies=createSecureShopModelQualifier(router);
  assert.equal(qualifies(identity('ollama','router-ollama')),true);
  assert.equal(qualifies(identity('openai','router-openai')),true);
  assert.equal(qualifies(identity('anthropic','claimed-anthropic')),false,'plain registered claims are not adapters');
  assert.equal(qualifies(identity('bedrock','router-openai')),false,'adapter in wrong router slot is rejected');
  assert.equal(qualifies(identity('mock','mock')),false);
});

test('plain fixtures, custom providers, MockProvider and later configuration mutation fail closed', () => {
  for (const provider of [null,new MockProvider(),
    { provider:'ollama',model:'llama3.1:8b',mocked:false,chat(){},isReachable(){return true;} },
    { constructor:OllamaProvider,model:'llama3.1:8b',transport:{} },
    new (class CustomProvider { constructor(){this.config={provider:'ollama',model:'llama3.1:8b'};} })(),
  ]) assert.equal(createSecureShopModelQualifier(provider)(identity('ollama','llama3.1:8b')),false);

  const adapter=new OllamaProvider({baseUrl:'http://127.0.0.1:1',model:'captured-model'});
  const qualifies=createSecureShopModelQualifier(adapter);
  adapter.model='mutated-model';
  assert.equal(qualifies(identity('ollama','captured-model')),true,'qualification is an immutable configuration snapshot');
  assert.equal(qualifies(identity('ollama','mutated-model')),false);
  assert.equal(qualifies(null),false);
});

test('constructor-spoofed adapters and routers cannot establish qualification', () => {
  const fakeAdapter={constructor:OllamaProvider,model:'spoofed-model',transport:{}};
  const fakeRouter={constructor:ProviderRouter,providers:{ollama:fakeAdapter}};
  assert.equal(createSecureShopModelQualifier(fakeAdapter)(identity('ollama','spoofed-model')),false);
  assert.equal(createSecureShopModelQualifier(fakeRouter)(identity('ollama','spoofed-model')),false);
});
