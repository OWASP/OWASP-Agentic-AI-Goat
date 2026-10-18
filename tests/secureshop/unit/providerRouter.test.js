const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

const REPO = path.resolve(__dirname, '../../..');
const { ProviderRouter } = require(path.join(REPO, 'server/services/secureshop/providerRouter.js'));

function fakeProvider(id, opts = {}) {
  return {
    id,
    ...(opts.model ? { model: opts.model } : {}),
    async isReachable() { return opts.reachable !== false; },
    async chat() { return { stop_reason: 'end_turn', text: `hi from ${id}` }; },
  };
}

test('router picks ollama when reachable and no override', async () => {
  const router = new ProviderRouter({
    ollama: fakeProvider('ollama', { reachable: true }),
    anthropic: fakeProvider('anthropic'),
    openai: fakeProvider('openai'),
    bedrock: fakeProvider('bedrock'),
    mock: fakeProvider('mock'),
  });
  delete process.env.AI_PROVIDER;
  const p = await router.selectProvider();
  assert.equal(p.id, 'ollama');
});

test('router attributes the provider that actually returns, including fallback and mock status', async () => {
  const router = new ProviderRouter({
    ollama: { model: 'local-model', async isReachable() { return true; }, async chat() { throw new Error('offline'); } },
    anthropic: { config: { provider: 'anthropic', model: 'actual-model' }, async isReachable() { return true; },
      async chat() { return { stop_reason: 'tool_use', tool_uses: [{ id: 'c1', name: 'system.read', args: { raw: '<script>' } }] }; } },
    mock: fakeProvider('mock'),
  });
  delete process.env.AI_PROVIDER;
  const result = await router.chat({});
  assert.equal(result.provider, 'anthropic');
  assert.equal(result.model, 'actual-model');
  assert.equal(result.mocked, false);
  assert.deepEqual(result.tool_uses[0].args, { raw: '<script>' });

  const mockOnly = new ProviderRouter({ mock: fakeProvider('mock') });
  assert.deepEqual(await mockOnly.chat({}), {
    stop_reason: 'end_turn', text: 'hi from mock', provider: 'mock', model: null, mocked: true,
  });
});

test('router honors AI_PROVIDER=anthropic override', async () => {
  const router = new ProviderRouter({
    ollama: fakeProvider('ollama', { reachable: true }),
    anthropic: fakeProvider('anthropic', { reachable: true }),
    openai: fakeProvider('openai'),
    bedrock: fakeProvider('bedrock'),
    mock: fakeProvider('mock'),
  });
  process.env.AI_PROVIDER = 'anthropic';
  try {
    const p = await router.selectProvider();
    assert.equal(p.id, 'anthropic');
  } finally {
    delete process.env.AI_PROVIDER;
  }
});

test('router falls through to mock when nothing is reachable', async () => {
  const router = new ProviderRouter({
    ollama: fakeProvider('ollama', { reachable: false }),
    anthropic: fakeProvider('anthropic', { reachable: false }),
    openai: fakeProvider('openai', { reachable: false }),
    bedrock: fakeProvider('bedrock', { reachable: false }),
    mock: fakeProvider('mock', { reachable: true }),
  });
  delete process.env.AI_PROVIDER;
  const p = await router.selectProvider();
  assert.equal(p.id, 'mock');
});

test('router finalResponse selects an explicit capability and preserves its actual identity',async()=>{
  const router=new ProviderRouter({ollama:{model:'local8b',async isReachable(){return false;}},
    anthropic:{config:{provider:'anthropic',model:'actual'},async isReachable(){return true;},
      async finalResponse(){return{stop_reason:'end_turn',text:'answer',responseMode:'structured_final',usage:{outputTokens:4}};}},
    mock:fakeProvider('mock')});
  const result=await router.finalResponse({});
  assert.deepEqual(result,{stop_reason:'end_turn',text:'answer',responseMode:'structured_final',
    usage:{outputTokens:4},provider:'anthropic',model:'actual',mocked:false});
});

test('router finalResponse fails the selected reachable provider without generic or provider fallback',async()=>{
  let fallback=0;
  const unsupported=new ProviderRouter({ollama:{async isReachable(){return true;},async chat(){return{stop_reason:'end_turn',text:'coerced'};}},
    mock:{async isReachable(){return true;},async finalResponse(){fallback++;return{responseMode:'structured_final',text:'fallback'};}}});
  await assert.rejects(unsupported.finalResponse({}),{code:'SECURESHOP_FINAL_RESPONSE_UNSUPPORTED'});
  assert.equal(fallback,0);
  const invalid=new ProviderRouter({ollama:{async isReachable(){return true;},async finalResponse(){
    throw Object.assign(new Error('bad schema'),{code:'SECURESHOP_INVALID_DECISION'});}},
    mock:{async isReachable(){return true;},async finalResponse(){fallback++;return{responseMode:'structured_final',text:'fallback'};}}});
  await assert.rejects(invalid.finalResponse({}),{code:'SECURESHOP_INVALID_DECISION'});
  assert.equal(fallback,0);
});

test('a real provider slot cannot relabel an explicitly simulated response as genuine', async () => {
  const response = { stop_reason: 'end_turn', text: 'simulated result', mocked: true,
    fallback: true, responseMode: 'structured_final' };
  const router = new ProviderRouter({ ollama: { model: 'llama3.1:8b',
    async isReachable() { return true; }, async chat() { return response; },
    async finalResponse() { return response; } } });
  for (const operation of ['chat', 'finalResponse']) {
    const result = await router[operation]({});
    assert.equal(result.provider, 'ollama');
    assert.equal(result.mocked, true);
    assert.equal(result.fallback, true);
  }
});
