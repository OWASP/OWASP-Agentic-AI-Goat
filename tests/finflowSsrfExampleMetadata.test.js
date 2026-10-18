'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');

process.env.EXPORT_INTERNALS = '1';
const Module=require('node:module'),originalLoad=Module._load;let api;
try{Module._load=function(request,parent,main){if(/(?:^|\/)multiProviderAIService(?:\.js)?$/.test(request))return {getActiveProviderInfo:()=>({provider:process.env.AI_PROVIDER||'ollama'})};return originalLoad.call(this,request,parent,main);};api=require('../server/services/sensitiveInfoWorkshopAgent');}finally{Module._load=originalLoad;}
const { getConfiguredSsrfExamples } = api;

const ENV_KEYS = ['FINFLOW_INTERNAL_HEALTH_URL', 'OLLAMA_BASE_URL', 'AI_PROVIDER'];
const original = Object.fromEntries(ENV_KEYS.map(key => [key, process.env[key]]));
test.afterEach(() => {
  for (const key of ENV_KEYS) original[key] === undefined
    ? delete process.env[key] : process.env[key] = original[key];
});

test('publishes default and alternate configured targets only for solution-visible objectives', () => {
  delete process.env.FINFLOW_INTERNAL_HEALTH_URL;
  delete process.env.OLLAMA_BASE_URL;
  process.env.AI_PROVIDER = 'ollama';
  assert.deepEqual({ ...getConfiguredSsrfExamples({ ssrf_internal: true, ssrf_ollama: false }) }, {
    ssrf_internal: { url: 'http://localhost:8081/api/monitoring/health' },
  });

  process.env.FINFLOW_INTERNAL_HEALTH_URL = 'https://internal.lab.test:9443/ready';
  process.env.OLLAMA_BASE_URL = 'https://models.lab.test/runtime/';
  assert.deepEqual({ ...getConfiguredSsrfExamples({ ssrf_internal: true, ssrf_ollama: true }) }, {
    ssrf_internal: { url: 'https://internal.lab.test:9443/ready' },
    ssrf_ollama: { url: 'https://models.lab.test/runtime/api/tags' },
  });
});

test('omits metadata when configuration is invalid or could disclose credentials', () => {
  process.env.AI_PROVIDER = 'ollama';
  process.env.FINFLOW_INTERNAL_HEALTH_URL = 'https://user:secret@internal.lab.test/ready';
  process.env.OLLAMA_BASE_URL = 'https://models.lab.test/?token=secret';
  assert.deepEqual({ ...getConfiguredSsrfExamples({ ssrf_internal: true, ssrf_ollama: true }) }, {
    ssrf_ollama: { url: 'https://models.lab.test/api/tags' },
  });

  process.env.FINFLOW_INTERNAL_HEALTH_URL = 'not-a-url';
  process.env.OLLAMA_BASE_URL = 'file:///tmp/model';
  assert.deepEqual({ ...getConfiguredSsrfExamples({ ssrf_internal: true, ssrf_ollama: true }) }, {});
});

test('derives credential-free Bedrock examples from a validated configured region', () => {
  assert.deepEqual({ ...getConfiguredSsrfExamples(
    { ssrf_internal: true, ssrf_ollama: true },
    { providerInfo: { provider: 'bedrock', region: 'us-west-2' } },
  ) }, {
    ssrf_internal: { url: 'https://bedrock-runtime.us-west-2.amazonaws.com/' },
    ssrf_ollama: { url: 'https://bedrock.us-west-2.amazonaws.com/foundation-models' },
  });
  assert.deepEqual({ ...getConfiguredSsrfExamples(
    { ssrf_internal: true, ssrf_ollama: true },
    { providerInfo: { provider: 'bedrock', region: 'bad.example/credential' } },
  ) }, {});
});

test('does not publish any target without an explicit effective solution gate', () => {
  process.env.AI_PROVIDER = 'ollama';
  delete process.env.FINFLOW_INTERNAL_HEALTH_URL;
  delete process.env.OLLAMA_BASE_URL;
  assert.deepEqual({ ...getConfiguredSsrfExamples() }, {});
  assert.deepEqual({ ...getConfiguredSsrfExamples({ ssrf_internal: false, ssrf_ollama: false }) }, {});
});
