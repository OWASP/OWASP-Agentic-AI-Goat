'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');

function freshAgent(value) {
  const key = require.resolve('../server/services/sensitiveInfoWorkshopAgent');
  delete require.cache[key];
  if (value === undefined) delete process.env.FINFLOW_INTERNAL_HEALTH_URL;
  else process.env.FINFLOW_INTERNAL_HEALTH_URL = value;
  const Module=require('node:module'),load=Module._load;
  try{Module._load=function(request,parent,main){if(/(?:^|\/)multiProviderAIService(?:\.js)?$/.test(request))return {getActiveProviderInfo:()=>({provider:'ollama'})};return load.call(this,request,parent,main);};return require(key);}finally{Module._load=load;}
}

test.afterEach(() => {
  delete process.env.FINFLOW_INTERNAL_HEALTH_URL;
  delete process.env.OLLAMA_BASE_URL;
  delete require.cache[require.resolve('../server/services/sensitiveInfoWorkshopAgent')];
});

test('FinFlow defaults to the existing internal health teaching target', () => {
  const agent = freshAgent(undefined);
  assert.equal(agent.getConfiguredInternalHealthUrl(), 'http://localhost:8081/api/monitoring/health');
});

test('FinFlow classifies only the exact server-owned internal URL as internal', () => {
  const configured = 'http://127.0.0.1:39123/api/monitoring/health';
  const agent = freshAgent(configured);
  const result = target => agent.detectObjectives('check_credit_score', { api_endpoint: target }, {
    realRequest: true, ssrfTarget: target, success: true, securityFlag: 'vulnerability_exploited', result: 'HTTP 200',
  }, '');
  assert.deepEqual(result(configured), ['ssrf_internal']);
  assert.deepEqual(result(configured + '?forged=1'), ['ssrf_oob']);
  assert.deepEqual(result(`http://attacker.invalid/?next=${encodeURIComponent(configured)}`), ['ssrf_oob']);
});

test('FinFlow recognizes the exact configured Ollama model-list URL', () => {
  process.env.OLLAMA_BASE_URL = 'http://127.0.0.1:11434';
  const agent = freshAgent(undefined);
  const exact = 'http://127.0.0.1:11434/api/tags';
  const result = target => agent.detectObjectives('check_credit_score', { api_endpoint: target }, {
    realRequest: true, ssrfTarget: target, success: true, securityFlag: 'vulnerability_exploited', result: 'HTTP 200',
  }, '');
  assert.equal(agent.getConfiguredOllamaModelListUrl(), exact);
  assert.deepEqual(result(exact), ['ssrf_ollama']);
  assert.deepEqual(result(exact + '?forged=1'), ['ssrf_oob']);
  delete process.env.OLLAMA_BASE_URL;
});

test('FinFlow rejects malformed or credential-bearing internal target configuration', () => {
  for (const value of ['relative/path', 'file:///tmp/health', 'http://user:pass@127.0.0.1/health', 'http://127.0.0.1/health#fragment']) {
    const agent = freshAgent(value);
    assert.throws(() => agent.getConfiguredInternalHealthUrl(), /FINFLOW_INTERNAL_HEALTH_URL/);
  }
});
