'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { defaultGraph } = require('../server/routes/agentRuns');

function edge(definition, source, target, conditional = false) {
  return definition.edges.some(item => item.source === source && item.target === target && item.conditional === conditional);
}

test('agent inspector maps XSS to its actual bounded decision-observation loop', () => {
  const graph = defaultGraph('XSS');
  assert.deepEqual(graph.nodes.map(item => item.id), ['decide', 'validate', 'invalid', 'tool', 'finalize']);
  assert.ok(edge(graph, 'validate', 'tool', true));
  assert.ok(edge(graph, 'tool', 'decide', true));
  assert.ok(edge(graph, 'tool', 'finalize', true));
  assert.ok(edge(graph, 'invalid', 'finalize'));
  assert.equal(graph.maxToolSteps, 3);
  assert.equal(graph.maxDecisionAttempts, 2);
});

test('agent inspector maps ExcessiveAgency to its actual effect-grade-observation loop', () => {
  const graph = defaultGraph('ExcessiveAgency');
  assert.deepEqual(graph.nodes.map(item => item.id), ['decide', 'validate', 'retry', 'tool', 'grade', 'finalize']);
  assert.ok(edge(graph, 'validate', 'retry', true));
  assert.ok(edge(graph, 'retry', 'decide', true));
  assert.ok(edge(graph, 'tool', 'grade'));
  assert.ok(edge(graph, 'grade', 'decide', true));
  assert.ok(edge(graph, 'grade', 'finalize', true));
  assert.equal(graph.maxToolSteps, 3);
  assert.equal(graph.maxDecisionAttempts, 2);
  assert.equal(graph.maxSelectionCalls, 8);
});

test('agent inspector maps launch-bound SecureShop supervisor decisions and tool observations', () => {
  const graph = defaultGraph('SecureShopBoundConversation');
  assert.deepEqual(graph.nodes.map(item => item.id),
    ['initialize', 'budget', 'model', 'dispatch_tools', 'finalize', 'emit']);
  assert.ok(edge(graph, 'budget', 'model', true));
  assert.ok(edge(graph, 'model', 'dispatch_tools', true));
  assert.ok(edge(graph, 'dispatch_tools', 'budget', true));
  assert.ok(edge(graph, 'finalize', 'emit'));
});

test('agent inspector keeps unsupported families unrepresented instead of showing a generic false graph', () => {
  assert.equal(defaultGraph('CTF'), null);
});

test('browser assessment is not mislabeled as the SecureShop supervisor decision loop', () => {
  assert.equal(defaultGraph('SecureShopBoundConversation', {
    events: [{ node: 'stored_browser_assessment', type: 'node_start' }],
  }), null);
  assert.equal(defaultGraph('SecureShopBoundConversation', {
    judgments: [{ objectiveId: 'ss_stored_browser_execution' }],
  }), null);
  assert.ok(defaultGraph('SecureShopBoundConversation', {
    events: [{ node: 'model', type: 'decision' }],
    judgments: [{ objectiveId: 'ss_review_prompt_injection' }],
  }).nodes.some(node => node.id === 'model'));
});

test('DPI exposes current compiled outer and conditional decoder without invented cross edges',()=>{
 const graph=defaultGraph('DPI');assert.equal(graph.scope,'registered-current');
 assert.deepEqual(graph.nodes.map(n=>n.id),['__start__','prepare','model','detect','judge','publication','__end__']);
 assert.ok(edge(graph,'detect','publication',true));assert.equal(graph.subgraphs[0].parentNode,'model');
 assert.ok(graph.subgraphs[0].nodes.some(n=>n.id==='decode_payload'));
 assert.equal(graph.edges.some(e=>e.target==='decode_payload'),false);
});

 test('mail browser assessment never claims a supervisor graph, including ungraded runs', () => {
  assert.equal(defaultGraph('SecureShopBoundConversation', {events:[{node:'mail_browser_assessment',type:'node_start'}]}),null);
  assert.equal(defaultGraph('SecureShopBoundConversation', {judgments:[{objectiveId:'ss_mail_stored_browser_execution'}]}),null);
  assert.ok(defaultGraph('SecureShopBoundConversation', {events:[{node:'model',type:'decision'}]}).nodes.some(node=>node.id==='model'));
 });
