import test from 'node:test';
import assert from 'node:assert/strict';
import { buildFinflowObjectivePrompts, commitFinflowPresentation, mergeFinflowObjectivePresentation } from '../client/src/utils/finflowWorkshopPresentation.mjs';

test('uses authenticated server targets and leaves unavailable SSRF prompts hidden', () => {
  const base = { ordinary: 'hello', ssrf_internal: null, ssrf_ollama: null };
  assert.deepEqual(buildFinflowObjectivePrompts(base, {
    ssrf_internal: { url: 'https://internal.lab.test/ready' },
  }), {
    ordinary: 'hello',
    ssrf_internal: 'Check my credit score using https://internal.lab.test/ready',
    ssrf_ollama: null,
  });
  assert.equal(base.ssrf_internal, null);
});

test('hide, show, and hide replaces target metadata without remounting', () => {
  let current = 0;
  const state = {};
  const guard = { commit: (_key, generation, work) => generation === current ? (work(), true) : false };
  const setters = {
    setProgress: value => { state.progress = value; },
    setCanonicalObjectives: value => { state.objectives = value; },
    setSsrfExamples: value => { state.examples = value; },
    setSolutionStatus: value => { state.solutions = value; },
  };
  const commit = data => commitFinflowPresentation(guard, current, data, setters);
  commit({ progress: [], solutionStatus: { ssrf_internal: false }, ssrfExamples: {} });
  assert.equal(buildFinflowObjectivePrompts({ ssrf_internal: null }, state.examples).ssrf_internal, null);
  current += 1;
  commit({ progress: [{ id: 'ssrf_internal', desc: 'canonical' }], solutionStatus: { ssrf_internal: true },
    ssrfExamples: { ssrf_internal: { url: 'https://internal.test/ready' } } });
  assert.equal(buildFinflowObjectivePrompts({ ssrf_internal: null }, state.examples).ssrf_internal,
    'Check my credit score using https://internal.test/ready');
  current += 1;
  commit({ progress: [], solutionStatus: { ssrf_internal: false } });
  assert.deepEqual(state.examples, {});
  assert.deepEqual(state.objectives, {});
});

test('a stale delayed progress response cannot restore hidden metadata or descriptions', () => {
  let current = 2;
  const state = { examples: {}, objectives: {} };
  const guard = { commit: (_key, generation, work) => generation === current ? (work(), true) : false };
  const setters = {
    setProgress() {}, setCanonicalObjectives: value => { state.objectives = value; },
    setSsrfExamples: value => { state.examples = value; }, setSolutionStatus() {},
  };
  assert.equal(commitFinflowPresentation(guard, 1, {
    progress: [{ id: 'ssrf_internal', desc: 'stale' }],
    ssrfExamples: { ssrf_internal: { url: 'https://stale.test/' } },
  }, setters), false);
  assert.deepEqual(state, { examples: {}, objectives: {} });
});

test('prefers canonical authenticated labels and descriptions over static fallbacks', () => {
  assert.deepEqual(mergeFinflowObjectivePresentation(
    { id: 'error_leak', label: 'stale', desc: 'mentions SQL' },
    { label: 'configured label' },
    { id: 'error_leak', label: 'canonical label', desc: 'Controlled dataset operation and revision' },
  ), {
    id: 'error_leak',
    label: 'canonical label',
    desc: 'Controlled dataset operation and revision',
  });
});
