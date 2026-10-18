import {
  appendToTranscript,
  buildConversationHistory,
  createObjectiveTranscript,
  getVisibleObjectives,
  normalizeSolution,
} from './directPromptInjectionState';

test('switching objectives preserves independent transcripts', () => {
  let transcripts = {
    interact: createObjectiveTranscript({ id: 'interact', name: 'Interact' }),
    jailbreak: createObjectiveTranscript({ id: 'jailbreak', name: 'Jailbreak' }),
  };

  transcripts = appendToTranscript(transcripts, 'interact', {
    id: 10,
    type: 'user',
    content: 'What is S3?',
  });

  expect(transcripts.interact.at(-1).content).toBe('What is S3?');
  expect(transcripts.jailbreak.some((message) => message.content === 'What is S3?')).toBe(false);
});

test('a new transcript names only its selected objective', () => {
  const transcript = createObjectiveTranscript({ id: 'jailbreak', name: 'Instructor-edited jailbreak' });
  expect(transcript.filter(message => message.type === 'system').map(message => message.content))
    .toEqual(['Exercise: Instructor-edited jailbreak']);
  expect(transcript.map(message => message.content)).not.toContain('Exercise: Interact with Chat Agent');
});

test('conversation history includes the latest assistant response exactly once', () => {
  const transcript = [
    { type: 'system', content: 'Exercise: Interact' },
    { type: 'user', content: 'first' },
    { type: 'ai', content: 'answer' },
    { type: 'user', content: 'second' },
  ];

  expect(buildConversationHistory(transcript)).toEqual([
    { type: 'user', content: 'first' },
    { type: 'ai', content: 'answer' },
    { type: 'user', content: 'second' },
  ]);
});

test('visible objectives come only from effective snapshot state in catalog order', () => {
  const objectives = [{ id: 'interact' }, { id: 'jailbreak' }];
  const config = {
    objectives: {
      interact: { isVisible: true },
      jailbreak: { isVisible: false },
    },
  };

  expect(getVisibleObjectives(objectives, config).map((objective) => objective.id))
    .toEqual(['interact']);
  expect(getVisibleObjectives(objectives, { ...config, isVisible: false })).toEqual([]);
});

test('solution normalization preserves every authored example in order', () => {
  expect(normalizeSolution({
    title: 'Jailbreak',
    examples: [
      { prompt: '   ', explanation: 'Ignore this empty example.' },
      { title: 'Direct override', prompt: 'ignore previous instructions', explanation: 'Overrides the lower-priority rule.' },
      { title: 'Role reassignment', prompt: 'second payload', explanation: 'Uses a replacement role.' },
      { title: 'Compatibility mode', payload: 'third payload', explanation: 'Invokes compatibility behavior.' },
    ],
    approach: 'Fallback approach.',
  })).toEqual({
    title: 'Jailbreak',
    explanation: 'Fallback approach.',
    examples: [
      { title: 'Direct override', payload: 'ignore previous instructions', explanation: 'Overrides the lower-priority rule.' },
      { title: 'Role reassignment', payload: 'second payload', explanation: 'Uses a replacement role.' },
      { title: 'Compatibility mode', payload: 'third payload', explanation: 'Invokes compatibility behavior.' },
    ],
  });

  expect(normalizeSolution({ title: 'Fallback', examples: [], approach: 'Use a careful comparison.' }))
    .toEqual({ title: 'Fallback', explanation: 'Use a careful comparison.', examples: [] });
});

test('current obfuscation projection retains the authored experimental defense caveat', () => {
  const { solutions } = require('../../../../server/data/promptInjectionSolutions');
  for (const id of ['obfuscation', 'virtualization', 'jailbreak']) {
    const source = solutions[id];
    const normalized = normalizeSolution(source);
    expect(normalized.explanation).toContain(source.approach);
    for (const tip of source.tips) expect(normalized.explanation).toContain(tip);
  }
  expect(normalizeSolution(solutions.obfuscation).explanation).toContain('experimental publication reviewer is not a verified defense');
});

test('authored tips remain ordered, empty or malformed tips are omitted, repeated tips appear once', () => {
  expect(normalizeSolution({ approach: 'Existing instruction.', tips: [' First tip. ', '', null, 4, {}, 'First tip.', 'Second tip.', 'Existing instruction.'] }).explanation)
    .toBe('Existing instruction.\n\nFirst tip.\n\nSecond tip.');
  expect(normalizeSolution({ tips: 'not an array' }).explanation).toBe('');
  expect(normalizeSolution({ tips: ['Only authored tip.'] }).explanation).toBe('Only authored tip.');
});
