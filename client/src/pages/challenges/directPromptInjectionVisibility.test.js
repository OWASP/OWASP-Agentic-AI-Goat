import {
  EMPTY_DPI_DISCLOSURE,
  deriveDpiVisibility,
  isDpiExerciseUsable,
  reconcileDpiActiveObjective,
  reduceDpiDisclosure,
} from './directPromptInjectionVisibility';

const snapshot = {
  revision: 5,
  exercises: {
    direct_prompt_injection: {
      isVisible: true,
      objectives: {
        system_prompt: { label: 'Instructor prompt disclosure', isVisible: true, hintVisible: true, solutionVisible: true },
        jailbreak: { isVisible: true, hintVisible: false, solutionVisible: false },
      },
    },
  },
};

test('derives DPI objective, hint, and solution gates from the shared snapshot', () => {
  expect(deriveDpiVisibility(snapshot)).toEqual({
    isVisible: true,
    objectives: {
      system_prompt: { label: 'Instructor prompt disclosure', isVisible: true, hintVisible: true, solutionVisible: true },
      jailbreak: { isVisible: true, hintVisible: false, solutionVisible: false },
    },
  });
  expect(deriveDpiVisibility(null)).toEqual({ isVisible: false, objectives: {} });
});

test('live solution disable closes and clears the open disclosure', () => {
  const open = {
    objectiveId: 'system_prompt',
    solution: { title: 'Cached solution' },
  };
  const disabled = deriveDpiVisibility({
    ...snapshot,
    revision: 6,
    exercises: {
      direct_prompt_injection: {
        ...snapshot.exercises.direct_prompt_injection,
        objectives: {
          ...snapshot.exercises.direct_prompt_injection.objectives,
          system_prompt: { isVisible: true, hintVisible: false, solutionVisible: false },
        },
      },
    },
  });

  expect(reduceDpiDisclosure(open, { type: 'CONFIG_UPDATED', visibility: disabled }))
    .toEqual(EMPTY_DPI_DISCLOSURE);
});

test('403 content response evicts cached/viewing solution state', () => {
  const open = {
    objectiveId: 'system_prompt',
    solution: { title: 'Cached solution' },
  };

  expect(reduceDpiDisclosure(open, { type: 'CONTENT_FAILED', status: 403 }))
    .toEqual(EMPTY_DPI_DISCLOSURE);
  expect(reduceDpiDisclosure(open, { type: 'CONTENT_FAILED', status: 500 }))
    .toBe(open);
});

test('a late solution response cannot reopen content after live disable', () => {
  const disabled = {
    isVisible: true,
    objectives: {
      system_prompt: { isVisible: true, hintVisible: true, solutionVisible: false },
    },
  };

  expect(reduceDpiDisclosure(EMPTY_DPI_DISCLOSURE, {
    type: 'SOLUTION_LOADED',
    objectiveId: 'system_prompt',
    solution: { title: 'Late response' },
    visibility: disabled,
  })).toEqual(EMPTY_DPI_DISCLOSURE);
});

test('active objective reconciliation clears disabled state and selects the first objective on re-enable', () => {
  const allDisabled = deriveDpiVisibility({
    revision: 6,
    exercises: {
      direct_prompt_injection: {
        isVisible: false,
        objectives: {
          interact: { isVisible: false },
          system_prompt: { isVisible: false },
        },
      },
    },
  });
  expect(reconcileDpiActiveObjective(allDisabled, 'interact', ['interact', 'system_prompt']))
    .toBeNull();
  expect(isDpiExerciseUsable(allDisabled, null)).toBe(false);

  const reenabled = deriveDpiVisibility({
    revision: 7,
    exercises: {
      direct_prompt_injection: {
        isVisible: true,
        objectives: {
          interact: { isVisible: false },
          system_prompt: { isVisible: true },
        },
      },
    },
  });
  expect(reconcileDpiActiveObjective(reenabled, null, ['interact', 'system_prompt']))
    .toBe('system_prompt');
  expect(isDpiExerciseUsable(reenabled, 'system_prompt')).toBe(true);
});
