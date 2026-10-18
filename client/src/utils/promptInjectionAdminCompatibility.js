const PROMPT_INJECTION_EXERCISES = new Set([
  'direct_prompt_injection',
  'indirect_prompt_injection',
]);

async function mutatePromptInjectionMasterSolution(client, challengeKey, enabled, requestConfig) {
  if (!PROMPT_INJECTION_EXERCISES.has(challengeKey)) {
    throw new Error(`Unsupported prompt-injection exercise: ${challengeKey}`);
  }
  const response = await client.patch(
    `/api/admin/exercises/${challengeKey}/solutions`,
    { enabled },
    requestConfig
  );
  return response.data;
}

function gateValueLike(current, enabled) {
  return typeof current === 'number' ? Number(enabled) : Boolean(enabled);
}

function reconcilePromptInjectionExercise({
  challengeKey,
  exercise,
  challenges,
  solutionRows,
  objectiveRows,
  hintMap,
}) {
  const objectiveState = exercise?.objectives || {};
  const solutionIdKey = challengeKey === 'direct_prompt_injection'
    ? 'challengeId'
    : 'objective_id';
  const solutionEnabledKey = challengeKey === 'direct_prompt_injection'
    ? 'solutionsEnabled'
    : 'solutions_enabled';

  return {
    challenges: challenges.map((challenge) =>
      (challenge.key || challenge.id) === challengeKey
        ? Object.assign({}, challenge, { showSolutions: Boolean(exercise.showSolutions) })
        : challenge),
    solutionRows: solutionRows.map((row) => {
      const gate = objectiveState[row[solutionIdKey]]?.raw?.solutionEnabled;
      if (gate === undefined) return row;
      const update = { [solutionEnabledKey]: gateValueLike(row[solutionEnabledKey], gate) };
      return Object.assign({}, row, update);
    }),
    objectiveRows: objectiveRows.map((row) => {
      const gate = objectiveState[row.objective_id]?.raw?.objectiveEnabled;
      return gate === undefined
        ? row
        : Object.assign({}, row, { is_enabled: gateValueLike(row.is_enabled, gate) });
    }),
    hintMap: Object.fromEntries(Object.entries(hintMap).map(([objectiveId, current]) => {
      const gate = objectiveState[objectiveId]?.raw?.hintEnabled;
      return [objectiveId, gate === undefined ? current : Boolean(gate)];
    })),
  };
}

module.exports = {
  PROMPT_INJECTION_EXERCISES,
  mutatePromptInjectionMasterSolution,
  reconcilePromptInjectionExercise,
};
