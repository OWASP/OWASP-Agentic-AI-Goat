export const EMPTY_DPI_DISCLOSURE = Object.freeze({
  objectiveId: null,
  solution: null,
});

export function deriveDpiVisibility(snapshot) {
  const exercise = snapshot?.exercises?.direct_prompt_injection;
  if (!exercise) return { isVisible: false, objectives: {} };

  return {
    isVisible: exercise.isVisible === true,
    objectives: Object.fromEntries(
      Object.entries(exercise.objectives || {}).map(([objectiveId, objective]) => [objectiveId, {
        ...(typeof objective?.label === 'string' && objective.label.trim()
          ? { label: objective.label.trim() }
          : {}),
        ...(typeof objective?.description === 'string' && objective.description.trim()
          ? { description: objective.description.trim() }
          : {}),
        isVisible: objective?.isVisible === true,
        hintVisible: objective?.hintVisible === true,
        solutionVisible: objective?.solutionVisible === true,
      }])
    ),
  };
}

export function reconcileDpiActiveObjective(visibility, activeObjectiveId, orderedObjectiveIds) {
  if (!visibility?.isVisible) return null;
  if (activeObjectiveId && visibility.objectives[activeObjectiveId]?.isVisible) {
    return activeObjectiveId;
  }
  return orderedObjectiveIds.find((objectiveId) => visibility.objectives[objectiveId]?.isVisible) || null;
}

export function isDpiExerciseUsable(visibility, activeObjectiveId) {
  return visibility?.isVisible === true
    && Boolean(activeObjectiveId)
    && visibility.objectives[activeObjectiveId]?.isVisible === true;
}

export function reduceDpiDisclosure(state, action) {
  switch (action.type) {
    case 'CONFIG_UPDATED':
      if (state.objectiveId && !action.visibility.objectives[state.objectiveId]?.solutionVisible) {
        return EMPTY_DPI_DISCLOSURE;
      }
      return state;
    case 'SOLUTION_LOADED':
      if (!action.visibility.objectives[action.objectiveId]?.solutionVisible) {
        return EMPTY_DPI_DISCLOSURE;
      }
      return { objectiveId: action.objectiveId, solution: action.solution };
    case 'CONTENT_FAILED':
      return action.status === 403 ? EMPTY_DPI_DISCLOSURE : state;
    case 'CLOSE':
      return EMPTY_DPI_DISCLOSURE;
    default:
      return state;
  }
}
