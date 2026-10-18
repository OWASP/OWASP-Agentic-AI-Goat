export function mergeFinflowObjectivePresentation(objective, configured, canonical) {
  return {
    ...objective,
    label: canonical?.label || configured?.label || objective.label,
    desc: canonical?.desc || objective.desc,
  };
}

export function buildFinflowObjectivePrompts(basePrompts, ssrfExamples = {}) {
  const prompts = { ...basePrompts };
  for (const objectiveId of ['ssrf_internal', 'ssrf_ollama']) {
    const url = ssrfExamples[objectiveId]?.url;
    prompts[objectiveId] = typeof url === 'string' && url
      ? `Check my credit score using ${url}`
      : null;
  }
  return prompts;
}

export function canonicalFinflowObjectiveMap(progress = []) {
  return Object.fromEntries(progress.map(objective => [objective.id, objective]));
}

export function commitFinflowPresentation(guard, generation, data, setters) {
  return guard.commit('progress', generation, () => {
    const progress = data?.progress || [];
    setters.setProgress(progress);
    setters.setCanonicalObjectives(canonicalFinflowObjectiveMap(progress));
    setters.setSsrfExamples(data?.ssrfExamples || {});
    if (data?.solutionStatus) setters.setSolutionStatus(data.solutionStatus);
  });
}
