export function resolveCsrfDeepLink(search, visibleTabs) {
  const params = new URLSearchParams(search || '');
  const requestedScenario = params.get('scenario');
  const requestedObjective = params.get('objective');
  const objectiveTabIndex = requestedObjective
    ? visibleTabs.findIndex(tab => tab.objectives.some(objective => objective.id === requestedObjective))
    : -1;
  const scenarioTabIndex = requestedScenario
    ? visibleTabs.findIndex(tab => tab.id === requestedScenario && tab.objectives.length > 0)
    : -1;
  const firstVisibleTabIndex = visibleTabs.findIndex(tab => tab.objectives.length > 0);
  const tabIndex = objectiveTabIndex >= 0
    ? objectiveTabIndex
    : scenarioTabIndex >= 0 ? scenarioTabIndex : Math.max(0, firstVisibleTabIndex);
  const objective = objectiveTabIndex >= 0
    ? visibleTabs[objectiveTabIndex].objectives.find(item => item.id === requestedObjective)
    : null;
  return { tabIndex, objectiveId: objective?.payload === true ? objective.id : null };
}
