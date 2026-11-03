// One administrative surface, retaining the canonical identity of every objective.
export const XSS_ADMIN_KEY = 'reflected_xss_llm';
export const XSS_ADMIN_SOURCES = Object.freeze(['reflected_xss_llm', 'xss_email_builder']);
export const XSS_CONFIG_KEYS = Object.freeze(['xss_workshop', 'xss_email_builder']);
export const isXssAdminKey = key => [...XSS_ADMIN_SOURCES, 'xss_workshop'].includes(key);
export const sameAdminExercise = (viewKey, sourceKey) => viewKey === sourceKey
  || (isXssAdminKey(viewKey) && isXssAdminKey(sourceKey));
export function projectXssAdminCard(rows, exercises) {
  const members = rows.filter(row => isXssAdminKey(row.key || row.id));
  const parent = members.find(row => (row.key || row.id) !== 'xss_email_builder') || members[0];
  if (!parent) return null;
  const configurations = members.map(row => ({ row, config: exercises?.[(row.key || row.id) === 'xss_email_builder' ? 'xss_email_builder' : 'xss_workshop'] }));
  const values = field => configurations.map(({ row, config }) => config?.[field] ?? row[field === 'isVisible' ? 'enabled' : field] ?? false);
  const all = field => values(field).every(Boolean);
  const mixed = field => values(field).some(Boolean) && !all(field);
  return { ...parent, key: XSS_ADMIN_KEY,
    name: members.find(row => (row.key || row.id) !== 'xss_email_builder')?.name || 'XSS in AI Powered Chat System',
    enabled: all('isVisible'), showHints: all('showHints'), showSolutions: all('showSolutions'),
    mixed: { active: mixed('isVisible'), hints: mixed('showHints'), solutions: mixed('showSolutions') },
    objectiveEntries: configurations.every(({config}) => config)
      ? configurations.flatMap(({config}) => Object.values(config.objectives || {})) : null,
    // A learner completing both families must be counted once, by the server.
    completions: members.find(row => Number.isFinite(row.displayCompletions))?.displayCompletions ?? null,
  };
}
