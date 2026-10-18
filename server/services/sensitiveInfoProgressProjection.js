'use strict';

function projectCanonicalSensitiveProgress(snapshot, descriptions = []) {
  if (!snapshot || !Array.isArray(snapshot.objectives)) {
    throw new TypeError('Canonical Sensitive Information progress is required');
  }
  const byId = new Map(descriptions.map(objective => [objective.id, objective]));
  const progress = snapshot.objectives.map(objective => ({
    id: objective.id,
    label: objective.label,
    desc: byId.get(objective.id)?.desc || '',
    completed: objective.completed === true,
    completed_at: objective.completedAt || null,
  }));
  return { success: true, progress,
    completedCount: progress.filter(objective => objective.completed).length,
    total: progress.length };
}

module.exports = { projectCanonicalSensitiveProgress };
