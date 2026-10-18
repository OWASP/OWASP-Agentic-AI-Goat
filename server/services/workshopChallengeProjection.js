'use strict';

const solutionRegistry = require('../config/workshopSolutionPaths');

function projectWorkshopChallenge(challenge) {
  return {
    ...challenge,
    difficulty: challenge.difficulty
      ? challenge.difficulty.charAt(0).toUpperCase() + challenge.difficulty.slice(1)
      : challenge.difficulty,
    objectives: (challenge.objectives || []).map((objective) => {
      const registry = solutionRegistry[objective.sourceWorkshopKey || challenge.workshopKey];
      return {
        ...objective,
        solutionEnabled: objective.solutionVisible,
        solutionEndpoint: objective.solutionVisible && registry?.statusPrefix
          ? `/api/solutions/${registry.statusPrefix}/${registry.contentSubpath || ''}${objective.id}`
          : null,
      };
    }),
  };
}

const XSS_WORKSHOP_KEY = 'xss_workshop';
const XSS_CHALLENGE_KEY = 'reflected_xss_llm';
const XSS_BUILDER_KEY = 'xss_email_builder';
const XSS_ROUTE = '/vulnerabilities/xss';
const XSS_TITLE = 'XSS in AI Powered Chat System';

function sourceObjectives(challenge) {
  return (challenge.objectives || []).map(objective => ({
    ...objective,
    // A display card can contain objectives from two independently gated stores.
    // Keep the original keys for hint, solution and progress requests.
    workshopKey: objective.sourceWorkshopKey || objective.workshopKey || challenge.workshopKey,
    challengeKey: objective.sourceChallengeKey || objective.challengeKey || challenge.challengeKey || challenge.id,
    sourceWorkshopKey: objective.sourceWorkshopKey || objective.workshopKey || challenge.workshopKey,
    sourceChallengeKey: objective.sourceChallengeKey || objective.challengeKey || challenge.challengeKey || challenge.id,
  }));
}

function foldXssChallenges(rows) {
  const main = rows.find(row => row.workshopKey === XSS_WORKSHOP_KEY);
  const builder = rows.find(row => row.workshopKey === XSS_BUILDER_KEY);
  if (!builder) return rows;

  const sources = [main, builder].filter(Boolean);
  const objectiveCount = sources.reduce((sum, row) => sum + (Number(row.objectiveCount) || 0), 0);
  const completedObjectiveCount = sources.reduce((sum, row) => sum + (Number(row.completedObjectiveCount) || 0), 0);
  const timeSpentSeconds = sources.reduce((sum, row) => sum + (Number(row.timeSpentSeconds) || 0), 0);
  const canonicalStatus = completedObjectiveCount === 0 ? 'not_started'
    : objectiveCount > 0 && completedObjectiveCount === objectiveCount ? 'completed' : 'in_progress';
  const completed = canonicalStatus === 'completed';
  const completedAt = completed ? sources.map(row => row.completedAt || row.completed_at)
    .filter(Boolean).sort((a, b) => new Date(b) - new Date(a))[0] || null : null;
  const merged = {
    ...(main || builder),
    id: XSS_CHALLENGE_KEY,
    challengeKey: XSS_CHALLENGE_KEY,
    workshopKey: XSS_WORKSHOP_KEY,
    name: main?.name || XSS_TITLE,
    title: main?.title || main?.name || XSS_TITLE,
    route: XSS_ROUTE,
    objectiveCount,
    totalObjectives: objectiveCount,
    completedObjectiveCount,
    completedObjectives: completedObjectiveCount,
    timeSpentSeconds,
    canonicalStatus,
    status: objectiveCount === 0 ? 'locked' : canonicalStatus === 'not_started' ? 'unlocked' : canonicalStatus,
    completed,
    completedAt,
    completed_at: completedAt,
    showHints: sources.some(row => row.showHints === true),
    showSolutions: sources.some(row => row.showSolutions === true),
    objectives: sources.flatMap(sourceObjectives),
  };
  return rows.flatMap(row => row === (main || builder) ? [merged] : row === builder ? [] : [row]);
}

const projectWorkshopChallenges = challenges => foldXssChallenges(challenges.map(projectWorkshopChallenge));

module.exports = { projectWorkshopChallenge, projectWorkshopChallenges };
