'use strict';
const { projectCanonicalSensitiveProgress } = require('./sensitiveInfoProgressProjection');

async function readSensitiveInfoPresentation({ platformStores, userId, workshopKey, objectives, getSsrfExamples }) {
  if (!platformStores?.progress || !platformStores?.config) throw new TypeError('Canonical platform stores required');
  const [progressSnapshot, configSnapshot] = await Promise.all([
    platformStores.progress.getWorkshopProgress(userId, workshopKey),
    platformStores.config.getSnapshot(),
  ]);
  const projection = projectCanonicalSensitiveProgress(progressSnapshot, objectives);
  const configured = configSnapshot.exercises?.[workshopKey]?.objectives || {};
  const solutionStatus = Object.fromEntries(Object.entries(configured)
    .map(([id, objective]) => [id, objective.solutionVisible === true]));
  return {
    ...projection,
    solutionStatus,
    ssrfExamples: getSsrfExamples(solutionStatus),
  };
}

module.exports = { readSensitiveInfoPresentation };
