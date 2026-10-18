'use strict';
const progress = require('../services/postgresPlatformStores').getPostgresPlatformStores().progress;
module.exports = Object.fromEntries(['syncObjectiveComplete', 'syncWorkshopStarted', 'checkAndMarkWorkshopComplete', 'resetWorkshopProgress', 'getUserWorkshopProgress', 'getCanonicalWorkshopCompletions'].map(name => [name, async (userId, ...args) => {
  if (!userId) return;
  return progress[name](userId, ...args);
}]));
