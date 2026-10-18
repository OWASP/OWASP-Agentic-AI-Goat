'use strict';
const {createLegacyFileSsiResetRepository}=require('../database/postgres/legacyFileSsiResetRepository');
const {createLegacyFileSsiCleanupRepository}=require('../database/postgres/legacyFileSsiCleanupRepository');
const {createLegacyFileSsiReset}=require('./legacyFileSsiReset');
async function createLegacyFileSsiResetComposition({identityPool,finflowPool,runs}={}){
 const journal=createLegacyFileSsiResetRepository(identityPool),cleanup=createLegacyFileSsiCleanupRepository(finflowPool);
 await Promise.all([journal.assertReady(),cleanup.assertReady()]);
 return Object.freeze({reset:createLegacyFileSsiReset({legacyRuns:runs,journal,cleanup}),journal,cleanup});
}
module.exports={createLegacyFileSsiResetComposition};
