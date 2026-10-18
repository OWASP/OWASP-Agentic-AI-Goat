'use strict';
// Candidate qualification seam; supported startup does not call this until publication is reviewed.
const curriculum=require('../../config/legacyFileSsiCurriculum');
async function seedLegacyFileSsiCandidate(pool){
 const seed=require('./workshopPlatformSeed');
 return seed.seedWorkshopPlatform(pool,{
  catalog:{...require('../../config/workshopCatalog').WORKSHOP_OBJECTIVES,[curriculum.WORKSHOP_KEY]:curriculum.OBJECTIVES},
  challenges:[...require('../../../db/postgres/workshopChallengeFixtures').filter(row=>row.key!==curriculum.WORKSHOP_KEY),curriculum.CHALLENGE],
  hints:{...require('../../data/workshopHints'),[curriculum.WORKSHOP_KEY]:curriculum.HINTS},
  solutions:{...seed.solutionFixtures(),[curriculum.WORKSHOP_KEY]:curriculum.SOLUTIONS},
  catalogVersion:'legacy-file-ssi-candidate-v1',
 });
}
module.exports={seedLegacyFileSsiCandidate};
