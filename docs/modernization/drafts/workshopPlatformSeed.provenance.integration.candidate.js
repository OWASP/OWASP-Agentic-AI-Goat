'use strict';

// This is the production-shaped wrapper for the separately qualified seed
// factory. It is staged here so the active startup seed cannot change before
// the provenance migrations and populated-store transition are promoted.
const {withTransaction}=require('./index');
const {WORKSHOP_OBJECTIVES,toChallengeKey}=require('../../config/workshopCatalog');
const challengeFixtures=require('../../../db/postgres/workshopChallengeFixtures');
const hintFixtures=require('../../data/workshopHints');
const {bump}=require('./workshopPlatformSupport');
const legacyXssSolutions=require('../../data/xssWorkshopSolutions').solutions;
const provenance=require('./catalogDefaultProvenance');
const {createWorkshopPlatformSeed}=require('./workshopPlatformSeedCore');

// The version is audit metadata. Canonical document hashes, rather than this
// label, determine whether a managed value needs an update.
const CATALOG_VERSION='workshop-defaults-2026-09-14-v1';

function solutionFixtures(){
 const arrayMap=rows=>Object.fromEntries(rows.map(row=>[row.objective_id||row.id,row]));
 return {
  secureshop_agent_security:require('../../config/secureshopCurriculum').SOLUTIONS,
  direct_prompt_injection:require('../../data/promptInjectionSolutions').solutions,
  indirect_prompt_injection:require('../../data/indirectPromptInjectionSolutions'),
  xss_workshop:arrayMap(require('../../data/xssWorkshopSolutions').objectiveSolutions),
  csrf_workshop:arrayMap(require('../../data/csrfWorkshopSolutions').objectiveSolutions),
  sensitive_info_disclosure:require('../../data/sensitiveInfoSolutions').solutions,
  supply_chain_rce:require('../../data/supplyChainSolutions').solutions,
  excessive_agency:require('../../data/excessiveAgencySolutions').solutions,
  mcp_workshop:require('../../data/mcpWorkshopSolutions'),
  sql_injection_workshop:require('../../data/postgres/sqlInjectionWorkshopSolutions')(require('../../data/sqlInjectionWorkshopSolutions')),
  nosql_injection_workshop:require('../../data/postgres/nosqlInjectionWorkshopSolutions')(require('../../data/nosqlInjectionWorkshopSolutions')),
 };
}

const seed=createWorkshopPlatformSeed({withTransaction,bump,provenance,toChallengeKey,legacyXssSolutions});
function seedWorkshopPlatform(pool,{catalog=WORKSHOP_OBJECTIVES,hints=hintFixtures,
 solutions=solutionFixtures(),challenges=challengeFixtures,catalogVersion=CATALOG_VERSION}={}){
 return seed(pool,{catalog,hints,solutions,challenges,catalogVersion});
}

module.exports={CATALOG_VERSION,solutionFixtures,seedWorkshopPlatform};
