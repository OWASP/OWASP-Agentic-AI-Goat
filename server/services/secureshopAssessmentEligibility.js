'use strict';
const {isAssessmentReleaseAllowed}=require('../config/secureshopCurriculum');
const {createLaunchScope}=require('./secureshopConversationBinding');
async function readSecureShopAssessmentEligibility(pool,raw,objectiveIds){
  const scope=createLaunchScope(raw);
  if(!Array.isArray(objectiveIds)||objectiveIds.length>64||objectiveIds.some(id=>typeof id!=='string'))throw TypeError('Objective IDs required');
  objectiveIds=objectiveIds.filter(isAssessmentReleaseAllowed);
  if(!objectiveIds.length)return [];
  const owner=(await pool.query('SELECT realm,shop_tenant_id FROM identity.secureshop_authority_owners WHERE id=$1 AND is_active=1',[scope.platformOwnerId])).rows[0];
  if(owner?.realm==='platform'&&owner.shop_tenant_id===null)return (await pool.query(`SELECT o.objective_id FROM workshop_platform.objectives o
    JOIN workshop_platform.exercises w USING(workshop_key) WHERE o.workshop_key=$1 AND o.objective_id=ANY($2::text[])
    AND o.is_enabled AND o.catalog_active AND w.is_visible AND w.catalog_active`,['secureshop_agent_security',objectiveIds])).rows.map(row=>row.objective_id).filter(isAssessmentReleaseAllowed);
  if(owner?.realm!=='shop'||!owner.shop_tenant_id)throw Object.assign(Error('Assessment realm unavailable'),{code:'SHOP_ASSESSMENT_STALE'});
  return (await pool.query(`SELECT o.objective_id FROM secureshop_auth.assessment_objectives o
    LEFT JOIN secureshop_auth.assessment_configuration c ON c.objective_id=o.objective_id AND c.tenant_id=$1
    WHERE o.objective_id=ANY($2::text[]) AND o.catalog_active AND COALESCE(c.is_enabled,o.is_enabled)
      AND o.qualification IN ('native-model','native-browser-judge')`,[owner.shop_tenant_id,objectiveIds])).rows.map(row=>row.objective_id).filter(isAssessmentReleaseAllowed);
}
module.exports={readSecureShopAssessmentEligibility};
