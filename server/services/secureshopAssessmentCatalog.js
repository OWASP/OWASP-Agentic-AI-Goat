'use strict';
const {assertSecureShopStandalonePrincipal,assertSecureShopStandaloneAuthPrincipal}=require('./secureshopStandaloneAuth');
const {isAssessmentReleaseAllowed}=require('../config/secureshopCurriculum');
const fail=code=>Object.assign(Error('Shop assessment configuration unavailable'),{code});
function createSecureShopAssessmentCatalog({pool,authService}){
  if(typeof pool?.query!=='function'||typeof authService?.establishTenantContext!=='function')throw TypeError('Shop assessment catalog dependencies required');
  async function context(base){if(assertSecureShopStandaloneAuthPrincipal(base).role!=='admin')throw fail('SHOP_ADMIN_REQUIRED');const value=assertSecureShopStandalonePrincipal(await authService.establishTenantContext(base));if(value.role!=='admin')throw fail('SHOP_ADMIN_REQUIRED');return value;}
  const dto=row=>({objectiveId:row.objective_id,enabled:isAssessmentReleaseAllowed(row.objective_id)&&row.is_enabled,qualification:isAssessmentReleaseAllowed(row.objective_id)?row.qualification:'pending',revision:row.revision});
  return Object.freeze({
    async list(base){const c=await context(base);const rows=(await pool.query(`SELECT o.objective_id,o.label,o.qualification,
      COALESCE(c.is_enabled,o.is_enabled) AS is_enabled,COALESCE(c.revision,1)::text AS revision
      FROM secureshop_auth.assessment_objectives o LEFT JOIN secureshop_auth.assessment_configuration c
      ON c.objective_id=o.objective_id AND c.tenant_id=$1 WHERE o.catalog_active ORDER BY o.objective_id`,[c.tenantId])).rows;
      return {objectives:rows.map(row=>({...dto(row),label:row.label}))};},
    async set(base,input){const c=await context(base);
      if(!input||Object.keys(input).sort().join(',')!=='enabled,expectedRevision,objectiveId'||typeof input.enabled!=='boolean'
        ||typeof input.objectiveId!=='string'||!/^ss_[a-z0-9_]{1,100}$/.test(input.objectiveId)
        ||typeof input.expectedRevision!=='string'||! /^[1-9][0-9]{0,18}$/.test(input.expectedRevision)
        ||BigInt(input.expectedRevision)>=9223372036854775807n)throw fail('INVALID_ARGUMENT');
      if(input.enabled&&!isAssessmentReleaseAllowed(input.objectiveId))throw fail('SHOP_OBJECTIVE_UNQUALIFIED');
      try{return dto((await pool.query('SELECT * FROM secureshop_auth.set_assessment_objective($1,$2,$3,$4,$5,$6)',
        [c.sessionId,c.tenantId,c.principalId,input.objectiveId,input.enabled,input.expectedRevision])).rows[0]);}
      catch(error){if(error.code==='40001')throw fail('SHOP_OBJECTIVE_CONFLICT');if(error.code==='22023')throw fail('SHOP_OBJECTIVE_UNQUALIFIED');if(error.code==='28000')throw fail('SHOP_ADMIN_REQUIRED');throw error;}
    },
  });
}
module.exports={createSecureShopAssessmentCatalog};
