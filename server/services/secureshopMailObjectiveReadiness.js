'use strict';
// Reviewed release gates, independent of instructor visibility. Serving flags
// cannot qualify an objective. Cleanup is deliberately outside this policy.
const QUALIFICATION=Object.freeze({ss_mail_reply_redirect:true,ss_mail_header_construction:true,ss_mail_cross_persona_read:true,ss_mail_stored_browser_execution:true,ss_mail_agent_html_injection:true,ss_mail_agent_cross_persona_read:true});
function projectMailObjectiveReadiness(qualification,{transportReady=false,judgeReady=false,catalog={}}={}){
 return Object.freeze(Object.fromEntries(Object.keys(QUALIFICATION).map(id=>[id,transportReady===true&&judgeReady===true&&qualification[id]===true&&catalog[id]===true])));
}
function mailObjectiveReadiness(options){return projectMailObjectiveReadiness(QUALIFICATION,options);}
async function readMailObjectiveCatalog(identityPool,scope){
 if(scope!==undefined){
  const enabled=await require('./secureshopAssessmentEligibility').readSecureShopAssessmentEligibility(identityPool,scope,Object.keys(QUALIFICATION));
  return Object.fromEntries(Object.keys(QUALIFICATION).map(id=>[id,enabled.includes(id)]));
 }
 const rows=(await identityPool.query(`SELECT o.objective_id FROM workshop_platform.objectives o
  JOIN workshop_platform.exercises w USING(workshop_key)
  WHERE o.workshop_key=$1 AND o.objective_id=ANY($2::text[])
  AND o.is_enabled AND o.catalog_active AND w.is_visible AND w.catalog_active`,['secureshop_agent_security',Object.keys(QUALIFICATION)])).rows;
 return Object.fromEntries(Object.keys(QUALIFICATION).map(id=>[id,rows.some(row=>row.objective_id===id)]));
}
async function readMailObjectiveReadiness({identityPool,scope,...dependencies}){
 // Pending releases admit no catalog dependency; once an individual reviewed
 // gate is promoted, effective canonical instructor availability is read here.
 const catalog=Object.values(QUALIFICATION).some(x=>x===true)?await readMailObjectiveCatalog(identityPool,scope):{};
 return mailObjectiveReadiness({...dependencies,catalog});
}
module.exports={MAIL_OBJECTIVE_QUALIFICATION:QUALIFICATION,mailObjectiveReadiness,readMailObjectiveReadiness,readMailObjectiveCatalog,projectMailObjectiveReadiness};
