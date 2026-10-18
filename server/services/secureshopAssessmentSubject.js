'use strict';
const {createLaunchScope}=require('./secureshopConversationBinding');
const subjects=new WeakMap();
const fail=()=>Object.assign(new Error('Shop assessment authority unavailable'),{code:'SHOP_ASSESSMENT_STALE'});
function subjectState(subject){const value=subjects.get(subject);if(!value)throw fail();return value;}
function createSecureShopAssessmentSubjects({identityPool,launches,personaAuthority}) {
  if(typeof identityPool?.query!=='function'||typeof launches?.assertCurrent!=='function'
    ||typeof personaAuthority?.capture!=='function')throw TypeError('Shop assessment authority dependencies required');
  return Object.freeze({async capture(input,execution){
    const scope=createLaunchScope(input.scope);
    if(typeof execution?.check!=='function'||typeof execution.runId!=='string'
      ||typeof execution.ownerKey!=='string'||execution.durableGeneration==null)throw fail();
    await execution.check();await launches.assertCurrent(scope);
    const owner=(await identityPool.query('SELECT realm,shop_tenant_id FROM identity.secureshop_authority_owners WHERE id=$1 AND is_active=1',
      [scope.platformOwnerId])).rows[0];
    if(owner?.realm==='platform'&&owner.shop_tenant_id===null)return null;
    if(owner?.realm!=='shop'||!owner.shop_tenant_id)throw fail();
    const row=(await identityPool.query(`SELECT e.tenant_id,e.principal_id,p.shop_user_id,
      s.membership_version::text FROM secureshop_auth.execution_authority_state e
      JOIN secureshop_auth.principals p ON p.principal_id=e.principal_id
      JOIN secureshop_auth.execution_sessions s ON s.session_id=e.session_id
      WHERE e.session_id=$1 AND e.owner_id=$2 AND e.is_active=1 AND e.expires_at>clock_timestamp()
        AND p.shop_user_id=$3`,[scope.platformSessionId,scope.platformOwnerId,input.personaId])).rows[0];
    if(!row||row.tenant_id!==owner.shop_tenant_id)throw fail();
    const fence=personaAuthority.capture(input);await fence.assertRemoteAdmission();
    const binding=Object.freeze({tenantId:row.tenant_id,principalId:row.principal_id,
      shopUserId:Number(row.shop_user_id),membershipVersion:row.membership_version,scope,
      personaSessionId:input.sessionId,personaAuthorityVersion:input.authorityVersion,role:input.role,
      runId:execution.runId,ownerKey:execution.ownerKey,ownerGeneration:String(execution.durableGeneration)});
    const subject=Object.freeze({});
    subjects.set(subject,Object.freeze({binding,fence,execution,async check(){
      await execution.check();await launches.assertCurrent(scope);await fence.assertRemoteAdmission();
    }}));
    return subject;
  }});
}
module.exports={createSecureShopAssessmentSubjects,subjectState};
