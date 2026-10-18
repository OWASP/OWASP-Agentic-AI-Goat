'use strict';
// Caller owns current authority, owner/launch/credential locks and transaction.
// This is the same scoped credential overlay SQL used by self-service change.
async function writePersonaCredential(client,{scope:s,shopUserId,passwordHash,credentialVersion}){
 if(!/^\$2[aby]\$\d\d\$[./A-Za-z0-9]{53}$/.test(passwordHash)||!Number.isSafeInteger(shopUserId)||shopUserId<1||!/^[2-9]$|^[1-9]\d+$/.test(String(credentialVersion)))throw TypeError('Validated credential replacement required');
 await client.query(`INSERT INTO secureshop_agents.bound_persona_credentials
 (platform_launch_id,platform_scenario_id,platform_launch_generation,original_platform_owner_id,original_platform_session_id,shop_user_id,password_hash,credential_version)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8)
 ON CONFLICT(platform_launch_id,platform_scenario_id,platform_launch_generation,original_platform_owner_id,original_platform_session_id,shop_user_id)
 DO UPDATE SET password_hash=EXCLUDED.password_hash,credential_version=EXCLUDED.credential_version`,[s.launchId,s.scenarioId,s.generation,s.platformOwnerId,s.platformSessionId,shopUserId,passwordHash,credentialVersion]);
}
module.exports={writePersonaCredential};
