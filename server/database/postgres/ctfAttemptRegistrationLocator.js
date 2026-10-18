'use strict';
// Registration locators label attempt telemetry; they never confer authority.
function validateRegistrationLocator(value){
 if(value===null)return null;
 if(typeof value!=='string'||!value.isWellFormed()||value.includes('\0')||Buffer.byteLength(value)>256)throw TypeError('Invalid CTF registration locator');
 return value;
}
async function resolveAttemptRegistrationLocator(client,scope,value){
 const locator=validateRegistrationLocator(value);
 if(locator===null)return null;
 for(const key of ['ownerId','participantId','ownerGeneration'])if(typeof scope?.[key]!=='string'||!/^\d+$/.test(scope[key]))throw TypeError('Invalid CTF locator scope');
 const row=(await client.query(`SELECT s.session_token FROM ctf.ctf_sessions s
 JOIN ctf.ctf_participants p ON p.id=s.participant_id
 JOIN ctf.projection_scopes a ON a.scope_key='owner:'||p.user_id
 WHERE s.session_token=$1 AND p.id=$2 AND p.user_id=$3 AND a.owner_generation=$4::bigint`,[locator,scope.participantId,scope.ownerId,scope.ownerGeneration])).rows[0];
 return row?.session_token===locator?locator:null;
}
module.exports={validateRegistrationLocator,resolveAttemptRegistrationLocator};
