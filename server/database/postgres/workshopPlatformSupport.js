'use strict';
const {withTransaction}=require('./index');
function error(code,message){return Object.assign(new Error(message),{code});}
function userId(value){if(typeof value==='string'&&!/^\d+$/.test(value))throw error('AUTH_REQUIRED','Authenticated user ID required');const n=Number(value);if(!Number.isInteger(n)||n<=0||n>2147483647)throw error('AUTH_REQUIRED','Authenticated user ID required');return n;}
function key(value){if(typeof value!=='string'||!/^[a-z0-9][a-z0-9_-]{0,99}$/i.test(value)||['__proto__','constructor','prototype'].includes(value))throw error('BAD_REQUEST','Invalid workshop key');return value;}
async function exercise(client,value){key(value);const row=(await client.query('SELECT * FROM workshop_platform.exercises WHERE (workshop_key=$1 OR challenge_key=$1) AND catalog_active=true',[value])).rows[0];if(!row)throw error('NOT_FOUND','Unknown workshop');return row;}
async function bump(client,{scopeType,scopeKey,category}) {
 if(!['global','workshop','user'].includes(scopeType)||typeof scopeKey!=='string'||typeof category!=='string'||!/^[a-z][a-z0-9_-]{0,99}$/i.test(category)||['__proto__','constructor','prototype'].includes(category))throw error('BAD_REQUEST','Invalid revision scope');
 if(scopeType==='global'&&scopeKey!=='*')throw error('BAD_REQUEST','Global key must be *');
 if(scopeType==='workshop')key(scopeKey);
 if(scopeType==='user')userId(scopeKey);
 return (await client.query('INSERT INTO workshop_platform.revisions(scope_type,scope_key,category,revision) VALUES($1,$2,$3,1) ON CONFLICT(scope_type,scope_key,category) DO UPDATE SET revision=workshop_platform.revisions.revision+1,updated_at=now() RETURNING revision',[scopeType,scopeKey,category])).rows[0].revision;
}
async function ownerTransaction(pool,uid,k,expectedGeneration,work){
 return withTransaction(pool,async client=>{
  uid=userId(uid);const w=await exercise(client,k);
  await client.query('INSERT INTO workshop_platform.user_state(user_id,workshop_key) VALUES($1,$2) ON CONFLICT DO NOTHING',[uid,w.workshop_key]);
  const state=(await client.query('SELECT * FROM workshop_platform.user_state WHERE user_id=$1 AND workshop_key=$2 FOR UPDATE',[uid,w.workshop_key])).rows[0];
  if(expectedGeneration!==undefined&&expectedGeneration!==state.generation)throw error('STALE_GENERATION','Workshop was reset while work was running');
  return work(client,w,state,uid);
 });
}
async function consistentRead(pool,work){return withTransaction(pool,async client=>{await client.query('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY');return work(client);});}
module.exports={error,userId,key,exercise,bump,ownerTransaction,consistentRead};
