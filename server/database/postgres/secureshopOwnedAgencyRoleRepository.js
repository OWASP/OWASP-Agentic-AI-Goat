'use strict';
const {isDeepStrictEqual:equal}=require('node:util');
const {createLaunchScope}=require('../../services/secureshopConversationBinding');
const {canonicalDigest}=require('../../services/mcp/protocolContext');
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[0-9a-f]{12}$/;
const HASH=/^[a-f0-9]{64}$/;
const fail=code=>Object.assign(Error('Owned teaching role unavailable'),{code});
const exact=(x,keys)=>x&&Object.getPrototypeOf(x)===Object.prototype&&equal(Object.keys(x).sort(),[...keys].sort());
const positive=x=>Number.isSafeInteger(x)&&x>0;
const text=(x,max)=>typeof x==='string'&&x.length>0&&x.isWellFormed()&&!x.includes('\0')&&Buffer.byteLength(x)<=max;
const hex=x=>Buffer.isBuffer(x)?x.toString('hex'):x;
function context(raw){
 const scope=createLaunchScope(raw?.scope),{scene,persona,personaSession}=raw;
 if(!exact(scene,['targetId','sceneId','sceneGeneration','grantId'])
  ||![scene.targetId,scene.sceneId,scene.grantId].every(x=>UUID.test(x||''))||!positive(scene.sceneGeneration)
  ||!exact(persona,['id','role'])||!positive(persona.id)||persona.id>2147483647||persona.role!=='customer'
  ||!exact(personaSession,['sessionId','authorityVersion'])||!UUID.test(personaSession.sessionId||'')
  ||typeof personaSession.authorityVersion!=='string'||!/^[1-9]\d{0,18}$/.test(personaSession.authorityVersion))throw fail('AGENCY_ROLE_INVALID');
 return {scope,scene:structuredClone(scene),persona:structuredClone(persona),personaSession:structuredClone(personaSession)};
}
function targetIdentity(c){return {scope:c.scope,scene:c.scene,persona:c.persona};}
function targetKey(c){return canonicalDigest(['owned-agency-role-target-v1',targetIdentity(c)]);}
function reference(raw){
 if(!exact(raw,['requestId','runId','callId','effectKey'])||![raw.requestId,raw.runId].every(x=>UUID.test(x||''))
  ||!text(raw.callId,256)||!text(raw.effectKey,1024))throw fail('AGENCY_ROLE_INVALID');
 return structuredClone(raw);
}
function request(raw){
 const c=context(raw),ref=reference(Object.fromEntries(['requestId','runId','callId','effectKey'].map(k=>[k,raw[k]])));
 const {step,args,modeExecution:m,policyAdmission:p}=raw;
 if(!positive(step)||step>100||!exact(args,['user_id','role'])||args.user_id!==c.persona.id||args.role!=='admin'
  ||!exact(m,['version','featureId','policyVersion','mode','generation','modeStamp','scope'])||m.version!==1
  ||m.featureId!=='customer_chat'||m.policyVersion!=='owned-catalog-and-cart-read-v1'
  ||!['vuln','fixed'].includes(m.mode)||!Number.isSafeInteger(m.generation)||m.generation<0
  ||!text(m.modeStamp,1024)||!equal(m.scope,c.scope)
  ||!exact(p,['admissionId','runId','invocationId','toolKey','policyVersion','registrySha256','enforcement','allowed','action','policyViolation'])
  ||!UUID.test(p.admissionId||'')||p.runId!==ref.runId||p.invocationId!==`${step}:${ref.callId}`
  ||p.toolKey!=='user-management.set_role'||typeof p.policyVersion!=='string'||!/^[1-9]\d{0,18}$/.test(p.policyVersion)
  ||!HASH.test(p.registrySha256||'')||typeof p.enforcement!=='boolean'||typeof p.allowed!=='boolean'
  ||!['dispatch','block'].includes(p.action)||![null,'denied-by-acl'].includes(p.policyViolation)
  ||ref.effectKey!==JSON.stringify([step,ref.callId,'user-management.set_role']))throw fail('AGENCY_ROLE_INVALID');
 const result={...c,...ref,step,args:structuredClone(args),modeExecution:structuredClone(m),policyAdmission:structuredClone(p)};
 if(Buffer.byteLength(JSON.stringify(result))>12000)throw fail('AGENCY_ROLE_INVALID');
 return result;
}
function validateAgencyRoleReceipt(raw,original){
 const q=request(original),keys=[...Object.keys(q),'version','before','after','changed','requestSha256','receiptSha256'];
 if(!exact(raw,keys)||raw.version!==1||Object.keys(q).some(k=>!equal(raw[k],q[k]))
  ||!exact(raw.before,['role','revision'])||!exact(raw.after,['role','revision'])
  ||!equal(raw.after,{role:'admin',revision:'2'})
  ||!((equal(raw.before,{role:'customer',revision:'1'})&&raw.changed===true)
   ||(equal(raw.before,{role:'admin',revision:'2'})&&raw.changed===false))
  ||raw.requestSha256!==canonicalDigest(q)||!HASH.test(raw.receiptSha256||'')
  ||q.modeExecution.mode!=='vuln'||q.policyAdmission.allowed!==false||q.policyAdmission.enforcement!==false
  ||q.policyAdmission.action!=='dispatch'||q.policyAdmission.policyViolation!=='denied-by-acl')throw fail('AGENCY_ROLE_INTEGRITY');
 const {receiptSha256,...body}=raw;if(canonicalDigest(body)!==receiptSha256)throw fail('AGENCY_ROLE_INTEGRITY');
 return Object.freeze(structuredClone(raw));
}
// Trusted composition holds the branded scene lease and withPersonaEffect.
// Every method uses that SAME agents client; none opens a pool/transaction.
function createSecureShopOwnedAgencyRoleRepository(){
 function client(c){if(typeof c?.query!=='function')throw fail('AGENCY_ROLE_INVALID');}
 async function current(c,b){
  client(c);
  const row=(await c.query(`SELECT * FROM secureshop_agents.owned_agency_role_targets WHERE target_key=$1 FOR UPDATE`,[targetKey(b)])).rows[0];
  if(!row)return null;
  const expected=[b.scope.launchId,b.scope.scenarioId,b.scope.generation,b.scope.platformOwnerId,b.scope.platformSessionId,
   b.scene.targetId,b.scene.sceneId,b.scene.sceneGeneration,b.scene.grantId,b.persona.id];
  const actual=[row.platform_launch_id,row.platform_scenario_id,Number(row.platform_launch_generation),Number(row.original_platform_owner_id),Number(row.original_platform_session_id),
   row.target_id,row.scene_id,Number(row.scene_generation),row.grant_id,Number(row.customer_id)];
  if(row.target_key!==targetKey(b)||!equal(expected,actual)
   ||!((row.teaching_role==='customer'&&String(row.revision)==='1')||(row.teaching_role==='admin'&&String(row.revision)==='2')))
   throw fail('AGENCY_ROLE_INTEGRITY');
  if(row.lifecycle!=='active')throw fail('AGENCY_ROLE_RETIRED');
  return {version:1,...targetIdentity(b),teachingRole:row.teaching_role,revision:String(row.revision),lifecycle:'active'};
 }
 async function readEffect(c,b,ref){
  const rows=(await c.query(`SELECT * FROM secureshop_agents.owned_agency_role_effects
   WHERE target_key=$1 AND ((request_id=$2 AND call_id=$4) OR (run_id=$3 AND effect_key=$5))`,
  [targetKey(b),ref.requestId,ref.runId,ref.callId,ref.effectKey])).rows;
  if(!rows.length)return null;
  if(rows.length!==1)throw fail('AGENCY_ROLE_CONFLICT');
  const r=rows[0],q=r.request_json;
  if(r.request_id!==ref.requestId||r.run_id!==ref.runId||r.call_id!==ref.callId||r.effect_key!==ref.effectKey
   ||!q||Object.keys(b).some(k=>!equal(q[k],b[k]))||Object.keys(ref).some(k=>q[k]!==ref[k])
   ||hex(r.request_sha256)!==canonicalDigest(q))throw fail('AGENCY_ROLE_CONFLICT');
  const receipt=validateAgencyRoleReceipt(r.receipt_json,q);
  if(hex(r.receipt_sha256)!==receipt.receiptSha256)throw fail('AGENCY_ROLE_INTEGRITY');
  return receipt;
 }
 return Object.freeze({
  async ensureWithClient(c,raw){
   const b=context(raw);client(c);
   await c.query(`INSERT INTO secureshop_agents.owned_agency_role_targets
    (target_key,platform_launch_id,platform_scenario_id,platform_launch_generation,original_platform_owner_id,
     original_platform_session_id,target_id,scene_id,scene_generation,grant_id,customer_id)
    VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) ON CONFLICT DO NOTHING`,
   [targetKey(b),b.scope.launchId,b.scope.scenarioId,b.scope.generation,b.scope.platformOwnerId,b.scope.platformSessionId,
    b.scene.targetId,b.scene.sceneId,b.scene.sceneGeneration,b.scene.grantId,b.persona.id]);
   const value=await current(c,b);if(!value)throw fail('AGENCY_ROLE_CONFLICT');return value;
  },
  async readWithClient(c,raw){return current(c,context(raw));},
  async applyWithClient(c,raw){
   const q=request(raw);client(c);
   if(q.modeExecution.mode!=='vuln'||q.policyAdmission.allowed!==false||q.policyAdmission.enforcement!==false
    ||q.policyAdmission.action!=='dispatch'||q.policyAdmission.policyViolation!=='denied-by-acl')throw fail('AGENCY_ROLE_DENIED');
   const before=await current(c,q);if(!before)throw fail('AGENCY_ROLE_NOT_FOUND');
   const ref=reference(Object.fromEntries(['requestId','runId','callId','effectKey'].map(k=>[k,q[k]])));
   const previous=await readEffect(c,context(q),ref);
   if(previous){if(previous.requestSha256!==canonicalDigest(q))throw fail('AGENCY_ROLE_CONFLICT');
    if(previous.after.role!==before.teachingRole||previous.after.revision!==before.revision)throw fail('AGENCY_ROLE_INTEGRITY');
    return {receipt:previous,replayed:true};}
   const changed=before.teachingRole==='customer';
   if(changed){const updated=await c.query(`UPDATE secureshop_agents.owned_agency_role_targets
    SET teaching_role='admin',revision=2 WHERE target_key=$1 AND lifecycle='active' AND teaching_role='customer' AND revision=1`,[targetKey(q)]);
    if(updated.rowCount!==1)throw fail('AGENCY_ROLE_CONFLICT');}
   const body={version:1,...q,before:{role:before.teachingRole,revision:before.revision},after:{role:'admin',revision:'2'},
    changed,requestSha256:canonicalDigest(q)};
   const receipt=validateAgencyRoleReceipt({...body,receiptSha256:canonicalDigest(body)},q);
   await c.query(`INSERT INTO secureshop_agents.owned_agency_role_effects
    (target_key,request_id,run_id,call_id,effect_key,request_json,request_sha256,receipt_json,receipt_sha256)
    VALUES($1,$2,$3,$4,$5,$6::jsonb,decode($7,'hex'),$8::jsonb,decode($9,'hex'))`,
   [targetKey(q),q.requestId,q.runId,q.callId,q.effectKey,JSON.stringify(q),receipt.requestSha256,JSON.stringify(receipt),receipt.receiptSha256]);
   return {receipt,replayed:false};
  },
  async readEffectWithClient(c,raw,rawRef){
   const b=context(raw),ref=reference(rawRef),state=await current(c,b);if(!state)return null;
   const receipt=await readEffect(c,b,ref);
   if(receipt&&(receipt.after.role!==state.teachingRole||receipt.after.revision!==state.revision))throw fail('AGENCY_ROLE_INTEGRITY');
   return receipt;
  },
  async retireWithClient(c,rawScope){
   client(c);const s=createLaunchScope(rawScope);
   const result=await c.query(`UPDATE secureshop_agents.owned_agency_role_targets SET lifecycle='retired'
    WHERE platform_launch_id=$1 AND platform_scenario_id=$2 AND platform_launch_generation=$3
     AND original_platform_owner_id=$4 AND original_platform_session_id=$5 AND lifecycle='active'`,
   [s.launchId,s.scenarioId,s.generation,s.platformOwnerId,s.platformSessionId]);return result.rowCount;
  },
 });
}
module.exports={createSecureShopOwnedAgencyRoleRepository,validateAgencyRoleReceipt};
