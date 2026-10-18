'use strict';
// Protected identity-store recovery. No bound launch, persona, or workshop
// coordinate can satisfy this distinct AAD domain.
const {createCipheriv,createDecipheriv,randomBytes}=require('node:crypto');
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const TOKEN=/^[A-Za-z0-9_-]{32,128}$/;
const VERSION=/^[1-9]\d{0,18}$/;
const KEYS=['version','operationId','tenantId','actorPrincipalId','actorAuthSessionId','actorExecutionSessionId','actorMembershipVersion','actorAuthorityVersion','targetPrincipalId','targetId','expectedCredentialVersion','expectedAuthorityVersion','expectedMembershipVersion','credentialVersion','authorityVersion','receiptSha256','expiresAt'];
const fail=()=>Object.assign(Error('Registered reset recovery unavailable'),{code:'REGISTERED_RESET_RECOVERY_UNAVAILABLE'});
const exact=(value,keys)=>value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).sort().join(',')===[...keys].sort().join(',');
function receiptContext(value){
 if(!exact(value,KEYS)||value.version!==1||![value.operationId,value.tenantId,value.actorPrincipalId,value.targetPrincipalId].every(x=>typeof x==='string'&&UUID.test(x))
  ||![value.actorAuthSessionId,value.actorExecutionSessionId,value.targetId].every(x=>Number.isSafeInteger(x)&&x>0)
  ||![value.actorMembershipVersion,value.actorAuthorityVersion,value.expectedCredentialVersion,value.expectedAuthorityVersion,value.expectedMembershipVersion,value.credentialVersion,value.authorityVersion].every(x=>typeof x==='string'&&VERSION.test(x))
  ||value.actorPrincipalId===value.targetPrincipalId||!/^[a-f0-9]{64}$/.test(value.receiptSha256)
  ||typeof value.expiresAt!=='string'||!Number.isFinite(Date.parse(value.expiresAt))||new Date(value.expiresAt).toISOString()!==value.expiresAt)throw fail();
 // PostgreSQL jsonb reorders object keys. Keep AAD independent of wire order.
 return Object.freeze(Object.fromEntries(KEYS.map(key=>[key,value[key]])));
}
function createRegisteredAdminResetEnvelope({activeKeyId,keys,now=Date.now}={}){
 if(typeof activeKeyId!=='string'||!/^[A-Za-z0-9_-]{1,64}$/.test(activeKeyId)||!(keys instanceof Map)||typeof now!=='function')throw TypeError('Private registered reset key ring required');
 const ring=new Map();for(const [id,key]of keys){if(typeof id!=='string'||!/^[A-Za-z0-9_-]{1,64}$/.test(id)||!Buffer.isBuffer(key)||key.length!==32)throw TypeError('Private registered reset key ring required');ring.set(id,Buffer.from(key));}
 if(!ring.has(activeKeyId))throw TypeError('Active registered reset key unavailable');
 const deadline=receipt=>{const time=now();if(!Number.isFinite(time)||Date.parse(receipt.expiresAt)<=time)throw fail();return time;};
 const aad=(receipt,keyId)=>Buffer.from(JSON.stringify(['secureshop-registered-admin-reset-envelope',1,keyId,receipt]));
 const decode=(text,min,max)=>{if(typeof text!=='string'||text.length>max*2||!/^[A-Za-z0-9_-]+$/.test(text))throw fail();const value=Buffer.from(text,'base64url');if(value.length<min||value.length>max||value.toString('base64url')!==text)throw fail();return value;};
 return Object.freeze({
  seal({receipt:raw,secret}){const receipt=receiptContext(raw),time=deadline(receipt);if(Date.parse(receipt.expiresAt)>time+15*60*1000||typeof secret!=='string'||!TOKEN.test(secret))throw fail();const nonce=randomBytes(12),cipher=createCipheriv('aes-256-gcm',ring.get(activeKeyId),nonce);cipher.setAAD(aad(receipt,activeKeyId));const ciphertext=Buffer.concat([cipher.update(secret,'utf8'),cipher.final()]);return Object.freeze({version:1,keyId:activeKeyId,nonce:nonce.toString('base64url'),ciphertext:ciphertext.toString('base64url'),tag:cipher.getAuthTag().toString('base64url')});},
  open({receipt:raw,envelope}){try{const receipt=receiptContext(raw);deadline(receipt);if(!exact(envelope,['version','keyId','nonce','ciphertext','tag'])||envelope.version!==1||!ring.has(envelope.keyId))throw fail();const decipher=createDecipheriv('aes-256-gcm',ring.get(envelope.keyId),decode(envelope.nonce,12,12));decipher.setAAD(aad(receipt,envelope.keyId));decipher.setAuthTag(decode(envelope.tag,16,16));const secret=Buffer.concat([decipher.update(decode(envelope.ciphertext,32,128)),decipher.final()]).toString('utf8');if(!TOKEN.test(secret))throw fail();return secret;}catch{throw fail();}}
 });
}
module.exports={createRegisteredAdminResetEnvelope,receiptContext};
