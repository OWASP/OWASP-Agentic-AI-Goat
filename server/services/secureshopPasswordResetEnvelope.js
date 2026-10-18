'use strict';
// Private cryptographic leaf only. Callers must independently verify current
// original-admin authority and immutable receipt before decrypting or revealing.
const {createCipheriv,createDecipheriv,randomBytes}=require('node:crypto');
const {createLaunchScope}=require('./secureshopConversationBinding');
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const KEYS=['operationId','scope','actorId','actorSessionId','actorAuthorityVersion','targetId','credentialVersion','authorityVersion','receiptSha256','expiresAt'];
const fail=()=>Object.assign(Error('Password reset recovery unavailable'),{code:'PASSWORD_RESET_RECOVERY_UNAVAILABLE'});
const exact=(value,keys)=>value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).sort().join(',')===[...keys].sort().join(',');
function context(input){
 if(!exact(input,KEYS))throw fail();
 const c=structuredClone(input),scope=createLaunchScope(c.scope);
 if(!exact(c.scope,Object.keys(scope))||!UUID.test(c.operationId)||!UUID.test(c.actorSessionId)||![c.actorId,c.targetId].every(n=>Number.isSafeInteger(n)&&n>0)||c.actorId===c.targetId||![c.actorAuthorityVersion,c.credentialVersion,c.authorityVersion].every(n=>typeof n==='string'&&/^[1-9]\d{0,18}$/.test(n))||!/^[a-f0-9]{64}$/.test(c.receiptSha256)||typeof c.expiresAt!=='string'||!Number.isFinite(Date.parse(c.expiresAt))||new Date(c.expiresAt).toISOString()!==c.expiresAt)throw fail();
 return {operationId:c.operationId,scope,actorId:c.actorId,actorSessionId:c.actorSessionId,actorAuthorityVersion:c.actorAuthorityVersion,targetId:c.targetId,credentialVersion:c.credentialVersion,authorityVersion:c.authorityVersion,receiptSha256:c.receiptSha256,expiresAt:c.expiresAt};
}
function createPasswordResetEnvelope({activeKeyId,keys,now=Date.now}={}){
 if(typeof activeKeyId!=='string'||!/^[A-Za-z0-9_-]{1,64}$/.test(activeKeyId)||!(keys instanceof Map)||typeof now!=='function')throw TypeError('Private reset key ring required');
 const ring=new Map();for(const [id,key]of keys){if(typeof id!=='string'||!/^[A-Za-z0-9_-]{1,64}$/.test(id)||!Buffer.isBuffer(key)||key.length!==32)throw TypeError('Private reset key ring required');ring.set(id,Buffer.from(key));}
 if(!ring.has(activeKeyId))throw TypeError('Active reset key unavailable');
 function deadline(c){const time=now();if(!Number.isFinite(time)||Date.parse(c.expiresAt)<=time)throw fail();return time;}
 function aad(c,keyId){return Buffer.from(JSON.stringify(['secureshop-password-reset-envelope',1,keyId,c]));}
 return Object.freeze({
  seal({receipt,secret}){const c=context(receipt),time=deadline(c);if(Date.parse(c.expiresAt)>time+15*60*1000||typeof secret!=='string'||!/^[A-Za-z0-9_-]{32,128}$/.test(secret))throw fail();const nonce=randomBytes(12),cipher=createCipheriv('aes-256-gcm',ring.get(activeKeyId),nonce);cipher.setAAD(aad(c,activeKeyId));const encrypted=Buffer.concat([cipher.update(secret,'utf8'),cipher.final()]);return Object.freeze({version:1,keyId:activeKeyId,nonce:nonce.toString('base64url'),ciphertext:encrypted.toString('base64url'),tag:cipher.getAuthTag().toString('base64url')});},
  open({receipt,envelope}){try{const c=context(receipt);deadline(c);if(!exact(envelope,['version','keyId','nonce','ciphertext','tag'])||envelope.version!==1||!ring.has(envelope.keyId))throw fail();const decode=(value,min,max)=>{if(typeof value!=='string'||value.length>max*2||!/^[A-Za-z0-9_-]+$/.test(value))throw fail();const bytes=Buffer.from(value,'base64url');if(bytes.length<min||bytes.length>max||bytes.toString('base64url')!==value)throw fail();return bytes;};const nonce=decode(envelope.nonce,12,12),tag=decode(envelope.tag,16,16),encrypted=decode(envelope.ciphertext,32,128),decipher=createDecipheriv('aes-256-gcm',ring.get(envelope.keyId),nonce);decipher.setAAD(aad(c,envelope.keyId));decipher.setAuthTag(tag);const secret=Buffer.concat([decipher.update(encrypted),decipher.final()]).toString('utf8');if(!/^[A-Za-z0-9_-]{32,128}$/.test(secret))throw fail();return secret;}catch{throw fail();}}
 });
}
module.exports={createPasswordResetEnvelope};
