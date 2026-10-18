'use strict';
const {createHash}=require('node:crypto');
const {createLaunchScope}=require('../../server/services/secureshopConversationBinding');
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const HASH=/^[a-f0-9]{64}$/;
const fields=['launchId','scenarioId','generation','platformOwnerId','platformSessionId'];
function canonical(value){if(value&&typeof value.toJSON==='function')value=value.toJSON();if(Array.isArray(value))return value.map(canonical);if(value&&typeof value==='object')return Object.fromEntries(Object.keys(value).sort().map(key=>[key,canonical(value[key])]));return value;}
const hash=value=>createHash('sha256').update(typeof value==='string'?value:JSON.stringify(canonical(value))).digest('hex');
// Completed and pending query rows written before canonical hashing retain this digest.
const legacyRequestHash=value=>createHash('sha256').update(JSON.stringify(value)).digest('hex');
const fail=code=>Object.assign(Error(code),{code});
function exact(value,keys){if(!value||Object.getPrototypeOf(value)!==Object.prototype||Reflect.ownKeys(value).length!==keys.length||keys.some(k=>!Object.hasOwn(Object.getOwnPropertyDescriptor(value,k)||{},'value')))throw fail('ANALYTICS_TARGET_INVALID');}
function scope(value){exact(value,fields);return createLaunchScope(value);}
function target(value){exact(value,['targetId','scope','sourceManifestSha256']);if(!UUID.test(value.targetId)||!HASH.test(value.sourceManifestSha256))throw fail('ANALYTICS_TARGET_INVALID');return Object.freeze({targetId:value.targetId,scope:scope(value.scope),sourceManifestSha256:value.sourceManifestSha256});}
const sameScope=(a,b)=>fields.every(k=>a?.[k]===b?.[k]);
function databaseName(id){if(!UUID.test(id))throw fail('ANALYTICS_TARGET_INVALID');return 'analytics_'+id.replaceAll('-','');}
function request(value){exact(value,['target','operationId','runId','requestId','sessionId','callId','sql',...(Object.hasOwn(value||{},'mode')?['mode']:[])]);const bound=target(value.target);
 if(Object.hasOwn(value,'mode')){exact(value.mode,['version','mode','generation','modeStamp']);if(value.mode.version!==1)throw fail('ANALYTICS_TARGET_INVALID');require('../../server/services/secureshopAnalyticsModeAuthority').checkedMode(value.mode);}
 for(const k of ['operationId','runId','requestId','sessionId'])if(!UUID.test(value[k]))throw fail('ANALYTICS_TARGET_INVALID');
 if(typeof value.callId!=='string'||!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(value.callId)||typeof value.sql!=='string'||!value.sql.trim()||!value.sql.isWellFormed()||Buffer.byteLength(value.sql)>16384||value.sql.includes('\0'))throw fail('ANALYTICS_TARGET_INVALID');
 return Object.freeze({...value,target:bound});}
module.exports={UUID,HASH,fields,hash,legacyRequestHash,fail,exact,scope,target,sameScope,databaseName,request};
