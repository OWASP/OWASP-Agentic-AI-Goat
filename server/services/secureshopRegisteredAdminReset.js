'use strict';
const {createHash,randomBytes}=require('node:crypto');
const bcrypt=require('bcryptjs');
const TOKEN=/^[A-Za-z0-9_-]{43}$/;
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const VERSION=/^[1-9]\d{0,18}$/;
const fail=code=>Object.assign(Error('Registered administrator reset unavailable'),{code});
const hashToken=token=>{if(typeof token!=='string'||!TOKEN.test(token))throw fail('SHOP_AUTH_INVALID');return createHash('sha256').update(token,'utf8').digest('hex');};
const targetId=value=>{if(!Number.isSafeInteger(value)||value<1||value>2147483647)throw fail('INVALID_ARGUMENT');return value;};
const operationId=value=>{if(typeof value!=='string'||!UUID.test(value))throw fail('INVALID_ARGUMENT');return value.toLowerCase();};
const version=value=>{if(typeof value!=='string'||!VERSION.test(value)||BigInt(value)>=9007199254740991n)throw fail('INVALID_ARGUMENT');return value;};
function createRegisteredAdminResetService({repository,hashPassword=secret=>bcrypt.hash(secret,12),randomSecret=()=>randomBytes(32).toString('base64url')}={}){
 if(['preview','reset','read','reveal','acknowledge'].some(name=>typeof repository?.[name]!=='function')||typeof hashPassword!=='function'||typeof randomSecret!=='function')throw TypeError('Protected registered reset dependencies required');
 const actor=token=>Object.freeze({tokenHash:hashToken(token)});
 return Object.freeze({
  preview({token,targetId:id}){return repository.preview({...actor(token),targetId:targetId(id)});},
  async reset({token,targetId:id,operationId:op,expectedCredentialVersion,expectedAuthorityVersion,expectedMembershipVersion}){
   const input={...actor(token),targetId:targetId(id),operationId:operationId(op),expectedCredentialVersion:version(expectedCredentialVersion),expectedAuthorityVersion:version(expectedAuthorityVersion),expectedMembershipVersion:version(expectedMembershipVersion)};
   // Material is generated before the identity transaction; a replay discards it.
   const secret=randomSecret();if(typeof secret!=='string'||!TOKEN.test(secret))throw fail('REGISTERED_RESET_RECOVERY_UNAVAILABLE');
   const passwordHash=await hashPassword(secret);if(typeof passwordHash!=='string'||!/^\$2[aby]\$\d\d\$[./A-Za-z0-9]{53}$/.test(passwordHash))throw fail('REGISTERED_RESET_RECOVERY_UNAVAILABLE');
   return repository.reset({...input,secret,passwordHash});
  },
  read({token,targetId:id,operationId:op}){return repository.read({...actor(token),targetId:targetId(id),operationId:operationId(op)});},
  reveal({token,targetId:id,operationId:op}){return repository.reveal({...actor(token),targetId:targetId(id),operationId:operationId(op)});},
  acknowledge({token,targetId:id,operationId:op}){return repository.acknowledge({...actor(token),targetId:targetId(id),operationId:operationId(op)});},
 });
}
module.exports={createRegisteredAdminResetService};
