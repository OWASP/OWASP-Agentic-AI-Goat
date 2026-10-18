'use strict';

const {readBearerAuthorization}=require('../middleware/bearerToken');
function integer(value,label){value=Number(value);if(!Number.isSafeInteger(value)||value<1)throw new TypeError(`Valid ${label} required`);return value;}
function authFailure(message='Legacy platform authentication unavailable',statusCode=401){return Object.assign(new Error(message),{code:'LEGACY_PLATFORM_AUTH_UNAVAILABLE',statusCode});}
function createLegacyPlatformAuthorityResolver(adapter){
 if(typeof adapter?.validateSession!=='function')throw new TypeError('Platform identity adapter required');
 return async req=>{
  const {present,token}=readBearerAuthorization(req);
  if(!present)return null;
  if(token===null)throw authFailure();
  let found;
  try{found=await adapter.validateSession(token);}
  catch(error){
   if(error?.name==='AccountLocked')throw authFailure('Platform account is locked',423);
   if(['JsonWebTokenError','TokenExpiredError','NotBeforeError'].includes(error?.name))throw authFailure();
   throw error;
  }
  if(!found?.user||!found?.session)throw authFailure();
  const authority={ownerId:integer(found.user.id,'platform owner'),sessionId:integer(found.session.id,'platform session')};
  return Object.freeze(authority);
 };
}

module.exports={createLegacyPlatformAuthorityResolver};
