'use strict';

function unavailable(statusCode=503){
 return Object.assign(new Error('Teaching session binding unavailable'),{code:'TEACHING_SESSION_BINDING_UNAVAILABLE',statusCode});
}
function positive(value){
 if(!['number','string'].includes(typeof value)||!/^[1-9][0-9]*$/.test(String(value))||!Number.isSafeInteger(Number(value)))throw unavailable(401);
 return Number(value);
}
function normalize(error){
 if(['TEACHING_SESSION_AUTHORITY_UNAVAILABLE','TEACHING_SESSION_BINDING_UNAVAILABLE'].includes(error?.code))return error;
 return unavailable();
}
const invoke=(object,method)=>new Promise((resolve,reject)=>{
 if(typeof object?.[method]!=='function')return reject(unavailable());
 try{object[method](error=>error?reject(error):resolve());}catch(error){reject(error);}
});

// Mount only after express-session. A new anonymous Session object is expected
// when no cookie exists; absent middleware is an error, not a fabricated session.
function createTeachingSessionBearerBinding({resolveAuthority,assertCookieBinding,readTrustedUsername}={}){
 if(typeof resolveAuthority!=='function'||typeof assertCookieBinding!=='function'
   ||(readTrustedUsername!==undefined&&typeof readTrustedUsername!=='function'))throw new TypeError('Canonical teaching authority and durable cookie assertion required');
 return async function bind(req){
  let rotatedSession,rotatedId;
  try{
   const authority=await resolveAuthority(req,{allowCookie:false});
   if(authority?.source!=='bearer'||typeof authority.check!=='function')throw unavailable(401);
   const binding=Object.freeze({ownerId:positive(authority.ownerId),sessionId:positive(authority.sessionId)});
   const checkAuthority=authority.check.bind(authority);
   await checkAuthority();
   const original=req.session,originalId=req.sessionID;
   if(typeof original?.regenerate!=='function')throw unavailable();
   let matches=false;
   try{matches=typeof originalId==='string'&&!!originalId&&positive(original.userId)===binding.ownerId
     &&positive(original.platformOwnerId)===binding.ownerId&&positive(original.platformSessionId)===binding.sessionId;}catch{matches=false;}
   if(matches){
    try{await assertCookieBinding(originalId,binding);}
    catch(error){if(error?.code!=='55000')throw error;matches=false;}
    // 55000 may also mean canonical revocation: it only permits repair after
    // the separately captured bearer passes a new canonical authority check.
    await checkAuthority();
    if(req.session!==original||req.sessionID!==originalId)throw unavailable();
   }
   let sid=originalId;
   if(!matches){
    let username;
    if(readTrustedUsername){
     username=await readTrustedUsername(binding);
     if(username!==undefined&&(typeof username!=='string'||Buffer.byteLength(username)>256))throw unavailable();
    }
    await checkAuthority();
    if(req.session!==original||req.sessionID!==originalId)throw unavailable();
    await invoke(original,'regenerate');
    rotatedSession=req.session;rotatedId=req.sessionID;
    if(!rotatedSession||rotatedSession===original||typeof rotatedId!=='string'||!rotatedId||rotatedId===originalId)throw unavailable();
    await checkAuthority();
    if(req.session!==rotatedSession||req.sessionID!==rotatedId)throw unavailable();
    rotatedSession.userId=binding.ownerId;
    rotatedSession.platformOwnerId=binding.ownerId;
    rotatedSession.platformSessionId=binding.sessionId;
    if(username!==undefined)rotatedSession.username=username;
    await invoke(rotatedSession,'save');
    await checkAuthority();
    if(req.session!==rotatedSession||req.sessionID!==rotatedId)throw unavailable();
    await assertCookieBinding(rotatedId,binding);
    await checkAuthority();
    sid=rotatedId;
   }
   const capturedSession=matches?original:rotatedSession;
   if(req.session!==capturedSession||req.sessionID!==sid)throw unavailable();
   const check=async()=>{
    try{
     await checkAuthority();
     if(req.session!==capturedSession||req.sessionID!==sid)throw unavailable();
     await assertCookieBinding(sid,binding);
     await checkAuthority();
     if(req.session!==capturedSession||req.sessionID!==sid)throw unavailable();
    }catch(error){throw normalize(error);}
   };
   return Object.freeze({...binding,source:'bearer',rotated:!matches,check});
  }catch(error){
   // Express Session.destroy clears req.session immediately; keep failed
   // binding from being saved again automatically when an error response ends.
   if(rotatedSession&&req.session===rotatedSession&&req.sessionID===rotatedId){
    try{await invoke(rotatedSession,'destroy');}catch{/* Preserve original failure; storage remains fail closed. */}
    if(req.session===rotatedSession)req.session=undefined;
   }
   throw normalize(error);
  }
 };
}
module.exports={createTeachingSessionBearerBinding};
