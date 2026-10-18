'use strict';
const KEY='csrf_workshop';
function effectiveMode(mode){if(![null,'vuln','fixed'].includes(mode))throw Object.assign(Error('Unsupported canonical email mode'),{code:'CSRF_MODE_UNSUPPORTED',statusCode:409});return mode??'vuln';}
function projection(mode){return Object.freeze({mode,effectiveMode:effectiveMode(mode),defaultMode:null,allowedModes:['vuln','fixed'],fixedObjectiveIds:['csrf_g1','csrf_g2','csrf_g3','csrf_p1','csrf_p2','csrf_p3','csrf_x1','csrf_x2','csrf_x3','csrf_i1','csrf_i2','csrf_i3']});}
function createAttemptFence({attempt,execution,progress,platformSessionId,checkSession}){
 if(!attempt||typeof execution?.check!=='function'||typeof progress?.getEvaluationScope!=='function'||typeof checkSession!=='function'||typeof platformSessionId!=='string'||!/^[1-9][0-9]{0,18}$/.test(platformSessionId))throw TypeError('Canonical email scope required');
 effectiveMode(attempt.mode);
 return async()=>{await execution.check();await checkSession();const scope=await progress.getEvaluationScope(attempt.userId,KEY);await execution.check();await checkSession();if(scope.generation!==attempt.generation||scope.mode!==attempt.mode||scope.modeStamp!==attempt.modeStamp)throw Object.assign(Error('Canonical email scope changed'),{code:'MODE_MISMATCH',statusCode:409});};
}
function publicScopeDenial(error){if(error?.code==='SESSION_REVOKED'||error?.statusCode===401)return {status:401,body:{error:'Canonical session is no longer current.',code:'SESSION_REVOKED'}};if(error?.code==='MODE_MISMATCH')return {status:409,body:{error:'Workshop mode changed; submit a new request.',code:'MODE_MISMATCH'}};return null;}
module.exports={publicScopeDenial,KEY,effectiveMode,projection,createAttemptFence};
