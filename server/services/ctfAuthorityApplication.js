'use strict';
const {createCtfAuthorityRuntime}=require('./ctfAuthorityRuntime');
const {createCtfAuthorityAttemptRoute}=require('./ctfAuthorityAttemptRoute');
const {createCtfAuthorityPreviewRoute}=require('./ctfAuthorityPreviewRoute');
const {createCtfFixedPracticeRoute}=require('./ctfFixedPracticeRoute');
const {createCtfAuthorityRouter}=require('../routes/ctfAuthorityRouter');
// Inert assembly. The application owner controls initialization, activation and
// all borrowed pool lifetimes; no fallback or implicit startup is provided.
function createCtfAuthorityApplication(options){
 const keys=['identityPool','ctfPool','deliveryPool','deliveryDatabaseUrl','activation','validateSession','coordinator'];
 if(!options||![Object.prototype,null].includes(Object.getPrototypeOf(options))||Reflect.ownKeys(options).length!==keys.length||!keys.every(k=>Object.hasOwn(options,k)))throw TypeError('Explicit CTF application dependencies required');
 const {identityPool,ctfPool,deliveryPool,deliveryDatabaseUrl,activation,validateSession,coordinator}=options;
 if(typeof validateSession!=='function'||typeof coordinator?.run!=='function'||identityPool===ctfPool||identityPool===deliveryPool||ctfPool===deliveryPool)throw TypeError('Distinct CTF pools and canonical session/coordinator required');
 const runtime=createCtfAuthorityRuntime({identityPool,ctfPool,deliveryPool,deliveryDatabaseUrl,activation:structuredClone(activation),validateSession,attempts:'production'});
 const attemptHandlers=createCtfAuthorityAttemptRoute({runtime,coordinator});
 const previewHandler=createCtfAuthorityPreviewRoute({runtime});
 const practiceHandler=createCtfFixedPracticeRoute({runtime,coordinator});
 const routes=createCtfAuthorityRouter({runtime,attemptHandlers,previewHandler,practiceHandler,authenticate:validateSession});
 let stopping;
 const router=(req,res,next)=>stopping?res.status(503).json({error:'CTF temporarily unavailable'}):routes(req,res,next);
 return Object.freeze({router,runtime,start:()=>stopping?Promise.reject(Error('CTF application stopping')):runtime.start(),status:()=>Object.freeze({...runtime.status(),previews:previewHandler.status(),practice:practiceHandler.status()}),stop:()=>{if(!stopping)stopping=(async()=>{const [previews,practice]=await Promise.all([previewHandler.close(),practiceHandler.close()]);const result=await runtime.stop();const outcome=Object.freeze({...result,previewDrained:previews.drained,activePreviews:previews.active,practiceDrained:practice.drained,activePractice:practice.active,drained:result.drained&&previews.drained&&practice.drained});if(!outcome.drained)throw Object.assign(Error('CTF application did not drain'),{code:'CTF_APPLICATION_UNDRAINED',outcome});return outcome;})();return stopping;}});
}
module.exports={createCtfAuthorityApplication};
