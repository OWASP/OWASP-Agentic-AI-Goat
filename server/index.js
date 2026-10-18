'use strict';
// Keep the callable CommonJS Express export; stateful construction is asynchronous
// and cannot run until this process owns its database maintenance exclusion lease.
require('../scripts/application-node-runtime').assertSupportedApplicationNodeVersion(process.versions.node);
require('dotenv').config();
require('./services/applicationDatabaseEngine').assertApplicationDatabaseEngine();
require('./services/platformSigningConfiguration').assertPlatformSigningConfiguration(process.env);
const app=require('express')();
const lifecycle=require('./services/applicationLifecycle').createApplicationLifecycle({timeoutMs:60000});
const controller=new AbortController();
// Acquisition cancellation must never release an already-held lifetime lease.
const acquisitionController=new AbortController();
let ready=false,lease;
const shutdown=code=>{ready=false;controller.abort();if(!lease)acquisitionController.abort();return lifecycle.shutdown(code);};
process.once('SIGTERM',()=>shutdown(0));
process.once('SIGINT',()=>shutdown(0));
process.on('uncaughtException',()=>shutdown(1));
process.on('unhandledRejection',()=>shutdown(1));
app.use((req,res,next)=>ready&&!controller.signal.aborted?next():res.status(503).json({error:'Application unavailable'}));
module.exports=app;
app.locals.applicationReady=(async()=>{
 try{
  lease=await require('./services/applicationMaintenanceLease').acquireApplicationMaintenanceLease({mode:'application',signal:acquisitionController.signal});
  // If shutdown finished while acquisition settled, close without constructing.
  if(controller.signal.aborted||lifecycle.stopping){await lease.close();return;}
  lifecycle.registerFinalizer(()=>lease.close());
  lease.signal.addEventListener('abort',()=>{if(!lifecycle.stopping)void shutdown(1);},{once:true});
  lease.assertHeld();
  await lease.assertClean();
  controller.signal.throwIfAborted();lease.assertHeld();
  await require('./applicationServer').startApplicationServer({app,lifecycle,signal:controller.signal,assertHeld:()=>lease.assertHeld()});
  controller.signal.throwIfAborted();lease.assertHeld();ready=true;
 }catch(error){
  ready=false;
  require('./services/applicationStartupDiagnostic').reportStartupDiagnostic(error,(...args)=>console.error(...args));
  await shutdown(1);
  throw error;
 }
})();
// Expose readiness to in-process consumers without an unhandled startup rejection.
app.locals.applicationReady.catch(()=>{});
