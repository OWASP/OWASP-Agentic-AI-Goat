'use strict';
const {createCtfProjectionDecisionRepository}=require('./ctfDecisionProjectionRepository');
const {createCtfResponseDiagnosticsRepository}=require('./ctfResponseDiagnosticsRepository');
// Production composition keeps the projection snapshot capture and authorizer,
// replacing only proposal staging with the atomic diagnostic wrapper. No
// fallback to diagnostic-free staging is available on this adapter.
function createCtfDiagnosticDecisionRepository(pool){
 const decisions=createCtfProjectionDecisionRepository(pool);
 const diagnostics=createCtfResponseDiagnosticsRepository(pool);
 return Object.freeze({...decisions,requireDiagnostics:true,stage:diagnostics.stage});
}
module.exports={createCtfDiagnosticDecisionRepository};
