'use strict';
const {withCtfTransaction}=require('./ctfLifecycleRepository');
const {validateEvent,validateReceipt}=require('../../services/ctfDeletionContract');
function createCtfDeletionRepository(pool){return Object.freeze({
 async admit({jobId,leaseToken,subjectId},options){const row=await withCtfTransaction(pool,async c=>(await c.query('SELECT identity.admit_ctf_student_deletion($1,$2,$3) AS event',[jobId,leaseToken,subjectId])).rows[0].event,options);return validateEvent({...row,command:JSON.parse(row.canonicalCommand)});},
 async acknowledge(scope,event,receipt,options){validateReceipt(event,receipt.canonicalResult,receipt.resultHash);return withCtfTransaction(pool,async c=>(await c.query('SELECT identity.ack_ctf_student_deletion($1,$2,$3,$4,$5) AS receipt',[scope.jobId,scope.leaseToken,scope.subjectId,receipt.canonicalResult,receipt.resultHash])).rows[0].receipt,options);}
});}
module.exports={createCtfDeletionRepository};
