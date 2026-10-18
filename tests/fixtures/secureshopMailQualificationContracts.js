'use strict';
// Shared by the genuine fixture and its no-PG/no-model dependency preflight.
function mailQualificationOptions({grading,judge,...options}){
 if(typeof judge!=='function'||!grading?.assessmentDependencies)throw TypeError('Explicit canonical grading and Judge required');
 return {...options,assessmentDependencies:{...grading.assessmentDependencies,judge}};
}
async function authenticateMailPersona({auth,scope,templates,role}){
 const template=templates.find(row=>row.role===role);if(!template)throw TypeError('Owned mail persona missing');
 const login=await auth.login({scope,username:template.username,password:'student123'});
 const verified=await auth.authenticateBoundToken({scope,token:login.token});
 if(login.user.id!==template.id||login.user.role!==role)throw Error('Mail fixture persona identity mismatch');
 return {scope,persona:{id:login.user.id,role},personaSession:{sessionId:verified.sessionId,authorityVersion:verified.authorityVersion}};
}
function mailSourceEnvelope({templates,context,recipientRole,subject,body_markdown}){
 const sender=templates.find(row=>row.id===context.persona.id&&row.role===context.persona.role),recipient=templates.find(row=>row.role===recipientRole);
 if(!sender||!recipient)throw TypeError('Mail envelope requires matching caller and owned recipient');
 return {from:sender.email,to:recipient.email,subject,body_markdown};
}
module.exports={mailQualificationOptions,authenticateMailPersona,mailSourceEnvelope};
