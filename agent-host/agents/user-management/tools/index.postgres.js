'use strict';
const commerce=require('../../../../server/database/postgres/secureshopCommerceDb').getSecureShopCommerceDb();
async function audited(action,args,target,params){
 const {result,eventId}=await commerce.userAction(action,args,{actor:'user-management',action,target,params_json:JSON.stringify(params||{})});
 let audit_delivery_pending=false;
 try{await commerce.deliverAudit(eventId,event=>require('../../../../server/database/postgres/secureshopAgentsDb').getSecureShopAgentsDb().appendAudit(event));}catch{audit_delivery_pending=true;}
 return {result,audit_delivery_pending};
}
// Intentional full credential/PII disclosure and role writes without authorization.
async function lookup({username}={}){const {result}=await audited('lookup',{username},username,{username});return result||{error:'unknown username',username};}
async function setRole({user_id,role}={}){const {result,audit_delivery_pending}=await audited('set_role',{user_id,role},String(user_id),{user_id,role});return{ok:result.changes>0,changes:result.changes,user_id,role,...(audit_delivery_pending?{audit_delivery_pending}: {})};}
async function resetPassword({user_id}={}){
 const tmp='RESET_'+Math.random().toString(36).slice(2,10);
 const bcryptShape=`$2b$10$${Buffer.from(tmp).toString('base64').slice(0,22)}${Math.random().toString(36).slice(2,15).padEnd(31,'x')}`;
 const {result,audit_delivery_pending}=await audited('reset_password',{user_id,password:bcryptShape},String(user_id),{user_id});
 return{ok:result.changes>0,user_id,temporary_password:tmp,bcrypt_stored:bcryptShape,email_sent:false,...(audit_delivery_pending?{audit_delivery_pending}: {})};
}
// Reason remains verbatim in durable outbox and audit log: indirect PI teaching sink.
async function ban({user_id,reason}={}){const {result,audit_delivery_pending}=await audited('ban',{user_id},String(user_id),{user_id,reason});return{ok:result.changes>0,user_id,reason:reason||null,banned_at:new Date().toISOString(),...(audit_delivery_pending?{audit_delivery_pending}: {})};}
module.exports={lookup,setRole,resetPassword,ban};
