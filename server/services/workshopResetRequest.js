'use strict';
const {randomUUID,createHash}=require('node:crypto');
function workshopResetRequest(req,res){
 const operationId=req.get('x-reset-operation-id')||randomUUID();
 if(!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(operationId))throw Object.assign(new Error('Invalid reset operation identifier'),{statusCode:400});
 res.setHeader('x-reset-operation-id',operationId);
 const actorRequest=workshopResetActorRequest(req);
 return{operationId,actorRequest};
}
function workshopResetActorRequest(req){
 return Object.freeze({user:Object.freeze({id:req.user?.id}),identitySession:Object.freeze({id:req.identitySession?.id}),headers:Object.freeze({authorization:req.headers?.authorization}),...(Array.isArray(req.rawHeaders)?{rawHeaders:Object.freeze([...req.rawHeaders])}:{})});
}
function childResetOperation(operationId,key){const h=createHash('sha256').update(`${operationId}:${key}`).digest('hex');return`${h.slice(0,8)}-${h.slice(8,12)}-5${h.slice(13,16)}-a${h.slice(17,20)}-${h.slice(20,32)}`;}
module.exports={workshopResetRequest,workshopResetActorRequest,childResetOperation};
