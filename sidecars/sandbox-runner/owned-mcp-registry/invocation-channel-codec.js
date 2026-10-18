'use strict';
const crypto=require('node:crypto');
const MAX=196608,HEADER=224,ID=/^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const operations={start:1,status:2,drain:3,lease:4},states={1:'completed',2:'failed_before_effect',3:'uncertain'};
const fail=()=>{throw Error('Invalid private supervisor frame');};
function ids(q){return[q.requestId,q.identity.supervisorEpoch,q.intent.invocationId,q.intent.workerId,q.intent.bootId];}
function encode(q,secret){if(!Buffer.isBuffer(secret)||secret.length!==32||!operations[q.operation]||!ids(q).every(v=>typeof v==='string'&&ID.test(v)))fail();const payload=q.operation==='start'?Buffer.from(JSON.stringify(q.claim)):Buffer.alloc(0);if(payload.length>MAX)fail();const b=Buffer.alloc(HEADER+payload.length);b.write('DVI1');b[4]=operations[q.operation];ids(q).forEach((v,i)=>b.write(v,8+i*36,36,'ascii'));secret.copy(b,188);b.writeUInt32BE(payload.length,220);payload.copy(b,HEADER);return b;}
function decode(b,q){if(!Buffer.isBuffer(b)||b.length<HEADER||b.toString('ascii',0,4)!=='DVO1'||b[4]!==operations[q.operation]||!states[b[5]]||b[6]!==1||b[7]!==0||b.subarray(188,220).some(x=>x!==0)||b.readUInt32BE(220)>65536||b.length!==HEADER+b.readUInt32BE(220)||!ids(q).every((v,i)=>b.toString('ascii',8+i*36,44+i*36)===v))fail();const result=b.length>HEADER?JSON.parse(b.toString('utf8',HEADER)):null;if(b[5]===1&&b.length===HEADER)fail();return{version:q.version,requestId:q.requestId,operation:q.operation,intent:q.intent,state:states[b[5]],drained:true,...(b.length>HEADER?{result}:{})};}
function exactSecret(a,b){return Buffer.isBuffer(a)&&Buffer.isBuffer(b)&&a.length===32&&b.length===32&&crypto.timingSafeEqual(a,b);}
module.exports={HEADER,MAX,encode,decode,exactSecret};
