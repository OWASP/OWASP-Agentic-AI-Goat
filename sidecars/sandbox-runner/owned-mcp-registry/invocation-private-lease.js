'use strict';
// Only this module brands the packaged lease after an actual native peer/lock
// check. No caller-supplied predicate can mint a manager lease.
const fs=require('node:fs'),net=require('node:net'),{randomUUID}=require('node:crypto');
const codec=require('./invocation-channel-codec');
const leases=new WeakMap();
async function openPrivateChannel({identity,secret,lockFd=4,socketPath='/run/dvaia-invocation/control.sock'}={}){
 if(process.platform!=='linux'||process.pid===1||process.getuid()!==10001||identity.peerPid!==1||identity.peerUid!==10001||!Buffer.isBuffer(secret)||secret.length!==32)throw Error('Private Linux supervisor required');
 const native=require('/usr/local/libexec/dvaia-invocation-peer.node');let closed=false;
 async function connect(){const socket=net.createConnection(socketPath);await new Promise((resolve,reject)=>{const timer=setTimeout(()=>{socket.destroy();reject(Error('Supervisor connect deadline'));},2000);socket.once('connect',()=>{clearTimeout(timer);resolve();});socket.once('error',e=>{clearTimeout(timer);reject(e);});});try{const peer=native.check(socket._handle.fd,lockFd);if(peer.pid!==identity.peerPid||peer.uid!==identity.peerUid)throw Error('Supervisor peer changed');return socket;}catch(e){socket.destroy();throw e;}}
 const initial=await connect(),leaseRequest={version:'owned-mcp-supervisor-v1',operation:'lease',requestId:randomUUID(),identity,intent:{invocationId:randomUUID(),workerId:randomUUID(),bootId:randomUUID()}};
 const leaseReply=await exchangeOnSocket(initial,leaseRequest,secret,{timeoutMs:2000});if(leaseReply.state!=='completed'||JSON.stringify(leaseReply.result)!=='{"lease":true}')throw Error('Supervisor lease handshake denied');
 const lease=Object.freeze({});leases.set(lease,{assert(){if(closed)throw Error('Supervisor lease closed');fs.fstatSync(lockFd);},close(){closed=true;}});
 const channel=Object.freeze({async exchange(q,{signal}={}){leases.get(lease).assert();signal?.throwIfAborted();const socket=await connect();return {peer:identity,body:await exchangeOnSocket(socket,q,secret,{signal})};}});
 return Object.freeze({lease,channel,async qualificationEpochProbe(){leases.get(lease).assert();const socket=await connect();return rejectEpochOnSocket(socket,leaseRequest,secret);},close(){leases.get(lease).close();}});
}
function exchangeOnSocket(socket,q,secret,{signal,timeoutMs=15000}={}){
 if(!Number.isSafeInteger(timeoutMs)||timeoutMs<1||timeoutMs>15000){socket.destroy();throw Error('Bounded supervisor deadline required');}
 return new Promise((resolve,reject)=>{let length=0,finished=false;const chunks=[];
  const finish=(error,value)=>{if(finished)return;finished=true;clearTimeout(timer);signal?.removeEventListener('abort',abort);socket.destroy();error?reject(error):resolve(value);};
  const abort=()=>finish(Error('Supervisor exchange aborted'));
  const timer=setTimeout(()=>finish(Error('Supervisor reply deadline')),timeoutMs);
  signal?.addEventListener('abort',abort,{once:true});if(signal?.aborted){abort();return;}
  socket.on('error',e=>finish(e));socket.on('end',()=>finish(Error('Supervisor reply incomplete')));
  socket.on('data',chunk=>{length+=chunk.length;if(length>codec.HEADER+65536)return finish(Error('Supervisor output limit'));chunks.push(chunk);const b=Buffer.concat(chunks);
   if(b.length>=codec.HEADER){const expected=codec.HEADER+b.readUInt32BE(220);if(expected>codec.HEADER+65536)return finish(Error('Supervisor frame limit'));if(b.length===expected){try{finish(null,codec.decode(b,q));}catch(e){finish(e);}}else if(b.length>expected)finish(Error('Supervisor trailing bytes'));}
  });
  try{socket.end(codec.encode(q,secret));}catch(error){finish(error);}
 });
}
// Private qualification opt-in only; no externally supplied identity or payload.
async function rejectEpochOnSocket(socket,validRequest,secret){
 let received=0;const observe=chunk=>{received+=chunk.length;};socket.on('data',observe);
 const wrong={...validRequest,requestId:randomUUID(),identity:{...validRequest.identity,supervisorEpoch:randomUUID()}};
 try{await exchangeOnSocket(socket,wrong,secret,{timeoutMs:2000});}
 catch(error){if(received===0&&(error.message==='Supervisor reply incomplete'||error.code==='ECONNRESET'))return true;throw error;}
 finally{socket.removeListener('data',observe);}
 throw Error('Supervisor accepted stale epoch');
}
function assertPrivateLease(lease){const held=leases.get(lease);if(!held)throw Error('Unverified supervisor lease');held.assert();}
module.exports={openPrivateChannel,assertPrivateLease,_internals:{exchangeOnSocket,rejectEpochOnSocket}};
