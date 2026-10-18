'use strict';
const fs=require('node:fs/promises');const path=require('node:path');const crypto=require('node:crypto');
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
async function createSecureShopMcpOwnedFixture({root,targetId,fsImpl=fs}={}){
  if(typeof root!=='string'||!path.isAbsolute(root)||!UUID.test(targetId))throw new TypeError('Owned MCP fixture scope required');
  const directory=path.join(root,targetId);const file=path.join(directory,'private-forecast.json');
  const value=Object.freeze({recordId:`forecast-export:${targetId}`,customerNote:'Hold this synthetic shipment for manual review.',classification:'protected-training-record'});
  let created=false;try{await fsImpl.mkdir(directory,{recursive:false});created=true;}catch(error){if(error.code!=='EEXIST')throw error;}
  if(created)await fsImpl.writeFile(file,JSON.stringify(value),{flag:'wx',mode:0o600});
  else {const [bytes,metadata]=await Promise.all([fsImpl.readFile(file),fsImpl.stat(file)]);
    if(!metadata.isFile()||(metadata.mode&0o777)!==0o600||bytes.toString('utf8')!==JSON.stringify(value))throw new Error('Owned MCP fixture recovery mismatch');}
  const cleanupOperationId=crypto.randomUUID();let state='active',accepted=0,drain,cleanupPending=null;
  async function directoryAbsent(){try{await fsImpl.stat(directory);return false;}catch(error){if(error.code==='ENOENT')return true;throw error;}}
  return Object.freeze({targetId,cleanupOperationId,async read(requested){if(state!=='active'||requested!==targetId)throw new Error('Owned MCP fixture unavailable');
    accepted++;try{const bytes=await fsImpl.readFile(file);return Object.freeze({value:JSON.parse(bytes),contentSha256:crypto.createHash('sha256').update(bytes).digest('hex')});}
    finally{accepted--;if(!accepted&&drain){drain();drain=null;}}},
    async cleanup(operationId){if(!UUID.test(operationId)||operationId!==cleanupOperationId)throw new Error('Owned MCP cleanup operation mismatch');
      if(state==='retired')return Object.freeze({ok:true,replayed:true,operationId});
      if(cleanupPending)return cleanupPending;
      state='retiring';
      cleanupPending=(async()=>{
        if(accepted)await new Promise(resolve=>{drain=resolve;});
        if(!await directoryAbsent())await fsImpl.rm(directory,{recursive:true,force:false});
        if(!await directoryAbsent())throw new Error('Owned MCP fixture removal incomplete');
        state='retired';return Object.freeze({ok:true,replayed:false,operationId});
      })();
      try{return await cleanupPending;}finally{if(state!=='retired')cleanupPending=null;}
    }});
}
async function retireSecureShopMcpOwnedFixturePath({root,targetId,fsImpl=fs}={}){
  if(typeof root!=='string'||!path.isAbsolute(root)||!UUID.test(targetId))throw new TypeError('Owned MCP fixture scope required');
  const directory=path.join(root,targetId);let existed=true;
  try{await fsImpl.stat(directory);}catch(error){if(error.code==='ENOENT')existed=false;else throw error;}
  if(existed)await fsImpl.rm(directory,{recursive:true,force:false});
  try{await fsImpl.stat(directory);throw new Error('Owned MCP fixture removal incomplete');}catch(error){if(error.code!=='ENOENT')throw error;}
  return Object.freeze({ok:true,replayed:!existed});
}
module.exports={createSecureShopMcpOwnedFixture,retireSecureShopMcpOwnedFixturePath};
