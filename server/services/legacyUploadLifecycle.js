'use strict';
const {randomUUID}=require('node:crypto');
const fs=require('node:fs/promises');
const path=require('node:path');
const LOCK_CLASS=741902;
function integer(value,label,max=Number.MAX_SAFE_INTEGER){value=Number(value);if(!Number.isSafeInteger(value)||value<1||value>max)throw new TypeError(`Valid ${label} required`);return value;}
function createLegacyUploadLifecycle({identityPool,uploadRoot=path.resolve(__dirname,'../uploads'),fileSystem=fs}={}){
 if(typeof identityPool?.connect!=='function'||typeof uploadRoot!=='string'||!path.isAbsolute(uploadRoot)
   ||typeof fileSystem?.mkdir!=='function'||typeof fileSystem?.rm!=='function')throw new TypeError('Identity pool and absolute upload root required');
 const root=path.resolve(uploadRoot);
 const intentRoot=(owner,intent)=>path.join(root,'managed',String(owner),intent);
 function managedIntent(value,owner,intent){if(typeof value!=='string'||!value.length)throw new Error('Invalid managed upload path');const target=path.resolve(value),directory=intentRoot(owner,intent);if(path.dirname(target)!==directory)throw new Error('Managed upload path escaped intent');return target;}
 async function removeIntent(owner,intent){const directory=intentRoot(owner,intent);try{await fileSystem.rm(directory,{recursive:true,force:false});return true;}catch(error){if(error?.code==='ENOENT')return false;throw error;}}
 // Classic uploads retain a shared logical filename namespace for the lab,
 // while physical bytes live in immutable per-intent directories. The global
 // lock serializes durable admission/retirement with owner deletion.
 async function locked(_owner,work){const client=await identityPool.connect();let held=false,discard=false;try{await client.query('SELECT pg_advisory_lock($1,$2)',[LOCK_CLASS,0]);held=true;return await work(client);}finally{if(held){try{const row=(await client.query('SELECT pg_advisory_unlock($1,$2) AS unlocked',[LOCK_CLASS,0])).rows[0];if(row?.unlocked===false)discard=true;}catch{discard=true;}}client.release(discard?new Error('Legacy upload lock connection was lost'):undefined);}}
 return Object.freeze({
  uploadRoot:root,
  async runUpload({ownerId,sessionId},work){ownerId=integer(ownerId,'upload owner',2147483647);sessionId=integer(sessionId,'upload session');if(typeof work!=='function')throw new TypeError('Upload callback required');
   return locked(ownerId,async client=>{const intentId=randomUUID(),directory=intentRoot(ownerId,intentId),controller=new AbortController();const connectionError=error=>controller.abort(error);let admitted=false;client.on?.('error',connectionError);
    try{
     // Create the immutable physical namespace before publishing its durable
     // intent. Once admission succeeds, neither Multer nor this lifecycle may
     // recreate it: retirement can therefore remove it as a final fence even
     // when this worker loses its database connection mid-upload.
     await fileSystem.mkdir(directory,{recursive:true,mode:0o700});controller.signal.throwIfAborted();
     await client.query('SELECT identity.admit_legacy_upload($1,$2,$3)',[intentId,ownerId,sessionId]);admitted=true;controller.signal.throwIfAborted();
     const lease=Object.freeze({intentId,ownerId,directory,signal:controller.signal,async bindFilename(value){controller.signal.throwIfAborted();if(typeof value!=='string'||!value||path.basename(value)!==value)throw new Error('Invalid logical upload filename');const bound=managedIntent(path.join(directory,value),ownerId,intentId);await client.query('SELECT identity.bind_legacy_upload_path($1,$2,$3)',[intentId,ownerId,bound]);controller.signal.throwIfAborted();return value;}});
     const result=await work(lease);controller.signal.throwIfAborted();await client.query('SELECT identity.publish_legacy_upload($1,$2)',[intentId,ownerId]);return result;
    }catch(error){try{await removeIntent(ownerId,intentId);if(admitted)await client.query('SELECT identity.retire_legacy_upload($1,$2)',[intentId,ownerId]);}catch(cleanupError){error.cleanupError=cleanupError;}throw error;}
    finally{client.off?.('error',connectionError);}
   });
  },
  async destroyOwner(ownerId,destroyStore){ownerId=integer(ownerId,'deletion owner',2147483647);if(typeof destroyStore!=='function')throw new TypeError('Legacy store cleanup required');
   return locked(ownerId,async client=>{const intents=(await client.query('SELECT * FROM identity.list_legacy_upload_cleanup($1)',[ownerId])).rows;const receipt=await destroyStore(ownerId,intents.map(intent=>intent.file_path).filter(Boolean),intents.map(intent=>intent.intent_id));for(const intent of intents)await removeIntent(ownerId,intent.intent_id);await client.query('SELECT identity.retire_legacy_uploads($1)',[ownerId]);return receipt;});
  }
 });
}
let singleton;
function getLegacyUploadLifecycle(){if(!singleton){const adapter=require('./postgresIdentityAdapter').getPostgresIdentityAdapter();singleton=createLegacyUploadLifecycle({identityPool:adapter.pool});}return singleton;}
module.exports={createLegacyUploadLifecycle,getLegacyUploadLifecycle};
