'use strict';
const fs=require('node:fs/promises'),path=require('node:path'),{randomUUID}=require('node:crypto');
const {readManagedAnalyticsConfiguration,validate}=require('../../server/services/secureshopAnalyticsManagedConfiguration');
const fail=code=>Object.assign(Error('Owned Analytics activation unavailable; private configuration preserved'),{code});
// Activation is a separate installer operation. Existing disabled preferences
// are preserved unless the caller explicitly requested activation.
async function activate({root,homeDirectory,expectedSha256,assertReady,explicit=false,fresh=false}={}){
 if(typeof assertReady!=='function'||!/^[a-f0-9]{64}$/.test(expectedSha256||''))throw fail('ANALYTICS_ACTIVATION_ARGUMENTS');
 const options={root,homeDirectory},before=await readManagedAnalyticsConfiguration(options);
 if(!before||before.sha256!==expectedSha256)throw fail('ANALYTICS_ACTIVATION_CONFLICT');
 if(!before.config.enabled&&!explicit&&!fresh)return {activationEnabled:false,changed:false};
 const lock=before.filename+'.activation-lock';await fs.mkdir(lock,{mode:0o700});let temporary;
 try{
  const verify=async()=>{const now=await readManagedAnalyticsConfiguration(options);if(!now||now.sha256!==expectedSha256)throw fail('ANALYTICS_ACTIVATION_CONFLICT');return now;};
  await verify();await assertReady();await verify();
  if(before.config.enabled)return {activationEnabled:true,changed:false};
  const value=validate({...before.config,enabled:true},{root});temporary=path.join(before.directory,'.analytics-activate-'+randomUUID());
  const handle=await fs.open(temporary,'wx',0o600);try{await handle.writeFile(JSON.stringify(value)+'\n');await handle.sync();}finally{await handle.close();}
  await verify();await fs.rename(temporary,before.filename);temporary=null;
  const directory=await fs.open(before.directory,'r');try{await directory.sync();}finally{await directory.close();}
  return {activationEnabled:true,changed:true};
 }finally{if(temporary)await fs.unlink(temporary);await fs.rmdir(lock);}
}
module.exports={activate};
