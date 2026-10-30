'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs/promises'),os=require('node:os'),path=require('node:path'),{createHash,randomUUID}=require('node:crypto');
const {validate,readManagedAnalyticsConfiguration}=require('../server/services/secureshopAnalyticsManagedConfiguration');
function config(root){const id=createHash('sha256').update(root).digest('hex').slice(0,12);return{version:1,enabled:false,workspaceId:id,dockerAuthoritySha256:'a'.repeat(64),containerName:`owasp-ai-goat-analytics-${id}`,containerId:'b'.repeat(64),volumeName:`owasp-ai-goat-analytics-${id}-data`,imageId:'sha256:'+'c'.repeat(64),port:18095,password:'d'.repeat(64),ownerId:randomUUID(),identity:{systemIdentifier:'1234567890123456789',controlDatabase:`owasp_ai_goat_analytics_control_${id}`,clusterName:`owasp-ai-goat-owned-analytics-${id}`},controlSchemaSha256:'e'.repeat(64)};}
test('private managed record rejects foreign scope, URLs, extra fields and unsafe files',async()=>{
 const home=await fs.mkdtemp(path.join(os.tmpdir(),'owasp-ai-goat-analytics-config-')),root=path.join(home,'workspace'),value=config(root),directory=path.join(home,'.owasp-ai-goat',value.workspaceId),filename=path.join(directory,'analytics-managed.json');
 try {
  assert.equal(await readManagedAnalyticsConfiguration({root,homeDirectory:home}),null);
  await fs.mkdir(directory,{recursive:true,mode:0o700});await fs.writeFile(filename,JSON.stringify(value),{mode:0o600});
  const result=await readManagedAnalyticsConfiguration({root,homeDirectory:home});assert.equal(result.config.enabled,false);assert.equal(result.config.identity.systemIdentifier,value.identity.systemIdentifier);
  for(const bad of [{...value,workspaceId:'f'.repeat(12)},{...value,databaseUrl:'postgres://app'},{...value,port:543},{...value,identity:{...value.identity,controlDatabase:'identity'}}])assert.throws(()=>validate(bad,{root}),{code:'ANALYTICS_MANAGED_CONFIGURATION_INVALID'});
  await fs.chmod(filename,0o644);await assert.rejects(readManagedAnalyticsConfiguration({root,homeDirectory:home}),{code:'ANALYTICS_MANAGED_CONFIGURATION_INVALID'});
  await fs.chmod(filename,0o600);await fs.rename(filename,filename+'.original');await fs.symlink(filename+'.original',filename);
  await assert.rejects(readManagedAnalyticsConfiguration({root,homeDirectory:home}),{code:'ANALYTICS_MANAGED_CONFIGURATION_INVALID'});
 }finally{await fs.rm(home,{recursive:true,force:true});}
});
