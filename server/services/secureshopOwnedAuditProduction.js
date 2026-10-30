'use strict';
const fs=require('node:fs/promises'),path=require('node:path'),os=require('node:os');
const {workspaceId}=require('./mcp/ownedManagedConfiguration');
function createOwnedAuditProduction({root=path.resolve(__dirname,'../..'),home=os.homedir(),start=require('../../sidecars/audit-sql-target/main').start,createClient=require('./secureshopOwnedAuditHttpClient').createOwnedAuditHttpClient}={}){
 let pending,retained,closing;
 async function get(){
  if(closing)throw Error('Owned audit service is closing');if(retained)return retained;if(pending)return pending;
  pending=(async()=>{
   const id=workspaceId(root),file=path.join(home,'.owasp-ai-goat',id,'audit-sql-target.json');let stat,bytes;
   if(process.platform==='win32'){bytes=require('../../scripts/lib/audit-sql-private-state').read(file,{allowMissing:true});if(bytes===null)return null;}
   else {
   try{stat=await fs.lstat(file);}catch(error){if(error.code==='ENOENT')return null;throw error;}
   if(!stat.isFile()||stat.isSymbolicLink()||(stat.mode&0o077)||stat.uid!==process.getuid())throw Error('Private owned audit configuration required');
   bytes=await fs.readFile(file,'utf8');}
   const config=JSON.parse(bytes);
   if(config.workspace!==id||config.container!==`owasp-ai-goat-audit-sql-${id}`||config.volume!==`owasp-ai-goat-audit-sql-${id}-data`||config.database!==`owasp_ai_goat_audit_control_${id}`||config.provisioned!==true||typeof config.enabled!=='boolean'||(config.agentEnabled!==undefined&&typeof config.agentEnabled!=='boolean'))throw Error('Owned audit workspace configuration mismatch');
   const daemon=await start(file,{cleanupOnly:!config.enabled});
   try{const client=createClient({url:`http://127.0.0.1:${config.port}`,token:config.token});await client.readiness();if(closing)throw Error('Owned audit service is closing');retained=Object.freeze({client,admissions:config.enabled,agentAdmissions:config.enabled&&config.agentEnabled===true,close:()=>daemon.close()});return retained;}catch(error){await daemon.close();throw error;}
  })();try{return await pending;}finally{pending=undefined;}
 }
 function close(){if(closing)return closing;closing=(async()=>{if(pending)try{await pending;}catch{}const owned=retained;retained=undefined;if(owned)await owned.close();})();return closing;}
 return Object.freeze({get,close});
}
const production=createOwnedAuditProduction();
module.exports={createOwnedAuditProduction,getOwnedAuditProduction:production.get,closeOwnedAuditProduction:production.close};
