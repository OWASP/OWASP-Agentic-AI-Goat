'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs/promises'),os=require('node:os'),path=require('node:path');
const {createOwnedAuditProduction}=require('../server/services/secureshopOwnedAuditProduction');
const {workspaceId}=require('../server/services/mcp/ownedManagedConfiguration');
test('private production service retains disabled cleanup, joins singleton startup and closes once',async t=>{
 const home=await fs.mkdtemp(path.join(os.tmpdir(),'audit-production-'));t.after(()=>fs.rm(home,{recursive:true,force:true}));const root=path.join(home,'source'),id=workspaceId(root),folder=path.join(home,'.dvaia',id);await fs.mkdir(folder,{recursive:true});
 const config={workspace:id,container:`dvaia-audit-sql-${id}`,volume:`dvaia-audit-sql-${id}-data`,database:`dvaia_audit_control_${id}`,provisioned:true,enabled:false,port:8095,token:'x'.repeat(64)};await fs.writeFile(path.join(folder,'audit-sql-target.json'),JSON.stringify(config),{mode:0o600});
 let starts=0,closes=0;const client={readiness:async()=>({ready:true})};const runtime=createOwnedAuditProduction({root,home,start:async(file,opts)=>{starts++;assert.equal(opts.cleanupOnly,true);return{close:async()=>{closes++;}};},createClient:()=>client});const [a,b]=await Promise.all([runtime.get(),runtime.get()]);assert.equal(a,b);assert.equal(a.client,client);assert.equal(a.admissions,false);assert.equal(starts,1);await Promise.all([runtime.close(),runtime.close()]);assert.equal(closes,1);await assert.rejects(runtime.get(),/closing/);
});
test('missing config is absent and wrong workspace never starts daemon',async t=>{
 const home=await fs.mkdtemp(path.join(os.tmpdir(),'audit-production-'));t.after(()=>fs.rm(home,{recursive:true,force:true}));const root=path.join(home,'source'),id=workspaceId(root);let starts=0;const runtime=createOwnedAuditProduction({root,home,start:async()=>{starts++;}});assert.equal(await runtime.get(),null);const folder=path.join(home,'.dvaia',id);await fs.mkdir(folder,{recursive:true});await fs.writeFile(path.join(folder,'audit-sql-target.json'),JSON.stringify({workspace:'foreign'}),{mode:0o600});await assert.rejects(runtime.get(),/mismatch/);assert.equal(starts,0);await runtime.close();
});
