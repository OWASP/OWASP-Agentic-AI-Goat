'use strict';
const assert=require('node:assert/strict');const fs=require('node:fs/promises');
async function main(){
 assert.equal(process.getuid(),10001);
 const {createOwnedHttpExecutor}=require('/app/owned-http/executor');
 const runtime=createOwnedHttpExecutor({expectedProfile:process.env.MCP_OWNED_TARGET_APPARMOR_PROFILE});
 await runtime.checkReadiness();
 await assert.rejects(runtime.execute({input:{url:'http://169.254.169.254/',mode:'vuln',canary:'b'.repeat(64)}}),{code:'HTTP_CHILD_FAILED'});
 assert.equal((await fs.readFile(`/proc/self/task/${process.pid}/children`,'utf8')).trim(),'');
 return {childFailureRejected:true,allDescendantsJoined:true,productionQualified:false};
}
if(require.main===module)main().then(value=>console.log(JSON.stringify(value))).catch(error=>{console.error(error.stack);process.exitCode=1;});
module.exports={main};
