'use strict';
// Fresh process: only durable session token + operation ID arrive over IPC.
const {Pool}=require('pg');
const assert=require('node:assert/strict');
function errorRecord(error){return {name:error?.name||'Error',code:error?.code||null,message:String(error?.message||error)};}
async function closeChildResources({production,server,pools}){
 const errors=[];
 try{await production?.close();}catch(error){errors.push({phase:'production.close',...errorRecord(error)});}
 if(server){
  try{server.closeAllConnections?.();}catch(error){errors.push({phase:'server.closeAllConnections',...errorRecord(error)});}
  try{await new Promise((resolve,reject)=>server.close(error=>error?reject(error):resolve()));}catch(error){errors.push({phase:'server.close',...errorRecord(error)});}
 }
 const results=await Promise.all((pools||[]).map(async pool=>{try{await pool.end();return{status:'fulfilled'};}catch(reason){return{status:'rejected',reason};}}));
 for(const result of results)if(result.status==='rejected')errors.push({phase:'pool.end',...errorRecord(result.reason)});
 try{assert.equal(require('../../server/database/postgres').getPoolBudgetSnapshot().reserved,0);}catch(error){errors.push({phase:'pool-budget',...errorRecord(error)});}
 return errors;
}
async function runChild(input){
 let server,production;const pools=[];const pool=(url,lease=false)=>{const p=new Pool({connectionString:url,max:lease?2:3,connectionTimeoutMillis:1000});pools.push(p);return p;};
 let outcome;
 try{
  const identity=pool(process.env.PG_GRAPH_TEST_RUNTIME_URL);
  const repository=require('../../server/database/postgres/identityRepository').createIdentityRepository(identity);
  const auth=require('../../server/services/postgresIdentityAdapter').createPostgresIdentityAdapter({repository,jwtSecret:'protected-owned-native-only-signature'});
  const targets=require('../../server/services/mcp/ownedTargetClient').createMcpOwnedTargetClient({baseURL:input.baseURL,token:input.privateToken,timeoutMs:3000});await targets.readiness();
  production=await require('../../server/services/mcp/protectedRecoveryProduction').createProtectedRecoveryProduction({env:{MCP_PROTECTED_RECOVERY_ENABLED:'true',IDENTITY_DATABASE_URL:process.env.PG_GRAPH_TEST_RUNTIME_URL,MCP_WORKSHOP_DATABASE_URL:process.env.PG_MCP_RUNTIME_URL},identityAdapter:{pool:identity,validateSession:t=>auth.validateSession(t)},targets});
  require('node:assert/strict').equal(require('../../server/database/postgres').getPoolBudgetSnapshot().reserved,4);
  const service=production;
  const app=require('express')();app.use(require('express').json());
  const authenticateToken=async(req,res,next)=>{const token=(req.headers.authorization||'').replace(/^Bearer /,'');try{const value=await auth.validateSession(token);if(!value?.user)return res.status(401).json({error:'login_required'});req.user=value.user;next();}catch{return res.status(401).json({error:'login_required'});}};
  app.post('/api/workshop/mcp/protected-operations/reconcile',require('../../server/middleware/workshopPlatformAuthority').createWorkshopPlatformAuthority({authenticateToken}),require('../../server/services/mcp/protectedRecoveryRoute').createProtectedRecoveryHandler({getService:()=>service}));
  server=await new Promise(resolve=>{const value=app.listen(0,'127.0.0.1',()=>resolve(value));});
  const response=await fetch('http://127.0.0.1:'+server.address().port+'/api/workshop/mcp/protected-operations/reconcile',{method:'POST',headers:{'content-type':'application/json',authorization:input.authorization},body:JSON.stringify(input.body||{operationId:input.operationId})});const result=await response.json();
  outcome=response.ok?{ok:true,result}:{ok:false,status:response.status,code:result.error};
 }catch(error){outcome={ok:false,code:error.code||null,message:error.message,httpServerStarted:Boolean(server),serviceConstructed:Boolean(production)};}
 const cleanupErrors=await closeChildResources({production,server,pools});
 if(cleanupErrors.length)outcome=outcome?.ok===false?{...outcome,cleanupErrors}:{ok:false,code:'MCP_PROTECTED_RECOVERY_CLEANUP_FAILED',result:outcome,cleanupErrors};
 return outcome;
}
if(require.main===module)process.once('message',async input=>{
 try{process.send(await runChild(input));}finally{process.disconnect();}
});
module.exports={closeChildResources,runChild,errorRecord};
