'use strict';
const assert=require('node:assert/strict');
const {randomUUID}=require('node:crypto');
function requireToolResult(status,body){assert.equal(status,200,'actual MCP tool HTTP status');assert.equal(body?.error,undefined,'no JSON-RPC error');assert.equal(body?.result?.isError,false,'actual MCP tool succeeded');assert(Array.isArray(body.result.content));return body.result.content.map(v=>v.text||'').join('\n');}
function requireRetirement(receipt,scope,operationId){for(const [key,value] of Object.entries({targetId:scope.targetId,ownerId:scope.platformOwnerId,platformSessionId:scope.platformSessionId,generation:scope.generation,operationId,status:'completed',cleanupPending:false}))assert(receipt?.[key]===value,`exact retirement ${key}`);assert.match(receipt.receiptSha256,/^[a-f0-9]{64}$/);}
function readinessDiagnostic(outcomes){
 const [sandbox,mail]=outcomes;
 const project=(outcome,keys)=>Object.fromEntries(keys.map(key=>[key,outcome?.status==='fulfilled'&&outcome.value?.[key]===true]));
 return {sandbox:{...project(sandbox,['ready','runnerReady']),reason:sandbox?.status==='rejected'?'readiness_rejected':'receipt_not_ready'},mail:{...project(mail,['ready','smtp','api']),reason:mail?.status==='rejected'?'readiness_rejected':'receipt_not_ready'}};
}
async function waitForExternalReadiness(signal){
 const client=require('../../server/services/mcp/ownedTargetClient').createMcpOwnedTargetClient({baseURL:process.env.MCP_OWNED_TARGET_URL,token:process.env.MCP_OWNED_TARGET_TOKEN,timeoutMs:3000});
 const mail=require('../../server/services/mcp/mailClient'),until=Date.now()+45000;
 while(true){signal.throwIfAborted();const outcomes=await Promise.allSettled([client.readiness(),mail.readiness()]);
  if(outcomes.every(x=>x.status==='fulfilled'&&x.value.ready===true)&&outcomes[0].value.runnerReady===true)return;
  assert(Date.now()<until,'actual strict sandbox and real SMTP/API readiness: '+JSON.stringify(readinessDiagnostic(outcomes)));await new Promise(resolve=>setTimeout(resolve,100));
 }
}
async function createExternalEffects({base,subject,sibling,subjectSession,siblingSession,pool,identityPool,signal}){
 const mail=require('../../server/services/mcp/mailClient');
 async function tool(session,name,args){const response=await fetch(base+'/api/workshop/mcp/jsonrpc',{method:'POST',headers:{authorization:`Bearer ${session.token}`,'content-type':'application/json'},body:JSON.stringify({jsonrpc:'2.0',id:randomUUID(),method:'tools/call',params:{name,arguments:args}}),signal:AbortSignal.any([signal,AbortSignal.timeout(15000)])});return requireToolResult(response.status,await response.json());}
 async function fullMessage(message){const response=await fetch(process.env.MAILPIT_API_URL+'/api/v1/message/'+encodeURIComponent(message.id),{signal:AbortSignal.any([signal,AbortSignal.timeout(5000)])});assert.equal(response.status,200);const value=await response.json();assert.equal(value.ID,message.id);assert.equal(typeof value.Text,'string');return JSON.stringify({ID:value.ID,MessageID:value.MessageID,To:value.To,From:value.From,Subject:value.Subject,Text:value.Text,HTML:value.HTML,Attachments:value.Attachments});}
 const rows=async(owner)=> (await pool.query('SELECT target_id,platform_session_id,generation,state FROM mcp.runner_targets WHERE user_key=$1 ORDER BY target_id',[String(owner.id)])).rows;
 const messages=async(owner)=>(await pool.query("SELECT assigned_message_id,status FROM mcp.mail_intents WHERE user_key=$1 ORDER BY intent_id",[String(owner.id)])).rows;
 async function noCredit(){for(const table of ['workshop_platform.objective_judgments','workshop_platform.completions'])assert.equal((await identityPool.query(`SELECT count(*)::integer AS n FROM ${table} WHERE user_id=ANY($1::integer[]) AND workshop_key='mcp_workshop'`,[[subject.id,sibling.id]])).rows[0].n,0,'manual Inspector cannot create Judge/progress credit');}
 await noCredit();
 const fixtures=[];
 for(const [owner,session] of [[subject,subjectSession],[sibling,siblingSession]]){
  const marker='ctf-deletion-'+randomUUID(),filename='/tmp/ctf-owned-lifecycle.txt';
  const output=await tool(session,'run_command',{command:`pwd; printf '%s' '${marker}' > ${filename}; cat ${filename}`});assert(output.includes(marker),'real sandbox wrote/read exact synthetic bytes');
  await tool(session,'send_report',{to:'cleanup@acme-corp.internal',body:marker});
  const targetRows=await rows(owner);assert.equal(targetRows.length,1);assert.equal(targetRows[0].state,'active');
  const intents=await messages(owner);assert.equal(intents.length,1);assert.equal(intents[0].status,'accepted');
  const observed=await mail.listMessagesBySmtpIds([intents[0].assigned_message_id]);assert.equal(observed.ok,true);assert.equal(observed.messages.length,1);
  fixtures.push({owner,session,marker,filename,target:targetRows[0],messageId:intents[0].assigned_message_id,mailBefore:await fullMessage(observed.messages[0])});
 }
 await noCredit();
 for(const owner of [subject,sibling])assert((await identityPool.query('SELECT count(*)::integer AS n FROM graph_runtime.effects e JOIN graph_runtime.runs r USING(run_id) WHERE r.owner_key=$1',[JSON.stringify(['MCP',String(owner.id)])])).rows[0].n>0,'actual MCP effect persisted');
 const targetClient=require('../../server/services/mcp/ownedTargetClient').createMcpOwnedTargetClient({baseURL:process.env.MCP_OWNED_TARGET_URL,token:process.env.MCP_OWNED_TARGET_TOKEN});
 return {async verifyAfterDeletion(currentBase){base=currentBase;const [deleted,kept]=fixtures;
  const targetRows=await rows(deleted.owner);assert.equal(targetRows.length,1);assert.equal(targetRows[0].state,'retired');
  const cleanups=(await pool.query("SELECT operation_id,status FROM mcp.runner_target_cleanups WHERE target_id=$1",[deleted.target.target_id])).rows;assert.equal(cleanups.length,1);assert.equal(cleanups[0].status,'completed');
  const scope={targetId:deleted.target.target_id,platformOwnerId:deleted.owner.id,platformSessionId:Number(deleted.target.platform_session_id),generation:Number(deleted.target.generation)};
  const receipt=await targetClient.readRetirement({scope,operationId:cleanups[0].operation_id});requireRetirement(receipt,scope,cleanups[0].operation_id);
  const absent=await mail.listMessagesBySmtpIds([deleted.messageId]);assert.equal(absent.ok,true);assert.equal(absent.messages.length,0);
  assert.deepEqual(await rows(kept.owner),[kept.target],'sibling target identity and state unchanged');
  const output=await tool(kept.session,'run_command',{command:`pwd >/dev/null; cat ${kept.filename}`});assert.equal(output.trim(),kept.marker,'sibling actual target bytes retained');
  const present=await mail.listMessagesBySmtpIds([kept.messageId]);assert.equal(present.ok,true);assert.equal(present.messages.length,1);assert((await fullMessage(present.messages[0]))===kept.mailBefore,'sibling full delivered mail bytes retained');
  await noCredit();
  return {targetFilesystemRetirement:true,mailDeliveryRetirement:true,siblingTargetBytesPreserved:true,siblingMailPreserved:true,manualInspector:true,modelCredit:false};
 }};
}
module.exports={readinessDiagnostic,createExternalEffects,requireToolResult,requireRetirement,waitForExternalReadiness};
