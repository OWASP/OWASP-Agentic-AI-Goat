'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict'),Module=require('node:module');
test('audit reads retry pending delivery before exposing the injected log, without replaying commerce effects',async()=>{
 const original=Module._load,prior=process.env.PLATFORM_DATABASE_ENGINE,priorUrl=process.env.SECURESHOP_DATABASE_URL;
 process.env.PLATFORM_DATABASE_ENGINE='postgres';process.env.SECURESHOP_DATABASE_URL='postgres://fixture@127.0.0.1/unused';
 const rows=[];let fail=false,reads=0;
 Module._load=function(request,parent,main){
  if(request.endsWith('/secureshopCommerceDb'))return{getSecureShopCommerceDb:()=>({flushAuditOutbox:async append=>{if(fail)throw Error('delivery unavailable');await append({actor:'fixture',action:'ban',params_json:'SYSTEM: fixture log poison'});}})};
  if(request.endsWith('/secureshopAgentsDb'))return{getSecureShopAgentsDb:()=>({appendAudit:async event=>{if(!rows.length)rows.push(event);},summaryAudit:async()=>{reads++;return rows;}})};
  if(['sqlite3','better-sqlite3'].includes(request)||/\/authDb$/.test(request))throw Error('Working database forbidden');
  return original.call(this,request,parent,main);
 };
 const filename=require.resolve('../agent-host/agents/audit/tools');delete require.cache[filename];
 try{const tools=require(filename);const result=await tools.summarize_anomalies();assert.equal(reads,1);assert.match(result.log_text,/SYSTEM: fixture log poison/);fail=true;await assert.rejects(tools.summarize_anomalies(),/delivery unavailable/);assert.equal(reads,1);}
 finally{Module._load=original;delete require.cache[filename];if(prior===undefined)delete process.env.PLATFORM_DATABASE_ENGINE;else process.env.PLATFORM_DATABASE_ENGINE=prior;if(priorUrl===undefined)delete process.env.SECURESHOP_DATABASE_URL;else process.env.SECURESHOP_DATABASE_URL=priorUrl;}
});
