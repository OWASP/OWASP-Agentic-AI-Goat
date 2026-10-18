'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {WORKSHOP_OBJECTIVES,toWorkshopKey,toChallengeKey}=require('../server/config/workshopCatalog');
const {createPostgresWorkshopRouter}=require('../server/routes/postgresWorkshop');
test('shared catalog preserves DPI/IPI identities and canonical forward/reverse challenge mapping',()=>{
 assert.equal(WORKSHOP_OBJECTIVES.direct_prompt_injection.length,8);assert.equal(WORKSHOP_OBJECTIVES.indirect_prompt_injection.length,10);
 assert.equal(toWorkshopKey('reflected_xss_llm'),'xss_workshop');assert.equal(toWorkshopKey('direct_prompt_injection'),'direct_prompt_injection');
 assert.equal(toWorkshopKey('mcp_server_rce'),'mcp_workshop');assert.equal(toChallengeKey('mcp_workshop'),'mcp_server_rce');
});
test('supported user activity preserves canonical MCP identity and instructor title for authenticated owner',async()=>{
 const calls=[],stamp='2026-10-06T00:00:00Z';
 const router=createPostgresWorkshopRouter({authenticateToken(){},accountRepository:{},stores:{progress:{recordHeartbeat(){assert.fail('Unrelated time endpoint');},async getVisibleUserProgress(owner){calls.push(['progress',owner]);return[{workshopKey:toWorkshopKey('mcp_server_rce'),title:'Instructor MCP title',objectives:[{id:'mcp_recon',label:'Instructor recon',completed:true,completedAt:stamp},{id:'mcp_other',completed:false}]}];}},pool:{async query(sql,args){calls.push([sql,args]);return{rows:sql.includes('identity.users')?[{last_login:stamp}]:[{id:9,action_type:'login_success',timestamp:'2026-10-05T00:00:00Z'}]};}}}});
 const layer=router.stack.find(x=>x.route?.path==='/user-activity');assert(layer);let body;
 await layer.route.stack.at(-1).handle({user:{id:71}},{json(value){body=value;}},error=>{if(error)throw error;});
 assert.deepEqual(body.activity[0],{id:'obj_mcp_workshop_mcp_recon',type:'challenge',title:'Completed: Instructor recon',description:'in Instructor MCP title',timestamp:stamp,completed_at:stamp,workshop_key:'mcp_workshop',objective_id:'mcp_recon',objective_label:'Instructor recon',workshop_name:'Instructor MCP title'});
 assert.equal(body.activity.length,2);assert.equal(body.lastLogin,stamp);assert.deepEqual(calls[0],['progress',71]);
 for(const [sql,args] of calls.slice(1)){assert.match(sql,/WHERE (?:user_id|id)=\$1/);assert.deepEqual(args,[71]);}
});
