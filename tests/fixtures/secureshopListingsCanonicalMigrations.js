'use strict';
const assert=require('node:assert/strict'),{randomUUID}=require('node:crypto');
const {migrate}=require('../../db/postgres/migrate');
async function qualifyCanonicalMigrations({agents,am,review,rm}){
 await migrate(am,process.env.LISTINGS_AGENTS_PRIOR_MIGRATIONS);await migrate(rm,process.env.OWNED_LISTING_CANONICAL_MIGRATIONS);
 const repo=require('../../server/database/postgres/secureshopBoundConversationsRepository').createBoundConversationsRepository({pool:agents,queue:async(_id,work)=>work()}),binding={launchId:randomUUID(),scenarioId:randomUUID(),generation:1,platformOwnerId:991,platformSessionId:992,shopUserId:993,role:'merchant'},sessionId=randomUUID();
 await repo.acquireBoundSession({id:sessionId,binding,purpose:'general'});await repo.activateBoundSession(sessionId,binding,'general');await repo.appendMessage(sessionId,binding,{role:'user',content:'Preserved pre-Listings conversation'},'general');const beforeAgent=(await am.query('SELECT * FROM secureshop_agents.agent_sessions WHERE id=$1',[sessionId])).rows;
 const targetId=randomUUID();await rm.query(`INSERT INTO secureshop_review.product_targets(target_id,launch_id,scenario_id,generation,original_platform_owner_id,original_platform_session_id,own_merchant_id,source_count,source_sha256) VALUES($1,$2,$3,1,9997,9998,12,1,$4)`,[targetId,randomUUID(),randomUUID(),Buffer.alloc(32,1)]);
 await rm.query(`INSERT INTO secureshop_review.product_target_products(target_id,product_id,source_retailer_id,retailer_id,source_product_sha256,name,description_html,price,stock_quantity,status) VALUES($1,1,12,12,$2,'Preserved seed','<i>Instructor raw HTML</i>',5,2,'active')`,[targetId,Buffer.alloc(32,2)]);
 const beforeProduct=(await review.query('SELECT * FROM secureshop_review.product_target_products WHERE target_id=$1',[targetId])).rows;
 const appliedAgents=await migrate(am,'db/postgres/workshop-migrations/secureshop_agents'),appliedReview=await migrate(rm,process.env.OWNED_LISTING_CANDIDATE_MIGRATIONS);
 assert.ok(appliedAgents.includes('0037_listing_conversation_purpose.sql'));for(const name of ['0022_owned_listing_operations.sql','0023_listing_declined_terminal.sql','0024_listing_rewrite_publication.sql'])assert.ok(appliedReview.includes(name));
 assert.deepEqual((await am.query('SELECT * FROM secureshop_agents.agent_sessions WHERE id=$1',[sessionId])).rows,beforeAgent);assert.deepEqual((await review.query('SELECT * FROM secureshop_review.product_target_products WHERE target_id=$1',[targetId])).rows,beforeProduct);
 assert.deepEqual(await migrate(am,'db/postgres/workshop-migrations/secureshop_agents'),[]);assert.deepEqual(await migrate(rm,process.env.OWNED_LISTING_CANDIDATE_MIGRATIONS),[]);
 return{status:'passed',appliedAgents,appliedReview,checks:['canonical prerequisite initialization','populated pre-Listings conversation and raw product preserved','canonical ordered upgrade','second initialization no-op'],scope:'Canonical populated upgrade and no-op; exact-byte fresh qualification retained from prior independent native reports'};
}
module.exports={qualifyCanonicalMigrations};
