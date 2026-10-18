
'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const root=path.join(__dirname,'../db/postgres/workshop-migrations/secureshop_agents');
const purposes=s=>[...s.matchAll(/'((?:secureshop_|mcp_|persona_|controlled_|review_|general)[a-z_]*)'/g)].map(m=>m[1]);
test('0097 is additive to every admitted 0095 purpose and preserves authority constraint',()=>{
 const prior=fs.readFileSync(path.join(root,'0095_coupon_probe_conversation_purpose.sql'),'utf8');
 const next=fs.readFileSync(path.join(root,'0097_product_search_union_conversation_purpose.sql'),'utf8');
 for(const p of purposes(prior))assert.ok(purposes(next).includes(p),p);
 assert.ok(purposes(next).includes('secureshop_product_search_union'));
 assert.match(next,/authority_mode='launch_bound' OR conversation_purpose='general'/);
 assert.doesNotMatch(next,/DELETE FROM|UPDATE secureshop_agents.agent_sessions/);
 assert.equal(require('../server/services/secureshopConversationPurpose').SECURESHOP_CONVERSATION_PURPOSES.productSearchUnion,'secureshop_product_search_union');
});
