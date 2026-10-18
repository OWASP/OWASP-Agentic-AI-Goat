'use strict';
// Explicit model-shaped controlled provider: no actual model or Judge credit.
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict'),{randomUUID}=require('node:crypto');
assert.equal(process.env.PG_TEST_DISPOSABLE,'yes');assert.equal(process.env.INVENTORY_FULL_APP,'1');
const file=path.join(process.env.LISTINGS_EVIDENCE_ROOT,'controlled-inventory-provider.json'),counts={actualModelCalls:0,judgeCalls:0,decisions:0,finals:0,metadataOverride:true};
const save=()=>fs.writeFileSync(file,JSON.stringify(counts),{mode:0o600});save();
const production=require('../../server/services/secureshopInventoryProduction'),original=production.createInventoryProduction;
production.PRODUCTION_QUALIFIED=true; // Private fixture process only; shared gate unchanged.
production.createInventoryProduction=options=>original({...options,provider:{config:{provider:'controlled-inventory-ui',model:'transport-fixture',mocked:false},async chat(){const step=counts.decisions++;assert.ok(counts.decisions<=4);save();return{provider:'controlled-inventory-ui',model:'transport-fixture',mocked:false,fallback:false,stop_reason:'tool_use',tool_uses:[{id:randomUUID(),name:step%2===0?'inventory.stock_levels':'inventory.set_stock',args:step%2===0?{}:{productId:1,quantity:4}}]};},async finalResponse(){counts.finals++;save();return{provider:'controlled-inventory-ui',model:'transport-fixture',mocked:false,fallback:false,stop_reason:'end_turn',responseMode:'structured_final',text:'Controlled inventory request completed.'};}},assessmentDependencies:{...options.assessmentDependencies,judge:async()=>{counts.judgeCalls++;save();throw Error('Judge forbidden in inventory transport cohort');}}});
