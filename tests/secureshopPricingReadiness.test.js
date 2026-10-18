'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {assertPricingReadiness}=require('../server/database/postgres/secureshopPricingReadiness');
function pool({role='dvaia_secureshop_agents_runtime',flipTable,flipPrivilege,trigger=true,fn=true,publicGrant=false,columnGrant=false}={}){return{async query(sql,args=[]){
 if(sql.includes('current_user AS role'))return{rows:[{role}]};
 if(sql.includes('has_table_privilege')){let allowed=args[1]==='SELECT'||args[1]==='INSERT'&&!args[0].endsWith('cleanup_receipts');if(args[0].endsWith('_'+flipTable)&&args[1]===flipPrivilege)allowed=!allowed;return{rows:[{allowed}]};}
 if(sql.includes('AS private'))return{rows:[{private:!publicGrant}]};
 if(sql.includes('has_column_privilege'))return{rows:[{attname:'run_id',writable:columnGrant}]};
 if(sql.includes('pg_trigger'))return{rows:[{ready:trigger}]};
 if(sql.includes('pg_proc')){for(const name of ['guard_pricing_record','guard_pricing_actor','cleanup_pricing_records'])assert.ok(sql.includes("WHEN '"+name+"' THEN '"));return{rows:[{ready:fn}]};}
 throw Error('Unexpected read after injected drift');
}};}
test('readiness rejects each missing required or newly granted forbidden privilege independently',async()=>{
 for(const table of ['admissions','outcomes','cleanup_receipts'])for(const privilege of ['SELECT','INSERT','UPDATE','DELETE','TRUNCATE','REFERENCES','TRIGGER'])await assert.rejects(assertPricingReadiness(pool({flipTable:table,flipPrivilege:privilege})),{code:'PRICING_NOT_READY'});
});
test('runtime identity, PUBLIC/column grants, trigger drift and function body/grant failure deny readiness',async()=>{
 for(const options of [{role:'migration'},{publicGrant:true},{columnGrant:true},{trigger:false},{fn:false}])await assert.rejects(assertPricingReadiness(pool(options)),{code:'PRICING_NOT_READY'});
});
