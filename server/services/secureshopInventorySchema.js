'use strict';
const {fail}=require('./secureshopInventoryContract');
async function assertInventorySchema(pool){
 if(typeof pool?.query!=='function')throw fail('INVENTORY_SCHEMA_UNAVAILABLE');
 const relation=(await pool.query("SELECT to_regclass('secureshop_review.owned_inventory_operations') IS NOT NULL AS present")).rows[0];
 if(relation?.present!==true)throw fail('INVENTORY_SCHEMA_UNAVAILABLE');
 const rights=(await pool.query(`SELECT has_table_privilege(current_user,'secureshop_review.owned_inventory_operations','SELECT') AS reads,
 has_table_privilege(current_user,'secureshop_review.owned_inventory_operations','INSERT') AS admits,
 has_table_privilege(current_user,'secureshop_review.owned_inventory_operations','UPDATE') AS completes,
 has_table_privilege(current_user,'secureshop_review.owned_inventory_operations','DELETE') AS deletes,
 has_column_privilege(current_user,'secureshop_review.product_target_products','stock_quantity','UPDATE') AS changes_snapshot`)).rows[0];
 if(!rights||rights.reads!==true||rights.admits!==true||rights.completes!==true||rights.deletes!==false||rights.changes_snapshot!==false)throw fail('INVENTORY_SCHEMA_UNAVAILABLE');
 const expected=[['owned_inventory_operation_guard','owned_inventory_operations','guard_owned_inventory_operation',31,false],['retire_owned_inventory_operations','product_targets','retire_owned_inventory_operations',17,true]];
 const rows=(await pool.query(`SELECT t.tgname,t.tgrelid::regclass::text AS relation,t.tgfoid::regprocedure::text AS function,t.tgtype::integer AS type,
 p.prosecdef AS definer,has_function_privilege(current_user,p.oid,'EXECUTE') AS executable,
 EXISTS(SELECT 1 FROM aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) a WHERE a.grantee=0 AND a.privilege_type='EXECUTE') AS public_execute,
 p.proconfig AS settings FROM pg_trigger t JOIN pg_proc p ON p.oid=t.tgfoid
 WHERE NOT t.tgisinternal AND t.tgenabled='O' AND t.tgname=ANY($1::text[])`,[expected.map(row=>row[0])])).rows;
 if(rows.length!==2||!expected.every(([name,table,fn,type,definer])=>rows.some(row=>row.tgname===name&&row.relation==='secureshop_review.'+table&&row.function==='secureshop_review.'+fn+'()'&&row.type===type&&row.definer===definer&&row.executable===true&&row.public_execute===false&&(!definer||row.settings?.includes('search_path=pg_catalog, secureshop_review')))))throw fail('INVENTORY_SCHEMA_UNAVAILABLE');
 return true;
}
module.exports={assertInventorySchema};
