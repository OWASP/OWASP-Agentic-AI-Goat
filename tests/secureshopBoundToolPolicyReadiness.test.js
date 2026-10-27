'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {assertBoundToolPolicyReadiness}=require('../server/database/postgres/secureshopBoundToolPolicyReadiness');
const currentRegistry = require('../server/services/secureshopBoundAclRegistry');
const LEGACY_SEARCH_ROW={toolKey:'product-search.search',workflow:null,supported:false,roleApplicability:{customer:false,merchant:false,admin:false},defaultAllowed:{customer:true,merchant:true,admin:true},unavailableReason:'No supported bound execution workflow'};
const v27={...currentRegistry,REGISTRY:require('./helpers/secureshopHistoricalRegistry').registryV29Rows(currentRegistry.REGISTRY).map(row=>row.toolKey==='product-search.search'?LEGACY_SEARCH_ROW:row),REGISTRY_UPGRADES:currentRegistry.PRE_PRODUCT_SEARCH_REGISTRY_UPGRADES};
const LEGACY_COUPON_ROW = Object.freeze({toolKey:v27.COUPON_PROBE_KEY,workflow:null,supported:false,roleApplicability:{customer:false,merchant:false,admin:false},defaultAllowed:{customer:true,merchant:false,admin:true},unavailableReason:'No supported bound execution workflow'});
const latest = { ...v27, REGISTRY_VERSION:26, REGISTRY_SHA256:v27.MAIL_SUMMARY_PREDECESSOR_REGISTRY_SHA256,
 REGISTRY:v27.REGISTRY.filter(row=>row.toolKey!==v27.MAIL_SUMMARY_KEY&&row.toolKey!==v27.COUPON_PROBE_KEY).concat(LEGACY_COUPON_ROW).sort((a,b)=>a.toolKey.localeCompare(b.toolKey)),
 REGISTRY_UPGRADES:Object.fromEntries(Object.entries(v27.REGISTRY_UPGRADES)
  .filter(([hash])=>hash!==v27.MAIL_SUMMARY_PREDECESSOR_REGISTRY_SHA256)
  .map(([hash,keys])=>[hash,keys.filter(key=>key!==v27.MAIL_SUMMARY_KEY)])) };
const registryV25 = { ...latest, REGISTRY_VERSION:25, REGISTRY_SHA256:latest.DIAGNOSTIC_PREDECESSOR_REGISTRY_SHA256,
 REGISTRY:latest.REGISTRY.filter(row=>row.toolKey!==latest.DIAGNOSTIC_PREPARE_KEY),
 REGISTRY_UPGRADES:Object.fromEntries(Object.entries(latest.REGISTRY_UPGRADES)
  .filter(([hash])=>hash!==latest.DIAGNOSTIC_PREDECESSOR_REGISTRY_SHA256)
  .map(([hash,keys])=>[hash,keys.filter(key=>key!==latest.DIAGNOSTIC_PREPARE_KEY)])) };
const withoutManagement=(R,keys)=>keys.filter(key=>!R.ADMIN_MANAGEMENT_PREPARE_KEYS.includes(key));
const historicalRegistry = current => ({ ...current,
 REGISTRY_SHA256: current.PRICING_COMPARE_PREDECESSOR_REGISTRY_SHA256,
 REGISTRY_UPGRADES: Object.fromEntries(Object.entries(current.BASE_REGISTRY_UPGRADES)
  .filter(([hash])=>hash!==current.PRICING_COMPARE_PREDECESSOR_REGISTRY_SHA256)
  .map(([hash,keys])=>[hash,keys.filter(key=>key!==current.PRICING_COMPARE_PREPARE_KEY)])),
});

function fixture(mutate=()=>{}){let calls=0;return{async query(sql,args){const phase=calls++;let rows;
 if(phase===0)rows=[{runtime_role:'dvaia_secureshop_agents_runtime',schema_usage:true}];
 else if(phase===1)rows=args[0].map((table,i)=>({ordinal:i+1,present:true,allowed:args[1][i]==='SELECT'||(args[1][i]==='INSERT'&&!['bound_tool_policy_cleanup_receipts','bound_tool_registry_upgrade_cleanup_receipts'].includes(table))||(args[1][i]==='UPDATE'&&['bound_tool_policy_heads','bound_tool_policy_overrides'].includes(table))}));
 else if(phase===2)rows=args[0].map((_,i)=>({ordinal:i+1,present:true,definer:true,runtime_execute:false,public_execute:false,safe_path:true}));
 else if(phase===3){const types=[27,23,11,23,11,7,27,7,7,27,7,5,5,7,31,5,19,27,5];rows=args[1].map((_,i)=>({ordinal:i+1,tgenabled:'O',type:types[i],correct_function:true,unconditional:true}));}
 else if(phase===4)rows=[5,5,10,14,6,11,3].map((checks,i)=>({ordinal:i+1,checks,primary_keys:1,uniques:i===3?1:0,foreign_keys:i===1?1:0,validated:true}));
 else rows=[{primary_columns:['platform_launch_id','platform_scenario_id','platform_launch_generation','original_platform_owner_id','original_platform_session_id','successor_version'],successor_constraint:true,added_denials_constraint:'CHECK (((jsonb_typeof(added_denials) = \'array\'::text) AND (jsonb_array_length(added_denials) = ANY (ARRAY[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,64,65,66,67,69,70,71,73,74,75,76,77,78,79,80]))))',upgrade_guard_sha256:'445e8716ed8920be8666c95e7aaa04f662c61a1726172f6d93ac9fbff20f43d6',head_guard_sha256:'6830fb9d9680c1150204c3f3991345be6692008cae800e035b5e06e6b1549d95'}];
 mutate(phase,rows,sql,args);return{rows};}};}
test('exact runtime and individual required/forbidden grants are checked without writes',async()=>{await assertBoundToolPolicyReadiness(fixture((_p,_r,sql)=>assert.match(sql,/^SELECT/)));for(let index=0;index<49;index++)await assert.rejects(assertBoundToolPolicyReadiness(fixture((phase,rows)=>{if(phase===1)rows[index].allowed=!rows[index].allowed;})),{code:'BOUND_TOOL_POLICY_NOT_READY'});});
test('every private function fails closed for PUBLIC/runtime execution, absence or unsafe definition',async()=>{for(let index=0;index<9;index++)for(const [key,value] of [['runtime_execute',true],['public_execute',true],['present',false],['definer',false],['safe_path',false]])await assert.rejects(assertBoundToolPolicyReadiness(fixture((phase,rows)=>{if(phase===2)rows[index][key]=value;})),{code:'BOUND_TOOL_POLICY_NOT_READY'});});
test('all required trigger identities and validated constraint shapes must remain available',async()=>{for(let index=0;index<19;index++)for(const [key,value] of [['tgenabled','D'],['type',0],['correct_function',false],['unconditional',false]])await assert.rejects(assertBoundToolPolicyReadiness(fixture((phase,rows)=>{if(phase===3)rows[index][key]=value;})),{code:'BOUND_TOOL_POLICY_NOT_READY'});for(let index=0;index<7;index++)for(const key of ['checks','primary_keys','uniques','foreign_keys','validated'])await assert.rejects(assertBoundToolPolicyReadiness(fixture((phase,rows)=>{if(phase===4)rows[index][key]=key==='validated'?false:99;})),{code:'BOUND_TOOL_POLICY_NOT_READY'});});
test('wrong role, missing catalog rows and query failure never report readiness',async()=>{await assert.rejects(assertBoundToolPolicyReadiness(fixture((phase,rows)=>{if(!phase)rows[0].runtime_role='migration';})),{code:'BOUND_TOOL_POLICY_NOT_READY'});await assert.rejects(assertBoundToolPolicyReadiness(fixture((phase,rows)=>{if(!phase)rows[0].schema_usage=false;})),{code:'BOUND_TOOL_POLICY_NOT_READY'});for(let n=0;n<6;n++)await assert.rejects(assertBoundToolPolicyReadiness(fixture((phase,rows)=>{if(phase===n)rows.pop();})),{code:'BOUND_TOOL_POLICY_NOT_READY'});await assert.rejects(assertBoundToolPolicyReadiness({query:async()=>{throw Error('private SQL detail');}}),e=>e.code==='BOUND_TOOL_POLICY_NOT_READY'&&!e.message.includes('private SQL'));});

test('canonical-denial successor readiness denies old function bytes, missing transition constraint and old receipt key',async()=>{const exact='CHECK (((jsonb_typeof(added_denials) = \'array\'::text) AND (jsonb_array_length(added_denials) = ANY (ARRAY[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,64,65,66,67,69,70,71,73,74,75,76,77,78,79,80]))))';for(const [key,value] of [['successor_constraint',false],['primary_columns',['platform_launch_id']],['added_denials_constraint','CHECK ((jsonb_array_length(added_denials) = ANY (ARRAY[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,64,65,66,67,69,70,71,73,74,75,76,77,78,79])))'],['added_denials_constraint',exact.replace(" AND "," OR ")],['added_denials_constraint',exact.replace(" = 'array'::text"," <> 'array'::text")],['added_denials_constraint',exact.replace("'array'::text","'object'::text")],['upgrade_guard_sha256','0e1425028934b2b0b42d8859a5c5b630f2cb1ff5d448d59a3f4886f7f0c5e7c4'],['head_guard_sha256','b'.repeat(64)]])await assert.rejects(assertBoundToolPolicyReadiness(fixture((phase,rows)=>{if(phase===5)rows[0][key]=value;})),{code:'BOUND_TOOL_POLICY_NOT_READY'});});

test('runtime readiness pins exact v39 guard bytes and rejects token-only or old guard readiness',async()=>{
 const {readFileSync}=require('node:fs'),{join}=require('node:path');
 const sql=readFileSync(join(__dirname,'../db/postgres/workshop-migrations/secureshop_agents/0118_mcp_list_servers_registry_successor.sql'),'utf8');
 const expected=sql.match(/upgraded_guard_sha256 constant text := '([a-f0-9]{64})'/)[1];
 await assertBoundToolPolicyReadiness(fixture((phase,rows)=>{if(phase===5)rows[0].upgrade_guard_sha256=expected;}));
 for(const wrong of ['36f1ed75cc90c0e62c30a5495bcea4ddbbd024f3fd184391f33dfd606e7ce9af','851ca7a3b08b91dcc124112a2fe2cb01daf9f8c497e8dc445ef077571893ab4e','7fb69fd5108910bdeb523c416d17e4da915db87fee3b810a89fed00643eb424b','32a77ee440bdcc16e8e5b8606d5458a47eacae659dfa06aba1e1bf404ca55530','29c18a399a6273f8fde1c1c6c23355369a410f4beab42a8a52c2a2aa2115c2cf','ebd90aa7e547b3040bf946d5c25484aa615d799bd3a89ed69ac93bc1d142e6af','9f33be5293a6a7c0d91d499b20f790a7ce5aa932c16717f6ebfe295d1f69defc','cc4530dbd45ae2dffa6f006396e3c413c9e7de1fd7f45624d3193d8efeb4c5bb','0'.repeat(64)]){
  await assert.rejects(assertBoundToolPolicyReadiness(fixture((phase,rows)=>{if(phase===5){rows[0].upgrade_guard_sha256=wrong;rows[0].upgrade_guard_coupon_probe=true;}})),{code:'BOUND_TOOL_POLICY_NOT_READY'});
 }
});

test('v21 mail successor retains all v20 edges and defaults only three new merchant keys to deny',()=>{
 const {readFileSync}=require('node:fs'),{join}=require('node:path');
 const registryCurrent=registryV25;
 const R={...registryCurrent,REGISTRY_VERSION:21,REGISTRY_SHA256:registryCurrent.MERCHANT_MAIL_PREPARE_PREDECESSOR_REGISTRY_SHA256,
  REGISTRY:registryCurrent.REGISTRY.filter(row=>!registryCurrent.MERCHANT_MAIL_PREPARE_KEYS.includes(row.toolKey)&&!registryCurrent.MERCHANT_LISTING_SETUP_KEYS.includes(row.toolKey)&&row.toolKey!==registryCurrent.COUPON_PREPARE_KEY&&row.toolKey!==registryCurrent.TICKET_PREPARE_KEY),
  REGISTRY_UPGRADES:Object.fromEntries(Object.entries(registryCurrent.REGISTRY_UPGRADES).filter(([hash])=>hash!==registryCurrent.MERCHANT_MAIL_PREPARE_PREDECESSOR_REGISTRY_SHA256&&hash!==registryCurrent.MERCHANT_LISTING_SETUP_PREDECESSOR_REGISTRY_SHA256&&hash!==registryCurrent.COUPON_PREDECESSOR_REGISTRY_SHA256&&hash!==registryCurrent.TICKET_PREDECESSOR_REGISTRY_SHA256&&hash!==registryCurrent.COUPON_PROBE_PREDECESSOR_REGISTRY_SHA256)
   .map(([hash,keys])=>[hash,keys.filter(key=>!registryCurrent.MERCHANT_MAIL_PREPARE_KEYS.includes(key)&&!registryCurrent.MERCHANT_LISTING_SETUP_KEYS.includes(key)&&key!==registryCurrent.COUPON_PREPARE_KEY&&key!==registryCurrent.TICKET_PREPARE_KEY)]))};
 const base=join(__dirname,'../db/postgres/workshop-migrations/secureshop_agents');
 const prior=readFileSync(join(base,'0080_merchant_manual_search_registry_successor.sql'),'utf8');
 const current=readFileSync(join(base,'0082_merchant_mail_reads_registry_successor.sql'),'utf8');
 const edges=value=>[...value.matchAll(/encode\(predecessor_sha256,'hex'\)='[a-f0-9]+' AND encode\(successor_sha256,'hex'\)='[a-f0-9]+' AND jsonb_array_length\(added_denials\)=\d+/g)].map(match=>match[0]);
 assert.equal(edges(prior).length,190);assert.equal(edges(current).length,210);
 for(const edge of edges(prior))assert.ok(edges(current).includes(edge),'historical edge retained exactly');
 assert.match(current,/DROP CONSTRAINT bound_tool_registry_successor_v20,\s+ADD CONSTRAINT bound_tool_registry_successor_v21 CHECK/);
 assert.equal(R.REGISTRY_UPGRADES[R.MERCHANT_MAIL_PREDECESSOR_REGISTRY_SHA256].length,3);
 assert.deepEqual(R.REGISTRY_UPGRADES[R.MERCHANT_MAIL_PREDECESSOR_REGISTRY_SHA256],R.MERCHANT_MAIL_KEYS);
 const head=current.slice(current.indexOf(`IF encode(NEW.successor_sha256,'hex')='${R.REGISTRY_SHA256}' THEN`));
 const branch=head.slice(0,head.indexOf(' ELSE NULL END;'));
 for(const [hash,keys] of Object.entries(R.REGISTRY_UPGRADES)){
  const expected=R.REGISTRY.filter(row=>keys.includes(row.toolKey)).flatMap(row=>R.ROLES.filter(role=>row.roleApplicability[role]).map(role=>({toolKey:row.toolKey,role})));
  assert.ok(branch.includes(`WHEN '${hash}' THEN '${JSON.stringify(expected)}'::jsonb`),'exact canonical new denial set');
  assert.ok(current.includes(`(encode(predecessor_sha256,'hex')='${hash}' AND encode(successor_sha256,'hex')='${R.REGISTRY_SHA256}' AND jsonb_array_length(added_denials)=${expected.length})`),'new edge count');
 }
 assert.match(current,/REVOKE ALL ON FUNCTION secureshop_agents\.guard_bound_tool_registry_upgrade\(\)\s+FROM PUBLIC,dvaia_secureshop_agents_runtime/);
});

test('v23 listing setup successor retains 231 history edges and admits every published predecessor only with its exact current denials',()=>{
 const {readFileSync}=require('node:fs'),{join}=require('node:path');
 const latest=registryV25;
 const R={...latest,REGISTRY_SHA256:latest.COUPON_PREDECESSOR_REGISTRY_SHA256,
  REGISTRY:latest.REGISTRY.filter(row=>row.toolKey!==latest.COUPON_PREPARE_KEY&&row.toolKey!==latest.TICKET_PREPARE_KEY),
  REGISTRY_UPGRADES:Object.fromEntries(Object.entries(latest.REGISTRY_UPGRADES)
   .filter(([hash])=>hash!==latest.COUPON_PREDECESSOR_REGISTRY_SHA256&&hash!==latest.TICKET_PREDECESSOR_REGISTRY_SHA256&&hash!==latest.COUPON_PROBE_PREDECESSOR_REGISTRY_SHA256)
   .map(([hash,keys])=>[hash,keys.filter(key=>key!==latest.COUPON_PREPARE_KEY&&key!==latest.TICKET_PREPARE_KEY)]))};
 const text=readFileSync(join(__dirname,'../db/postgres/workshop-migrations/secureshop_agents/0085_merchant_listing_setup_registry_successor.sql'),'utf8');
 assert.match(text,/old_guard_sha256 constant text := '0e1425028934b2b0b42d8859a5c5b630f2cb1ff5d448d59a3f4886f7f0c5e7c4'/);
 assert.match(text,/upgraded_guard_sha256 constant text := '06c33ce3114d68003f0271384d4524f0a1a7256adc5a172c333513a433b8d02b'/);
 assert.match(text,/regexp_count\(constraint_def,'jsonb_array_length'\)<>231/);
 const edge=hash=>"encode(predecessor_sha256,''hex'')=''"+hash+"'' AND encode(successor_sha256,''hex'')=''"+R.REGISTRY_SHA256+"''";
 const guardEdge=hash=>"encode(NEW.predecessor_sha256,''hex'')=''"+hash+"'' AND encode(NEW.successor_sha256,''hex'')=''"+R.REGISTRY_SHA256+"''";
 const denials=keys=>R.REGISTRY.filter(row=>keys.includes(row.toolKey)).flatMap(row=>R.ROLES.filter(role=>row.roleApplicability[role]).map(role=>({toolKey:row.toolKey,role}))).sort((a,b)=>a.toolKey.localeCompare(b.toolKey)||a.role.localeCompare(b.role));
 assert.equal(Object.keys(R.REGISTRY_UPGRADES).length,22);
 assert.equal((text.match(new RegExp("encode\\(NEW\\.successor_sha256,''hex''\\)=''"+R.REGISTRY_SHA256+"''",'g'))||[]).length,23,'22 edge clauses plus the v23 expected-denial branch');
 for(const [hash,keys] of Object.entries(R.REGISTRY_UPGRADES)){
  const expected=denials(keys);
  assert.ok(text.includes(guardEdge(hash)),'guard accepts '+hash);
  assert.ok(text.includes("WHEN ''"+hash+"'' THEN ''"+JSON.stringify(expected)+"''::jsonb"),'guard pins denials for '+hash);
  assert.ok(text.includes(edge(hash)+" AND jsonb_array_length(added_denials)="+expected.length),'constraint pins count for '+hash);
 }
 assert.match(text,/41,42,43,44,45,46,47,48/);assert.match(text,/59,61,63\)\);/);
});

test('merchant review successor retains every published transition and guards every new exact denial set',()=>{
 const fs=require('node:fs'),path=require('node:path');
 const base=path.join(__dirname,'../db/postgres/workshop-migrations/secureshop_agents');
 const prior=fs.readFileSync(path.join(base,'0067_merchant_orders_registry_successor.sql'),'utf8');
 const next=fs.readFileSync(path.join(base,'0068_merchant_reviews_registry_successor.sql'),'utf8');
 const R=historicalRegistry(registryV25);
 const historical=prior.match(/\(encode\(predecessor_sha256,'hex'\)='[a-f0-9]+' AND encode\(successor_sha256,'hex'\)='[a-f0-9]+' AND jsonb_array_length\(added_denials\)=\d+\)/g);
 assert.equal(historical.length,45);for(const edge of historical)assert.ok(next.includes(edge));
 const historicalUpgrades=Object.fromEntries(Object.entries(R.REGISTRY_UPGRADES)
  .filter(([hash])=>hash!==R.PROFILE_CHAT_REGISTRY_SHA256&&hash!==R.ADMIN_USER_REGISTRY_SHA256&&hash!==R.PASSWORD_RESET_PREDECESSOR_REGISTRY_SHA256&&hash!==R.ADMIN_POLICY_PREDECESSOR_REGISTRY_SHA256&&hash!==R.ADMIN_MCP_PREDECESSOR_REGISTRY_SHA256&&hash!==R.ADMIN_AUDIT_SYSTEM_PREDECESSOR_REGISTRY_SHA256&&hash!==R.ADMIN_MANAGEMENT_PREPARE_PREDECESSOR_REGISTRY_SHA256)
  .map(([hash,keys])=>[hash,withoutManagement(R,keys).filter(key=>!R.PROFILE_CHAT_KEYS.includes(key)&&!R.ADMIN_USER_PREPARE_KEYS.includes(key)&&key!==R.PASSWORD_RESET_SETUP_KEY&&!R.ADMIN_POLICY_KEYS.includes(key)&&!R.ADMIN_MCP_KEYS.includes(key)&&!R.ADMIN_AUDIT_SYSTEM_KEYS.includes(key))]));
 for(const [hash,keys] of Object.entries(historicalUpgrades)){
  const expected=withoutManagement(R,keys).filter(key=>!R.ADMIN_MCP_KEYS.includes(key)&&!R.ADMIN_AUDIT_SYSTEM_KEYS.includes(key)).flatMap(toolKey=>Object.entries(R.REGISTRY.find(row=>row.toolKey===toolKey).roleApplicability).filter(([,allowed])=>allowed).map(([role])=>({toolKey,role}))).sort((a,b)=>a.toolKey<b.toolKey?-1:a.toolKey>b.toolKey?1:0);
  assert.ok(next.includes(`(encode(predecessor_sha256,'hex')='${hash}' AND encode(successor_sha256,'hex')='${R.PROFILE_CHAT_REGISTRY_SHA256}' AND jsonb_array_length(added_denials)=${expected.length})`));
  assert.ok(next.includes(`WHEN '${hash}' THEN '${JSON.stringify(expected)}'::jsonb`));
 }
 const oldBody=prior.slice(prior.indexOf(" IF encode(NEW.successor_sha256,'hex')='fa2ca449"),prior.indexOf(' SELECT jsonb_agg(value ORDER'));
 assert.ok(next.includes(oldBody),'historical guard logic retained verbatim');
 assert.equal((next.match(/\(/g)||[]).length,(next.match(/\)/g)||[]).length);
 assert.match(next,/REVOKE ALL ON FUNCTION secureshop_agents.guard_bound_tool_registry_upgrade\(\) FROM PUBLIC,dvaia_secureshop_agents_runtime/);
});


test('merchant review guard closes the legal-edge predicate before its independent override digest check',()=>{
 const text=require('node:fs').readFileSync(require('node:path').join(__dirname,'../db/postgres/workshop-migrations/secureshop_agents/0068_merchant_reviews_registry_successor.sql'),'utf8');
 assert.match(text,/OR NOT \(\n[\s\S]*?\n  \)\n  OR NEW\.overrides_sha256<>sha256\(convert_to\(NEW\.overrides_before::text,'UTF8'\)\) THEN/);
 assert.doesNotMatch(text,/sha256\(convert_to\(NEW\.overrides_before::text,'UTF8'\)\n\s+OR \(encode/);
});

test('canonical-denial successor changes only the final generated-denial sort to C collation',()=>{
 const fs=require('node:fs'),path=require('node:path');
 const base=path.join(__dirname,'../db/postgres/workshop-migrations/secureshop_agents');
 const prior=fs.readFileSync(path.join(base,'0068_merchant_reviews_registry_successor.sql'),'utf8');
 const next=fs.readFileSync(path.join(base,'0069_registry_denial_canonical_order.sql'),'utf8');
 const functionBody=text=>text.match(/FUNCTION secureshop_agents\.guard_bound_tool_registry_upgrade\(\)[\s\S]*?AS \$\$([\s\S]*?)\$\$;/)?.[1];
 const oldBody=functionBody(prior),newBody=functionBody(next);
 const oldOrder="ORDER BY value->>'toolKey',value->>'role'";
 const newOrder="ORDER BY (value->>'toolKey') COLLATE \"C\",(value->>'role') COLLATE \"C\"";
 assert.equal(typeof oldBody,'string');assert.equal(typeof newBody,'string');
 assert.ok(newBody.includes(newOrder));assert.equal((newBody.match(/COLLATE \"C\"/g)||[]).length,2);
 assert.equal(newBody.replace(newOrder,oldOrder),oldBody);
 assert.match(newBody,/ORDER BY tool_key,role/,'override snapshots retain database ordering');
 assert.match(next,/REVOKE ALL ON FUNCTION secureshop_agents.guard_bound_tool_registry_upgrade\(\) FROM PUBLIC,dvaia_secureshop_agents_runtime/);
});


test('customer profile successor admits every published predecessor only with its exact new customer denials',()=>{
 const fs=require('node:fs'),path=require('node:path');
 const text=fs.readFileSync(path.join(__dirname,'../db/postgres/workshop-migrations/secureshop_agents/0070_customer_profile_registry_successor.sql'),'utf8');
 const R=historicalRegistry(registryV25);
 assert.match(text,/bound_tool_registry_successor_v12/);
 assert.match(text,/ORDER BY \(value->>'toolKey'\) COLLATE "C",\(value->>'role'\) COLLATE "C"/);
 for(const [hash,currentKeys] of Object.entries(R.REGISTRY_UPGRADES).filter(([hash])=>hash!==R.ADMIN_USER_REGISTRY_SHA256&&hash!==R.PASSWORD_RESET_PREDECESSOR_REGISTRY_SHA256&&hash!==R.ADMIN_POLICY_PREDECESSOR_REGISTRY_SHA256&&hash!==R.ADMIN_MCP_PREDECESSOR_REGISTRY_SHA256&&hash!==R.ADMIN_AUDIT_SYSTEM_PREDECESSOR_REGISTRY_SHA256&&hash!==R.ADMIN_MANAGEMENT_PREPARE_PREDECESSOR_REGISTRY_SHA256)){
  const keys=withoutManagement(R,currentKeys).filter(key=>!R.ADMIN_USER_PREPARE_KEYS.includes(key)&&key!==R.PASSWORD_RESET_SETUP_KEY&&!R.ADMIN_POLICY_KEYS.includes(key)&&!R.ADMIN_MCP_KEYS.includes(key)&&!R.ADMIN_AUDIT_SYSTEM_KEYS.includes(key));
  const expected=withoutManagement(R,keys).filter(key=>!R.ADMIN_MCP_KEYS.includes(key)&&!R.ADMIN_AUDIT_SYSTEM_KEYS.includes(key)).flatMap(toolKey=>Object.entries(R.REGISTRY.find(row=>row.toolKey===toolKey).roleApplicability).filter(([,allowed])=>allowed).map(([role])=>({toolKey,role}))).sort((a,b)=>a.toolKey<b.toolKey?-1:a.toolKey>b.toolKey?1:a.role<b.role?-1:a.role>b.role?1:0);
  assert.ok(text.includes(`(encode(NEW.predecessor_sha256,'hex')='${hash}' AND encode(NEW.successor_sha256,'hex')='${R.ADMIN_USER_REGISTRY_SHA256}')`));
  assert.ok(text.includes(`(encode(predecessor_sha256,'hex')='${hash}' AND encode(successor_sha256,'hex')='${R.ADMIN_USER_REGISTRY_SHA256}' AND jsonb_array_length(added_denials)=${expected.length})`));
  assert.ok(text.includes(`WHEN '${hash}' THEN '${JSON.stringify(expected)}'::jsonb`));
 }
});


test('admin successor preserves all historical edges and exact denied permissions with C ordering',()=>{
 const fs=require('node:fs'),path=require('node:path'),R=historicalRegistry(registryV25);
 const base=path.join(__dirname,'../db/postgres/workshop-migrations/secureshop_agents');
 const prior=fs.readFileSync(path.join(base,'0070_customer_profile_registry_successor.sql'),'utf8');
 const next=fs.readFileSync(path.join(base,'0071_admin_user_prepare_registry_successor.sql'),'utf8');
 const edges=text=>[...text.matchAll(/encode\(predecessor_sha256,'hex'\)='[a-f0-9]+' AND encode\(successor_sha256,'hex'\)='[a-f0-9]+' AND jsonb_array_length\(added_denials\)=\d+/g)].map(m=>m[0]);
 assert.equal(edges(prior).length,66);assert.equal(edges(next).length,78);for(const edge of edges(prior))assert.ok(edges(next).includes(edge));
 for(const [hash,keysWithPassword]of Object.entries(R.REGISTRY_UPGRADES).filter(([hash])=>hash!==R.PASSWORD_RESET_PREDECESSOR_REGISTRY_SHA256&&hash!==R.ADMIN_POLICY_PREDECESSOR_REGISTRY_SHA256&&hash!==R.ADMIN_MCP_PREDECESSOR_REGISTRY_SHA256&&hash!==R.ADMIN_AUDIT_SYSTEM_PREDECESSOR_REGISTRY_SHA256&&hash!==R.ADMIN_MANAGEMENT_PREPARE_PREDECESSOR_REGISTRY_SHA256)){
  const keys=withoutManagement(R,keysWithPassword).filter(key=>key!==R.PASSWORD_RESET_SETUP_KEY&&!R.ADMIN_POLICY_KEYS.includes(key)&&!R.ADMIN_MCP_KEYS.includes(key)&&!R.ADMIN_AUDIT_SYSTEM_KEYS.includes(key));
  const expected=withoutManagement(R,keys).filter(key=>!R.ADMIN_MCP_KEYS.includes(key)&&!R.ADMIN_AUDIT_SYSTEM_KEYS.includes(key)).flatMap(toolKey=>Object.entries(R.REGISTRY.find(row=>row.toolKey===toolKey).roleApplicability).filter(([,v])=>v).map(([role])=>({toolKey,role}))).sort((a,b)=>a.toolKey<b.toolKey?-1:a.toolKey>b.toolKey?1:a.role<b.role?-1:1);
  assert.ok(next.includes(`WHEN '${hash}' THEN '${JSON.stringify(expected)}'::jsonb`));
  assert.ok(next.includes(`(encode(NEW.predecessor_sha256,'hex')='${hash}' AND encode(NEW.successor_sha256,'hex')='${R.PASSWORD_RESET_PREDECESSOR_REGISTRY_SHA256}')`));
  assert.ok(next.includes(`(encode(predecessor_sha256,'hex')='${hash}' AND encode(successor_sha256,'hex')='${R.PASSWORD_RESET_PREDECESSOR_REGISTRY_SHA256}' AND jsonb_array_length(added_denials)=${expected.length})`));
 }
 const start=prior.indexOf(" IF encode(NEW.successor_sha256,'hex')="),end=prior.indexOf(' SELECT jsonb_agg(value ORDER');
 assert.ok(next.includes(prior.slice(start,end)),'historical denial branches retained verbatim');
 assert.equal((next.match(/\(/g)||[]).length,(next.match(/\)/g)||[]).length);
 assert.match(next,/bound_tool_registry_successor_v13/);
 assert.match(next,/COLLATE "C"/);
 assert.match(next,/REVOKE ALL ON FUNCTION secureshop_agents.guard_bound_tool_registry_upgrade\(\) FROM PUBLIC,dvaia_secureshop_agents_runtime/);
});

test('password reset successor preserves v13 receipts and adds one exact admin denial per predecessor',()=>{
 const fs=require('node:fs'),path=require('node:path'),{createHash}=require('node:crypto');
 const R=historicalRegistry(registryV25);
 const base=path.join(__dirname,'../db/postgres/workshop-migrations/secureshop_agents');
 const prior=fs.readFileSync(path.join(base,'0071_admin_user_prepare_registry_successor.sql'),'utf8');
 const next=fs.readFileSync(path.join(base,'0072_admin_password_reset_setup_registry_successor.sql'),'utf8');
 const edges=text=>[...text.matchAll(/encode\(predecessor_sha256,'hex'\)='[a-f0-9]+' AND encode\(successor_sha256,'hex'\)='[a-f0-9]+' AND jsonb_array_length\(added_denials\)=\d+/g)].map(match=>match[0]);
 assert.equal(edges(prior).length,78);assert.equal(edges(next).length,91);
 for(const edge of edges(prior))assert.ok(edges(next).includes(edge),'historical transition remains exact');
 assert.equal(createHash('sha256').update(next.match(/FUNCTION secureshop_agents\.guard_bound_tool_registry_upgrade\(\)[\s\S]*?AS \$\$([\s\S]*?)\$\$;/)[1]).digest('hex'),'444d71ef82c3dc6c06fa20cdcd3b671d2c41802b41d1e25905505f1eb001d0ce');
 for(const [hash,allKeys] of Object.entries(R.REGISTRY_UPGRADES).filter(([hash])=>hash!==R.ADMIN_POLICY_PREDECESSOR_REGISTRY_SHA256&&hash!==R.ADMIN_MCP_PREDECESSOR_REGISTRY_SHA256&&hash!==R.ADMIN_AUDIT_SYSTEM_PREDECESSOR_REGISTRY_SHA256&&hash!==R.ADMIN_MANAGEMENT_PREPARE_PREDECESSOR_REGISTRY_SHA256)){
  const keys=withoutManagement(R,allKeys).filter(key=>!R.ADMIN_POLICY_KEYS.includes(key)&&!R.ADMIN_MCP_KEYS.includes(key)&&!R.ADMIN_AUDIT_SYSTEM_KEYS.includes(key));
  assert.equal(keys.filter(key=>key===R.PASSWORD_RESET_SETUP_KEY).length,1);
  const expected=withoutManagement(R,keys).filter(key=>!R.ADMIN_MCP_KEYS.includes(key)&&!R.ADMIN_AUDIT_SYSTEM_KEYS.includes(key)).flatMap(toolKey=>Object.entries(R.REGISTRY.find(row=>row.toolKey===toolKey).roleApplicability)
   .filter(([,allowed])=>allowed).map(([role])=>({toolKey,role})))
   .sort((a,b)=>a.toolKey<b.toolKey?-1:a.toolKey>b.toolKey?1:a.role<b.role?-1:a.role>b.role?1:0);
  assert.ok(next.includes(`(encode(NEW.predecessor_sha256,'hex')='${hash}' AND encode(NEW.successor_sha256,'hex')='${R.ADMIN_POLICY_PREDECESSOR_REGISTRY_SHA256}')`));
  assert.ok(next.includes(`WHEN '${hash}' THEN '${JSON.stringify(expected)}'::jsonb`));
  assert.ok(next.includes(`(encode(predecessor_sha256,'hex')='${hash}' AND encode(successor_sha256,'hex')='${R.ADMIN_POLICY_PREDECESSOR_REGISTRY_SHA256}' AND jsonb_array_length(added_denials)=${expected.length})`));
 }
 assert.match(next,/DROP CONSTRAINT bound_tool_registry_successor_v13,\s+ADD CONSTRAINT bound_tool_registry_successor_v14 CHECK/);
 const successorLines=next.slice(next.indexOf('ADD CONSTRAINT bound_tool_registry_successor_v14 CHECK(')).split('\n')
  .filter(line=>line.includes("encode(predecessor_sha256,'hex')"));
 assert.equal(successorLines.length,91);
 for(const line of successorLines){
  assert.equal((line.match(/encode\(predecessor_sha256,'hex'\)/g)||[]).length,1,
   'each historical or v14 transition must remain an independent constraint branch');
  assert.match(line,/jsonb_array_length\(added_denials\)=\d+\)$/, 'each branch closes before the next OR');
 }
 assert.match(next,/REVOKE ALL ON FUNCTION secureshop_agents\.guard_bound_tool_registry_upgrade\(\) FROM PUBLIC,dvaia_secureshop_agents_runtime/);
 assert.equal((next.match(/\(/g)||[]).length,(next.match(/\)/g)||[]).length);
});

test('policy successor preserves 91 independent historical edges and adds 14 exact admin-only denial sets',()=>{
 const fs=require('node:fs'),path=require('node:path'),{createHash}=require('node:crypto');
 const R=historicalRegistry(registryV25);
 const base=path.join(__dirname,'../db/postgres/workshop-migrations/secureshop_agents');
 const prior=fs.readFileSync(path.join(base,'0072_admin_password_reset_setup_registry_successor.sql'),'utf8');
 const next=fs.readFileSync(path.join(base,'0073_admin_policy_registry_successor.sql'),'utf8');
 const edges=text=>[...text.matchAll(/encode\(predecessor_sha256,'hex'\)='[a-f0-9]+' AND encode\(successor_sha256,'hex'\)='[a-f0-9]+' AND jsonb_array_length\(added_denials\)=\d+/g)].map(match=>match[0]);
 assert.equal(edges(prior).length,91);assert.equal(edges(next).length,105);
 for(const edge of edges(prior))assert.ok(edges(next).includes(edge),'historical transition remains exact');
 const body=next.match(/FUNCTION secureshop_agents\.guard_bound_tool_registry_upgrade\(\)[\s\S]*?AS \$\$([\s\S]*?)\$\$;/)?.[1];
 assert.equal(createHash('sha256').update(body).digest('hex'),'214de5fb275514b6a86a1077647dd220d66304887811b7af284a95a573a008aa');
 for(const [hash,keys] of Object.entries(R.REGISTRY_UPGRADES).filter(([hash])=>hash!==R.ADMIN_MCP_PREDECESSOR_REGISTRY_SHA256&&hash!==R.ADMIN_AUDIT_SYSTEM_PREDECESSOR_REGISTRY_SHA256&&hash!==R.ADMIN_MANAGEMENT_PREPARE_PREDECESSOR_REGISTRY_SHA256)){
  assert.deepEqual(withoutManagement(R,keys).filter(key=>!R.ADMIN_MCP_KEYS.includes(key)&&!R.ADMIN_AUDIT_SYSTEM_KEYS.includes(key)).slice(-6),R.ADMIN_POLICY_KEYS);
  const expected=withoutManagement(R,keys).filter(key=>!R.ADMIN_MCP_KEYS.includes(key)&&!R.ADMIN_AUDIT_SYSTEM_KEYS.includes(key)).flatMap(toolKey=>Object.entries(R.REGISTRY.find(row=>row.toolKey===toolKey).roleApplicability)
   .filter(([,allowed])=>allowed).map(([role])=>({toolKey,role})))
   .sort((a,b)=>a.toolKey<b.toolKey?-1:a.toolKey>b.toolKey?1:a.role<b.role?-1:a.role>b.role?1:0);
  assert.ok(next.includes(`(encode(NEW.predecessor_sha256,'hex')='${hash}' AND encode(NEW.successor_sha256,'hex')='${R.ADMIN_MCP_PREDECESSOR_REGISTRY_SHA256}')`));
  assert.ok(next.includes(`WHEN '${hash}' THEN '${JSON.stringify(expected)}'::jsonb`));
  assert.ok(next.includes(`(encode(predecessor_sha256,'hex')='${hash}' AND encode(successor_sha256,'hex')='${R.ADMIN_MCP_PREDECESSOR_REGISTRY_SHA256}' AND jsonb_array_length(added_denials)=${expected.length})`));
 }
 assert.match(next,/DROP CONSTRAINT bound_tool_registry_successor_v14,\s+ADD CONSTRAINT bound_tool_registry_successor_v15 CHECK/);
 const successorLines=next.slice(next.indexOf('ADD CONSTRAINT bound_tool_registry_successor_v15 CHECK(')).split('\n')
  .filter(line=>line.includes("encode(predecessor_sha256,'hex')"));
 assert.equal(successorLines.length,105);
 const allowedCounts=new Set(next.match(/jsonb_array_length\(added_denials\) IN \(([^)]+)\)/)?.[1].split(',').map(Number));
 assert.ok(allowedCounts.has(24)&&allowedCounts.has(39));
 for(const line of successorLines){assert.equal((line.match(/encode\(predecessor_sha256,'hex'\)/g)||[]).length,1);assert.match(line,/jsonb_array_length\(added_denials\)=\d+\)$/);assert.ok(allowedCounts.has(Number(line.match(/jsonb_array_length\(added_denials\)=(\d+)\)$/)[1])));}
 assert.match(next,/REVOKE ALL ON FUNCTION secureshop_agents\.guard_bound_tool_registry_upgrade\(\) FROM PUBLIC,dvaia_secureshop_agents_runtime/);
 assert.equal((next.match(/\(/g)||[]).length,(next.match(/\)/g)||[]).length);
});

test('owned MCP successor preserves 105 historical edges and adds 15 exact admin-only denial sets',()=>{
 const fs=require('node:fs'),path=require('node:path'),{createHash}=require('node:crypto');
 const R=historicalRegistry(registryV25);
 const base=path.join(__dirname,'../db/postgres/workshop-migrations/secureshop_agents');
 const prior=fs.readFileSync(path.join(base,'0073_admin_policy_registry_successor.sql'),'utf8');
 const next=fs.readFileSync(path.join(base,'0074_admin_mcp_registry_successor.sql'),'utf8');
 const edges=text=>[...text.matchAll(/encode\(predecessor_sha256,'hex'\)='[a-f0-9]+' AND encode\(successor_sha256,'hex'\)='[a-f0-9]+' AND jsonb_array_length\(added_denials\)=\d+/g)].map(match=>match[0]);
 assert.equal(edges(prior).length,105);assert.equal(edges(next).length,120);
 for(const edge of edges(prior))assert.ok(edges(next).includes(edge),'historical transition remains exact');
 const body=next.match(/FUNCTION secureshop_agents\.guard_bound_tool_registry_upgrade\(\)[\s\S]*?AS \$\$([\s\S]*?)\$\$;/)?.[1];
 assert.equal(createHash('sha256').update(body).digest('hex'),'667a01be298cb0f9abcafd62abe4ccf1ecb54d39d46a4e296954555f322fcf24');
 for(const [hash,keys] of Object.entries(R.REGISTRY_UPGRADES).filter(([hash])=>hash!==R.ADMIN_AUDIT_SYSTEM_PREDECESSOR_REGISTRY_SHA256&&hash!==R.ADMIN_MANAGEMENT_PREPARE_PREDECESSOR_REGISTRY_SHA256)){
  assert.deepEqual(withoutManagement(R,keys).filter(key=>!R.ADMIN_AUDIT_SYSTEM_KEYS.includes(key)).slice(-6),R.ADMIN_MCP_KEYS);
  const expected=withoutManagement(R,keys).filter(key=>!R.ADMIN_AUDIT_SYSTEM_KEYS.includes(key)).flatMap(toolKey=>Object.entries(R.REGISTRY.find(row=>row.toolKey===toolKey).roleApplicability)
   .filter(([,allowed])=>allowed).map(([role])=>({toolKey,role})))
   .sort((a,b)=>a.toolKey<b.toolKey?-1:a.toolKey>b.toolKey?1:a.role<b.role?-1:a.role>b.role?1:0);
  assert.ok(next.includes(`(encode(NEW.predecessor_sha256,'hex')='${hash}' AND encode(NEW.successor_sha256,'hex')='${R.ADMIN_AUDIT_SYSTEM_PREDECESSOR_REGISTRY_SHA256}')`));
  assert.ok(next.includes(`WHEN '${hash}' THEN '${JSON.stringify(expected)}'::jsonb`));
  assert.ok(next.includes(`(encode(predecessor_sha256,'hex')='${hash}' AND encode(successor_sha256,'hex')='${R.ADMIN_AUDIT_SYSTEM_PREDECESSOR_REGISTRY_SHA256}' AND jsonb_array_length(added_denials)=${expected.length})`));
 }
 assert.match(next,/DROP CONSTRAINT bound_tool_registry_successor_v15,\s+ADD CONSTRAINT bound_tool_registry_successor_v16 CHECK/);
 const successorLines=next.slice(next.indexOf('ADD CONSTRAINT bound_tool_registry_successor_v16 CHECK(')).split('\n')
  .filter(line=>line.includes("encode(predecessor_sha256,'hex')"));
 assert.equal(successorLines.length,120);
 const allowedCounts=new Set(next.match(/jsonb_array_length\(added_denials\) IN \(([^)]+)\)/)?.[1].split(',').map(Number));
 for(const line of successorLines){assert.equal((line.match(/encode\(predecessor_sha256,'hex'\)/g)||[]).length,1);assert.match(line,/jsonb_array_length\(added_denials\)=\d+\)$/);assert.ok(allowedCounts.has(Number(line.match(/jsonb_array_length\(added_denials\)=(\d+)\)$/)[1])));}
 assert.match(next,/REVOKE ALL ON FUNCTION secureshop_agents\.guard_bound_tool_registry_upgrade\(\) FROM PUBLIC,dvaia_secureshop_agents_runtime/);
 assert.equal((next.match(/\(/g)||[]).length,(next.match(/\)/g)||[]).length);
});


test('admin audit and system read successor retains every v16 edge and adds only exact admin denials',()=>{
 const fs=require('node:fs'),path=require('node:path'),{createHash}=require('node:crypto'),R=historicalRegistry(registryV25);
 const base=path.join(__dirname,'../db/postgres/workshop-migrations/secureshop_agents');
 const prior=fs.readFileSync(path.join(base,'0074_admin_mcp_registry_successor.sql'),'utf8');
 const next=fs.readFileSync(path.join(base,'0075_admin_audit_system_read_registry_successor.sql'),'utf8');
 const edges=text=>[...text.matchAll(/encode\(predecessor_sha256,'hex'\)='[a-f0-9]+' AND encode\(successor_sha256,'hex'\)='[a-f0-9]+' AND jsonb_array_length\(added_denials\)=\d+/g)].map(match=>match[0]);
 assert.equal(edges(prior).length,120);assert.equal(edges(next).length,136);for(const edge of edges(prior))assert.ok(edges(next).includes(edge));
 const body=next.match(/FUNCTION secureshop_agents\.guard_bound_tool_registry_upgrade\(\)[\s\S]*?AS \$\$([\s\S]*?)\$\$;/)?.[1];
 assert.equal(createHash('sha256').update(body).digest('hex'),'7c36d3192c60a5eea2cf95d67212d98039e5f0e3bb65870166284a853562aec3');
 for(const [hash,keys] of Object.entries(R.REGISTRY_UPGRADES).filter(([hash])=>hash!==R.ADMIN_MANAGEMENT_PREPARE_PREDECESSOR_REGISTRY_SHA256)){const expected=keys.filter(key=>!R.ADMIN_MANAGEMENT_PREPARE_KEYS.includes(key)).flatMap(toolKey=>Object.entries(R.REGISTRY.find(row=>row.toolKey===toolKey).roleApplicability).filter(([,allowed])=>allowed).map(([role])=>({toolKey,role}))).sort((a,b)=>a.toolKey<b.toolKey?-1:a.toolKey>b.toolKey?1:a.role<b.role?-1:a.role>b.role?1:0);assert.ok(next.includes(`WHEN '${hash}' THEN '${JSON.stringify(expected)}'::jsonb`));assert.ok(next.includes(`(encode(predecessor_sha256,'hex')='${hash}' AND encode(successor_sha256,'hex')='${R.ADMIN_MANAGEMENT_PREPARE_PREDECESSOR_REGISTRY_SHA256}' AND jsonb_array_length(added_denials)=${expected.length})`));}
 assert.match(next,/DROP CONSTRAINT bound_tool_registry_successor_v16,\s+ADD CONSTRAINT bound_tool_registry_successor_v17 CHECK/);
 assert.match(body,/ORDER BY \(value->>'toolKey'\) COLLATE "C",\(value->>'role'\) COLLATE "C"/);
});

test('admin management successor preserves every v17 edge and defaults only the six new admin capabilities to deny',()=>{
 const fs=require('node:fs'),path=require('node:path'),{createHash}=require('node:crypto'),R=historicalRegistry(registryV25);
 const base=path.join(__dirname,'../db/postgres/workshop-migrations/secureshop_agents');
 const prior=fs.readFileSync(path.join(base,'0075_admin_audit_system_read_registry_successor.sql'),'utf8');
 const next=fs.readFileSync(path.join(base,'0076_admin_management_prepare_registry_successor.sql'),'utf8');
 const edges=text=>[...text.matchAll(/encode\(predecessor_sha256,'hex'\)='[a-f0-9]+' AND encode\(successor_sha256,'hex'\)='[a-f0-9]+' AND jsonb_array_length\(added_denials\)=\d+/g)].map(match=>match[0]);
 assert.equal(edges(prior).length,136);assert.equal(edges(next).length,153);for(const edge of edges(prior))assert.ok(edges(next).includes(edge));
 const expected=R.ADMIN_MANAGEMENT_PREPARE_KEYS.map(toolKey=>({toolKey,role:'admin'})).sort((a,b) => a.toolKey < b.toolKey ? -1 : a.toolKey > b.toolKey ? 1 : 0);
 const body=next.match(/FUNCTION secureshop_agents\.guard_bound_tool_registry_upgrade\(\)[\s\S]*?AS \$\$([\s\S]*?)\$\$;/)?.[1];
 assert.equal(createHash('sha256').update(body).digest('hex'),'740c51445a5f075a365f4697a37f30848d8533c5ec6a9fb66c072a38194c808c');
 for(const [predecessor,keys] of Object.entries(R.REGISTRY_UPGRADES)){
  const denials=keys.flatMap(toolKey=>Object.entries(R.REGISTRY.find(row=>row.toolKey===toolKey).roleApplicability).filter(([,allowed])=>allowed).map(([role])=>({toolKey,role}))).sort((a,b)=>a.toolKey<b.toolKey?-1:a.toolKey>b.toolKey?1:a.role<b.role?-1:a.role>b.role?1:0);
  assert.ok(body.includes(`WHEN '${predecessor}' THEN '${JSON.stringify(denials)}'::jsonb`));
  assert.ok(next.includes(`(encode(predecessor_sha256,'hex')='${predecessor}' AND encode(successor_sha256,'hex')='${R.REGISTRY_SHA256}' AND jsonb_array_length(added_denials)=${denials.length})`));
 }
 assert.ok(next.includes(`(encode(predecessor_sha256,'hex')='${R.ADMIN_MANAGEMENT_PREPARE_PREDECESSOR_REGISTRY_SHA256}' AND encode(successor_sha256,'hex')='${R.REGISTRY_SHA256}' AND jsonb_array_length(added_denials)=6)`));
 assert.ok(body.includes(`WHEN '${R.ADMIN_MANAGEMENT_PREPARE_PREDECESSOR_REGISTRY_SHA256}' THEN '${JSON.stringify(expected)}'::jsonb`));
 assert.match(next,/DROP CONSTRAINT bound_tool_registry_successor_v17,\s+ADD CONSTRAINT bound_tool_registry_successor_v18 CHECK/);
 assert.match(body,/ORDER BY \(value->>'toolKey'\) COLLATE "C",\(value->>'role'\) COLLATE "C"/);
});

test('0077 admits exactly the denial cardinalities used by all 153 v18 transition edges without changing the v18 guard',()=>{
 const fs=require('node:fs'),path=require('node:path');
 const base=path.join(__dirname,'../db/postgres/workshop-migrations/secureshop_agents');
 const v18=fs.readFileSync(path.join(base,'0076_admin_management_prepare_registry_successor.sql'),'utf8');
 const repair=fs.readFileSync(path.join(base,'0077_admin_management_successor_cardinality_repair.sql'),'utf8');
 const edgeCounts=[...v18.matchAll(/jsonb_array_length\(added_denials\)=(\d+)/g)].map(match=>Number(match[1]));
 assert.equal(edgeCounts.length,153);
 const expected=[...new Set(edgeCounts)].sort((a,b)=>a-b);
 const actual=repair.match(/jsonb_array_length\(added_denials\) IN \(([^)]+)\)/)?.[1].split(',').map(Number);
 assert.deepEqual(actual,expected);
 assert.ok(actual.includes(54),'direct v1-to-v18 receipt cardinality remains admissible');
 assert.match(repair,/DROP CONSTRAINT bound_tool_registry_upgrades_added_denials_check,\s+ADD CONSTRAINT bound_tool_registry_upgrades_added_denials_check/);
 assert.doesNotMatch(repair,/CREATE OR REPLACE FUNCTION|guard_bound_tool_registry_upgrade|bound_tool_registry_successor_v18/);
});

test('v26 readiness rejects the exact otherwise valid prior v25 guard',async()=>{await assert.rejects(assertBoundToolPolicyReadiness(fixture((phase,rows)=>{if(phase===5)rows[0].upgrade_guard_sha256='47f07012763e1aa5cdb185e2a021266d60a561533003d6c7c4620f7a9a9c603c';})),{code:'BOUND_TOOL_POLICY_NOT_READY'});});
