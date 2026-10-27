'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),path=require('node:path');
const R=require('../server/services/secureshopBoundAclRegistry');
const H=require('./helpers/secureshopRegistryGuard');
const {registryV36Rows,registryV37Rows}=require('./helpers/secureshopHistoricalRegistry');
const read=name=>fs.readFileSync(path.join(H.directory,name),'utf8');
function previousGuard(){
 let body=H.reconstruct();
 for(const name of ['0108_file_summary_registry_successor.sql','0111_admin_user_lookup_registry_successor.sql','0112_upload_preview_registry_successor.sql','0114_customer_agency_role_registry_successor.sql'])body=H.apply(body,read(name));
 return body;
}
test('registration uses a separate exact administrator workflow without changing old declarations',()=>{
 const admin=R.REGISTRY.filter(row=>row.workflow==='admin-assistant').map(({toolKey})=>{const[agent,tool]=toolKey.split('.');return{agent,tool};});
 const register={agent:'mcp-registry',tool:'register'},describe={agent:'mcp-registry',tool:'describe_tools'},list={agent:'mcp-registry',tool:'list_servers'},declaredTools=[...admin,register,describe,list];
 const legacy=R.createBoundAclResolver({workflow:'admin-assistant',declaredTools:admin});
 assert.equal(legacy.resolve('mcp-registry','register'),null);
 const selected=R.createBoundAclResolver({workflow:'admin-registration-assistant',declaredTools});
 assert.deepEqual(selected.resolve('mcp-registry','register'),{
  toolKey:'mcp-registry.register',workflow:'admin-registration-assistant',supported:true,
  roleApplicability:{customer:false,merchant:false,admin:true},defaultAllowed:{customer:false,merchant:false,admin:true}});
 assert.equal(selected.resolve('mcp-registry','describe_tools').toolKey,'mcp-registry.describe_tools');
 assert.equal(selected.isRoleApplicable('admin'),true);
 for(const role of ['customer','merchant','unknown'])assert.equal(selected.isRoleApplicable(role),false);
 for(const descriptor of admin)assert.deepEqual(selected.resolve(descriptor.agent,descriptor.tool),legacy.resolve(descriptor.agent,descriptor.tool));
 for(const bad of [admin,[register],[...admin,{agent:'mcp-registry',tool:'execute'}],[...admin,{agent:'admin',tool:'register'}],[...declaredTools,register],[...admin.slice(1),register,register]])
  assert.throws(()=>R.createBoundAclResolver({workflow:'admin-registration-assistant',declaredTools:bad}),TypeError);
 assert.throws(()=>R.createBoundAclResolver({workflow:'admin-assistant',declaredTools}),TypeError);
 assert.throws(()=>R.createBoundAclResolver({workflow:'admin-registration-assistant',declaredTools,admittedMcp:{}}),TypeError);
 for(const workflow of ['customer-chat','merchant-assistant']){
  const tools=R.REGISTRY.filter(row=>row.workflow===workflow).map(({toolKey})=>{const[agent,tool]=toolKey.split('.');return{agent,tool};});
  assert.equal(R.createBoundAclResolver({workflow,declaredTools:tools}).resolve('mcp-registry','register'),null);
  assert.throws(()=>R.createBoundAclResolver({workflow,declaredTools:[...tools,register]}),TypeError);
 }
});
test('v37 preserves every v36 row except the explicitly promoted original register capability',()=>{
 const v37=registryV37Rows(R.REGISTRY),old=registryV36Rows(v37);
 assert.equal(H.hash(JSON.stringify({version:36,rows:old})),R.MCP_REGISTRATION_PREDECESSOR_REGISTRY_SHA256);
 assert.deepEqual(old.filter(row=>row.toolKey!==R.MCP_REGISTRATION_KEY),v37.filter(row=>row.toolKey!==R.MCP_REGISTRATION_KEY));
 assert.equal(old.find(row=>row.toolKey===R.MCP_REGISTRATION_KEY).supported,false);
 for(const [prior,keys]of Object.entries(R.PRE_MCP_REGISTRATION_REGISTRY_UPGRADES))assert.deepEqual(R.PRE_MCP_DESCRIBE_REGISTRY_UPGRADES[prior],[...keys,R.MCP_REGISTRATION_KEY]);
 assert.deepEqual(R.PRE_MCP_DESCRIBE_REGISTRY_UPGRADES[R.MCP_REGISTRATION_PREDECESSOR_REGISTRY_SHA256],[R.MCP_REGISTRATION_KEY]);
 assert.equal(Object.keys(R.PRE_MCP_DESCRIBE_REGISTRY_UPGRADES).length,36);
});
test('0116 reconstructs exact old guard and extends only closed edges with exact canonical admin denials',()=>{
 const before=previousGuard(),sql=read('0116_mcp_registration_registry_successor.sql'),v=H.constants(sql),after=H.apply(before,sql);
 assert.equal(H.hash(before),v.old_guard_sha256);assert.equal(H.hash(after),v.upgraded_guard_sha256);
 assert.equal(after.replace(v.old_edge+'\n'+v.new_edges,v.old_edge).replace(v.v37_branch+v.v36_branch,v.v36_branch).replace('\n END IF;'+v.denial_anchor,v.denial_anchor),before);
 for(const [prior,keys]of Object.entries(R.PRE_MCP_DESCRIBE_REGISTRY_UPGRADES)){
  const denials=registryV37Rows(R.REGISTRY).filter(row=>keys.includes(row.toolKey)).flatMap(row=>R.ROLES.filter(role=>row.roleApplicability[role]).map(role=>({toolKey:row.toolKey,role})));
  assert(v.new_edges.includes(`(encode(NEW.predecessor_sha256,'hex')='${prior}' AND encode(NEW.successor_sha256,'hex')='${R.MCP_DESCRIBE_PREDECESSOR_REGISTRY_SHA256}')`));
  assert(v.v37_branch.includes(`WHEN '${prior}' THEN '${JSON.stringify(denials)}'::jsonb`));
  assert(v.constraint_additions.includes(`encode(predecessor_sha256,'hex')='${prior}' AND encode(successor_sha256,'hex')='${R.MCP_DESCRIBE_PREDECESSOR_REGISTRY_SHA256}' AND jsonb_array_length(added_denials)=${denials.length}`));
  assert.deepEqual(denials.filter(row=>row.toolKey===R.MCP_REGISTRATION_KEY),[{toolKey:R.MCP_REGISTRATION_KEY,role:'admin'}]);
 }
 assert.equal([...v.new_edges.matchAll(/OR \(/g)].length,36);
 assert.equal([...v.v37_branch.matchAll(/WHEN '/g)].length,36);
 assert(v.v37_branch.endsWith('\n ELSE\n'));assert.doesNotMatch(v.v37_branch,/RETURN NEW/);
 assert.doesNotMatch(sql,/UPDATE secureshop_agents|DELETE FROM|TRUNCATE|GRANT /);
 assert.match(sql,/REVOKE ALL ON FUNCTION secureshop_agents.guard_bound_tool_registry_upgrade\(\) FROM PUBLIC,dvaia_secureshop_agents_runtime/);
 const readiness=fs.readFileSync(path.join(__dirname,'../server/database/postgres/secureshopBoundToolPolicyReadiness.js'),'utf8');
 assert(read('0117_mcp_describe_tools_registry_successor.sql').includes(v.upgraded_guard_sha256));assert(readiness.includes('bound_tool_registry_successor_v39'));
 assert.throws(()=>H.apply(before.replace('RETURN NEW','RETURN OLD'),sql));
 assert.throws(()=>H.apply(before,sql.replace(v.upgraded_guard_sha256,'0'.repeat(64))));
 const lengths=text=>text.match(/added_denials\) IN \(([^)]+)\)/)[1].split(',').map(Number);
 const expected=[...new Set([...lengths(read('0114_customer_agency_role_registry_successor.sql')),...Object.values(R.PRE_MCP_DESCRIBE_REGISTRY_UPGRADES).map(keys=>keys.length)])].sort((a,b)=>a-b);
 assert.deepEqual(lengths(sql),expected);assert(readiness.includes('Object.freeze(['+[...expected,79,80].join(',')+'])'));
});
