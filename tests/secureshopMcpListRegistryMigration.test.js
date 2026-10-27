'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),path=require('node:path');
const R=require('../server/services/secureshopBoundAclRegistry');
const H=require('./helpers/secureshopRegistryGuard');
const {registryV38Rows}=require('./helpers/secureshopHistoricalRegistry');
const read=name=>fs.readFileSync(path.join(H.directory,name),'utf8');

function v38Guard(){
 let body=H.reconstruct();
 for(const name of ['0108_file_summary_registry_successor.sql','0111_admin_user_lookup_registry_successor.sql',
  '0112_upload_preview_registry_successor.sql','0114_customer_agency_role_registry_successor.sql',
  '0116_mcp_registration_registry_successor.sql'])body=H.apply(body,read(name));
 const v=H.constants(read('0117_mcp_describe_tools_registry_successor.sql'));
 assert.equal(H.hash(body),v.old_guard_sha256);
 const oldCase=v.old_anchor+body.split(v.old_anchor)[1].split(' ELSE NULL END;')[0]+' ELSE NULL END;';
 const nextCase=oldCase.replace(v.old_anchor,v.new_anchor).replace(v.old_prefix,v.new_prefix)
  .replace(' ELSE NULL END;',v.new_suffix);
 body=body.replace(v.old_edge,v.old_edge+'\n'+v.new_edges)
  .replace(v.old_anchor,nextCase+'\n ELSE\n'+v.old_anchor)
  .replace(v.denial_anchor,'\n END IF;'+v.denial_anchor);
 assert.equal(H.hash(body),v.upgraded_guard_sha256);
 return body;
}
function v39Guard(before,sql){
 const v=H.constants(sql);
 assert.equal(H.hash(before),v.old_guard_sha256);
 for(const anchor of [v.old_edge,v.old_anchor,v.old_branch_end,v.denial_anchor])assert.equal(before.split(anchor).length,2);
 const oldCase=v.old_anchor+before.split(v.old_anchor)[1].split(v.old_branch_end)[0];
 assert.equal(oldCase.split('  expected_denials=').length,2);
 const oldAssignment='  expected_denials='+oldCase.split('  expected_denials=')[1].split(';')[0]+';';
 assert.equal(oldCase.split(oldAssignment).length,2);
 const oldExpression=oldAssignment.slice('  expected_denials='.length,-1);
 const nextCase=oldCase.replace(v.old_anchor,v.new_anchor)
  .replace(oldAssignment,v.new_prefix+oldExpression+v.new_suffix);
 const after=before.replace(v.old_edge,v.old_edge+'\n'+v.new_edges)
  .replace(v.old_anchor,nextCase+'\n ELSE\n'+v.old_anchor)
  .replace(v.denial_anchor,'\n END IF;'+v.denial_anchor);
 assert.equal(H.hash(after),v.upgraded_guard_sha256);
 assert.equal(after.replace(v.old_edge+'\n'+v.new_edges,v.old_edge)
  .replace(nextCase+'\n ELSE\n'+v.old_anchor,v.old_anchor)
  .replace('\n END IF;'+v.denial_anchor,v.denial_anchor),before);
 return {after,v,nextCase};
}

test('v39 adds only admin list_servers; v38 registry remains byte-identical',()=>{
 const old=registryV38Rows(R.REGISTRY);
 assert.equal(H.hash(JSON.stringify({version:38,rows:old})),R.MCP_LIST_PREDECESSOR_REGISTRY_SHA256);
 assert.deepEqual(old.filter(row=>row.toolKey!==R.MCP_LIST_KEY),R.REGISTRY.filter(row=>row.toolKey!==R.MCP_LIST_KEY));
 assert.equal(old.find(row=>row.toolKey===R.MCP_LIST_KEY).supported,false);
 const current=R.REGISTRY.find(row=>row.toolKey===R.MCP_LIST_KEY);
 assert.equal(current.workflow,'admin-registration-assistant');
 assert.deepEqual(current.roleApplicability,{customer:false,merchant:false,admin:true});
 assert.deepEqual(current.defaultAllowed,{customer:false,merchant:false,admin:true});
 for(const [prior,keys]of Object.entries(R.PRE_MCP_LIST_REGISTRY_UPGRADES))
  assert.deepEqual(R.REGISTRY_UPGRADES[prior],[...keys,R.MCP_LIST_KEY]);
 assert.deepEqual(R.REGISTRY_UPGRADES[R.MCP_LIST_PREDECESSOR_REGISTRY_SHA256],[R.MCP_LIST_KEY]);
 assert.equal(Object.keys(R.REGISTRY_UPGRADES).length,38);
 const admin=R.REGISTRY.filter(row=>row.workflow==='admin-assistant').map(row=>{const[agent,tool]=row.toolKey.split('.');return{agent,tool};});
 const list={agent:'mcp-registry',tool:'list_servers'};
 assert.equal(R.createBoundAclResolver({workflow:'admin-assistant',declaredTools:admin}).resolve(...Object.values(list)),null);
 const registered=[...admin,{agent:'mcp-registry',tool:'register'},{agent:'mcp-registry',tool:'describe_tools'},list];
 assert.equal(R.createBoundAclResolver({workflow:'admin-registration-assistant',declaredTools:registered}).resolve(list.agent,list.tool).toolKey,R.MCP_LIST_KEY);
 assert.throws(()=>R.createBoundAclResolver({workflow:'admin-registration-assistant',declaredTools:registered.slice(0,-1)}));
 for(const workflow of ['customer-chat','merchant-assistant']){
  const tools=R.REGISTRY.filter(row=>row.workflow===workflow).map(row=>{const[agent,tool]=row.toolKey.split('.');return{agent,tool};});
  assert.throws(()=>R.createBoundAclResolver({workflow,declaredTools:[...tools,list]}));
 }
});

test('0118 closes nested v39 guard and pins 38 canonical denial edges',()=>{
 const before=v38Guard(),sql=read('0118_mcp_list_servers_registry_successor.sql');
 const {after,v,nextCase}=v39Guard(before,sql);
 assert.equal(after.split(v.new_anchor).length,2);
 assert(after.includes(nextCase+'\n ELSE\n'+v.old_anchor));
 assert(after.includes('\n END IF;'+v.denial_anchor));
 assert.equal([...v.new_edges.matchAll(/OR \(/g)].length,38);
 assert.equal([...v.constraint_additions.matchAll(/OR \(/g)].length,38);
 const canonical=keys=>R.REGISTRY.filter(row=>keys.includes(row.toolKey))
  .flatMap(row=>R.ROLES.filter(role=>row.roleApplicability[role]).map(role=>({toolKey:row.toolKey,role})));
 for(const [prior,keys]of Object.entries(R.REGISTRY_UPGRADES)){
  const denials=canonical(keys);
  assert(v.new_edges.includes(`(encode(NEW.predecessor_sha256,'hex')='${prior}' AND encode(NEW.successor_sha256,'hex')='${R.REGISTRY_SHA256}')`));
  assert(v.constraint_additions.includes(`encode(predecessor_sha256,'hex')='${prior}' AND encode(successor_sha256,'hex')='${R.REGISTRY_SHA256}' AND jsonb_array_length(added_denials)=${denials.length}`));
  assert.deepEqual(denials.filter(row=>row.toolKey===R.MCP_LIST_KEY),[{toolKey:R.MCP_LIST_KEY,role:'admin'}]);
 }
 assert(v.new_prefix.includes(`predecessor_sha256,'hex')='${R.MCP_LIST_PREDECESSOR_REGISTRY_SHA256}' THEN '[]'::jsonb`));
 assert(v.new_suffix.includes('mcp-registry.list_servers'));
 assert.doesNotMatch(sql,/UPDATE secureshop_agents|DELETE FROM|TRUNCATE|GRANT /);
 assert.match(sql,/REVOKE ALL ON FUNCTION secureshop_agents.guard_bound_tool_registry_upgrade\(\) FROM PUBLIC,dvaia_secureshop_agents_runtime/);
 const readiness=fs.readFileSync(path.join(__dirname,'../server/database/postgres/secureshopBoundToolPolicyReadiness.js'),'utf8');
 assert(readiness.includes(v.upgraded_guard_sha256));assert(readiness.includes('bound_tool_registry_successor_v39'));
 assert.notEqual(H.hash(after.replace('\n END IF;'+v.denial_anchor,v.denial_anchor)),v.upgraded_guard_sha256);
 assert.throws(()=>v39Guard(before.replace('RETURN NEW','RETURN OLD'),sql));
 assert.throws(()=>v39Guard(before,sql.replace(v.upgraded_guard_sha256,'0'.repeat(64))));
});
