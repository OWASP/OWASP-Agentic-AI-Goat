'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),path=require('node:path');
const R=require('../server/services/secureshopBoundAclRegistry');
const H=require('./helpers/secureshopRegistryGuard');
const {registryV37Rows,registryV38Rows}=require('./helpers/secureshopHistoricalRegistry');
const read=name=>fs.readFileSync(path.join(H.directory,name),'utf8');

function v37Guard(){
 let body=H.reconstruct();
 for(const name of ['0108_file_summary_registry_successor.sql','0111_admin_user_lookup_registry_successor.sql',
  '0112_upload_preview_registry_successor.sql','0114_customer_agency_role_registry_successor.sql',
  '0116_mcp_registration_registry_successor.sql'])body=H.apply(body,read(name));
 return body;
}
function v38Guard(before,sql){
 const v=H.constants(sql);
 assert.equal(H.hash(before),v.old_guard_sha256);
 for(const anchor of [v.old_edge,v.old_anchor,v.denial_anchor])assert.equal(before.split(anchor).length,2);
 const oldCase=v.old_anchor+before.split(v.old_anchor)[1].split(' ELSE NULL END;')[0]+' ELSE NULL END;';
 assert.equal(oldCase.split(v.old_prefix).length,2);
 const nextCase=oldCase.replace(v.old_anchor,v.new_anchor).replace(v.old_prefix,v.new_prefix)
  .replace(' ELSE NULL END;',v.new_suffix);
 const after=before.replace(v.old_edge,v.old_edge+'\n'+v.new_edges)
  .replace(v.old_anchor,nextCase+'\n ELSE\n'+v.old_anchor)
  .replace(v.denial_anchor,'\n END IF;'+v.denial_anchor);
 assert.equal(H.hash(after),v.upgraded_guard_sha256);
 assert.equal(after.replace(v.old_edge+'\n'+v.new_edges,v.old_edge)
  .replace(nextCase+'\n ELSE\n'+v.old_anchor,v.old_anchor)
  .replace('\n END IF;'+v.denial_anchor,v.denial_anchor),before);
 return {after,v,nextCase};
}

test('v38 adds only the exact admin description-read capability and preserves historical v37 bytes',()=>{
 const old=registryV37Rows(R.REGISTRY);
 assert.equal(H.hash(JSON.stringify({version:37,rows:old})),R.MCP_DESCRIBE_PREDECESSOR_REGISTRY_SHA256);
 assert.deepEqual(old.filter(row=>row.toolKey!==R.MCP_DESCRIBE_KEY),registryV38Rows(R.REGISTRY).filter(row=>row.toolKey!==R.MCP_DESCRIBE_KEY));
 assert.equal(old.find(row=>row.toolKey===R.MCP_DESCRIBE_KEY).supported,false);
 const promoted=R.REGISTRY.find(row=>row.toolKey===R.MCP_DESCRIBE_KEY);
 assert.equal(promoted.workflow,'admin-registration-assistant');
 assert.deepEqual(promoted.roleApplicability,{customer:false,merchant:false,admin:true});
 assert.deepEqual(promoted.defaultAllowed,{customer:false,merchant:false,admin:true});
 for(const [prior,keys]of Object.entries(R.PRE_MCP_DESCRIBE_REGISTRY_UPGRADES))
  assert.deepEqual(R.PRE_MCP_LIST_REGISTRY_UPGRADES[prior],[...keys,R.MCP_DESCRIBE_KEY]);
 assert.deepEqual(R.PRE_MCP_LIST_REGISTRY_UPGRADES[R.MCP_DESCRIBE_PREDECESSOR_REGISTRY_SHA256],[R.MCP_DESCRIBE_KEY]);
 assert.equal(Object.keys(R.PRE_MCP_LIST_REGISTRY_UPGRADES).length,37);
});

test('0117 closes the nested guard branch and pins all 37 canonical successor/denial edges',()=>{
 const before=v37Guard(),sql=read('0117_mcp_describe_tools_registry_successor.sql');
 const {after,v,nextCase}=v38Guard(before,sql);
 assert.equal(after.split(v.new_anchor).length,2);
 assert(after.includes(nextCase+'\n ELSE\n'+v.old_anchor));
 assert(after.includes('\n END IF;'+v.denial_anchor));
 assert.equal([...v.new_edges.matchAll(/OR \(/g)].length,37);
 assert.equal([...v.constraint_additions.matchAll(/OR \(/g)].length,37);
 const canonical=(keys)=>registryV38Rows(R.REGISTRY).filter(row=>keys.includes(row.toolKey))
  .flatMap(row=>R.ROLES.filter(role=>row.roleApplicability[role]).map(role=>({toolKey:row.toolKey,role})));
 for(const [prior,keys]of Object.entries(R.PRE_MCP_LIST_REGISTRY_UPGRADES)){
  const expected=canonical(keys);
  assert(v.new_edges.includes(`(encode(NEW.predecessor_sha256,'hex')='${prior}' AND encode(NEW.successor_sha256,'hex')='${R.MCP_LIST_PREDECESSOR_REGISTRY_SHA256}')`));
  assert(nextCase.includes(`WHEN '${prior}' THEN '${JSON.stringify(canonical(keys.filter(key=>key!==R.MCP_DESCRIBE_KEY)))}'::jsonb`)
   ||prior===R.MCP_DESCRIBE_PREDECESSOR_REGISTRY_SHA256);
  assert(v.constraint_additions.includes(`encode(predecessor_sha256,'hex')='${prior}' AND encode(successor_sha256,'hex')='${R.MCP_LIST_PREDECESSOR_REGISTRY_SHA256}' AND jsonb_array_length(added_denials)=${expected.length}`));
  assert.deepEqual(expected.filter(row=>row.toolKey===R.MCP_DESCRIBE_KEY),[{toolKey:R.MCP_DESCRIBE_KEY,role:'admin'}]);
 }
 assert(v.new_suffix.includes(`WHEN '${R.MCP_DESCRIBE_PREDECESSOR_REGISTRY_SHA256}' THEN '[]'::jsonb`));
 assert(v.new_suffix.includes('mcp-registry.describe_tools'));
 assert.doesNotMatch(sql,/UPDATE secureshop_agents|DELETE FROM|TRUNCATE|GRANT /);
 assert.match(sql,/REVOKE ALL ON FUNCTION secureshop_agents.guard_bound_tool_registry_upgrade\(\) FROM PUBLIC,dvaia_secureshop_agents_runtime/);
 const readiness=fs.readFileSync(path.join(__dirname,'../server/database/postgres/secureshopBoundToolPolicyReadiness.js'),'utf8');
 assert(read('0118_mcp_list_servers_registry_successor.sql').includes(v.upgraded_guard_sha256));assert(readiness.includes('bound_tool_registry_successor_v39'));
 const broken=after.replace('\n END IF;'+v.denial_anchor,v.denial_anchor);
 assert.notEqual(H.hash(broken),v.upgraded_guard_sha256);
 assert.throws(()=>v38Guard(before.replace('RETURN NEW','RETURN OLD'),sql));
 assert.throws(()=>v38Guard(before,sql.replace(v.upgraded_guard_sha256,'0'.repeat(64))));
});
