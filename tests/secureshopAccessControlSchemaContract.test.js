'use strict';
// Source contract only; this is not SQL execution or native privilege proof.
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs');
const sql=fs.readFileSync('docs/modernization/drafts/secureshop-bound-access-control/schema.candidate.sql','utf8');
test('ACL candidate lifecycle follows actual canonical tombstones and owner-first lock order',()=>{
 assert.match(sql,/AFTER INSERT ON secureshop_agents.conversation_generation_retirements/);
 assert.match(sql,/AFTER INSERT ON secureshop_agents.bound_audit_owner_deletion_receipts/);
 const guard=sql.slice(sql.indexOf('CREATE FUNCTION secureshop_agents.guard_bound_tool_policy_write'),sql.indexOf('CREATE FUNCTION secureshop_agents.guard_bound_tool_policy_history'));
 assert.ok(guard.indexOf('secureshop-bound-audit-owner:')<guard.indexOf('secureshop-conversation-admission:'));
 assert.match(guard,/Tool policy authority retired/);assert.match(guard,/policy_version<>OLD.policy_version\+1/);
 const cleanup=sql.slice(sql.indexOf('CREATE FUNCTION secureshop_agents.cleanup_bound_tool_policy'),sql.indexOf('CREATE TRIGGER cleanup_bound_tool_policy_retirement'));
 const retirement=cleanup.slice(cleanup.indexOf("kind:='retirement'"),cleanup.indexOf('\n ELSE'));
 assert.doesNotMatch(retirement,/DELETE FROM secureshop_agents.bound_tool_(admissions|policy_operations)/);
 assert.match(cleanup,/DELETE FROM secureshop_agents.bound_tool_admissions/);
});
test('runtime cannot erase history or invoke cleanup and nullable advisory classification is constrained',()=>{
 for(const table of ['bound_tool_policy_operations','bound_tool_admissions']){
  assert.ok(sql.includes(`GRANT SELECT,INSERT ON secureshop_agents.${table} TO dvaia_secureshop_agents_runtime`));
  assert.ok(!sql.includes(`GRANT DELETE ON secureshop_agents.${table}`));
 }
 assert.match(sql,/REVOKE ALL ON FUNCTION secureshop_agents.cleanup_bound_tool_policy\(\) FROM PUBLIC,dvaia_secureshop_agents_runtime/);
 assert.match(sql,/policy_violation IS NOT DISTINCT FROM CASE WHEN allowed THEN NULL ELSE 'denied-by-acl' END/);
 assert.match(sql,/s\.credential_version=COALESCE/);assert.match(sql,/s\.revoked_at IS NULL/);
 assert.match(sql,/UNIQUE\(platform_launch_id,platform_scenario_id,platform_launch_generation,original_platform_owner_id,original_platform_session_id,run_id,invocation_id\)/);
 assert.equal((sql.match(/CREATE TABLE secureshop_agents.bound_tool_/g)||[]).length,5);
});
