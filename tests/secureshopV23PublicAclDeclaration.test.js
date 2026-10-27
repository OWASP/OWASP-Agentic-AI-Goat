'use strict';

// Proposed destination after the ACL declaration repair is applied:
// tests/secureshopV23PublicAclDeclaration.test.js
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const root = fs.existsSync(path.join(__dirname, '../server'))
  ? path.resolve(__dirname, '..') : path.resolve(__dirname, '../..');
const services = path.join(root, 'server/services');
const compositionSource = fs.readFileSync(path.join(services, 'secureshopBoundReviewComposition.js'), 'utf8');
const roleSource = fs.readFileSync(path.join(services, 'secureshopBoundRoleChat.js'), 'utf8');
const { TOOLS, ORIGINAL_REGISTER_TOOL } = require(path.join(services, 'secureshopBoundRoleChat.js'));
const { ORIGINAL_DESCRIBE_TOOL, ORIGINAL_LIST_TOOL } = require(path.join(services, 'secureshopOriginalRegistrationRuntime.js'));
const { createBoundAclResolver } = require(path.join(services, 'secureshopBoundAclRegistry.js'));

const compositionDeclaration = compositionSource.match(
  /const toolPolicyAdmission = admission\(\{repository:toolPolicyRepository,[\s\S]*?\}\);/);
assert(compositionDeclaration, 'actual composition ACL declaration');
const evaluateComposition = new Function('admission', 'toolPolicyRepository', 'role',
  'mcpRegistrationApplication', 'ROLE_CHAT_TOOLS', 'ORIGINAL_REGISTER_TOOL',
  'ORIGINAL_DESCRIBE_TOOL', 'ORIGINAL_LIST_TOOL',
  `${compositionDeclaration[0]} return toolPolicyAdmission;`);
const roleDeclaration = roleSource.match(/const purpose=PURPOSES\[role\],declared=([\s\S]*?);/);
assert(roleDeclaration, 'actual RoleChat model catalog declaration');
const evaluateRoleCatalog = new Function('role', 'mcpRegistrationApplication', 'tools',
  'ORIGINAL_REGISTER_TOOL', `return ${roleDeclaration[1]};`);
const roleGuard = roleSource.match(/checkToolAcl:async\(actorRole,agent,tool\)=>\{[\s\S]*?\},\n    observeLocalTool:/);
assert(roleGuard, 'actual RoleChat dispatch guard');
const evaluateGuard = new Function('role', 'available',
  `return ({${roleGuard[0].slice(0, -',\n    observeLocalTool:'.length)}}).checkToolAcl;`);
const withRegistration = () => ({ ready: true });
const declaredFor = (role, registration) => evaluateComposition(
  options => options, {}, role, registration, TOOLS, ORIGINAL_REGISTER_TOOL,
  ORIGINAL_DESCRIBE_TOOL, ORIGINAL_LIST_TOOL);

test('registered admin composition declares all exact ACL tools without changing other workflows', () => {
  const registered = declaredFor('admin', withRegistration);
  assert.equal(registered.workflow, 'admin-registration-assistant');
  assert.equal(registered.declaredTools.length, 31);
  const registry = createBoundAclResolver(registered);
  for (const name of ['register', 'describe_tools', 'list_servers'])
    assert(registry.resolve('mcp-registry', name));
  assert.equal(registry.resolve('mcp-registry', 'unknown'), null);
  const baseAdmin = declaredFor('admin', undefined);
  assert.equal(baseAdmin.workflow, 'admin-assistant');
  assert.equal(baseAdmin.declaredTools.length, 28);
  assert.doesNotThrow(() => createBoundAclResolver(baseAdmin));
  const merchant = declaredFor('merchant', withRegistration);
  assert.equal(merchant.workflow, 'merchant-assistant');
  assert.doesNotThrow(() => createBoundAclResolver(merchant));
});

test('model catalog and actual dispatch still deny the two policy-only tools', async () => {
  const modelCatalog = evaluateRoleCatalog('admin', withRegistration, TOOLS, ORIGINAL_REGISTER_TOOL);
  assert.equal(modelCatalog.length, 29);
  const names = modelCatalog.map(tool => `${tool.agent}.${tool.tool}`);
  assert(names.includes('mcp-registry.register'));
  assert(!names.includes('mcp-registry.describe_tools'));
  assert(!names.includes('mcp-registry.list_servers'));
  const dispatch = evaluateGuard('admin', modelCatalog);
  assert.equal((await dispatch('admin', 'mcp-registry', 'register')).allowed, true);
  for (const name of ['describe_tools', 'list_servers']) {
    assert.deepEqual(await dispatch('admin', 'mcp-registry', name),
      { allowed: false, action: 'block', policyViolation: 'blocked', enforcement: true });
    assert.equal((await dispatch('merchant', 'mcp-registry', name)).allowed, false);
  }
});
