'use strict';

/**
 * SecureShop RBAC contracts against launcher-owned disposable PostgreSQL.
 * Layer B deliberately logs and dispatches denied calls while enforcement is
 * disabled; user-management.set_role deliberately retains its Layer C bypass.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

const REPO = path.resolve(__dirname, '../../..');
const { seedShop, seedAgents } = require('../vuln/_fixture.js');
const enabled = process.env.PG_TEST_DISPOSABLE === 'yes'
  && !!process.env.SECURESHOP_DATABASE_URL
  && !!process.env.SECURESHOP_MIGRATION_DATABASE_URL
  && !!process.env.SECURESHOP_AGENTS_DATABASE_URL
  && !!process.env.SECURESHOP_AGENTS_MIGRATION_DATABASE_URL;

test('rbac: canonical PostgreSQL seed, Layer B policy, and intentional set_role bypass', { skip: !enabled }, async () => {
  let shop;
  let agents;
  try {
    shop = await seedShop();
    agents = await seedAgents();
    const { TOOLS } = require(path.join(REPO, 'server/data/secureshopAgentSeeds.js'));
    const permissionRows = (await agents.query(`
      SELECT tool_name,role,allowed
      FROM secureshop_agents.tool_permissions
      ORDER BY tool_name,role
    `)).rows;
    assert.equal(permissionRows.length, TOOLS.length * 3, `${TOOLS.length * 3} rows expected`);
    const expected = new Map(TOOLS);
    const byTool = new Map();
    for (const row of permissionRows) {
      if (!byTool.has(row.tool_name)) byTool.set(row.tool_name, new Map());
      byTool.get(row.tool_name).set(row.role, Number(row.allowed));
    }
    assert.equal(byTool.size, TOOLS.length);
    for (const [tool, matrix] of expected) {
      assert.deepEqual(
        Object.fromEntries(byTool.get(tool) || []),
        { admin: matrix.admin ? 1 : 0, customer: matrix.customer ? 1 : 0, merchant: matrix.merchant ? 1 : 0 },
        `canonical role matrix for ${tool}`
      );
    }
    assert.deepEqual(
      Object.fromEntries(permissionRows.filter((row) => row.tool_name === 'user-management.set_role').map((row) => [row.role, Number(row.allowed)])),
      { admin: 1, customer: 0, merchant: 0 }
    );

    const acl = require(path.join(REPO, 'server/services/secureshop/toolAcl.js'));
    assert.equal(await acl.isEnforcementEnabled(), false);
    assert.deepEqual(await acl.checkToolAcl('customer', 'user-management', 'set_role'), {
      allowed: false, action: 'log', policyViolation: 'denied-by-acl', enforcement: false,
    });
    assert.deepEqual(await acl.checkToolAcl('customer', 'cart', 'view'), {
      allowed: true, action: 'dispatch', policyViolation: null, enforcement: false,
    });

    await acl.setEnforcement(true, 'rbac-pg-fixture');
    assert.equal(await acl.isEnforcementEnabled(), true);
    assert.deepEqual(await acl.checkToolAcl('customer', 'user-management', 'set_role'), {
      allowed: false, action: 'block', policyViolation: 'blocked', enforcement: true,
    });
    await acl.setEnforcement(false, 'rbac-pg-fixture');
    assert.equal(await acl.isEnforcementEnabled(), false);

    const listed = await acl.listAllPermissions();
    assert.equal(listed.length, TOOLS.length * 3);
    assert.deepEqual(await acl.setPermission('cart.view', 'customer', false), {
      ok: true, tool_name: 'cart.view', role: 'customer', allowed: false,
    });
    assert.equal(Number((await agents.query(`
      SELECT allowed FROM secureshop_agents.tool_permissions
      WHERE tool_name='cart.view' AND role='customer'
    `)).rows[0].allowed), 0);
    await acl.setPermission('cart.view', 'customer', true);

    const victim = (await shop.query("SELECT id,role FROM secureshop.shop_users WHERE username='alice'")).rows[0];
    assert.equal(victim.role, 'customer');
    const { extractCaller } = require(path.join(REPO, 'agent-host/shared/callerContext.js'));
    const { setRole } = require(path.join(REPO, 'agent-host/agents/user-management/tools/index.js'));
    const rawArgs = {
      user_id: victim.id,
      role: 'admin',
      _ss_caller: { role: 'customer', id: victim.id, policy_violation: 'denied-by-acl' },
    };
    const { caller, args } = extractCaller(rawArgs);
    assert.equal(caller.role, 'customer');
    assert.equal(args._ss_caller, undefined);
    const result = await setRole(args);
    assert.equal(result.ok, true, 'set_role must execute despite the denied Layer B caller role');
    assert.equal((await shop.query('SELECT role FROM secureshop.shop_users WHERE id=$1', [victim.id])).rows[0].role, 'admin');
    const audit = (await agents.query(`
      SELECT actor,action,target,params_json
      FROM secureshop_agents.audit_events
      WHERE action='set_role' AND target=$1
      ORDER BY id DESC LIMIT 1
    `, [String(victim.id)])).rows[0];
    assert.equal(audit.actor, 'user-management');
    assert.equal(audit.action, 'set_role');
    assert.equal(audit.target, String(victim.id));
    assert.deepEqual(JSON.parse(audit.params_json), { user_id: victim.id, role: 'admin' });
  } finally {
    const outcomes = await Promise.allSettled([shop?.close(), agents?.close()]);
    const errors = outcomes.filter((outcome) => outcome.status === 'rejected').map((outcome) => outcome.reason);
    if (errors.length) throw new AggregateError(errors, 'Failed to close PostgreSQL RBAC fixtures');
  }
});

test('rbac: mcpClientPool.callTool smuggles the Layer B decision into arguments', async () => {
  const seen = { args: null };
  const fakeClient = {
    async callTool(payload) { seen.args = payload; return { content: [{ type: 'text', text: 'ok' }] }; },
  };
  const { McpClientPool } = require(path.join(REPO, 'server/services/secureshop/mcpClientPool.js'));
  const pool = new McpClientPool({ baseUrl: 'http://unused' });
  pool.clients.set('cart', fakeClient);
  await pool.callTool('cart', 'view', { user_id: 1 }, {
    callerRole: 'customer', callerId: 42, policyViolation: 'denied-by-acl',
  });
  assert.equal(seen.args.name, 'view');
  assert.equal(seen.args.arguments.user_id, 1);
  assert.deepEqual(seen.args.arguments._ss_caller, {
    role: 'customer', id: 42, policy_violation: 'denied-by-acl', layer: 'B->C',
  });
});

test('rbac: Layer C extracts caller context without forwarding it to tools', () => {
  const { extractCaller } = require(path.join(REPO, 'agent-host/shared/callerContext.js'));
  const { caller, args } = extractCaller({ product_id: 5, _ss_caller: { role: 'merchant', id: 2 } });
  assert.deepEqual(caller, { role: 'merchant', id: 2, policy_violation: null });
  assert.equal(args.product_id, 5);
  assert.equal(args._ss_caller, undefined);
});

test('rbac: Layer C denies wrong and anonymous roles and permits matching roles', () => {
  const { enforceRole } = require(path.join(REPO, 'agent-host/shared/callerContext.js'));
  const denied = enforceRole({ role: 'customer', id: 1 }, ['merchant', 'admin']);
  assert.equal(denied.isError, true);
  assert.match(denied.content[0].text, /forbidden-by-caller-role/);
  assert.match(denied.content[0].text, /"caller_role":"customer"/);
  assert.equal(enforceRole({ role: 'admin', id: 99 }, ['admin']), null);
  const anonymous = enforceRole({ role: null, id: null }, ['admin']);
  assert.equal(anonymous.isError, true);
  assert.match(anonymous.content[0].text, /anonymous-caller/);
});

test('rbac: explicit Layer C disable flag retains the teaching configuration', () => {
  const { enforceRole } = require(path.join(REPO, 'agent-host/shared/callerContext.js'));
  const previous = process.env.SS_ENFORCE_CALLER_ROLE;
  process.env.SS_ENFORCE_CALLER_ROLE = 'false';
  try {
    assert.equal(enforceRole({ role: 'customer' }, ['admin']), null);
  } finally {
    if (previous === undefined) delete process.env.SS_ENFORCE_CALLER_ROLE;
    else process.env.SS_ENFORCE_CALLER_ROLE = previous;
  }
});

test('rbac: system dispatch retains its Layer C denial before the tool sink', () => {
  const { extractCaller, enforceRole } = require(path.join(REPO, 'agent-host/shared/callerContext.js'));
  const { caller, args } = extractCaller({ path: 'foo.yml', _ss_caller: { role: 'customer', id: 1 } });
  const denied = enforceRole(caller, ['admin']);
  assert.equal(denied.isError, true);
  assert.match(denied.content[0].text, /forbidden-by-caller-role/);
  assert.equal(args.path, 'foo.yml');
});
