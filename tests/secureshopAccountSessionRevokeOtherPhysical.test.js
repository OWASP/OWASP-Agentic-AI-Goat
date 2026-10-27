'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const cases = require('./fixtures/secureshopAccountSessionRevokeRenderedCases');
const fs = require('node:fs');
const source = fs.readFileSync(require.resolve('./postgres/secureshopStandaloneAccountSessionRevokeRendered.integration.test.js'),'utf8');
const begin = source.indexOf('async function runOtherSessionPhysical(');
const end = source.indexOf('\n\nasync function runRenderedCase(',begin);
assert(begin >= 0 && end > begin);
const runOtherSessionPhysical = Function('assert','return ('+source.slice(begin,end)+')')(assert);

const currentId = 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee';
const otherId = 'bbbbbbbb-cccc-4ddd-8eee-ffffffffffff';
const foreignId = 'cccccccc-dddd-4eee-8fff-aaaaaaaaaaaa';
const scope = { launchId: 'owned-launch', platformOwnerId: 'owned-owner',
  platformSessionId: 'owned-platform-session' };

async function controlled({ selected = true, committedStatus = 200,
  blockedRow = true, blockedButton = true, reauthDenied = false } = {}) {
  const priorFetch = global.fetch;
  const posts = [], requests = [{ authorization: 'Bearer current-token', launch: 'launch-bearer' }];
  const sessionReplies = [200], siblingBefore = [{ session_id: foreignId, revoked_at: null }];
  let refreshes = 0, confirmed = 0, closed = false;
  const clickPhysical = async (_frame, lookup) => {
    if (lookup.includes("textContent.trim()==='Refresh'")) {
      refreshes++;
      requests.push({ ...requests[0] }); sessionReplies.push(200);
    } else if (lookup.includes(',"Confirm revoke")')) {
      confirmed++;
      posts.push({ path: cases.revokePath(otherId),
        authorization: 'Bearer current-token', launch: 'launch-bearer' });
    }
  };
  const localCases = { ...cases, loseOneCompletedAck: async () => ({
    observed: () => ({ status: committedStatus, replySha256: 'a'.repeat(64) }),
    close: async () => { closed = true; },
  }) };
  const setupPrincipal = Object.freeze({ controlledServiceResult: true });
  const composition = {
    launches: { resolveCapability: async () => scope },
    personaAuth: {
      establishAdditionalSession: async input => {
        assert.equal(input.shopPrincipal, setupPrincipal);
        assert.equal(input.scope, scope);
        assert.equal(input.token, 'current-token');
        assert.equal(input.ip, '127.0.0.2');
        assert.equal(input.userAgent, 'Q05 other owned session');
        return { token: 'other-token' };
      },
      authenticateBoundToken: async ({ token }) => {
        if (token === 'other-token' && !closed) return { sessionId: otherId, user: { id: 71 } };
        if (token === 'other-token') throw Error('revoked');
        return { sessionId: currentId, user: { id: 71 } };
      },
      listSessions: async () => selected ? [
        { id: currentId, is_current: true },
        { id: otherId, is_current: false, user_agent: 'Q05 other owned session', ip: '127.0.0.2' },
      ] : [{ id: currentId, is_current: true }],
    },
  };
  const args = {
    frame: { waitForFunction: async () => {}, evaluate: async fn => {
      const priorDocument = global.document;
      global.document = { querySelectorAll: () => blockedRow ? [{
        textContent: 'Q05 other owned session',
        querySelectorAll: () => blockedButton
          ? [{ textContent: 'Revoke', disabled: true }] : [],
      }] : [] };
      try { return fn(); } finally { global.document = priorDocument; }
    } },
    page: {}, origin: 'http://127.0.0.1:1', buyerName: 'owned-buyer', password: 'owned-password',
    auth: { async withReauthenticatedExecution(input, action) {
      assert.deepEqual(input, {token:'physical-cookie',username:'owned-buyer',password:'owned-password'});
      if (reauthDenied) throw Object.assign(new Error('denied'),{code:'SHOP_AUTH_INVALID'});
      return action(setupPrincipal);
    } }, browserCookie: {value:'physical-cookie',httpOnly:true},
    cases: localCases, clickPhysical,
    exactConsequenceDialogButton() {}, composition, scope,
    browserSession: { sessionId: currentId, user: { id: 71 }, authorityVersion: '1' },
    browserAuth: { authorization: 'Bearer current-token', launch: 'launch-bearer' },
    siblingSession: { sessionId: foreignId },
    siblingRows: async () => ({ rows: siblingBefore }), siblingBefore,
    posts, requests, sessionReplies,
    agents: { query: async sql => sql.includes('bound_audit_events')
      ? { rows: [{ shop_user_id: 71, launch_id: scope.launchId,
        original_platform_owner_id: scope.platformOwnerId,
        original_platform_session_id: scope.platformSessionId }] }
      : { rows: [{ session_id: otherId, revoked_at: '2026-10-24T00:00:00Z' }] } },
    identity: { query: async () => ({ rows: [{ judgments: 0, contributions: 0 }] }) },
    admission: { verifyBuild: async () => {} },
    boundary: { assertNoUnexpectedTargets: () => {} },
    modelCalls: () => 0, judgeCalls: () => 0,
  };
  global.fetch = async () => ({ status: 200, json: async () => ({ ok: false }) });
  try {
    const receipt = await runOtherSessionPhysical(args);
    return { receipt, posts, requests, sessionReplies, refreshes, confirmed, closed };
  } finally { global.fetch = priorFetch; }
}

test('controlled physical sequence selects same-owner OTHER, loses committed ACK, recovers by one GET', async () => {
  const row = await controlled();
  assert.equal(cases.assertReceipt(row.receipt), true);
  assert.equal(row.confirmed, 1);
  assert.equal(row.posts.length, 1);
  assert.equal(row.refreshes, 2);
  assert.equal(row.requests.length, 3);
  assert.equal(row.closed, true);
});

test('one-row inventory cannot masquerade as the OTHER-session consequence', async () => {
  await assert.rejects(controlled({ selected: false }), /Expected values to be strictly equal/);
});

test('non-200 response cannot masquerade as committed-acknowledgement loss', async () => {
  await assert.rejects(controlled({ committedStatus: 503 }), /The expression evaluated to a falsy value/);
});

test('missing selected row cannot satisfy unresolved disabled protection', async () => {
  await assert.rejects(controlled({ blockedRow: false }), /unresolved revoke must disable another row click/);
});

test('missing Revoke control cannot satisfy unresolved disabled protection', async () => {
  await assert.rejects(controlled({ blockedButton: false }), /unresolved revoke must disable another row click/);
});

test('actual admission denies mixed current and OTHER selectors', async () => {
  const path = require('node:path');
  const { admitCommerceBrowser } = require('./fixtures/secureshopCommerceBrowserAdmission');
  const workspace = path.resolve(__dirname,'..');
  const run = path.join(workspace,'tasks/qualification/run-controlled');
  const env = {SECURESHOP_COMMERCE_TEST_NO_SANDBOX:'1', SECURESHOP_ACCOUNT_SESSION_REVOKE_NATIVE:'1', SECURESHOP_ACCOUNT_SESSION_REVOKE_OTHER_NATIVE:'1'};
  for (const variant of ['account-session-revoke','account-session-revoke-other']) {
    const receipt = variant === 'account-session-revoke' ? 'account-current-session-revoke-browser-v2.json' : 'account-other-session-revoke-browser-v1.json';
    await assert.rejects(admitCommerceBrowser(env,{workspace,evidencePath:path.join(run,receipt),executablePath:process.execPath,variant}),{code:'ERR_ASSERTION'});
  }
});

// The fixture must stop before any physical refresh/revoke if genuine setup denies.
test('OTHER physical setup propagates authenticated issuance denial', async () => {
  await assert.rejects(controlled({reauthDenied:true}), {code:'SHOP_AUTH_INVALID'});
});
