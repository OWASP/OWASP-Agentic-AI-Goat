'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { assertTicketRetirement, assertUnclaimedLegacyScene } = require('./postgres/secureshopSceneReset.integration.test');

function snapshots() {
  const tickets = ['first', 'second', 'sibling'].map((target_id, index) => ({
    ticket_id: index + 1, target_id, birth_launch_id: `launch-${index}`,
    birth_scenario_id: `scenario-${index}`, birth_generation: 1,
    birth_platform_owner_id: index === 2 ? 2 : 1, birth_platform_session_id: index + 10,
  }));
  const before = { tickets, receipts: tickets.map(row => ({ ticket_id: row.ticket_id, digest: 'original' })),
    retirements: [], profiles: [{ target_id: 'sibling', email: 'sibling@example.invalid' }] };
  const after = structuredClone(before);
  after.retirements = tickets.slice(0, 2).map(row => ({ ...row, retired_at: '2026-10-12T12:00:00.000Z' }));
  return { before, after };
}

test('ticket reset projection retains original receipts and sibling profile with exact owner retirements', () => {
  const { before, after } = snapshots();
  assertTicketRetirement(before, after, ['first', 'second']);
});

test('ticket reset projection rejects missing, extra, substituted or altered immutable rows', () => {
  const mutations = [
    value => value.retirements.pop(),
    value => value.retirements.push({ ...value.tickets[2], retired_at: '2026-10-12T12:00:00Z' }),
    value => { value.retirements[0].ticket_id = 3; },
    value => { value.retirements[0].birth_platform_session_id++; },
    value => { value.retirements[0].retired_at = null; },
    value => { value.tickets[0].birth_generation++; },
    value => { value.receipts[0].digest = 'rewritten'; },
    value => { value.profiles[0].email = 'changed@example.invalid'; },
  ];
  for (const mutate of mutations) {
    const { before, after } = snapshots(); mutate(after);
    assert.throws(() => assertTicketRetirement(before, after, ['first', 'second']));
  }
});

test('later authenticated reset retains prior retirement history and adds only its own target', () => {
  const { before, after } = snapshots();
  before.retirements = [structuredClone(after.retirements[0])];
  assertTicketRetirement(before, after, ['second']);
  const rewritten = structuredClone(after);
  rewritten.retirements[0].retired_at = '2026-10-13T12:00:00.000Z';
  assert.throws(() => assertTicketRetirement(before, rewritten, ['second']));
  const missing = structuredClone(after);
  missing.retirements.shift();
  assert.throws(() => assertTicketRetirement(before, missing, ['second']));
  const duplicated = structuredClone(after);
  duplicated.retirements.push(structuredClone(duplicated.retirements[0]));
  assert.throws(() => assertTicketRetirement(before, duplicated, ['second']));
});

test('legacy reset denial requires an actually retired unclaimed scene and one active exact review mapping', () => {
  const scene = [{ status: 'retired', claim: null }];
  const mapping = [{ target: 'owned-review', lifecycle: 'active' }];
  assertUnclaimedLegacyScene(scene, mapping, 'owned-review');
  for (const invalid of [[], [{ status: 'active', claim: null }],
    [{ status: 'retired', claim: 'valid-current-claim' }], [...scene, ...scene]]) {
    assert.throws(() => assertUnclaimedLegacyScene(invalid, mapping, 'owned-review'));
  }
  for (const invalid of [[], [{ target: 'sibling-review', lifecycle: 'active' }],
    [{ target: 'owned-review', lifecycle: 'retired' }], [...mapping, ...mapping]]) {
    assert.throws(() => assertUnclaimedLegacyScene(scene, invalid, 'owned-review'));
  }
});
