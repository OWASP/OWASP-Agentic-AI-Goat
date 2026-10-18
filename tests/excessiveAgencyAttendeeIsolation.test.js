const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const {
  createExcessiveAgencyAttendeeLabStore,
} = require('../server/services/excessiveAgencyAttendeeLabStore');

const vulnerableAlice = {
  sessionUserId: 'alice',
  scenario: 'A',
  labMode: 'vuln',
};

test('each platform attendee gets an isolated five-persona mutable lab graph', async () => {
  const store = createExcessiveAgencyAttendeeLabStore();
  const attendeeA = store.getOrCreate(101);
  const attendeeB = store.getOrCreate(202);

  assert.notEqual(attendeeA.database, attendeeB.database);
  assert.ok(attendeeA.database.getNote('note-bob-1'));
  assert.ok(attendeeB.database.getNote('note-bob-1'));

  const result = await attendeeA.toolRouter.executeTool(
    'deleteNote',
    { noteId: 'note-bob-1' },
    vulnerableAlice
  );

  assert.equal(result.deleted, 'note-bob-1');
  assert.equal(attendeeA.database.getNote('note-bob-1'), null);
  assert.ok(attendeeB.database.getNote('note-bob-1'), 'another attendee must retain the seeded target');
});

test('a lab session is bound to its authenticated platform attendee', () => {
  const store = createExcessiveAgencyAttendeeLabStore();
  const labUser = store.getOrCreate(101).database.authenticateUser('alice', 'alice123');

  store.createSession('token-a', 101, labUser);

  assert.equal(store.resolveSession('token-a', 101).labUser.userId, 'alice');
  assert.equal(store.resolveSession('token-a', 202), null);
});

test('attendee reset restores only that attendee graph and conversation state', async () => {
  const store = createExcessiveAgencyAttendeeLabStore();
  const attendeeA = store.getOrCreate(101);
  const attendeeB = store.getOrCreate(202);

  attendeeA.database.deleteNote('note-bob-1');
  attendeeB.database.deleteNote('note-alice-1');
  attendeeA.database.markObjectiveComplete('platform:101', 8);
  attendeeB.database.markObjectiveComplete('platform:202', 5);
  attendeeA.conversations.set('alice', [{ role: 'user', content: 'private A' }]);
  attendeeB.conversations.set('bob', [{ role: 'user', content: 'private B' }]);

  const resetState = store.resetAttendee(101);

  assert.equal(resetState, attendeeA, 'active lab sessions must retain their state reference');
  assert.ok(attendeeA.database.getNote('note-bob-1'), 'A receives a fresh repeatable target');
  assert.equal(attendeeA.database.getCompletedObjectivesCount('platform:101'), 0);
  assert.equal(attendeeA.conversations.size, 0);
  assert.equal(attendeeB.database.getNote('note-alice-1'), null, 'B state is not rewritten');
  assert.equal(attendeeB.database.getCompletedObjectivesCount('platform:202'), 1);
  assert.equal(attendeeB.conversations.get('bob')[0].content, 'private B');
});

test('admin bulk progress reset reaches every attendee partition without consuming lab targets', () => {
  const store = createExcessiveAgencyAttendeeLabStore();
  const attendeeA = store.getOrCreate(101);
  const attendeeB = store.getOrCreate(202);
  attendeeA.database.markObjectiveComplete('platform:101', 8);
  attendeeB.database.markObjectiveComplete('platform:202', 5);
  attendeeA.database.deleteNote('note-bob-1');

  store.resetAllProgress();

  assert.equal(attendeeA.database.getCompletedObjectivesCount('platform:101'), 0);
  assert.equal(attendeeB.database.getCompletedObjectivesCount('platform:202'), 0);
  assert.equal(attendeeA.database.getNote('note-bob-1'), null, 'progress-only reset preserves lab data');
  assert.ok(attendeeB.database.getNote('note-bob-1'));
});

test('multiple personas remain mutually vulnerable inside one attendee partition', async () => {
  const store = createExcessiveAgencyAttendeeLabStore();
  const state = store.getOrCreate(101);

  const bobNotes = await state.toolRouter.executeTool(
    'listNotes',
    { userId: 'bob' },
    vulnerableAlice
  );

  assert.equal(bobNotes.success, true);
  assert.ok(bobNotes.notes.every((note) => note.ownerUserId === 'bob'));
  assert.match(bobNotes._warning, /without authorization/);
});

test('every lab-session route first authenticates and binds the platform attendee', () => {
  const source = fs.readFileSync(
    path.resolve(__dirname, '../server/routes/excessiveAgencyLab.js'),
    'utf8'
  );
  const sessionRoutes = source
    .split('\n')
    .filter((line) => /router\.(get|post|delete|put)\(.+\b(labAuth|optionalAuth)\b/.test(line));

  assert.ok(sessionRoutes.length > 0, 'the contract must inspect real lab-session routes');
  for (const route of sessionRoutes) {
    assert.match(route, /authenticateToken,\s*(labAuth|optionalAuth)/, route.trim());
  }
  assert.match(source, /router\.post\('\/auth\/login',\s*authenticateToken,/);
  assert.match(source, /attendeeLabs\.resolveSession\(sessionToken,\s*req\.user\.id\)/);
});
