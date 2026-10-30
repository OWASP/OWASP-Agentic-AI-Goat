'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const {createPool,closePostgresPools}=require('../../server/database/postgres');

const enabled=process.env.PG_TEST_DISPOSABLE==='yes'&&!!process.env.PG_EXCESSIVE_AGENCY_TEST_RUNTIME_URL;
test('native Excessive Agency store preserves attendee isolation, intentional BOLA, sessions, all objectives and scoped reset',{skip:!enabled},async()=>{
  assert.match(new URL(process.env.PG_EXCESSIVE_AGENCY_TEST_RUNTIME_URL).pathname,/^\/owasp_ai_goat_test_excessive_agency$/);
  const runtime=createPool(process.env,'PG_EXCESSIVE_AGENCY_TEST_RUNTIME_URL');
  const migration=createPool(process.env,'PG_EXCESSIVE_AGENCY_TEST_MIGRATION_URL');
  try{
    const {createExcessiveAgencyDatabaseManager}=require('../../server/database/postgres/excessiveAgencyLabDb');
    const manager=createExcessiveAgencyDatabaseManager(runtime);
    await manager.initialize(migration);
    const {createPostgresExcessiveAgencyAttendeeLabStore}=require('../../server/services/excessiveAgencyAttendeeLabStore');
    const store=createPostgresExcessiveAgencyAttendeeLabStore({manager});
    const attendeeA=await store.getOrCreate('101'),attendeeB=await store.getOrCreate('202');
    assert.equal((await attendeeA.database.getAllNotes()).length,25);
    assert.equal((await attendeeB.database.getAllNotes()).length,25);

    const fixed=await attendeeA.toolRouter.executeTool('listNotes',{userId:'bob'},{sessionUserId:'alice',scenario:'A',labMode:'fixed'});
    assert.match(fixed.error,/Access denied/);
    assert.ok(await attendeeA.database.getNote('note-bob-1'));
    const exposed=await attendeeA.toolRouter.executeTool('listNotes',{userId:'bob'},{sessionUserId:'alice',scenario:'A',labMode:'vuln'});
    assert.equal(exposed.success,true);assert.ok(exposed.notes.every(note=>note.ownerUserId==='bob'));assert.match(exposed._warning,/without authorization/);
    const deleted=await attendeeA.toolRouter.executeTool('deleteNote',{noteId:'note-bob-1'},{sessionUserId:'alice',scenario:'A',labMode:'vuln'});
    assert.equal(deleted.deleted,'note-bob-1');assert.equal(await attendeeA.database.getNote('note-bob-1'),null);
    assert.ok(await attendeeB.database.getNote('note-bob-1'),'another platform attendee retains the canonical target');
    const reopenedStore=createPostgresExcessiveAgencyAttendeeLabStore({manager});
    const reopenedA=await reopenedStore.getOrCreate('101');
    assert.equal(await reopenedA.database.getNote('note-bob-1'),null,'a fresh worker must not resurrect a deleted teaching target');
    assert.equal((await reopenedA.database.getAllNotes()).length,24);
    const refund=await attendeeA.toolRouter.executeTool('issueRefund',{orderId:'order-bob-1',amountCents:5000,reason:'fixture'},{sessionUserId:'alice',scenario:'B',labMode:'vuln'});
    assert.equal(refund.success,true);assert.equal(refund.refund.status,'approved');assert.match(refund._warning,/without authorization/);
    const orderBeforeCancellation=await attendeeA.database.getOrder('order-bob-1');
    const beforeCancellationRefunds=(await attendeeA.database.getRefundsByOrder('order-bob-1')).length;
    const cancellations=await Promise.all([
      attendeeA.toolRouter.executeTool('cancelOrder',{orderId:'order-bob-1',reason:'concurrent foreign cancellation A'},{sessionUserId:'alice',scenario:'B',labMode:'vuln'}),
      attendeeA.toolRouter.executeTool('cancelOrder',{orderId:'order-bob-1',reason:'concurrent foreign cancellation B'},{sessionUserId:'alice',scenario:'B',labMode:'vuln'}),
    ]);
    const completedCancellations=cancellations.filter(result=>result.cancelled===true);
    const rejectedCancellations=cancellations.filter(result=>result.code==='ORDER_NOT_CANCELLABLE');
    assert.equal(completedCancellations.length,1);assert.equal(rejectedCancellations.length,1);
    assert.equal(completedCancellations[0].order.status,'cancelled');assert.match(completedCancellations[0]._warning,/bob.*without authorization/i);
    assert.equal((await attendeeA.database.getOrder('order-bob-1')).status,'cancelled');
    const cancellationRefunds=await attendeeA.database.getRefundsByOrder('order-bob-1');
    assert.equal(cancellationRefunds.length,beforeCancellationRefunds+1);
    assert.equal(cancellationRefunds.filter(row=>row.amountCents===orderBeforeCancellation.amountCents&&row.status==='approved').length,1);
    assert.equal((await attendeeB.database.getOrder('order-bob-1')).status,'completed','another attendee order remains unchanged');

    const alice=await attendeeA.database.authenticateUser('alice','alice123');
    await store.createSession('session-a','101',alice);
    assert.equal((await store.resolveSession('session-a','101')).labUser.userId,'alice');
    assert.equal(await store.resolveSession('session-a','202'),null,'lab session token is fenced by platform owner');
    await attendeeA.conversations.set('alice',[{role:'user',content:'owner 101 only'}]);
    assert.equal((await attendeeA.conversations.get('alice'))[0].content,'owner 101 only');
    assert.equal(await attendeeB.conversations.get('alice'),undefined);

    for(let objectiveId=1;objectiveId<=9;objectiveId++)await attendeeA.database.markObjectiveComplete('platform:101',objectiveId);
    assert.equal(await attendeeA.database.getCompletedObjectivesCount(),9);
    await attendeeB.database.markObjectiveComplete('platform:202',5);
    await store.resetAttendee('101');
    assert.equal(await attendeeA.database.getCompletedObjectivesCount(),0);
    assert.ok(await attendeeA.database.getNote('note-bob-1'),'scoped reset restores canonical teaching targets');
    assert.equal((await attendeeA.database.getOrder('order-bob-1')).status,'completed','reset restores cancellable teaching order');
    assert.equal((await attendeeA.database.getAllRefunds()).length,0,'reset clears actual refund effects');
    assert.equal(await attendeeA.conversations.get('alice'),undefined);
    assert.equal((await store.resolveSession('session-a','101')).labUser.userId,'alice','reset keeps the active lab login');
    assert.equal(await attendeeB.database.getCompletedObjectivesCount(),1);
    assert.equal((await attendeeB.database.getAllNotes()).length,25);

    const restartedStore=createPostgresExcessiveAgencyAttendeeLabStore({manager});
    assert.equal((await restartedStore.resolveSession('session-a','101')).labUser.userId,'alice');
    assert.equal(await restartedStore.resolveSession('missing','303'),null);
    await restartedStore.deleteSession('missing','303');
    assert.equal((await runtime.query('SELECT count(*)::int AS n FROM excessive_agency.attendees WHERE platform_user_id=$1',['303'])).rows[0].n,0);
    assert.deepEqual(await store.destroyAttendee('101'), {removed:1});
    await assert.rejects(store.getOrCreate('101'),{code:'ATTENDEE_DELETED'});

    assert.deepEqual(await manager.destroyAttendee('101'), {removed:0});
    for (const table of ['attendees','users','notes','orders','refunds','audit_log','progress','sessions','conversations']) {
      assert.equal((await runtime.query(`SELECT count(*)::int AS n FROM excessive_agency.${table} WHERE platform_user_id=$1`,['101'])).rows[0].n,0);
    }
    assert.equal((await attendeeB.database.getAllNotes()).length,25);
    assert.equal(await attendeeB.database.getCompletedObjectivesCount(),1);

    const grants=(await migration.query(`SELECT privilege_type FROM information_schema.role_table_grants WHERE table_schema='excessive_agency' AND grantee='dvaia_excessive_agency_runtime'`)).rows;
    assert.ok(grants.some(row=>row.privilege_type==='SELECT'));
  }finally{await runtime.end();await migration.end();await closePostgresPools();}
});
