'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),{EventEmitter}=require('node:events');
const {createLegacyChallengeDb}=require('../server/database/postgres/legacyChallengeDb');
const {createLegacyPlatformMutationLifecycle,createLegacyPlatformMutationMiddleware}=require('../server/services/legacyPlatformMutationLifecycle');
function fixture(){const legacy=new EventEmitter(),identity=new EventEmitter(),queries=[];legacy.query=async(arg,values)=>{const sql=typeof arg==='string'?arg:arg.text;queries.push(['legacy',sql,values||arg.values]);return{rows:sql.includes('RETURNING id')?[{id:3}]:[{}],rowCount:1};};identity.query=async(sql,args)=>{queries.push(['identity',sql,args]);return{rows:[{}],rowCount:1};};legacy.release=()=>{};identity.release=()=>{};return{db:createLegacyChallengeDb({connect:async()=>legacy}),identityPool:{connect:async()=>identity},legacy,identity,queries};}
test('cookie-only lab provenance cannot mutate when the durable identity guard denies it', async () => {
  const { db, identityPool, identity, queries } = fixture();
  const query = identity.query;
  identity.query = async (sql, args) => {
    const result = await query(sql, args);
    if (sql.includes('identity.assert_legacy_platform_mutation')) {
      assert.deepEqual(args, [7, 9]);
      throw Object.assign(new Error('Legacy mutation authority unavailable'), { code: '55000' });
    }
    return result;
  };
  const lifecycle = createLegacyPlatformMutationLifecycle({ identityPool, store: db, enabled: true });
  let invoked = false;
  await assert.rejects(lifecycle.run({ session: { platformOwnerId: 7, platformSessionId: 9 } }, async () => {
    invoked = true;
    await db.addComment([2, 'must not persist', 7]);
  }), { code: '55000' });
  assert.equal(invoked, false);
  assert.equal(queries.some(row => row[1].includes('INSERT INTO comments')), false);
  assert.equal(queries.some(row => row[1] === 'COMMIT'), false);
  assert.deepEqual(queries.filter(row => row[1] === 'ROLLBACK').map(row => row[0]).sort(),
    ['identity', 'legacy']);
});
test('scoped mutations execute on the same legacy transaction that owns the deletion fence',async()=>{const {db,identityPool,queries}=fixture();await db.withPlatformMutationAuthority({identityPool,ownerId:7,sessionId:9},()=>db.addComment([2,'raw',7]));const insert=queries.find(row=>row[1].includes('INSERT INTO comments'));assert.equal(insert[0],'legacy');assert.ok(queries.findIndex(row=>row[1].includes('pg_advisory_xact_lock'))<queries.indexOf(insert));});
test('an async continuation cannot fall back to an unscoped write after its authority scope closes',async()=>{const {db,identityPool,queries}=fixture();let release,late;const gate=new Promise(resolve=>{release=resolve;});await db.withPlatformMutationAuthority({identityPool,ownerId:7,sessionId:9},async()=>{late=(async()=>{await gate;return db.addComment([2,'late']);})();});release();await assert.rejects(late,/authority expired/);assert.equal(queries.some(row=>row[1].includes('INSERT INTO comments')),false);});
test('loss of the held legacy lock invalidates a delayed scoped write',async()=>{const {db,identityPool,legacy,queries}=fixture();let release,late;const gate=new Promise(resolve=>{release=resolve;});const running=db.withPlatformMutationAuthority({identityPool,ownerId:7,sessionId:9},async()=>{late=(async()=>{await gate;return db.addComment([2,'late',7]);})();legacy.emit('error',new Error('lost'));});await assert.rejects(running,/lost/);release();await assert.rejects(late,/authority expired/);assert.equal(queries.some(row=>row[1].includes('INSERT INTO comments')),false);});
test('identity authority connection loss also invalidates the held legacy transaction context',async()=>{const {db,identityPool,identity,queries}=fixture();let release,late;const gate=new Promise(resolve=>{release=resolve;});const running=db.withPlatformMutationAuthority({identityPool,ownerId:7,sessionId:9},async()=>{late=(async()=>{await gate;return db.addComment([2,'late',7]);})();identity.emit('error',new Error('identity lost'));});await assert.rejects(running,/identity lost/);release();await assert.rejects(late,/authority expired/);assert.equal(queries.some(row=>row[1].includes('INSERT INTO comments')),false);});
test('mounted request disconnect expires the transaction context before a delayed model callback can write',async()=>{const {db,identityPool,queries}=fixture(),lifecycle=createLegacyPlatformMutationLifecycle({identityPool,store:db,enabled:true}),middleware=createLegacyPlatformMutationMiddleware(lifecycle),res=new EventEmitter();res.headersSent=false;res.status=()=>res;res.json=()=>{};res.off=res.removeListener.bind(res);let release,late;const gate=new Promise(resolve=>{release=resolve;});middleware({session:{platformOwnerId:7,platformSessionId:9}},res,()=>{late=(async()=>{await gate;return db.addComment([2,'late after disconnect',7]);})();});await new Promise(resolve=>setImmediate(resolve));res.emit('close');await new Promise(resolve=>setImmediate(resolve));release();await assert.rejects(late,/authority expired/);assert.equal(queries.some(row=>row[1].includes('INSERT INTO comments')),false);});
