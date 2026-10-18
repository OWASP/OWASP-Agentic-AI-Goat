'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const {
  a21RowSet,
  assertA21RowSet,
  chooseA21RestoredSubset,
  a21ReviewSnapshot,
  schemaText,
  verifyCouponBackfill,
  verifyPriceHistoryBackfill,
  verifySequenceTransition,
  verifyMaintenanceTransition,
  maintenanceLifecycleTables,
  preservationTablesForLifecycle,
  maintenanceState,
} = require('./release-inputs/populated16-rehearsal.cjs');

function historySequence(count){return {schema:'secureshop_review',name:'product_target_price_history_observation_id_seq',type:'bigint',start:'1',increment:'1',minimum:'1',maximum:'9223372036854775807',cache:'1',cycle:false,last_value:count==='0'?'1':count,is_called:count!=='0'};}
function historyProof(count){return {expected:count,actual:count,invalid:'0',distinctIds:count,minId:count==='0'?'0':'1',maxId:count};}
test('A21 new price history covers every active effective product and exact identity sequence',async()=>{
 for(const count of ['0','7']){
  let calls=0;
  await verifyPriceHistoryBackfill({ledger:[],tables:{}},{},async(_command,args)=>{
   calls++;const sql=args.at(-1);assert.match(sql,/COALESCE\(o.price,p.price\)/);assert.match(sql,/t.lifecycle='active'/);
   assert.match(sql,/FULL JOIN actual/);assert.match(sql,/migration_baseline/);assert.doesNotMatch(sql,/\b(?:INSERT|UPDATE|DELETE|nextval|setval)\b/i);
   return {stdout:JSON.stringify(historyProof(count))};
  },[historySequence(count)]);
  assert.equal(calls,1);
 }
});
test('A21 price history rejects incomplete or incorrect backfill and identity high water',async()=>{
 for(const patch of [{actual:'6'},{invalid:'1'},{distinctIds:'6'},{minId:'2'},{maxId:'8'}]){
  await assert.rejects(verifyPriceHistoryBackfill({ledger:[],tables:{}},{},async()=>({stdout:JSON.stringify({...historyProof('7'),...patch})}),[historySequence('7')]));
 }
 for(const sequences of [[],[{...historySequence('7'),last_value:'8'}],[{...historySequence('7'),is_called:false}],[{...historySequence('7'),increment:'2'}]]){
  await assert.rejects(verifyPriceHistoryBackfill({ledger:[],tables:{}},{},async()=>({stdout:JSON.stringify(historyProof('7'))}),sequences));
 }
});
test('A21 historical price history is not reinterpreted and second upgrade preserves new sequence exactly',async()=>{
 const tables={'secureshop_review.product_target_price_history':{}},ledger=[{name:'0040_owned_product_price_history.sql'}];
 await verifyPriceHistoryBackfill({ledger,tables},{},async()=>{throw Error('Historical rows must use exact preservation');},[]);
 await assert.rejects(verifyPriceHistoryBackfill({ledger:[],tables},{},async()=>{},[]),/schema and ledger disagree/);
 await assert.rejects(verifyPriceHistoryBackfill({ledger,tables:{}},{},async()=>{},[]),/schema and ledger disagree/);
 const first=[historySequence('7')];verifySequenceTransition(first,structuredClone(first),{});
 assert.throws(()=>verifySequenceTransition(first,[historySequence('8')],{}),/Undeclared sequence advance/);
});

const fs = require('node:fs');
const path = require('node:path');
const { createHash } = require('node:crypto');
const maintenanceLedger = [{name:'0001_maintenance_fence.sql',checksum:createHash('sha256')
  .update(fs.readFileSync(path.resolve(__dirname,'../db/postgres/maintenance-migrations/0001_maintenance_fence.sql'))).digest('hex'),applied_at:'2026-09-01T00:00:00Z'}];
const recoveryLedger=[...maintenanceLedger,{name:'0002_local_recovery.sql',checksum:'2'.repeat(64),applied_at:'2026-09-02T00:00:00Z'}];
function binding(epoch,{operation=`operation-${epoch}`,createdAt='2026-10-10T01:00:30Z'}={}){
  return {epoch:String(epoch),operation_id:operation,profile:'unavailable',reason_code:'UNMANAGED_BEGIN',workspace_sha256:null,
    store_manifest_sha256:null,publication_id:null,publication_sha256:null,source_manifest_sha256:null,owner_record:null,
    owner_record_sha256:null,created_at:createdAt};
}
function maintenance(epoch,{ledger=maintenanceLedger,epochBindings=[]}={}){
  const row={epoch:String(epoch),operation_id:'operation-'+epoch,owner_host_sha256:'owner',
    begun_at:'2026-10-10T01:00:00Z',finished_at:'2026-10-10T01:01:00Z'};
  return{control:[{id:1,state:'clean',...row}],epochs:[row],ledger:structuredClone(ledger),epochBindings:structuredClone(epochBindings)};
}
test('A21 first upgrade preserves prior maintenance history and advances exactly one epoch',()=>{
  const before=maintenance(8),after=maintenance(9);after.epochs.unshift(...before.epochs);
  verifyMaintenanceTransition(before,after);
  for(const mutate of [value=>{value.epochs[0].operation_id='changed';},value=>{value.ledger[0].applied_at='changed';},value=>{value.control[0].epoch='1';},value=>{value.control[0].id=2;}]){
    const changed=structuredClone(after);mutate(changed);assert.throws(()=>verifyMaintenanceTransition(before,changed));
  }
});
test('A21 direct initializer preserves prior bindings and appends one unavailable binding',()=>{
  const before=maintenance(8,{ledger:recoveryLedger,epochBindings:[binding(8)]});
  const after=maintenance(9,{ledger:recoveryLedger,epochBindings:[binding(8),binding(9)]});after.epochs.unshift(...before.epochs);
  verifyMaintenanceTransition(before,after);
  for(const mutate of [
    value=>{value.epochBindings[0].reason_code='CHANGED';},
    value=>{value.epochBindings[1].operation_id='other';},
    value=>{value.epochBindings[1].profile='upgrade-canonical16-v1';},
    value=>{value.epochBindings[1].workspace_sha256='a'.repeat(64);},
    value=>{value.epochBindings[1].created_at='2026-10-10T02:00:00Z';},
    value=>{value.epochBindings.pop();},
    value=>{value.epochBindings.push(binding(10));},
  ]){const changed=structuredClone(after);mutate(changed);assert.throws(()=>verifyMaintenanceTransition(before,changed));}
});
test('A21 absent maintenance history requires the exact first foundation ledger and epoch',()=>{
  const before={control:[],epochs:[],ledger:[],epochBindings:[]},after=maintenance(1);verifyMaintenanceTransition(before,after);
  for(const mutate of [value=>{value.ledger[0].checksum='00'.repeat(32);},value=>{value.epochs.push({...value.epochs[0]});},value=>{value.control[0].epoch='2';},value=>{value.epochBindings.push(binding(1));}]){
    const changed=structuredClone(after);mutate(changed);assert.throws(()=>verifyMaintenanceTransition(before,changed));
  }
  assert.throws(()=>verifyMaintenanceTransition({...before,epochs:[{epoch:'0'}]},after));
});
test('A21 baseline excludes only the independently checked identity maintenance lifecycle',()=>{
 const tables={'identity.users':{},'dvaia_maintenance.control':{},'dvaia_maintenance.epochs':{},'dvaia_maintenance.ledger':{},'dvaia_maintenance.epoch_bindings':{}};
 const exact=['dvaia_maintenance.control','dvaia_maintenance.epochs','dvaia_maintenance.epoch_bindings'];
 assert.deepEqual(maintenanceLifecycleTables(tables),exact);
 assert.strictEqual(preservationTablesForLifecycle({schema:'identity'},tables,[]),tables);
 assert.deepEqual(preservationTablesForLifecycle({schema:'identity'},tables,exact),{'identity.users':{},'dvaia_maintenance.ledger':{}});
 const oldTables={'identity.users':{},'dvaia_maintenance.control':{},'dvaia_maintenance.epochs':{},'dvaia_maintenance.ledger':{}};
 assert.deepEqual(maintenanceLifecycleTables(oldTables),['dvaia_maintenance.control','dvaia_maintenance.epochs']);
 assert.deepEqual(preservationTablesForLifecycle({schema:'identity'},oldTables,['dvaia_maintenance.control','dvaia_maintenance.epochs']),{'identity.users':{},'dvaia_maintenance.ledger':{}});
 assert.throws(()=>preservationTablesForLifecycle({schema:'identity'},tables,['identity.users']));
 assert.throws(()=>preservationTablesForLifecycle({schema:'secureshop'},tables,exact));
 assert.throws(()=>preservationTablesForLifecycle({schema:'identity'},tables,['dvaia_maintenance.control','dvaia_maintenance.epochs']));
 assert.throws(()=>preservationTablesForLifecycle({schema:'identity'},tables,[...exact,'identity.users']));
 assert.throws(()=>maintenanceLifecycleTables({'dvaia_maintenance.epochs':{}}));
});
test('A21 maintenance baseline distinguishes absent, historical, and binding-backed history',async()=>{
  const probe=values=>async()=>({stdout:JSON.stringify(values.shift())});
  assert.deepEqual(await maintenanceState({},probe([[false,false,false,false]])),{control:[],epochs:[],ledger:[],epochBindings:[]});
  const names=[true,true,true,false];
  await assert.rejects(maintenanceState({},probe([[names[0],false,names[2],names[3]]])),/Partial maintenance schema/);
  const before=maintenance(8);assert.deepEqual(await maintenanceState({},probe([names,before])),before);
  const bindings=[true,true,true,true],bound=maintenance(8,{ledger:recoveryLedger,epochBindings:[binding(8)]});
  assert.deepEqual(await maintenanceState({},probe([bindings,bound])),bound);
  await assert.rejects(maintenanceState({},probe([names,maintenance(8,{ledger:recoveryLedger})])),/binding table required/);
  await assert.rejects(maintenanceState({},probe([bindings,{control:null,epochs:[],ledger:maintenanceLedger,epochBindings:[]}])),/Existing maintenance control missing/);
});

function couponSnapshot(applied) {
  return {ledger:applied?[{name:'0025_bound_coupon_commerce.sql'}]:[],tables:{
    'secureshop_review.product_target_orders':{rows:1},
    'secureshop_review.product_target_order_items':{rows:1},
  }};
}
function couponRun(applied,counts=[]){
  const queries=[];
  return {queries,async run(_command,args){
    const sql=args.at(-1);queries.push(sql);
    if(sql.includes('column_names::text'))return{stdout:JSON.stringify(sql.includes("table_name='secureshop_review.product_target_orders'")
      ?['id','total_amount',...(applied?['subtotal_amount','discount_amount','coupon_code','coupon_percent']:[])]
      :['id','quantity','price',...(applied?['discount_amount']:[])])};
    return{stdout:String(counts.shift()??0)};
  }};
}
test('A21 pre0025 coupon backfill validates zero-discount defaults only for the original old schema',async()=>{
  const probe=couponRun(false);await verifyCouponBackfill(couponSnapshot(false),{},probe.run);
  assert.equal(probe.queries.filter(sql=>sql.startsWith('SELECT count(*)')).length,2);
  const failed=couponRun(false,[1]);await assert.rejects(verifyCouponBackfill(couponSnapshot(false),{},failed.run),/Original order subtotal backfill differs/);
});
test('A21 modern coupon rows bypass historical zero-discount predicates and retain exact-row preservation',async()=>{
  const probe=couponRun(true,[1,1]);await verifyCouponBackfill(couponSnapshot(true),{},probe.run);
  assert.equal(probe.queries.length,2);assert(probe.queries.every(sql=>sql.includes('column_names::text')));
  const original=a21RowSet([{payload:'{"id":1,"discount_amount":2,"coupon_code":"PRACTICE"}'}]);
  assertA21RowSet(original,original,'retained coupon order');
  assert.throws(()=>assertA21RowSet(a21RowSet([{payload:'{"id":1,"discount_amount":0,"coupon_code":null}'}]),original,'retained coupon order'));
});
test('A21 coupon ledger and original schema disagreement fails closed',async()=>{
  for(const applied of [false,true]){const probe=couponRun(!applied);await assert.rejects(verifyCouponBackfill(couponSnapshot(applied),{},probe.run),/Original coupon schema and ledger disagree/);assert.equal(probe.queries.length,1);}
});

const sourceSha256 = 'ab'.repeat(32);
const receiptOperationId = '11111111-1111-4111-8111-111111111111';

function shopIdentity(targetId, overrides = {}) {
  return {
    sceneId: `scene-${targetId}`,
    sceneIsDefault: true,
    sceneStatus: 'active',
    targetId,
    launchId: `launch-${targetId}`,
    scenarioId: `scenario-${targetId}`,
    generation: '3',
    ownerId: 41,
    sessionId: 71,
    realm: 'shop',
    platformUserId: null,
    ownerShopPrincipalId: null,
    ownerShopTenantId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
    sessionRealm: 'shop',
    platformSessionId: null,
    shopSessionId: null,
    shopExecutionSessionId: 71,
    sceneLaunchId: `launch-${targetId}`,
    sceneScenarioId: `scenario-${targetId}`,
    sceneGeneration: '3',
    sceneOwnerId: 41,
    sceneSessionId: 71,
    ...overrides,
  };
}

function platformIdentity(targetId, overrides = {}) {
  return shopIdentity(targetId, {
    realm: 'platform',
    platformUserId: 41,
    ownerShopTenantId: null,
    sessionRealm: 'platform',
    platformSessionId: 71,
    shopExecutionSessionId: null,
    ...overrides,
  });
}

function review(targetId, overrides = {}) {
  return {
    targetId,
    launchId: `launch-${targetId}`,
    scenarioId: `scenario-${targetId}`,
    generation: '3',
    lifecycle: 'active',
    ownerId: 41,
    sessionId: 71,
    sourceSha256,
    productCount: 2,
    productHashesValid: true,
    orderCount: 1,
    itemCount: 2,
    checkoutCount: 1,
    receiptOperationId,
    receiptActorId: 17,
    ...overrides,
  };
}

test('A21 inventory preserves every restored target and records actual platform-scene presence', () => {
  const identities = [
    shopIdentity('shop-receipt'),
    platformIdentity('platform-scene', { ownerId: 43, platformUserId: 43,
      sessionId: 73, platformSessionId: 73, sceneOwnerId: 43, sceneSessionId: 73 }),
    shopIdentity('unselected-shop', { ownerId: 45, sessionId: 75,
      ownerShopTenantId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', shopExecutionSessionId: 75,
      sceneId: null, sceneLaunchId: null, sceneScenarioId: null, sceneGeneration: null,
      sceneOwnerId: null, sceneSessionId: null }),
    shopIdentity('retired', { ownerId: 47, sessionId: 77,
      ownerShopTenantId: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc', shopExecutionSessionId: 77,
      sceneId: null, sceneLaunchId: null, sceneScenarioId: null, sceneGeneration: null,
      sceneOwnerId: null, sceneSessionId: null }),
  ];
  const reviews = [
    review('shop-receipt'),
    review('platform-scene', { ownerId: 43, sessionId: 73, orderCount: 0,
      itemCount: 0, checkoutCount: 0, receiptOperationId: null, receiptActorId: null }),
    review('unselected-shop', { ownerId: 45, sessionId: 75, orderCount: 0,
      itemCount: 0, checkoutCount: 0, receiptOperationId: null, receiptActorId: null }),
    review('retired', { ownerId: 47, sessionId: 77, lifecycle: 'retired', productCount: 0,
      productHashesValid: false, orderCount: 0, itemCount: 0, checkoutCount: 0,
      receiptOperationId: null, receiptActorId: null }),
  ];

  const selected = chooseA21RestoredSubset(identities, reviews);
  assert.deepEqual(selected.targets.map(row => row.targetId),
    ['shop-receipt', 'platform-scene', 'unselected-shop', 'retired']);
  assert.deepEqual(selected.receiptTargetIds, ['shop-receipt']);
  assert.deepEqual(selected.attestation, { platformScenes: 1, shopScenes: 1, targets: 4 });
});

test('A21 inventory attests zero platform scenes without requiring a fabricated legacy scene', () => {
  const selected = chooseA21RestoredSubset(
    [shopIdentity('shop-receipt')],
    [review('shop-receipt')],
  );
  assert.deepEqual(selected.attestation, { platformScenes: 0, shopScenes: 1, targets: 1 });
});

test('A21 inventory rejects unmatched targets and incoherent restored authority', () => {
  assert.throws(() => chooseA21RestoredSubset(
    [shopIdentity('shop-receipt')],
    [review('shop-receipt'), review('unmatched')],
  ), /review target has no identity reservation/);
  assert.throws(() => chooseA21RestoredSubset(
    [shopIdentity('shop-receipt'), shopIdentity('identity-only', { sceneId: null })],
    [review('shop-receipt')],
  ), /identity reservation has no restored review target/);
  assert.throws(() => chooseA21RestoredSubset(
    [shopIdentity('shop-receipt', { realm: 'platform' })],
    [review('shop-receipt')],
  ), /authority realm is invalid/);
  assert.throws(() => chooseA21RestoredSubset(
    [shopIdentity('shop-receipt')],
    [review('shop-receipt', { generation: '4' })],
  ), /target generation differs/);
});

test('A21 append allowance retains every original immutable row', () => {
  const original = a21RowSet([{ payload: '{"id":1}' }, { payload: '{"id":2}' }]);
  const appended = a21RowSet([{ payload: '{"id":1}' }, { payload: '{"id":2}' },
    { payload: '{"id":3}' }]);
  const modified = a21RowSet([{ payload: '{"id":1}' }, { payload: '{"id":9}' },
    { payload: '{"id":3}' }]);

  assert.doesNotThrow(() => assertA21RowSet(appended, original, 'grant rows', { allowAppend: true }));
  assert.throws(() => assertA21RowSet(appended, original, 'grant rows'), /grant rows/);
  assert.throws(() => assertA21RowSet(modified, original, 'grant rows', { allowAppend: true }),
    /original row digest missing/);
});

test('A21 review snapshot hashes only restored target tables after an additive upgrade', async () => {
  const required = ['bound_commerce_operations', 'product_target_order_items',
    'product_target_orders', 'product_target_products', 'product_targets'];
  const queries = [];
  const pool = { async query(sql) {
    queries.push(sql);
    if (sql.includes('information_schema.columns')) {
      return { rows: [...required, 'future_target_effects'].map(name => ({ name })) };
    }
    const table = /FROM secureshop_review\.([a-z0-9_]+) t/.exec(sql)?.[1];
    assert(required.includes(table));
    if (table === 'product_targets') return { rows: [{ payload: '{"target":"owned"}' }] };
    if (table === 'product_target_products') return { rows: [
      { payload: '{"product":2,"source":"bb"}' },
      { payload: '{"product":1,"source":"aa"}' },
    ] };
    return { rows: [] };
  } };
  const snapshot = await a21ReviewSnapshot(pool, 'target-id', required);
  assert.deepEqual(Object.keys(snapshot), required);
  assert.equal(snapshot.product_targets.rows, 1);
  assert.equal(snapshot.product_target_products.rows, 2);
  assert.equal(Object.hasOwn(snapshot, 'future_target_effects'), false);
  assert.equal(queries.some(sql => sql.includes('future_target_effects t')), false);
});

const emailConstraintForms=["    CONSTRAINT principals_email_check CHECK ((((octet_length(email) >= 3) AND (octet_length(email) <= 320)) AND (email = lower(email)) AND (email ~ '^[^[:space:]@]+@[^[:space:]@]+\\.[^[:space:]@]+$'::text))),", "    CONSTRAINT principals_email_check CHECK (((octet_length(email) >= 3) AND (octet_length(email) <= 320) AND (email = lower(email)) AND (email ~ '^[^[:space:]@]+@[^[:space:]@]+\\.[^[:space:]@]+$'::text))),"];
test('A21 identity email CHECK accepts only the two observed equivalent PostgreSQL forms',()=>{
 const wrap=(line,table='secureshop_auth.principals')=>'CREATE TABLE '+table+' (\n'+line+'\n);\n';
 const [before,after]=emailConstraintForms;
 assert.notEqual(before,after);assert.equal(schemaText(wrap(before)),schemaText(wrap(after)));
 for(const change of [line=>line.replace('<= 320','<= 321'),line=>line.replace('>= 3','>= 2'),line=>line.replace('[^[:space:]@]+$','[^[:space:]@]*$'),line=>line.replace('lower(email)','upper(email)')]){
  assert.notEqual(schemaText(wrap(change(before))),schemaText(wrap(after)));
  assert.notEqual(schemaText(wrap(change(after))),schemaText(wrap(after)));
 }
 for(const table of ['identity.principals','secureshop_auth.other_principals'])assert.notEqual(schemaText(wrap(before,table)),schemaText(wrap(after,table)));
 assert.notEqual(schemaText(wrap('')+before),schemaText(wrap('')+after));
});

test('A21 provisions fresh delivery before every restore and retains exact restore failure',async()=>{
 const {restoreStoresWithDelivery}=require('./release-inputs/populated16-rehearsal.cjs');
 const plan=require('../db/postgres/provision-application').provisioningPlan();
 const sourceConfiguration={},configuration={},stores={};
 for(const row of plan){
  for(const key of [row.runtimeVariable,row.migrationVariable]){
   sourceConfiguration[key]='postgresql://owned:old@installed.invalid/'+row.database;
   configuration[key]='postgresql://owned:fresh@127.0.0.1:55432/'+row.database;
  }
  stores[row.schema]={dump:row.schema+'.dump',tocSha256:createHash('sha256').update('toc').digest('hex'),source:{tables:{},ledger:[]},sequences:[]};
 }
 sourceConfiguration.CTF_DELIVERY_DATABASE_URL='postgresql://delivery:old@installed.invalid/dvaia_ctf';
 const generated='postgresql://delivery:fresh@127.0.0.1:55432/dvaia_ctf';
 const options={sourceConfiguration,provision:{plan,configuration},directory:'/owned/private',admin:'postgresql://postgres@127.0.0.1:55432/postgres',port:55432,installation:'/owned/installation',home:'/owned/home',mappings:{},saved:{stores},backupRoot:'/owned/backup'};
 const calls=[];let failure=null;
 const deps={delivery:async()=>{calls.push('delivery');return{configuration:{CTF_DELIVERY_DATABASE_URL:generated}};},
  run:async(_command,args,opts)=>{assert.equal(calls[0],'delivery');if(args[0]==='--list')return{stdout:'toc'};
   assert.equal(args[0],'--exit-on-error');assert.equal(opts.capture,false);calls.push(args[2]);
   if(failure&&args[2]===plan.find(row=>row.schema==='ctf').database)throw failure;return{};
  },schema:async()=>{},snapshot:async()=>({tables:{},ledger:[]}),sequences:async()=>[]};
 const result=await restoreStoresWithDelivery(options,deps);
 assert.deepEqual(calls,['delivery',...plan.map(row=>row.database)]);assert.equal(result.restored.length,16);
 assert.equal(result.env.CTF_DELIVERY_DATABASE_URL,generated);
 calls.length=0;failure=Object.assign(new Error('controlled restore failure'),{code:'CHILD_FAILED'});
 await assert.rejects(restoreStoresWithDelivery(options,deps),error=>error===failure);
 assert.equal(calls.at(-1),plan.find(row=>row.schema==='ctf').database);
 let restoreCalled=false;await assert.rejects(restoreStoresWithDelivery(options,{...deps,delivery:async()=>{throw failure;},run:async()=>{restoreCalled=true;}}),error=>error===failure);
 assert.equal(restoreCalled,false);
});

test('A21 child stderr stays bounded private evidence with categorical public failure',()=>{
 const {retainFailure,failureProjection}=require('./release-inputs/populated16-rehearsal.cjs');
 const root=fs.realpathSync(fs.mkdtempSync(path.join(require('node:os').tmpdir(),'a21-child-diagnostic-')));
 const priorOwner=process.env.SETUP_PHASE_OWNER;process.env.SETUP_PHASE_OWNER='controlled-owner';
 try{
  fs.chmodSync(root,0o700);
  const journal={nativePid:process.pid,owner:'controlled-owner',cohort:'restored-populated-upgrade',sourceRoot:path.resolve(__dirname,'..')};
  fs.writeFileSync(path.join(root,'ownership.json'),JSON.stringify(journal),{mode:0o600});
  const secret='private-controlled-diagnostic';
  const stderr=Buffer.from(secret.repeat(2000));
  const error=Object.assign(new Error(secret),{code:'CHILD_FAILED',privateDiagnostic:{stderr,stderrTruncated:false}});
  const result=retainFailure(error,root);assert.equal(result.status,'failed');assert.equal(result.error.code,'CHILD_FAILED');
  const file=path.join(root,result.diagnostic.name),bytes=fs.readFileSync(file),stat=fs.lstatSync(file);
  assert.equal(bytes.length,16384);assert.deepEqual(bytes,stderr.subarray(0,16384));assert.equal(result.diagnostic.truncated,true);
  assert.equal(result.diagnostic.sha256,createHash('sha256').update(bytes).digest('hex'));
  assert.equal(stat.mode&0o777,0o600);assert.equal(stat.uid,process.getuid());assert.equal(stat.nlink,1);
  assert(!JSON.stringify(result).includes(secret));assert(!JSON.stringify(failureProjection(error)).includes(secret));
  assert.equal(retainFailure(error,root).diagnosticFailure,'CHILD_DIAGNOSTIC_UNAVAILABLE');assert.deepEqual(fs.readFileSync(file),bytes);
  fs.unlinkSync(file);fs.symlinkSync(path.join(root,'ownership.json'),file);
  assert.equal(retainFailure(error,root).diagnosticFailure,'CHILD_DIAGNOSTIC_UNAVAILABLE');assert.deepEqual(JSON.parse(fs.readFileSync(path.join(root,'ownership.json'))),journal);
  fs.unlinkSync(file);fs.writeFileSync(path.join(root,'ownership.json'),JSON.stringify({...journal,owner:'foreign'}));
  assert.equal(retainFailure(error,root).diagnosticFailure,'CHILD_DIAGNOSTIC_UNAVAILABLE');assert.equal(fs.existsSync(file),false);
  assert.equal(retainFailure(new Error(secret),root).diagnostic,undefined);
 }finally{if(priorOwner===undefined)delete process.env.SETUP_PHASE_OWNER;else process.env.SETUP_PHASE_OWNER=priorOwner;fs.rmSync(root,{recursive:true,force:true});}
});

test('A21 retained child diagnostic accepts only the two owned rehearsal cohorts',()=>{
 const {retainFailure}=require('./release-inputs/populated16-rehearsal.cjs');
 const root=fs.realpathSync(fs.mkdtempSync(path.join(require('node:os').tmpdir(),'a21-retained-cohort-')));
 const priorOwner=process.env.SETUP_PHASE_OWNER;process.env.SETUP_PHASE_OWNER='controlled-owner';
 try{
  fs.chmodSync(root,0o700);
  const journal={nativePid:process.pid,owner:'controlled-owner',cohort:'retained-ownership-migrations',sourceRoot:path.resolve(__dirname,'..')};
  fs.writeFileSync(path.join(root,'ownership.json'),JSON.stringify(journal),{mode:0o600});
  const error=Object.assign(new Error('private'),{code:'CHILD_FAILED',privateDiagnostic:{stderr:Buffer.from('private'),stderrTruncated:false}});
  const result=retainFailure(error,root);assert.equal(result.diagnostic.name,'failed-child-stderr.bin');
  fs.unlinkSync(path.join(root,result.diagnostic.name));
  fs.writeFileSync(path.join(root,'ownership.json'),JSON.stringify({...journal,cohort:'foreign'}),{mode:0o600});
  assert.equal(retainFailure(error,root).diagnosticFailure,'CHILD_DIAGNOSTIC_UNAVAILABLE');
 }finally{if(priorOwner===undefined)delete process.env.SETUP_PHASE_OWNER;else process.env.SETUP_PHASE_OWNER=priorOwner;fs.rmSync(root,{recursive:true,force:true});}
});

test('A21 failure projection emits only safe retained preservation phase, statement digest, and stdout-limit counters',()=>{
 const {failureProjection}=require('./release-inputs/populated16-rehearsal.cjs');
 const error=Object.assign(new Error('secret SQL'),{code:'CHILD_FAILED',privateDiagnostic:{command:'psql',exitCode:null,signal:'SIGKILL',stdoutBytes:2097153,stdoutLimitExceeded:true,stderrBytes:0,stderr:Buffer.alloc(0),stderrTruncated:false}});
 Object.defineProperty(error,'preservationDiagnostic',{value:{phase:'baseline-drop',querySha256:'a'.repeat(64),store:'identity'},configurable:true});
 const projection=failureProjection(error);
 assert.deepEqual(projection.preservationDiagnostic,{phase:'baseline-drop',querySha256:'a'.repeat(64),store:'identity'});
 assert.deepEqual(projection.processDiagnostic,{command:'psql',exitCode:null,signal:'SIGKILL',stdoutBytes:2097153,stdoutLimitExceeded:true,stderrBytes:0});
 assert(!JSON.stringify(projection).includes('secret SQL'));
 Object.defineProperty(error,'preservationDiagnostic',{value:{phase:'not-allowed',querySha256:'a'.repeat(64)}});
 assert.equal(failureProjection(error).preservationDiagnostic,undefined);
 error.privateDiagnostic={command:'psql',exitCode:0,signal:null,stdoutBytes:1,stdoutLimitExceeded:'yes',stderrBytes:0};
 assert.equal(failureProjection(error).processDiagnostic,undefined);
});

test('A21 failure projection exposes only catalog field identity and states',()=>{
 const {failureProjection}=require('./release-inputs/populated16-rehearsal.cjs');
 const error=Object.assign(new Error('private catalog value'),{code:'CHILD_FAILED'});
 Object.defineProperty(error,'catalogFieldDiagnostic',{value:{entityKind:'objective',workshopKey:'secure_shop',objectiveId:'objective_1',fieldName:'hint_content',beforeState:'managed',afterState:'custom'}});
 const result=failureProjection(error);
 assert.deepEqual(result.catalogField,{entityKind:'objective',workshopKey:'secure_shop',objectiveId:'objective_1',fieldName:'hint_content',beforeState:'managed',afterState:'custom'});
 assert(!JSON.stringify(result).includes('private catalog value'));
 const invalid=Object.assign(new Error('private catalog value'),{code:'CHILD_FAILED'});
 Object.defineProperty(invalid,'catalogFieldDiagnostic',{value:{entityKind:'objective',workshopKey:'secure_shop',objectiveId:'private value with spaces',fieldName:'hint_content',beforeState:'managed',afterState:'custom'}});
 assert.equal(failureProjection(invalid).catalogField,undefined);
});

test('A21 failure projection retains only exact known delivery and PostgreSQL categories',()=>{
 const {failureProjection}=require('./release-inputs/populated16-rehearsal.cjs');
 const sources=['db/postgres/provision-ctf-delivery.js','scripts/install/ctf-delivery-setup.js']
  .map(file=>fs.readFileSync(path.resolve(__dirname,'..',file),'utf8')).join('\n');
 const codes=[...new Set([...sources.matchAll(/['"](CTF_DELIVERY_[A-Z_]+)['"]/g)].map(match=>match[1]))].filter(code=>code!=='CTF_DELIVERY_DATABASE_URL');
 assert.equal(codes.length,18);
 for(const code of codes){
  const result=failureProjection(Object.assign(new Error('private detail'),{code}));
  assert.equal(result.error.code,code);assert(!JSON.stringify(result).includes('private detail'));
 }
 for(const code of ['08001','08006','08P01','28000','28P01','3D000','42601','42710','53300','57P03','ECONNREFUSED','ECONNRESET','EPIPE','EPERM','ENOSPC','42501'])assert.equal(failureProjection(Object.assign(new Error('private detail'),{code})).error.code,code);
 assert.equal(failureProjection(new Error('CTF_DELIVERY_CONFIGURATION_INVALID')).error.code,'CTF_DELIVERY_CONFIGURATION_INVALID');
 for(const value of ['CTF_DELIVERY_FUTURE_PRIVATE_CODE','CTF_DELIVERY_DATABASE_URL','CTF_DELIVERY_ROLE_MISMATCH: private detail','ZZZZZ','postgresql://private:secret@host/db']){
  const result=failureProjection(Object.assign(new Error(value),{code:value}));assert.equal(result.error.code,null);assert(!JSON.stringify(result).includes(value));
 }
});

test('A21 failure projection publishes only bounded preservation table counts',()=>{
 const {failureProjection}=require('./release-inputs/populated16-rehearsal.cjs');
 const error=new Error('private row value must not escape');
 Object.defineProperty(error,'preservationComparison',{value:{store:'identity',table:'identity.users',missing:1,added:0}});
 const result=failureProjection(error);
 assert.deepEqual(result.comparison,{store:'identity',table:'identity.users',missing:1,added:0});
 assert(!JSON.stringify(result).includes('private row value'));
 const malformed=new Error('private');
 Object.defineProperty(malformed,'preservationComparison',{value:{store:'identity',table:'identity.users;secret',missing:1,added:0}});
  assert.equal(failureProjection(malformed).comparison,undefined);
});

test('A21 failure projection caps aggregate preservation diagnostics without row values',()=>{
 const {failureProjection}=require('./release-inputs/populated16-rehearsal.cjs');
 const error=new Error('private row values must not escape');
 Object.defineProperty(error,'preservationComparisons',{value:{entries:[
  {store:'identity',table:'identity.users',missing:1,added:0},
  {store:'secureshop',table:'secureshop.products',missing:0,added:2},
 ],omitted:7}});
 const result=failureProjection(error);
 assert.deepEqual(result.comparisons,{entries:[
  {store:'identity',table:'identity.users',missing:1,added:0},
  {store:'secureshop',table:'secureshop.products',missing:0,added:2},
 ],omitted:7});
 assert(!JSON.stringify(result).includes('private row values'));
 const malformed=new Error('private');
 Object.defineProperty(malformed,'preservationComparisons',{value:{entries:[{store:'identity',table:'identity.users',missing:1,added:0}],omitted:-1}});
 assert.equal(failureProjection(malformed).comparisons,undefined);
});

test('A21 failure projection retains the prior closed restore hash comparison',()=>{
 const {compareRestore,failureProjection}=require('./release-inputs/populated16-rehearsal.cjs');
 let error;try{compareRestore({rows:2},{rows:1},'rows-ledger');}catch(caught){error=caught;}
 const result=failureProjection(error);
 assert.deepEqual(result.comparison,{kind:'rows-ledger',actualSha256:createHash('sha256').update(JSON.stringify({rows:2})).digest('hex'),expectedSha256:createHash('sha256').update(JSON.stringify({rows:1})).digest('hex')});
});

const embeddingConstraintForms=["    CONSTRAINT product_embedding_policy_shape CHECK ((((policy_version IS NULL) AND (policy_snapshot_sha256 IS NULL)) OR (((policy_version >= 1) AND (policy_version <= '9007199254740991'::bigint)) AND (octet_length(policy_snapshot_sha256) = 32)))),", "    CONSTRAINT product_embedding_policy_shape CHECK ((((policy_version IS NULL) AND (policy_snapshot_sha256 IS NULL)) OR ((policy_version >= 1) AND (policy_version <= '9007199254740991'::bigint) AND (octet_length(policy_snapshot_sha256) = 32)))),"];
test('A21 review embedding CHECK accepts only the two observed equivalent PostgreSQL forms',()=>{
 const wrap=(line,table='secureshop_review.product_target_embedding_revisions')=>'CREATE TABLE '+table+' (\n'+line+'\n);\n';
 const [before,after]=embeddingConstraintForms;
 assert.notEqual(before,after);assert.equal(schemaText(wrap(before)),schemaText(wrap(after)));
 for(const change of [line=>line.replace('>= 1','>= 0'),line=>line.replace('9007199254740991','9007199254740992'),line=>line.replace('= 32','= 31'),line=>line.replace('IS NULL','IS NOT NULL'),line=>line.replace(' OR ',' AND '),line=>line.replace('CHECK (','CHECK  (')]){
  assert.notEqual(schemaText(wrap(change(before))),schemaText(wrap(after)));
  assert.notEqual(schemaText(wrap(change(after))),schemaText(wrap(after)));
 }
 for(const table of ['other.product_target_embedding_revisions','secureshop_review.other_embedding_revisions'])assert.notEqual(schemaText(wrap(before,table)),schemaText(wrap(after,table)));
 assert.notEqual(schemaText(wrap('')+before),schemaText(wrap('')+after));
});

test('A21 managed env encoding matches each actual consumer dialect without changing flags',()=>{
 const {encodeRestoredManagedEnvironment}=require('./release-inputs/populated16-rehearsal.cjs');
 const qualified=require('../server/services/secureshopQualifiedManagedConfiguration');
 const options={installation:'/owned/installation with spaces',home:'/owned/home'};
 const roots=qualified.expectedRoots(options.installation,options.home);
 const values={SS_ENABLE:'true',...Object.fromEntries(qualified.BOOLEAN_KEYS.map(key=>[key,'true'])),...roots};
 const bytes=encodeRestoredManagedEnvironment('secureshop-qualified.env',values,options);
 assert(bytes.startsWith('SS_ENABLE=true\n'));assert.deepEqual({...qualified.parse(Buffer.from(bytes),{root:options.installation,home:options.home})},values);
 for(const patch of [{SS_ENABLE:'"true"'},{SS_ENABLE:'false'},{SS_PERSONA_INBOX_READY:'false'},{SS_MCP_TRUST_FIXTURE_ROOT:'/foreign/root'},{SS_MCP_TRUST_FIXTURE_ROOT:roots.SS_MCP_TRUST_FIXTURE_ROOT+'\nSS_ENABLE=false'}])assert.throws(()=>encodeRestoredManagedEnvironment('secureshop-qualified.env',{...values,...patch},options));
 const mcp={MCP_OWNED_TARGET_APPARMOR_PROFILE:'dvaia-mcp-sandbox',MCP_OWNED_TARGET_PORT:'8092',MCP_OWNED_TARGET_URL:'http://127.0.0.1:8092',MCP_OWNED_TARGET_TOKEN:'a'.repeat(64),MCP_OWNED_RESOURCES_ENABLED:'true',MCP_OBSERVED_ACTION_ENABLED:'true',MCP_INDIRECT_INJECTION_ENABLED:'true',MCP_SUPPLY_CHAIN_ENABLED:'true',MCP_PROTECTED_RECOVERY_ENABLED:'true',CODEBOT_SANDBOX_RUNNER_URL:'http://127.0.0.1:8092',CODEBOT_OWNED_EXECUTION_ENABLED:'true'};
 const encodedMcp=encodeRestoredManagedEnvironment('mcp-owned.env',mcp,options);
 assert.deepEqual({...require('../server/services/mcp/ownedManagedConfiguration').parseManagedConfiguration(Buffer.from(encodedMcp))},mcp);
 const password='a'.repeat(64);
 assert.equal(encodeRestoredManagedEnvironment('postgres-container.env',{POSTGRES_PASSWORD:password},options),`POSTGRES_PASSWORD=${password}\n`);
 assert.throws(()=>encodeRestoredManagedEnvironment('postgres-container.env',{POSTGRES_PASSWORD:password,EXTRA:'true'},options));
 assert.throws(()=>encodeRestoredManagedEnvironment('postgres-container.env',{POSTGRES_PASSWORD:'abc\nINJECT=true'},options));
 for(const code of ['SECURESHOP_MANAGED_CONFIGURATION_INVALID','ANALYTICS_MANAGED_CONFIGURATION_INVALID','COUPON_MANAGED_CONFIGURATION_INVALID','MCP_MANAGED_CONFIGURATION_INVALID'])assert.equal(require('./release-inputs/populated16-rehearsal.cjs').failureProjection(Object.assign(new Error('private'),{code})).error.code,code);
});

const {
  retainedOwnershipPreservationTables,
  retainedAssessmentDefaultContract,
  retainedAssessmentDefaultBaseline,
  retainedAssessmentDatabaseClock,
  verifyRetainedAssessmentDefaultAddition,
} = require('./release-inputs/populated16-rehearsal.cjs');

test('A21 retains every existing assessment objective and admits only the canonical disabled Listings default', async () => {
  const tables={
    'identity.users':{},
    'secureshop_auth.assessment_objectives':{},
    'dvaia_maintenance.control':{},'dvaia_maintenance.epochs':{},
    'dvaia_maintenance.ledger':{},'dvaia_maintenance.epoch_bindings':{},
  };
  assert.deepEqual(retainedOwnershipPreservationTables({schema:'identity'},tables),{
    'identity.users':{},'dvaia_maintenance.ledger':{},
  });
  const contract=retainedAssessmentDefaultContract();
  assert.deepEqual(contract,{
    objectiveId:'ss_listing_template_execution',
    label:'Cause the Listings agent to execute a saved template command inside its isolated target',
    enabled:false,qualification:'native-model',
    sourceDocument:{version:1,id:'ss_listing_template_execution',
      label:'Cause the Listings agent to execute a saved template command inside its isolated target',
      defaultEnabled:false,qualification:'native-model'},
    sourceSha256:'763c4acc55d0d12fd5cc3bfe4474728a1fb0f3246adf5ee910f4ce19003ea599',
    catalogActive:true,configurationSource:'checked_in_default',
  });
  const queries=[];
  const run=async(_command,args)=>{
    const query=args.at(-1);queries.push(query);
    if(query.includes('CREATE TABLE dvaia_qualification.retained_assessment_objectives')){
      return {stdout:JSON.stringify({rows:25,targetRows:0})};
    }
    if(query.includes("clock_timestamp()")) return {stdout:JSON.stringify({at:'2026-10-10T00:00:00.000Z'})};
    return {stdout:JSON.stringify({missing:0,added:1,baselineRows:25,targetRows:1,targetMatches:1})};
  };
  const baseline=await retainedAssessmentDefaultBaseline({},run);
  assert.deepEqual(baseline,{rows:25});
  assert.equal(await retainedAssessmentDatabaseClock({},run),'2026-10-10T00:00:00.000Z');
  const result=await verifyRetainedAssessmentDefaultAddition({}, {
    baseline,startedAt:'2026-10-10T00:00:00.000Z',finishedAt:'2026-10-10T00:00:02.000Z',
  },run);
  assert.deepEqual(result,{objectiveId:'ss_listing_template_execution',sourceSha256:contract.sourceSha256});
  const query=queries.at(-1);
  for(const field of ['label=','is_enabled=false','catalog_active=true','qualification=',
    'source_sha256=','source_document=','configuration_source=','updated_at>=','updated_at<=']) assert.match(query,new RegExp(field.replace(/[=]/g,'\\=')));
  assert.match(query,/ss_listing_template_execution/);
  assert.match(query,/763c4acc55d0d12fd5cc3bfe4474728a1fb0f3246adf5ee910f4ce19003ea599/);
});

test('A21 assessment default rejects modified baseline, unknown additions, wrong defaults, and unbounded generated timestamps', async () => {
  const valid={missing:0,added:1,baselineRows:25,targetRows:1,targetMatches:1};
  for(const patch of [
    {missing:1}, // a preexisting objective changed or disappeared
    {added:2}, // unknown additional default
    {targetRows:0}, {targetRows:2},
    {targetMatches:0}, // wrong label/default/hash/document/configuration/timestamp
    {baselineRows:24},
  ]){
    await assert.rejects(verifyRetainedAssessmentDefaultAddition({}, {
      baseline:{rows:25},startedAt:'2026-10-10T00:00:00.000Z',finishedAt:'2026-10-10T00:00:02.000Z',
    },async()=>({stdout:JSON.stringify({...valid,...patch})})));
  }
  await assert.rejects(verifyRetainedAssessmentDefaultAddition({}, {
    baseline:{rows:25},startedAt:'invalid',finishedAt:'2026-10-10T00:00:02.000Z',
  },async()=>({stdout:JSON.stringify(valid)})));
  await assert.rejects(retainedAssessmentDefaultBaseline({},async()=>({stdout:JSON.stringify({rows:25,targetRows:1})})));
  await assert.rejects(retainedAssessmentDatabaseClock({},async()=>({stdout:JSON.stringify({at:'invalid'})})));
  assert.throws(()=>retainedOwnershipPreservationTables({schema:'secureshop'}, {
    'secureshop_auth.assessment_objectives':{},
    'dvaia_maintenance.control':{},'dvaia_maintenance.epochs':{},'dvaia_maintenance.ledger':{},
  }));
});
