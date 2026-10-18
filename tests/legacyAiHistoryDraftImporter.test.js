'use strict';
const assert=require('node:assert/strict');const test=require('node:test');
const {createLegacyAiHistoryDraftImporter,canonicalRow,digest}=require('../server/database/postgres/legacyAiHistoryDraftImporter');
const {bindSourceStoreIdentity}=require('../server/database/postgres/legacyAiHistoryArchiveAttestation');
const batchId='10000000-0000-4000-8000-000000000099';
const rows=[{id:7,userId:9,prompt:'owned',response:'answer',modelUsed:'m',createdAt:'2026-09-15T01:02:03.123456Z',platformOwnerId:99},{id:8,userId:1,prompt:'unknown',response:'kept',modelUsed:'m',createdAt:'2026-09-15T01:02:04.123457Z',platformOwnerId:null}];
const manifestDigest='a'.repeat(64),attestationReceipt='b'.repeat(64);
function attestationEnvelope(value,claims=[],overrides={}){
 const canonical=claims.map(claim=>({...claim,requestId:typeof claim.requestId==='string'?claim.requestId.toLowerCase():claim.requestId})).sort((a,b)=>a.sourceRowId-b.sourceRowId);
 const claimsDigest=digest(canonical);
 return {envelopeVersion:1,batchId:value.batchId,sourceStoreDigest:value.sourceStoreDigest,
  aggregateDigest:value.aggregateDigest,manifestDigest,claims,claimsDigest,attestationReceipt,
  boundSourceStoreIdentity:bindSourceStoreIdentity({sourceStoreDigest:value.sourceStoreDigest,
   manifestDigest,claimsDigest,attestationReceipt}),...overrides};
}
const verified=value=>Object.freeze({batchId:value.batchId,sourceRemovalReceipt:value.aggregateDigest,
 verified:true,sourceRemovalAuthorized:false});
test('draft importer archives every exact row and promotes only attested ownership',async()=>{
 const calls=[];let aggregate;
 const source=Object.freeze({readSnapshot:async()=>({batchId,sourceStoreIdentity:'legacy://owned-snapshot',rows})});
 const attest=Object.freeze({attest:async value=>{aggregate=value.aggregateDigest;return attestationEnvelope(value,[{sourceRowId:7,sourceDigest:value.rows[0].sourceDigest,ownerId:42,requestId:'10000000-0000-4000-8000-000000000007',sourceRoute:'prompt_injection'}]);}});
 const target=Object.freeze({begin:async x=>{calls.push(['begin',x]);return{state:'copying'};},archive:async x=>calls.push(['archive',x]),promote:async x=>calls.push(['promote',x]),readArchived:async()=>calls.filter(([k])=>k==='archive').map(([,x])=>({sourceRowId:x.sourceRowId,sourceDigest:x.sourceDigest,sourceRecord:x.sourceRecord,classification:x.classification,ownerId:x.ownerId})),readPromoted:async()=>({ownerId:42,requestId:'10000000-0000-4000-8000-000000000007',sourceRoute:'prompt_injection',sourceDigest:digest({id:7,userId:9,prompt:'owned',response:'answer',modelUsed:'m',createdAt:'2026-09-15T01:02:03.123456Z',platformOwnerId:99}),historyDigest:digest({ownerId:42,requestId:'10000000-0000-4000-8000-000000000007',sourceRoute:'prompt_injection',row:{id:7,userId:9,prompt:'owned',response:'answer',modelUsed:'m',createdAt:'2026-09-15T01:02:03.123456Z',platformOwnerId:99}}),createdAt:rows[0].createdAt,prompt:rows[0].prompt,response:rows[0].response,modelUsed:rows[0].modelUsed}),verify:async x=>{calls.push(['verify',x]);return verified(x);}});
 const result=await createLegacyAiHistoryDraftImporter({sourceSnapshotCapability:source,ownershipAttestationCapability:attest,targetImportCapability:target}).quarantine();
 assert.equal(result.targetReceipt.sourceRemovalAuthorized,false);assert.equal(calls.filter(([k])=>k==='archive').length,2);assert.equal(calls.filter(([k])=>k==='promote').length,1);
 assert.ok(calls.findIndex(([k])=>k==='promote') > calls.map(([k])=>k).lastIndexOf('archive'));
 assert.equal(calls.find(([k,x])=>k==='archive'&&x.sourceRowId===8)[1].classification,'unknown');assert.equal(calls.at(-1)[1].aggregateDigest,aggregate);
});
test('draft importer rejects untrusted-shaped capabilities and mismatched attestations',async()=>{
 assert.throws(()=>createLegacyAiHistoryDraftImporter({sourceSnapshotCapability:{},ownershipAttestationCapability:{},targetImportCapability:{}}),/Frozen reviewed/);
 const source=Object.freeze({readSnapshot:async()=>({batchId,sourceStoreIdentity:'legacy://x',rows})});const bad=Object.freeze({attest:async value=>attestationEnvelope(value,[],{aggregateDigest:'0'.repeat(64)})});const target=Object.freeze({begin:async()=>{},archive:async()=>{},promote:async()=>{},readArchived:async()=>[],readPromoted:async()=>null,verify:async()=>{}});
 await assert.rejects(createLegacyAiHistoryDraftImporter({sourceSnapshotCapability:source,ownershipAttestationCapability:bad,targetImportCapability:target}).quarantine(),/attestation differs/);
});
test('attestation request-id conflicts fail before target writes',async()=>{
 const source=Object.freeze({readSnapshot:async()=>({batchId,sourceStoreIdentity:'legacy://x',rows})});let writes=0;
 const attestationCapability=Object.freeze({attest:async value=>attestationEnvelope(value,value.rows.map(row=>({sourceRowId:row.sourceRowId,sourceDigest:row.sourceDigest,ownerId:42,requestId:'10000000-0000-4000-8000-000000000007',sourceRoute:'prompt_injection'})))});
 const target=Object.freeze({begin:async()=>{writes++;},archive:async()=>{writes++;},promote:async()=>{writes++;},readArchived:async()=>[],readPromoted:async()=>null,verify:async()=>{writes++;}});
 await assert.rejects(createLegacyAiHistoryDraftImporter({sourceSnapshotCapability:source,ownershipAttestationCapability:attestationCapability,targetImportCapability:target}).quarantine(),/reuses a request ID/);assert.equal(writes,0);
});
test('Proxy length cannot hide a nonempty attestation claim array', async () => {
 const source=Object.freeze({readSnapshot:async()=>({batchId,sourceStoreIdentity:'legacy://proxy',rows})});
 let writes=0, lengthReads=0;
 const attest=Object.freeze({attest:async value=>{
  const claim={sourceRowId:7,sourceDigest:value.rows[0].sourceDigest,ownerId:42,
   requestId:'10000000-0000-4000-8000-000000000007',sourceRoute:'prompt_injection'};
  const claims=new Proxy([claim],{get(target,key,receiver){
   if(key==='length')return ++lengthReads<3?1:0;
   return Reflect.get(target,key,receiver);
  }});
  return attestationEnvelope(value,[],{claims});
 }});
 const target=Object.freeze({begin:async()=>{writes++;},archive:async()=>{writes++;},
  promote:async()=>{writes++;},readArchived:async()=>[],readPromoted:async()=>null,verify:async()=>{writes++;}});
 await assert.rejects(createLegacyAiHistoryDraftImporter({sourceSnapshotCapability:source,
  ownershipAttestationCapability:attest,targetImportCapability:target}).quarantine(),/claim digest differs/);
 assert.equal(lengthReads,0);assert.equal(writes,0);
});
test('verified replay rechecks ownership and promoted bytes without archive or promotion writes',async()=>{
 const source=Object.freeze({readSnapshot:async()=>({batchId,sourceStoreIdentity:'legacy://replay',rows})});let archive=0,promote=0;
 const claim={sourceRowId:7,sourceDigest:digest({id:7,userId:9,prompt:'owned',response:'answer',modelUsed:'m',createdAt:'2026-09-15T01:02:03.123456Z',platformOwnerId:99}),ownerId:42,requestId:'10000000-0000-4000-8000-000000000007',sourceRoute:'prompt_injection'};
 const attestationCapability=Object.freeze({attest:async value=>attestationEnvelope(value,[claim])});
 const archiveRows=rows.map(row=>({sourceRowId:row.id,sourceDigest:digest({id:row.id,userId:row.userId,prompt:row.prompt,response:row.response,modelUsed:row.modelUsed,createdAt:row.createdAt,platformOwnerId:row.platformOwnerId}),sourceRecord:{id:row.id,userId:row.userId,prompt:row.prompt,response:row.response,modelUsed:row.modelUsed,createdAt:row.createdAt,platformOwnerId:row.platformOwnerId},classification:row.id===7?'owned':'unknown',ownerId:row.id===7?42:null}));
 const target=Object.freeze({begin:async()=>({state:'verified'}),archive:async()=>archive++,promote:async()=>promote++,readArchived:async()=>archiveRows,readPromoted:async()=>({ownerId:42,requestId:claim.requestId,sourceRoute:claim.sourceRoute,sourceDigest:claim.sourceDigest,historyDigest:digest({ownerId:42,requestId:claim.requestId,sourceRoute:claim.sourceRoute,row:archiveRows[0].sourceRecord}),createdAt:rows[0].createdAt,prompt:rows[0].prompt,response:rows[0].response,modelUsed:rows[0].modelUsed}),verify:async x=>verified(x)});
 await createLegacyAiHistoryDraftImporter({sourceSnapshotCapability:source,ownershipAttestationCapability:attestationCapability,targetImportCapability:target}).quarantine();assert.equal(archive,0);assert.equal(promote,0);
 const tampered=Object.freeze({...target,readPromoted:async()=>({ownerId:42,requestId:claim.requestId,sourceRoute:'context_stuffing',sourceDigest:'0'.repeat(64),historyDigest:'0'.repeat(64),createdAt:rows[0].createdAt,prompt:rows[0].prompt,response:rows[0].response,modelUsed:rows[0].modelUsed})});
 await assert.rejects(createLegacyAiHistoryDraftImporter({sourceSnapshotCapability:source,ownershipAttestationCapability:attestationCapability,targetImportCapability:tampered}).quarantine(),/owned history bytes differ/);
  const omitted=Object.freeze({attest:async value=>attestationEnvelope(value,[])});
 await assert.rejects(createLegacyAiHistoryDraftImporter({sourceSnapshotCapability:source,ownershipAttestationCapability:omitted,targetImportCapability:target}).quarantine(),/ownership differs/);
});
test('malformed attested request IDs reject before begin',async()=>{
 const source=Object.freeze({readSnapshot:async()=>({batchId,sourceStoreIdentity:'legacy://uuid',rows})});let began=false;
 const attestationCapability=Object.freeze({attest:async value=>attestationEnvelope(value,[{sourceRowId:7,sourceDigest:value.rows[0].sourceDigest,ownerId:42,requestId:'not-a-uuid',sourceRoute:'prompt_injection'}])});
 const target=Object.freeze({begin:async()=>{began=true;},archive:async()=>{},promote:async()=>{},readArchived:async()=>[],readPromoted:async()=>null,verify:async()=>{}});
 await assert.rejects(createLegacyAiHistoryDraftImporter({sourceSnapshotCapability:source,ownershipAttestationCapability:attestationCapability,targetImportCapability:target}).quarantine(),/invalid or conflicting/);assert.equal(began,false);
});

test('uppercase attested UUIDs use canonical identity and resist mutation during target calls', async () => {
 const row = rows[0], requestId = 'abcdefab-abcd-4abc-8abc-abcdefabcdef';
 const claim = { sourceRowId: row.id, sourceDigest: digest(row), ownerId: 42,
   requestId: requestId.toUpperCase(), sourceRoute: 'prompt_injection' };
 let archived, promoted;
 const source = Object.freeze({ readSnapshot: async () => ({ batchId, sourceStoreIdentity: 'legacy://canonical', rows: [row] }) });
 const attestationCapability = Object.freeze({ attest: async value => attestationEnvelope(value, [claim]) });
 const target = Object.freeze({
   begin: async () => { claim.ownerId = 999; claim.requestId = '10000000-0000-4000-8000-000000000077'; return { state: 'copying' }; },
   archive: async value => { archived = value; },
   promote: async value => { promoted = value; },
   readArchived: async () => [archived],
   readPromoted: async () => ({ ...promoted, requestId: promoted.requestId.toLowerCase() }),
   verify: async value => verified(value),
 });
 await createLegacyAiHistoryDraftImporter({ sourceSnapshotCapability: source,
   ownershipAttestationCapability: attestationCapability, targetImportCapability: target }).quarantine();
 assert.equal(promoted.ownerId, 42);
 assert.equal(promoted.requestId, requestId);
 assert.equal(promoted.historyDigest, digest({ ownerId: 42, requestId, sourceRoute: 'prompt_injection', row }));
});

test('out-of-range PostgreSQL owner claims reject before any target write', async () => {
 let writes = 0;
 const source = Object.freeze({ readSnapshot: async () => ({ batchId, sourceStoreIdentity: 'legacy://owner-range', rows }) });
 const attest = Object.freeze({ attest: async value => attestationEnvelope(value,
   [{ sourceRowId: 7, sourceDigest: value.rows[0].sourceDigest, ownerId: 2147483648,
     requestId: '10000000-0000-4000-8000-000000000007', sourceRoute: 'prompt_injection' }]) });
 const target = Object.freeze({ begin: async () => { writes++; }, archive: async () => { writes++; },
   promote: async () => { writes++; }, readArchived: async () => [], readPromoted: async () => null,
   verify: async () => { writes++; } });
 await assert.rejects(createLegacyAiHistoryDraftImporter({ sourceSnapshotCapability: source,
   ownershipAttestationCapability: attest, targetImportCapability: target }).quarantine(), /invalid or conflicting/);
 assert.equal(writes, 0);
});

test('unknown signed and nullable source rows retain every scalar and exact archive digest', async () => {
 const sourceRows = [
   { id: -2147483648, userId: -2147483648, prompt: 'negative source identity', response: null,
     modelUsed: null, createdAt: null, platformOwnerId: -2147483648 },
   { id: 0, userId: null, prompt: '', response: '', modelUsed: '', createdAt: 'infinity',
     platformOwnerId: 2147483647 },
 ];
 const archived = [];
 const source = Object.freeze({ readSnapshot: async () => ({ batchId,
   sourceStoreIdentity: 'legacy://signed-nullable', rows: sourceRows }) });
 const attestationCapability = Object.freeze({ attest: async value => attestationEnvelope(value, []) });
 const target = Object.freeze({
   begin: async () => ({ state: 'copying' }),
   archive: async value => archived.push(value),
   promote: async () => { throw new Error('unknown row promoted'); },
   readArchived: async () => archived,
   readPromoted: async () => { throw new Error('unknown promotion read'); },
   verify: async value => verified(value),
 });
 await createLegacyAiHistoryDraftImporter({ sourceSnapshotCapability: source,
   ownershipAttestationCapability: attestationCapability, targetImportCapability: target }).quarantine();
 assert.equal(archived.length, 2);
 assert.deepEqual(archived.map(item => item.sourceRecord), sourceRows);
 assert.deepEqual(archived.map(item => item.sourceRowId), [-2147483648, 0]);
 assert.deepEqual(archived.map(item => item.sourceDigest), sourceRows.map(digest));
 assert.deepEqual(archived.map(item => [item.classification, item.ownerId]),
   [['unknown', null], ['unknown', null]], 'raw platform_owner_id must not infer classified ownership');
});

test('raw nullable fields require exact null and never normalize missing values', () => {
 const row = { id: -1, userId: null, prompt: 'raw', response: null, modelUsed: null,
   createdAt: null, platformOwnerId: null };
 assert.deepEqual(canonicalRow(row), row);
 for (const field of ['userId', 'response', 'modelUsed', 'createdAt', 'platformOwnerId']) {
   const omitted = { ...row };
   delete omitted[field];
   assert.throws(() => canonicalRow(omitted), /Exact legacy AI source row required/, field);
 }
});

test('unpromotable attested row fails after every raw row is archived and before promotion or verify', async () => {
 const sourceRows = [
   { id: 1, userId: 1, prompt: 'eligible', response: 'answer', modelUsed: 'model',
     createdAt: '2026-09-15T01:02:03.123456Z', platformOwnerId: null },
   { id: 2, userId: -2, prompt: 'attested but source-null response', response: null, modelUsed: 'model',
     createdAt: '2026-09-15T01:02:04.123456Z', platformOwnerId: 88 },
   { id: 3, userId: null, prompt: 'later unknown', response: null, modelUsed: null,
     createdAt: null, platformOwnerId: -3 },
 ];
 const calls = [];
 const source = Object.freeze({ readSnapshot: async () => ({ batchId,
   sourceStoreIdentity: 'legacy://archive-before-promotion', rows: sourceRows }) });
 const attestationCapability = Object.freeze({ attest: async value => attestationEnvelope(value, [
   { sourceRowId: 1, sourceDigest: value.rows[0].sourceDigest, ownerId: 41,
     requestId: '10000000-0000-4000-8000-000000000001', sourceRoute: 'prompt_injection' },
   { sourceRowId: 2, sourceDigest: value.rows[1].sourceDigest, ownerId: 42,
     requestId: '10000000-0000-4000-8000-000000000002', sourceRoute: 'prompt_injection' },
 ]) });
 const target = Object.freeze({
   begin: async value => { calls.push(['begin', value]); return { state: 'copying' }; },
   archive: async value => calls.push(['archive', value]),
   promote: async value => calls.push(['promote', value]),
   readArchived: async () => calls.filter(([kind]) => kind === 'archive').map(([, value]) => value),
   readPromoted: async value => { calls.push(['readPromoted', value]); return null; },
   verify: async value => { calls.push(['verify', value]); return value; },
 });
 await assert.rejects(createLegacyAiHistoryDraftImporter({ sourceSnapshotCapability: source,
   ownershipAttestationCapability: attestationCapability, targetImportCapability: target }).quarantine(),
 /not eligible for application history promotion/);
 const archives = calls.filter(([kind]) => kind === 'archive').map(([, value]) => value);
 assert.deepEqual(archives.map(item => item.sourceRowId), [1, 2, 3]);
 assert.equal(archives[1].classification, 'owned');
 assert.equal(archives[1].ownerId, 42);
 assert.equal(archives[1].sourceRecord.response, null);
 assert.equal(archives[2].classification, 'unknown');
 assert.equal(archives[2].sourceRecord.prompt, 'later unknown');
 assert.equal(calls.some(([kind]) => kind === 'promote'), false);
 assert.equal(calls.some(([kind]) => kind === 'readPromoted'), false);
 assert.equal(calls.some(([kind]) => kind === 'verify'), false);
});


test('snapshot batch identity and descriptors cannot change across asynchronous capabilities', async () => {
  const originalIdentity = 'legacy://stable-snapshot';
  const supplied = { batchId, sourceStoreIdentity: originalIdentity, rows: [{ ...rows[0] }] };
  const calls = [];
  let archived;
  const source = Object.freeze({ readSnapshot: async () => supplied });
  const attestation = Object.freeze({ attest: async request => {
    assert.ok(Object.isFrozen(request.rows));
    assert.throws(() => request.rows.push({ sourceRowId: 99 }), TypeError);
    supplied.batchId = '20000000-0000-4000-8000-000000000099';
    supplied.sourceStoreIdentity = 'legacy://substituted';
    supplied.rows[0].prompt = 'changed after snapshot';
    return attestationEnvelope(request, []);
  } });
  const target = Object.freeze({
    begin: async input => { calls.push(input); return { state: 'copying' }; },
    archive: async input => { calls.push(input); archived = input; },
    promote: async () => { throw new Error('Unknown row must not promote'); },
    readArchived: async input => { calls.push(input); return [archived]; },
    readPromoted: async () => { throw new Error('Unknown row must not promote'); },
    verify: async input => { calls.push(input); return verified(input); },
  });
  await createLegacyAiHistoryDraftImporter({ sourceSnapshotCapability: source,
    ownershipAttestationCapability: attestation, targetImportCapability: target }).quarantine();
  assert.ok(calls.every(input => input.batchId === batchId));
  assert.match(calls[0].sourceStoreIdentity, /^legacy-ai-history-attestation-v1:/);
  assert.notEqual(calls[0].sourceStoreIdentity, originalIdentity);
  assert.equal(archived.sourceRecord.prompt, rows[0].prompt);
});
