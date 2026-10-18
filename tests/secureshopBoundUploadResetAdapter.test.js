"use strict";

const test = require('node:test'),
  assert = require('node:assert/strict');
const {
  createSecureShopBoundUploadResetAdapter
} = require('../server/services/secureshopBoundUploadResetAdapter');
const {
  normalizeAdmission,
  normalizeEffect
} = require('../server/services/secureshopBoundUploadReceipt');
const id = n => `0000000${n}-0000-4000-8000-00000000000${n}`,
  operationId = id(9),
  item = {
    targetId: id(1),
    launchId: id(2),
    scenarioId: id(3),
    fromGeneration: 4,
    platformOwnerId: 5,
    platformSessionId: 6,
    targetKind: 'files'
  };
function row(outcome, retained = false, bodySha256 = 'b'.repeat(64)) {
  const a = normalizeAdmission({
    operationId: id(4),
    uploadRequestId: id(5),
    storageKey: id(6),
    scope: {
      targetId: item.targetId,
      launchId: retained ? id(7) : item.launchId,
      scenarioId: item.scenarioId,
      generation: retained ? 8 : 4,
      platformOwnerId: 5,
      platformSessionId: retained ? 99 : 6,
      sceneId: id(7),
      sceneGeneration: 1,
      grantId: id(8),
      shopUserId: 9,
      personaSessionId: id(1),
      personaAuthorityVersion: '1',
      mode: 'vuln',
      modeGeneration: 0,
      modeStamp: 'a'.repeat(64)
    },
    request: {
      kind: 'avatar',
      scopeId: 9,
      originalFilename: 'x.html',
      declaredMime: 'text/html',
      public: true,
      byteCount: 5,
      bodySha256
    }
  });
  const s = a.scope,
    r = a.request,
    buffer = x => Buffer.from(x, 'hex');
  const value = {
    operation_id: a.operationId,
    upload_request_id: a.uploadRequestId,
    admission_storage_key: a.storageKey,
    target_id: s.targetId,
    launch_id: s.launchId,
    scenario_id: s.scenarioId,
    generation: String(s.generation),
    platform_owner_id: 5,
    platform_session_id: s.platformSessionId,
    scene_id: s.sceneId,
    scene_generation: '1',
    grant_id: s.grantId,
    shop_user_id: 9,
    persona_session_id: s.personaSessionId,
    persona_authority_version: '1',
    mode: 'vuln',
    mode_generation: '0',
    mode_stamp: buffer(s.modeStamp),
    kind: 'avatar',
    scope_id: 9,
    admission_original_filename: r.originalFilename,
    admission_declared_mime: r.declaredMime,
    is_public: true,
    admission_byte_count: 5,
    admission_body_sha256: buffer(r.bodySha256),
    binding_sha256: buffer(a.bindingSha256),
    request_sha256: buffer(a.requestSha256)
  };
  if (outcome) {
    const e = normalizeEffect({
      effectId: id(8),
      outcome,
      file: outcome === 'completed' ? {
        storageKey:a.storageKey, originalFilename:a.request.originalFilename,
        cleanedFilename:'x.html', declaredMime:a.request.declaredMime, byteCount:5,
        bodySha256, baseVirtualPath:'avatars/9', resolvedVirtualPath:'avatars/9/x.html',
        storedVirtualPath:`operations/${a.storageKey}/avatars/9/x.html`, isTraversal:false
      } : null,
      denialCode: outcome === 'denied' ? 'DENIED' : null,
      quarantineRequired: outcome === 'unresolved'
    }, a);
    Object.assign(value, {
      effect_id: e.effectId,
      outcome,
      file: null,
      denial_code: e.denialCode,
      quarantine_required: e.quarantineRequired,
      effect_sha256: buffer(e.effectSha256),
      ...(e.file ? {effect_storage_key:e.file.storageKey,effect_original_filename:e.file.originalFilename,
        cleaned_filename:e.file.cleanedFilename,effect_declared_mime:e.file.declaredMime,
        effect_byte_count:e.file.byteCount,effect_body_sha256:buffer(e.file.bodySha256),
        base_virtual_path:e.file.baseVirtualPath,resolved_virtual_path:e.file.resolvedVirtualPath,
        stored_virtual_path:e.file.storedVirtualPath,is_traversal:e.file.isTraversal} : {})
    });
  }
  return value;
}
function setup(rows) {
  const calls = [];
  const pool = {
      async query(sql, args) {
        assert.match(sql, /a\.platform_owner_id/);
        assert.doesNotMatch(sql, /original_platform_owner_id/);
        assert.equal(args[0], item.targetId);
        return {
          rows
        };
      }
    },
    storage = {
      async reconcile() {
        calls.push('quarantine');
        return {
          action: 'quarantined',
          receiptSha256: 'c'.repeat(64)
        };
      },
      async verifyReconciliation() {
        calls.push('verify');
      },
      async removeCompleted() {
        calls.push('delete');
      }
    },
    journal = {
      async reconcile(a, e, r, opts) {
        assert.equal(opts.cleanupOperationId, operationId);
        calls.push('reconcile');
      },
      async reconcileOrphan(a, r, opts) {
        assert.equal(opts.cleanupOperationId, operationId);
        calls.push('orphan');
      },
      async recordCleanup(r) {
        calls.push('record');
        assert.equal(r.quarantinedCount, rows.length);
      }
    },
    fileCleanup = {
      async cleanup() {
        calls.push('files');
        return {
          receiptSha256: 'd'.repeat(64)
        };
      }
    },
    cleanupAuthority = {
      async checkTarget(v) {
        assert.equal(v.operationId, operationId);
        calls.push('authority');
        return {
          status: 'fenced'
        };
      }
    };
  return {
    calls,
    storage,
    journal,
    adapter: createSecureShopBoundUploadResetAdapter({
      pool,
      storage,
      journal,
      fileCleanup,
      cleanupAuthority
    })
  };
}
for (const outcome of [null, 'unresolved']) test(`${outcome || 'orphan'} storage quarantine precedes immutable reconciliation and target cleanup`, async () => {
  const x = setup([row(outcome)]);
  await x.adapter.cleanup(item, {
    operationId
  });
  assert.deepEqual(x.calls.filter(v => v !== 'authority'), ['quarantine', outcome ? 'reconcile' : 'orphan', 'files', 'record']);
});
test('immutable journal failure prevents target cleanup; retry can recover quarantined storage', async () => {
  const x = setup([row()]);
  x.journal.reconcileOrphan = async () => {
    throw Error('lost ACK');
  };
  await assert.rejects(x.adapter.cleanup(item, {
    operationId
  }), /lost ACK/);
  assert.ok(!x.calls.includes('files'));
});
test('existing reconciliation is physically verified before cleanup', async () => {
  const r = row();
  r.reconciliation_action = 'quarantined';
  r.reconciliation_receipt_sha256 = Buffer.from('c'.repeat(64), 'hex');
  const x = setup([r]);
  await x.adapter.cleanup(item, {
    operationId
  });
  assert.deepEqual(x.calls.filter(v => v !== 'authority'), ['verify', 'files', 'record']);
});
test('foreign scope or corrupted immutable digest fails before any storage effect', async () => {
  for (const field of ['platform_owner_id', 'binding_sha256']) {
    const r = row();
    r[field] = field === 'platform_owner_id' ? 10 : Buffer.alloc(32);
    const x = setup([r]);
    await assert.rejects(x.adapter.cleanup(item, {
      operationId
    }));
    assert.deepEqual(x.calls, ['authority']);
  }
});
test('retained scene reconciles execution digests under target birth authority and records birth cleanup', async () => {
  const r = row(null, true),
    x = setup([r]);
  let reconciled = false,
    recorded = false;
  x.journal.reconcileOrphan = async (a, receipt, opts) => {
    reconciled = true;
    assert.equal(a.scope.launchId, id(7));
    assert.equal(a.scope.generation, 8);
    assert.equal(a.scope.platformSessionId, 99);
    assert.equal(a.bindingSha256, r.binding_sha256.toString('hex'));
    assert.equal(opts.cleanupScope.launchId, item.launchId);
    assert.equal(opts.cleanupScope.generation, item.fromGeneration);
    assert.equal(opts.cleanupScope.platformSessionId, item.platformSessionId);
  };
  x.journal.recordCleanup = async receipt => {
    recorded = true;
    assert.equal(receipt.scope.launchId, item.launchId);
    assert.equal(receipt.scope.generation, item.fromGeneration);
    assert.equal(receipt.scope.platformSessionId, item.platformSessionId);
  };
  await x.adapter.cleanup(item, {
    operationId
  });
  assert.ok(reconciled && recorded);
});
test('no upload admission retains ordinary owned-file cleanup', async () => {
  const x = setup([]);
  await x.adapter.cleanup(item, {
    operationId
  });
  assert.deepEqual(x.calls.filter(v => v !== 'authority'), ['files']);
});


test('actual product reset dispatch removes owned upload without a reserved file target and preserves sibling and originals', async t => {
  const fs=require('node:fs/promises'),path=require('node:path'),os=require('node:os');
  const {createHash}=require('node:crypto');
  const {createSecureShopReviewResetCoordinator}=require('../server/services/secureshopReviewResetCoordinator');
  const {createSecureShopUploadStorageLifecycle}=require('../server/services/secureshopUploadStorageLifecycle');
  const root=await fs.mkdtemp(path.join(await fs.realpath(os.tmpdir()),'product-upload-reset-'));
  t.after(()=>fs.rm(root,{recursive:true,force:true}));
  const bytes=Buffer.from('owned'),sha=createHash('sha256').update(bytes).digest('hex');
  const original=row('completed',true,sha),before=JSON.stringify(original),events=[];
  const file=path.join(root,original.stored_virtual_path),sibling=path.join(root,'operations',id(9),'sentinel');
  for(const value of [file,sibling]){await fs.mkdir(path.dirname(value),{recursive:true,mode:0o700});await fs.writeFile(value,bytes,{mode:0o600});}
  const productItem={...item,targetKind:'products'},receipt={receiptSha256:'d'.repeat(64)};
  let recorded,retired=false,recordFailure=true;
  const authority={
    async checkTarget(value){assert.equal(value.targetKind,'products');assert.equal(value.fromGeneration,4);
      assert.equal(value.targetId,item.targetId);assert.equal(value.operationId,operationId);return{status:'fenced'};},
    async listTargets(){return{resetId:operationId,targets:[productItem]};},
    async assertResolved(){return{status:'fenced'};},async finalizeReconciliation(){events.push('finalize');}
  };
  const cleanup=createSecureShopBoundUploadResetAdapter({targetKind:'products',cleanupAuthority:authority,
    pool:{async query(sql,args){assert.deepEqual(args,[item.targetId]);return{rows:[original]};}},
    storage:createSecureShopUploadStorageLifecycle({root}),
    fileCleanup:{async cleanup(binding,options){assert.equal(binding.generation,4);assert.equal(binding.fromGeneration,undefined);
      assert.equal(options.operationId,operationId);await assert.rejects(fs.stat(file),{code:'ENOENT'});
      events.push('products');retired=true;return receipt;}},
    journal:{async reconcile(){assert.fail('completed upload must not rewrite reconciliation');},async reconcileOrphan(){assert.fail('completed upload is not orphan');},
      async recordCleanup(value){assert.ok(retired);assert.equal(value.scope.generation,4);assert.equal(value.scope.launchId,item.launchId);
        assert.equal(value.scope.platformSessionId,6);assert.equal(value.deletedCount,1);assert.equal(value.quarantinedCount,0);
        assert.equal(value.receiptSha256,createHash('sha256').update(JSON.stringify(['bound-upload-target-cleanup-v2',operationId,item.targetId,receipt.receiptSha256,1,0])).digest('hex'));
        if(recordFailure)throw Error('cleanup receipt unavailable');
        if(recorded)assert.deepEqual(value,recorded);recorded=value;events.push('upload receipt');}}
  });
  const coordinator=createSecureShopReviewResetCoordinator({launches:{async beginReset(){},async commitReset(){}},cleanupAuthority:authority,
    reviewRepository:{async cleanup(){assert.fail('not a review target');}},
    fileCleanup:{async cleanup(){assert.fail('no reserved filesystem target exists');}},productCleanup:cleanup,
    reconciler:{async reconcile(){assert.ok(recorded);events.push('reconcile');return{history:receipt};}}});
  await assert.rejects(coordinator.recover(operationId),/cleanup receipt unavailable/);
  assert.deepEqual(events,['products']);recordFailure=false;
  await coordinator.recover(operationId);await coordinator.recover(operationId);
  assert.deepEqual(events,['products','products','upload receipt','reconcile','finalize','products','upload receipt','reconcile','finalize']);
  await assert.rejects(fs.stat(file),{code:'ENOENT'});assert.deepEqual(await fs.readFile(sibling),bytes);
  assert.equal(JSON.stringify(original),before);
  await assert.rejects(cleanup.cleanup({...productItem,generation:4,targetKind:'files'},{operationId}),{code:'BOUND_UPLOAD_MISMATCH'});
  await assert.rejects(cleanup.cleanup({...productItem,generation:5},{operationId}),{code:'BOUND_UPLOAD_MISMATCH'});
});

test('product target without uploads preserves ordinary cleanup without touching storage',async()=>{
  const events=[],receipt={receiptSha256:'d'.repeat(64)};
  const unexpected=async()=>assert.fail('no upload storage or journal effect');
  const adapter=createSecureShopBoundUploadResetAdapter({targetKind:'products',
    pool:{async query(){return{rows:[]};}},cleanupAuthority:{async checkTarget(value){assert.equal(value.targetKind,'products');assert.equal(value.fromGeneration,4);return{status:'fenced'};}},
    fileCleanup:{async cleanup(){events.push('products');return receipt;}},
    journal:{recordCleanup:unexpected,reconcile:unexpected,reconcileOrphan:unexpected},
    storage:{reconcile:unexpected,verifyReconciliation:unexpected,removeCompleted:unexpected}});
  assert.equal(await adapter.cleanup({...item,targetKind:'products',generation:4},{operationId}),receipt);
  assert.deepEqual(events,['products']);
});
