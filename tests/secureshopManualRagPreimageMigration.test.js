'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const {createHash}=require('node:crypto');
const directory=path.join(__dirname,'../db/postgres/workshop-migrations/secureshop_review');
const prior=fs.readFileSync(path.join(directory,'0014_product_embedding_revisions.sql'),'utf8');
const next=fs.readFileSync(path.join(directory,'0050_product_embedding_revision_preimages.sql'),'utf8');
function body(sql){return sql.slice(sql.indexOf('FUNCTION secureshop_review.publish_product_embedding_revision(')).split('AS $$')[1].split('$$;')[0];}
test('forward publisher preserves every prior admission CAS and replay statement byte-for-byte',()=>{
 const old=body(prior),updated=body(next);
 const start=updated.indexOf(' -- Capture original canonical input, never float8[] reserialization.');
 const end=updated.indexOf(' INSERT INTO secureshop_review.product_target_embedding_heads',start);
 assert.ok(start>updated.indexOf('INSERT INTO secureshop_review.product_target_embedding_vectors'));
 assert.equal(updated.slice(0,start)+updated.slice(end),old);
 const expected=createHash('sha256').update(old).digest('hex');
 assert.ok(next.includes(`AND encode(sha256(convert_to(prosrc,'UTF8')),'hex')='${expected}'`));
 assert.ok(updated.indexOf('IF FOUND THEN')<start,'old replay returns before capture, never backfills');
 assert.match(updated.slice(start,end),/FROM jsonb_array_elements\(documents\)/);
 assert.doesNotMatch(updated.slice(start,end),/to_jsonb\(.*embedding/);
});
test('preimage writes remain privileged and payload retirement uses existing canonical privacy receipt',()=>{
 assert.match(next,/REVOKE ALL ON TABLE secureshop_review.product_target_embedding_preimages,secureshop_review.product_target_manual_preimages FROM PUBLIC,dvaia_secureshop_review_runtime/);
 assert.doesNotMatch(next,/GRANT\s+(?:ALL|INSERT|UPDATE|DELETE)[^;]*product_target_(?:embedding|manual)_preimages/i);
 for(const table of ['embedding','manual'])assert.match(next,new RegExp(`BEFORE UPDATE OR DELETE ON secureshop_review.product_target_${table}_preimages`));
 assert.match(next,/current_user='dvaia_secureshop_review_migration'/);
 assert.match(next,/JOIN secureshop_review.product_target_embedding_cleanup_receipts c USING\(target_id\)/);
 assert.match(next,/PERFORM secureshop_review.cleanup_retired_product_embeddings\(NEW.target_id\);/);
 assert.match(next,/DELETE FROM secureshop_review.product_target_embedding_preimages WHERE target_id=NEW.target_id/);
 assert.match(next,/DELETE FROM secureshop_review.product_target_manual_preimages WHERE target_id=NEW.target_id/);
 assert.doesNotMatch(next,/DELETE FROM secureshop_review.product_target_(?:manual_ingests|embedding_revisions)\b/);
});
test('manual snapshot capture is exact fresh-transaction-only and verifies receipt/runtime/chunk preimages',()=>{
 const capture=next.slice(next.indexOf('CREATE FUNCTION secureshop_review.capture_product_manual_preimage'));
 assert.match(capture,/original_xid IS DISTINCT FROM pg_current_xact_id\(\)::text::xid/);
 assert.match(capture,/original.document_digest<>sha256\(convert_to\(chunks::text,'UTF8'\)\)/);
 assert.match(capture,/product_manual_scene_receipt_digest\(original\)/);
 assert.match(capture,/manual_runtime_receipt_digest\(/);
 assert.match(capture,/d.source_sha256=sha256\(convert_to\(jsonb_build_object/);
 assert.match(capture,/matched_count<>original.document_count/);
 assert.match(capture,/VALUES\(requested_operation,requested_target,chunks::text\) ON CONFLICT DO NOTHING/);
 assert.match(capture,/REVOKE ALL ON FUNCTION secureshop_review.capture_product_manual_preimage\(uuid,uuid,jsonb\) FROM PUBLIC,dvaia_secureshop_review_runtime/);
 assert.match(capture,/GRANT EXECUTE ON FUNCTION secureshop_review.capture_product_manual_preimage\(uuid,uuid,jsonb\) TO dvaia_secureshop_review_runtime/);
});
