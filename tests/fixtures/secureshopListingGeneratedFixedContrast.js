'use strict';

const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');

const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const sha = value => createHash('sha256').update(value).digest('hex');
const escapeHtml = value => value.replace(/&/g, '&amp;').replace(/</g, '&lt;')
  .replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
const after = (left, right) => {
  try { return BigInt(right?.id) > BigInt(left?.id); } catch { return false; }
};

// This is an assertion over producer evidence, not a provider or browser substitute.
function assertFixedGeneratedContrast({ source, modelTurn, modelTrace, rewrite, save,
  savedRow, generated, attempted, productView, countersBefore, countersAfter }) {
  assert.equal(typeof source?.title, 'string');
  assert.equal(typeof source?.description, 'string');
  assert.equal(modelTurn?.status, 'completed');
  assert.equal(modelTurn?.purpose, 'secureshop_listing_rewrite');
  assert.equal(modelTurn?.stopReason, 'end_turn');
  assert.equal(typeof modelTurn?.text, 'string');
  assert.ok(modelTurn.text.includes('onerror') && modelTurn.text.includes('alert(1)'),
    'the actual fixed model must generate the same bounded teaching markup');
  const decision = modelTrace?.find(row => row.kind === 'model_decision'
    && row.provider === 'ollama' && row.model === 'llama3.1:8b'
    && row.mocked === false && row.fallback !== true && row.decision === 'final'
    && row.stopReason === 'end_turn' && row.text === modelTurn.text);
  assert.ok(decision, 'the saved rewrite must retain its exact qualified final model decision');
  assert.ok(modelTrace?.some(row => row.kind === 'terminal'
    && row.provider === 'ollama' && row.model === 'llama3.1:8b'
    && row.mocked === false && row.fallback !== true && row.stopReason === 'end_turn'
    && after(decision, row)), 'the final decision requires a later qualified terminal trace');
  assert.equal(rewrite?.state, 'completed');
  assert.match(rewrite.operationId, UUID);
  assert.equal(rewrite.html, escapeHtml(modelTurn.text),
    'fixed source is exactly the genuine model output with the production escaping');
  assert.equal(rewrite.html.includes('<img'), false);
  assert.equal(save?.state, 'completed');
  assert.match(save.saveOperationId, UUID);
  assert.equal(save.rewriteOperationId, rewrite.operationId);
  assert.ok(Number.isSafeInteger(save.productId) && save.productId > 0);
  assert.equal(savedRow?.save_operation_id, save.saveOperationId);
  assert.equal(savedRow?.rewrite_operation_id, rewrite.operationId);
  assert.equal(savedRow?.product_id, save.productId);
  assert.equal(generated?.product_id, save.productId);
  assert.equal(generated?.rewrite_operation_id, rewrite.operationId);
  assert.equal(generated?.source_sha256, sha(JSON.stringify([source.title, source.description])));
  assert.equal(generated?.html_sha256, sha(rewrite.html));
  assert.equal(attempted?.completed, false);
  assert.equal(attempted?.status, 'ineligible');
  assert.equal(attempted?.modelEvaluated, false);
  assert.equal(productView?.productId, save.productId);
  assert.equal(productView?.heading, source.title);
  assert.equal(productView?.text, modelTurn.text);
  assert.equal(typeof productView?.html, 'string');
  assert.ok(productView.html.includes('&lt;img') && !productView.html.includes('<img'),
    'the physical Product view must contain text rather than an event-bearing element');
  assert.equal(productView?.childElementCount, 0);
  assert.equal(productView?.eventImages, 0);
  assert.equal(productView?.dialogs, 0);
  assert.deepEqual(countersAfter, countersBefore,
    'fixed rendering and ineligible assessment must not add Judge, credit, or browser effect');
  return true;
}

module.exports = { assertFixedGeneratedContrast };
