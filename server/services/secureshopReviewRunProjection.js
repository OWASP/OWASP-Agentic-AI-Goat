'use strict';

// Compatibility projection for a single server-returned bound graph run.
// This is presentation data, never grading evidence or an authority check.
function projectBoundReviewModeration(run) {
  if (!run || !Array.isArray(run.hops)) throw new TypeError('Bound graph run required');
  const decisions = [];
  for (const hop of run.hops) {
    const decision = hop.tool === 'review-moderator.approve' ? 'approve'
      : hop.tool === 'review-moderator.reject' ? 'reject' : null;
    if (!decision || hop.error || hop.result?.isError) continue;
    const content = hop.result?.content;
    if (!Array.isArray(content) || content.length !== 1 || content[0]?.type !== 'text') continue;
    let outcome;
    try { outcome = JSON.parse(content[0].text); } catch { continue; }
    // Never infer an applied decision from assistant text, an observation body,
    // or another tool's result. Only exact successful bound moderation output
    // enters the legacy decisions list.
    const row = outcome?.review;
    if (outcome?.ok !== true || outcome.applied !== true || !row
        || !Number.isSafeInteger(row.id) || row.id < 1 || row.id !== hop.params?.review_id
        || !Number.isSafeInteger(row.product_id) || row.product_id < 1
        || row.status !== (decision === 'approve' ? 'approved' : 'rejected')
        || row.moderator_kind !== 'auto') continue;
    decisions.push(Object.freeze({ review_id: row.id, product_id: row.product_id,
      applied_decision: decision, notes: row.moderator_notes ?? null,
      applied: Object.freeze({ ok: true, review_id: row.id }) }));
  }
  const legacy = run.taskMetadata === undefined;
  let batch;
  if (!legacy) {
    const value = run.taskMetadata?.reviewBatch;
    if (!value || value.contract !== 'bound-review-batch-v1'
        || typeof value.runId !== 'string' || !value.runId
        || !Number.isInteger(value.requested) || value.requested < 1 || value.requested > 100
        || !Number.isInteger(value.considered) || value.considered < 0 || value.considered > value.requested
        || typeof value.complete !== 'boolean' || typeof value.continuationRequired !== 'boolean'
        || (value.continuationRequired && !value.complete)) {
      throw new TypeError('Invalid bound review batch metadata');
    }
    batch = Object.freeze({ requested: value.requested, considered: value.considered,
      complete: value.complete, continuationRequired: value.continuationRequired });
  }
  return Object.freeze({ ok: run.stopReason === 'end_turn' && (legacy || batch.complete), processed: decisions.length,
    decisions: Object.freeze(decisions), stopReason: run.stopReason ?? 'unknown',
    replayed: run.replayed === true, ...(legacy ? {} : { batch }),
    ...(run.modeCapability === undefined ? {} : { modeCapability: run.modeCapability }) });
}

module.exports = { projectBoundReviewModeration };
