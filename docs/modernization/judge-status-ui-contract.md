# Objective Judge feedback and retry contract

Workshop adapters return a `judgment` or a `judgments` array. The shared `getJudgeFeedback` utility accepts both shapes. Preserve each adapter's existing response envelope; do not infer success from assistant text or introduce a competing client completion counter.

A representative unavailable result is:

```json
{
  "judgment": {
    "objectiveId": "server-owned-objective-id",
    "rubricVersion": "versioned-rubric",
    "verdict": "unavailable",
    "explanation": "Objective evaluation is temporarily unavailable; no completion was awarded.",
    "errorCode": "JUDGE_TIMEOUT",
    "evaluationId": "opaque-evaluation-id",
    "canRetry": true
  }
}
```

`verdict` is `pass`, `fail`, `inconclusive`, or `unavailable`. A model pass alone does not mean completion: receipt acceptance, objective visibility, owner/reset/mode fences and any practice threshold still apply. Green objectives and counters come from the authoritative progress response. Shared feedback renders non-pass outcomes near the relevant attempt; the run inspector retains detailed grading metadata.

## Failure and recovery behavior

Only fixed public error categories are exposed. Queue, timeout, provider transport and storage configuration failures have actionable messages; raw exceptions, SQL, endpoints and credentials must never become diagnostic copy. An unknown category cannot become an arbitrary public error message.

The retry button requires all three: an unavailable verdict, a nonempty evaluation ID and server `canRetry: true`. Initial responses, receipt replays and the owner recovery list use the same retryable-error policy. Context-limit and oversized-evidence outcomes cannot be repaired by rerunning the same packet. Transient failures can qualify, subject to retained evidence, expiry, ownership, mode, generation and retry limits.

`POST /api/agent-runs/judgments/:evaluationId/retry` accepts an empty object. It regrades retained evidence without replaying the learner's action or its tools. After a retry, refresh canonical progress. `GET /api/agent-runs/judgments` lets the owner recover eligible evaluations after refresh or a lost response. The repository rechecks eligibility even when an earlier response advertised retry.

## Scenario and request ownership

Keep feedback attached to the objective and scenario that submitted the request. A late response must not attach to a newly selected objective. Reset/unmount cancels pending UI requests and invalidates callbacks; resetting an IPI scenario must preserve sibling scenario state. DPI uses one scenario with multiple objectives; IPI uses independent scenario state.

RAG feedback remains visible when grading returns a result but retrieval produced zero chunks. The shared retry control remains usable under React StrictMode effect replay. DPI Enter submission ignores active IME composition.

## Verification

Focused tests cover non-pass normalization, fixed diagnostics, retry visibility, retained-evidence retry requests, progress refresh and stale-request ownership. Production-bundle browser checks cover DPI/IPI at four widths, scenario switching, keyboard focus and reset behavior using injected API responses. These UI checks do not claim a live database/model integration or screen-reader certification; see the separate Judge verification report for connected workflow evidence.

## Secondary progress projections

An accepted canonical receipt remains authoritative if an exercise's secondary progress table cannot be updated. MCP, XSS, Email, Excessive Agency and CSRF grading responses report affected IDs in `projectionPending`; CSRF also includes it on grading events. MCP/XSS progress reads retain canonical results and report `projectionUnavailable: true` when a secondary read fails, without inventing missing objective IDs. This condition must not ask the learner to repeat a mutating exercise action. PostgreSQL progress views and CSRF prerequisites read enabled canonical completion records. They do not write secondary rows during GET requests, so stale rows cannot restore progress after reset.

Email and Excessive Agency progress, including Excessive Agency chat responses, also read canonical completion. Its five-objective reset preserves the RAG scenario. Legacy/non-durable grading must establish canonical acceptance before reporting completion; a missing or unavailable canonical record cannot be converted into successful credit by projection-error handling.
