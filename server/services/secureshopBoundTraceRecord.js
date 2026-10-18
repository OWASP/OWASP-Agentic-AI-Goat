'use strict';

// One projection for persistence and private grading evidence. Unknown metadata
// must not become purported stored proof merely because it was on an input row.
const BOUND_TRACE_COLUMNS = Object.freeze(['event_id', 'session_id', 'step', 'actor', 'kind',
  'agent_ns', 'tool_name', 'params_json', 'result_json', 'latency_ms', 'tokens_in',
  'tokens_out', 'provider', 'policy_violation']);
function snapshotBoundTraceRows(rows) {
  return Object.freeze(rows.map(row => Object.freeze(Object.fromEntries(
    BOUND_TRACE_COLUMNS.map(column => [column, row[column] ?? null])
  ))));
}
module.exports = { BOUND_TRACE_COLUMNS, snapshotBoundTraceRows };
