'use strict';
// Stable, public categories only. Never persist an exception message, SQL text,
// provider response body, endpoint or credentials in a grading receipt.
const RETRYABLE_CODES = Object.freeze(['JUDGE_TIMEOUT','JUDGE_UNAVAILABLE','INVALID_JUDGE_OUTPUT',
  'JUDGE_STORAGE_CONSTRAINT','JUDGE_STORAGE_SCHEMA','JUDGE_STORAGE_PERMISSION','JUDGE_TRANSPORT','JUDGE_QUEUE_FULL']);
const ERROR_CODES = Object.freeze([...RETRYABLE_CODES,'INVALID_OR_OVERSIZED_EVIDENCE','JUDGE_CONTEXT_LIMIT',
  'SEMANTIC_COVERAGE_UNAVAILABLE','SEMANTIC_EFFECT_UNAVAILABLE','REQUIRED_FACTS_NOT_SATISFIED','LISTINGS_EVIDENCE_VERSION_UNSUPPORTED','LISTINGS_EVIDENCE_INCONSISTENT','CSRF_RECON_VERSION_UNSUPPORTED','CSRF_RECON_HISTORY_INVALID','MCP_DESCRIPTION_CAUSAL_FINDING_CONTRADICTION']);
function judgeFailureCode(cause, {timedOut = false} = {}) {
  if (cause?.code === 'AI_QUEUE_FULL') return 'JUDGE_QUEUE_FULL';
  if (timedOut || cause?.name === 'TimeoutError' || ['ETIMEDOUT','UND_ERR_CONNECT_TIMEOUT','UND_ERR_HEADERS_TIMEOUT'].includes(cause?.code)) return 'JUDGE_TIMEOUT';
  if (cause?.code === '23514') return 'JUDGE_STORAGE_CONSTRAINT';
  if (['42P01','42703'].includes(cause?.code)) return 'JUDGE_STORAGE_SCHEMA';
  if (cause?.code === '42501') return 'JUDGE_STORAGE_PERMISSION';
  if (['ECONNREFUSED','ECONNRESET','ENOTFOUND','EAI_AGAIN','UND_ERR_SOCKET'].includes(cause?.code)) return 'JUDGE_TRANSPORT';
  return 'JUDGE_UNAVAILABLE';
}
function canRetryJudgeError(code) { return code == null || RETRYABLE_CODES.includes(code); }
module.exports = {ERROR_CODES, judgeFailureCode, canRetryJudgeError};
