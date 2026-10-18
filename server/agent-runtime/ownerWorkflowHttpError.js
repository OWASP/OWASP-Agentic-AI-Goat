'use strict';
// A failed owner run can have a deliberate, bounded HTTP response. Throwing
// preserves failed ledger status; only the outer route publishes this message.
class OwnerWorkflowHttpError extends Error {
  constructor(status, message, retryAfter) {
    if (!Number.isInteger(status) || status < 400 || status > 599
      || typeof message !== 'string' || message.length > 1000
      || (retryAfter !== undefined && (!Number.isInteger(retryAfter) || retryAfter < 1 || retryAfter > 3600))) {
      throw new TypeError('Invalid owner workflow HTTP error');
    }
    super(message);
    this.status = status;
    this.retryAfter = retryAfter;
  }
}
module.exports = { OwnerWorkflowHttpError };
