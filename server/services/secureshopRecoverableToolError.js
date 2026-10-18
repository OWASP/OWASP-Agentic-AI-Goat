'use strict';

const RECOVERABLE_CODES = new Set(['INVALID_TOOL_ARGUMENTS', 'INVALID_TOOL_SELECTION']);

// Each admitted external tool pool owns one classifier. Recoverability is
// object identity held only in this closure; public error codes, messages and
// remote result fields cannot opt an error into model feedback.
function createPrivateRecoverableToolErrorClassifier() {
  const errors = new WeakMap();
  return Object.freeze({
    brand(error, code) {
      if (!(error instanceof Error) || !RECOVERABLE_CODES.has(code)) {
        throw new TypeError('Invalid recoverable tool error classification');
      }
      errors.set(error, code);
      return error;
    },
    project(error) {
      return error && typeof error === 'object' ? errors.get(error) || null : null;
    },
  });
}

module.exports = { createPrivateRecoverableToolErrorClassifier };
