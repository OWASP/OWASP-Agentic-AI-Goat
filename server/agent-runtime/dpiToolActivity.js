'use strict';

// Only the owned decoder records failures here. Error messages and private
// grading proofs are never used as a public tool-event source.
const failures = new WeakMap();

function projectToolActivity(entries) {
  if (!Array.isArray(entries)) return [];
  return entries.filter(entry => entry && entry.name === 'decode_payload'
    && typeof entry.id === 'string' && /^dpi_decode_[a-f0-9]{32}$/.test(entry.id)
    && ['success', 'error'].includes(entry.status)
    && typeof entry.timestamp === 'string' && Number.isFinite(Date.parse(entry.timestamp)))
    .map(entry => ({
      id: entry.id, name: 'decode_payload', arguments: {}, status: entry.status,
      timestamp: entry.timestamp,
      ...(entry.status === 'success' && typeof entry.result?.encoding === 'string'
        && typeof entry.result?.decodedRequest === 'string'
        ? { result: { encoding: entry.result.encoding, decodedRequest: entry.result.decodedRequest } }
        : {}),
      ...(entry.status === 'error' ? { error: 'The payload could not be decoded.' } : {}),
    }));
}

function recordToolActivityFailure(error, entries) {
  if (error && typeof error === 'object' && entries.length) {
    failures.set(error, projectToolActivity(entries));
  }
}

function readToolActivityFailure(error) {
  return projectToolActivity(error && typeof error === 'object' ? failures.get(error) : []);
}

module.exports = { projectToolActivity, recordToolActivityFailure, readToolActivityFailure };
