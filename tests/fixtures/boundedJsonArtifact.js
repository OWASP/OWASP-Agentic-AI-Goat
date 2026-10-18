'use strict';

// Standalone copy of the bounded writer used by historical diagnostic fixtures.
// Keep this module import-inert: artifact persistence must not load agent runtimes.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const ARTIFACT_BYTES = 256 * 1024 * 1024;

function saveBounded(file, value) {
  const fd = fs.openSync(file + '.tmp', 'w', 0o600);
  let bytes = 0;
  function emit(text) {
    bytes += Buffer.byteLength(text);
    assert(bytes <= ARTIFACT_BYTES, 'Evidence artifact byte ceiling');
    const chunk = Buffer.from(text);
    let offset = 0;
    while (offset < chunk.length) {
      const wrote = fs.writeSync(fd, chunk, offset, chunk.length - offset);
      assert(wrote > 0);
      offset += wrote;
    }
  }
  function visit(item) {
    if (item === null || typeof item !== 'object') {
      emit(JSON.stringify(item));
      return;
    }
    // Use the native internal-slot check, including cross-realm Dates. Never
    // invoke caller-supplied toJSON methods while persisting evidence.
    let timestamp;
    try { timestamp = Date.prototype.getTime.call(item); } catch { /* not a Date */ }
    if (timestamp !== undefined) {
      assert(Number.isFinite(timestamp), 'Invalid Date in evidence artifact');
      emit(JSON.stringify(Date.prototype.toISOString.call(item)));
      return;
    }
    if (Array.isArray(item)) {
      emit('[');
      item.forEach((entry, index) => {
        if (index) emit(',');
        visit(entry);
      });
      emit(']');
      return;
    }
    emit('{');
    Object.entries(item).forEach(([key, entry], index) => {
      if (index) emit(',');
      emit(JSON.stringify(key) + ':');
      visit(entry);
    });
    emit('}');
  }
  try {
    visit(value);
    emit('\n');
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  fs.renameSync(file + '.tmp', file);
}

module.exports = { ARTIFACT_BYTES, saveBounded };
