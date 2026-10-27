'use strict';
// No raw stderr, URLs, command lines, environment or exception messages escape.
const crypto = require('node:crypto');
function observeEarlyBrowser(browser) {
  const child = browser.process(), chunks = [];
  let bytes = 0, truncated = false, disconnected = false, detached = false;
  let exitCode = Number.isInteger(child?.exitCode) ? child.exitCode : null;
  let signal = null, stage = 'acknowledge';
  const signals = new Set(['SIGABRT', 'SIGBUS', 'SIGILL', 'SIGKILL', 'SIGSEGV', 'SIGTERM']);
  const data = value => {
    if (!Buffer.isBuffer(value)) return;
    const take = Math.min(value.length, 8192 - bytes);
    if (take) { chunks.push(Buffer.from(value.subarray(0, take))); bytes += take; }
    if (take < value.length) truncated = true;
  };
  const exit = (code, name) => { exitCode = Number.isInteger(code) ? code : null; signal = signals.has(name) ? name : name == null ? null : 'other'; };
  const disconnect = () => { disconnected = true; };
  child?.stderr?.on('data', data); child?.on('exit', exit); browser.on('disconnected', disconnect);
  function detach() {
    if (detached) return; detached = true;
    child?.stderr?.removeListener('data', data); child?.removeListener('exit', exit); browser.off('disconnected', disconnect);
  }
  return Object.freeze({
    stage(value) { if (['acknowledge', 'new-page', 'viewport', 'ready'].includes(value)) stage = value; },
    detach,
    snapshot() {
      const raw = Buffer.concat(chunks), text = raw.toString('utf8');
      return { stage, exitCode, signal, disconnected, stderrBytesCaptured: bytes, stderrTruncated: truncated,
        stderrSha256: crypto.createHash('sha256').update(raw).digest('hex'),
        stderrCategories: ['sandbox', 'zygote', 'crashpad', 'dbus', 'segmentation fault'].filter(word => text.toLowerCase().includes(word)) };
    }
  });
}
module.exports = { observeEarlyBrowser };
