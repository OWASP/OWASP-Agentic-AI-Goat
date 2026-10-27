'use strict';

// Read one bounded, inherited launcher grant and retire its descriptor before
// the fixture can create a child process or open a browser.
const assert = require('node:assert/strict');
const fs = require('node:fs');

async function readInheritedFifoGrant(env, key, label) {
  assert(/^(0|[1-9]\d*)$/.test(env[key] || '')
    && Number.isSafeInteger(Number(env[key])) && Number(env[key]) > 2,
  `${label} inherited admission pipe required`);
  const descriptor = Number(env[key]);
  const stat = fs.fstatSync(descriptor);
  assert(stat.isFIFO(), `${label} admission must be an inherited pipe`);
  assert.equal(stat.uid, process.getuid(), `${label} admission pipe owner mismatch`);
  // The stream owns the inherited FIFO descriptor once constructed. Node
  // closes it on end/destroy; a second closeSync can race that close.
  const stream = fs.createReadStream('/dev/null', { fd: descriptor, autoClose: true });
  const chunks = [];
  let size = 0;
  let timer;
  let primaryError;
  try {
    const bytes = await new Promise((resolve, reject) => {
      timer = setTimeout(() => { stream.destroy(); reject(new Error(`${label} admission pipe timed out`)); }, 10000);
      stream.on('data', chunk => {
        size += chunk.length;
        if (size > 8192) {
          stream.destroy();
          reject(new Error(`${label} admission pipe exceeded bound`));
        } else chunks.push(chunk);
      });
      stream.once('error', reject);
      stream.once('end', () => resolve(Buffer.concat(chunks)));
    });
    return JSON.parse(bytes.toString('utf8'));
  } catch (error) {
    primaryError = error;
    throw error;
  } finally {
    clearTimeout(timer);
    let closeError;
    try {
      if (!stream.closed) await new Promise(resolve => {
        const onError = error => { closeError ||= error; };
        stream.on('error', onError);
        stream.once('close', () => { stream.off('error', onError); resolve(); });
        stream.destroy();
      });
    } catch (error) { closeError ||= error; }
    finally {
      delete env[key];
      delete process.env[key];
    }
    if (closeError && !primaryError) throw closeError;
  }
}

module.exports = { readInheritedFifoGrant };
