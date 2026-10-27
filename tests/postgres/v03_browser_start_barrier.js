'use strict';

// Loaded with Node --require before the original V03 test module. The owner
// releases one byte only after the private parent has acknowledged the exact
// spawned browser worker. No fixture code or HTTP request runs before this.
const fs = require('node:fs');
const {randomBytes} = require('node:crypto');
const key = 'SECURESHOP_V03_PRIVATE_START_FD';
const raw = process.env[key];
delete process.env[key];
const marker = 'SECURESHOP_V03_PRIVATE_START_GRANTED';
const inherited = process.env[marker];
if (raw === undefined && inherited !== undefined) {
  // Node's --test worker replays --require. It may inherit only this marker
  // from the already released parent process, never the original pipe FD.
  if (process.env.NODE_TEST_CONTEXT !== 'child-v8' ||
      !/^[0-9]+:[a-f0-9]{64}$/.test(inherited) ||
      Number(inherited.split(':', 1)[0]) !== process.ppid) {
    throw new Error('V03_PRIVATE_START_BARRIER_DENIED');
  }
  delete process.env[marker];
} else {
  const fd = Number(raw);
  if (inherited !== undefined || !/^[0-9]+$/.test(raw || '') ||
      !Number.isSafeInteger(fd) || fd < 5) {
    throw new Error('V03_PRIVATE_START_BARRIER_DENIED');
  }
  let admitted = false;
  try {
    if (!fs.fstatSync(fd).isFIFO()) throw new Error('V03_PRIVATE_START_BARRIER_DENIED');
    const byte = Buffer.alloc(1);
    admitted = fs.readSync(fd, byte, 0, 1, null) === 1 && byte[0] === 0x47 &&
      fs.readSync(fd, byte, 0, 1, null) === 0;
  } catch (_) {
    admitted = false;
  } finally {
    try { fs.closeSync(fd); } catch (_) { admitted = false; }
  }
  if (!admitted) throw new Error('V03_PRIVATE_START_BARRIER_DENIED');
  process.env[marker] = `${process.pid}:${randomBytes(32).toString('hex')}`;
}
