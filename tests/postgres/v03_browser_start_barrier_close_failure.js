'use strict';
// Offline failure injection only. MAIN never imports this module.
const fs = require('node:fs');
const original = fs.closeSync;
const target = Number(process.env.SECURESHOP_V03_PRIVATE_START_FD);
fs.closeSync = function injectedClose(fd) {
  if (fd === target) {
    throw new Error('CONTROLLED_CLOSE_FAILURE');
  }
  return original(fd);
};
