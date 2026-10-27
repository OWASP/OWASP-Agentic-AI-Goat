'use strict';
const test = require('node:test');
test('barrier released before original test module', () => {
  process.stdout.write('NODE_TEST_CONTEXT=' + String(process.env.NODE_TEST_CONTEXT) + '\n');
  if (process.env.SECURESHOP_V03_PRIVATE_START_FD !== undefined) {
    throw new Error('V03 private start descriptor leaked to test body');
  }
});
