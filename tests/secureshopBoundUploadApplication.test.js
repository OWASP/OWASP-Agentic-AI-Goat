'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const {
  createSecureShopBoundUploadApplication
} = require('../server/services/secureshopBoundUploadApplication');
const admission = {
  operationId: 'op',
  storageKey: 'key',
  scope: {
    shopUserId: 11
  }
};
const file = {
  bytes: Buffer.from('x'),
  filename: 'x.php',
  mime: 'text/plain'
};
const written = {
  cleanedFilename: 'x.php',
  byteCount: 1,
  bodySha256: 'a'.repeat(64),
  baseVirtualPath: '/b',
  resolvedVirtualPath: '/r',
  storedVirtualPath: '/s',
  isTraversal: false
};
test('lost acknowledgement recovers immutable effect without a second write', async () => {
  let writes = 0,
    finds = 0;
  const committed = {
    operationId: 'op',
    storageKey: 'key',
    outcome: 'completed'
  };
  const app = createSecureShopBoundUploadApplication({
    effects: {
      async find() {
        return ++finds === 1 ? null : committed;
      }
    },
    writer: {
      async writeAndReadBack() {
        writes++;
        return written;
      }
    },
    journal: {
      async recordEffect() {
        throw new Error('lost ack');
      }
    }
  });
  const out = await app.execute({
    admission,
    file,
    mode: 'vuln',
    execution: {
      async check() {}
    },
    effectId: 'effect'
  });
  assert.equal(writes, 1);
  assert.equal(out.effect, committed);
  assert.equal(out.replayed, true);
});
test('fixed denial records no file and vulnerable write records exact readback', async () => {
  const rows = [];
  let writes = 0;
  const app = createSecureShopBoundUploadApplication({
    effects: {
      async find() {
        return null;
      }
    },
    writer: {
      async writeAndReadBack() {
        writes++;
        return written;
      }
    },
    journal: {
      async recordEffect(_a, e) {
        rows.push(e);
        return e;
      }
    }
  });
  await app.execute({
    admission,
    file,
    mode: 'fixed',
    execution: {
      async check() {}
    },
    effectId: 'd'
  });
  assert.equal(writes, 0);
  assert.equal(rows[0].outcome, 'denied');
  await app.execute({
    admission,
    file: {
      ...file,
      filename: 'x.txt'
    },
    mode: 'vuln',
    execution: {
      async check() {}
    },
    effectId: 'c'
  });
  assert.equal(writes, 1);
  assert.equal(rows[1].file.storedVirtualPath, '/s');
});
