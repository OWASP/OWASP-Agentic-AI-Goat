'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { projectSecureShopV46TraversalDestination } = require('../server/services/secureshopV46TraversalDestination');

const storageKey = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const file = Object.freeze({
  cleanedFilename: '../escaped.txt',
  baseVirtualPath: `operations/${storageKey}/avatars/46`,
  resolvedVirtualPath: `operations/${storageKey}/avatars/46/../escaped.txt`,
  storedVirtualPath: `operations/${storageKey}/avatars/escaped.txt`,
  isTraversal: true
});

test('V46 projects only the verified operation-relative escaped destination', () => {
  assert.deepEqual(projectSecureShopV46TraversalDestination(file, { storageKey, shopUserId: 46 }), {
    operationRelativePath: 'avatars/escaped.txt',
    escapedAvatarSubdirectory: true
  });
});

test('V46 rejects fabricated or mismatched destination coordinates', () => {
  for (const changed of [
    { storedVirtualPath: `operations/${storageKey}/foreign.txt` },
    { storedVirtualPath: 'operations/bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb/avatars/escaped.txt' },
    { resolvedVirtualPath: `operations/${storageKey}/avatars/46/escaped.txt` },
    { baseVirtualPath: `operations/${storageKey}/avatars/47` },
    { cleanedFilename: '../../escaped.txt' },
    { storedVirtualPath: `operations/${storageKey}/avatars/.` },
    { storedVirtualPath: `operations/${storageKey}/avatars/..` },
    { isTraversal: false }
  ]) assert.throws(() => projectSecureShopV46TraversalDestination({ ...file, ...changed }, {
    storageKey, shopUserId: 46
  }), { code: 'BOUND_UPLOAD_EFFECT_MISMATCH' });
});
