'use strict';

const inspector = require('node:inspector');
const store = require('../../server/services/ragVectorStore');
const sessionId = '11111111-1111-4111-8111-111111111111';
const vector = offset => Float32Array.from({ length: 384 }, (_, index) => (index + offset) / 1000);
store.sessions.set(`17::${sessionId}`, [
  { text: 'owned first teaching chunk', embedding: vector(1), chunkIndex: 0 },
  { text: 'owned second teaching chunk', embedding: vector(2), chunkIndex: 1 },
]);
store.sessionMetadata.set(`17::${sessionId}`, { filename: 'owned.txt' });
store.lastSessionByUser.set('17', { sessionId, filename: 'selection-fallback.txt', chunksStored: 2 });
store.runtimeFingerprint = { fingerprint: 'a'.repeat(64), privatePath: '/must-not-export' };
store.resourceFamilies.set('CSRF', { sessions: new Map([['unrelated', [{ text: 'DO-NOT-EXPORT-CSRF' }]]]) });
globalThis.UNRELATED_PRIVATE_VALUE = 'DO-NOT-EXPORT-UNRELATED';
process.env.LEGACY_EXPORT_TEST_SECRET = 'DO-NOT-EXPORT-ENVIRONMENT';

let heartbeat = 0;
const timer = setInterval(() => { heartbeat += 1; process.send?.({ type: 'heartbeat', heartbeat }); }, 10);
process.on('message', message => {
  if (message === 'ready') process.send?.({ type: 'ready', url: inspector.url(), heartbeat });
  if (message === 'stop') { clearInterval(timer); process.exit(0); }
});
