'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const dgram = require('node:dgram');
const { createCsrfBrowserExecutor } = require('../server/services/csrfBrowserExecutor');

test('learner WebRTC cannot bypass HTTP interception through non-proxied UDP', {timeout:10000}, async t => {
  const socket = dgram.createSocket('udp4');
  let packets = 0;
  socket.on('message', () => packets++);
  await new Promise(resolve => socket.bind(0, '127.0.0.1', resolve));
  t.after(() => socket.close());
  const executor = createCsrfBrowserExecutor({ attackerOrigin: 'http://attacker.lab.invalid',
    victimOrigin: 'http://victim.lab.invalid', timeoutMs: 3000 });
  t.after(() => executor.close());
  const html = `<script>
    const pc = new RTCPeerConnection({iceServers:[{urls:'stun:127.0.0.1:${socket.address().port}'}]});
    pc.createDataChannel('owned-isolation-probe');
    pc.createOffer().then(offer=>pc.setLocalDescription(offer));
  </script>`;
  await assert.rejects(executor.execute({ html, victimCookie: { name: 'owned', value: 'fixture' },
    onRequest: async () => { throw new Error('No HTTP action expected'); } }), { code: 'CSRF_BROWSER_TIMEOUT' });
  assert.equal(packets, 0, 'Browser may not send STUN packets outside the refusing proxy');
});
