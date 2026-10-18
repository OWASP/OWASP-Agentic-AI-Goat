'use strict';
const crypto = require('node:crypto');
const VERSION = 'secureshop-endpoint-ipc.v1';
function error(code) { return Object.assign(Error(code), { code }); }
// The supplied channel is the inherited Node IPC handle of an already verified
// owned child. A message-provided PID or owner ID is never channel authority.
function createEndpointIpcSender(channel, { timeoutMs = 3000, revokeAll } = {}) {
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 30000 || typeof revokeAll !== 'function') throw error('IPC_CONFIGURATION');
  let sequence = 0, closed = false;const pending = new Map(), failures = [];
  const status = () => Object.freeze({ closed, failures: Object.freeze([...failures]) });
  function close(reason = error('IPC_DISCONNECTED')) {
    if (closed) return;closed = true;
    try { revokeAll(); } catch { failures.push('REVOKE_FAILED'); } finally {
      for (const entry of pending.values()) entry.finish(reason);
      channel.off('message', onMessage);channel.off('disconnect', onDisconnect);channel.off('error', onError);
      try { if (channel.connected !== false) channel.disconnect?.(); } catch { failures.push('DISCONNECT_FAILED'); }
    }
  }
  function onDisconnect() { close(); }
  function onError() { close(error('IPC_CHANNEL_FAILED')); }
  function onMessage(message) {
    if (message?.version !== VERSION || message.type !== 'ack') return;
    const entry = pending.get(message.id);
    if (!entry || message.sequence !== entry.sequence || message.digest !== entry.digest) return close(error('IPC_ACK_MISMATCH'));
    if (message.ok !== true) return close(error('IPC_REMOTE_REJECTED'));
    entry.finish(null, Object.freeze({ sequence: entry.sequence, digest: entry.digest }));
  }
  channel.on('message', onMessage);channel.on('disconnect', onDisconnect);channel.on('error', onError);
  function send(operation, { signal } = {}) {
    if (closed || channel.connected === false) return Promise.reject(error('IPC_DISCONNECTED'));
    if (signal?.aborted) return Promise.reject(signal.reason || error('IPC_CANCELLED'));
    const payload = JSON.parse(JSON.stringify(operation));
    const digest = crypto.createHash('sha256').update(JSON.stringify(payload)).digest('hex');
    const id = crypto.randomUUID(), current = ++sequence;
    return new Promise((resolve, reject) => {
      const onAbort = () => close(signal.reason || error('IPC_CANCELLED'));
      const timer = setTimeout(() => close(error('IPC_ACK_TIMEOUT')), timeoutMs);
      const finish = (failure, result) => {
        clearTimeout(timer);signal?.removeEventListener('abort', onAbort);pending.delete(id);
        failure ? reject(failure) : resolve(result);
      };
      pending.set(id, { sequence: current, digest, finish });signal?.addEventListener('abort', onAbort, { once: true });
      try { channel.send({ version: VERSION, type: 'command', id, sequence: current, digest, payload }, failure => {
        if (failure) close(error('IPC_SEND_FAILED'));
      }); } catch { close(error('IPC_SEND_FAILED')); }
    });
  }
  return Object.freeze({ send, close, status });
}
function createEndpointIpcReceiver(channel, { grant, apply, revokeAll } = {}) {
  if (typeof grant !== 'function' || typeof apply !== 'function' || typeof revokeAll !== 'function') throw error('IPC_CONFIGURATION');
  let sequence = 0, closed = false, chain = Promise.resolve();
  const grants = new Map(), failures = [];
  const status = () => Object.freeze({ closed, failures: Object.freeze([...failures]) });
  function close() {
    if (closed) return;closed = true;
    try { revokeAll(); } catch { failures.push('REVOKE_FAILED'); } finally { channel.off('message', onMessage);channel.off('disconnect', close);channel.off('error', close);
      try { if (channel.connected !== false) channel.disconnect?.(); } catch { failures.push('DISCONNECT_FAILED'); } }
  }
  async function accept(message) {
    if (closed) return;
    const digest = crypto.createHash('sha256').update(JSON.stringify(message.payload)).digest('hex');
    if (message.sequence !== sequence + 1 || message.digest !== digest || typeof message.id !== 'string') { close();return; }
    sequence = message.sequence;
    try {
      const payload = message.payload;
      if (payload?.operation === 'bootstrap') {
        if (Object.keys(payload).sort().join(',') !== 'capability,operation,scope,version' || payload.version !== 1
            || !/^[a-f0-9]{64}$/.test(payload.capability) || grants.has(payload.capability)) throw error('IPC_GRANT_REJECTED');
        // Child mints its own capability; the authenticated parent handle is
        // translated only within this channel, never imported as registry authority.
        const local = grant(payload.scope);
        grants.set(payload.capability, local);
      } else {
        const local = grants.get(payload?.capability);
        if (!local) throw error('IPC_GRANT_REQUIRED');
        await apply({ ...payload, capability: local.capability });
      }
      if (closed) { try { revokeAll(); } catch { failures.push('REVOKE_FAILED'); } return; }
      channel.send({ version: VERSION, type: 'ack', id: message.id, sequence, digest, ok: true }, failure => { if (failure) close(); });
    } catch { close(); }
  }
  function onMessage(message) {
    if (message?.version !== VERSION || message.type !== 'command') return;
    chain = chain.then(() => accept(message)).catch(close);
  }
  channel.on('message', onMessage);channel.on('disconnect', close);channel.on('error', close);
  return Object.freeze({ close, status });
}
module.exports = { createEndpointIpcSender, createEndpointIpcReceiver };
