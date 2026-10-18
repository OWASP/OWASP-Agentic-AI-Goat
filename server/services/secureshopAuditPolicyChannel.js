'use strict';
// The inherited Node IPC pipe belongs to one spawned child, never a public socket.
const fail = () => Object.assign(new Error('Audit policy channel unavailable'), { code: 'AUDIT_POLICY_CHANNEL_INVALID', executionBoundary: true });
function createAuditPolicyParent({ runId, requestedCount, admit, check, send, stop,taskRequestVersion=1 }) {
  if(![1,2].includes(taskRequestVersion))throw fail();
  const seen = new Set(), receipts = new Map(),argumentsByInvocation=new Map();
  let busy = false, closed = false;
  return Object.freeze({ receipts,argumentsByInvocation,
    close() { closed = true; },
    async receive(message) {
      try {
        const focused=Object.hasOwn(message?.args||{},'focus_action');
        if (closed || busy || seen.size >= 4 || !message || Object.keys(message).sort().join(',') !== 'args,callId,step,type'
          || message.type !== 'audit_policy_request' || !Number.isSafeInteger(message.step) || message.step < 1 || message.step > 4
          || typeof message.callId !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(message.callId)
          || !message.args || !Object.hasOwn(message.args,'limit')||Object.keys(message.args).length!==(focused?2:1)||message.args.limit!==requestedCount
          ||(focused&&(taskRequestVersion!==2||typeof message.args.focus_action!=='string'||!/^[A-Za-z0-9_.:-]{1,100}$/.test(message.args.focus_action)))) throw fail();
        const invocationId = `${message.step}:${message.callId}`;
        if (seen.has(invocationId)) throw fail();
        seen.add(invocationId); busy = true;
        const args=Object.freeze({...message.args});
        const input = Object.freeze({ runId, invocationId, agent: 'audit', tool: 'summarize_anomalies',args });
        await check(); const receipt = structuredClone(await admit(input)); await check();
        if (closed || receipt?.runId !== runId || receipt.invocationId !== invocationId
          || receipt.toolKey !== 'audit.summarize_anomalies') throw fail();
        receipts.set(invocationId, Object.freeze(receipt));argumentsByInvocation.set(invocationId,args);
        send({ type: 'audit_policy_response', invocationId, admission: receipt });
      } catch (error) { closed = true; stop(error); }
      finally { busy = false; }
    },
  });
}
function createAuditPolicyChild(channel, { timeoutMs = 10000 } = {}) {
  let pending, closed = false;
  function reject() { closed = true; if (pending) { clearTimeout(pending.timer); pending.reject(fail()); pending = null; } }
  channel.on('disconnect', reject);
  channel.on('message', message => {
    if (!pending || !message || Object.keys(message).sort().join(',') !== 'admission,invocationId,type'
      || message.type !== 'audit_policy_response' || message.invocationId !== pending.id) { reject(); return; }
    const selected = pending; pending = null; clearTimeout(selected.timer); selected.resolve(message.admission);
  });
  return Object.freeze({ close: reject, request(context) {
    if (closed || pending || !channel.connected || typeof channel.send !== 'function') return Promise.reject(fail());
    return new Promise((resolve, rejectPromise) => {
      const id = `${context.step}:${context.callId}`;
      pending = { id, resolve, reject: rejectPromise, timer: setTimeout(reject, timeoutMs) };
      channel.send({ type: 'audit_policy_request', step: context.step, callId: context.callId, args: context.args }, error => { if (error) reject(); });
    });
  } });
}
module.exports = { createAuditPolicyParent, createAuditPolicyChild };
