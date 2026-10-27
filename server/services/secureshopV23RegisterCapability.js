'use strict';

// Only a server-created closure can authorize the original registry tool to
// submit stdio_cmd to the isolated executor. MCP arguments and _ss_caller are
// data: neither can mint this in-process capability.
const issued = new WeakSet();
const fail = code => Object.assign(new Error(code), { code, executionBoundary: true });
const uncertain = cause => {
  const error = fail('V23_EXECUTION_OUTCOME_UNCERTAIN');
  error.automaticRetry = false;
  Object.defineProperty(error, 'cause', { value: cause });
  return error;
};
const exact = (value, keys) => value && Object.getPrototypeOf(value) === Object.prototype
  && Object.keys(value).sort().join(',') === [...keys].sort().join(',');

function originalCommand(raw) {
  if (!exact(raw, ['name', 'transport', 'url', 'stdio_cmd'])
      || typeof raw.name !== 'string' || !raw.name.trim() || Buffer.byteLength(raw.name) > 256
      || raw.transport !== 'stdio' || raw.url !== null && raw.url !== ''
      || typeof raw.stdio_cmd !== 'string' || !raw.stdio_cmd.trim()
      || !raw.stdio_cmd.isWellFormed() || raw.stdio_cmd.includes('\0')
      || Buffer.byteLength(raw.stdio_cmd) > 4096) throw fail('V23_REGISTER_ARGUMENTS_INVALID');
  return Object.freeze({ name: raw.name, transport: 'stdio', url: '', stdio_cmd: raw.stdio_cmd });
}

function createOwnerScopedRegisterCapability({ mode, assertCurrent, dispatch } = {}) {
  if (!['vuln', 'fixed'].includes(mode) || typeof assertCurrent !== 'function'
      || typeof dispatch !== 'function') throw new TypeError('Trusted V23 register dependencies required');
  const capability = Object.freeze({
    async execute(raw) {
      const request = originalCommand(raw);
      await assertCurrent();
      // The current owned registry worker accepts stdio in Fixed too. Until
      // the lesson's signed/allowlisted Fixed registrar policy is bound, no
      // Fixed stdio command may reach that worker.
      if (mode === 'fixed') return Object.freeze({ ok: false, name: request.name,
        error: 'V23_FIXED_STDIO_DENIED', effectNotStarted: true });
      let result;
      try { result = await dispatch(request); await assertCurrent(); }
      catch (cause) { throw uncertain(cause); }
      // Dispatch owns the durable operation and effect receipt. This adapter
      // never infers command success from the absence of a transport error.
      if (!result || result.ok !== true || result.isolation !== 'owned-mcp-registry-v1'
          || typeof result.operationId !== 'string' || !result.operationId
          || result.command !== request.stdio_cmd) throw uncertain(fail('V23_EXECUTION_RECEIPT_INVALID'));
      return Object.freeze({ ...result });
    },
  });
  issued.add(capability);
  return capability;
}

function isOwnerScopedRegisterCapability(value) { return issued.has(value); }

module.exports = { createOwnerScopedRegisterCapability, isOwnerScopedRegisterCapability, originalCommand };
