'use strict';

const { verifyFinflowOwnerDeletionReceipt } = require('./finflowOwnerDeletionReceipt');

function exactScope(scope) {
  if (!Number.isSafeInteger(scope?.subjectId) || scope.subjectId < 1 || scope.subjectId > 2147483647
      || typeof scope.check !== 'function') throw new TypeError('Deletion owner and lease check required');
  return String(scope.subjectId);
}
async function checked(scope, operation) {
  const owner = exactScope(scope);
  scope.signal?.throwIfAborted(); await scope.check();
  const result = await operation(owner);
  scope.signal?.throwIfAborted(); await scope.check();
  if (result?.completed !== true) throw new Error('Deletion adapter returned an invalid receipt');
  return result;
}

// Complete ordered application registry. Production publishes it only after
// every durable finalizer and the retained SecureShop cleanup runtime pass
// readiness; individual adapters are never treated as terminal deletion.
function createStudentDeletionAdapters(load = require, options = {}) {
  const { secureShopCleanup, storeCleanup, ctfRuntime,
    retireFinflowTraversalOwner, cleanupFinflowBackups } = options;
  // Selected only by the complete authority cutover. A supplied but unavailable
  // runtime must never fall back to the legacy direct writer.
  const orderedCtf = Object.hasOwn(options, 'ctfRuntime');
  const deleteCtf = typeof ctfRuntime?.deleteStudent === 'function'
    ? ctfRuntime.deleteStudent.bind(ctfRuntime) : null;
  return {
    async revoke_runs(scope) {
      if (!Number.isSafeInteger(scope?.subjectId) || scope.subjectId < 1 || scope.subjectId > 2147483647 || typeof scope.check !== 'function') throw new TypeError('Deletion owner and lease check required');
      scope.signal?.throwIfAborted();
      await scope.check();
      const { pool } = load('./postgresIdentityAdapter').getPostgresIdentityAdapter();
      const ledger = load('../agent-runtime/postgresRunLedger').configuredRunLedger();
      const drain = load('./studentDeletionRunDrain').createStudentDeletionRunDrain({ pool, ledger });
      return drain(scope);
    },
    async excessive_agency({ subjectId, check }) {
      if (!Number.isSafeInteger(subjectId) || subjectId < 1 || subjectId > 2147483647 || typeof check !== 'function') throw new TypeError('Deletion owner and lease check required');
      await check();
      const router = load('../routes/excessiveAgencyLab');
      const store = load('./excessiveAgencyAttendeeLabStore').excessiveAgencyAttendeeLabStore;
      if (typeof router.resetOwner !== 'function' || typeof store.destroyAttendee !== 'function') throw new Error('Deletion adapter unavailable');
      const owner = String(subjectId);
      await router.resetOwner(owner, async () => {
        await check();
        const receipt = await store.destroyAttendee(owner);
        if (!Number.isInteger(receipt?.removed) || receipt.removed < 0 || receipt.removed > 1) throw new Error('Invalid deletion receipt');
        await check();
      });
      return { completed: true };
    },
    async session_disclosure({ subjectId, check }) {
      if (!Number.isSafeInteger(subjectId) || subjectId < 1 || subjectId > 2147483647 ||
          typeof check !== 'function') throw new TypeError('Deletion owner and lease check required');
      await check();
      const lab = load('./sessionDisclosureLab').getSessionDisclosureLab();
      await check();
      const removed = await lab.destroyOwner(subjectId);
      if (!Number.isInteger(removed) || removed < 0 || removed > 1) throw new Error('Invalid deletion receipt');
      await check();
      return { completed: true };
    },
    async secureshop(scope) {
      if (typeof secureShopCleanup !== 'function') throw new Error('SecureShop deletion adapter unavailable');
      return secureShopCleanup(scope);
    },
    sql_injection_workshop: scope => checked(scope, async owner => {
      const agent = load('./ariaAgentService');
      const store = load('../database/postgres/sqlWorkshopDb');
      if (typeof agent.reset !== 'function' || typeof store.destroyOwner !== 'function') throw new Error('ARIA deletion adapter unavailable');
      let receipt;
      await agent.reset(owner, async () => { await scope.check(); receipt = await store.destroyOwner(owner); });
      if (!Number.isSafeInteger(receipt?.removed) || receipt.removed < 0 || receipt.removed > 1000000) throw new Error('Invalid ARIA deletion receipt');
      return { completed: true };
    }),
    nosql_injection_workshop: scope => checked(scope, async owner => {
      const agent = load('./novaAgentService');
      const store = load('../database/postgres/nosqlWorkshopDb');
      if (typeof agent.reset !== 'function' || typeof store.destroyOwner !== 'function') throw new Error('NOVA deletion adapter unavailable');
      let receipt;
      await agent.reset(owner, async () => { await scope.check(); receipt = await store.destroyOwner(owner); });
      if (!Number.isSafeInteger(receipt?.removed) || receipt.removed < 0 || receipt.removed > 1000000) throw new Error('Invalid NOVA deletion receipt');
      return { completed: true };
    }),
    mcp_workshop: scope => checked(scope, async owner => {
      const route = load('../routes/mcpWorkshop');
      const store = load('../database/postgres/mcpWorkshopDb');
      if (typeof route.resetOwner !== 'function' || typeof store.destroyOwner !== 'function') throw new Error('MCP deletion adapter unavailable');
      await route.resetOwner(owner, async () => {
        await scope.check();
        const receipt = await store.destroyOwner(owner);
        if (!Number.isSafeInteger(receipt?.removed) || receipt.removed < 0 || receipt.removed > 1000000) throw new Error('Invalid MCP deletion receipt');
      }, { check: scope.check });
      return { completed: true };
    }),
    csrf_workshop: scope => checked(scope, async owner => {
      const route = load('../routes/csrfWorkshop');
      const store = load('../database/postgres/csrfWorkshopDb');
      const sandbox = load('./csrfVictimSandbox');
      if (typeof route.resetOwner !== 'function' || typeof store.destroyOwner !== 'function'
          || typeof route.clearRagOwnerState !== 'function' || typeof sandbox.resetSandbox !== 'function') throw new Error('CSRF deletion adapter unavailable');
      await route.resetOwner(owner, async () => {
        await scope.check();
        const durableRag = route.durableRagComposition?.();
        if (durableRag) await durableRag.deleteOwner({ownerId: Number(owner), jobId: scope.jobId, leaseToken: scope.leaseToken});
        else await route.clearRagOwnerState(owner);
        const receipt = await store.destroyOwner(owner);
        if (!Number.isSafeInteger(receipt?.removed) || receipt.removed < 0 || receipt.removed > 1000000) throw new Error('Invalid CSRF deletion receipt');
        sandbox.resetSandbox(`csrf_${owner}`);
      });
      return { completed: true };
    }),
    direct_prompt_injection: scope => checked(scope, async owner => {
      const route = load('../routes/promptInjectionWorkshop');
      if (typeof route.resetOwner !== 'function') throw new Error('DPI deletion adapter unavailable');
      await route.resetOwner(owner, async () => { await scope.check(); });
      return { completed: true };
    }),
    indirect_prompt_injection: scope => checked(scope, async owner => {
      const route = load('../routes/ragInjection');
      const email = load('../routes/emailAgent');
      if (typeof route.resetOwner !== 'function' || typeof route.clearOwnerState !== 'function'
          || typeof email.resetOwner !== 'function' || typeof email.destroyOwnerArtifacts !== 'function') {
        throw new Error('IPI deletion adapter unavailable');
      }
      let removed;
      await route.resetOwner(owner, async () => {
        await scope.check();
        const durableRag = route.durableRagComposition?.();
        if (durableRag) await durableRag.deleteOwner({ownerId: Number(owner), jobId: scope.jobId, leaseToken: scope.leaseToken});
        else await route.clearOwnerState(owner);
        await scope.check();
        await email.resetOwner(owner, async () => {
          await scope.check(); removed = await email.destroyOwnerArtifacts(owner); await scope.check();
        });
      });
      if (!Number.isSafeInteger(removed) || removed < 0 || removed > 1000000) throw new Error('Invalid IPI email artifact deletion receipt');
      return { completed: true };
    }),
    supply_chain_rce: scope => checked(scope, async owner => {
      const route = load('../routes/supplyChainWorkshop');
      const store = load('../database/postgres/supplyChainWorkshopDb');
      const sandbox = load('./supplyChain/codeBotSandboxRuntime');
      if (typeof route.resetOwner !== 'function' || typeof store.destroyOwner !== 'function'
          || typeof sandbox.resetOwner !== 'function'
          || typeof storeCleanup?.codeBotExecutionAbsent !== 'function') {
        throw new Error('Supply Chain deletion adapter unavailable');
      }
      await route.resetOwner(owner, async () => {
        await scope.check();
        const executionAbsent = await storeCleanup.codeBotExecutionAbsent(scope);
        if (executionAbsent !== true) {
          const isolated = await sandbox.resetOwner(owner);
          if (isolated?.ok !== true) throw new Error('CodeBot sandbox deletion incomplete');
        }
        await scope.check();
        const receipt = await store.destroyOwner(owner);
        if (!Number.isSafeInteger(receipt?.removed) || receipt.removed < 0 || receipt.removed > 1000000) throw new Error('Invalid Supply Chain deletion receipt');
      });
      return { completed: true };
    }),
    ctf: scope => checked(scope, async owner => {
      if (orderedCtf) {
        if (!deleteCtf) throw new Error('CTF authority deletion unavailable');
        const receipt = await deleteCtf({ ...scope });
        if (receipt?.completed !== true || typeof receipt.operationId !== 'string'
            || !/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(receipt.operationId)) {
          throw new Error('CTF authority deletion incomplete');
        }
        return { completed: true };
      }
      const route = load('../routes/ctf');
      const store = load('../database/postgres/ctfDb').CTFHelpers;
      if (typeof route.resetOwner !== 'function' || typeof store?.destroyOwner !== 'function') throw new Error('CTF deletion adapter unavailable');
      await route.resetOwner(owner, async () => {
        await scope.check();
        const receipt = await store.destroyOwner(Number(owner));
        if (!Number.isSafeInteger(receipt?.removed) || receipt.removed < 0 || receipt.removed > 1000000) throw new Error('Invalid CTF deletion receipt');
      });
      return { completed: true };
    }),
    legacy_challenge: scope => checked(scope, async owner => {
      const cleanup = load('./legacyChallengeOwnerCleanup').getLegacyChallengeOwnerCleanup();
      if (typeof cleanup?.destroyOwner !== 'function') throw new Error('Legacy challenge deletion adapter unavailable');
      const receipt = await cleanup.destroyOwner(owner);
      if (!Number.isSafeInteger(receipt?.removed) || receipt.removed < 0 || receipt.removed > 1000000
          || !Number.isSafeInteger(receipt?.filesRemoved) || receipt.filesRemoved < 0 || receipt.filesRemoved > 1000000) {
        throw new Error('Invalid legacy challenge deletion receipt');
      }
      return { completed: true };
    }),
    sensitive_lookup: scope => checked(scope, async owner => {
      const store = load('../database/postgres/sensitiveLookupDb').getSensitiveLookupDb();
      if (typeof store?.destroyOwner !== 'function') throw new Error('Sensitive lookup deletion adapter unavailable');
      const receipt = await store.destroyOwner(owner);
      if (!Number.isSafeInteger(receipt?.removed) || receipt.removed < 0 || receipt.removed > 1000000) {
        throw new Error('Invalid sensitive lookup deletion receipt');
      }
      return { completed: true };
    }),
    xss: async scope => {
      if (typeof storeCleanup?.xss !== 'function') throw new Error('XSS deletion adapter unavailable');
      exactScope(scope);
      const route = load('../routes/xssWorkshop');
      if (typeof route.resetOwner !== 'function') throw new Error('XSS deletion run fence unavailable');
      let receipt;
      await route.resetOwner(String(scope.subjectId), async () => { await scope.check(); receipt = await storeCleanup.xss(scope); });
      return receipt;
    },
    finflow: async scope => {
      if (typeof storeCleanup?.finflow !== 'function') throw new Error('FinFlow deletion adapter unavailable');
      if (typeof cleanupFinflowBackups !== 'function') throw new Error('FinFlow backup deletion cleanup unavailable');
      if (typeof retireFinflowTraversalOwner !== 'function') throw new Error('FinFlow traversal deletion cleanup unavailable');
      exactScope(scope);
      const route = load('../routes/sensitiveInfoWorkshop');
      if (typeof route.resetOwner !== 'function') throw new Error('FinFlow deletion run fence unavailable');
      let receipt;
      await route.resetOwner(String(scope.subjectId), async () => {
        await scope.check();
        const backupReceipt = await cleanupFinflowBackups(scope);
        if (!verifyFinflowOwnerDeletionReceipt(backupReceipt, { ownerId:scope.subjectId, jobId:scope.jobId })) {
          throw new Error('Invalid FinFlow backup deletion receipt');
        }
        await scope.check();
        const retired = await retireFinflowTraversalOwner(String(scope.subjectId));
        if (retired !== true) throw new Error('Invalid FinFlow traversal deletion receipt');
        await scope.check();
        receipt = await storeCleanup.finflow(scope);
      });
      return receipt;
    },
    identity: scope => {
      if (typeof storeCleanup?.identity !== 'function') throw new Error('Identity deletion adapter unavailable');
      return storeCleanup.identity(scope);
    },
  };
}
module.exports = { createStudentDeletionAdapters };
