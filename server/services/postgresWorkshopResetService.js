'use strict';

const {
  toWorkshopKey
} = require('../config/workshopCatalog');
const {
  userId
} = require('../database/postgres/workshopPlatformSupport');
const {childResetOperation:resetChildOperation}=require('./workshopResetRequest');
const { withStudentLifecycleLock } = require('../database/postgres/studentLifecycleLock');
function createPostgresWorkshopResetService({
  progress,
  adapters,
  listUserIds,
  bulkJournal,
  resolveBulkActor,
  withStudentResetAdmission = (_userId, work) => work()
}) {
  function resolve(workshopKey) {
    const key = toWorkshopKey(workshopKey);
    const adapter = adapters[key];
    if (!adapter) throw Object.assign(new Error('Challenge reset storage has not completed PostgreSQL migration'), {
      code: 'RESET_STORAGE_NOT_READY',
      statusCode: 503
    });
    return {
      key,
      adapter
    };
  }
  async function preflight(adapter, administrative) {
    if (typeof adapter.preflight === 'function') await adapter.preflight();
    if (administrative && typeof adapter.preflightAdministrative === 'function') {
      await adapter.preflightAdministrative();
    }
  }
  async function resetStudent(input, administrative) {
    const id = userId(input?.userId);
    const { workshopKey, operationId, actorRequest } = input || {};
    const {
      key,
      adapter
    } = resolve(workshopKey);
    await preflight(adapter, administrative);
    await adapter.cancelBeforeAdmission?.(id,{operationId});
    return withStudentResetAdmission(id, async lifecycle => {
      if (administrative && typeof adapter.resetAdministrativeOwner === 'function') {
        return adapter.resetAdministrativeOwner(id, { operationId, lifecycle });
      }
      if (!administrative && typeof adapter.assertStudentResetAdmitted === 'function') {
        if (typeof lifecycle?.check !== 'function') {
          throw Object.assign(new Error('Current student reset lifecycle authority is required'), {
            code: 'RESET_AUTHORITY_UNAVAILABLE', statusCode: 503,
          });
        }
        await lifecycle.check();
        await adapter.assertStudentResetAdmitted(id, lifecycle);
        await lifecycle.check();
      }
      if (typeof adapter.resetOwnerWithLifecycle === 'function') {
        return adapter.resetOwnerWithLifecycle(id,{operationId,lifecycle});
      }
      if (typeof adapter.resetOwner === 'function') {
        const options = adapter.resetOwnerIncludesCanonical === true
          ? { operationId, resetCanonical: () => progress.resetWorkshopProgress(id, key) }
          : { operationId };
        return adapter.resetOwner(id, { ...options, ...(actorRequest ? { actorRequest } : {}) });
      }
      // Runtime coordinator cancels and drains the same owner's outstanding work.
      // Separate challenge/platform databases cannot promise atomic cross-database commits.
      return adapter.reset(String(id), async execution => {
        if (adapter.requiresResetAuthority === true && typeof execution?.check !== 'function') {
          throw Object.assign(new Error('Current owner reset authority is required'), {
            code: 'RESET_AUTHORITY_UNAVAILABLE', statusCode: 503,
          });
        }
        try {
          await execution?.check?.();
          await adapter.clear(String(id));
          await execution?.check?.();
          await progress.resetWorkshopProgress(id, key);
          await execution?.check?.();
        } catch (cause) {
          throw Object.assign(new Error('Reset failed; some challenge state may already have been cleared'), {
            code: 'RESET_PARTIAL_FAILURE',
            statusCode: 503,
            cause
          });
        }
      });
    });
  }
  async function resetBulk({requestKind,workshopKeys,operationId,actorRequest}) {
    if(!bulkJournal || !resolveBulkActor) throw Object.assign(new Error('Durable bulk reset storage required'),{code:'RESET_STORAGE_NOT_READY',statusCode:503});
    return bulkJournal.withOperation(operationId, async journal => {
      const authority=await resolveBulkActor(actorRequest);
      const cohort=await journal.begin({operationId,requestKind,workshopKeys,...authority});
      const pending=cohort.children.filter(child=>!['completed','deleted'].includes(child.state));
      if(!pending.length)return cohort;
      for(const key of new Set(pending.map(child=>child.workshopKey))) await preflight(resolve(key).adapter,true);
      for(const child of cohort.children){
        if(['completed','deleted'].includes(child.state))continue;
        const current=await resolveBulkActor(actorRequest);
        const replaySafe=await resolve(child.workshopKey).adapter.bulkResetReplaySafe?.()===true;
        const claim=await journal.claim({operationId,ordinal:child.ordinal,replaySafe,...current});
        if(['completed','deleted'].includes(claim.state))continue;
        try {
          await api.resetAdministrativeStudent({userId:child.ownerId,workshopKey:child.workshopKey,operationId:child.childOperationId,actorRequest});
          await journal.finish({operationId,ordinal:child.ordinal,leaseToken:claim.leaseToken,completed:true,...await resolveBulkActor(actorRequest)});
        } catch(error) {
          // A remote effect may have committed. Only replay-capable children may reconcile;
          // generic children retain explicit debt and are never blindly repeated.
          try{await journal.finish({operationId,ordinal:child.ordinal,leaseToken:claim.leaseToken,completed:false,...await resolveBulkActor(actorRequest)});}catch{}
          throw error;
        }
      }
      return journal.begin({operationId,requestKind,workshopKeys,...await resolveBulkActor(actorRequest)});
    });
  }
  const api = {
    resetStudent(input) { return resetStudent(input, false); },
    resetAdministrativeStudent(input) { return resetStudent(input, true); },
    assertSupported(workshopKey) {
      resolve(workshopKey);
    },
    async listPendingBulkResets({actorRequest,scope}={}) {
      if(!bulkJournal || !resolveBulkActor) throw Object.assign(new Error('Durable bulk reset storage required'),{code:'RESET_STORAGE_NOT_READY',statusCode:503});
      if(scope?.requestKind==='workshop'&&scope.workshopKey==='xss_combined')await bulkJournal.assertCombinedReady?.();
      return bulkJournal.listPending(await resolveBulkActor(actorRequest),scope);
    },
    resetWorkshop({workshopKey,operationId,actorRequest}) {
      // This display alias exists only for the administrative bulk scope. Durable
      // canonical children retain each family's reset and replay authority.
      if(workshopKey==='xss_combined') return (async()=>{
        await bulkJournal?.assertCombinedReady?.();
        return resetBulk({requestKind:'workshop',workshopKeys:['xss_email_builder','xss_workshop'],operationId,actorRequest});
      })();
      if(!bulkJournal){
        if(!listUserIds)throw new TypeError('User inventory required for bulk reset');
        return (async()=>{for(const id of await listUserIds())await api.resetAdministrativeStudent({userId:id,workshopKey,actorRequest,...(operationId?{operationId:resetChildOperation(operationId,String(id))}:{})});})();
      }
      return resetBulk({requestKind:'workshop',workshopKeys:[toWorkshopKey(workshopKey)],operationId,actorRequest});
    },
    resetAll({operationId,actorRequest}={}) {
      if(!bulkJournal)return (async()=>{const keys=Object.keys(require('../config/workshopCatalog').WORKSHOP_OBJECTIVES);for(const key of keys)await preflight(resolve(key).adapter,true);for(const key of keys)await api.resetWorkshop({workshopKey:key,actorRequest,...(operationId?{operationId:resetChildOperation(operationId,key)}:{})});})();
      return resetBulk({requestKind:'all',workshopKeys:Object.keys(require('../config/workshopCatalog').WORKSHOP_OBJECTIVES),operationId,actorRequest});
    }

  };
  return api;
}
async function listPostgresStudentIds(pool) {
  if (typeof pool?.query !== 'function') throw new TypeError('PostgreSQL pool is required');
  const rows = (await pool.query(`SELECT users.id FROM identity.users users
    WHERE users.role='student' AND users.admin_level=0 AND NOT EXISTS (
      SELECT 1 FROM identity.student_deletion_jobs deletion
      WHERE deletion.subject_user_id=users.id
    ) ORDER BY users.id`)).rows;
  return rows.map(row => userId(row.id));
}
async function withPostgresStudentResetAdmission(pool, studentId, work) {
  const id = userId(studentId);
  return withStudentLifecycleLock(pool, id, async (client, lifecycleGuard) => {
    const student = (await client.query(`SELECT id FROM identity.users
      WHERE id=$1 AND role='student' AND admin_level=0`, [id])).rows[0];
    if (!student) throw Object.assign(new Error('Student not found'), {
      code: 'STUDENT_NOT_FOUND', statusCode: 404,
    });
    if ((await client.query(`SELECT 1 FROM identity.student_deletion_jobs
      WHERE subject_user_id=$1`, [id])).rowCount) {
      throw Object.assign(new Error('Student deletion has already been admitted'), {
        code: 'STUDENT_DELETION_ADMITTED', statusCode: 409,
      });
    }
    return work(lifecycleGuard);
  });
}
function createLazyStudentResetAdmission({ createLifecyclePool, admit = withPostgresStudentResetAdmission } = {}) {
  if (typeof createLifecyclePool !== 'function' || typeof admit !== 'function') {
    throw new TypeError('Student reset lifecycle pool factory and admission required');
  }
  let lifecyclePool;
  return (studentId, work) => {
    // Pool creation is intentionally synchronous and assigned before admission
    // starts, so concurrent first requests share one bounded lease pool. A
    // failed creation leaves no retained value and can be retried later.
    lifecyclePool ||= createLifecyclePool();
    return admit(lifecyclePool, studentId, work);
  };
}
function createPostgresWorkshopResetAdapters(load = require) {
    const entries = [['sql_injection_workshop', 'ariaAgentService', 'sqlWorkshopDb', 'clearCart'], ['nosql_injection_workshop', 'novaAgentService', 'nosqlWorkshopDb', 'clearReadingList']];
    const adapters = Object.fromEntries(entries.map(([key, agentName, dbName, clearState]) => [key, {
      reset: (owner, work) => load(`./${agentName}`).reset(owner, work),
      async clear(owner) {
        const db = load(`../database/postgres/${dbName}`);
        await db.clearHistory(owner);
        await db[clearState](owner);
      }
    }]));
    adapters.mcp_workshop = {
      requiresResetAuthority: true,
      reset: (owner, work) => load('../routes/mcpWorkshop').resetOwner(owner, work),
      async clear(owner) {
        await load('../database/postgres/mcpWorkshopDb').resetUser(owner);
      }
    };
    adapters.csrf_workshop = {
      bulkResetReplaySafe: () => Boolean(load('../routes/csrfWorkshop').durableRagComposition?.()),
      resetOwnerIncludesCanonical: true,
      async resetOwner(owner, {resetCanonical, actorRequest, operationId} = {}) {
        if(typeof resetCanonical !== 'function') throw new TypeError('Canonical progress reset required');
        const route=load('../routes/csrfWorkshop');
        const durable=route.durableRagComposition?.();
        return route.resetOwner(String(owner), async execution => {
          const cleanup=async()=>{
            if(!durable) await route.clearRagOwnerState(String(owner));
            await load('../database/postgres/csrfWorkshopDb').resetUser(String(owner));
            const sandbox=load('./csrfVictimSandbox').getOrCreateSandbox(`csrf_${owner}`);
            await sandbox.ready(); sandbox.reset(); await sandbox.flush(); await resetCanonical();
          };
          if(durable){
            const request=await durable.resolveRequest(actorRequest);
            return request.reset(execution,{family:'CSRF',targetOwnerId:Number(owner),operationId,afterErase:cleanup});
          }
          await cleanup();
        });
      }
    };
    const resetBuilder=async(owner,{operationId,lifecycle})=>load('./xssEmailBuilderCanonical').getXssEmailBuilderCanonical()
      .reset({owner,operationId,lifecycle,runs:load('../routes/xssEmail').builderRuns});
    adapters.xss_email_builder={
      cancelBeforeAdmission:(owner,{operationId})=>load('./xssEmailBuilderCanonical').getXssEmailBuilderCanonical().cancelBeforeReset({owner,operationId,runs:load('../routes/xssEmail').builderRuns}),
      preflight:()=>load('./xssEmailBuilderCanonical').getXssEmailBuilderCanonical().assertReady(),
      bulkResetReplaySafe:()=>load('./xssEmailBuilderCanonical').getXssEmailBuilderCanonical().assertReady(),
      resetOwnerWithLifecycle:resetBuilder,resetAdministrativeOwner:resetBuilder,
      async assertStudentResetAdmitted(owner,lifecycle){
        await load('../database/postgres/xssParentResetJournalRepository').createXssParentResetJournalRepository(
          load('./postgresIdentityAdapter').getPostgresIdentityAdapter().pool).assertMutationAdmitted(owner);
        await load('./xssMutationAdmission').configuredXssProfileResetPendingCheck(owner,lifecycle);
      },
    };
    adapters.xss_workshop = {
      async bulkResetReplaySafe(){
        const composition=await load('./xssParentResetComposition').getXssParentResetComposition();
        if(typeof composition?.reset!=='function'||typeof composition?.assertReady!=='function')return false;
        await composition.assertReady();return true;
      },
      async assertStudentResetAdmitted(ownerId, lifecycle) {
        const identityPool = load('./postgresIdentityAdapter').getPostgresIdentityAdapter().pool;
        const journal = load('../database/postgres/xssParentResetJournalRepository')
          .createXssParentResetJournalRepository(identityPool);
        try {
          await journal.assertMutationAdmitted(ownerId);
        } catch (error) {
          if (['XSS_PARENT_RESET_UNAVAILABLE', 'XSS_PARENT_RESET_STALE'].includes(error?.code)) {
            error.statusCode = 503;
          }
          throw error;
        }
        await load('./xssMutationAdmission')
          .configuredXssProfileResetPendingCheck(ownerId, lifecycle);
      },
      reset: (owner, work) => load('../routes/xssWorkshop').resetOwner(owner, work),
      async clear(owner) {
        const store = load('../database/postgres/xssWorkshopDb');
        await store.resetProgress(owner, null);
        await store.resetProfile(owner);
      },
      async preflightAdministrative() {
        const composition = await load('./xssParentResetComposition').getXssParentResetComposition();
        if (typeof composition?.assertReady !== 'function' || typeof composition?.reset !== 'function') {
          throw Object.assign(new Error('Durable XSS parent reset is not ready'), {
            code: 'RESET_STORAGE_NOT_READY', statusCode: 503,
          });
        }
        await composition.assertReady();
      },
      async resetAdministrativeOwner(ownerId, { operationId, lifecycle } = {}) {
        const composition = await load('./xssParentResetComposition').getXssParentResetComposition();
        if (typeof composition?.reset !== 'function') {
          throw Object.assign(new Error('Durable XSS parent reset is not ready'), {
            code: 'RESET_STORAGE_NOT_READY', statusCode: 503,
          });
        }
        return composition.reset({ ownerId, operationId, lifecycle });
      },
    };
    adapters.direct_prompt_injection = {
      reset: (owner, work) => load('../routes/promptInjectionWorkshop').resetOwner(owner, work),
      // DPI has no separate challenge database. Canonical progress, generation,
      // and the two-interaction activity counter are cleared together below by
      // workshopProgressRepository.resetWorkshopProgress().
      clear: async () => {},
    };
    const indirectState = () => {
      const rag = load('../routes/ragInjection');
      const email = load('../routes/emailAgent');
      const artifacts = load('./emailArtifactStore');
      if (typeof rag?.resetOwner !== 'function' || typeof rag?.clearOwnerState !== 'function'
          || typeof email?.resetOwner !== 'function' || typeof artifacts?.retireOwner !== 'function'
          || typeof artifacts?.assertReady !== 'function') {
        throw Object.assign(new Error('Indirect PI durable reset is not ready'), {
          code: 'RESET_STORAGE_NOT_READY', statusCode: 503,
        });
      }
      return { rag, email, artifacts };
    };
    adapters.indirect_prompt_injection = {
      bulkResetReplaySafe: () => Boolean(load('../routes/ragInjection').durableRagComposition?.()),
      resetOwnerIncludesCanonical: true,
      preflight: async () => { await indirectState().artifacts.assertReady(); },
      async resetOwner(owner, { resetCanonical, actorRequest, operationId } = {}) {
        if (typeof resetCanonical !== 'function') throw new TypeError('Canonical progress reset required');
        const { rag, email, artifacts } = indirectState();
        const durable=rag.durableRagComposition?.();
        return rag.resetOwner(String(owner), async execution => {
          const cleanup=async()=>{
          if(!durable) await rag.clearOwnerState(String(owner));
          await email.resetOwner(String(owner), async () => {
            await artifacts.retireOwner({ ownerId:Number(owner),
              ownerKey:JSON.stringify(['IndirectEmail', String(owner)]) });
            await resetCanonical();
          });
          };
          if(durable){
            const request=await durable.resolveRequest(actorRequest);
            return request.reset(execution,{family:'RAG',targetOwnerId:Number(owner),operationId,afterErase:cleanup});
          }
          await cleanup();
        });
      },
    };
    const sensitiveInfoAggregate = async () => {
      const composition = await load('./sensitiveInfoResetComposition').getSensitiveInfoResetComposition();
      if (typeof composition?.reset?.reset !== 'function') {
        throw Object.assign(new Error('Canonical Sensitive Information reset is not ready'), {
          code: 'RESET_STORAGE_NOT_READY', statusCode: 503,
        });
      }
      return composition.reset;
    };
    { // Lazy adapter: resetAll enumerates the canonical catalog, not this registry.
      const legacyReset=async()=>{
        const composition=await load('./legacySensitiveCandidateComposition').getLegacySensitiveCandidateComposition({legacyRuns:load('./legacySensitiveRunCoordinator').legacySensitiveRuns});
        if(typeof composition?.reset?.reset!=='function')throw Object.assign(new Error('Legacy file/SSI reset is unavailable'),{code:'RESET_STORAGE_NOT_READY',statusCode:503});
        return composition.reset;
      };
      adapters.legacy_sensitive_file_ssi={preflight:async()=>{await legacyReset();},bulkResetReplaySafe:async()=>{await legacyReset();return true;},resetOwner:async(owner,options)=>(await legacyReset()).reset(owner,options)};
    }
    adapters.sensitive_info_disclosure = {
      preflight: async () => { await sensitiveInfoAggregate(); },
      resetOwner: async (owner, options) => (await sensitiveInfoAggregate()).reset(owner, options),
    };
    adapters.supply_chain_rce = {
      reset:(owner,work)=>load('../routes/supplyChainWorkshop').resetOwner(owner,work),
      clear:owner=>load('../database/postgres/supplyChainWorkshopDb').resetUser(owner),
    };
    adapters.excessive_agency = {
      reset:(owner,work)=>load('../routes/excessiveAgencyLab').resetOwner(owner,work),
      async clear(owner){await (await load('./excessiveAgencyAttendeeLabStore').excessiveAgencyAttendeeLabStore.getOrCreate(owner)).database.reset();},
    };
    adapters.secureshop_agent_security = {
      async bulkResetReplaySafe(){await load('./secureshopOwnerResetService').getSecureShopOwnerResetService().assertReady();return true;},
      preflight: () => load('./secureshopOwnerResetService').getSecureShopOwnerResetService().assertReady(),
      resetOwner: (owner, options) => load('./secureshopOwnerResetService').getSecureShopOwnerResetService()
        .resetOwner(Number(owner), options),
    };
    return adapters;
}
let service;
function getPostgresWorkshopResetService() {
  if (!service) {
    const {
      progress,
      pool
    } = require('./postgresPlatformStores').getPostgresPlatformStores();
    const withStudentResetAdmission = createLazyStudentResetAdmission({
      createLifecyclePool: () => require('../database/postgres').createPool(
        process.env, 'IDENTITY_DATABASE_URL', { purpose:'lease' }),
    });
    const adapters = createPostgresWorkshopResetAdapters();
    const bulk=require('./adminBulkResetComposition').createAdminBulkResetComposition({pool,identityAdapter:require('./postgresIdentityAdapter').getPostgresIdentityAdapter(),createLeasePool:()=>require('../database/postgres').createPool(process.env,'IDENTITY_DATABASE_URL',{purpose:'lease'})});
    service = createPostgresWorkshopResetService({
      bulkJournal:bulk.bulkJournal,resolveBulkActor:bulk.resolveBulkActor,
      progress,
      adapters,
      listUserIds: () => listPostgresStudentIds(pool),
      withStudentResetAdmission,
    });
  }
  return service;
}
module.exports = {
  createPostgresWorkshopResetService,
  createPostgresWorkshopResetAdapters,
  listPostgresStudentIds,
  withPostgresStudentResetAdmission,
  createLazyStudentResetAdmission,
  getPostgresWorkshopResetService
};
