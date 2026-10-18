'use strict';
const {randomUUID} = require('node:crypto');
const {WORKSHOP_KEY, objectiveId} = require('../config/xssEmailBuilderCurriculum');
function failure(code) { return Object.assign(new Error(code), {code, statusCode:503}); }
function createXssEmailBuilderCanonical({pool, config, progress, completion, store} = {}) {
  if (!pool?.query || !config?.getSnapshot || !progress?.getVisibleUserProgress || !completion?.beginAttempt || !store?.clearBuilder) throw new TypeError('Canonical builder dependencies required');
  const pending = async owner => (await pool.query("SELECT * FROM identity.xss_email_builder_resets WHERE owner_id=$1 AND status='pending'", [owner])).rows[0];
  async function admit(owner, execution) {
    await execution.check();
    if (await pending(owner)) throw failure('BUILDER_RESET_PENDING');
    const snapshot = await config.getSnapshot();
    const workshop = snapshot.exercises[WORKSHOP_KEY];
    if (!workshop?.isVisible) throw failure('OBJECTIVE_DISABLED');
    await execution.check();
    return workshop;
  }
  return Object.freeze({
    admit,
    async cancelBeforeReset({owner,operationId,runs,check=async()=>{}}) {
      await check();
      if(operationId!==undefined){
        if(typeof operationId!=='string'||!/^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i.test(operationId))throw new TypeError('Reset operation ID must be a UUID');
        const prior=(await pool.query('SELECT * FROM identity.xss_email_builder_resets WHERE operation_id=$1',[operationId.toLowerCase()])).rows[0];
        await check();
        if(prior && Number(prior.owner_id)!==owner)throw failure('BUILDER_RESET_SCOPE_MISMATCH');
        if(prior?.status==='completed')return;
      }
      await check();runs.cancel(String(owner));
    },
    async assertReady() {
      const row=(await pool.query("SELECT to_regclass('identity.xss_email_builder_resets') IS NOT NULL AND has_function_privilege(current_user,'identity.begin_xss_email_builder_reset(integer,uuid)','EXECUTE') AND has_function_privilege(current_user,'identity.finish_xss_email_builder_reset(integer,uuid,bigint,bigint)','EXECUTE') AS ready")).rows[0];
      if(!row?.ready)throw failure('BUILDER_RESET_UNAVAILABLE');
      await store.assertBuilderResetReady();return true;
    },
    async begin(owner, level, execution) {
      const workshop = await admit(owner, execution);
      const id = objectiveId(level);
      if (!workshop.objectives[id]?.isVisible) throw failure('OBJECTIVE_DISABLED');
      return completion.beginAttempt({userId:owner,workshopKey:WORKSHOP_KEY,objectiveId:id,execution});
    },
    evaluate: input => completion.evaluate({...input,workshopKey:WORKSHOP_KEY}),
    async snapshot(owner) {
      const rows = await progress.getVisibleUserProgress(owner);
      return rows.find(row => row.workshopKey === WORKSHOP_KEY) || null;
    },
    async reset({owner, operationId, lifecycle, runs, sessionCheck = async()=>{}}) {
      if (lifecycle?.ownerId !== owner || typeof lifecycle.check !== 'function') throw new TypeError('Held owner lifecycle required');
      if (operationId !== undefined && (typeof operationId !== 'string' || !/^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i.test(operationId))) throw new TypeError('Reset operation ID must be a UUID');
      const check = async()=>{await lifecycle.check();await sessionCheck();};
      await check();
      const requested=operationId ? operationId.toLowerCase() : (await pending(owner))?.operation_id || randomUUID();
      await check();
      const intent=(await pool.query('SELECT * FROM identity.begin_xss_email_builder_reset($1,$2)',[owner,requested])).rows[0];
      await check();
      if (!intent || Number(intent.owner_id)!==owner || intent.operation_id!==requested) throw failure('BUILDER_RESET_SCOPE_MISMATCH');
      if(intent.status==='completed')return intent;
      let result;
      await runs.reset(String(owner),async execution=>{
        const current=async()=>{await check();await execution.check();};
        await current();
        const receipt=await store.clearBuilder(intent);
        await current();
        for(const key of ['operation_id','owner_id','from_generation','to_generation']) {
          if(String(receipt?.[key])!==String(intent[key]))throw failure('BUILDER_RESET_RECEIPT_MISMATCH');
        }
        result=(await pool.query('SELECT * FROM identity.finish_xss_email_builder_reset($1,$2,$3,$4)',
          [owner,intent.operation_id,intent.from_generation,intent.to_generation])).rows[0];
        await current();
        if(result?.status!=='completed' || ['operation_id','owner_id','from_generation','to_generation'].some(key=>String(result[key])!==String(intent[key])))throw failure('BUILDER_RESET_RECEIPT_MISMATCH');
      });
      return result;
    },
  });
}
let configured;
function getXssEmailBuilderCanonical() {
  if (!configured) {
    const stores=require('./postgresPlatformStores').getPostgresPlatformStores();
    configured=createXssEmailBuilderCanonical({...stores,
      completion:require('./objectiveCompletionService').getObjectiveCompletionService(),
      store:require('../database/postgres/xssWorkshopDb').emailBuilder});
  }
  return configured;
}
module.exports={createXssEmailBuilderCanonical,getXssEmailBuilderCanonical};
