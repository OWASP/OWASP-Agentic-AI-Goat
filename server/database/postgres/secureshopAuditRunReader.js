'use strict';
const { createHash } = require('node:crypto');
const { createConversationBinding } = require('../../services/secureshopConversationBinding');
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const NAMES = ['log','sources','messages','traces','effects'];
const failure = code => Object.assign(new Error('Audit run evidence is unavailable'), { code });
const SCOPE = `r.run_id=$1 AND r.launch_id=$2 AND r.scenario_id=$3 AND r.generation=$4
  AND r.original_platform_owner_id=$5 AND r.original_platform_session_id=$6 AND r.shop_user_id=$7
  AND NOT EXISTS (SELECT 1 FROM secureshop_agents.bound_audit_owner_deletion_receipts d
    WHERE d.original_platform_owner_id=r.original_platform_owner_id)`;

// Server-only reader. A publication is prepared evidence, not proof that the
// enclosing durable effect completed. Every read independently checks both.
function createSecureShopAuditRunReader({ pool, checkCurrent, readCompletedEffect } = {}) {
  if (typeof pool?.query !== 'function' || typeof checkCurrent !== 'function'
      || typeof readCompletedEffect !== 'function') throw new TypeError('Audit readback dependencies required');
  return Object.freeze({
    async open({ scope, persona, runId, signal } = {}) {
      const binding = createConversationBinding(scope, persona);
      if (binding.role !== 'admin' || !UUID.test(runId)) throw failure('AUDIT_RUN_INVALID');
      const values = [runId.toLowerCase(),binding.launchId,binding.scenarioId,binding.generation,
        binding.platformOwnerId,binding.platformSessionId,binding.shopUserId];
      const check = async () => { signal?.throwIfAborted(); await checkCurrent(binding); signal?.throwIfAborted(); };
      const lookup = async () => {
        await check();
        return (await pool.query(`SELECT r.run_id,r.owner_key,r.durable_generation::text,r.effect_key,
          r.summary,r.provider,r.model,r.requested_count::text,r.row_count::text
          FROM secureshop_agents.bound_audit_runs r
          JOIN secureshop_agents.bound_audit_run_publications p USING(run_id) WHERE ${SCOPE}`, values)).rows[0];
      };
      const row = await lookup();
      if (!row) throw failure('AUDIT_RUN_UNAVAILABLE');
      const context = Object.freeze({ runId: row.run_id, ownerKey: row.owner_key, durableGeneration: row.durable_generation });
      const verifyEffect = async () => {
        await check();
        const receipt = await readCompletedEffect(context,row.effect_key);
        if (!receipt || receipt.status !== 'completed' || receipt.runId !== context.runId
            || receipt.ownerKey !== context.ownerKey || String(receipt.generation) !== context.durableGeneration
            || receipt.effectKey !== row.effect_key) throw failure('AUDIT_RUN_EFFECT_UNVERIFIED');
        await check();
      };
      await verifyEffect();
      const manifests = (await pool.query(`SELECT a.artifact,a.bytes::text,a.sha256
        FROM secureshop_agents.bound_audit_run_artifacts a
        JOIN secureshop_agents.bound_audit_runs r USING(run_id)
        JOIN secureshop_agents.bound_audit_run_publications p USING(run_id) WHERE ${SCOPE}`, values)).rows;
      const refs = {};
      for (const item of manifests) {
        const bytes = Number(item.bytes);
        if (!NAMES.includes(item.artifact) || refs[item.artifact] || !Number.isSafeInteger(bytes)
            || bytes < 0 || bytes > 134217728 || !Buffer.isBuffer(item.sha256) || item.sha256.length !== 32)
          throw failure('AUDIT_RUN_INTEGRITY');
        refs[item.artifact] = Object.freeze({ bytes, sha256: item.sha256.toString('hex') });
      }
      if (Object.keys(refs).length !== 5 || refs.log.bytes+refs.sources.bytes > 67108864
          || refs.messages.bytes+refs.traces.bytes+refs.effects.bytes > 134217728) throw failure('AUDIT_RUN_INTEGRITY');
      await verifyEffect();
      return Object.freeze({
        runId: context.runId, summary: row.summary, provider: row.provider, model: row.model,
        requestedCount: Number(row.requested_count), rowCount: Number(row.row_count),
        artifacts: Object.freeze(refs), objectiveCredit: false,
        // Consumers must fully consume the iterator before treating its contents
        // as verified. A partial stream never establishes artifact integrity.
        async *readArtifact(name) {
          if (!NAMES.includes(name)) throw failure('AUDIT_RUN_INVALID');
          const ref = refs[name], hash = createHash('sha256'); let ordinal = 0, bytes = 0;
          await verifyEffect();
          for (;;) {
            await check();
            const chunks = (await pool.query(`SELECT c.ordinal,c.content,c.content_sha256
              FROM secureshop_agents.bound_audit_run_chunks c
              JOIN secureshop_agents.bound_audit_runs r USING(run_id)
              JOIN secureshop_agents.bound_audit_run_publications p USING(run_id)
              WHERE ${SCOPE} AND c.artifact=$8 AND c.ordinal >= $9 ORDER BY c.ordinal LIMIT 8`,
            [...values,name,ordinal])).rows;
            if (!chunks.length) break;
            for (const chunk of chunks) {
              await check();
              if (chunk.ordinal !== ordinal || !Buffer.isBuffer(chunk.content) || chunk.content.length < 1
                  || chunk.content.length > 65536 || bytes+chunk.content.length > ref.bytes
                  || (bytes+chunk.content.length < ref.bytes && chunk.content.length !== 65536)
                  || !Buffer.isBuffer(chunk.content_sha256)
                  || !createHash('sha256').update(chunk.content).digest().equals(chunk.content_sha256))
                throw failure('AUDIT_RUN_INTEGRITY');
              ordinal++; bytes += chunk.content.length; hash.update(chunk.content);
              yield chunk.content;
            }
          }
          if (bytes !== ref.bytes || hash.digest('hex') !== ref.sha256) throw failure('AUDIT_RUN_INTEGRITY');
          if (!await lookup()) throw failure('AUDIT_RUN_UNAVAILABLE');
          await verifyEffect();
        },
      });
    },
  });
}
module.exports = { createSecureShopAuditRunReader };
