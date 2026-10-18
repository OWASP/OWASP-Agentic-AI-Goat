'use strict';
const fs = require('node:fs/promises');
const { constants } = require('node:fs');
const path = require('node:path');
const { createHash } = require('node:crypto');
const { createConversationBinding, createLaunchScope } = require('../../services/secureshopConversationBinding');
const { verifyAuditWorkerArtifacts } = require('../../services/secureshopAuditArtifactVerification');
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const invalid = () => Object.assign(new Error('Invalid audit run publication'), { code: 'AUDIT_RUN_INVALID' });
const personaInvalid = () => Object.assign(new Error('Shop authentication required'), { code: 'SHOP_AUTH_INVALID' });
const publicationUncertain = cause => Object.assign(new Error('Audit run publication outcome uncertain'), {
  code: 'AUDIT_RUN_PUBLICATION_UNCERTAIN', executionBoundary: true, cause,
});
const COLUMNS = ['run_id','request_id','launch_id','scenario_id','generation','original_platform_owner_id',
  'original_platform_session_id','shop_user_id','owner_key','durable_generation','effect_key','requested_count',
  'row_count','provider','model','summary'];
function createSecureShopAuditRunRepository({ pool, checkCurrent } = {}) {
  if (typeof pool?.connect !== 'function' || typeof checkCurrent !== 'function') throw new TypeError('Bound audit publication dependencies required');
  return Object.freeze({
    async publish({ scope, persona, requestId, execution, effectKey, spool, result, signal } = {}, personaFence) {
      const binding = createConversationBinding(scope, persona);
      if (binding.role !== 'admin' || !UUID.test(requestId) || !UUID.test(execution?.runId)
          || typeof execution.ownerKey !== 'string' || !execution.ownerKey || execution.ownerKey.length > 1024
          || !/^(0|[1-9][0-9]*)$/.test(String(execution.durableGeneration))
          || typeof effectKey !== 'string' || !effectKey || Buffer.byteLength(effectKey) > 1024
          || spool?.manifest?.runId !== execution.runId || result?.runId !== execution.runId
          || JSON.stringify(createLaunchScope(spool.manifest.scope)) !== JSON.stringify(createLaunchScope(binding))
          || result.provider !== 'ollama' || typeof result.model !== 'string' || !result.model || Buffer.byteLength(result.model)>256
          || typeof result.summary !== 'string' || !result.summary || Buffer.byteLength(result.summary)>65536
          || result.logSha256 !== spool.manifest.logSha256 || result.sourcesSha256 !== spool.manifest.sourcesSha256
          || result.rowCount !== spool.manifest.rowCount || result.objectiveCredit !== false) throw invalid();
      const manifest = structuredClone(spool.manifest);
      const values = [execution.runId,requestId,binding.launchId,binding.scenarioId,binding.generation,
        binding.platformOwnerId,binding.platformSessionId,binding.shopUserId,execution.ownerKey,String(execution.durableGeneration),
        effectKey,manifest.requestedCount,manifest.rowCount,result.provider,result.model,result.summary];
      const check = async () => { signal?.throwIfAborted(); await checkCurrent(binding); signal?.throwIfAborted(); };
      if (personaFence !== undefined) {
        const authority = personaFence?.binding;
        if (typeof personaFence?.withPersonaEffect !== 'function' || !authority
            || ['launchId','scenarioId','generation','platformOwnerId','platformSessionId'].some(key => authority[key] !== binding[key])
            || authority.personaId !== binding.shopUserId || authority.role !== binding.role) throw personaInvalid();
      }
      const references = await verifyAuditWorkerArtifacts({ directory: spool.directory,
        artifacts: result.artifacts, manifest, checkCurrent: check, signal });
      const files = [];
      for (const name of ['log','sources','messages','traces','effects']) {
        const filename = path.join(spool.directory, name === 'log' ? 'log.txt' : `${name}.json`);
        const ref = references[name] || { sha256: name === 'log' ? manifest.logSha256 : manifest.sourcesSha256,
          bytes: (await fs.lstat(filename)).size };
        files.push({ name, filename, ...ref });
      }
      await check();
      const publishWithClient = async client => {
        if (typeof client?.query !== 'function') throw personaInvalid();
        const leaseDeadline = Date.now() + 120000;
        const inLeaseCheck = personaFence === undefined ? check : async () => {
          signal?.throwIfAborted();
          if (Date.now() > leaseDeadline) throw Object.assign(new Error('Audit run publication deadline exceeded'), { code: 'AUDIT_RUN_TIMEOUT' });
        };
        await inLeaseCheck();
        await client.query("SET LOCAL statement_timeout='10s'");
        await client.query("SET LOCAL idle_in_transaction_session_timeout='30s'");
        if (personaFence !== undefined) await client.query("SET LOCAL transaction_timeout='120s'");
        await client.query("SELECT pg_advisory_xact_lock(hashtextextended('secureshop-bound-audit-owner:' || $1::text,0))", [binding.platformOwnerId]);
        // Publication is one transaction; any stream/hash/fence failure rolls
        // back the run and every chunk, including a final post-write mismatch.
        await client.query(`INSERT INTO secureshop_agents.bound_audit_runs (${COLUMNS.join(',')}) VALUES (${values.map((_,i)=>'$'+(i+1)).join(',')})`, values);
        for (const file of files) {
          await inLeaseCheck();
          await client.query('INSERT INTO secureshop_agents.bound_audit_run_artifacts(run_id,artifact,bytes,sha256) VALUES($1,$2,$3,$4)',
            [values[0],file.name,file.bytes,Buffer.from(file.sha256,'hex')]);
          const handle = await fs.open(file.filename,constants.O_RDONLY|constants.O_NOFOLLOW);
          try {
            const before = await handle.stat();
            if (!before.isFile() || before.size !== file.bytes) throw invalid();
            const hash = createHash('sha256'); let bytes = 0, ordinal = 0;
            for (;;) {
              const buffer = Buffer.alloc(65536); let filled = 0;
              while (filled < buffer.length) {
                await inLeaseCheck();
                const { bytesRead } = await handle.read(buffer,filled,buffer.length-filled,null);
                if (!bytesRead) break; filled += bytesRead;
              }
              if (!filled) break;
              bytes += filled; if (bytes>file.bytes) throw invalid();
              const content = buffer.subarray(0,filled); hash.update(content);
              await inLeaseCheck();
              await client.query('INSERT INTO secureshop_agents.bound_audit_run_chunks(run_id,artifact,ordinal,content) VALUES($1,$2,$3,$4)',
                [values[0],file.name,ordinal++,content]);
            }
            const after = await handle.stat();
            if (bytes!==file.bytes || after.size!==before.size || after.mtimeMs!==before.mtimeMs || hash.digest('hex')!==file.sha256) throw invalid();
          } finally { await handle.close(); }
        }
        await inLeaseCheck();
        await client.query('INSERT INTO secureshop_agents.bound_audit_run_publications(run_id) VALUES($1)',[values[0]]);
        await inLeaseCheck();
        return Object.freeze({ runId: values[0], requestId, published: true, objectiveCredit: false,
          artifacts: Object.freeze(Object.fromEntries(files.map(file => [file.name,Object.freeze({bytes:file.bytes,sha256:file.sha256})]))) });
      };
      if (personaFence !== undefined) {
        let callbackStarted=false,callbackCompleted=false,published;
        try {
          published = await personaFence.withPersonaEffect(async (client, authority) => {
            callbackStarted=true;
            if (!authority || ['launchId','scenarioId','generation','platformOwnerId','platformSessionId'].some(key => authority[key] !== binding[key])
                || authority.personaId !== binding.shopUserId || authority.role !== binding.role) throw personaInvalid();
            const value=await publishWithClient(client);callbackCompleted=true;return value;
          });
        } catch(error) {
          if(callbackCompleted)throw publicationUncertain(error);
          if(!callbackStarted)throw error;
          throw error;
        }
        // The persona effect has committed when it returns. Any later failure
        // is uncertain and must never be described as a rollback.
        let reader, readbackError;
        try {
          signal?.throwIfAborted(); reader = await pool.connect();
          const row = (await reader.query(`SELECT r.run_id,r.request_id,r.owner_key,r.durable_generation,r.effect_key,
            r.requested_count,r.row_count,r.provider,r.model,r.summary,
            (SELECT jsonb_object_agg(a.artifact,jsonb_build_object('bytes',a.bytes,'sha256',encode(a.sha256,'hex')))
              FROM secureshop_agents.bound_audit_run_artifacts a WHERE a.run_id=r.run_id) AS artifacts
            FROM secureshop_agents.bound_audit_runs r
            JOIN secureshop_agents.bound_audit_run_publications p USING(run_id)
            WHERE r.run_id=$1 AND r.launch_id=$2 AND r.scenario_id=$3 AND r.generation=$4
            AND r.original_platform_owner_id=$5 AND r.original_platform_session_id=$6 AND r.shop_user_id=$7`,
          [values[0],binding.launchId,binding.scenarioId,binding.generation,binding.platformOwnerId,binding.platformSessionId,binding.shopUserId])).rows[0];
          const artifactsMatch=row?.artifacts&&typeof row.artifacts==='object'&&!Array.isArray(row.artifacts)
            &&Object.keys(row.artifacts).length===files.length&&files.every(file=>
              Number(row.artifacts[file.name]?.bytes)===file.bytes&&row.artifacts[file.name]?.sha256===file.sha256);
          if (row?.run_id !== values[0] || row.request_id !== requestId || row.owner_key !== execution.ownerKey
              || String(row.durable_generation) !== String(execution.durableGeneration) || row.effect_key !== effectKey
              || Number(row.requested_count) !== manifest.requestedCount || Number(row.row_count) !== manifest.rowCount
              || row.provider !== result.provider || row.model !== result.model || row.summary !== result.summary
              || !artifactsMatch) throw invalid();
          signal?.throwIfAborted();
        } catch (error) { readbackError=error; }
        finally { try { reader?.release(); } catch (error) { readbackError ||= error; } }
        if(readbackError)throw publicationUncertain(readbackError);
        return published;
      }
      const client = await pool.connect(); let broken;
      try {
        await client.query('BEGIN');
        const published = await publishWithClient(client);
        await client.query('COMMIT'); await check(); return published;
      } catch (error) {
        try { await client.query('ROLLBACK'); } catch (rollback) { broken = rollback; }
        throw error;
      } finally { client.release(broken); }
    },
  });
}
module.exports = { createSecureShopAuditRunRepository };
