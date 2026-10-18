'use strict';

// Unmounted foundation. Render execution is deliberately outside this repository.
const {
  canonicalDigest
} = require('../../services/mcp/protocolContext');
const {
  createLaunchScope,
  createConversationBinding
} = require('../../services/secureshopConversationBinding');
const C = 'platform_launch_id,platform_scenario_id,platform_launch_generation,original_platform_owner_id,original_platform_session_id';
const W = C.split(',').map((x, i) => `${x}=$${i + 1}`).join(' AND '),
  T = 'secureshop_agents.bound_prompt_policy_';
const uuid = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i;
const fail = code => Object.assign(Error('Bound prompt policy unavailable'), {
  code
});
const hash = value => canonicalDigest(value);
const bytes = value => Buffer.byteLength(value, 'utf8');
const taskContract = require('../../services/secureshopPromptPolicyTaskMutation');
const {isDeepStrictEqual}=require('node:util');
const {guardFeatureFence}=require('../../services/secureshopFeatureModeAuthority');
const taskSnapshots = require('../../services/secureshopPromptPolicyTaskSnapshot');
const policySnapshots = require('../../services/secureshopPromptPolicySnapshot');
const values = x => [x.scope.launchId, x.scope.scenarioId, x.scope.generation, x.scope.platformOwnerId, x.scope.platformSessionId];
function positive(value) {
  if (typeof value !== 'string' || !/^[1-9]\d*$/.test(value) || BigInt(value) >= 9007199254740991n) throw fail('INVALID_ARGUMENT');
  return value;
}
function snapshot(raw, admin = true) {
  const x = structuredClone(raw);
  x.scope = createLaunchScope(x.scope);
  createConversationBinding(x.scope, x.persona);
  if (admin && x.persona.role !== 'admin') throw fail('ADMIN_REQUIRED');
  if (!uuid.test(x.personaSession?.sessionId)) throw fail('SHOP_AUTH_INVALID');
  x.personaSession = {
    sessionId: x.personaSession.sessionId.toLowerCase(),
    authorityVersion: positive(x.personaSession.authorityVersion)
  };
  return x;
}
function operationId(value) {
  if (typeof value !== 'string' || !uuid.test(value)) throw fail('INVALID_ARGUMENT');
  return value.toLowerCase();
}
function sameActor(row, x) {
  return Number(row.persona_id) === x.persona.id && row.persona_session_id === x.personaSession.sessionId && String(row.authority_version) === x.personaSession.authorityVersion;
}
function createBoundPromptPolicyRepository({
  pool,
  personaAuthority,
  audit,
  checkRunBinding,
  modeAuthority,
  contract
} = {}) {
  if (typeof pool?.query !== 'function' || typeof personaAuthority?.capture !== 'function' || typeof audit?.append !== 'function') throw TypeError('Trusted policy repository dependencies required');
  // Explicit injectable seam supports controlled contracts; production uses the shared renderer contract.
  const rules = contract || require('../../services/secureshopPromptPolicyContract');
  if (modeAuthority !== undefined && (typeof modeAuthority?.capture !== 'function' || typeof modeAuthority?.assertToken !== 'function')) throw TypeError('Policy mode authority required');
  function executionToken(x, options) {
    if (modeAuthority === undefined) {
      if (options?.modeToken || x.execution !== undefined) throw fail('POLICY_MODE_INVALID');
      return undefined;
    }
    const token=modeAuthority.assertToken(options?.modeToken);
    if(token.snapshot.featureId!=='policy'||!isDeepStrictEqual(token.snapshot.scope,x.scope)
      || (x.execution !== undefined && !isDeepStrictEqual(x.execution,token.snapshot))) throw fail('POLICY_MODE_INVALID');
    return token;
  }
  async function transaction(x, work, write = false, modeToken) {
    const expected = {
      ...x.scope,
      personaId: x.persona.id,
      role: x.persona.role,
      sessionId: x.personaSession.sessionId,
      authorityVersion: x.personaSession.authorityVersion
    };
    let fence = await personaAuthority.capture({
      scope: x.scope,
      personaId: x.persona.id,
      role: x.persona.role,
      sessionId: x.personaSession.sessionId,
      authorityVersion: x.personaSession.authorityVersion
    });
    if (!fence?.binding || Object.keys(expected).some(k => fence.binding[k] !== expected[k]) || typeof fence.withPersonaEffect !== 'function' || typeof fence.assertRemoteAdmission !== 'function') throw fail('SHOP_AUTH_INVALID');
    if(modeToken)fence=guardFeatureFence(fence,modeToken);
    let completed = false;
    try {
      const result = await fence.withPersonaEffect(async c => {
        await c.query("SET LOCAL statement_timeout='3000ms'");
        await c.query("SET LOCAL lock_timeout='3000ms'");
        const result = await work(c);
        completed = true;
        return result;
      });
      await fence.assertRemoteAdmission();
      return result;
    } catch (cause) {
      if (write && completed) {
        const error = fail('POLICY_OUTCOME_UNCERTAIN');
        Object.defineProperty(error, 'cause', {
          value: cause
        });
        throw error;
      }
      throw cause;
    }
  }
  async function head(c, x) {
    await c.query(`INSERT INTO ${T}heads (${C}) VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING`, values(x));
    return (await c.query(`SELECT policy_version::text AS version FROM ${T}heads WHERE ${W} FOR UPDATE`, values(x))).rows[0].version;
  }
  async function count(c, x, table, limit) {
    const n = Number((await c.query(`SELECT count(*) AS n FROM ${T}${table} WHERE ${W}`, values(x))).rows[0].n);
    if (n >= limit) throw fail('POLICY_QUOTA_EXCEEDED');
  }
  async function stored(c, x, id, digest) {
    const row = (await c.query(`SELECT * FROM ${T}operations WHERE ${W} AND operation_id=$6`, [...values(x), id])).rows[0];
    if (!row) return null;
    if (!sameActor(row, x) || digest && row.mutation_sha256.toString('hex') !== digest) throw fail('OPERATION_CONFLICT');
    if (row.result_json && hash(row.result_json) !== row.result_sha256?.toString('hex')) throw fail('POLICY_INTEGRITY_UNAVAILABLE');
    return row;
  }
  const result = row => row.result_json ? {
    ...row.result_json,
    replayed: true
  } : {
    state: 'pending',
    operationId: row.operation_id
  };
  function request(raw) {
    const x = snapshot(raw);
    if (!['upsert', 'preview'].includes(x.action)) throw fail('INVALID_ARGUMENT');
    x.expectedVersion = positive(x.expectedVersion);
    x.taskPolicy = x.request?.contractVersion === 2;
    x.request = x.taskPolicy ? taskContract.normalizeTaskMutationRequest(x.request) : rules.normalizeRenderRequest(x.request);
    x.renderRequest = x.taskPolicy ? taskContract.renderRequest(x.request) : x.request;
    x.operationId = operationId(x.request.operationId);
    x.digest = hash([x.taskPolicy ? 'prompt-policy-mutation-v2' : 'prompt-policy-mutation-v1', x.scope, x.persona, x.personaSession, x.action, x.expectedVersion, x.request]);
    return x;
  }
  async function insertOperation(c, x, payload) {
    await c.query(`INSERT INTO ${T}operations (${C},operation_id,persona_id,persona_session_id,authority_version,action,expected_version,mutation_sha256,payload_json,request_sha256) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,decode($12,'hex'),$13::jsonb,decode($14,'hex'))`, [...values(x), x.operationId, x.persona.id, x.personaSession.sessionId, x.personaSession.authorityVersion, x.action, x.expectedVersion, x.digest, JSON.stringify(payload), x.request ? rules.requestDigest(x.renderRequest || x.request) : null]);
  }
  async function finalize(c, x, receipt) {
    await c.query(`UPDATE ${T}operations SET result_json=$7::jsonb,result_sha256=decode($8,'hex') WHERE ${W} AND operation_id=$6 AND result_json IS NULL`, [...values(x), x.operationId, JSON.stringify(receipt), hash(receipt)]);
    await audit.append(c, {
      eventId: x.operationId,
      scope: x.scope,
      persona: x.persona,
      actor: 'admin',
      action: `prompt_policy_${x.action}`,
      target: x.request?.name || x.name,
      paramsJson: JSON.stringify({
        operationId: x.operationId,
        version: receipt.version,
        requestSha256: receipt.requestSha256
      }),
      outcome: 'completed',
      sourceKind: 'prompt_policy_operation',
      sourceId: x.operationId
    });
    return receipt;
  }
  async function current(c, x) {
    const rows = (await c.query(`SELECT name,policy_version::text,payload_json,encode(payload_sha256,'hex') AS digest FROM ${T}current WHERE ${W} ORDER BY name`, values(x))).rows;
    for (const r of rows) if (hash(r.payload_json) !== r.digest) throw fail('POLICY_INTEGRITY_UNAVAILABLE');
    return rows;
  }
  return Object.freeze({
    async checkReadiness() {
      const identity=(await pool.query('SELECT current_user AS role')).rows[0];
      if(identity?.role!=='dvaia_secureshop_agents_runtime')throw fail('POLICY_NOT_READY');
      const tables = ['heads', 'current', 'revisions', 'operations', 'snapshots'];
      for (const table of tables) {
        const row = (await pool.query(`SELECT has_table_privilege(current_user,$1,'SELECT') AS readable,has_table_privilege(current_user,$1,'INSERT') AS appendable,has_table_privilege(current_user,$1,'UPDATE,TRUNCATE') AS broad,has_table_privilege(current_user,$1,'DELETE') AS erasable`, [T + table])).rows[0];
        if (!row?.readable || !row.appendable || row.broad || row.erasable !== (table === 'current')) throw fail('POLICY_NOT_READY');
      }
      const columns = {
        heads: ['policy_version'],
        current: ['policy_version', 'payload_json', 'payload_sha256'],
        operations: ['result_json', 'result_sha256'],
        revisions: [],
        snapshots: []
      };
      for (const [table, allowed] of Object.entries(columns)) {
        const rows = (await pool.query(`SELECT attname,has_column_privilege(current_user,attrelid,attnum,'UPDATE') AS writable FROM pg_attribute WHERE attrelid=$1::regclass AND attnum>0 AND NOT attisdropped`, [T + table])).rows;
        if (!rows.length || rows.some(row => row.writable !== allowed.includes(row.attname)) || allowed.some(name => !rows.some(row => row.attname === name))) throw fail('POLICY_NOT_READY');
      }
      const triggers = [];
      for (const table of tables) {
        triggers.push({
          rel: T + table,
          name: `prompt_policy_${table}_insert`,
          fn: 'secureshop_agents.guard_bound_persona_admin_insert()',
          kind: 7
        });
        triggers.push({
          rel: T + table,
          name: `prompt_policy_${table}_guard`,
          fn: 'secureshop_agents.guard_prompt_policy_record()',
          kind: 27
        });
      }
      triggers.push({
        rel: T + 'cleanup_receipts',
        name: 'prompt_policy_cleanup_immutable',
        fn: 'secureshop_agents.guard_bound_audit_owner_deletion_receipt()',
        kind: 27
      }, {
        rel: 'secureshop_agents.conversation_generation_retirements',
        name: 'prompt_policy_retirement',
        fn: 'secureshop_agents.cleanup_prompt_policy_records()',
        kind: 5
      }, {
        rel: 'secureshop_agents.bound_audit_owner_deletion_receipts',
        name: 'prompt_policy_owner_delete',
        fn: 'secureshop_agents.cleanup_prompt_policy_records()',
        kind: 5
      });
      triggers.push({rel:T+'operations',name:'z_prompt_policy_operations_actor',fn:'secureshop_agents.guard_prompt_policy_actor()',kind:23},{rel:T+'snapshots',name:'z_prompt_policy_snapshots_actor',fn:'secureshop_agents.guard_prompt_policy_actor()',kind:7});
      const integrity = (await pool.query(`SELECT count(*)=15 AS ready FROM jsonb_to_recordset($1::jsonb) AS e(rel text,name text,fn text,kind integer) JOIN pg_trigger t ON t.tgrelid=to_regclass(e.rel) AND t.tgname=e.name AND t.tgfoid=to_regprocedure(e.fn) AND t.tgtype=e.kind AND t.tgenabled='O' AND t.tgqual IS NULL AND NOT t.tgisinternal`, [JSON.stringify(triggers)])).rows[0];
      if (integrity?.ready !== true) throw fail('POLICY_NOT_READY');
      const functions = (await pool.query(`SELECT current_user AS role,count(*)=3 AND bool_and(p.proconfig=CASE WHEN p.proname='guard_prompt_policy_actor' THEN ARRAY['search_path=pg_catalog, secureshop_agents']::text[] ELSE ARRAY['search_path=pg_catalog']::text[] END AND p.prosecdef=(p.proname IN ('cleanup_prompt_policy_records','guard_prompt_policy_actor')) AND NOT has_function_privilege(current_user,p.oid,'EXECUTE') AND NOT EXISTS(SELECT 1 FROM aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a WHERE a.grantee=0 AND a.privilege_type='EXECUTE')) AS ready FROM pg_proc p WHERE p.oid IN(to_regprocedure('secureshop_agents.guard_prompt_policy_record()'),to_regprocedure('secureshop_agents.cleanup_prompt_policy_records()'),to_regprocedure('secureshop_agents.guard_prompt_policy_actor()'))`)).rows[0];
      if (functions?.role !== 'dvaia_secureshop_agents_runtime' || functions.ready !== true) throw fail('POLICY_NOT_READY');
      const cleanup = (await pool.query(`SELECT has_table_privilege(current_user,$1,'SELECT') AS readable,has_table_privilege(current_user,$1,'INSERT,UPDATE,DELETE,TRUNCATE') OR has_any_column_privilege(current_user,$1,'UPDATE') AS mutable`, [T + 'cleanup_receipts'])).rows[0];
      if (cleanup?.readable !== true || cleanup.mutable !== false) throw fail('POLICY_NOT_READY');
      const scoped = ['platform_launch_generation > 0', 'original_platform_owner_id > 0', 'original_platform_session_id > 0'];
      const nullableBytes = field => `${field} IS NULL OR octet_length(${field}) = 32`;
      const payload = field => `${field} IS NULL OR octet_length(${field}::text) <= 1048576`;
      const checks = {
        heads: [...scoped, 'policy_version >= 1 AND policy_version <= 9007199254740991'],
        current: [...scoped, 'octet_length(name) >= 1 AND octet_length(name) <= 80', 'policy_version > 1', 'octet_length(payload_json::text) <= 1048576', 'octet_length(payload_sha256) = 32'],
        revisions: [...scoped, 'policy_version > 1', "action = ANY (ARRAY['upsert'::text, 'delete'::text])", payload('payload_json'), 'octet_length(payload_sha256) = 32'],
        operations: [...scoped, "persona_role = 'admin'::text", "action = ANY (ARRAY['upsert'::text, 'preview'::text, 'delete'::text])", 'expected_version > 0', 'octet_length(mutation_sha256) = 32', nullableBytes('request_sha256'), payload('payload_json'), payload('result_json'), nullableBytes('result_sha256')],
        snapshots: [...scoped, "persona_role = ANY (ARRAY['customer'::text, 'merchant'::text, 'admin'::text])", 'policy_version > 0', payload('payload_json'), 'octet_length(payload_sha256) = 32'],
        cleanup_receipts: ["cleanup_kind = ANY (ARRAY['retirement'::text, 'owner_deletion'::text])", 'octet_length(receipt_sha256) = 32']
      };
      // PostgreSQL adds casts and grouping to these simple CHECK expressions.
      // Compare every expression, not only the number of validated constraints.
      const normalize = expression => expression.replace(/'([0-9]+)'::(?:bigint|integer)/g, '$1').replace(/::(?:text|bigint|integer)/g, '').replace(/[()\s]/g, '');
      for (const [table, expected] of Object.entries(checks)) {
        const rows = (await pool.query(`SELECT pg_get_expr(conbin,conrelid) AS expression,convalidated AND conenforced AS ready FROM pg_constraint WHERE conrelid=$1::regclass AND contype='c'`, [T + table])).rows;
        const actual = rows.map(row => normalize(row.expression)).sort();
        if (rows.some(row => row.ready !== true) || JSON.stringify(actual) !== JSON.stringify(expected.map(normalize).sort())) {
          const error = fail('POLICY_NOT_READY');
          Object.defineProperty(error, 'schemaDiagnostic', { value: { table, actual, expected: expected.map(normalize).sort() } });
          throw error;
        }
      }
      return {
        ready: true
      };
    },
    async list(raw) {
      const x = snapshot(raw);
      return transaction(x, async c => ({
        version: await head(c, x),
        policies: (await current(c, x)).map(r => ({
          name: r.name,
          version: r.policy_version,
          ...r.payload_json
        }))
      }));
    },
    async operation(raw) {
      const x = snapshot(raw),
        id = operationId(x.operationId);
      return transaction(x, async c => {
        const row = await stored(c, x, id);
        return row ? result(row) : null;
      });
    },
    // Private evidence projection. Read the original revision, never a later
    // current head, and do not initialize a policy head during saved readback.
    async readAssessmentPublication(raw) {
      const x = snapshot(raw), id = operationId(x.operationId);
      return transaction(x, async c => {
        const row = await stored(c, x, id);
        if (!row?.result_json) return null;
        const expectedVersion = positive(String(row.expected_version));
        const receipt = structuredClone(row.result_json);
        const wrapped = row.payload_json?.version === 2;
        let requestValue = null, execution = null, expectedPayload, name, digest;
        if (row.action === 'delete') {
          name = row.payload_json?.name;
          rules.normalizeRenderRequest({operationId:id,name,markdown:'',targets:['admin']});
          if (!isDeepStrictEqual(row.payload_json,{name})) throw fail('POLICY_INTEGRITY_UNAVAILABLE');
          digest = hash(['prompt-policy-delete-v1',x.scope,x.persona,x.personaSession,id,name,expectedVersion]);
          if (!isDeepStrictEqual(receipt,{version:(BigInt(expectedVersion)+1n).toString(),operationId:id,requestSha256:digest,deleted:true})) throw fail('POLICY_INTEGRITY_UNAVAILABLE');
          expectedPayload = {name,tombstone:true};
        } else {
          const normalized = request({...x,action:row.action,expectedVersion,request:wrapped?row.payload_json.request:row.payload_json});
          if (normalized.operationId !== id) throw fail('POLICY_INTEGRITY_UNAVAILABLE');
          requestValue = normalized.request; name = requestValue.name; digest = normalized.digest;
          if (wrapped) {
            execution = row.payload_json.execution;
            if (!isDeepStrictEqual(Object.keys(row.payload_json).sort(),['execution','request','version'])
              || !execution || !isDeepStrictEqual(Object.keys(execution).sort(),['featureId','generation','mode','modeStamp','policyVersion','scope','version'])
              || execution.version !== 1 || execution.featureId !== 'policy'
              || execution.policyVersion !== 'owned-policy-literal-render-v1'
              || !isDeepStrictEqual(execution.scope,x.scope)) throw fail('POLICY_INTEGRITY_UNAVAILABLE');
            require('../../services/secureshopAnalyticsModeAuthority').checkedMode(execution);
          }
          const rendered = wrapped
            ? rules.validateRenderExecutionResult({version:2,mode:execution.mode,request:normalized.renderRequest},receipt.renderResult)
            : rules.validateRenderResult(normalized.renderRequest,receipt.renderResult);
          const expectedReceipt = {version:row.action==='upsert'?(BigInt(expectedVersion)+1n).toString():expectedVersion,
            operationId:id,requestSha256:rules.requestDigest(normalized.renderRequest),renderResult:rendered,
            ...(normalized.taskPolicy?{policyRequestSha256:taskContract.taskMutationDigest(requestValue)}:{})};
          if (!isDeepStrictEqual(receipt,expectedReceipt) || row.request_sha256?.toString('hex') !== expectedReceipt.requestSha256) throw fail('POLICY_INTEGRITY_UNAVAILABLE');
          expectedPayload = {...(normalized.taskPolicy?{contractVersion:2}:{}),markdown:requestValue.markdown,
            targets:requestValue.targets,rendered:rendered.rendered,renderedSha256:rendered.renderedSha256};
        }
        if (row.mutation_sha256?.toString('hex') !== digest) throw fail('POLICY_INTEGRITY_UNAVAILABLE');
        const rows = (await c.query(`SELECT name,policy_version::text AS version,action,payload_json,encode(payload_sha256,'hex') AS digest FROM ${T}revisions WHERE ${W} AND operation_id=$6`,[...values(x),id])).rows;
        let revision = null;
        if (row.action === 'preview') {
          if (rows.length) throw fail('POLICY_INTEGRITY_UNAVAILABLE');
        } else {
          const r=rows[0];
          if (rows.length!==1 || r.name!==name || r.version!==receipt.version || r.action!==row.action
            || !isDeepStrictEqual(r.payload_json,expectedPayload) || hash(r.payload_json)!==r.digest) throw fail('POLICY_INTEGRITY_UNAVAILABLE');
          revision={name:r.name,version:r.version,action:r.action,payload:r.payload_json,payloadSha256:r.digest};
        }
        return structuredClone({operationId:id,action:row.action,expectedVersion,request:requestValue,execution,receipt,revision});
      });
    },
    // The assessment must consume the exact policy text saved for the original
    // admitted run. Never derive it from the mutable current-policy head.
    async readAssessmentSnapshot(raw) {
      const x = snapshot(raw), runId = operationId(x.runId);
      return transaction(x, async c => {
        const rows = (await c.query(`SELECT run_id,persona_id,persona_session_id,authority_version,persona_role,
          policy_version::text AS version,payload_json,encode(payload_sha256,'hex') AS digest
          FROM ${T}snapshots WHERE ${W} AND run_id=$6`, [...values(x), runId])).rows;
        if (!rows.length) return null;
        if (rows.length !== 1) throw fail('POLICY_INTEGRITY_UNAVAILABLE');
        const row = rows[0];
        if (row.run_id !== runId || !sameActor(row, x) || row.persona_role !== 'admin'
          || typeof row.digest !== 'string' || !row.payload_json || hash(row.payload_json) !== row.digest) {
          throw fail('POLICY_INTEGRITY_UNAVAILABLE');
        }
        let immutable;
        try {
          immutable = policySnapshots.validatePolicySnapshot(row.payload_json);
        } catch {
          throw fail('POLICY_INTEGRITY_UNAVAILABLE');
        }
        if (immutable.role !== 'admin' || immutable.policyVersion !== String(row.version)) {
          throw fail('POLICY_INTEGRITY_UNAVAILABLE');
        }
        const revisions = (await c.query(`SELECT operation_id,name,action,payload_json,
          encode(payload_sha256,'hex') AS digest FROM ${T}revisions
          WHERE ${W} AND policy_version=$6 ORDER BY operation_id LIMIT 2`,
        [...values(x), immutable.policyVersion])).rows;
        const matching = revisions.filter(revision => revision.action === 'upsert'
          && typeof revision.digest === 'string' && hash(revision.payload_json) === revision.digest
          && immutable.policies.some(policy => policy.name === revision.name
            && policy.targets.includes('admin')
            && isDeepStrictEqual(revision.payload_json?.targets, policy.targets)
            && revision.payload_json?.rendered === policy.rendered
            && revision.payload_json?.renderedSha256 === policy.renderedSha256));
        if (revisions.length !== 1 || matching.length !== 1 || !uuid.test(matching[0].operation_id || '')) {
          throw fail('POLICY_INTEGRITY_UNAVAILABLE');
        }
        return structuredClone({
          runId,
          scope: x.scope,
          persona: { id: x.persona.id, role: 'admin' },
          personaSession: x.personaSession,
          snapshot: immutable,
          publicationOperationId: matching[0].operation_id.toLowerCase()
        });
      });
    },
    async beginRender(raw, options) {
      const x = request(raw), modeToken=executionToken(x,options);
      if(modeToken&&!isDeepStrictEqual(x.execution,modeToken.snapshot))throw fail('POLICY_MODE_INVALID');
      return transaction(x, async c => {
        const version = await head(c, x),
          old = await stored(c, x, x.operationId, x.digest);
        if (old) return {
          state: old.result_json ? 'completed' : 'pending',
          operationId: x.operationId,
          requestSha256: rules.requestDigest(x.renderRequest || x.request),
          ...(x.taskPolicy ? { policyRequestSha256: taskContract.taskMutationDigest(x.request) } : {}),
          ...(old.result_json ? {
            receipt: result(old)
          } : {})
        };
        if (version !== x.expectedVersion) throw fail('REVISION_CONFLICT');
        await count(c, x, 'operations', 512);
        await insertOperation(c, x, modeToken?{version:2,request:x.request,execution:x.execution}:x.request);
        return {
          state: 'admitted',
          operationId: x.operationId,
          requestSha256: rules.requestDigest(x.renderRequest || x.request),
          ...(x.taskPolicy ? { policyRequestSha256: taskContract.taskMutationDigest(x.request) } : {})
        };
      }, true, modeToken);
    },
    async publish(raw, options) {
      const x = request(raw), modeToken=executionToken(x,options);
      if(modeToken&&!isDeepStrictEqual(x.execution,modeToken.snapshot))throw fail('POLICY_MODE_INVALID');
      const rendered = modeToken
        ? rules.validateRenderExecutionResult({version:2,mode:modeToken.snapshot.mode,request:x.renderRequest},structuredClone(raw.renderResult))
        : rules.validateRenderResult(x.renderRequest, structuredClone(raw.renderResult));
      return transaction(x, async c => {
        const version = await head(c, x),
          old = await stored(c, x, x.operationId, x.digest);
        if (!old) throw fail('POLICY_RENDER_NOT_ADMITTED');
        if(modeToken&&(!old.payload_json||old.payload_json.version!==2||!isDeepStrictEqual(old.payload_json.request,x.request)||!isDeepStrictEqual(old.payload_json.execution,x.execution)))throw fail('POLICY_MODE_INVALID');
        if (old.result_json) {
          if (hash({
            version: old.result_json.version,
            operationId: x.operationId,
            requestSha256: rendered.requestSha256,
            renderResult: rendered,
            ...(x.taskPolicy ? { policyRequestSha256: taskContract.taskMutationDigest(x.request) } : {})
          }) !== hash(old.result_json)) throw fail('OPERATION_CONFLICT');
          return result(old);
        }
        if (version !== x.expectedVersion) throw fail('REVISION_CONFLICT');
        let next = version;
        if (x.action === 'upsert') {
          const rows = await current(c, x),
            others = rows.filter(r => r.name !== x.request.name);
          if (others.length >= 32 || others.reduce((n, r) => n + bytes(r.payload_json.rendered), bytes(rendered.rendered)) > 131072) throw fail('POLICY_QUOTA_EXCEEDED');
          const candidates = [...others.map(r => ({
            name: r.name,
            targets: r.payload_json.targets,
            rendered: r.payload_json.rendered,
            renderedSha256: r.payload_json.renderedSha256
          })), {
            name: x.request.name,
            targets: x.request.targets,
            rendered: rendered.rendered,
            renderedSha256: rendered.renderedSha256
          }];
          for (const [role, recipient] of [['customer', null], ['customer', 'summarizer'], ['merchant', null], ['merchant', 'review-moderator'], ['merchant', 'listing'], ['merchant', 'analytics'], ['admin', null], ['admin', 'analytics']]) taskSnapshots.buildTaskPolicySnapshot({
            policyVersion: version,
            role, recipient,
            policies: candidates
          });
          next = (BigInt(version) + 1n).toString();
          const payload = {
            ...(x.taskPolicy ? { contractVersion: 2 } : {}),
            markdown: x.request.markdown,
            targets: x.request.targets,
            rendered: rendered.rendered,
            renderedSha256: rendered.renderedSha256
          };
          await c.query(`INSERT INTO ${T}revisions (${C},operation_id,name,policy_version,action,payload_json,payload_sha256) VALUES($1,$2,$3,$4,$5,$6,$7,$8,'upsert',$9::jsonb,decode($10,'hex'))`, [...values(x), x.operationId, x.request.name, next, JSON.stringify(payload), hash(payload)]);
          await c.query(`INSERT INTO ${T}current (${C},name,policy_version,payload_json,payload_sha256) VALUES($1,$2,$3,$4,$5,$6,$7,$8::jsonb,decode($9,'hex')) ON CONFLICT(${C},name) DO UPDATE SET policy_version=EXCLUDED.policy_version,payload_json=EXCLUDED.payload_json,payload_sha256=EXCLUDED.payload_sha256`, [...values(x), x.request.name, next, JSON.stringify(payload), hash(payload)]);
          await c.query(`UPDATE ${T}heads SET policy_version=$6 WHERE ${W}`, [...values(x), next]);
        }
        return finalize(c, x, {
          version: next,
          operationId: x.operationId,
          requestSha256: rendered.requestSha256,
          renderResult: rendered,
          ...(x.taskPolicy ? { policyRequestSha256: taskContract.taskMutationDigest(x.request) } : {})
        });
      }, true, modeToken);
    },
    async remove(raw, options) {
      const x = snapshot(raw), modeToken=executionToken(x,options);
      x.operationId = operationId(x.operationId);
      x.expectedVersion = positive(x.expectedVersion);
      x.name = rules.normalizeRenderRequest({
        operationId: x.operationId,
        name: x.name,
        markdown: '',
        targets: ['admin']
      }).name;
      x.action = 'delete';
      x.digest = hash(['prompt-policy-delete-v1', x.scope, x.persona, x.personaSession, x.operationId, x.name, x.expectedVersion]);
      return transaction(x, async c => {
        const version = await head(c, x),
          old = await stored(c, x, x.operationId, x.digest);
        if (old) return result(old);
        if (version !== x.expectedVersion) throw fail('REVISION_CONFLICT');
        if (!(await current(c, x)).some(r => r.name === x.name)) throw fail('POLICY_NOT_FOUND');
        await count(c, x, 'operations', 512);
        await insertOperation(c, x, {
          name: x.name
        });
        const next = (BigInt(version) + 1n).toString(),
          payload = {
            name: x.name,
            tombstone: true
          };
        await c.query(`INSERT INTO ${T}revisions (${C},operation_id,name,policy_version,action,payload_json,payload_sha256) VALUES($1,$2,$3,$4,$5,$6,$7,$8,'delete',$9::jsonb,decode($10,'hex'))`, [...values(x), x.operationId, x.name, next, JSON.stringify(payload), hash(payload)]);
        await c.query(`DELETE FROM ${T}current WHERE ${W} AND name=$6`, [...values(x), x.name]);
        await c.query(`UPDATE ${T}heads SET policy_version=$6 WHERE ${W}`, [...values(x), next]);
        return finalize(c, x, {
          version: next,
          operationId: x.operationId,
          requestSha256: x.digest,
          deleted: true
        });
      }, true, modeToken);
    },
    async admitRunSnapshot(raw) {
      const x = snapshot(raw, false),
        runId = operationId(x.runId);
      const taskPolicy = Object.hasOwn(x, 'policyContractVersion') || Object.hasOwn(x, 'recipient');
      if (taskPolicy) {
        if (x.policyContractVersion !== 2) throw fail('INVALID_ARGUMENT');
        taskSnapshots.buildTaskPolicySnapshot({ policyVersion: '1', role: x.persona.role, recipient: x.recipient, policies: [] });
      }
      if (typeof checkRunBinding !== 'function') throw fail('POLICY_RUN_AUTHORITY_UNAVAILABLE');
      return transaction(x, async c => {
        if(await checkRunBinding(c, {...x,runId})!==true)throw fail('POLICY_RUN_AUTHORITY_UNAVAILABLE');
        const version = await head(c, x),
          old = (await c.query(`SELECT * FROM ${T}snapshots WHERE ${W} AND run_id=$6`, [...values(x), runId])).rows[0];
        if (old) {
          if (!sameActor(old, x) || old.persona_role !== x.persona.role || !old.payload_json || hash(old.payload_json) !== old.payload_sha256.toString('hex')) throw fail('OPERATION_CONFLICT');
          if (old.payload_json.version !== (taskPolicy ? 2 : 1)) throw fail('OPERATION_CONFLICT');
          if (taskPolicy) {
            const existing = taskSnapshots.validateTaskPolicySnapshot(old.payload_json);
            if (existing.recipient !== x.recipient) throw fail('OPERATION_CONFLICT');
            return existing;
          }
          return require('../../services/secureshopPromptPolicySnapshot').validatePolicySnapshot(old.payload_json);
        }
        await count(c, x, 'snapshots', 512);
        const policies = (await current(c, x)).filter(r => taskPolicy || r.payload_json.targets.includes(x.persona.role)).map(r => ({
          name: r.name,
          rendered: r.payload_json.rendered,
          renderedSha256: r.payload_json.renderedSha256,
          targets: taskPolicy ? r.payload_json.targets : r.payload_json.targets.filter(target => ['customer', 'merchant', 'admin'].includes(target))
        }));
        const builder = taskPolicy ? taskSnapshots.buildTaskPolicySnapshot : require('../../services/secureshopPromptPolicySnapshot').buildPolicySnapshot;
        const policySnapshot = builder({
          policyVersion: version,
          role: x.persona.role,
          ...(taskPolicy ? { recipient: x.recipient } : {}),
          policies
        });
        if (bytes(JSON.stringify(policySnapshot)) > 1048576) throw fail('POLICY_QUOTA_EXCEEDED');
        await c.query(`INSERT INTO ${T}snapshots (${C},run_id,persona_id,persona_session_id,authority_version,persona_role,policy_version,payload_json,payload_sha256) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::jsonb,decode($13,'hex'))`, [...values(x), runId, x.persona.id, x.personaSession.sessionId, x.personaSession.authorityVersion, x.persona.role, version, JSON.stringify(policySnapshot), hash(policySnapshot)]);
        return policySnapshot;
      }, true);
    }
  });
}
module.exports = {
  createBoundPromptPolicyRepository
};
