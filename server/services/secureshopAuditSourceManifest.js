'use strict';
const { createHash } = require('node:crypto');
const { createLaunchScope } = require('./secureshopConversationBinding');
const { encodeAuditCursor } = require('./secureshopAuditCursor');
const digest = text => createHash('sha256').update(text, 'utf8').digest('hex');

const FIELDS = ['id', 'store', 'ts', 'actor', 'action', 'target', 'params_json', 'outcome', 'source_kind', 'source_id'];
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
function exact(value, keys) {
  if (!value || Object.getPrototypeOf(value) !== Object.prototype
      || Reflect.ownKeys(value).length !== keys.length
      || keys.some(key => !Object.hasOwn(value, key) || !('value' in Object.getOwnPropertyDescriptor(value, key))))
    throw new TypeError('Invalid scene audit source');
}
function scope(value) {
  exact(value, ['launchId','scenarioId','generation','platformOwnerId','platformSessionId']);
  const result = createLaunchScope(value);
  if (Object.keys(result).some(key => result[key] !== value[key])) throw new TypeError('Invalid scene audit execution');
  return result;
}
function sceneOrigin(input, row, consumerScope) {
  exact(input, ['version','kind','sourceExecution','sourceGrant','consumerExecution','consumerGrant','scene','product']);
  if (input.version !== 2 || input.kind !== 'scene_product_listing_update') throw new TypeError('Invalid scene audit version');
  const sourceExecution = scope(input.sourceExecution), consumerExecution = scope(input.consumerExecution);
  exact(input.scene, ['sceneId','sceneGeneration','targetId','birth']);
  exact(input.product, ['productId','merchantId']);
  const scene = Object.freeze({...input.scene, birth:scope(input.scene.birth)});
  const product = Object.freeze({...input.product});
  if (![scene.sceneId,scene.targetId].every(id => typeof id === 'string' && UUID.test(id))
      || !Number.isSafeInteger(scene.sceneGeneration) || scene.sceneGeneration < 1
      || ![product.productId,product.merchantId].every(id => Number.isSafeInteger(id) && id > 0)
      || [sourceExecution,scene.birth].some(e => e.platformOwnerId !== consumerExecution.platformOwnerId)
      || (consumerScope && Object.keys(consumerExecution).some(key => consumerExecution[key] !== consumerScope[key])))
    throw new TypeError('Invalid scene audit ownership');
  function grant(value) {
    exact(value, ['grantId','sceneId','sceneGeneration','targetId']);
    if (!UUID.test(value.grantId || '') || ['sceneId','sceneGeneration','targetId'].some(key => value[key] !== scene[key]))
      throw new TypeError('Invalid scene audit grant');
    return Object.freeze({...value});
  }
  let storage;
  try { storage = JSON.parse(row.params_json).storage; } catch { throw new TypeError('Invalid scene audit storage'); }
  if (row.store !== 'review' || row.actor !== 'merchant' || row.action !== 'listing_update'
      || row.outcome !== 'completed' || row.source_kind !== 'product'
      || row.source_id !== String(product.productId) || row.target !== row.source_id
      || storage?.targetId !== scene.targetId || storage?.sceneId !== scene.sceneId
      || storage?.birthLaunchId !== scene.birth.launchId || storage?.birthGeneration !== scene.birth.generation)
    throw new TypeError('Invalid scene audit event');
  return Object.freeze({version:2,kind:input.kind,sourceExecution,sourceGrant:grant(input.sourceGrant),
    consumerExecution,consumerGrant:grant(input.consumerGrant),scene,product});
}
const eventHash = row => digest(JSON.stringify([row.id,row.ts,row.actor,row.action,row.target,
  row.params_json,row.outcome,row.source_kind,row.source_id]));
function sourceEntry(row, sceneSource, fixedSource, consumerScope) {
  const base = {id:row.id,store:row.store,ts:row.ts,sourceKind:row.source_kind,sourceId:row.source_id,sha256:eventHash(row)};
  if (sceneSource !== undefined && fixedSource !== undefined) throw new TypeError('Ambiguous scene audit source');
  if (sceneSource !== undefined) return Object.freeze({version:2,...base,event:Object.freeze(row),
    origin:sceneOrigin(sceneSource,row,consumerScope)});
  if (fixedSource !== undefined) {
    exact(fixedSource,['version','id','store','ts','sourceKind','sourceId','sha256','event','origin']);
    exact(fixedSource.event,FIELDS);
    const original = sourceEntry({...fixedSource.event},fixedSource.origin,undefined,consumerScope);
    if (JSON.stringify(original) !== JSON.stringify(fixedSource)
        || row.id !== original.id || row.store !== original.store || row.ts !== original.ts
        || row.actor !== 'recorded_actor' || row.action !== 'recorded_event'
        || row.target !== 'sha256:'+original.sha256 || row.source_kind !== 'audit_metadata_projection'
        || row.source_id !== original.sha256 || row.outcome !== original.event.outcome
        || row.params_json !== JSON.stringify({outcome:original.event.outcome,store:original.store}))
      throw new TypeError('Invalid fixed scene audit source');
    return Object.freeze({version:2,...base,original});
  }
  return Object.freeze(base);
}

// Evidence preparation only: this function does not run a model or grant credit.
function createAuditSourceManifest(events, { consumerScope } = {}) {
  if (!Array.isArray(events)) throw new TypeError('Audit source rows required');
  const ids = new Set();
  const rows = [], sources = [];
  if (consumerScope) consumerScope = createLaunchScope(consumerScope);
  for (const input of events) {
    if (!input || typeof input !== 'object') throw new TypeError('Invalid audit source row');
    // Read each field once so the observation and provenance use the same snapshot.
    const row = Object.fromEntries(FIELDS.map(key => [key, input[key]]));
    if (!['agents', 'review'].includes(row.store) || typeof row.id !== 'string'
      || !row.id.startsWith(`${row.store}:`) || ids.has(row.id)
      || ['ts', 'actor', 'action', 'params_json', 'source_kind', 'source_id'].some(key => typeof row[key] !== 'string')
      || !['completed', 'denied', 'failed'].includes(row.outcome)
      || (row.target !== null && typeof row.target !== 'string')) throw new TypeError('Invalid audit source row');
    encodeAuditCursor({ ts: row.ts, store: row.store, eventId: row.id.slice(row.store.length + 1) });
    ids.add(row.id);
    rows.push(row);
    sources.push(sourceEntry(row,input.sceneSource,input.fixedSource,consumerScope));
  }
  const logText = rows.map(row => `[${row.ts}] actor=${row.actor} action=${row.action} target=${row.target || '-'} params=${row.params_json}`).join('\n');
  return Object.freeze({ version: 1, rowCount: rows.length, logText, logSha256: digest(logText),
    sources: Object.freeze(sources), sourcesSha256: digest(JSON.stringify(sources)) });
}
module.exports = { createAuditSourceManifest };
