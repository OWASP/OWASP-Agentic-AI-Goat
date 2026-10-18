import { trustedTurnMode } from './turnModeCapability.mjs';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const CURSOR = /^[A-Za-z0-9_-]{1,256}$/;
const DATE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$/;
const encoder = new TextEncoder();
const exact = (value, keys) => value && Object.getPrototypeOf(value) === Object.prototype
  && Object.keys(value).sort().join(',') === keys.slice().sort().join(',');
const text = (value, maximum, nullable = false) => (nullable && value === null)
  || (typeof value === 'string' && !!value.length && value.isWellFormed()
    && encoder.encode(value).byteLength <= maximum);
const validMode = value => exact(value, ['version', 'featureId', 'policyVersion', 'effectiveMode', 'scope'])
  && exact(value.scope, ['kind', 'id']) && !!trustedTurnMode(value)
  && value.featureId === 'admin_assistant'
  && value.policyVersion === 'owned-admin-read-and-confirmation-v1'
  && value.scope.kind === 'launch_feature' && value.scope.id === 'admin_assistant';

function event(value) {
  if (!exact(value, ['store', 'id', 'event_id', 'ts', 'actor', 'action', 'target',
    'params_json', 'outcome', 'source_kind', 'source_id', 'ip', 'user_agent'])
    || !['agents', 'review'].includes(value.store)
    || !UUID.test(value.event_id) || value.id !== `${value.store}:${value.event_id}`
    || typeof value.ts !== 'string' || !DATE.test(value.ts)
    || !Number.isFinite(Date.parse(value.ts))
    || !text(value.actor, 128) || !text(value.action, 128)
    || !text(value.target, 1024, true) || !text(value.params_json, 16384)
    || !['completed', 'denied', 'failed'].includes(value.outcome)
    || !text(value.source_kind, 128) || !text(value.source_id, 256)
    || value.ip !== null || value.user_agent !== null) return null;
  try { JSON.parse(value.params_json); } catch { return null; }
  return Object.freeze({ ...value });
}

// Only the protected completed role-turn GET supplies this saved hop. The
// streamed observation and model's prose are never read by this decoder.
export function decodeAdminAuditRead(hops, modeCapability, stopReason) {
  if (!Array.isArray(hops) || !validMode(modeCapability) || stopReason !== 'end_turn') return null;
  const reads = hops.filter(hop => hop?.tool === 'admin.audit_recent'
    && !hop.error && hop.result?.isError !== true);
  if (!reads.length) return null;
  const result = reads.at(-1).result;
  if (!exact(result, ['content']) || !Array.isArray(result.content) || result.content.length !== 1
    || !exact(result.content[0], ['type', 'text']) || result.content[0].type !== 'text'
    || typeof result.content[0].text !== 'string'
    || encoder.encode(result.content[0].text).byteLength > 16384) {
    throw new Error('Saved admin audit read invalid');
  }
  let page;
  try { page = JSON.parse(result.content[0].text); } catch {
    throw new Error('Saved admin audit read invalid');
  }
  if (!exact(page, ['count', 'events', 'hasMore', 'nextCursor'])
    || !Array.isArray(page.events) || page.events.length > 5
    || !Number.isInteger(page.count) || page.count !== page.events.length
    || typeof page.hasMore !== 'boolean'
    || !(page.nextCursor === null || typeof page.nextCursor === 'string'
      && CURSOR.test(page.nextCursor))
    || (!page.hasMore && page.nextCursor !== null)) {
    throw new Error('Saved admin audit read invalid');
  }
  const events = page.events.map(event);
  if (events.some(value => value === null)) throw new Error('Saved admin audit read invalid');
  return Object.freeze({ events: Object.freeze(events), hasMore: page.hasMore,
    nextPageAvailable: page.nextCursor !== null });
}
