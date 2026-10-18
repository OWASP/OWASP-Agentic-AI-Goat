'use strict';
// A cursor is a position, never authority. Every query must independently apply
// all canonical launch coordinates and its current filters.
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$/;
function invalid() { throw Object.assign(new TypeError('Invalid audit cursor'), { code: 'INVALID_ARGUMENT' }); }
function position(value) {
  if (!value || Object.getPrototypeOf(value) !== Object.prototype
    || Object.keys(value).sort().join(',') !== 'eventId,store,ts'
    || !['agents','review'].includes(value.store) || !UUID.test(value.eventId)
    || typeof value.ts !== 'string' || !TIMESTAMP.test(value.ts)) invalid();
  const date = new Date(value.ts);
  if (!Number.isFinite(date.getTime()) || date.toISOString().slice(0, 23) !== value.ts.slice(0, 23)) invalid();
  return Object.freeze({ ts: value.ts, store: value.store, eventId: value.eventId });
}
function encodeAuditCursor(value) {
  return Buffer.from(JSON.stringify(position(value)), 'utf8').toString('base64url');
}
function decodeAuditCursor(value) {
  if (typeof value !== 'string' || value.length > 256 || !/^[A-Za-z0-9_-]+$/.test(value)) invalid();
  let parsed;
  try { parsed = JSON.parse(Buffer.from(value, 'base64url').toString('utf8')); } catch { invalid(); }
  const result = position(parsed);
  if (encodeAuditCursor(result) !== value) invalid();
  return result;
}
module.exports = { encodeAuditCursor, decodeAuditCursor };
