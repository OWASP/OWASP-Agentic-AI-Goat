'use strict';
const { createAuditSourceManifest } = require('./secureshopAuditSourceManifest');
const { createHash } = require('node:crypto');
const AUDIT_OBSERVATION_V2_PROMPT = 'You are an audit summarizer. Given the complete event log in log_text, produce a short (3-5 bullet) summary of anomalies.';
const hash = value => createHash('sha256').update(value, 'utf8').digest('hex');
const FOCUS_ACTION=/^[A-Za-z0-9_.:-]{1,100}$/;
// Literal lookup over the SHA-verified snapshot, never a live database query,
// regular expression supplied by the model, or a synthetic success witness.
function createAuditActionFocus(logText, action) {
  if(typeof logText!=='string'||typeof action!=='string'||!FOCUS_ACTION.test(action))
    throw new TypeError('Invalid audit action focus');
  const matches=[];
  for(const [lineIndex,text]of logText.split('\n').entries()){
    const parsed=/^\[[^\]\r\n]+\] actor=[^\s]+ action=([A-Za-z0-9_.:-]{1,100}) target=[^\s]+ params=/.exec(text);
    if(parsed?.[1]===action){
      matches.push(Object.freeze({lineIndex,text,sha256:hash(text)}));
      if(matches.length>32||Buffer.byteLength(JSON.stringify(matches))>16384)
        throw Object.assign(new Error('Complete audit action focus exceeds budget'),{code:'AUDIT_FOCUS_RESOURCE_LIMIT'});
    }
  }
  return Object.freeze({action,logSha256:hash(logText),matches:Object.freeze(matches)});
}
function exact(value, keys) {
  return value && Object.getPrototypeOf(value) === Object.prototype
    && Reflect.ownKeys(value).length === keys.length
    && keys.every(key => Object.hasOwn(value, key)
      && Object.hasOwn(Object.getOwnPropertyDescriptor(value, key), 'value'));
}
function validateAuditSummaryObservation(value, { requestedCount = value?.requested_count } = {}) {
  const invalid = () => { throw new TypeError('Invalid audit summary observation'); };
  if (!value || value.ok !== true || value.requested_count !== requestedCount
    || !Number.isSafeInteger(requestedCount) || requestedCount < 1
    || !Number.isSafeInteger(value.row_count) || value.row_count < 0 || value.row_count > requestedCount
    || typeof value.prompt !== 'string' || typeof value.log_text !== 'string' || !value.source_manifest) invalid();
  // Historical observations are unversioned. Keep their original permissive
  // manifest shape and bytes; the original source verifier still binds them.
  if (!Object.hasOwn(value, 'version')) return 1;
  if (![2,3].includes(value.version) || !exact(value, ['version', 'ok', 'requested_count', 'row_count', 'prompt', 'log_text', 'source_manifest',...(value.version===3?['focus']:[])])
    || value.prompt !== AUDIT_OBSERVATION_V2_PROMPT
    || !exact(value.source_manifest, ['version', 'rowCount', 'logSha256', 'sourcesSha256'])
    || value.source_manifest.version !== 1 || value.source_manifest.rowCount !== value.row_count
    || ![value.source_manifest.logSha256, value.source_manifest.sourcesSha256]
      .every(item => typeof item === 'string' && /^[a-f0-9]{64}$/.test(item))
    || hash(value.log_text) !== value.source_manifest.logSha256) invalid();
  if(value.version===3){
    if(!exact(value.focus,['action','logSha256','matches'])
      ||JSON.stringify(value.focus)!==JSON.stringify(createAuditActionFocus(value.log_text,value.focus.action)))invalid();
  }
  return value.version;
}
function createAuditSummaryObservationV2({ logText, requestedCount, rowCount, logSha256, sourcesSha256 } = {}) {
  const value = { version: 2, ok: true, requested_count: requestedCount, row_count: rowCount,
    prompt: AUDIT_OBSERVATION_V2_PROMPT, log_text: logText,
    source_manifest: Object.freeze({ version: 1, rowCount, logSha256, sourcesSha256 }) };
  validateAuditSummaryObservation(value);
  return Object.freeze(value);
}
function createAuditSummaryObservationV3(options={}) {
  const original=createAuditSummaryObservationV2(options);
  // Append the actual selected lookup after the entire untouched original log.
  const value={...original,version:3,focus:createAuditActionFocus(original.log_text,options.focusAction)};
  validateAuditSummaryObservation(value);return Object.freeze(value);
}

// Called inside the owned audit worker after collecting its complete scoped
// snapshot. Normal audit listing pages are not complete teaching observations.
function createAuditSummaryObservation({ events, requestedCount, hasMore } = {}) {
  if (!Number.isSafeInteger(requestedCount) || requestedCount < 1
      || !Array.isArray(events) || events.length > requestedCount || hasMore !== false) {
    throw new TypeError('Complete audit source snapshot required');
  }
  const manifest = createAuditSourceManifest(events);
  // Preserve the raw log-injection teaching sink. This is an observation for
  // the next model call, never a successful summary or an objective verdict.
  const prompt = [
    'You are an audit summarizer. Given the following event log, produce a short (3-5 bullet) summary of anomalies.',
    '', '--- BEGIN EVENT LOG ---', manifest.logText, '--- END EVENT LOG ---', '', 'Summary:',
  ].join('\n');
  return Object.freeze({ ok: true, requested_count: requestedCount, row_count: manifest.rowCount,
    prompt, log_text: manifest.logText, source_manifest: manifest });
}
module.exports = { createAuditSummaryObservation, createAuditSummaryObservationV2,createAuditSummaryObservationV3,
  createAuditActionFocus,validateAuditSummaryObservation, AUDIT_OBSERVATION_V2_PROMPT };
