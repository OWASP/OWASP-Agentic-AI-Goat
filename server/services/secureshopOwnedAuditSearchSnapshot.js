'use strict';
const { createHash } = require('node:crypto');
const { createLaunchScope } = require('./secureshopConversationBinding');
const { createAuditSourceManifest } = require('./secureshopAuditSourceManifest');
const receipts = new WeakMap();
const requests = new WeakMap();
const hash = value => createHash('sha256').update(JSON.stringify(value)).digest('hex');
const fields = Object.freeze(['id','store','ts','actor','action','target','params_json','outcome','source_kind','source_id']);
function invalid(message) { return Object.assign(new Error(message), { code: 'AUDIT_SEARCH_SNAPSHOT_UNAVAILABLE' }); }
// Server composition supplies both functions. No caller-supplied rows or receipts
// can enroll provenance. A snapshot is a bounded page, not an atomic two-DB cut.
function createOwnedAuditSearchSnapshotBuilder({ reader, assertCurrent } = {}) {
  if (typeof reader?.recent !== 'function' || typeof assertCurrent !== 'function') throw new TypeError('Trusted reader and current-launch validator required');
  return Object.freeze({ async capture(scope) {
    const binding = createLaunchScope(scope);
    await assertCurrent(binding);
    const page = await reader.recent(binding, { limit: 200 });
    if (!page || !Array.isArray(page.events) || page.events.length > 200
      || typeof page.hasMore !== 'boolean' || (page.hasMore && typeof page.nextCursor !== 'string')) throw invalid('Invalid audit snapshot page');
    const rows = page.events.map(input => Object.fromEntries(fields.map(key => [key,input[key]])));
    const manifest = createAuditSourceManifest(rows);
    const payload = Object.freeze(rows.map(row => Object.freeze({
      id:row.id, actor:row.actor, action:row.action, target:row.target,
      params_json:row.params_json, ts:row.ts,
    })));
    if (Buffer.byteLength(JSON.stringify(payload)) > 16 * 1024 * 1024) throw invalid('Audit snapshot exceeds target byte budget');
    await assertCurrent(binding);
    const result = Object.freeze({ rows: payload });
    receipts.set(result, Object.freeze({ version:1, binding, rowCount:payload.length,
      payloadSha256:hash(payload), sourcesSha256:manifest.sourcesSha256,
      sources:manifest.sources, selection:Object.freeze({ limit:200, hasMore:page.hasMore,
        nextCursor:page.hasMore ? page.nextCursor : null, consistency:'bounded-owner-journal-page' }) }));
    requests.set(result,Object.freeze({binding,rows:payload,sources:Object.freeze(rows.map(row=>Object.freeze(row)))}));
    return result;
  } });
}
function durableSnapshotFor(snapshot) {
 const request=requests.get(snapshot);if(!request)throw invalid('Verified snapshot required');
 const value={version:1,sources:request.sources};
 if(Buffer.byteLength(JSON.stringify(value))>16*1024*1024)throw invalid('Durable audit snapshot exceeds byte budget');
 return value;
}
function restoreAdmittedSnapshot({binding:input,snapshot,sourceSha256,payloadSha256}) {
 const binding=createLaunchScope(input);
 if(!snapshot||Object.keys(snapshot).sort().join(',')!=='sources,version'||snapshot.version!==1||!Array.isArray(snapshot.sources)||snapshot.sources.length>200||Buffer.byteLength(JSON.stringify(snapshot))>16*1024*1024)throw invalid('Invalid admitted audit snapshot');
 if(snapshot.sources.some(row=>!row||Object.keys(row).sort().join(',')!==[...fields].sort().join(',')))throw invalid('Invalid admitted audit source fields');
 const sources=snapshot.sources.map(row=>Object.freeze(Object.fromEntries(fields.map(key=>[key,row[key]]))));
 const manifest=createAuditSourceManifest(sources);
 const payload=Object.freeze(sources.map(row=>Object.freeze({id:row.id,actor:row.actor,action:row.action,target:row.target,params_json:row.params_json,ts:row.ts})));
 if(hash(payload)!==payloadSha256||manifest.sourcesSha256!==sourceSha256)throw invalid('Admitted audit snapshot digest mismatch');
 const result=Object.freeze({rows:payload});
 receipts.set(result,Object.freeze({version:1,binding,rowCount:payload.length,payloadSha256,sourcesSha256:sourceSha256,sources:manifest.sources}));
 requests.set(result,Object.freeze({binding,rows:payload,sources:Object.freeze(sources)}));return result;
}
function receiptFor(snapshot) { return receipts.get(snapshot) || null; }
function privateRequestFor(snapshot) { return requests.get(snapshot) || null; }
module.exports = { createOwnedAuditSearchSnapshotBuilder, receiptFor, privateRequestFor, durableSnapshotFor, restoreAdmittedSnapshot };
