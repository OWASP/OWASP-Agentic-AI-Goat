'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const shared=require('./postgres/ownedV03DiagnosticDerivation');
const listings=require('./postgres/ownedV03ListingsDerivation');
test('fixed Listings source loader compiles the exact bounded preimage without resource execution',async()=>{
 const result=await listings.loadListingsBounded();
 assert.equal(result.sourceSha256,shared.SOURCE_SHA);
 assert.equal(result.executionApproved,false);
 assert.equal(typeof result.bounded.specification,'function');
 assert.match(result.derivedSha256,/^[a-f0-9]{64}$/);
});
test('only fixed producer domain differs in emitted parent-bound holder lease',()=>{
 assert.equal(shared.LISTINGS_LEASE_PY.replaceAll(':v03-listings',':v03-diagnostic'),shared.LEASE_PY);
 assert.match(shared.LISTINGS_LEASE_PY,/expiresAtMs=request\['expiresAtMs'\]/);
 assert.match(shared.LISTINGS_LEASE_PY,/request\['guestBootId'\]==BOOT/);
 assert.doesNotMatch(shared.LISTINGS_LEASE_PY,/request\['remainingMs'\]|expiresAtMs=start\+TOTAL/);
});
test('altered bounded source cannot enter either fixed derivation',()=>{
 const source=fs.readFileSync(path.join(__dirname,'postgres/ownedMcpBoundedBuild.js'),'utf8');
 assert.throws(()=>shared.deriveListingsSource(source+'\n'),{code:'DIAGNOSTIC_LEASE_SOURCE'});
 assert.notEqual(shared.deriveListingsSource(source),shared.deriveSource(source));
});
