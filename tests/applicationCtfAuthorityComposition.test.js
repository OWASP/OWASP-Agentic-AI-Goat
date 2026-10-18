'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
const source=fs.readFileSync(require.resolve('../server/applicationServer'),'utf8');
const selection=source.slice(source.indexOf('const ctfRoutes ='),source.indexOf("const { createChangeRevisionsRouter"));
test('PostgreSQL dispatch stays unavailable until private authority publication',()=>{
 const ctx={ctfAuthorityRouter:null};vm.createContext(ctx);vm.runInContext(selection+'\nglobalThis.dispatch=ctfRoutes;',ctx);
 let status;ctx.dispatch({}, {status(n){status=n;return this;},json(body){assert.equal(body.error,'CTF temporarily unavailable');}});assert.equal(status,503);
 let count=0;ctx.ctfAuthorityRouter=()=>count++;ctx.dispatch({},{});assert.equal(count,1);
});
test('supported entry has no legacy CTF router or refresher selector',()=>{
 assert.doesNotMatch(source,/require\(['"]\.\/routes\/ctf['"]\)/);
 assert.doesNotMatch(source,/ctfLeaderboardRefresh|ctfAuthorityEnabled/);
});
test('startup CTF readiness precedes deletion and listener; cleanup uses existing ordered hook',()=>{
 const init=source.indexOf('initializeProductionCtfAuthority({'),deletion=source.indexOf('await checked(platformDataLifecycle.initialize'),listen=source.indexOf('server.listen(PORT');assert(init>0&&init<deletion&&deletion<listen);
 assert.match(source,/validateSession: identity\.validateSession\.bind\(identity\)/);assert.match(source,/ctfPool: require\('\.\/database\/postgres\/ctfDb'\)\.getCtfPool\(\)/);
 assert.match(source,/closeCtfRuntime:.*ctfAuthorityRouter=null;.*closeProductionCtfAuthority/);
});
