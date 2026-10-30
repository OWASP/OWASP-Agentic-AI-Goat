'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),path=require('node:path');
const parser=require(require.resolve('@babel/parser',{paths:[path.resolve(__dirname,'../client')]}));
const {loadModules}=require('./fixtures/secureshopBridgeBrowserModules');
function verify(modules){for(const [url,source]of modules){const ast=parser.parse(source,{sourceType:'module'});for(const node of ast.program.body){if(!node.source)continue;const target=new URL(node.source.value,'http://fixture.invalid'+url);assert.equal(target.origin,'http://fixture.invalid');assert(modules.has(target.pathname),`${url} missing ${target.pathname}`);}}}
test('closed fixture module map covers actual transitive static imports',()=>{const modules=loadModules();assert.equal(modules.size,54);verify(modules);assert(!modules.has('/../../server/.env'));assert(!modules.has('/unknown.mjs'));});
test('missing actual nested dependency is a resource-free preflight failure',()=>{const modules=loadModules();modules.delete('/utils/couponReference.mjs');assert.throws(()=>verify(modules),/missing \/utils\/couponReference/);});
