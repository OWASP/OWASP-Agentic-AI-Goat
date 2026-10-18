'use strict';
require('./helpers/analyticsControlledDependencyGuard.cjs');
const test=require('node:test'),assert=require('node:assert/strict');
test('actual pure support remains available while storage/provider modules deny',()=>{
 const actual=require('../server/database/postgres/workshopPlatformSupport');assert.equal(typeof actual.userId,'function');assert.equal(actual.userId(4),4);assert(!require.cache[require.resolve('../server/database/postgres/index')]);
 for(const name of ['pg','sqlite3','../server/database/authDb','../server/services/ollamaService'])assert.throws(()=>require(name),{code:'ANALYTICS_CONTROLLED_DEPENDENCY_DENIED'});
});
test('delayed import remains denied for full test lifetime',async()=>{await new Promise(resolve=>setImmediate(resolve));assert.throws(()=>require('pg'),{code:'ANALYTICS_CONTROLLED_DEPENDENCY_DENIED'});assert(!Object.keys(require.cache).some(p=>/node_modules\/(?:pg|sqlite3)\//.test(p)));});

test('resolved relative and absolute storage/provider paths cannot bypass guard',()=>{
 const {createRequire}=require('node:module'),path=require('node:path');
 for(const [parent,request]of [['server/database/postgres/fixture.js','./index'],['server/services/fixture.js','./ollamaService'],['server/services/fixture.js','./multiProviderAIService']]){
  const scoped=createRequire(path.resolve(parent));assert.throws(()=>scoped(request),{code:'ANALYTICS_CONTROLLED_DEPENDENCY_DENIED'});
 }
 for(const name of ['pg','openai','@anthropic-ai/sdk']){assert.throws(()=>require(name),{code:'ANALYTICS_CONTROLLED_DEPENDENCY_DENIED'});try{const absolute=require.resolve(name);assert.throws(()=>require(absolute),{code:'ANALYTICS_CONTROLLED_DEPENDENCY_DENIED'});}catch(e){if(e.code!=='MODULE_NOT_FOUND')throw e;}}
 assert(!require.cache[require.resolve('../server/database/postgres/index')]);
});
