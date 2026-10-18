'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {catalogs,validateSnapshot}=require('../db/postgres/import-workshop-snapshot');
const snapshot=()=>({version:1,family:'aria',tables:Object.fromEntries(Object.keys(catalogs.aria).map(key=>[key,[]]))});
test('workshop snapshot rejects unknown scope and fields rather than discarding data',()=>{
 const extra=snapshot();extra.tables.unmapped=[{secret:'preserve in archive'}];assert.throws(()=>validateSnapshot(extra),/exactly/);
 const unknown=snapshot();unknown.tables.chat_history=[{id:1,user_id:'a',message_type:'user',message:'raw',timestamp:null,extra:true}];assert.throws(()=>validateSnapshot(unknown),/columns mismatch/);
 const tagged=snapshot();tagged.tables.chat_history=[{id:1,user_id:'a',message_type:'user',message:{type:'text',value:'raw'},timestamp:null}];assert.throws(()=>validateSnapshot(tagged),/Unsupported value/);
 assert.equal(validateSnapshot(snapshot()).family,'aria');
});
