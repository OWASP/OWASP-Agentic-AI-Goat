'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {execFileSync}=require('node:child_process');
test('PostgreSQL FinFlow module loads without opening SQLite or creating pools',()=>{
 const script=`const Module=require('node:module'),load=Module._load;Module._load=function(name,...args){if(name.includes('sqlite'))throw Error('SQLite must not load');return load.call(this,name,...args)};const fs=require('node:fs');fs.writeFileSync=()=>{throw Error('Import wrote a file')};fs.mkdirSync=()=>{throw Error('Import created directory')};const legacy=require('./server/database/sensitiveInfoDb');if(legacy.engine!=='postgres')throw Error('Legacy wrong engine');const store=require('./server/database/sensitiveInfoWorkshopDb');if(store.engine!=='postgres')throw Error('Wrong engine');if(require('./server/database/postgres').getPoolBudgetSnapshot().reserved!==0)throw Error('Import created a pool');`;
 assert.doesNotThrow(()=>execFileSync(process.execPath,['-e',script],{cwd:require('node:path').join(__dirname,'..'),env:{...process.env,PLATFORM_DATABASE_ENGINE:'postgres'},stdio:'pipe'}));
});
