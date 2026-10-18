'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const os=require('node:os');
const path=require('node:path');
const {spawnSync}=require('node:child_process');

test('offline SQL/NOVA route and grader composition loads without I/O',()=>{
 const logs=fs.mkdtempSync(path.join(os.tmpdir(),'dvaia-sql-nosql-offline-test-'));
 try{
  const result=spawnSync(process.execPath,['tests/postgres/sql-nosql-offline-composition-smoke.js'],{
   cwd:path.resolve(__dirname,'..'),encoding:'utf8',timeout:30000,
   env:{PATH:process.env.PATH||'',HOME:process.env.HOME||'',TMPDIR:process.env.TMPDIR||'',
    NODE_ENV:'test',SQL_NOSQL_OFFLINE_COMPOSITION:'1',PLATFORM_DATABASE_ENGINE:'postgres',
    WORKSHOP_DATABASE_ENGINE:'postgres',LOGS_DIR:logs,AWS_EC2_METADATA_DISABLED:'true'}
  });
  assert.equal(result.status,0,result.stderr);
  assert.equal(result.stdout,'SQL_NOSQL_OFFLINE_COMPOSITION_READY\n');
  assert.deepEqual(fs.readdirSync(logs),[]);
 }finally{fs.rmSync(logs,{recursive:true,force:true});}
});
