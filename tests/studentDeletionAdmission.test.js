'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createStudentDeletionRepository } = require('../server/database/postgres/studentDeletionRepository');
test('recovery rejects unbounded batches and immediate retry loops before database access', async () => {
  const repository=createStudentDeletionRepository({query:async()=>{throw Error('Unexpected database');}},{steps:['revoke_runs','identity']});
  for(const options of [{limit:0},{limit:101},{limit:'20'},{retryAfterMs:0},{retryAfterMs:Infinity}]) {
    await assert.rejects(repository.listRecoverable(options),TypeError);
  }
});
test('deletion admission validates manifest and IDs before obtaining database authority', async () => {
  const pool = { connect: async () => { throw Error('Database must not be reached'); } };
  for (const steps of [[],['same','same'],['arbitrary;sql'],[''],['runs'],['identity','runs'],['identity'],['excessive_agency','identity'],null]) assert.throws(() => createStudentDeletionRepository(pool,{steps}),TypeError);
  const repository = createStudentDeletionRepository(pool,{steps:['revoke_runs','excessive_agency','identity']});
  await assert.rejects(repository.admit({requesterId:1,subjectId:1}),{code:'SELF_DELETION_DENIED'});
  for (const subjectId of ['2',0,-1,2.5,2147483648]) await assert.rejects(repository.admit({requesterId:1,subjectId}),TypeError);
});

test('lease API rejects malformed tokens, durations and unregistered cleanup steps before database access', async () => {
  const pool={query:async()=>{throw Error('Unexpected database access');}};
  const repository=createStudentDeletionRepository(pool,{steps:['revoke_runs','identity']});
  const jobId='11111111-1111-4111-8111-111111111111';
  await assert.rejects(repository.claim('invalid'),TypeError);
  await assert.rejects(repository.claim(jobId,0),TypeError);
  await assert.rejects(repository.acknowledge({jobId,leaseToken:jobId,stepKey:'injected_step'}),TypeError);
});

test('renewal and failure reject invalid worker input without querying the database', async () => {
  const repository=createStudentDeletionRepository({query:async()=>{throw Error('Unexpected database');}},{steps:['revoke_runs','identity']});
  const jobId='11111111-1111-4111-8111-111111111111';
  await assert.rejects(repository.renew({jobId,leaseToken:jobId,leaseMs:Infinity}),TypeError);
  await assert.rejects(repository.fail({jobId,leaseToken:'bad',stepKey:'runs'}),TypeError);
});

test('completion rejects forged lease input before database access', async () => {
  const repository=createStudentDeletionRepository({query:async()=>{throw Error('Unexpected database');}},{steps:['revoke_runs','identity']});
  await assert.rejects(repository.complete({jobId:'invalid',leaseToken:'invalid'}),TypeError);
  await assert.rejects(repository.quarantine({jobId:'invalid',leaseToken:'invalid'}),TypeError);
  await assert.rejects(repository.resumeQuarantined({requesterId:0,jobId:'invalid'}),TypeError);
});

test('deletion admission takes the shared lifecycle lock before account rows', async () => {
  const queries=[];
  const client={
    async query(sql) {
      const normalized=sql.replace(/\s+/g,' ').trim();queries.push(normalized);
      if(normalized.includes('FROM identity.users'))return{rows:[
        {id:1,role:'super_admin',admin_level:2,is_active:1},
        {id:7,role:'student',admin_level:0,is_active:1},
      ],rowCount:2};
      if(normalized.includes('FROM identity.student_deletion_jobs'))return{rows:[{
        job_id:'11111111-1111-4111-8111-111111111111',state:'pending',
      }],rowCount:1};
      return{rows:[],rowCount:0};
    },
    release() {},
  };
  const repository=createStudentDeletionRepository({connect:async()=>client},{
    steps:['revoke_runs','excessive_agency','identity'],
  });
  assert.deepEqual(await repository.admit({requesterId:1,subjectId:7}),{
    jobId:'11111111-1111-4111-8111-111111111111',state:'pending',replayed:true,
  });
  assert.equal(queries[0],'BEGIN');
  assert.match(queries[1],/pg_advisory_xact_lock/);
  assert.match(queries[2],/FROM identity\.users.*FOR UPDATE/);
  assert.equal(queries.at(-1),'COMMIT');
});
