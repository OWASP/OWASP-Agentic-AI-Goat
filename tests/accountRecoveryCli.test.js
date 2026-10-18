'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const {Readable}=require('node:stream');
const bcrypt=require('bcryptjs');
const fs=require('node:fs');
const {createIdentityRepository}=require('../server/database/postgres/identityRepository');
const recovery=require('../scripts/admin/reset-auth-defaults');

function input(value,{tty=false}={}){const stream=Readable.from([value]);stream.isTTY=tty;return stream;}

test('recovery CLI requires one explicit username and password stdin',async()=>{
  assert.deepEqual(recovery.parseArguments(['--username','learner-7','--password-stdin']),{username:'learner-7'});
  assert.deepEqual(recovery.parseArguments(['--password-stdin','--username','learner-7']),{username:'learner-7'});
  for(const args of [[],['--all'],['--username','learner-7'],['--username','learner-7','--password','secret'],
    ['--username','--password-stdin','--password-stdin']]) assert.throws(()=>recovery.parseArguments(args),/Usage:/);
  assert.equal(await recovery.readPassword(input('Strong-Recovery9!\n')),'Strong-Recovery9!');
  await assert.rejects(recovery.readPassword(input('one\ntwo\n')),/exactly one/);
  await assert.rejects(recovery.readPassword(input('Strong-Recovery9!',{tty:true})),/must be piped/);
  await assert.rejects(recovery.readPassword(input('x'.repeat(513))),/too large/);
  const source=fs.readFileSync(require.resolve('../scripts/admin/reset-auth-defaults'),'utf8');
  assert.match(source,/createPool\(process\.env,'IDENTITY_DATABASE_URL'\)/);
  assert.doesNotMatch(source,/authDb|DEFAULTS|purpose:'maintenance'/);
});

test('main hashes stdin, recovers only the selected account, and never prints the secret',async()=>{
  const secret='Strong-Recovery9!';const calls=[];let output='';let loads=0,closed=0,verified=0;
  const dependencies={
    pool:{end:async()=>{closed+=1;}},verifyServer:async()=>{verified+=1;},
    validateUsername:value=>({valid:true,sanitized:value}),validatePassword:value=>({valid:value===secret}),
    hashPassword:async value=>bcrypt.hash(value,4),
    repository:{recoverAccount:async(username,passwordHash)=>{calls.push({username,passwordHash});return{userId:7,sessionsRevoked:2};}},
  };
  const result=await recovery.main(['--username','learner-7','--password-stdin'],
    {input:input(`${secret}\n`),output:{write:value=>{output+=value;}}},async()=>{loads+=1;return dependencies;});
  assert.deepEqual(result,{userId:7,sessionsRevoked:2});assert.equal(loads,1);assert.equal(verified,1);assert.equal(closed,1);
  assert.equal(calls[0].username,'learner-7');assert.equal(await bcrypt.compare(secret,calls[0].passwordHash),true);
  assert.doesNotMatch(output,new RegExp(secret.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')));
  assert.doesNotMatch(output,/password\s*[:=]/i);assert.match(output,/revoked 2 active session/);

  loads=0;output='';await recovery.main(['--help'],{input:input(''),output:{write:value=>{output+=value;}}},async()=>{loads+=1;});
  assert.equal(loads,0);assert.equal(output,`${recovery.USAGE}\n`);
});

test('identity recovery is one transaction and preserves account attributes by updating only recovery fields',async()=>{
  const queries=[];let released;
  const client={
    async query(sql,params){queries.push({sql,params});
      if(sql.startsWith('SELECT id FROM identity.users'))return{rows:[{id:41}],rowCount:1};
      if(sql.startsWith('UPDATE identity.user_sessions'))return{rows:[],rowCount:3};
      if(sql.startsWith('INSERT INTO identity.activity_logs'))return{rows:[{id:9}],rowCount:1};
      return{rows:[],rowCount:1};
    },
    release:error=>{released=error;},
  };
  const repository=createIdentityRepository({connect:async()=>client});
  const hash=await bcrypt.hash('Strong-Recovery9!',4);
  assert.deepEqual(await repository.recoverAccount('learner-41',hash),{userId:41,sessionsRevoked:3});
  assert.equal(queries[0].sql,'BEGIN');assert.match(queries[1].sql,/WHERE username=\$1 FOR UPDATE/);
  assert.match(queries[2].sql,/password=\$1,login_attempts=0/);
  for(const preserved of ['role','admin_level','is_active','email','full_name','password_reset_required'])
    assert.doesNotMatch(queries[2].sql,new RegExp(`\\b${preserved}\\s*=`));
  assert.match(queries[3].sql,/revoke_reason='administrative_recovery'/);
  assert.equal(queries[4].params[1],'administrative_account_recovery');assert.equal(queries[4].params[2],'{}');
  assert.equal(queries.at(-1).sql,'COMMIT');assert.equal(released,undefined);
});

test('missing account rolls back without changing or disclosing another account',async()=>{
  const queries=[];let released;
  const client={async query(sql,params){queries.push({sql,params});
    if(sql.startsWith('SELECT id FROM identity.users'))return{rows:[],rowCount:0};return{rows:[],rowCount:0};},
  release:error=>{released=error;}};
  const repository=createIdentityRepository({connect:async()=>client});
  const hash=await bcrypt.hash('Strong-Recovery9!',4);
  await assert.rejects(repository.recoverAccount('missing-user',hash),{code:'IDENTITY_ACCOUNT_UNAVAILABLE'});
  assert.deepEqual(queries.map(({sql})=>sql),['BEGIN','SELECT id FROM identity.users WHERE username=$1 FOR UPDATE','ROLLBACK']);
  assert.equal(released,undefined);
});
