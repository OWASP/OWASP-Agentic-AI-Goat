'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const bcrypt=require('bcryptjs');
const {bootstrapAdmin,BOOTSTRAP_PERMISSIONS}=require('../db/postgres/bootstrap-admin');
const defaults={username:'admin',email:'admin@dvaia.local',password:'admin123',initialTrainingProfile:true};

// Owned in-memory transaction adapter: never creates a PostgreSQL connection.
function fixture({users=[],failStudent=false}={}){
 const state={users:structuredClone(users),permissions:[],queries:[],released:0};
 let before,locked=false;
 const client={release(){state.released++;},async query(sql,args=[]){
  state.queries.push(sql);
  if(sql==='BEGIN'){before=structuredClone({users:state.users,permissions:state.permissions});return{rows:[]};}
  if(sql==='COMMIT')return{rows:[]};
  if(sql==='ROLLBACK'){Object.assign(state,before);return{rows:[]};}
  if(sql.startsWith('LOCK TABLE identity.users')){locked=true;return{rows:[]};}
  assert(locked,'identity reads and writes require the bootstrap lock');
  if(sql.startsWith('SELECT count(*)'))return{rows:[{count:state.users.length}]};
  if(sql.startsWith('SELECT id,username'))return{rows:state.users.filter(user=>user.username===args[0])};
  if(sql.startsWith('INSERT INTO identity.admin_permissions')){state.permissions.push({id:args[0],permissions:[...args[1]]});return{rows:[]};}
  if(sql.startsWith('INSERT INTO identity.users')){
   const student=sql.includes("'student',0");
   if(student&&failStudent)throw Error('controlled student insert failure');
   assert(!state.users.some(user=>user.username===args[0]||user.email===args[1]),'unique account identity');
   const user={id:state.users.length+1,username:args[0],email:args[1],password:args[2],role:student?'student':'super_admin',admin_level:student?0:2,email_verified:1,is_active:1};
   state.users.push(user);
   return{rows:[{id:user.id,username:user.username,email:user.email,role:user.role}]};
  }
  assert.fail(`Unexpected query: ${sql}`);
 }};
 return{state,pool:{async connect(){return client;}}};
}

test('fresh training profile creates exactly admin and student with bcrypt and the literal spaced password',async()=>{
 const f=fixture(),result=await bootstrapAdmin({pool:f.pool,...defaults});
 assert.equal(result.created,true);assert.equal(result.user.username,'admin');assert.equal(result.student.username,'student');
 assert.deepEqual(f.state.users.map(({username,email,role,admin_level})=>({username,email,role,admin_level})),[
  {username:'admin',email:'admin@dvaia.local',role:'super_admin',admin_level:2},
  {username:'student',email:'student@dvaia.local',role:'student',admin_level:0},
 ]);
 for(const user of f.state.users){assert.match(user.password,/^\$2[aby]\$12\$/);assert.equal(user.email_verified,1);assert.equal(user.is_active,1);}
 assert(await bcrypt.compare('admin123',f.state.users[0].password));
 assert(await bcrypt.compare('student 123',f.state.users[1].password));
 assert.equal(await bcrypt.compare('student123',f.state.users[1].password),false);
 assert.deepEqual(f.state.permissions,[{id:1,permissions:[...BOOTSTRAP_PERMISSIONS]}]);
 assert.equal(f.state.queries.filter(sql=>sql==='COMMIT').length,1);assert.equal(f.state.released,1);
});

test('generic bootstrap retains long password policy and creates only the requested administrator',async()=>{
 for(const changes of [{initialTrainingProfile:false},{initialTrainingProfile:undefined},{username:'other'},{email:'other@example.invalid'},{password:'other123'},{initialTrainingProfile:'true'}]){
  const f=fixture();await assert.rejects(bootstrapAdmin({pool:f.pool,...defaults,...changes}),/Explicit valid administrator/);assert.equal(f.state.queries.length,0);
 }
 const f=fixture();await bootstrapAdmin({pool:f.pool,username:'instructor',email:'instructor@example.invalid',password:'owned administrator credential'});assert.equal(f.state.users.length,1);
});

test('empty identity with a retained older journal preserves its administrator and uses the requested fresh student profile',async()=>{
 const f=fixture();await bootstrapAdmin({pool:f.pool,username:'Abhinav',email:'admin@dvaia.local',password:'owned older journal credential',initialTrainingProfile:true});
 assert.deepEqual(f.state.users.map(user=>user.username),['Abhinav','student']);assert(await bcrypt.compare('owned older journal credential',f.state.users[0].password));
});

test('populated retry preserves all students and their changed passwords without backfill',async()=>{
 const f=fixture();await bootstrapAdmin({pool:f.pool,...defaults});
 f.state.users[1].password=await bcrypt.hash('changed owned student credential',4);
 f.state.users.push({id:3,username:'sibling',email:'sibling@example.invalid',password:'retained',role:'student',admin_level:0});
 const before=structuredClone(f.state.users),retry=await bootstrapAdmin({pool:f.pool,...defaults});
 assert.equal(retry.status,'already_created');assert.equal(retry.created,false);assert.deepEqual(f.state.users,before);
 f.state.users=f.state.users.filter(user=>user.username!=='student');const remaining=structuredClone(f.state.users);
 await bootstrapAdmin({pool:f.pool,...defaults});assert.deepEqual(f.state.users,remaining);
});

test('changed administrator password and conflicting populated identities fail without any mutation',async()=>{
 const f=fixture();await bootstrapAdmin({pool:f.pool,...defaults});
 f.state.users[0].password=await bcrypt.hash('changed owned administrator credential',4);
 const before=structuredClone({users:f.state.users,permissions:f.state.permissions});
 await assert.rejects(bootstrapAdmin({pool:f.pool,...defaults}),/BOOTSTRAP_ADMIN_CREDENTIAL_MISMATCH/);assert.deepEqual({users:f.state.users,permissions:f.state.permissions},before);
 const conflicting=fixture({users:[{id:1,username:'other',email:'other@example.invalid',role:'super_admin',admin_level:2,is_active:1,password:'retained'}]});
 const conflictBefore=structuredClone(conflicting.state.users);
 await assert.rejects(bootstrapAdmin({pool:conflicting.pool,...defaults}),/BOOTSTRAP_ADMIN_CREDENTIAL_MISMATCH/);assert.deepEqual(conflicting.state.users,conflictBefore);assert.deepEqual(conflicting.state.permissions,[]);
});

test('student insert failure rolls back both accounts and administrator permissions together',async()=>{
 const f=fixture({failStudent:true});await assert.rejects(bootstrapAdmin({pool:f.pool,...defaults}),/controlled student insert failure/);
 assert.deepEqual(f.state.users,[]);assert.deepEqual(f.state.permissions,[]);assert(f.state.queries.includes('ROLLBACK'));assert(!f.state.queries.includes('COMMIT'));assert.equal(f.state.released,1);
});
