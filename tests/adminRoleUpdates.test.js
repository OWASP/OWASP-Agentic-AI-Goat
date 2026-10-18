'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {createPostgresAdminRepository}=require('../server/database/postgres/adminRepository');
test('locked account updates preserve omitted flags and require level two for consistent role transitions',async()=>{
 let row={id:7,username:'fixture',email:'fixture@example.test',full_name:'Name',role:'admin',admin_level:1,is_active:1,email_verified:1,department:null,phone:null},updates=0;
 const client={release(){},async query(sql,p){if(sql.startsWith('SELECT *'))return{rows:[{...row}]};if(sql.includes('AS active_admins'))return{rows:[{active_admins:1,managers:1}]};if(sql.startsWith('UPDATE identity.users')){updates++;row={...row,username:p[0],email:p[1],full_name:p[2],role:p[3],admin_level:p[4],is_active:p[7],email_verified:p[8]};return{rows:[row]};}return{rows:[]};}};
 const repo=createPostgresAdminRepository({query:client.query,connect:async()=>client});
 await assert.rejects(repo.updateUser(7,{full_name:'New Name',is_active:true},1),{statusCode:403});
 await repo.updateUser(7,{full_name:'New Name',is_active:true},2);assert.equal(row.admin_level,1);assert.equal(row.full_name,'New Name');assert.equal(row.email_verified,1);
 await assert.rejects(repo.updateUser(7,{role:'super_admin',adminLevel:2},1),{statusCode:403});assert.equal(updates,1);
 await assert.rejects(repo.updateUser(7,{role:'student'},2),{code:'BAD_REQUEST'});
 await repo.updateUser(7,{role:'super_admin',adminLevel:2},2);assert.equal(row.role,'super_admin');
 await repo.updateUser(7,{role:'student',adminLevel:0},2);assert.equal(row.admin_level,0);
 await assert.rejects(repo.updateUser(7,{is_active:'false'},2),{code:'BAD_REQUEST'});
});
