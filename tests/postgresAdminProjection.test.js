'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {userDto}=require('../server/services/postgresIdentityAdapter');
const {createPostgresSessionManager}=require('../server/middleware/postgresSessionManager');
const matrix=[['student',0,false,'student'],['student',1,false,'student'],['student',2,false,'student'],['admin',0,false,'user'],['admin',1,true,'admin'],['admin',2,true,'super_admin'],['super_admin',0,false,'user'],['super_admin',1,true,'admin'],['super_admin',2,true,'super_admin']];
for(const [role,level,expected,type]of matrix)test(`PostgreSQL projection ${role}/${level}`,()=>{
 const row={id:7,username:'synthetic',role,admin_level:level,email_verified:1,isAdmin:!expected};
 const result=userDto(row,['manage_progress']);assert.equal(result.isAdmin,expected);assert.equal(result.role,role);assert.equal(result.adminLevel,level);assert.equal(result.emailVerified,1);assert.deepEqual(result.permissions,['manage_progress']);
 const manager=createPostgresSessionManager({repository:{},jwtSecret:'controlled'});assert.equal(manager.getSessionType(role,level),type);
 // Preserve existing duration policy: students and level2 remain4h, other identities2h.
 assert.equal(manager.getSessionDuration(role,level),(role==='student'||level===2?4:2)*3600000);
});
