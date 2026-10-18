'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),Module=require('node:module');
test('PostgreSQL sensitive lookup selection imports no MySQL/SQLite and performs no initialization',()=>{
 const previous=process.env.PLATFORM_DATABASE_ENGINE,load=Module._load;process.env.PLATFORM_DATABASE_ENGINE='postgres';let initialization=0;
 Module._load=function(name,parent,main){if(/mysql2|sqlite/.test(name))throw Error('legacy engine imported');if(name.endsWith('/postgres/sensitiveLookupDb'))return{initializeSensitiveLookupDb:()=>{initialization++;}};return load.call(this,name,parent,main);};
 try{const db=require('../server/database/mysqlSensitiveInfoDb');assert.equal(db.engine,'postgres');assert.equal(initialization,0);}finally{Module._load=load;if(previous===undefined)delete process.env.PLATFORM_DATABASE_ENGINE;else process.env.PLATFORM_DATABASE_ENGINE=previous;}
});
