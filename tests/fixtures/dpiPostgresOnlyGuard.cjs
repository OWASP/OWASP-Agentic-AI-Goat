'use strict';
// Disposable full-index DPI qualification must never open retained SQLite stores.
const Module=require('node:module');
const path=require('node:path');
const source=process.env.OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE;
if(!source||!path.isAbsolute(source))throw Error('Exact DPI PostgreSQL source required');
const original=Module._load;
const drivers=new Set(['sqlite3','better-sqlite3','sql.js','node:sqlite']);
Module._load=function(request,parent,isMain){
 if(drivers.has(request))throw Error('SQLite driver denied in disposable DPI PostgreSQL qualification');
 const filename=Module._resolveFilename(request,parent,isMain);
 if(typeof filename==='string'&&(filename===path.join(source,'server/database/authDb.js')||filename.startsWith(path.join(source,'db/initialize-db')+path.sep)))throw Error('Legacy SQLite module denied in disposable DPI PostgreSQL qualification');
 return original.apply(this,arguments);
};
