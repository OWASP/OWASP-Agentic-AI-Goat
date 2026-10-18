'use strict';
const assert=require('node:assert/strict'),{createHash}=require('node:crypto');
const hash=value=>createHash('sha256').update(JSON.stringify(value)).digest('hex');
function observeFactory(original,record){return function(...factoryArgs){const real=original.apply(this,factoryArgs);return Object.freeze({...real,async search(...args){const before=hash(args);try{const result=await real.search.apply(real,args),resultHash=hash(result);assert.equal(hash(args),before,'Search mutated observation arguments');record({scope:structuredClone(args[0]),query:{...structuredClone(args[1]),embedding:undefined,embeddingSha256:hash(args[1].embedding)},result:structuredClone(result),argumentsSha256:before,resultSha256:resultHash});assert.equal(hash(args),before);assert.equal(hash(result),resultHash);return result;}catch(error){assert.equal(hash(args),before);throw error;}}});};}
module.exports={observeFactory};
if(process.env.CSRF_INDIRECT_OBSERVER_FILE){
 const fs=require('node:fs'),path=require('node:path');const root=fs.realpathSync(process.env.CSRF_FULL_INDEX_ROOT),file=path.resolve(process.env.CSRF_INDIRECT_OBSERVER_FILE);assert.equal(path.dirname(file),root);assert.equal(path.basename(file),'csrf-indirect-search-observations.json');const rows=[];
 const target=require('../../server/database/postgres/workshopRagRevisionRepository');target.createWorkshopRagRevisionRepository=observeFactory(target.createWorkshopRagRevisionRepository,row=>{assert.equal(row.scope.family,'CSRF');assert(rows.length<32);rows.push(row);const bytes=JSON.stringify(rows,null,2);assert(Buffer.byteLength(bytes)<=4194304);fs.writeFileSync(file,bytes,{mode:0o600});});
}
