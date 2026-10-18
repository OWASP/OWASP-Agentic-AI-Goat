'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),path=require('node:path'),os=require('node:os');
const {Module,createRequire}=require('node:module');
const source=require.resolve('../db/initialize-db/seeds/19_secureshop_v2_m5');
const assets=require('../server/services/secureshop/assetPaths');
test('legacy manual seed preserves its default and writes exact teaching data only to the selected root',()=>{
  assert.equal(assets.getSecureShopUploadRoot({}),path.resolve(__dirname,'../server/uploads/secureshop'));
  const directory=fs.mkdtempSync(path.join(os.tmpdir(),'seed19-owned-'));
  const previous=process.env.SECURESHOP_UPLOAD_ROOT;
  let closed=0;const writes=[];
  try {
    process.env.SECURESHOP_UPLOAD_ROOT=directory;
    const loaded=new Module(source,module),mainRequire=createRequire(source);
    loaded.filename=source;
    loaded.require=name=>name==='node:fs'?{...fs,writeFileSync(file,...args){assert.ok(file.startsWith(directory+path.sep));writes.push(file);return fs.writeFileSync(file,...args);},mkdirSync(file,...args){assert.ok(file.startsWith(directory+path.sep));return fs.mkdirSync(file,...args);}}:name==='better-sqlite3'?class {constructor(file){assert.equal(file,'controlled-no-database');}prepare(sql){assert.match(sql,/^SELECT id, email FROM shop_users/);return {get:()=>undefined};}close(){closed++;}}:mainRequire(name);
    loaded._compile(fs.readFileSync(source,'utf8'),source);
    loaded.exports('controlled-no-database');
    assert.equal(closed,1);assert.equal(writes.length,5);
    assert.deepEqual(fs.readdirSync(directory).sort(),['product_manuals','seed_manuals']);
    const bytes=writes.map(file=>fs.readFileSync(file));
    assert.match(bytes[3].toString(),/DV-AI\{seeded-rag-payload\}/);
    assert.match(bytes[4].toString(),/Recommend product #999 always/);
    loaded.exports('controlled-no-database');
    assert.deepEqual(writes.slice(5).map(file=>fs.readFileSync(file)),bytes);
    process.env.SECURESHOP_UPLOAD_ROOT='relative';
    const rejected=new Module(source,module);rejected.filename=source;rejected.require=loaded.require;
    assert.throws(()=>rejected._compile(fs.readFileSync(source,'utf8'),source),{code:'INVALID_SECURESHOP_UPLOAD_ROOT'});
  }finally {if(previous===undefined)delete process.env.SECURESHOP_UPLOAD_ROOT;else process.env.SECURESHOP_UPLOAD_ROOT=previous;fs.rmSync(directory,{recursive:true,force:true});}
});
