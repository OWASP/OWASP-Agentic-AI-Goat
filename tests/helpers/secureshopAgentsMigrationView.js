"use strict";
const fs=require('node:fs/promises'),syncFs=require('node:fs'),path=require('node:path');
const {Module,createRequire}=require('node:module');
function createAgentsMigrationView(through){
 if(!Number.isInteger(through)||through<1)throw new TypeError('Explicit positive agents migration ceiling required');
 const directory=path.resolve(__dirname,'../../db/postgres/workshop-migrations/secureshop_agents');
 const virtualFs={...fs,async readdir(dir,...args){const names=await fs.readdir(dir,...args);return path.resolve(dir)===directory?names.filter(name=>!/^\d{4}_[a-z0-9_]+\.sql$/.test(name)||Number(name.slice(0,4))<=through):names;}};
 const filename=require.resolve('../../db/postgres/migrate'),local=createRequire(filename),loaded=new Module(filename,module);
 loaded.filename=filename;loaded.require=name=>['node:fs/promises','fs/promises'].includes(name)?virtualFs:local(name);
 loaded._compile(syncFs.readFileSync(filename,'utf8'),filename);
 return {directory,...loaded.exports};
}
module.exports={createAgentsMigrationView};
