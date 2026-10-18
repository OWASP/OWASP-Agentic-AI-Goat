'use strict';
const fs=require('node:fs'),path=require('node:path');
const {createCopyFilter}=require('../../scripts/lib/isolated-source-copy');
const OMITTED=new Set(['server/platform_secrets.json','server/config/secrets.env']);
function createFilter(source){const base=createCopyFilter(source);return filename=>base(filename)&&!filename.split(path.sep).includes('__pycache__')&&!filename.endsWith('.pyc')&&!OMITTED.has(path.relative(source,filename).split(path.sep).join('/'));}
function list(source,files,directories){const filter=createFilter(source),result=new Set();for(const name of files){const absolute=path.join(source,name);if(!filter(absolute)||!fs.statSync(absolute).isFile())throw Error('Required source excluded or absent');result.add(name);}
 function visit(absolute){if(!filter(absolute))return;const stat=fs.lstatSync(absolute);if(stat.isSymbolicLink()||stat.isFile()){result.add(path.relative(source,absolute).split(path.sep).join('/'));return;}if(stat.isDirectory())for(const entry of fs.readdirSync(absolute).sort())visit(path.join(absolute,entry));}
 for(const directory of directories)visit(path.join(source,directory));return [...result].sort();}
function copy(source,destination){fs.cpSync(source,destination,{recursive:true,filter:createFilter(source)});}
module.exports={createFilter,list,copy};
if(require.main===module){const [source,files,directories]=process.argv.slice(2);process.stdout.write(JSON.stringify(list(source,JSON.parse(files),JSON.parse(directories))));}
