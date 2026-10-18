'use strict';
const fs=require('node:fs'),path=require('node:path');
const {createCopyFilter}=require('../../scripts/lib/isolated-source-copy');
// This tracked synthetic teaching file belongs to other lab families. CSRF
// neither needs nor qualifies its consumers; leave the shared copier unchanged.
const EXCLUDED=['server/platform_secrets.json'];
function copyIsolatedSource(source,destination){const root=path.resolve(source),filter=createCopyFilter(root);fs.cpSync(root,path.resolve(destination),{recursive:true,filter:filename=>!EXCLUDED.includes(path.relative(root,filename).split(path.sep).join('/'))&&filter(filename)});for(const name of EXCLUDED)if(fs.existsSync(path.join(destination,name)))throw Error('Unexpected excluded CSRF artifact');}
module.exports={copyIsolatedSource,EXCLUDED};
