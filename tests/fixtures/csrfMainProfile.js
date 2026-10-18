'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
function admitCsrfMainProfile({mode,env=process.env,evidenceRoot}){
 const flag=env.CSRF_FULL_INDEX_70B;
 assert.ok(flag===undefined||flag===''||flag==='yes','Closed CSRF 70B selection required');
 if(flag!=='yes')return Object.freeze({selected70b:false});
 assert.equal(mode,'actual-indirect-chain','70B selection is only for the fixed indirect chain');
 const source=fs.realpathSync(env.CSRF_FULL_INDEX_SOURCE_ROOT);
 const runtimeRoot=fs.realpathSync(env.CSRF_FULL_INDEX_RUNTIME_ROOT);
 const browserPath=fs.realpathSync(env.CSRF_FULL_INDEX_BROWSER_EXECUTABLE);
 assert.ok(path.isAbsolute(source)&&path.isAbsolute(runtimeRoot)&&path.isAbsolute(browserPath));
 assert.equal(source,fs.realpathSync(path.resolve(__dirname,'../..')),'Exact current main checkout required');
 assert.ok(runtimeRoot!==source&&!runtimeRoot.startsWith(source+path.sep),'Runtime must be outside main source');
 assert.ok(runtimeRoot!==evidenceRoot&&!runtimeRoot.startsWith(evidenceRoot+path.sep),'Runtime must be outside evidence');
 try{fs.lstatSync(path.join(runtimeRoot,'.env'));assert.fail('External runtime must not load private environment');}catch(error){if(error.code!=='ENOENT')throw error;}
 assert.match(env.CSRF_FULL_INDEX_BROWSER_SHA256||'',/^[a-f0-9]{64}$/);
 return Object.freeze({selected70b:true,source,runtimeRoot,browserPath,browserSha256:env.CSRF_FULL_INDEX_BROWSER_SHA256});
}
function ensureOwnedRuntimeDirectory(directory,runtimeRoot){
 assert.equal(path.dirname(directory),runtimeRoot,'Only direct owned runtime directories allowed');
 try{fs.lstatSync(directory);}catch(error){if(error.code!=='ENOENT')throw error;fs.mkdirSync(directory,{mode:0o700});}
 const stat=fs.lstatSync(directory);
 assert.ok(stat.isDirectory()&&!stat.isSymbolicLink()&&stat.uid===process.getuid()&&(stat.mode&0o777)===0o700,'Owned private runtime directory required');
 assert.equal(fs.realpathSync(directory),directory,'Runtime directory identity changed');
}
module.exports={admitCsrfMainProfile,ensureOwnedRuntimeDirectory};
