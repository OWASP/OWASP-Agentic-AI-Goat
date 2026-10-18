'use strict';
const fs=require('node:fs/promises'),path=require('node:path');
const {prepareSetupCommandEnv}=require('./setup-command');
const policy=path.join(__dirname,'../install/runtime-version-policy.sh');
async function admitSetupNpm({environment=process.env,execute,node=process.execPath,platform=process.platform}){
 const minimum=(await fs.readFile(policy,'utf8')).match(/^DVAIA_MINIMUM_NPM_VERSION=(\d+\.\d+\.\d+)$/m)?.[1];
 const instruction=platform==='darwin'?'bash scripts/install/Mac/install-macos.sh':platform==='linux'?'bash scripts/install/Linux/install-linux.sh':'Install the supported Node.js runtime and npm before rerunning setup';
 const fail=()=>Object.assign(Error(`Compatible npm ${minimum}+ is required before setup. Run: ${instruction}`),{code:'SETUP_NPM_UNAVAILABLE'});
 if(!minimum)throw fail();
 const candidates=environment.npm_execpath?[environment.npm_execpath]:[path.resolve(path.dirname(node),'../lib/node_modules/npm/bin/npm-cli.js'),path.join(path.dirname(node),'node_modules/npm/bin/npm-cli.js')];
 let cli;
 for(const candidate of candidates){try{if(!path.isAbsolute(candidate))throw fail();const real=await fs.realpath(candidate);if(path.basename(real)!=='npm-cli.js'||!(await fs.stat(real)).isFile())throw fail();cli=real;break;}catch{}}
 if(!cli)throw fail();
 let version;try{const result=await execute(node,[cli,'--version'],{env:environment,timeout:10000,maxBuffer:4096});version=String(result.stdout||'').trim();}catch{throw fail();}
 if(!/^\d+\.\d+\.\d+$/.test(version))throw fail();
 const a=version.split('.').map(Number),b=minimum.split('.').map(Number);let compatible=false;
 for(let i=0;i<3;i++){if(a[i]!==b[i]){compatible=a[i]>b[i];break;}if(i===2)compatible=true;}
 if(!compatible)throw fail();
 return Object.freeze({command:node,prefix:Object.freeze([cli]),version,environment:Object.freeze(prepareSetupCommandEnv('npm',['ci'],environment,{platform}))});
}
module.exports={admitSetupNpm};
