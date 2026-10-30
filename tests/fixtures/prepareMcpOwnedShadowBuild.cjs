'use strict';
// Build-only helper; creates a fresh owned context and never changes the installed
// runner Dockerfile. Supply an independently installed esbuild executable.
const fs=require('node:fs'),path=require('node:path'),os=require('node:os'),{spawnSync}=require('node:child_process');
function prepare({root=path.resolve(__dirname,'../..'),esbuild}={}){
 if(typeof esbuild!=='string'||!path.isAbsolute(esbuild)||!fs.statSync(esbuild).isFile())throw Error('Explicit build tool required');
 const output=fs.mkdtempSync(path.join(os.tmpdir(),'owasp-ai-goat-shadow-package-'));
 for(const file of ['executor.js','contract.js','operationStore.js','service.js','buildAssets.js'])fs.copyFileSync(path.join(root,'sidecars/sandbox-runner/owned-shadow',file),path.join(output,file));
 const original=fs.readFileSync(path.join(root,'sidecars/sandbox-runner/owned-http/namespace-init.c'),'utf8');
 if(!original.includes('owasp-ai-goat-owned-http-worker.js')||!original.includes('OWASP_AI_GOAT_OWNED_HTTP_ATTESTED'))throw Error('Reviewed helper layout changed');
 // Only immutable executable names change; network/capability/syscall logic is
 // reused byte-for-byte from the qualified initializer.
 fs.writeFileSync(path.join(output,'namespace-init.c'),original.replaceAll('owasp-ai-goat-owned-http','owasp-ai-goat-owned-shadow'));
 fs.copyFileSync(path.join(root,'sidecars/sandbox-runner/owned-http/network-manifest.json'),path.join(output,'network-manifest.json'));
 fs.copyFileSync(path.join(root,'tests/fixtures/mcpOwnedShadowCandidate.Dockerfile'),path.join(output,'Dockerfile'));
 const result=spawnSync(esbuild,[path.join(root,'sidecars/sandbox-runner/owned-shadow/worker.js'),'--bundle','--platform=node','--format=cjs','--outfile='+path.join(output,'worker.bundle.js')],{encoding:'utf8'});if(result.status!==0)throw Error('Shadow worker build failed');return output;
}
if(require.main===module)process.stdout.write(prepare({esbuild:process.argv[2]})+'\n');
module.exports={prepare};
