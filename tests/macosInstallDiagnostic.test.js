'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const {spawnSync}=require('node:child_process');
const root=path.resolve(__dirname,'..');
function diagnostic(nodeVersion,npmVersion){
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'owasp-ai-goat-diagnostic-policy-'));
 try{
  // Run current source from stdin; only runtime discovery is controlled.
  let source=fs.readFileSync(path.join(root,'scripts/install/Mac/test-macos-install.sh'),'utf8');
  const rootLine='ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"';
  assert.equal(source.split(rootLine).length,2);
  source=source.replace(rootLine,'ROOT="${TEST_SOURCE_ROOT}"');
  const discovery='source "$ROOT/scripts/install/runtime-path.sh"';
  assert.equal(source.split(discovery).length,2);
  source=source.replace(discovery,'# controlled runtime discovery: PATH already selected');
  const heredoc=/node - <<'JS'\n([\s\S]*?)\nJS/;
  const match=source.match(heredoc);assert(match,'expected diagnostic node heredoc');
  const jsBody=match[1].replaceAll("'", "'\"'\"'");
  source=source.replace(heredoc,`printf '%s' '${jsBody}' | node -`);
  const bin=path.join(dir,'bin');fs.mkdirSync(bin);
  const stub=(name,body)=>fs.writeFileSync(path.join(bin,name),'#!/bin/bash\n'+body+'\n',{mode:0o700});
  stub('uname','echo Darwin');
  stub('dirname','exec /usr/bin/dirname "$@"');
  stub('git','exit 0');
  stub('npm','echo "$TEST_NPM"');
  stub('node','if [[ "${1:-}" == --version ]]; then echo "$TEST_NODE"; else echo browser >> "$TEST_LOG"; /bin/cat >/dev/null; fi');
  stub('ollama','echo model >> "$TEST_LOG"');
  const log=path.join(dir,'calls');
  const result=spawnSync('/bin/bash',['-s'],{input:source,encoding:'utf8',timeout:5000,env:{TEST_SOURCE_ROOT:root,PATH:bin,TEST_NODE:nodeVersion,TEST_NPM:npmVersion,TEST_LOG:log,TMPDIR:dir,HOME:dir}});
  return {...result,calls:fs.existsSync(log)?fs.readFileSync(log,'utf8'):''};
 }finally{fs.rmSync(dir,{recursive:true,force:true});}
}
for(const [name,node,npm] of [['older Node','v26.9.0','12.1.0'],['older npm','v26.10.0','12.0.0']])test(`${name} is denied before model/browser diagnostics`,()=>{
 const result=diagnostic(node,npm);assert.equal(result.status,1,result.stderr);assert.match(result.stderr,/requires Node.js 26\.10\.0\+ and npm 12\.1\.0\+/);assert.equal(result.calls,'');
});
test('supported exact floors retain model/browser diagnostic order and success output',()=>{
 const result=diagnostic('v26.10.0','12.1.0');assert.equal(result.status,0,result.stderr);assert.equal(result.calls,'model\nbrowser\n');assert.match(result.stdout,/Local model and application dependencies verified/);
});

test('application compatibility and Unix installer enforce the qualified Node floor',()=>{
 const {isSupportedApplicationNodeVersion}=require('../scripts/application-node-runtime');
 assert.equal(isSupportedApplicationNodeVersion('24.15.0'),false);
 assert.equal(isSupportedApplicationNodeVersion('26.9.0'),false);
 assert.equal(isSupportedApplicationNodeVersion('26.10.0'),true);
 const result=diagnostic('v26.9.0','12.1.0');
 assert.equal(result.status,1);assert.match(result.stderr,/Unix installer runtime target not met/);assert.equal(result.calls,'');
});
