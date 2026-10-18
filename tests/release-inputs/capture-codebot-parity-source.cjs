'use strict';
// Static source discovery only: parses files, never imports application modules.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const parser=require('../../client/node_modules/@babel/parser');
const root=path.resolve(__dirname,'../..'), pending=['tests/postgres/codeBotRenderedParityMainV1.js','tests/fixtures/codeBotRenderedParityV1.js'],seen=new Set(),dynamic=[],dependencyReferences=[];
const hash=b=>crypto.createHash('sha256').update(b).digest('hex');
// Require explicit stable-author pins before reading/sealing the closure.
if(![5,6].includes(process.argv.length))throw Error('Expected stable-pin JSON path, SHA256, new output basename and optional profile');
const profile=process.argv[5]||'codebot';if(!['codebot','workshop-history','mcp-audit-content','ipi-email-trigger-actual'].includes(profile))throw Error('Closed capture profile required');
// Closed resolution of the history fixture's three computed require families.
if(profile==='workshop-history')pending.push(
 'server/database/postgres/sqlWorkshopDb.js','server/database/postgres/nosqlWorkshopDb.js',
 'server/services/ariaAgentService.js','server/services/novaAgentService.js',
 'server/routes/sqlWorkshop.js','server/routes/nosqlWorkshop.js');
if(profile==='ipi-email-trigger-actual')pending.push('tests/postgres/ipiEmailRenderedFixture.js','tests/ipiEmailRenderedQualificationContract.test.js','tests/fixtures/ipiEmailTriggerActualInput.json','tests/postgres/finflowBackupBrowserActualTransport.js','tests/ipiRagActualParentContract.test.js','server/routes/emailAgent.js','server/agent-runtime/indirectEmailGraph.js','server/agent-runtime/indirectEmailDeliveryGraph.js','server/services/ipiEmailProvider.js');
if(profile==='mcp-audit-content')pending.push('tests/fixtures/mcpAuditContentBrowser.js','tests/fixtures/mcpAuditSeedUpgrade.js','server/database/postgres/mcpWorkshopDb.js','server/routes/mcpWorkshop.js');
if(!(profile==='codebot'?/^codebot-parity-source-pins(?:-v[0-9]+)?\.json$/:profile==='ipi-email-trigger-actual'?/^ipi-email-trigger-actual-source-pins-v[0-9]+\.json$/:profile==='mcp-audit-content'?/^mcp-audit-content-source-pins-v[0-9]+\.json$/:/^workshop-history-source-pins-v[0-9]+\.json$/).test(process.argv[4]))throw Error('Invalid capture output basename');
const sealBytes=fs.readFileSync(process.argv[2]);if(hash(sealBytes)!==process.argv[3])throw Error('Stable-pin seal mismatch');
const stable=JSON.parse(sealBytes);if(!stable.sourcePins||Object.keys(stable.sourcePins).length<5)throw Error('Stable source pins required');
for(const [rel,pin]of Object.entries(stable.sourcePins)){if(path.isAbsolute(rel)||rel.split('/').includes('..')||hash(fs.readFileSync(path.join(root,rel)))!==pin)throw Error('Stable source changed');}

function walk(node,visit){if(!node||typeof node!=='object')return;if(Array.isArray(node)){for(const n of node)walk(n,visit);return;}visit(node);for(const [k,v]of Object.entries(node))if(!['loc','start','end','extra','comments','tokens'].includes(k))walk(v,visit);}
function addFrom(from,spec){if(!spec.startsWith('.'))return;const file=require.resolve(path.resolve(path.dirname(from),spec));if(!file.startsWith(root+'/'))throw Error('Unexpected external local dependency');if(file.startsWith(root+'/node_modules/')||file.startsWith(root+'/client/node_modules/')){dependencyReferences.push({from:path.relative(root,from),file:path.relative(root,file)});return;}if(file.includes('/node_modules/'))throw Error('Unexpected dependency tree');pending.push(path.relative(root,file));}
while(pending.length){const rel=pending.pop();if(seen.has(rel))continue;seen.add(rel);const file=path.join(root,rel);if(!/\.[cm]?js$/.test(file))continue;
const source=fs.readFileSync(file,'utf8'),ast=parser.parse(source,{sourceType:'unambiguous',plugins:['dynamicImport']});
walk(ast,node=>{if(node.type==='CallExpression'&&(node.callee?.name==='require'||node.callee?.type==='Import')){const value=node.arguments?.[0];if(value?.type==='StringLiteral')addFrom(file,value.value);else dynamic.push({file:rel,offset:node.start});}if(['ImportDeclaration','ExportNamedDeclaration','ExportAllDeclaration'].includes(node.type)&&node.source)addFrom(file,node.source.value);});}
const extra=["client/index.html", "client/package-lock.json", "client/package.json", "client/vite.config.mjs", "package-lock.json", "package.json", "tests/release-inputs/capture-codebot-parity-main.py", "tests/release-inputs/record-current-frontend-build.py", "tests/codeBotRenderedParityV1.test.js", "tests/fixtures/browserProcessOwnership.js", "tests/fixtures/codeBotRenderedParityV1.js", "tests/fixtures/secureshopAnalyticsBrowserOwner.js", "tests/postgres/codeBotRenderedParityMainV1.js", "tests/postgres/codebot_capture_test.py", "tests/postgres/codebot_parity_launcher_test.py", "tests/postgres/ctf_setup_sidecars.py", "tests/postgres/run-finflow-backup-browser-main.py", "tests/postgres/run-setup-database-phase-isolated.py", "tests/postgres/sql_nosql_docker_ownership.py", "tests/postgres/sql_nosql_process_ownership.py"];
for(const rel of extra)seen.add(rel);
if(profile==='ipi-email-trigger-actual'){seen.add('tests/release-inputs/capture-codebot-parity-source.cjs');seen.add('tests/codebotCaptureRoots.test.js');}
for(const directory of ['db/postgres/identity-migrations',...(profile==='ipi-email-trigger-actual'?[]:profile==='mcp-audit-content'?['db/postgres/workshop-migrations/mcp']:profile==='workshop-history'?['db/postgres/workshop-migrations/aria','db/postgres/workshop-migrations/nova']:['db/postgres/workshop-migrations/supply_chain'])])for(const name of fs.readdirSync(path.join(root,directory))){if(name.endsWith('.sql'))seen.add(directory+'/'+name);}
const pins=Object.fromEntries([...seen].sort().map(rel=>[rel,hash(fs.readFileSync(path.join(root,rel)))]));
for(const [rel,pin]of Object.entries(stable.sourcePins)){if(hash(fs.readFileSync(path.join(root,rel)))!==pin)throw Error('Stable source changed during capture');if(!pins[rel])pins[rel]=pin;}
const target=path.join(__dirname,process.argv[4]);fs.writeFileSync(target,JSON.stringify({sourcePins:pins,dynamicRequires:dynamic,dependencyReferences},null,2)+'\n',{flag:'wx',mode:0o600});
process.stdout.write(JSON.stringify({file:target,sourceFiles:seen.size,dynamicRequires:dynamic,sha256:hash(fs.readFileSync(target))})+'\n');
