'use strict';
// Static source discovery only: parses files, never imports application modules.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const parser=require('../../client/node_modules/@babel/parser');
const root=path.resolve(__dirname,'../..'),pending=['tests/postgres/dpiCurrentOwnedMain.js','tests/postgres/dpiCurrentOwnedActualTransport.js','tests/fixtures/dpiCurrentOwnedQualification.js','tests/fixtures/dpiCurrentOwnedWireBinding.js','tests/fixtures/dpiCurrentOwnedContract.js','tests/dpiCurrentOwned.test.js','db/postgres/migrate.js','server/database/postgres/identityRepository.js','server/database/postgres/workshopPlatformSeed.js','server/data/workshopHints.js'],seen=new Set(),dynamic=[];
const hash=b=>crypto.createHash('sha256').update(b).digest('hex');
// Exact author reports are immutable inputs; their source pins must still match main.
if(![3,5].includes(process.argv.length)||!/^v[1-9][0-9]*$/.test(process.argv[2]))throw Error('Expected exclusive capture version');
const defaults=[['dpi-current-owned-source-v3.json','4fed5b7c564d5872c53f45d116a11c908542d248af82ef6421daab903e630fbd'],['dpi-current-owned-parent-source-v2.json','fb770d589270a43da4ebe5cd1fc5649eb56996e60d01315cdb0e5b2382d5c6ed']];
let reports=defaults;
if(process.argv.length===5){
 const seal=process.argv[3],pin=process.argv[4];
 if(!path.isAbsolute(seal)||path.dirname(seal)!==__dirname||path.resolve(seal)!==seal||!seal.endsWith('.json')||!/^[a-f0-9]{64}$/.test(pin))throw Error('Invalid author seal authority');
 const stat=fs.lstatSync(seal);
 if(!stat.isFile()||stat.isSymbolicLink()||fs.realpathSync(seal)!==seal)throw Error('Noncanonical author seal');
 reports=[[path.basename(seal),pin]];
}
const stable={sourcePins:{}};
function read(rel){if(path.isAbsolute(rel)||rel.split('/').includes('..'))throw Error('Invalid relative source');const file=path.join(root,rel);if(fs.realpathSync(file)!==file)throw Error('Noncanonical source');return fs.readFileSync(file);}
for(const [name,pin]of reports){const raw=fs.readFileSync(path.join(__dirname,name));if(hash(raw)!==pin)throw Error('Author report changed');const report=JSON.parse(raw);const sourcePins=report.sourcePins||report.files;if(!sourcePins||typeof sourcePins!=='object'||Array.isArray(sourcePins)||!Object.keys(sourcePins).length)throw Error('Invalid author pins');for(const [rel,h]of Object.entries(sourcePins)){if(typeof h!=='string'||!/^[a-f0-9]{64}$/.test(h))throw Error('Invalid author pin');if(stable.sourcePins[rel]&&stable.sourcePins[rel]!==h)throw Error('Conflicting authors');if(hash(read(rel))!==h)throw Error('Author source changed');stable.sourcePins[rel]=h;if(/\.[cm]?js$/.test(rel))pending.push(rel);}}
// Reviewed live maintenance closure supplies explicit lazy production modules/SQL.
// Parsing these files still discovers their current relative imports; unresolved sites are reported.
const maintenance='server/services/applicationMaintenanceInprocessSources.json';
const inventory=JSON.parse(read(maintenance));
for(const rel of Object.keys(inventory.files)){if(/\.[cm]?js$/.test(rel))pending.push(rel);}
seen.add(maintenance);

function walk(node,visit){if(!node||typeof node!=='object')return;if(Array.isArray(node)){for(const n of node)walk(n,visit);return;}visit(node);for(const [k,v]of Object.entries(node))if(!['loc','start','end','extra','comments','tokens'].includes(k))walk(v,visit);}
function addFrom(from,spec){if(!spec.startsWith('.'))return;const file=require.resolve(path.resolve(path.dirname(from),spec));if(!file.startsWith(root+'/')||file.includes('/node_modules/'))throw Error('Unexpected local dependency');pending.push(path.relative(root,file));}
while(pending.length){const rel=pending.pop();if(seen.has(rel))continue;seen.add(rel);const file=path.join(root,rel);if(!/\.[cm]?js$/.test(file))continue;
const source=fs.readFileSync(file,'utf8'),ast=parser.parse(source,{sourceType:'unambiguous',plugins:['dynamicImport']});
walk(ast,node=>{if(node.type==='CallExpression'&&(node.callee?.name==='require'||node.callee?.type==='Import')){const value=node.arguments?.[0];if(value?.type==='StringLiteral')addFrom(file,value.value);else dynamic.push({file:rel,offset:node.start});}if(['ImportDeclaration','ExportNamedDeclaration','ExportAllDeclaration'].includes(node.type)&&node.source)addFrom(file,node.source.value);});}
const extra=['tests/postgres/run-setup-database-phase-isolated.py','tests/postgres/dpi_current_owned_launcher_test.py','tests/postgres/sql_nosql_process_ownership.py','tests/postgres/sql_nosql_docker_ownership.py','tests/postgres/ctf_setup_sidecars.py','tests/postgres/fixtures/admin-curriculum-before.json','tests/postgres/fixtures/admin-curriculum-proposed.json','package.json','package-lock.json','client/package.json','client/package-lock.json','tests/release-inputs/capture-dpi-current-owned-source.cjs','tests/release-inputs/capture-dpi-current-owned-main.py'];
for(const rel of extra)seen.add(rel);
for(const directory of ['db/postgres/identity-migrations','db/postgres/migrations'])for(const name of fs.readdirSync(path.join(root,directory))){if(name.endsWith('.sql'))seen.add(directory+'/'+name);}
const pins=Object.fromEntries([...seen].sort().map(rel=>[rel,hash(read(rel))]));
for(const [rel,pin]of Object.entries(stable.sourcePins)){if(hash(read(rel))!==pin)throw Error('Stable source changed during capture');if(!pins[rel])pins[rel]=pin;}
for(const [name,pin]of reports)if(hash(fs.readFileSync(path.join(__dirname,name)))!==pin)throw Error('Author seal changed during capture');
const target=path.join(__dirname,'dpi-current-owned-source-pins-'+process.argv[2]+'.json');fs.writeFileSync(target,JSON.stringify({sourcePins:pins,dynamicRequires:dynamic,authorReports:reports,dynamicReviewRequired:true},null,2)+'\n',{flag:'wx',mode:0o600});
process.stdout.write(JSON.stringify({file:target,sourceFiles:seen.size,dynamicRequires:dynamic,sha256:hash(fs.readFileSync(target))})+'\n');
