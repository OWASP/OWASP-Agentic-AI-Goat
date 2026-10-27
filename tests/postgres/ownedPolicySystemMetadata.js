'use strict';

// Candidate acquisition only: neither an approved dependency lock nor image
// execution approval. Tmpfs occupancy is NOT downloaded/expanded byte usage.
const {createHash}=require('node:crypto');
const {performance}=require('node:perf_hooks');
const {targetSpecification,metadataRetentionSpecification,metadataSourcePolicy}=require('./ownedPolicySystemBuild');
const MIB=1024**2;
const LIMITS=Object.freeze({compressedIndex:32*MIB,compressedTotal:128*MIB,
 expandedTotal:512*MIB,release: MIB,report:MIB,diagnostics:2*MIB,deadlineMs:300000,sources:8});
const fail=code=>Object.assign(new Error(code),{code});

function createMetadataBudget({signal,now=()=>performance.now()}={}){
 const started=now();
 if(!Number.isFinite(started))throw fail('METADATA_CLOCK_INVALID');
 const totals={compressed:0,expanded:0,diagnostics:0,report:0};
 let sources=0,stopped=null;
 function check(){
  if(stopped)throw stopped;
  if(signal?.aborted){stopped=signal.reason instanceof Error?signal.reason:fail('METADATA_ABORTED');throw stopped;}
  const time=now();
  if(!Number.isFinite(time)||time<started||time-started>=LIMITS.deadlineMs){stopped=fail('METADATA_DEADLINE');throw stopped;}
 }
 function reserve(kind,bytes){
  check();
  const limit={compressed:LIMITS.compressedTotal,expanded:LIMITS.expandedTotal,diagnostics:LIMITS.diagnostics,report:LIMITS.report}[kind];
  if(!limit||!Number.isSafeInteger(bytes)||bytes<0)throw fail('METADATA_BUDGET_ARGUMENT');
  if(totals[kind]+bytes>limit){stopped=fail('METADATA_'+kind.toUpperCase()+'_LIMIT');throw stopped;}
  totals[kind]+=bytes;
 }
 async function transfer(kind,stream,write,{release=false}={}){
  check();
  if(!stream||typeof stream[Symbol.asyncIterator]!=='function'||typeof write!=='function'
    ||!['compressed','expanded','diagnostics','report'].includes(kind))throw fail('METADATA_STREAM_INVALID');
  if(kind==='compressed'&&++sources>LIMITS.sources){stopped=fail('METADATA_SOURCE_LIMIT');throw stopped;}
  const perFile=kind==='compressed'?(release?LIMITS.release:LIMITS.compressedIndex):Infinity;
  const hash=createHash('sha256');let bytes=0;
  try{
   for await(const chunk of stream){
    check();
    if(!Buffer.isBuffer(chunk))throw fail('METADATA_NONBINARY_STREAM');
    if(bytes+chunk.length>perFile){stopped=fail('METADATA_FILE_LIMIT');throw stopped;}
    reserve(kind,chunk.length);bytes+=chunk.length;hash.update(chunk);
    await write(chunk);check();
   }
   check();return Object.freeze({bytes,sha256:hash.digest('hex')});
  }catch(error){stopped ||= error;throw error;}
 }
 return Object.freeze({check,reserve,transfer,snapshot:()=>Object.freeze({...totals,sources,failed:!!stopped})});
}
function metadataPrerequisites(target){
 const specification=targetSpecification(target);
 return Object.freeze({target,baseImageDigest:specification.base,platform:'linux/arm64',
  packages:specification.packages,limits:LIMITS,executable:false,
  missing:Object.freeze(['reviewed-authenticated-dependency-lock','approved-build-manifest'])});
}
module.exports={LIMITS,createMetadataBudget,metadataPrerequisites};

// Closed grammar rather than searching arbitrary apt syntax for URLs. Unknown
// options are rejected, including source-local overrides of authentication.
function canonicalSources(name,value,policy=null){
 const bad=()=>{throw Error('METADATA_SOURCE_INVALID');};
 if(policy!==null&&policy!=='v03-diagnostic-trixie-freshness-v1'&&policy!=='v23-trixie-freshness-v1'&&policy!=='v24-system-trixie-freshness-v1'&&policy!=='v33-pricing-trixie-freshness-v1'&&policy!=='v24-policy-trixie-freshness-v1'&&policy!=='listings-trixie-freshness-v1')bad();
 if(typeof value!=='string'||Buffer.byteLength(value)>65536)bad();
 const uri=value=>{let u;try{u=new URL(value);}catch{bad();}
  if(!['http:','https:'].includes(u.protocol)||!['deb.debian.org','security.debian.org'].includes(u.hostname)
   ||u.port||u.username||u.password||u.search||u.hash||!['/debian','/debian/','/debian-security','/debian-security/'].includes(u.pathname))bad();
  return 'http://'+u.hostname+u.pathname;
 };
 const words=value=>{if(!/^[A-Za-z0-9][A-Za-z0-9+._/-]*(?: +[A-Za-z0-9][A-Za-z0-9+._/-]*)*$/.test(value))bad();return value;};
 const keyring='/usr/share/keyrings/debian-archive-keyring.gpg';
 const validKeyring=value=>value===keyring||value==='/usr/share/keyrings/debian-archive-keyring.pgp';
 // Local bounded policy, not a Debian freshness guarantee. Stable point
 // releases are roughly two months apart (release.debian.org); 90 days is
 // our maximum. APT still uses an earlier signed Valid-Until, never a minimum.
 // System's separately named policy is an explicit target decision: its
 // original Dockerfile has no seven-day maximum (APT's default is zero).
 // https://manpages.debian.org/trixie/apt/apt.conf.5.en.html#THE_ACQUIRE_GROUP
 const maximum=(address,suite,components)=>{
  if(components!=='main'||address!==(suite==='trixie-security'?'http://deb.debian.org/debian-security':'http://deb.debian.org/debian')
   ||!['trixie','trixie-updates','trixie-security'].includes(suite))bad();
  return suite==='trixie'?7776000:604800;
 };
 const text=value.split('\n').filter(line=>!/^\s*#/.test(line)).join('\n').trim();
 if(!text)return '';
 if(name.endsWith('.sources'))return text.split(/\n\s*\n/).map(block=>{
  const fields={};for(const line of block.split('\n')){
   const m=/^([A-Za-z-]+):\s*(\S.*?)\s*$/.exec(line);if(!m||Object.hasOwn(fields,m[1]))bad();fields[m[1]]=m[2];
  }
  if(Object.keys(fields).some(k=>!['Types','URIs','Suites','Components','Signed-By','Architectures'].includes(k))
   ||fields.Types!=='deb'||!validKeyring(fields['Signed-By'])||!fields.URIs||!fields.Suites||!fields.Components
   ||(fields.Architectures&&fields.Architectures!=='arm64'))bad();
  const addresses=fields.URIs.split(/ +/).map(uri),suites=words(fields.Suites),components=words(fields.Components);
  if(policy){
   if(addresses.length!==1||new Set(suites.split(' ')).size!==suites.split(' ').length)bad();
   return suites.split(' ').map(suite=>`Types: deb\nURIs: ${addresses[0]}\nSuites: ${suite}\nComponents: ${components}\nSigned-By: ${fields['Signed-By']}\nArchitectures: arm64\nValid-Until-Max: ${maximum(addresses[0],suite,components)}`).join('\n\n');
  }
  return `Types: deb\nURIs: ${addresses.join(' ')}\nSuites: ${suites}\nComponents: ${components}\nSigned-By: ${fields['Signed-By']}\nArchitectures: arm64`;
 }).join('\n\n')+'\n';
 if(!name.endsWith('.list'))bad();
 return text.split('\n').map(line=>{
  const m=/^deb\s+(?:\[([^\]]+)\]\s+)?(\S+)\s+(\S+)\s+(.+)$/.exec(line.trim());if(!m)bad();
  let selectedKeyring=keyring;
  const seen=new Set();for(const option of (m[1]||'').split(/\s+/).filter(Boolean)){
   const [key,val,...rest]=option.split('=');if(rest.length||seen.has(key))bad();seen.add(key);
   if(!(key==='arch'&&val==='arm64')&&!(key==='signed-by'&&validKeyring(val)))bad();
   if(key==='signed-by')selectedKeyring=val;
  }
  const address=uri(m[2]),suite=words(m[3]),components=words(m[4]);
  return `deb [arch=arm64 signed-by=${selectedKeyring}${policy?' valid-until-max='+maximum(address,suite,components):''}] ${address} ${suite} ${components}`;
 }).join('\n')+'\n';
}
module.exports.canonicalSources=canonicalSources;

// Same exact reconstruction on host and guest; originals remain separately
// retained. No caller-selected policy values or replacement source authority.
function sourcePolicyWitness(originals,policy,canonical){
 if(policy!=='v03-diagnostic-trixie-freshness-v1'&&policy!=='v23-trixie-freshness-v1'&&policy!=='v24-system-trixie-freshness-v1'&&policy!=='v33-pricing-trixie-freshness-v1'&&policy!=='v24-policy-trixie-freshness-v1'&&policy!=='listings-trixie-freshness-v1')throw Error('METADATA_SOURCE_POLICY');
 const suites=[],names=new Set();const files=originals.map(([name,value])=>{
  if(names.has(name))throw Error('METADATA_SOURCE_POLICY');names.add(name);
  const text=canonical(name,value,policy);
  for(const line of text.split('\n')){
   if(line.startsWith('Suites: '))suites.push(line.slice(8));
   if(line.startsWith('deb '))suites.push(line.split('] ')[1].split(' ')[1]);
  }
  return {name,sha256:require('node:crypto').createHash('sha256').update(text).digest('hex')};
 });
 if(JSON.stringify(suites.sort())!==JSON.stringify(['trixie','trixie-security','trixie-updates']))throw Error('METADATA_SOURCE_POLICY');
 return {version:1,policy,files};
}
module.exports.sourcePolicyWitness=sourcePolicyWitness;

// This is a second time-policy check, NOT a signature verifier. Only call on
// exact APT-authenticated InRelease files after apt-get update succeeds.
function authenticatedReleaseFreshness(name,text,now){
 const bad=()=>{throw Error('METADATA_RELEASE_FRESHNESS');};
 const names={
  'deb.debian.org_debian_dists_trixie_InRelease':['trixie',7776000],
  'deb.debian.org_debian_dists_trixie-updates_InRelease':['trixie-updates',604800],
  'deb.debian.org_debian-security_dists_trixie-security_InRelease':['trixie-security',604800],
 };
 if(!Object.hasOwn(names,name)||typeof text!=='string'||text.includes('\r')||Buffer.byteLength(text)>1048576||!Number.isSafeInteger(now)||now<0)bad();
 // Accept only the canonical clear-signed envelope; reject duplicate or
 // folded identity/date fields instead of guessing which APT interpreted.
 const match=/^-----BEGIN PGP SIGNED MESSAGE-----\nHash: [A-Z0-9, ]+\n\n([\s\S]+)\n-----BEGIN PGP SIGNATURE-----\n[\s\S]+\n-----END PGP SIGNATURE-----\n?$/.exec(text);
 if(!match)bad();
 const fields={};let previous='';
 for(const line of match[1].split('\n')){
  if(/^\s/.test(line)&&['Date','Valid-Until','Codename'].includes(previous))bad();
  const field=/^([^:]+): *(.*)$/.exec(line);
  if(field){previous=field[1];
   const canonical={'date':'Date','valid-until':'Valid-Until','codename':'Codename'}[previous.trim().toLowerCase()];
   if(canonical&&previous!==canonical)bad();
   if(['Date','Valid-Until','Codename'].includes(previous)){
   if(Object.hasOwn(fields,previous))bad();fields[previous]=field[2];
  }}else previous='';
 }
 const [codename,maximum]=names[name];
 const date=value=>{
  if(typeof value!=='string'||! /^(Mon|Tue|Wed|Thu|Fri|Sat|Sun), \d{2} (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{4} \d{2}:\d{2}:\d{2} (UTC|GMT|\+0000)$/.test(value))bad();
  const parsed=Date.parse(value);if(!Number.isFinite(parsed))bad();
  // Reject normalized impossible dates and wrong weekday rather than using
  // JavaScript's permissive date repair as release authority.
  if(new Date(parsed).toUTCString()!==value.replace(/(?:UTC|\+0000)$/,'GMT'))bad();
  return parsed;
 };
 if(fields.Codename!==codename||!fields.Date)bad();
 const issued=date(fields.Date),signedUntil=fields['Valid-Until']===undefined?null:date(fields['Valid-Until']);
 const expires=Math.min(issued+maximum*1000,signedUntil===null?Infinity:signedUntil);
 if(issued>now+10000||now>expires||expires<issued)bad();
 return {name,codename,date:fields.Date,validUntil:fields['Valid-Until']??null,maximumSeconds:maximum,checkedAt:now,expiresAt:expires,
  sha256:require('node:crypto').createHash('sha256').update(text).digest('hex')};
}
module.exports.authenticatedReleaseFreshness=authenticatedReleaseFreshness;

function validateCandidateReport(report,target='v24-policy',retained=false){
 const specification=targetSpecification(target),requestedPackages=specification.packages;
 const reject=()=>{throw fail('METADATA_REPORT_INVALID');};
 if(typeof retained!=='boolean')reject();
 const sha=value=>typeof value==='string'&&/^[a-f0-9]{64}$/.test(value);
 const bounded=(value,max)=>Number.isSafeInteger(value)&&value>0&&value<=max;
 if(!report||report.version!==1||report.candidateOnly!==true||report.qualified!==false
  ||typeof report.release!=='string'||Buffer.byteLength(report.release)>65536||!/^ID=debian$/m.test(report.release)
  ||!sha(report.keyringSha256)||!sha(report.installedStatusSha256)
  ||!['/usr/share/keyrings/debian-archive-keyring.gpg','/usr/share/keyrings/debian-archive-keyring.pgp'].includes(report.keyringPath)
  ||!bounded(report.keyringBytes,LIMITS.release)
  ||!bounded(report.compressedBytes,LIMITS.compressedTotal)||!bounded(report.expandedBytes,LIMITS.expandedTotal)
  ||!Number.isSafeInteger(report.diagnosticBytes)||report.diagnosticBytes<0||report.diagnosticBytes>LIMITS.diagnostics/2
  ||report.expandedMeterStage!=='after-update-before-offline-resolution'
  ||JSON.stringify(report.requestedPackages)!==JSON.stringify(requestedPackages)
  ||typeof report.selection!=='string'||!report.selection.trim()||Buffer.byteLength(report.selection)>LIMITS.diagnostics/2)reject();
 for(const [rows,max]of [[report.sources,8],[report.indices,64],[report.selected,128]])
  if(!Array.isArray(rows)||rows.length===0||rows.length>max)reject();
 const sourceNames=new Set(),indexNames=new Set(),packages=new Set(),selectedUris=new Map();
 for(const line of report.selection.split('\n')){
  if(!line.startsWith("'"))continue;
  // APT's compatibility --print-uris output prefers MD5, which newer
  // security package records may omit. That optional display is not the
  // package integrity authority: the separately selected row must have SHA256.
  const match=/^'([^']+)' \S+ ([0-9]+)(?: (SHA256:[a-f0-9]{64}|MD5Sum:[a-f0-9]{32}))?$/.exec(line.trim());
  if(!match||(!match[3]&&target!=='v23-registry'&&!(retained&&['v03-diagnostic','v24-system','v33-pricing','v24-policy','listings-package'].includes(target))))reject();
  let url,filename;try{url=new URL(match[1]);filename=decodeURIComponent(url.pathname.replace(/^\/(?:debian|debian-security)\//,''));}catch{reject();}
  if(!['http:','https:'].includes(url.protocol)||!['deb.debian.org','security.debian.org'].includes(url.hostname)
   ||url.username||url.password||url.port||url.search||url.hash||selectedUris.has(filename))reject();
  selectedUris.set(filename,{bytes:Number(match[2]),hash:match[3]??null});
 }
 if(selectedUris.size!==report.selected.length)reject();
 for(const row of report.sources){if(!row||!sha(row.sha256)||typeof row.name!=='string'
  ||! /^(?:[A-Za-z0-9_-]+\.)?(?:list|sources)$/.test(row.name)||sourceNames.has(row.name))reject();sourceNames.add(row.name);}
 for(const row of report.indices){if(!row||!sha(row.sha256)||typeof row.name!=='string'
  ||!/^[A-Za-z0-9_.+%-]+$/.test(row.name)||!bounded(row.bytes,LIMITS.expandedTotal)||indexNames.has(row.name))reject();indexNames.add(row.name);}
 if(!report.indices.some(row=>row.name.endsWith('_InRelease'))||!report.indices.some(row=>row.name.includes('_Packages')))reject();
 if(metadataSourcePolicy(target,retained)){
  if(!Array.isArray(report.releaseFreshness)||report.releaseFreshness.length!==3)reject();
  if(report.indices.filter(row=>row.name.endsWith('_InRelease')).length!==3)reject();
  const seen=new Set();
  for(const row of report.releaseFreshness){
   if(!row||Object.keys(row).sort().join(',')!=='checkedAt,codename,date,expiresAt,maximumSeconds,name,sha256,validUntil'
    ||seen.has(row.name)||!sha(row.sha256)||!report.indices.some(index=>index.name===row.name&&index.sha256===row.sha256))reject();
   seen.add(row.name);
   // Re-evaluate time arithmetic; this reconstruction is NOT signature proof.
   const text=`-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\nCodename: ${row.codename}\nDate: ${row.date}${row.validUntil===null?'':'\nValid-Until: '+row.validUntil}\n-----BEGIN PGP SIGNATURE-----\ncontrolled-host-policy-replay\n-----END PGP SIGNATURE-----\n`;
   let expected;try{expected=authenticatedReleaseFreshness(row.name,text,row.checkedAt);}catch{reject();}
   expected.sha256=row.sha256;
   if(Object.keys(expected).some(key=>expected[key]!==row[key]))reject();
  }
 }else if(report.releaseFreshness!==undefined||report.sourcePolicy!==undefined)reject();
 for(const row of report.selected){
  if(!row||! /^[a-z0-9][a-z0-9+.-]*$/.test(row.name)||typeof row.version!=='string'||! /^[A-Za-z0-9.+:~_-]+$/.test(row.version)
   ||!['arm64','all'].includes(row.architecture)||typeof row.filename!=='string'
   ||! /^pool\/[A-Za-z0-9_./+~:-]+\.deb$/.test(row.filename)||row.filename.split('/').includes('..')
   ||!bounded(row.bytes,1024**3)||!sha(row.sha256)||packages.has(row.name))reject();
  packages.add(row.name);
  // Join offline resolver output to the package row, not merely independent hashes.
  const selected=selectedUris.get(row.filename);
  if(!selected||selected.bytes!==row.bytes||(selected.hash?.startsWith('SHA256:')&&selected.hash!=='SHA256:'+row.sha256))reject();
 }
 return report;
}
module.exports.validateCandidateReport=validateCandidateReport;

function validateBinding(binding){
 if(!binding||Object.keys(binding).sort().join(',')!=='base,runId,target'||!/^[a-f0-9]{32}$/.test(binding.runId)
  ||targetSpecification(binding.target).base!==binding.base)throw fail('METADATA_BINDING_INVALID');
 return binding;
}
function metadataAptOptions(port){return ['-o','Dir::Etc::sourcelist=-','-o','Dir::Etc::sourceparts=/metadata/sources','-o','Dir::State::lists=/metadata/lists',
 '-o','Dir::Cache=/metadata/cache','-o','Acquire::http::Proxy=http://127.0.0.1:'+port,'-o','Acquire::https::Proxy=http://127.0.0.1:'+port,
 '-o','Acquire::Retries=0','-o','Acquire::PDiffs=false','-o','Acquire::Languages=none','-o','Acquire::Check-Valid-Until=true',
 '-o','Acquire::Check-Date=true','-o','Acquire::Max-FutureTime=10','-o','Acquire::Max-ValidTime=604800',
 '-o','Acquire::AllowInsecureRepositories=false','-o','Acquire::AllowDowngradeToInsecureRepositories=false','-o','APT::Get::List-Cleanup=false',
 '-o','APT::Sandbox::User=root'];}
function validCommand(file,args,target,retention=false){
 const installPackages=targetSpecification(target).installPackages;
 const indexPath=value=>typeof value==='string'&&/^\/metadata\/lists\/[A-Za-z0-9][A-Za-z0-9._%:+~-]*$/.test(value)&&!value.endsWith('/lock');
 if(file==='/usr/bin/sha256sum')return args.length===1&&indexPath(args[0]);
 if(file==='/usr/lib/apt/apt-helper')return args.length===2&&args[0]==='cat-file'&&indexPath(args[1]);
 const match=/^Acquire::http::Proxy=http:\/\/127\.0\.0\.1:([1-9]\d{0,4})$/.exec(args[9]||'');
 if(!match||Number(match[1])>65535)return false;
 const options=metadataAptOptions(match[1]);if(JSON.stringify(args.slice(0,options.length))!==JSON.stringify(options))return false;
 const tail=args.slice(options.length);
 if(file==='/usr/bin/apt-cache')return tail.length===2&&tail[0]==='show'&&/^[a-z0-9][a-z0-9+.-]*(?::arm64)?=[A-Za-z0-9.+:~_-]+$/.test(tail[1]);
 const lists=retention?metadataRetentionSpecification(target)?.stages.map(stage=>stage.packages):[installPackages];
 if(!lists)return false;
 return file==='/usr/bin/apt-get'&&[['update','--error-on=any'],...lists.flatMap(packages=>[
  ['--print-uris','--download-only','--yes','--no-install-recommends','install',...packages],['--simulate','--no-install-recommends','install',...packages]])].some(tailExpected=>JSON.stringify(tail)===JSON.stringify(tailExpected));
}
module.exports.metadataAptOptions=metadataAptOptions;
function validateRetainedMetadata(candidate,binding){
 const bad=()=>{throw fail('METADATA_RETENTION_INVALID');};
 const contract=metadataRetentionSpecification(binding.target);if(!contract)bad();
 const value=candidate.retainedMetadata;
 if(!value||Object.keys(value).sort().join(',')!=='binding,capBytes,kind,objects,retainedBytes,stages,version'
  ||value.version!==1||value.kind!==contract.kind||value.capBytes!==144*1024**2
  ||candidate.selectionKind!=='deduplicated-stage-uri-aggregate'
  ||!value.binding||Object.keys(value.binding).sort().join(',')!=='base,runId,target'
  ||Object.keys(binding).some(key=>value.binding[key]!==binding[key])
  ||!Array.isArray(value.objects)||value.objects.length<8||value.objects.length>64
  ||!Array.isArray(value.stages)||value.stages.length!==contract.stages.length)bad();
 let total=0,downloaded=0;const urls=new Set(),kinds=new Map();
 for(const row of value.objects){
  if(!row||Object.keys(row).sort().join(',')!=='bytes,file,kind,sha256,url'||!['upstream','keyring','installed-status'].includes(row.kind)
   ||typeof row.sha256!=='string'||!/^[a-f0-9]{64}$/.test(row.sha256)||row.file!=='objects/'+row.sha256
   ||!Number.isSafeInteger(row.bytes)||row.bytes<1)bad();
  total+=row.bytes;
  if(row.kind==='upstream'){
   let url;try{url=new URL(row.url);}catch{bad();}
   if(url.href!==row.url||url.protocol!=='http:'||url.host!=='deb.debian.org'||url.username||url.password||url.search||url.hash||urls.has(row.url)
    ||!/^\/(?:debian\/dists\/trixie(?:-updates)?|debian-security\/dists\/trixie-security)\/(?:InRelease|main\/binary-arm64\/(?:Packages(?:\.(?:xz|gz))?|by-hash\/(?:SHA256\/[a-f0-9]{64}|SHA512\/[a-f0-9]{128})))$/.test(url.pathname)
    ||row.bytes>(url.pathname.endsWith('/InRelease')?1024**2:32*1024**2))bad();
   urls.add(row.url);downloaded+=row.bytes;
  }else{
   if(row.url!==null||kinds.has(row.kind)||row.bytes>(row.kind==='keyring'?1024**2:8*1024**2))bad();kinds.set(row.kind,row);
  }
 }
 if(!Number.isSafeInteger(value.retainedBytes)||value.retainedBytes!==total||total>144*1024**2||downloaded>128*1024**2
  ||downloaded!==candidate.compressedBytes||kinds.get('keyring')?.sha256!==candidate.keyringSha256
  ||kinds.get('keyring')?.bytes!==candidate.keyringBytes||kinds.get('installed-status')?.sha256!==candidate.installedStatusSha256)bad();
 if(['v23-registry','v33-pricing','v24-policy','listings-package'].includes(binding.target)&&!Array.isArray(candidate.releaseFreshness))bad();
 for(const release of candidate.releaseFreshness||[]){
  const suffix=release.codename==='trixie-security'?'/debian-security/dists/trixie-security/InRelease':'/debian/dists/'+release.codename+'/InRelease';
  if(!value.objects.some(row=>row.kind==='upstream'&&row.url==='http://deb.debian.org'+suffix&&row.sha256===release.sha256))bad();
 }
 const union=new Map(),lines=new Set();
 for(const [index,stage]of value.stages.entries()){
  const {name,packages}=contract.stages[index];
  if(!stage||Object.keys(stage).sort().join(',')!=='installedStatusSha256,name,packages,selected,selection,simulation'
   ||stage.name!==name||JSON.stringify(stage.packages)!==JSON.stringify(packages)||stage.installedStatusSha256!==candidate.installedStatusSha256
   ||typeof stage.simulation!=='string'||!stage.simulation||Buffer.byteLength(stage.simulation)>1024**2)bad();
  validateCandidateReport({...candidate,selected:stage.selected,selection:stage.selection},binding.target,true);
  const instantiated=stage.simulation.split('\n').filter(line=>line.startsWith('Inst '));
  if(instantiated.length!==stage.selected.length)bad();
  const decisions=instantiated.map(line=>/^Inst ([a-z0-9][a-z0-9+.-]*)(?::arm64)? (?:\[[^\]]+\] )?\(([^\s]+) /.exec(line));
  if(decisions.some(row=>!row)||new Set(decisions.map(row=>row[1])).size!==decisions.length)bad();
  for(const row of stage.selected){
   if(!decisions.some(choice=>choice[1]===row.name&&choice[2]===row.version))bad();
   const previous=union.get(row.name);if(previous&&JSON.stringify(previous)!==JSON.stringify(row))bad();union.set(row.name,row);
  }
  for(const line of stage.selection.split('\n'))if(line.startsWith("'"))lines.add(line);
 }
 if(JSON.stringify([...union.values()])!==JSON.stringify(candidate.selected)||[...lines].join('\n')!==candidate.selection)bad();
 return value;
}
module.exports.validateRetainedMetadata=validateRetainedMetadata;
// System retention does not borrow V23's local 90-day source policy. Bind the
// raw objects to the exact declared sources and the APT-authenticated cache;
// signature replay remains the later original-base consumer's responsibility.
function validateSystemRetentionSources(candidate,snapshot){
 const bad=()=>{throw fail('METADATA_RETENTION_SOURCE');};
 const prefixes=new Set();
 function add(addresses,suites,components){
  if(components!=='main')bad();
  for(const address of addresses.split(' '))for(const suite of suites.split(' ')){
   const prefix=address.replace(/\/$/,'')+'/dists/'+suite+'/';
   if(!/^http:\/\/deb\.debian\.org\/(?:debian\/dists\/trixie(?:-updates)?|debian-security\/dists\/trixie-security)\/$/.test(prefix)
    ||prefixes.has(prefix))bad();
   prefixes.add(prefix);
  }
 }
 for(const row of snapshot.files){
  const normalized=canonicalSources(row.path.split('/').at(-1),row.text);
  if(!normalized.trim())continue;
  if(row.path.endsWith('.sources')){
   for(const block of normalized.trim().split('\n\n')){
    const fields=Object.fromEntries(block.split('\n').map(line=>{const split=line.indexOf(': ');return [line.slice(0,split),line.slice(split+2)];}));
    add(fields.URIs,fields.Suites,fields.Components);
   }
  }else for(const line of normalized.trim().split('\n')){
   const match=/^deb \[[^\]]+\] (\S+) (\S+) (.+)$/.exec(line);if(!match)bad();add(match[1],match[2],match[3]);
  }
 }
 if(!prefixes.size)bad();
 const upstream=candidate.retainedMetadata.objects.filter(row=>row.kind==='upstream');
 for(const row of upstream)if(![...prefixes].some(prefix=>row.url.startsWith(prefix)))bad();
 const releases=candidate.indices.filter(row=>row.name.endsWith('_InRelease'));
 if(releases.length!==prefixes.size)bad();
 for(const prefix of prefixes){
  const release=upstream.find(row=>row.url===prefix+'InRelease');
  const cacheName=(prefix+'InRelease').slice('http://'.length).replaceAll('/','_');
  if(!release||!releases.some(row=>row.name===cacheName&&row.sha256===release.sha256&&row.bytes===release.bytes)
   ||!upstream.some(row=>row.url.startsWith(prefix+'main/binary-arm64/')))bad();
 }
}
function validateResultEnvelope(raw,binding){
 validateBinding(binding);
 if(typeof raw!=='string'||Buffer.byteLength(raw)>LIMITS.report)throw fail('METADATA_REPORT_LIMIT');
 const envelope=JSON.parse(raw),bad=()=>{throw fail('METADATA_ENVELOPE_INVALID');};
 if(!envelope||Object.keys(envelope).sort().join(',')!=='binding,candidate,commandFailure,errorCode,kind,ok,sourceSnapshot,version'
  ||![2,3].includes(envelope.version)||(envelope.version===3&&!metadataRetentionSpecification(binding.target))||envelope.kind!=='owned-policy-system-metadata-result'
  ||!envelope.binding||Object.keys(envelope.binding).sort().join(',')!=='base,runId,target'
  ||Object.keys(binding).some(key=>binding[key]!==envelope.binding[key])||typeof envelope.ok!=='boolean')bad();
 const commandFailure=envelope.commandFailure;
 if(commandFailure!==null){
  if(!commandFailure||Object.keys(commandFailure).sort().join(',')!=='args,executable,exitCode,partial,signal,stderr,stdout,version'
   ||commandFailure.version!==1||!['/usr/bin/apt-get','/usr/bin/apt-cache','/usr/lib/apt/apt-helper','/usr/bin/sha256sum'].includes(commandFailure.executable)
   ||!Array.isArray(commandFailure.args)||commandFailure.args.length>128
   ||commandFailure.args.some(arg=>typeof arg!=='string'||Buffer.byteLength(arg)>4096||/[\x00-\x1f\x7f]/.test(arg))
   ||Buffer.byteLength(JSON.stringify(commandFailure.args))>32768||typeof commandFailure.partial!=='boolean'
   ||!(commandFailure.exitCode===null||Number.isInteger(commandFailure.exitCode)&&commandFailure.exitCode>=0&&commandFailure.exitCode<=255)
   ||!(commandFailure.signal===null||/^SIG[A-Z0-9]{1,12}$/.test(commandFailure.signal)))bad();
  if(!validCommand(commandFailure.executable,commandFailure.args,binding.target,envelope.version===3))bad();
  for(const row of [commandFailure.stdout,commandFailure.stderr]){
   if(!row||Object.keys(row).sort().join(',')!=='base64,bytesObserved,bytesRetained,observedSha256,retainedSha256,truncated'
    ||!Number.isSafeInteger(row.bytesObserved)||row.bytesObserved<0||!Number.isSafeInteger(row.bytesRetained)
    ||row.bytesRetained<0||row.bytesRetained>32768||row.bytesRetained>row.bytesObserved
    ||typeof row.base64!=='string'||row.base64.length>43692||typeof row.truncated!=='boolean'
    ||row.truncated!==(row.bytesRetained<row.bytesObserved))bad();
   const data=Buffer.from(row.base64,'base64');
   // Host verifies retained bytes. For truncated streams, observedSha256 is
   // owned-guest evidence only: the discarded suffix cannot be replayed here.
   if(data.length!==row.bytesRetained||data.toString('base64')!==row.base64||createHash('sha256').update(data).digest('hex')!==row.retainedSha256
    ||!/^[a-f0-9]{64}$/.test(row.observedSha256)||(!row.truncated&&row.observedSha256!==row.retainedSha256))bad();
  }
  if(envelope.ok||(!commandFailure.partial&&(!Number.isInteger(commandFailure.exitCode)||commandFailure.exitCode<=0||commandFailure.signal!==null)))bad();
  if(!commandFailure.partial&&envelope.errorCode!=='METADATA_COMMAND_FAILED')bad();
 }
 const snapshot=envelope.sourceSnapshot;
 if(snapshot!==null){
  if(!snapshot||Object.keys(snapshot).sort().join(',')!=='files,kind,version'||snapshot.version!==1
   ||snapshot.kind!=='owned-image-apt-sources'||!Array.isArray(snapshot.files)||snapshot.files.length<1||snapshot.files.length>8)bad();
  const seen=new Set();let bytes=0;
  for(const file of snapshot.files){
   if(!file||Object.keys(file).sort().join(',')!=='bytes,path,sha256,text'||typeof file.path!=='string'
    ||!(file.path==='/etc/apt/sources.list'||/^\/etc\/apt\/sources\.list\.d\/[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.(?:list|sources)$/.test(file.path))
    ||seen.has(file.path)||typeof file.text!=='string'||!Number.isSafeInteger(file.bytes)||file.bytes<0||file.bytes>65536
    ||Buffer.byteLength(file.text)!==file.bytes||!/^[a-f0-9]{64}$/.test(file.sha256)
    ||createHash('sha256').update(file.text).digest('hex')!==file.sha256)bad();
   bytes+=file.bytes;if(bytes>8*65536)bad();seen.add(file.path);
  }
 }
 if(envelope.ok){
  if(envelope.errorCode!==null||snapshot===null)bad();validateCandidateReport(envelope.candidate,binding.target,envelope.version===3);
  if(envelope.version===3)validateRetainedMetadata(envelope.candidate,binding);
  else if(envelope.candidate.retainedMetadata!==undefined||envelope.candidate.selectionKind!==undefined)bad();
  const expected=new Map(snapshot.files.map(file=>[file.path==='/etc/apt/sources.list'?'main.list':file.path.split('/').at(-1),file.sha256]));
  if(expected.size!==snapshot.files.length)bad();
  if(!expected.has('main.list'))expected.set('main.list',createHash('sha256').update('').digest('hex'));
  if(envelope.candidate.sources.length!==expected.size||envelope.candidate.sources.some(row=>expected.get(row.name)!==row.sha256))bad();
  const keys=new Set();
  for(const file of snapshot.files){
   const normalized=canonicalSources(file.path.split('/').at(-1),file.text,metadataSourcePolicy(binding.target,envelope.version===3));
   for(const match of normalized.matchAll(/(?:Signed-By: |signed-by=)(\/usr\/share\/keyrings\/debian-archive-keyring\.(?:gpg|pgp))/g))keys.add(match[1]);
  }
  if(keys.size!==1||!keys.has(envelope.candidate.keyringPath))bad();
  if(envelope.version===3&&['v03-diagnostic','v24-system','v24-policy'].includes(binding.target))validateSystemRetentionSources(envelope.candidate,snapshot);
  const policy=metadataSourcePolicy(binding.target,envelope.version===3);
  if(policy){
   const originals=snapshot.files.map(file=>[file.path==='/etc/apt/sources.list'?'main.list':file.path.split('/').at(-1),file.text]);
   if(!originals.some(row=>row[0]==='main.list'))originals.push(['main.list','']);
   const expectedPolicy=sourcePolicyWitness(originals,policy,canonicalSources);
   // Ordering is the captured original-file order, not a caller-supplied sort.
   if(JSON.stringify(envelope.candidate.sourcePolicy)!==JSON.stringify(expectedPolicy))bad();
  }
 }
 else if(envelope.candidate!==null||typeof envelope.errorCode!=='string'
  ||!(/^(?:METADATA_[A-Z_]{1,64}|EACCES|ENOENT|ENOSPC|ECONNRESET|ECONNREFUSED|ETIMEDOUT|CERT_HAS_EXPIRED|UNABLE_TO_VERIFY_LEAF_SIGNATURE|ERR_TLS_CERT_ALTNAME_INVALID)$/.test(envelope.errorCode)))bad();
 return envelope;
}
module.exports.validateResultEnvelope=validateResultEnvelope;

// Runs only inside the digest-pinned disposable base container. This function
// is serialized as source, never evaluated by the importing host process.
// This is also serialized into the guest. The only upstream authority is the
// builder-admitted private CONNECT adapter, never a conventional proxy env var.
function admittedMetadataGet(url,authority,signal,onResponse){
 const http=require('node:http'),tls=require('node:tls'),{EventEmitter}=require('node:events');
 const request=new EventEmitter(),active=new Set();
 let stopped=false,finished=false,stageTimer;
 request.closed=new Promise(resolve=>request.once('close',resolve));
 const invalid=()=>Error('METADATA_UPSTREAM_AUTHORITY');
 if(!authority||Object.keys(authority).sort().join(',')!=='host,port'||authority.host!=='127.0.0.1'
  ||!Number.isInteger(authority.port)||authority.port<1||authority.port>65535)throw invalid();
 if(!(url instanceof URL)||url.protocol!=='http:'||url.hostname!=='deb.debian.org'||url.port||url.username||url.password
  ||url.search||url.hash||!/^\/(debian|debian-security)\/dists\/[A-Za-z0-9_./+-]+$/.test(url.pathname))throw Error('METADATA_DESTINATION');
 const closeIfIdle=()=>{if(!active.size)request.emit('close');};
 const fail=error=>{if(stopped)return;stopped=true;clearTimeout(stageTimer);for(const item of active)item.destroy();request.emit('error',error);closeIfIdle();};
 request.destroy=()=>{if(stopped)return;stopped=true;clearTimeout(stageTimer);for(const item of active)item.destroy();closeIfIdle();};
 const track=item=>{active.add(item);item.once('close',()=>{active.delete(item);if(stopped||finished)closeIfIdle();});return item;};
 if(signal?.aborted){queueMicrotask(()=>fail(Error('METADATA_ABORTED')));return request;}
 const abort=()=>fail(Error('METADATA_ABORTED'));
 signal?.addEventListener('abort',abort,{once:true});
 request.once('close',()=>signal?.removeEventListener('abort',abort));
 const connect=track(http.request({host:authority.host,port:authority.port,method:'CONNECT',path:'deb.debian.org:443',
  agent:false,headers:{Host:'deb.debian.org:443'}}));
 stageTimer=setTimeout(()=>fail(Error('METADATA_CONNECT_TIMEOUT')),15000);
 connect.once('response',response=>{response.destroy();fail(Error('METADATA_CONNECT_STATUS'));});
 connect.once('connect',(response,socket,head)=>{
  clearTimeout(stageTimer);
  if(response.statusCode!==200||head.length){socket.destroy();return fail(Error('METADATA_CONNECT_STATUS'));}
  track(socket);
  const secure=track(tls.connect({socket,servername:'deb.debian.org',rejectUnauthorized:true,ALPNProtocols:['http/1.1']}));
  stageTimer=setTimeout(()=>fail(Error('METADATA_TLS_TIMEOUT')),15000);
  secure.once('secureConnect',()=>{
   clearTimeout(stageTimer);
   if(!secure.authorized||secure.alpnProtocol&&secure.alpnProtocol!=='http/1.1')return fail(Error('METADATA_TLS_AUTHORITY'));
   // With agent:false Node creates a fresh default Agent and ignores this
   // createConnection callback, which would permit a direct socket. Omit the
   // agent so this exact already-authenticated tunnel is the only connection.
   const upstream=track(http.request({method:'GET',host:'deb.debian.org',port:443,path:url.pathname,
    createConnection:()=>secure,headers:{Host:'deb.debian.org',Connection:'close'}},incoming=>{
     track(incoming);onResponse(incoming);
     incoming.once('end',()=>{finished=true;if(!active.size)request.emit('close');});
   }));
   upstream.once('error',fail);upstream.end();
  });
  secure.once('error',fail);
 });
 connect.once('error',fail);connect.end();
 return request;
}
module.exports.admittedMetadataGet=admittedMetadataGet;
// Exact private bind, never caller-selected filesystem authority. Objects are
// raw upstream bytes; no authentication claim is made by merely retaining them.
function createMetadataRetention(fs,crypto,binding,kind='v23-original-apt-retention'){
 const root='/metadata-retained',M=1024**2,objects=[],known=new Map(),pending=new Set();let bytes=0,sequence=0;
 const bad=()=>{throw Error('METADATA_RETENTION_INVALID');};
 const kinds={'v23-registry':'v23-original-apt-retention','v24-system':'v24-system-original-apt-retention',
  'v33-pricing':'v33-pricing-original-apt-retention','v24-policy':'v24-policy-original-apt-retention',
  'listings-package':'listings-original-apt-retention','v03-diagnostic':'v03-diagnostic-original-apt-retention'};
 if(!binding||typeof binding.target!=='string'||!Object.hasOwn(kinds,binding.target)||kind!==kinds[binding.target])bad();
 const info=fs.lstatSync(root);
 if(!info.isDirectory()||info.isSymbolicLink()||info.uid!==0||(info.mode&0o777)!==0o700||fs.realpathSync(root)!==root||fs.readdirSync(root).length)bad();
 fs.mkdirSync(root+'/objects',{mode:0o700});fs.mkdirSync(root+'/partial',{mode:0o700});
 function begin(kind,url,maximum){
  if(objects.length+pending.size>=64||!['upstream','keyring','installed-status'].includes(kind))bad();
  if(kind==='upstream'){
   const u=new URL(url);if(u.protocol!=='http:'||u.host!=='deb.debian.org'||u.search||u.hash||u.username||u.password
    ||!/^\/(?:debian|debian-security)\/dists\/[A-Za-z0-9_./+-]+$/.test(u.pathname)||objects.some(row=>row.url===url))bad();
  }else if(url!==null)bad();
  const temporary=root+'/partial/'+String(++sequence).padStart(4,'0'),fd=fs.openSync(temporary,'wx',0o600);
  const digest=crypto.createHash('sha256');let count=0,closed=false;pending.add(fd);
  return {
   write(chunk){
    if(closed||count+chunk.length>maximum||bytes+chunk.length>144*M)bad();
    let offset=0;while(offset<chunk.length){const n=fs.writeSync(fd,chunk,offset,chunk.length-offset);if(!Number.isInteger(n)||n<=0||n>chunk.length-offset)bad();offset+=n;}
    digest.update(chunk);count+=chunk.length;bytes+=chunk.length;
   },
   finish(){
    if(closed||count===0)bad();fs.fsyncSync(fd);fs.closeSync(fd);pending.delete(fd);closed=true;
    const sha256=digest.digest('hex'),file='objects/'+sha256;
    if(known.has(sha256)){if(known.get(sha256)!==count)bad();fs.unlinkSync(temporary);}
    else{fs.chmodSync(temporary,0o444);fs.renameSync(temporary,root+'/'+file);known.set(sha256,count);}
    const row={kind,url,file,sha256,bytes:count};objects.push(row);return row;
   },
  };
 }
 return {
  begin,
  store(kind,raw){const item=begin(kind,null,kind==='keyring'?M:8*M);item.write(raw);return item.finish();},
  manifest(stages){if(pending.size||!objects.some(row=>row.kind==='upstream'))bad();return {version:1,kind,binding,objects,stages,retainedBytes:bytes,capBytes:144*M};},
  writeReport(encoded,manifest){
   if(pending.size)bad();
   for(const [name,text]of [['manifest.json',JSON.stringify(manifest)],['result.json',encoded]]){
    const raw=Buffer.from(text);if(raw.length>M||bytes+raw.length>144*M)bad();
    const fd=fs.openSync(root+'/'+name,'wx',0o600);
    try{let offset=0;while(offset<raw.length){const n=fs.writeSync(fd,raw,offset,raw.length-offset);if(!Number.isInteger(n)||n<=0)bad();offset+=n;}fs.fsyncSync(fd);}finally{fs.closeSync(fd);}
    fs.chmodSync(root+'/'+name,0o444);bytes+=raw.length;
   }
  },
  close(){for(const fd of pending){try{fs.closeSync(fd);}finally{pending.delete(fd);}}},
 };
}
module.exports.createMetadataRetention=createMetadataRetention;
async function guestMetadataMain(canonicalSources,binding,metadataAptOptions,admittedMetadataGet,packageSelection,sourcePolicyWitness,authenticatedReleaseFreshness,createMetadataRetention){
 const fs=require('node:fs'),http=require('node:http'),cp=require('node:child_process'),crypto=require('node:crypto');
 // Reserve the other 1MiB diagnostic allowance for pull/SSH/container stderr.
 const M=1024**2,limit={compressed:128*M,file:32*M,expanded:512*M,diagnostic:M-4096,report:M};
 let compressed=0,expanded=0,diagnostic=0,failed=null,sourceSnapshot=null,commandFailure=null,retention=null;
 const children=new Set(),requests=new Set(),allRequests=new Set(),controller=new AbortController();
 const hash=b=>crypto.createHash('sha256').update(b).digest('hex');
 const stage=value=>process.stderr.write('DVAIA_METADATA_STAGE='+value+'\n');
 function emit(ok,candidate,errorCode){
  const encoded=JSON.stringify({version:packageSelection.retention?3:2,kind:'owned-policy-system-metadata-result',binding,ok,candidate,errorCode,sourceSnapshot,commandFailure});
  if(Buffer.byteLength(encoded)>limit.report)throw Error('METADATA_REPORT_LIMIT');
  if(retention&&ok)retention.writeReport(encoded,candidate.retainedMetadata);
  process.stdout.write(encoded);
 }
 function stop(error){failed ||= error;controller.abort();for(const r of requests)r.destroy();for(const child of children)child.kill('SIGKILL');}
 const timer=setTimeout(()=>stop(Error('METADATA_DEADLINE')),290000);
 const proxyPort=Number(process.env.DVAIA_METADATA_PROXY_PORT);
 if(!/^[1-9]\d{0,4}$/.test(process.env.DVAIA_METADATA_PROXY_PORT||'')||proxyPort>65535)
  throw Error('METADATA_UPSTREAM_AUTHORITY');
 const upstreamAuthority=Object.freeze({host:'127.0.0.1',port:proxyPort});
 const roots=new Set(['deb.debian.org']);
 const proxy=http.createServer((request,response)=>{
  let url;try{url=new URL(request.url);}catch{response.destroy();return stop(Error('METADATA_URL'));}
  if(request.method!=='GET'||url.protocol!=='http:'||url.port||url.username||url.password||!roots.has(url.hostname)
    ||url.search||url.hash||!/^\/(debian|debian-security)\/dists\/[A-Za-z0-9_./+-]+$/.test(url.pathname)){
   response.destroy();return stop(Error('METADATA_DESTINATION'));
  }
  const upstream=admittedMetadataGet(url,upstreamAuthority,controller.signal,incoming=>{
   if(incoming.statusCode!==200){incoming.destroy();response.destroy();return stop(Error('METADATA_HTTP_STATUS'));}
   let capture;try{capture=retention?.begin('upstream',url.href,url.pathname.endsWith('/InRelease')?M:limit.file);}catch(error){incoming.destroy();response.destroy();return stop(error);}
   response.writeHead(200);let bytes=0;
   incoming.on('data',chunk=>{
    bytes+=chunk.length;compressed+=chunk.length;
    if(bytes>(url.pathname.endsWith('/InRelease')?M:limit.file)||compressed>limit.compressed){stop(Error('METADATA_COMPRESSED_LIMIT'));response.destroy();return;}
    try{capture?.write(chunk);}catch(error){stop(error);response.destroy();return;}
    if(!response.write(chunk))incoming.pause();
   });
   response.on('drain',()=>incoming.resume());incoming.on('end',()=>{try{capture?.finish();response.end();}catch(error){stop(error);response.destroy();}});
   incoming.on('error',error=>{stop(error);response.destroy();});
  });
  requests.add(upstream);allRequests.add(upstream);
  upstream.on('close',()=>requests.delete(upstream));upstream.on('error',error=>{stop(error);response.destroy();});
 });
 proxy.on('connect',(_req,socket)=>{socket.destroy();stop(Error('METADATA_CONNECT_DENIED'));});
 function command(file,args,{expandedOutput=false}={}){
  return new Promise((resolve,reject)=>{
   if(failed)return reject(failed);
   const child=cp.spawn(file,args,{env:{PATH:'/usr/sbin:/usr/bin:/sbin:/bin',HOME:'/metadata',TMPDIR:'/metadata',LC_ALL:'C'},stdio:['ignore','pipe','pipe']});
   children.add(child);const chunks=[];let bytes=0;
   function capture(){let observed=0,retained=0;const parts=[],digest=crypto.createHash('sha256');return {
    push(chunk){observed+=chunk.length;digest.update(chunk);const size=Math.min(chunk.length,32768-retained);if(size){parts.push(Buffer.from(chunk.subarray(0,size)));retained+=size;}},
    snapshot(){const data=Buffer.concat(parts);return {bytesObserved:observed,bytesRetained:retained,base64:data.toString('base64'),retainedSha256:hash(data),observedSha256:digest.copy().digest('hex'),truncated:retained<observed};}
   };}
   const stdout=capture(),stderr=capture();
   function record(code,signal,closed){commandFailure={version:1,executable:file,args:[...args],exitCode:Number.isInteger(code)?code:null,
    signal:signal||null,partial:!closed||code===null||!!failed,stdout:stdout.snapshot(),stderr:stderr.snapshot()};}
   child.stdout.on('data',chunk=>{
    stdout.push(chunk);
    bytes+=chunk.length;
    if(expandedOutput){expanded+=chunk.length;if(expanded>limit.expanded)stop(Error('METADATA_EXPANDED_LIMIT'));}
    else{diagnostic+=chunk.length;if(diagnostic>limit.diagnostic)stop(Error('METADATA_DIAGNOSTIC_LIMIT'));else chunks.push(chunk);}
   });
   child.stderr.on('data',chunk=>{stderr.push(chunk);diagnostic+=chunk.length;if(diagnostic>limit.diagnostic)stop(Error('METADATA_DIAGNOSTIC_LIMIT'));});
   child.on('error',error=>{stop(error);record(null,null,false);reject(error);});
   child.on('close',(code,signal)=>{children.delete(child);if(failed||code!==0){record(code,signal,true);reject(failed||Error('METADATA_COMMAND_FAILED'));}else resolve(Buffer.concat(chunks).toString());});
  });
 }
 let outcome;
 try{
  stage('guest-enter');
  if(packageSelection.retention)retention=createMetadataRetention(fs,crypto,binding,packageSelection.retentionKind);
  const release=fs.readFileSync('/etc/os-release','utf8');
  if(!/^ID=debian$/m.test(release))throw Error('METADATA_BASE_DISTRO');
  fs.mkdirSync('/metadata/lists/partial',{recursive:true});fs.mkdirSync('/metadata/cache/archives/partial',{recursive:true});
  stage('sources');
  for(const directory of ['/etc','/etc/apt','/etc/apt/sources.list.d']){
   const stat=fs.lstatSync(directory);
   if(stat.isSymbolicLink()||!stat.isDirectory()||fs.realpathSync(directory)!==directory)throw Error('METADATA_SOURCE_PATH');
  }
  let sourceBytes=0;
  function readSource(file){
   const stat=fs.lstatSync(file);
   if(stat.isSymbolicLink()||!stat.isFile()||stat.size>65536||stat.size<0)throw Error('METADATA_SOURCE_PATH');
   if(sourceBytes+stat.size>8*65536)throw Error('METADATA_SOURCE_LIMIT');
   const raw=fs.readFileSync(file);
   if(raw.length!==stat.size||raw.length>65536)throw Error('METADATA_SOURCE_LIMIT');
   const text=raw.toString('utf8');if(!Buffer.from(text).equals(raw))throw Error('METADATA_SOURCE_ENCODING');
   sourceBytes+=raw.length;return text;
  }
  let sources='',mainPath=null;
  let mainPresent=false;
  try{fs.lstatSync('/etc/apt/sources.list');mainPresent=true;}catch(error){if(error.code!=='ENOENT')throw error;}
  if(mainPresent){mainPath='/etc/apt/sources.list';sources=readSource(mainPath);}
  // Debian deb822 sources are retained as separate files; reject arbitrary
  // URI schemes/hosts before invoking apt and normalize HTTPS through proxy.
  fs.mkdirSync('/metadata/sources');
  const originals=[];
  for(const name of fs.readdirSync('/etc/apt/sources.list.d'))if(name.endsWith('.sources')||name.endsWith('.list')){
   if(!/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.(?:list|sources)$/.test(name)||originals.length>=7)throw Error('METADATA_SOURCE_PATH');
   const file='/etc/apt/sources.list.d/'+name;originals.push([name,readSource(file),file]);
  }
  originals.push(['main.list',sources,mainPath]);
  if(originals.length>8)throw Error('METADATA_SOURCE_LIMIT');
  sourceSnapshot={version:1,kind:'owned-image-apt-sources',files:originals.filter(row=>row[2]!==null).map(([,text,file])=>({path:file,text,bytes:Buffer.byteLength(text),sha256:hash(text)}))};
  if(!sourceSnapshot.files.length)throw Error('METADATA_SOURCE_MISSING');
  const sourcePolicy=packageSelection.sourcePolicy?sourcePolicyWitness(originals,packageSelection.sourcePolicy,canonicalSources):null;
  const selectedKeyrings=new Set();
  for(const [name,value]of originals){
   if(Buffer.byteLength(value)>65536)throw Error('METADATA_SOURCE_LIMIT');
   const normalized=canonicalSources(name,value,packageSelection.sourcePolicy??null);
   for(const match of normalized.matchAll(/(?:Signed-By: |signed-by=)(\/usr\/share\/keyrings\/debian-archive-keyring\.(?:gpg|pgp))/g))selectedKeyrings.add(match[1]);
   fs.writeFileSync('/metadata/sources/'+name,normalized);
  }
  if(selectedKeyrings.size!==1)throw Error('METADATA_KEYRING_SELECTION');
  const keyringPath=[...selectedKeyrings][0];
  for(const directory of ['/usr','/usr/share','/usr/share/keyrings']){
   const stat=fs.lstatSync(directory);
   if(stat.isSymbolicLink()||!stat.isDirectory()||fs.realpathSync(directory)!==directory)throw Error('METADATA_KEYRING_PATH');
  }
  const keyringStat=fs.lstatSync(keyringPath);
  if(keyringStat.isSymbolicLink()||!keyringStat.isFile()||keyringStat.size<1||keyringStat.size>M
   ||fs.realpathSync(keyringPath)!==keyringPath)throw Error('METADATA_KEYRING_PATH');
  const keyring=fs.readFileSync(keyringPath);
  if(keyring.length!==keyringStat.size||keyring.length>M)throw Error('METADATA_KEYRING_LIMIT');
  if(retention){const stat=fs.lstatSync('/var/lib/dpkg/status');if(!stat.isFile()||stat.isSymbolicLink()||stat.size<1||stat.size>8*M||fs.realpathSync('/var/lib/dpkg/status')!=='/var/lib/dpkg/status')throw Error('METADATA_STATUS_PATH');}
  const installedStatus=fs.readFileSync('/var/lib/dpkg/status');
  if(retention){retention.store('keyring',keyring);retention.store('installed-status',installedStatus);}
  await new Promise(resolve=>proxy.listen(0,'127.0.0.1',resolve));
  const port=proxy.address().port;
  const opts=metadataAptOptions(port);
  // The tmpfs/memory limits contain update itself. The following independent
  // expansion meter gates offline resolution, not apt's internal decompressor.
  stage('apt-update');
  await command('/usr/bin/apt-get',[...opts,'update','--error-on=any']);
  const releaseFreshness=[];
  if(sourcePolicy){
   for(const name of ['deb.debian.org_debian_dists_trixie_InRelease','deb.debian.org_debian_dists_trixie-updates_InRelease','deb.debian.org_debian-security_dists_trixie-security_InRelease']){
    const file='/metadata/lists/'+name,stat=fs.lstatSync(file);
    if(stat.isSymbolicLink()||!stat.isFile()||stat.size<1||stat.size>M||fs.realpathSync(file)!==file)throw Error('METADATA_RELEASE_PATH');
    const raw=fs.readFileSync(file),text=raw.toString('utf8');
    if(raw.length!==stat.size||raw.length>M||!Buffer.from(text).equals(raw))throw Error('METADATA_RELEASE_PATH');
    releaseFreshness.push(authenticatedReleaseFreshness(name,text,Date.now()));
   }
  }
  stage('expanded-meter');
  const indices=[];
  for(const name of fs.readdirSync('/metadata/lists')){
   const file='/metadata/lists/'+name;if(!fs.statSync(file).isFile()||name==='lock')continue;
   await command('/usr/lib/apt/apt-helper',['cat-file',file],{expandedOutput:true});
   const digest=(await command('/usr/bin/sha256sum',[file])).split(' ')[0];
   if(!/^[a-f0-9]{64}$/.test(digest))throw Error('METADATA_INDEX_DIGEST');
   indices.push({name,bytes:fs.statSync(file).size,sha256:digest});
  }
  // Metadata-only: --print-uris suppresses package download and installation.
  stage('selection');
  async function resolvePackages(packages){
  const selection=await command('/usr/bin/apt-get',[...opts,'--print-uris','--download-only','--yes','--no-install-recommends','install',...packages]);
  const simulation=await command('/usr/bin/apt-get',[...opts,'--simulate','--no-install-recommends','install',...packages]);
  const selected=[];
  for(const line of simulation.split('\n')){
   if(!line.startsWith('Inst '))continue;
   const match=/^Inst ([a-z0-9][a-z0-9+.-]*(?::arm64)?) (?:\[[^\]]+\] )?\(([^\s]+) /.exec(line);
   if(!match||selected.length>=128)throw Error('METADATA_SELECTION_FORMAT');
   const output=await command('/usr/bin/apt-cache',[...opts,'show',match[1]+'='+match[2]]);
   const records=output.trim().split(/\n\n+/).map(block=>Object.fromEntries(block.split('\n').filter(row=>/^[A-Za-z][A-Za-z0-9-]*: /.test(row)).map(row=>{const i=row.indexOf(': ');return [row.slice(0,i),row.slice(i+2)];})));
   const record=records.find(row=>row.Version===match[2]&&['arm64','all'].includes(row.Architecture));
   if(!record||!record.Package||!/^pool\/[A-Za-z0-9_./+~:-]+\.deb$/.test(record.Filename||'')
     ||!/^[a-f0-9]{64}$/.test(record.SHA256||'')||!/^\d+$/.test(record.Size||''))throw Error('METADATA_PACKAGE_RECORD');
   selected.push({name:record.Package,version:record.Version,architecture:record.Architecture,
    filename:record.Filename,bytes:Number(record.Size),sha256:record.SHA256});
  }
  return {packages,selection,simulation,selected,installedStatusSha256:hash(installedStatus)};
  }
  let selection,selected,retainedMetadata;
  if(retention){
   const stages=[];
   for(const {name,packages}of packageSelection.retentionStages){
    if(hash(fs.readFileSync('/var/lib/dpkg/status'))!==hash(installedStatus))throw Error('METADATA_STATUS_CHANGED');
    stages.push({name,...await resolvePackages(packages)});
    if(hash(fs.readFileSync('/var/lib/dpkg/status'))!==hash(installedStatus))throw Error('METADATA_STATUS_CHANGED');
   }
   // Top-level legacy view is explicitly an aggregate. Exact original stdout
   // and independent selections remain in each stage, never relabeled as union.
   selection=[...new Set(stages.flatMap(row=>row.selection.split('\n')).filter(line=>line.startsWith("'")))].join('\n');
   const union=new Map();for(const row of stages.flatMap(stage=>stage.selected)){
    const previous=union.get(row.name);if(previous&&JSON.stringify(previous)!==JSON.stringify(row))throw Error('METADATA_STAGE_CONFLICT');union.set(row.name,row);
   }
   selected=[...union.values()];retainedMetadata=retention.manifest(stages);
  }else({selection,selected}=await resolvePackages(packageSelection.install));
  if(failed)throw failed;
  const report={version:1,candidateOnly:true,qualified:false,requestedPackages:packageSelection.requested,release,keyringPath,keyringBytes:keyring.length,keyringSha256:hash(keyring),installedStatusSha256:hash(fs.readFileSync('/var/lib/dpkg/status')),
   sources:originals.map(([name,value])=>({name,sha256:hash(value)})),indices,selection,selected,compressedBytes:compressed,
   expandedBytes:expanded,expandedMeterStage:'after-update-before-offline-resolution',diagnosticBytes:diagnostic};
  if(sourcePolicy){report.sourcePolicy=sourcePolicy;report.releaseFreshness=releaseFreshness;}
  if(retention){report.retainedMetadata=retainedMetadata;report.selectionKind='deduplicated-stage-uri-aggregate';}
  stage('report');outcome={ok:true,candidate:report,errorCode:null};
 }catch(error){
  const allowed=new Set(['EACCES','ENOENT','ENOSPC','ECONNRESET','ECONNREFUSED','ETIMEDOUT','CERT_HAS_EXPIRED','UNABLE_TO_VERIFY_LEAF_SIGNATURE','ERR_TLS_CERT_ALTNAME_INVALID']);
  const code=allowed.has(error.code)?error.code:/^METADATA_[A-Z_]{1,64}$/.test(error.message)?error.message:'METADATA_FAILED';
  process.stderr.write('DVAIA_METADATA_ERROR='+code+'\n');outcome={ok:false,candidate:null,errorCode:code};
 }
 finally{
  clearTimeout(timer);stop(Error('METADATA_FINISHED'));proxy.close();
  const retirement=Promise.all([...allRequests].map(request=>request.closed));
  let retirementTimer;
  const retired=await Promise.race([retirement.then(()=>true),new Promise(resolve=>{retirementTimer=setTimeout(()=>resolve(false),5000);})]);
  clearTimeout(retirementTimer);
  if(!retired){process.exitCode=1;outcome={ok:false,candidate:null,errorCode:'METADATA_TRANSPORT_RETIREMENT'};}
  retention?.close();
 }
 emit(outcome.ok,outcome.candidate,outcome.errorCode);
}
module.exports.guestMetadataSource=(binding,options={})=>{
 validateBinding(binding);
 const retained=metadataRetentionSpecification(binding.target);
 if(!options||typeof options!=='object'||Array.isArray(options)||Object.keys(options).some(key=>key!=='retention')
  ||options.retention!==undefined&&(!retained||options.retention!==retained.mode))throw fail('METADATA_RETENTION_MODE');
 const spec=targetSpecification(binding.target),policy=metadataSourcePolicy(binding.target,!!options.retention),packages={requested:spec.packages,install:spec.installPackages,...(policy?{sourcePolicy:policy}:{}),...(options.retention?{retention:options.retention,retentionKind:retained.kind,retentionStages:retained.stages}:{})};
 return `(${guestMetadataMain.toString()})(${canonicalSources.toString()},${JSON.stringify(binding)},${metadataAptOptions.toString()},${admittedMetadataGet.toString()},${JSON.stringify(packages)},${sourcePolicyWitness.toString()},${authenticatedReleaseFreshness.toString()},${createMetadataRetention.toString()}).catch(()=>{process.exitCode=1});`;
};

async function acquireMetadata({root,runId,target,runner,verify}={}){
 const fs=require('node:fs/promises'),path=require('node:path'),{Readable}=require('node:stream');
 const build=require('./ownedMcpBoundedBuild'),tools=build._internals;
 const targetSpec=targetSpecification(target),spec=build.specification(root,runId);
 const binding={runId,target,base:targetSpec.base};
 const guestSource=module.exports.guestMetadataSource(binding),guestSourceSha256=createHash('sha256').update(guestSource).digest('hex');
 runner ||= tools.execute;verify ||= tools.verifyHost;
 await verify(spec);
 const before=tools.checkInventory(await runner(spec,'inventory'));
 await fs.mkdir(spec.artifact,{mode:0o700});
 let primary,result,intended=false,acquisitionDiagnostics=null,cleanupDiagnostics=null,sourceSnapshot=null,commandFailure=null;const cleanup=[];
 try{
  await fs.writeFile(path.join(spec.artifact,'metadata-intent.json'),JSON.stringify({version:1,target,base:targetSpec.base,guestSourceSha256,limits:LIMITS,before}),{flag:'wx',mode:0o600});
  intended=true;
  const raw=await runner(spec,'metadata-acquire',{args:[targetSpec.base],input:Readable.from([guestSource]),onDiagnostics:value=>{acquisitionDiagnostics=value;}});
  const envelope=validateResultEnvelope(raw,binding);sourceSnapshot=envelope.sourceSnapshot;commandFailure=envelope.commandFailure;
  if(!envelope.ok)throw fail(envelope.errorCode);
  result=envelope.candidate;
  tools.checkDaemon(JSON.parse(await runner(spec,'inspect')),spec);
 }catch(error){primary=error;}
 if(intended)try{if((await runner(spec,'metadata-cleanup',{onDiagnostics:value=>{cleanupDiagnostics=value;}})).trim()!=='absent')throw fail('METADATA_CLEANUP_UNPROVEN');}catch(error){cleanup.push(error.code||error.name);}
 try{if(tools.checkInventory(await runner(spec,'inventory'))!==before)throw fail('METADATA_SHARED_STATE_CHANGED');}catch(error){cleanup.push(error.code||error.name);}
 const receipt={version:1,target,base:targetSpec.base,guestSourceSha256,candidate:primary?null:result,error:primary?.code||primary?.name||null,
  sourceSnapshot,commandFailure,acquisitionDiagnostics,cleanupDiagnostics,cleanupErrors:cleanup,cleanupVerified:cleanup.length===0,executionApproved:false};
 try{await fs.writeFile(path.join(spec.artifact,'metadata-result.json'),JSON.stringify(receipt),{flag:'wx',mode:0o600});}
 catch(error){if(!primary)primary=error;else cleanup.push('METADATA_REPORT_WRITE_FAILED');}
 if(primary||cleanup.length)throw new AggregateError([primary,...cleanup].filter(Boolean),'Metadata acquisition failed');
 return receipt;
}
module.exports.acquireMetadata=acquireMetadata;
