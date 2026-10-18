'use strict';
// Resource-free final-image model: literal local COPY and static relative JS imports.
// RUN-generated files, dynamic imports and package dependencies require runtime qualification.
const fs=require('node:fs'),path=require('node:path');
const parser=require(require.resolve('@babel/parser',{paths:[path.resolve(__dirname,'../../client')]}));
const imagePath=(cwd,name)=>path.posix.resolve(cwd,name);
function imageCopies(context,dockerfile){
 let cwd='/',files=new Map(),directories=new Set(['/']);
 const mkdir=name=>{while(name!=='/'){directories.add(name);name=path.posix.dirname(name);}};
 for(const line of dockerfile.replace(/\\\r?\n/g,' ').split(/\r?\n/)){
  const match=/^\s*(FROM|WORKDIR|COPY)\s+(.+?)\s*$/i.exec(line);if(!match)continue;
  const [,instruction,raw]=match;
  if(instruction.toUpperCase()==='FROM'){cwd='/';files=new Map();directories=new Set(['/']);continue;}
  if(instruction.toUpperCase()==='WORKDIR'){if(/[\s$]/.test(raw))throw Error('Unsupported WORKDIR');cwd=imagePath(cwd,raw);mkdir(cwd);continue;}
  let value=raw,from=false;
  while(value.startsWith('--')){const flag=/^--([^\s]+)\s+/.exec(value);if(!flag)throw Error('Unsupported COPY flag');if(flag[1].startsWith('from='))from=true;else if(!/^(chown|chmod)=/.test(flag[1]))throw Error('Unsupported COPY flag');value=value.slice(flag[0].length);}
  const parts=value.startsWith('[')?JSON.parse(value):value.match(/(?:"[^"\n]*"|'[^'\n]*'|[^\s]+)/g)?.map(x=>x.replace(/^(['"])(.*)\1$/,'$2'));
  if(!Array.isArray(parts)||parts.length<2||parts.some(x=>typeof x!=='string'||/[\n$*?]/.test(x)))throw Error('Unsupported COPY paths');
  const destination=parts.at(-1),sources=parts.slice(0,-1),target=imagePath(cwd,destination);
  if(from){if(/\.[cm]?js$/.test(destination)||destination.endsWith('/')||sources.length!==1)throw Error('Unmodeled build-stage JavaScript/directory COPY');mkdir(path.posix.dirname(target));files.set(target,null);continue;}
  if(sources.length>1&&!destination.endsWith('/'))throw Error('Multi-source COPY requires directory');
  for(const source of sources){
   const full=path.resolve(context,source);if(full!==context&&!full.startsWith(context+path.sep))throw Error('COPY outside context');
   const stat=fs.lstatSync(full);if(stat.isSymbolicLink())throw Error('Unmodeled COPY symlink');
   const walk=(host,image)=>{const st=fs.lstatSync(host);if(st.isSymbolicLink())throw Error('Unmodeled COPY symlink');if(st.isDirectory()){mkdir(image);for(const child of fs.readdirSync(host))walk(path.join(host,child),path.posix.join(image,child));}else{mkdir(path.posix.dirname(image));files.set(image,host);}};
   const dest=stat.isDirectory()?target:(destination.endsWith('/')||directories.has(target)?path.posix.join(target,path.basename(source)):target);walk(full,dest);
  }
 }
 return files;
}
function staticReferences(source){
 const ast=parser.parse(source,{sourceType:'unambiguous',allowReturnOutsideFunction:true});const refs=new Set();
 function walk(node){if(!node||typeof node!=='object')return;
  if(node.type==='CallExpression'&&node.callee?.type==='Identifier'&&node.callee.name==='require'&&node.arguments.length===1&&node.arguments[0].type==='StringLiteral')refs.add(node.arguments[0].value);
  if(['ImportDeclaration','ExportNamedDeclaration','ExportAllDeclaration'].includes(node.type)&&node.source?.type==='StringLiteral')refs.add(node.source.value);
  for(const [key,value] of Object.entries(node)){if(['loc','start','end','comments','leadingComments','trailingComments','innerComments'].includes(key))continue;if(Array.isArray(value))value.forEach(walk);else if(value&&typeof value==='object')walk(value);}
 }walk(ast);return [...refs].filter(x=>x.startsWith('.'));
}
function verifyImageJavaScript(context,dockerfile){
 const files=imageCopies(path.resolve(context),dockerfile);
 const resolve=(name,seen=new Set())=>{if(seen.has(name))return null;seen.add(name);for(const candidate of [name,name+'.js',name+'.json',name+'.node'])if(files.has(candidate))return candidate;
  const pkg=files.get(path.posix.join(name,'package.json'));if(pkg){const main=JSON.parse(fs.readFileSync(pkg,'utf8')).main;if(typeof main==='string'){const found=resolve(path.posix.resolve(name,main),seen);if(found)return found;}}
  for(const suffix of ['index.js','index.json','index.node'])if(files.has(path.posix.join(name,suffix)))return path.posix.join(name,suffix);return null;};
 for(const [image,host] of files){if(!/\.[cm]?js$/.test(image))continue;for(const ref of staticReferences(fs.readFileSync(host,'utf8'))){const requested=path.posix.resolve(path.posix.dirname(image),ref);if(!resolve(requested))throw Error(`${image} runtime dependency ${ref} is absent from final image (${requested})`);}}
 return files;
}
module.exports={imageCopies,staticReferences,verifyImageJavaScript};
