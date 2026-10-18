'use strict';
const fs=require('node:fs');
const {spawn}=require('node:child_process');
const C=require('./upload-preview-contract');
const runtime=()=>({nodeVersion:process.version,platform:process.platform,arch:process.arch});
const PREVIEW_ATTESTATION='upload-preview-init-v1';
function assertNamespace(){
 if(process.platform!=='linux'||process.getuid?.()!==10001||process.getgid?.()!==10001
  ||process.env.DVAIA_UPLOAD_PREVIEW_ATTESTED!==PREVIEW_ATTESTATION)throw Error('Upload preview requires its attested namespace');
}
async function decodeGif(bytes,sharp=require('sharp')){
 if(bytes.length<13||bytes.length>C.MAX_INPUT_BYTES||!['GIF87a','GIF89a'].includes(bytes.subarray(0,6).toString('ascii')))throw Error('Bounded GIF required');
 const logicalWidth=bytes.readUInt16LE(6),logicalHeight=bytes.readUInt16LE(8);
 if(!logicalWidth||!logicalHeight||logicalWidth>C.MAX_DIMENSION||logicalHeight>C.MAX_DIMENSION||logicalWidth*logicalHeight>C.MAX_PIXELS)throw Error('GIF logical screen bound exceeded');
 sharp.cache(false);sharp.concurrency(1);
 const image=sharp(bytes,{animated:true,limitInputPixels:C.MAX_PIXELS,failOn:'warning',sequentialRead:true});
 const meta=await image.metadata();
 if(meta.format!=='gif'||(meta.pages??1)!==1||!meta.width||!meta.height||meta.width>C.MAX_DIMENSION||meta.height>C.MAX_DIMENSION||meta.width*meta.height>C.MAX_PIXELS)throw Error('Single bounded GIF frame required');
 const {data,info}=await image.ensureAlpha().raw().toBuffer({resolveWithObject:true});
 if(info.channels!==4||info.width!==meta.width||info.height!==meta.height||data.length!==info.width*info.height*4||data.length>C.MAX_RAW_BYTES)throw Error('Full GIF decode correspondence failed');
 return{data,info,decoder:{sharpVersion:sharp.versions.sharp,vipsVersion:sharp.versions.vips,
  logicalWidth,logicalHeight,width:info.width,height:info.height,pages:1,rawSha256:C.hash(data),rawByteCount:data.length}};
}
function runNode(bytes,{syntax=false}={}){
 assertNamespace();
 return new Promise(resolve=>{
  let child,started=false,bytesObserved=0,timedOut=false,truncated=false,killTimer;
  try{child=spawn('/usr/local/bin/node',['--max-old-space-size=64',...(syntax?['--check']:[]),'--input-type=commonjs'],
   {env:{PATH:'/usr/local/bin:/usr/bin:/bin',HOME:'/work',LANG:'C.UTF-8'},stdio:['pipe','pipe','pipe']});}
  catch{return resolve({started:false,exitCode:null,timedOut:false,truncated:false});}
  const stop=()=>{child.kill('SIGTERM');killTimer??=setTimeout(()=>child.kill('SIGKILL'),200);};
  const timer=setTimeout(()=>{timedOut=true;stop();},1000);
  child.once('spawn',()=>{started=true;});child.once('error',()=>{started=false;});
  for(const stream of [child.stdout,child.stderr])stream.on('data',chunk=>{bytesObserved+=chunk.length;if(bytesObserved>C.MAX_OUTPUT_BYTES){truncated=true;stop();}});
  child.stdin.on('error',()=>{});child.stdin.end(bytes);
  child.once('close',code=>{clearTimeout(timer);clearTimeout(killTimer);resolve({started,exitCode:Number.isInteger(code)?code:null,timedOut,truncated});});
 });
}
async function processPreview(input,{bytes,sharp=require('sharp'),execute=runNode,measuredRuntime=runtime()}={}){
 const request=C.normalizeUploadPreviewRequest(input),original=bytes??Buffer.from(request.bytesBase64,'base64');
 if(!Buffer.isBuffer(original)||original.length!==request.byteCount||C.hash(original)!==request.bodySha256)throw Error('Original stored file bytes changed');
 const result={version:C.VERSION,operationId:request.operationId,uploadOperationId:request.uploadOperationId,
  uploadEffectId:request.uploadEffectId,storageKey:request.storageKey,requestSha256:C.requestDigest(request),bindingSha256:request.bindingSha256,
  bodySha256:request.bodySha256,mode:request.mode,isolation:C.ISOLATION,runtime:measuredRuntime,decoder:null,status:'invalid_image',
  scriptSyntaxValid:null,originalInterpreterStarted:false,reencoded:null,exitCode:null,timedOut:false,truncated:false,
  drained:true,workerAttested:true,codeEffectObserved:false,effectSha256:null};
 let decoded;try{decoded=await decodeGif(original,sharp);}catch{return result;}
 result.decoder=decoded.decoder;
 if(request.mode==='fixed'){
  try{
   // Reconstruct from decoded pixels, so original GIF extensions and appended
   // program bytes cannot be copied into the fixed preview representation.
   const png=await sharp(decoded.data,{raw:{width:decoded.info.width,height:decoded.info.height,channels:4},limitInputPixels:C.MAX_PIXELS}).png().toBuffer();
   if(!png.length||png.length>C.MAX_REENCODE_BYTES)throw Error('Reencoded output bound exceeded');
   result.status='fixed_reencoded';result.reencoded={format:'png',bodySha256:C.hash(png),byteCount:png.length};
  }catch{result.status='failed';}
  return result;
 }
 const checked=await execute(original,{syntax:true});
 result.timedOut=checked.timedOut;result.truncated=checked.truncated;
 if(!checked.started||checked.timedOut||checked.truncated){result.status='failed';return result;}
 result.scriptSyntaxValid=checked.exitCode===0;
 if(!result.scriptSyntaxValid){result.status='image_only';return result;}
 // @intentional-vulnerability file-upload-polyglot-rce
 // The legacy preview handler dispatches the exact decoded-but-unchanged
 // uploaded image bytes to Node. It exists only in the attested owned sandbox.
 const executed=await execute(original,{syntax:false});
 result.originalInterpreterStarted=executed.started;result.exitCode=executed.exitCode;
 result.timedOut=executed.timedOut;result.truncated=executed.truncated;
 result.status=executed.started&&executed.exitCode===0&&!executed.timedOut&&!executed.truncated?'executed':'failed';
 return result;
}
async function main(){
 assertNamespace();
 const marker=process.argv[2];if(!/^__UPLOAD_PREVIEW_[a-f0-9]{64}__$/.test(marker||''))throw Error('Invalid private result frame');
 if(process.argv[3]==='--probe'){
  const decoded=await decodeGif(Buffer.from('47494638396101000100800000000000ffffff21f90401000000002c00000000010001000002024401003b','hex'));
  process.stdout.write(marker+JSON.stringify({ready:true,isolation:C.ISOLATION,runtime:runtime(),sharpVersion:decoded.decoder.sharpVersion,vipsVersion:decoded.decoder.vipsVersion}));return;
 }
 const request=C.normalizeUploadPreviewRequest(JSON.parse(fs.readFileSync('/preview/request.json','utf8')));
 const stat=fs.lstatSync('/preview/original.gif');
 if(!stat.isFile()||stat.isSymbolicLink()||stat.size!==request.byteCount)throw Error('Immutable original artifact required');
 const receipt=await processPreview(request,{bytes:fs.readFileSync('/preview/original.gif')});
 process.stdout.write(marker+JSON.stringify(receipt));
}
if(require.main===module)main().catch(()=>{process.stderr.write('Owned upload preview failed\n');process.exitCode=70;});
module.exports={PREVIEW_ATTESTATION,decodeGif,processPreview,runNode,assertNamespace};
