'use strict';
// Fixed readiness-only GET executed inside the already identified manager.
// No caller URL, headers, command or endpoint is accepted.
const CLIENT=[
 "const http=require('node:http');let done=false;",
 "const finish=code=>{if(done)return;done=true;clearTimeout(timer);if(code){request.destroy();process.stdout.write('not-ready');}process.exitCode=0;};",
 "const request=http.get({host:'127.0.0.1',port:8095,path:'/manager/health',headers:{authorization:'Bearer '+process.env.LISTINGS_CONTROL_TOKEN}},response=>{",
 "let size=0;const chunks=[];response.on('data',chunk=>{size+=chunk.length;if(size>16384)finish(1);else chunks.push(chunk);});",
 "response.on('end',()=>{if(done)return;try{const row=JSON.parse(Buffer.concat(chunks));if(response.statusCode!==200||row.version!==1||row.ready!==true||row.capability!=='owned-listings-manager.v1'||row.runtimeDigest!==process.argv[1])throw Error('health');process.stdout.write('ready');finish(0);}catch{finish(1);}});",
 "response.on('error',()=>finish(1));});",
 "const timer=setTimeout(()=>finish(1),1500);request.on('error',()=>finish(1));"
].join('');
function program(){return [
 ' # Fixed authenticated readiness within the existing startup reservation.',
 ' import time',
 ' health_end=time.monotonic()+20',
 ' health_source='+JSON.stringify(CLIENT),
 ' while True:',
 "  health=docker('exec',cid,'node','-e',health_source,RUNTIME)",
 "  if health=='ready':break",
 "  assert health=='not-ready'",
 "  if time.monotonic()+5>=health_end:raise RuntimeError('V03_LISTINGS_HEALTH_EXPIRED')",
 '  time.sleep(0.1)',
 " if time.monotonic()>=health_end:raise RuntimeError('V03_LISTINGS_HEALTH_EXPIRED')",
 ''
].join('\n');}
module.exports={program};
