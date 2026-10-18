const test = require('node:test');
const assert = require('node:assert/strict');
let opaqueFrameCors;
test.before(async () => { ({ opaqueFrameCors } = await import('../client/vite.opaque-frame-cors.mjs')); });
function request(url, origin = 'null', method = 'GET', vary = '') {
  let middleware;
  opaqueFrameCors().configureServer({middlewares:{use(fn){middleware=fn;}}});
  const headers = {Vary:vary}; let continued = false;
  middleware({url,method,headers:{origin}}, {setHeader(k,v){headers[k]=v;},getHeader(k){return headers[k];}},()=>{continued=true;});
  assert.equal(continued,true); return headers;
}
test('opaque public runtime dependencies are allowed for GET and HEAD',()=>{
  for (const path of ['/node_modules/vite/dist/client/env.mjs','/node_modules/react-toastify/dist/ReactToastify.css','/node_modules/.vite/deps/react.js?v=abc']) {
    for (const method of ['GET','HEAD']) assert.equal(request(path,'null',method)['Access-Control-Allow-Origin'],'null');
  }
});
test('private files, other dependencies, APIs, arbitrary origins and mutation methods retain their policies',()=>{
  for(const path of ['/api/auth/me','/@fs/private/secret','/node_modules/vite/package.json','/node_modules/react-toastify/dist/other.css','/node_modules/vite/dist/client/env.mjs/extra']) assert.equal(request(path)['Access-Control-Allow-Origin'],undefined);
  for(const origin of ['https://evil.example','http://localhost:3000',undefined]) assert.equal(request('/node_modules/vite/dist/client/env.mjs',origin === undefined ? '' : origin)['Access-Control-Allow-Origin'],undefined);
  for(const method of ['POST','OPTIONS','DELETE']) assert.equal(request('/node_modules/vite/dist/client/env.mjs','null',method)['Access-Control-Allow-Origin'],undefined);
});
test('Vary preserves existing entries without duplicating Origin',()=>{
 assert.equal(request('/@vite/client','null','GET','Accept-Encoding')['Vary'],'Accept-Encoding, Origin');
 assert.equal(request('/@vite/client','null','GET','origin, Accept-Encoding')['Vary'],'origin, Accept-Encoding');
});
test('declared font assets are public, arbitrary font dependency files are not',()=>{
 assert.equal(request('/node_modules/@fontsource-variable/inter/files/inter-latin-wght-normal.woff2')['Access-Control-Allow-Origin'],'null');
 for(const path of ['/node_modules/@fontsource-variable/inter/package.json','/node_modules/@fontsource-variable/inter/files/private.woff2']) assert.equal(request(path)['Access-Control-Allow-Origin'],undefined);
});
