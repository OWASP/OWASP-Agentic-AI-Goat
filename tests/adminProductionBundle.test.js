const assert = require('node:assert/strict');
const { execFile } = require('node:child_process');
const fs = require('node:fs');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const { promisify } = require('node:util');
const puppeteer = require('puppeteer');

const execFileAsync = promisify(execFile);
const clientDir = path.resolve(__dirname, '../client');

function bounded(promise, label, ms = 10000) {
  let timer;
  return Promise.race([promise, new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error(`${label} deadline`)), ms);
  })]).finally(() => clearTimeout(timer));
}

async function buildProductionClient(buildDir) {
  assert.ok(fs.existsSync(path.join(clientDir, 'package.json')), 'client package.json required; never run npm in an incomplete fixture');
  const { buildBoundary, discoverSecrets, artifactEnvironment } = require('../scripts/lib/isolated-test-boundary');
  const directory = path.dirname(buildDir), source = fs.realpathSync(path.resolve(clientDir, '..'));
  const data = artifactEnvironment(directory);
  for (const key of ['HOME','TMPDIR','LOGS_DIR','XDG_CONFIG_HOME','XDG_CACHE_HOME','XDG_DATA_HOME']) {
    fs.mkdirSync(data[key], {recursive:true, mode:0o700});
  }
  const masks = path.join(directory, 'boundary-masks');
  fs.mkdirSync(masks, {mode:0o700});
  fs.mkdirSync(path.join(masks,'empty-dir'), {mode:0o500});
  fs.writeFileSync(path.join(masks,'empty-file'), '', {mode:0o400});
  const cli = path.join(clientDir, 'node_modules/vite/bin/vite.js');
  // Actual app/config only. The npm build chain also writes unrelated renderer artifacts.
  const boundary = buildBoundary({source,directory,secrets:discoverSecrets(source,os.homedir()),
    executable:process.execPath,args:[cli,'build',clientDir,'--config',path.join(clientDir,'vite.config.mjs'),
      '--configLoader','runner','--outDir',buildDir,'--emptyOutDir']});
  try {
    await execFileAsync(boundary.command, boundary.args, {
      cwd: boundary.cwd,
      env: {...data, PATH:path.dirname(process.execPath)+':/usr/bin:/bin', NODE_ENV:'production',
        BUILD_PATH:buildDir, BROWSERSLIST_IGNORE_OLD_DATA:'1', CI:'false'},
      maxBuffer:10*1024*1024, timeout:120000, killSignal:'SIGKILL',
    });
  } catch (error) {
    const output = [error.stdout, error.stderr].filter(Boolean).join('\n');
    throw new Error(`production client build failed:\n${output}`, {cause:error});
  }
}

function contentType(filePath) {
  if (filePath.endsWith('.html')) return 'text/html; charset=utf-8';
  if (filePath.endsWith('.js')) return 'text/javascript; charset=utf-8';
  if (filePath.endsWith('.css')) return 'text/css; charset=utf-8';
  if (filePath.endsWith('.json')) return 'application/json; charset=utf-8';
  return 'application/octet-stream';
}

function startProductionBuildServer(buildDir) {
  let chatCalls=0;
  const server = http.createServer((request, response) => {
    if (request.url === '/api/auth/status') {
      response.writeHead(200, { 'Content-Type': 'application/json' });
      response.end(JSON.stringify({
        authenticated: true,
        user: { id: 1, username: 'admin', role: 'admin', adminLevel: 1, isAdmin: true },
      }));
      return;
    }

    const pathname=request.url.split('?')[0];
    const json=value=>{response.writeHead(200,{'Content-Type':'application/json'});response.end(JSON.stringify(value));};
    if(pathname==='/api/workshop/challenges')return json({success:true,challenges:[{id:'csrf_prompt_injection',title:'CSRF via AI',route:'/vulnerabilities/csrf-via-ai',isVisible:true}]});
    if(pathname==='/api/workshop/config/snapshot')return json({revision:1,exercises:{csrf_workshop:{isVisible:true,objectives:{csrf_g1:{isVisible:true,label:'Controlled GET lesson'}}}}});
    if(pathname==='/api/workshop/csrf/victim-state')return json({success:true,state:{agentChatEnabled:true,victim:'Controlled victim',defenses:{csrfToken:false},baseline:{email:'owned@example.invalid',password:'synthetic',mfaEnabled:true,balance:100,role:'customer',payeeCount:0},profile:{email:'owned@example.invalid'},security:{password:'synthetic',mfaEnabled:true},account:{balance:100,role:'customer',payees:[]},attackLog:[]}});
    if(pathname==='/api/workshop/csrf/chat'&&request.method==='POST'){
      request.resume();chatCalls++;
      return json(chatCalls===1?{response:'**existing**'}:{response:'**literal** <img src="https://example.invalid/inert"> [link](https://example.invalid)',responseFormat:'plain_text'});
    }
    if (request.url.startsWith('/api/')) {
      response.writeHead(200, { 'Content-Type': 'application/json' });
      response.end('{}');
      return;
    }

    const requestPath = request.url.split('?')[0];
    const relativePath = requestPath === '/' ? 'index.html' : requestPath.replace(/^\/+/, '');
    const resolvedPath = path.resolve(buildDir, relativePath);
    const filePath = resolvedPath.startsWith(`${buildDir}${path.sep}`) && fs.existsSync(resolvedPath)
      ? resolvedPath
      : path.join(buildDir, 'index.html');

    response.writeHead(200, { 'Content-Type': contentType(filePath) });
    fs.createReadStream(filePath).pipe(response);
  });

  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => resolve(server));
  });
}

test('production admin bundle loads without CommonJS/ES-module runtime rejection', { timeout: 180000 }, async (t) => {
  const tempRoot = await fs.promises.mkdtemp(path.join(fs.realpathSync(os.tmpdir()), 'dvaia-admin-production-'));
  const buildDir = path.join(tempRoot, 'build');
  let server;
  let browser;
  t.after(async () => {
    const cleanupErrors = [];
    try {
      if (browser) await bounded(browser.close(), 'browser close', 5000);
    } catch (error) {
      cleanupErrors.push(error);
    }
    try {
      if (server?.listening) {
        await bounded(new Promise((resolve, reject) => {
          server.close((error) => error ? reject(error) : resolve());
          server.closeAllConnections?.();
        }), 'HTTP close', 5000);
      }
    } catch (error) {
      cleanupErrors.push(error);
    }
    if (cleanupErrors.length > 0) throw new AggregateError(cleanupErrors, 'test cleanup failed; owned data retained');
    try {
      await fs.promises.rm(tempRoot, { recursive: true, force: true });
    } catch (error) {
      cleanupErrors.push(error);
    }
    if (cleanupErrors.length > 0) throw new AggregateError(cleanupErrors, 'test cleanup failed');
  });

  await buildProductionClient(buildDir);
  assert.match(fs.readFileSync(path.join(buildDir, 'secureshop-frame.html'), 'utf8'), /type="module" crossorigin/, 'opaque SecureShop frame must retain compiled module CORS bootstrap');
  assert.equal(
    fs.existsSync(path.join(buildDir, 'index.html')),
    true,
    'production build did not create index.html in isolated output',
  );

  server = await bounded(startProductionBuildServer(buildDir), 'HTTP listen');

  browser = await puppeteer.launch({ headless: true, timeout:15000,
    executablePath:process.env.PUPPETEER_EXECUTABLE_PATH || puppeteer.executablePath(),
    userDataDir:path.join(tempRoot,'browser-profile') });

  const page = await browser.newPage();
  const pageErrors = [];
  const consoleErrors = [];
  const loadedChunks = [];
  const consoleDetails=[];const diagnosticReads=[];const failedRequests=[];
  page.on('requestfailed',request=>failedRequests.push({url:request.url(),failure:request.failure()}));
  page.on('pageerror', (error) => pageErrors.push(error.stack || error.message));
  page.on('console', (message) => {
    if (message.type() === 'error') { consoleErrors.push(message.text());diagnosticReads.push(Promise.all(message.args().map(arg=>arg.evaluate(value=>({message:value?.message,stack:value?.stack,text:typeof value==='string'?value:null})).catch(()=>null))).then(args=>consoleDetails.push(args))); }
  });
  page.on('response', (response) => {
    if (/\/(?:static\/js|assets)\/[^/]+\.js(?:\?|$)/.test(response.url())) {
      loadedChunks.push(response.url());
    }
  });

  const address = server.address();
  await page.goto(`http://127.0.0.1:${address.port}/admin/exercises`, {
    waitUntil: 'domcontentloaded', timeout:10000,
  });
  await page.waitForFunction(
    () => document.body.innerText.includes('Exercises Management')
      || document.body.innerText.includes('Something went wrong'),
    { timeout: 5000 },
  );

  assert.ok(loadedChunks.length > 0, 'admin route must load at least one production chunk');
  const bodyText = await page.evaluate(() => document.body.innerText);
  assert.match(
    bodyText,
    /Exercises Management/,
    `admin exercise UI did not render; browser errors:\n${[...pageErrors, ...consoleErrors].join('\n')}`,
  );
  assert.equal(
    pageErrors.some((message) => message.includes('ES Modules may not assign module.exports')),
    false,
    `admin chunk crashed: ${pageErrors.join('\n')}`,
  );
  const externalRequests=[];
  await page.setRequestInterception(true);
  page.on('request',request=>{const url=new URL(request.url());if(['http:','https:'].includes(url.protocol)&&url.origin!==`http://127.0.0.1:${address.port}`){externalRequests.push(request.url());return request.abort();}return request.continue();});
  await page.goto(`http://127.0.0.1:${address.port}/vulnerabilities/csrf-via-ai`,{waitUntil:'domcontentloaded',timeout:10000});
  const input='textarea[placeholder^="Ask the agent"]';
  try { await page.waitForSelector(input,{timeout:10000}); } catch(error) { await Promise.all(diagnosticReads);throw new Error('CSRF fixture failed: '+JSON.stringify({pageErrors,consoleErrors,consoleDetails,failedRequests,pathname:await page.evaluate(()=>location.pathname),text:await page.evaluate(()=>document.body.innerText.slice(0,1200))}),{cause:error}); }
  await page.type(input,'controlled markdown');await page.focus(input);await page.keyboard.press('Enter');
  await page.waitForFunction(()=>[...document.querySelectorAll('strong')].some(e=>e.textContent==='existing'),{timeout:10000});
  await page.waitForFunction(selector=>!document.querySelector(selector).disabled,{timeout:10000},input);
  await page.type(input,'controlled plain');await page.focus(input);await page.keyboard.press('Enter');
  const literal='**literal** <img src="https://example.invalid/inert"> [link](https://example.invalid)';
  await page.waitForFunction(value=>[...document.querySelectorAll('span')].some(e=>e.textContent===value&&e.style.whiteSpace==='pre-wrap'),{timeout:10000},literal);
  assert.equal(await page.evaluate(value=>{const e=[...document.querySelectorAll('span')].find(e=>e.textContent===value&&e.style.whiteSpace==='pre-wrap');return !!e&&!e.querySelector('strong,a,img,script,iframe');},literal),true);
  assert.deepEqual(externalRequests,[],'plain response must not initiate external requests');

});
