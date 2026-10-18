'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),{pathToFileURL}=require('node:url');
async function qualifyLegacyFileSsiRendered({backendPort,token,runtimeRoot,expectedCompleted=5}){
 assert.equal(process.env.PG_TEST_DISPOSABLE,'yes');
 const clientRoot=path.resolve('client');process.env.PORT=String(backendPort);
 const {createServer}=await import(pathToFileURL(path.join(clientRoot,'node_modules/vite/dist/node/index.js')));
 let vite,browser,pid;
 try{
  vite=await createServer({root:clientRoot,configFile:path.join(clientRoot,'vite.config.mjs'),configLoader:'native',cacheDir:path.join(runtimeRoot,'vite-cache'),server:{host:'127.0.0.1',port:0,strictPort:false},plugins:[{name:'owned-legacy-page-entry',configureServer(server){server.middlewares.use(async(req,res,next)=>{
   if(req.url!=='/__legacy_qualification')return next();res.setHeader('Content-Type','text/html');res.setHeader('Cache-Control','no-store');
   res.end(await server.transformIndexHtml('/__legacy_qualification','<div id="root"></div><script type="module">import React from "react";import {createRoot} from "react-dom/client";import axios from "axios";import Page from "/src/pages/workshops/LegacyFileSsiWorkshopPage.js";import {AuthProvider} from "/src/context/AuthContext.js";axios.defaults.headers.common.Authorization='+JSON.stringify('Bearer '+token)+';createRoot(document.getElementById("root")).render(React.createElement(AuthProvider,null,React.createElement(Page)));</script>'));
  });}}]});await vite.listen();
  const origin=`http://127.0.0.1:${vite.httpServer.address().port}`;
  // macOS rejects Chrome's nested sandbox inside the outer configuration-read fence.
  const browserArgs=['--disable-background-networking','--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1, EXCLUDE localhost',...(process.env.LEGACY_BROWSER_OUTER_SANDBOX==='1'?['--no-sandbox']:[])];
  browser=await require('puppeteer').launch({headless:true,dumpio:true,args:browserArgs,userDataDir:path.join(runtimeRoot,'browser-profile')});pid=browser.process().pid;
  fs.writeFileSync(path.join(runtimeRoot,'browser-ownership.json'),JSON.stringify({pid,profile:path.join(runtimeRoot,'browser-profile')}),{mode:0o600});
  const page=await browser.newPage();await page.setViewport({width:1280,height:900});const errors=[];page.on('pageerror',e=>{errors.push(e.message);console.error('Legacy rendered page error:',e.message);});
  await page.evaluateOnNewDocument(value=>localStorage.setItem('token',value),token);
  await page.setRequestInterception(true);page.on('request',r=>r.url().startsWith(origin+'/')||/^(data|blob|about):/.test(r.url())?r.continue():r.abort());
  await page.goto(origin+'/__legacy_qualification');await page.waitForSelector('[data-workshop="legacy_sensitive_file_ssi"]');
  assert.ok((await page.$eval('body',el=>el.innerText)).includes(`${expectedCompleted} of 5 objectives completed`));
  assert.equal(await page.$$eval('summary',els=>els.some(e=>e.textContent==='Hints')),false);
  assert.equal(await page.$$eval('summary',els=>els.some(e=>e.textContent==='Solution')),true);
  await page.click('[data-scenario-tab="templates"]');assert.equal(await page.$eval('select',el=>el.value),'ssi_injection');
  await page.click('[data-scenario-tab="agent"]');assert.equal(await page.$$eval('select option',els=>els.length),2);
  await page.click('[data-scenario-tab="files"]');
  await page.$$eval('button',els=>els.find(e=>e.textContent==='Reset exercise').click());await page.waitForSelector('[role="alertdialog"]');
  await page.$$eval('[role="alertdialog"] button',els=>els.find(e=>/reset/i.test(e.textContent)).click());
  await page.waitForFunction(()=>document.body.innerText.includes('0 of 5 objectives completed'));
  assert.deepEqual(errors,[]);return {newPageRendered:true,canonicalCompleted:expectedCompleted,canonicalTotal:5,hintSolutionGatesIndependent:true,scenarioNavigation:true,confirmedHttpReset:true};
 }finally{
  if(browser)await browser.close();if(vite)await vite.close();
  if(pid){let alive=false;try{process.kill(pid,0);alive=true;}catch(e){if(e.code!=='ESRCH')throw e;}assert.equal(alive,false,'Owned browser exited');}
 }
}
module.exports={qualifyLegacyFileSsiRendered};
