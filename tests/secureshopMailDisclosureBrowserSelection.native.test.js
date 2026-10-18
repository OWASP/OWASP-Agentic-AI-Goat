'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const {selectInboxUser}=require('./fixtures/secureshopMailDisclosureBrowser');
const executablePath=process.env.MAIL_SELECTION_BROWSER_EXECUTABLE;
test('real native number input in iframe supports helper clear and incremental typing',{skip:!executablePath,timeout:30000},async()=>{
 const profile=fs.mkdtempSync(path.join(os.tmpdir(),'mail-selection-browser-'));let browser,closed=false;
 try{
  browser=await require('puppeteer').launch({executablePath,userDataDir:profile,headless:true,args:['--no-sandbox']});
  const page=await browser.newPage();await page.setContent('<iframe></iframe>');
  // Native DOM setup only; helper performs every edit through real keyboard input.
  const frame=await (await page.$('iframe')).contentFrame();await frame.setContent('<input type="number" data-testid="inbox-userid" value="12">');
  const original=await frame.$('[data-testid="inbox-userid"]');
  for(const id of [123,4,2147483647]){
   await selectInboxUser({page,frame,id});
   assert.deepEqual(await original.evaluate(el=>({connected:el.isConnected,focused:document.activeElement===el,value:el.value})),{connected:true,focused:true,value:String(id)});
  }
 }finally{
  if(browser){await browser.close();closed=true;}else closed=true;
  if(closed)fs.rmSync(profile,{recursive:true,force:true});
 }
});
