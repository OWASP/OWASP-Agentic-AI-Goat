'use strict';
const assert=require('node:assert/strict');
async function pointer(page,handle){assert.ok(handle,'Required visible control');await handle.evaluate(e=>e.scrollIntoView({block:'center',behavior:'instant'}));await page.waitForFunction(e=>{const r=e.getBoundingClientRect(),s=getComputedStyle(e),hit=document.elementFromPoint(r.x+r.width/2,r.y+r.height/2);return r.width>0&&r.height>0&&s.visibility!=='hidden'&&Number(s.opacity)>0&&!e.disabled&&(hit===e||e.contains(hit));},{},handle);await handle.click();}
module.exports={pointer};
