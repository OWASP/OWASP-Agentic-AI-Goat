'use strict';
const assert=require('node:assert/strict');
const UI_LABELS=Object.freeze({
  "csrf_g1": "1. Recon the target",
  "csrf_g2": "2. Forge GET via <img> pixel",
  "csrf_g3": "3. Defense blocks the pixel",
  "csrf_p1": "1. Forge POST via auto-submit <form>",
  "csrf_p2": "2. Forge POST via fetch()+credentials",
  "csrf_p3": "3. Defense blocks the form",
  "csrf_x1": "1. Recon the victim inbox",
  "csrf_x2": "2. Send the attack email",
  "csrf_x3": "3. Trigger \u2014 agent reads the email",
  "csrf_i1": "1. Poison the RAG (XSS payload)",
  "csrf_i2": "2. Trigger \u2014 ask on the poisoned topic",
  "csrf_i3": "3. Prove persistence (re-fires)"
});
const BOUNDS=Object.freeze({parentSeconds:1440,childSeconds:960,buildSeconds:180,stores:16,postgresMiB:1024,maxModelHttp:8,modelHttpSeconds:60});
const CHAIN_BOUNDS=Object.freeze({...BOUNDS,parentSeconds:1920,childSeconds:1560,maxModelHttp:18});
function assertContract({catalog,uiSource,adminSource,launcherSource}){
 assert.deepEqual(catalog.map(r=>r.id).sort(),Object.keys(UI_LABELS).sort());
 for(const [id,label]of Object.entries(UI_LABELS)){assert.ok(uiSource.includes("id: '"+id+"', label: '"+label+"'"),id);}
 assert.ok(uiSource.includes('className="obj-content"'));assert.ok(uiSource.includes('Execute observed payload'));
 assert.ok(adminSource.includes('data-objective-id={objId}'));
 // SecureShop is an application; workshop rows still expose their exact key.
 assert.ok(adminSource.includes("data-exercise-key={cKey === 'secureshop_agent_security' ? undefined : cKey}"));
 assert.ok(launcherSource.includes('--csrf-full-app'));const guard=launcherSource.match(/^\s*if not \((args\.dpi_rendered[^\n]+)\):/m);assert.ok(guard,'qualified-package guard required');assert.ok(guard[1].split(/\s+or\s+/).includes('args.csrf_full_app'),'CSRF must bypass unrelated Listings package qualification');
 return{objectiveIds:Object.keys(UI_LABELS),bounds:BOUNDS};
}
module.exports={UI_LABELS,BOUNDS,CHAIN_BOUNDS,assertContract};
