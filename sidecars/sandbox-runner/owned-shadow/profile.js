'use strict';
const fs=require('node:fs'),path=require('node:path');
function renderOwnedShadowProfile(name){if(!/^owasp-ai-goat-owned-shadow-[a-f0-9]{12}$/.test(name||''))throw TypeError('Dedicated owned shadow profile required');return fs.readFileSync(path.join(__dirname,'../owned-http/http-profile.apparmor.in'),'utf8').replaceAll('@@SUPERVISOR_PROFILE@@',name);}
module.exports={renderOwnedShadowProfile};
