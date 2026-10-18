'use strict';
const {createHash}=require('node:crypto');
const VERSION='csrf-selected-mail-render-v2';
const sha=value=>createHash('sha256').update(value,'utf8').digest('hex');
function text(value){return value.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');}
function renderSelectedMail({body,mode}){
 if(typeof body!=='string'||!body.isWellFormed()||Buffer.byteLength(body)>65536||!['vuln','fixed'].includes(mode))throw TypeError('Bounded original mail and canonical mode required');
 const html=mode==='vuln'?body:'<pre style="white-space:pre-wrap">'+text(body)+'</pre>';
 return Object.freeze({version:VERSION,mode,policy:mode==='vuln'?'original_tool_html':'escaped_inert_text',originalSha256:sha(body),renderedSha256:sha(html),html});
}
function validateRendering(value,{body,mode}){
 if(!value||Object.keys(value).sort().join(',')!=='html,mode,originalSha256,policy,renderedSha256,version')return false;
 const expected=renderSelectedMail({body,mode});return Object.keys(expected).every(key=>value[key]===expected[key]);
}
module.exports={VERSION,renderSelectedMail,validateRendering};
