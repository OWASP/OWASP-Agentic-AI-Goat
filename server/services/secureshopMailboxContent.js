'use strict';
const {createHash}=require('node:crypto');
const MAX_BODY_BYTES=32768,MAX_HEADER_BYTES=8192,MAX_RECIPIENTS=16;
function invalid(message){return Object.assign(Error(message),{code:'MAILBOX_INVALID_ARGUMENT'});}
function text(value,label,max,{empty=false}={}){
 if(typeof value!=='string'||(!empty&&!value.length)||!value.isWellFormed()||value.includes('\0')||Buffer.byteLength(value)>max)throw invalid(`Invalid ${label}`);
 return value;
}
function plain(value){return value&&Object.getPrototypeOf(value)===Object.prototype;}
function address(value){return typeof value==='string'&&/^[A-Za-z0-9.!#$%&'*+\/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$/.test(value)&&Buffer.byteLength(value)<=254;}
function hash(value){return createHash('sha256').update(value).digest('hex');}
// @intentional-vulnerability html-injection
// @intentional-vulnerability xss-stored-email
// Markdown formatting preserves raw HTML for the opaque owned inbox renderer.
function renderUnsafeMarkdown(source){
 if(!source)return '';
 return source.split(/\n{2,}/).map(raw=>{let out=raw.replace(/\n/g,'<br>\n').replace(/\*\*([^*]+)\*\*/g,'<strong>$1</strong>').replace(/(^|[^*])\*([^*]+)\*/g,'$1<em>$2</em>').replace(/\[([^\]]+)\]\(([^)]+)\)/g,'<a href="$2">$1</a>');return /^\s*<[a-zA-Z!/]/.test(out)?out:`<p>${out}</p>`;}).join('\n');
}
function recipientsFromHeaders(raw){
 const recipients=[];
 for(const line of raw.split(/\r?\n/)){
  const match=/^(?:To|Cc|Bcc):\s*(.*)$/i.exec(line);if(!match)continue;
  for(const candidate of match[1].split(',')){
   const value=candidate.trim();if(!address(value))throw invalid('Invalid synthetic envelope recipient');
   if(!recipients.includes(value))recipients.push(value);
   if(recipients.length>MAX_RECIPIENTS)throw invalid('Too many synthetic envelope recipients');
  }
 }
 if(!recipients.length)throw invalid('Synthetic envelope recipient required');
 return recipients;
}
function prepareMailboxMessage(input,{mode}={}){
 if(!['vuln','fixed'].includes(mode))throw invalid('Trusted mailbox mode required');
 const keys=['from','to','subject','body_markdown'];
 if(!plain(input)||Reflect.ownKeys(input).length!==keys.length||keys.some(key=>!Object.hasOwn(Object.getOwnPropertyDescriptor(input,key)||{},'value')))throw invalid('Invalid mailbox message');
 const from=text(input.from,'sender',2048),to=text(input.to,'recipient',2048),subject=text(input.subject,'subject',2048),body=text(input.body_markdown,'body',MAX_BODY_BYTES,{empty:true});
 if(mode==='fixed'&&[from,to,subject].some(value=>/[\r\n]/.test(value)))throw invalid('Header newlines are disabled in fixed mode');
 // @intentional-vulnerability email-header-injection
 // Injected Bcc/Cc headers produce owned synthetic delivery effects, never SMTP.
 const headersRaw=text(`From: ${from}\r\nTo: ${to}\r\nSubject: ${subject}`,'headers',MAX_HEADER_BYTES);
 const recipients=recipientsFromHeaders(headersRaw),bodyHtml=mode==='vuln'?renderUnsafeMarkdown(body):body.split(/\n{2,}/).map(part=>part?`<p>${part.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;').replace(/\n/g,'<br>\n')}</p>`:'').join('\n');
 const contentSha256=hash(JSON.stringify(['secureshop-owned-mailbox-content-v1',from,to,subject,body,bodyHtml,headersRaw,recipients]));
 return Object.freeze({version:1,from,to,subject,bodyMarkdown:body,bodyHtml,headersRaw,recipients:Object.freeze(recipients),contentSha256});
}
module.exports={prepareMailboxMessage,renderUnsafeMarkdown,MAX_BODY_BYTES,MAX_HEADER_BYTES,MAX_RECIPIENTS};
