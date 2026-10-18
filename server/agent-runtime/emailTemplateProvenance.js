'use strict';
// Track unchanged model characters through native replacement-string semantics.
// Inserted profile text (including $&/$`/$' expansions) is conservatively profile-owned.
function createTemplateProvenance(raw){
 let html=String(raw),owners=Array(html.length).fill(true);
 return {
  replace(pattern,replacement){
   const value=String(replacement),previous=html,previousOwners=owners;let cursor=0,next='',nextOwners=[];
   for(const match of previous.matchAll(pattern)){
    const start=match.index,end=start+match[0].length;
    next+=previous.slice(cursor,start);nextOwners=nextOwners.concat(previousOwners.slice(cursor,start));
    const inserted=value.replace(/\$([$&`'])/g,(_,symbol)=>symbol==='$'?'$':symbol==='&'?match[0]:symbol==='`'?previous.slice(0,start):previous.slice(end));
    next+=inserted;nextOwners=nextOwners.concat(Array(inserted.length).fill(false));cursor=end;
   }
   next+=previous.slice(cursor);nextOwners=nextOwners.concat(previousOwners.slice(cursor));html=next;owners=nextOwners;return this;
  },
  append(value){html+=value;owners=owners.concat(Array(value.length).fill(false));return this;},
  get html(){return html;},
  snapshot(){const ranges=[];for(let i=0;i<owners.length;){if(!owners[i]){i++;continue;}const start=i;while(i<owners.length&&owners[i])i++;ranges.push({start,end:i});}return{html,modelRanges:ranges};}
 };
}
module.exports={createTemplateProvenance};
