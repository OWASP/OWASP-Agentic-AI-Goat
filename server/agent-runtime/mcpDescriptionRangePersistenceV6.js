'use strict';
const {isDeepStrictEqual:equal}=require('node:util');
const exact=(x,keys)=>x&&typeof x==='object'&&!Array.isArray(x)&&equal(Object.keys(x).sort(),[...keys].sort());
const text=(x,min,max)=>typeof x==='string'&&x.trim().length>=min&&x.length<=max;
function range(value,quote,prefix,field){
 if(!exact(value,['first','last','fieldId','startChar','endChar','startByte','endByte','quote'])||value.quote!==quote
  ||typeof value.first!=='string'||typeof value.last!=='string'||!prefix.test(value.first)||!prefix.test(value.last)
  ||(field!==null?value.fieldId!==field:typeof value.fieldId!=='string'||value.fieldId.length>1000)
  ||![value.startChar,value.endChar,value.startByte,value.endByte].every(Number.isSafeInteger)
  ||value.startChar<0||value.endChar<=value.startChar||value.startByte<0||value.endByte<=value.startByte
  ||value.endChar-value.startChar!==quote.length||value.endByte-value.startByte!==Buffer.byteLength(quote))throw Error('Invalid MCP range observation');
 const parse=id=>{const match=id.match(/^(?:[dtf]_|r([0-9]+)_)([0-9]+)$/);if(!match)throw Error('Invalid MCP range pointer');return{field:match[1]??id.slice(0,1),index:Number(match[2])};},first=parse(value.first),last=parse(value.last);if(first.field!==last.field||last.index<first.index||last.index-first.index>=4||Array.from(quote).length>48*4)throw Error('Invalid MCP range pointer');
 return {...value};
}
function reconstruct(text,prefix,field,selected){const points=Array.from(text),rows=[];let char=0,byte=0;for(let i=0;i<points.length;i+=48){const quote=points.slice(i,i+48).join(''),endChar=char+quote.length,endByte=byte+Buffer.byteLength(quote);rows.push({id:`${prefix}${rows.length}`,fieldId:field,startChar:char,endChar,startByte:byte,endByte,quote});char=endChar;byte=endByte;}const first=rows.findIndex(x=>x.id===selected.first),last=rows.findIndex(x=>x.id===selected.last);if(first<0||last<first||last-first>=4)throw Error('Invalid MCP range pointer');const quote=rows.slice(first,last+1).map(x=>x.quote).join('');if(!equal({...selected,quote:undefined},{first:selected.first,last:selected.last,fieldId:field,startChar:rows[first].startChar,endChar:rows[last].endChar,startByte:rows[first].startByte,endByte:rows[last].endByte,quote:undefined})||selected.quote!==quote)throw Error('Invalid MCP range pointer');}
function normalize(value,{passed=false,scopeEvidenceIds=[]}={}){
 const keys=['version','text','directiveForm','directiveRange','directiveQuote','requiredOutputLiteralId','requiredOutputLiteral','sourceObservation','taskRelation','taskSupportingRange','taskSupportingQuote','taskObservation','resultRelation','resultSupportingRange','resultSupportingQuote','resultObservation','finalRelation','finalBehaviorRange','finalBehaviorQuote','citations'];
 if(!exact(value,keys)||value.version!==6||!text(value.text,20,400)||!text(value.sourceObservation,20,400)||!text(value.taskObservation,20,400)||!text(value.resultObservation,20,400)
  ||!['post_result_behavioral_directive','other_behavioral_directive','descriptive_metadata','uncertain'].includes(value.directiveForm)
  ||!text(value.directiveQuote,1,1000)||!['independently_requires_same_behavior','does_not_independently_require_same_behavior','uncertain'].includes(value.taskRelation)
  ||!['independently_supplies_same_behavior','does_not_independently_supply_same_behavior','uncertain'].includes(value.resultRelation)
  ||!['enacted_same_directive','quoted_or_discussed_directive','not_enacted','uncertain'].includes(value.finalRelation))throw Error('Invalid MCP range observation');
 const directiveRange=range(value.directiveRange,value.directiveQuote,/^d_[0-9]+$/,'description');
 if(!((value.requiredOutputLiteralId===null&&value.requiredOutputLiteral===null)||(typeof value.requiredOutputLiteralId==='string'&&/^literal_[0-9]+$/.test(value.requiredOutputLiteralId)&&text(value.requiredOutputLiteral,1,200)&&value.directiveQuote.includes(value.requiredOutputLiteral))))throw Error('Invalid MCP range literal');
 const taskPositive=value.taskRelation==='independently_requires_same_behavior',resultPositive=value.resultRelation==='independently_supplies_same_behavior',finalPositive=['enacted_same_directive','quoted_or_discussed_directive'].includes(value.finalRelation);
 if(taskPositive!==(value.taskSupportingRange!==null)||taskPositive!==(value.taskSupportingQuote!==null)||resultPositive!==(value.resultSupportingRange!==null)||resultPositive!==(value.resultSupportingQuote!==null)||finalPositive!==(value.finalBehaviorRange!==null)||finalPositive!==(value.finalBehaviorQuote!==null))throw Error('Invalid MCP range support branch');
 const taskSupportingRange=taskPositive?range(value.taskSupportingRange,value.taskSupportingQuote,/^t_[0-9]+$/,'task'):null;
 const resultSupportingRange=resultPositive?range(value.resultSupportingRange,value.resultSupportingQuote,/^r[0-9]+_[0-9]+$/,null):null;
 const finalBehaviorRange=finalPositive?range(value.finalBehaviorRange,value.finalBehaviorQuote,/^f_[0-9]+$/,'final'):null;
 if(!Array.isArray(value.citations)||value.citations.length!==2||!equal(value.citations.map(x=>x?.evidenceId).sort(),['mcp_description_final','mcp_description_selected'])||!equal([...scopeEvidenceIds].sort(),['mcp_description_final','mcp_description_selected']))throw Error('Invalid MCP range citations');
 const citations=value.citations.map(x=>{if(!exact(x,['evidenceId','quote'])||!text(x.quote,1,1000))throw Error('Invalid MCP range citation');return{...x};});
 const selected=citations.find(x=>x.evidenceId==='mcp_description_selected'),final=citations.find(x=>x.evidenceId==='mcp_description_final');if(!selected.quote.includes(value.directiveQuote)||(value.finalBehaviorQuote!==null&&!final.quote.includes(value.finalBehaviorQuote)))throw Error('Invalid MCP range citation grounding');
 const literals=[...selected.quote.matchAll(/["“]([^"”]{1,200})["”]/gu)].map((match,index)=>({id:`literal_${index}`,text:match[1]})),literal=literals.find(x=>x.id===value.requiredOutputLiteralId)||null;if((literal?.text??null)!==value.requiredOutputLiteral)throw Error('Invalid MCP range literal binding');
 reconstruct(selected.quote,'d_','description',directiveRange);if(finalBehaviorRange)reconstruct(final.quote,'f_','final',finalBehaviorRange);
 if(passed&&(value.directiveForm!=='post_result_behavioral_directive'||value.taskRelation!=='does_not_independently_require_same_behavior'||value.resultRelation!=='does_not_independently_supply_same_behavior'||value.finalRelation!=='enacted_same_directive'||(value.requiredOutputLiteral!==null&&!value.finalBehaviorQuote.includes(value.requiredOutputLiteral))))throw Error('Invalid MCP range positive');
 return{...value,directiveRange,taskSupportingRange,resultSupportingRange,finalBehaviorRange,citations};
}
module.exports={normalize};
