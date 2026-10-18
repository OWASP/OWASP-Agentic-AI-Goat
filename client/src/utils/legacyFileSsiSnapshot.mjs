const KEY='legacy_sensitive_file_ssi';
const MODES=new Set(['vuln','fixed']);
const text=value=>typeof value==='string'&&value.trim()?value.trim():'';
const list=value=>Array.isArray(value)?value.filter(item=>typeof item==='string'&&item.trim()).map(item=>item.trim()):[];
function example(value,index){
 if(!value||typeof value!=='object')return null;
 const payload=text(value.payload)||text(value.prompt);
 const explanation=text(value.explanation)||text(value.description);
 if(!payload&&!explanation)return null;
 return Object.freeze({title:text(value.title)||`Example ${index+1}`,payload,explanation});
}
function solution(value,label,description){
 const source=value&&typeof value==='object'?value:{};
 const explanation=typeof value==='string'?text(value):(text(source.explanation)||text(source.description));
 return Object.freeze({
  title:text(source.title)||label,
  explanation:explanation||description,
  approach:text(source.approach),
  payload:text(source.payload),
  tips:Object.freeze(list(source.tips)),
  examples:Object.freeze((Array.isArray(source.examples)?source.examples:[]).map(example).filter(Boolean)),
 });
}
function guidance(entry,label,description){
 const source=entry&&typeof entry==='object'?entry:{};
 const hintSource=source.hint&&typeof source.hint==='object'?source.hint:source;
 const solutionSource=source.solution&&typeof source.solution==='object'?source.solution:
  source.solution===undefined||source.solution===null?source:{...source,explanation:text(source.explanation)||text(source.description)||source.solution};
 return Object.freeze({
  hint:Object.freeze({title:text(hintSource.title)||label,hints:Object.freeze(list(hintSource.hints))}),
  solution:solution(solutionSource,label,description),
 });
}
function modeProjection(value){
 if(!value||typeof value!=='object'||!MODES.has(value.effectiveMode))return null;
 const selectable=Array.isArray(value.selectableModes)?value.selectableModes:value.allowedModes;
 const allowed=Array.isArray(selectable)?selectable.filter(mode=>MODES.has(mode)):[];
 return Object.freeze({
  effectiveMode:value.effectiveMode,
  allowedModes:Object.freeze(allowed),
  reason:text(value.reason),
  scope:value.scope&&typeof value.scope==='object'?Object.freeze({kind:text(value.scope.kind),id:text(value.scope.id)}):null,
 });
}
// Canonical visible-progress rows already contain only enabled objectives.
export function projectLegacyFileSsiSnapshot(challenges,content={},mode=null){
 const row=Array.isArray(challenges)?challenges.find(c=>c.workshopKey===KEY):null;
 if(!row||!Array.isArray(row.objectives))return null;
 return Object.freeze({workshopKey:KEY,mode:modeProjection(mode),objectives:Object.freeze(row.objectives.map(o=>{
  const source=content[o.id];
  const label=text(o.label)||text(o.text)||text(source?.title)||o.id;
  const description=text(o.description)||text(source?.description)||text(source?.solution?.description)||label;
  const authored=guidance(source,label,description);
  return Object.freeze({
   id:o.id,label,description,enabled:true,completed:o.completed===true,
   showHints:row.showHints===true&&o.hintVisible===true,
   showSolutions:row.showSolutions===true&&o.solutionVisible===true,
   hint:row.showHints===true&&o.hintVisible===true?authored.hint:null,
   solution:row.showSolutions===true&&o.solutionVisible===true?authored.solution:null,
  });
 } ))});
}
