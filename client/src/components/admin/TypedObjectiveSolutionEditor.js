import React, { useRef, useState } from 'react';
import styled from 'styled-components';
const Overlay=styled.div`position:fixed;inset:0;background:rgba(0,0,0,.5);display:flex;align-items:center;justify-content:center;z-index:2100;padding:2rem;`;
const Content=styled.div`background:white;border-radius:16px;width:100%;max-width:640px;max-height:90vh;overflow-y:auto;color:#1a202c;`;
const Section=styled.div`padding:1.5rem 2rem;border-bottom:1px solid #e2e8f0;`;
const Field=styled.label`display:block;margin-bottom:1rem;font-size:.875rem;font-weight:600;input,textarea{box-sizing:border-box;width:100%;padding:.7rem;border:2px solid #e2e8f0;border-radius:8px;font-size:.95rem;}input:focus,textarea:focus{outline:none;border-color:#667eea;}`;
const Button=styled.button`border:none;border-radius:8px;padding:.55rem 1rem;cursor:pointer;font-weight:600;background:${p=>p.$secondary?'#edf2f7':'#667eea'};color:${p=>p.$secondary?'#4a5568':'white'};opacity:${p=>p.disabled?.6:1};`;
export function isEditableSolution(value){return !!value&&typeof value==='object'&&!Array.isArray(value)&&['title','difficulty','approach'].every(k=>value[k]===undefined||typeof value[k]==='string')&&(value.tips===undefined||(Array.isArray(value.tips)&&value.tips.every(x=>typeof x==='string')))&&(value.examples===undefined||(Array.isArray(value.examples)&&value.examples.every(x=>x&&typeof x==='object'&&!Array.isArray(x)&&typeof x.prompt==='string'&&typeof x.explanation==='string')));}
export function solutionContentPatch(original,draft){return Object.fromEntries(['title','difficulty','approach','examples','tips'].filter(key=>JSON.stringify(original[key])!==JSON.stringify(draft[key])).map(key=>[key,draft[key]]));}
export default function TypedObjectiveSolutionEditor({objectiveId,solution,onSave,onCancel}){
 const [draft,setDraft]=useState(()=>JSON.parse(JSON.stringify(solution))),[saving,setSaving]=useState(false),[error,setError]=useState('');const pending=useRef(false);
 if(!isEditableSolution(solution))return null;
 const patch=solutionContentPatch(solution,draft);
 const valid=Object.keys(patch).length>0&&Object.entries(patch).every(([key,value])=>['title','difficulty','approach'].includes(key)?typeof value==='string'&&!!value.trim():key==='tips'?Array.isArray(value)&&value.length>0&&value.every(x=>typeof x==='string'&&x.trim()):Array.isArray(value)&&value.length>0&&value.every(x=>x.prompt.trim()&&typeof x.explanation==='string'));
 const set=(key,value)=>setDraft(p=>({...p,[key]:value}));
 const save=async()=>{if(pending.current||!valid)return;pending.current=true;setSaving(true);setError('');try{await onSave(patch);}catch(e){setError(e.response?.data?.error||e.message||'Failed to save solution');}finally{pending.current=false;setSaving(false);}};
 const cancel=()=>{if(!pending.current)onCancel();};
 return <Overlay onClick={cancel}><Content role="dialog" aria-modal="true" aria-label={`Edit MCP solution — ${objectiveId}`} onClick={e=>e.stopPropagation()}>
 <Section style={{display:'flex',justifyContent:'space-between',alignItems:'center'}}><h2 style={{fontSize:'1.25rem',margin:0}}>Edit MCP solution — {objectiveId}</h2><button type="button" aria-label="Close solution editor" disabled={saving} onClick={cancel}>×</button></Section>
 <Section><fieldset disabled={saving} style={{border:0,padding:0,margin:0}}>
 {['title','difficulty','approach'].map(key=><Field key={key}>{key[0].toUpperCase()+key.slice(1)}{key==='approach'?<textarea rows={4} value={draft[key]??''} onChange={e=>set(key,e.target.value)}/>:<input value={draft[key]??''} onChange={e=>set(key,e.target.value)}/>}</Field>)}
 {(draft.examples||[]).map((entry,index)=><div key={index}>{['prompt','explanation'].map(key=><Field key={key}>Example {index+1} {key}<textarea rows={3} value={entry[key]} onChange={e=>set('examples',draft.examples.map((x,i)=>i===index?{...x,[key]:e.target.value}:x))}/></Field>)}<button type="button" onClick={()=>set('examples',draft.examples.filter((_,i)=>i!==index))}>Remove example {index+1}</button></div>)}
 <Button type="button" $secondary onClick={()=>set('examples',[...(draft.examples||[]),{prompt:'',explanation:''}])}>Add Example</Button>
 {(draft.tips||[]).map((tip,index)=><Field key={index}>Tip {index+1}<textarea rows={2} value={tip} onChange={e=>set('tips',draft.tips.map((x,i)=>i===index?e.target.value:x))}/><button type="button" onClick={()=>set('tips',draft.tips.filter((_,i)=>i!==index))}>Remove tip {index+1}</button></Field>)}
 <Button type="button" $secondary onClick={()=>set('tips',[...(draft.tips||[]),''])}>Add Tip</Button>
 </fieldset>{error&&<p role="alert">{error}</p>}</Section>
 <Section style={{display:'flex',justifyContent:'flex-end',gap:'.75rem'}}><Button type="button" $secondary disabled={saving} onClick={cancel}>Cancel</Button><Button type="button" disabled={saving||!valid} onClick={save}>{saving?'Saving…':'Save Changes'}</Button></Section>
 </Content></Overlay>;
}
