import React, { useEffect, useRef, useState } from 'react';
import styled from 'styled-components';
import { motion, useReducedMotion } from 'framer-motion';
import { FiFolder, FiCode, FiMessageSquare, FiTarget, FiArrowLeft, FiCheckCircle,
  FiLock, FiZap, FiUser, FiSend, FiInfo } from 'react-icons/fi';
import { defineWorkshop, workshopTokens as t } from '../../components/workshop/experience.mjs';
import { MultiScenarioWorkshop, ScenarioNavigator, ScenarioWorkspace, WorkshopButton,
  StatusNotice, ResetConfirmation, WorkshopModeControl, ObjectiveHelpActions, SafeChatBody } from '../../components/workshop/WorkshopExperience';
import ObjectiveHelpModal from '../../components/workshop/ObjectiveHelpModal';
import JudgeRetryButton from '../../components/workshop/JudgeRetryButton';
import { getJudgeFeedback } from '../../utils/judgeFeedback.mjs';

// Reuse the route's canonical visibility/session owner rather than mounting a
// second data-fetching VulnerabilityTemplate. These surfaces match its baseline.
const PageShell = styled.div`
 min-height:100vh; padding:2rem; background:${t.primaryGradient};
 @media(max-width:600px){padding:1rem;}
`;
const PageSurface = styled.div`
 max-width:1800px; min-width:0; margin:0 auto; padding:2rem; box-sizing:border-box;
 background:rgba(255,255,255,.95); border:1px solid rgba(255,255,255,.2);
 border-radius:24px; box-shadow:0 25px 50px rgba(0,0,0,.1); overflow-wrap:anywhere;
 @media(max-width:600px){padding:1rem;}
`;
const BackLink = styled.a`
 display:inline-flex; align-items:center; gap:.5rem; min-height:44px; margin-bottom:1rem;
 padding:.75rem 1.5rem; border-radius:12px; background:rgba(255,255,255,.9);
 color:${t.text}; font-weight:600; text-decoration:none;
 &:hover{background:white; transform:translateY(-2px); box-shadow:0 8px 25px rgba(0,0,0,.1);}
 &:focus-visible{outline:3px solid ${t.focus};outline-offset:2px;}
 @media(prefers-reduced-motion:reduce){&:hover{transform:none;}}
`;
const Hero = styled.header`
 background:rgba(255,255,255,.95); border:1px solid rgba(255,255,255,.2); border-radius:24px;
 padding:2.5rem; margin-bottom:2rem; box-shadow:0 25px 50px rgba(0,0,0,.1); text-align:center; overflow-wrap:anywhere;
 h1{display:flex;align-items:center;justify-content:center;gap:.75rem;margin:0 0 1rem;font-size:2.5rem;font-weight:700;
 color:${t.brand};background:${t.primaryGradient};background-clip:text;-webkit-background-clip:text;-webkit-text-fill-color:transparent;}
 p{margin:0 auto;max-width:800px;color:#666;font-size:1.2rem;line-height:1.6;}
 @media(max-width:600px){padding:1.25rem;h1{font-size:1.75rem;flex-wrap:wrap;}}
`;
const Difficulty = styled.span`
 display:inline-block;margin-top:1rem;padding:.5rem 1.5rem;border-radius:25px;color:white;
 font-size:.9rem;font-weight:600;text-transform:uppercase;letter-spacing:.5px;
 background:${({$level})=>$level==='beginner'?t.successGradient:$level==='intermediate'?'linear-gradient(135deg,#ffc107,#fd7e14)':$level==='advanced'?'linear-gradient(135deg,#dc3545,#fd7e14)':'linear-gradient(135deg,#6f42c1,#e83e8c)'};
`;
function FileSsiShell({snapshot,children}) {
 return <PageShell><BackLink href="/workshop/challenges"><FiArrowLeft aria-hidden="true"/>Back to Dashboard</BackLink>
  <Hero aria-labelledby="file-ssi-title"><h1 id="file-ssi-title"><FiFolder aria-hidden="true"/>{snapshot?.title||'File and SSI Security'}</h1>
   <p>{snapshot?.description||'Explore owned teaching files, template interpretation and a model-selected file agent.'}</p>
   {snapshot?.difficulty&&<Difficulty $level={snapshot.difficulty.toLowerCase()}>{snapshot.difficulty}</Difficulty>}
  </Hero><PageSurface>{children}</PageSurface></PageShell>;
}
const Intro = styled.section`
 padding:2rem;border:2px solid ${t.brand};border-radius:16px;background:linear-gradient(135deg,rgba(102,126,234,.1),rgba(118,75,162,.1));
 h2{display:flex;align-items:center;gap:.5rem;margin:0 0 1rem;color:${t.brand};font-size:1.3rem;}
 p{margin:.5rem 0;color:${t.mutedText};line-height:1.7;}
 .scenario{background:rgba(255,255,255,.8);border-left:4px solid ${t.brand};padding:1rem;margin:1rem 0;border-radius:8px;line-height:1.6;strong{color:${t.brand};}}
 .model-info{display:flex;align-items:flex-start;gap:.5rem;margin-top:1rem;color:${t.mutedText};font-size:.85rem;line-height:1.6;}
 @media(max-width:600px){padding:1.25rem;}
`;
const ModeStrip = styled.div`
 background:#f8fafc;border:1px solid #cbd5e1;border-radius:12px;padding:1rem 1.25rem;
 p{margin:0 0 .75rem;color:${t.mutedText};font-size:.9rem;line-height:1.5;}
`;
const Layout = styled.div`
 display:grid;grid-template-columns:minmax(0,2fr) minmax(0,1fr);gap:2rem;align-items:start;
 > *{min-width:0;} @media(max-width:1024px){grid-template-columns:minmax(0,1fr);}
`;
const Workbench = styled.section`
 min-width:0;display:flex;flex-direction:column;height:${({$chat})=>$chat?'600px':'auto'};min-height:560px;
 background:white;border-radius:16px;box-shadow:0 4px 20px rgba(0,0,0,.08);overflow:hidden;
`;
const WorkbenchHeader = styled.div`
 background:${t.primaryGradient};color:white;padding:1.25rem;display:flex;align-items:center;justify-content:space-between;gap:.75rem;flex-shrink:0;
 h2{display:flex;align-items:center;gap:.5rem;margin:0;font-size:1.1rem;font-weight:600;}
 .active-objective{display:block;margin-top:.5rem;font-size:.85rem;opacity:.95;overflow-wrap:anywhere;}
 button{background:rgba(255,255,255,.2);border:1px solid rgba(255,255,255,.5);padding:.5rem 1rem;font-size:.85rem;}
 @media(max-width:600px){flex-wrap:wrap;}
`;
const Observation = styled.div`
 flex:1;min-height:0;min-width:0;overflow-y:auto;padding:1.5rem;background:${t.canvas};
 &::-webkit-scrollbar{width:8px;} &::-webkit-scrollbar-thumb{background:rgba(102,126,234,.3);border-radius:4px;}
`;
const Message = styled(motion.div)`
 display:flex;align-items:flex-start;gap:.75rem;margin-bottom:1rem;flex-direction:${({$user})=>$user?'row-reverse':'row'};
 .avatar{width:36px;height:36px;flex-shrink:0;border-radius:50%;display:grid;place-items:center;color:white;
 background:${({$user})=>$user?t.primaryGradient:'linear-gradient(135deg,#06b6d4,#3b82f6)'};}
 .bubble{min-width:0;max-width:85%;padding:.875rem 1.125rem;border:1px solid ${t.controlBorder};
 border-radius:${({$user})=>$user?'18px 18px 4px 18px':'18px 18px 18px 4px'};background:${({$user})=>$user?t.primaryGradient:'white'};
 color:${({$user})=>$user?'white':t.text};box-shadow:0 2px 8px rgba(0,0,0,.06);overflow-wrap:anywhere;}
 .metadata{font-size:.75rem;opacity:.9;margin-bottom:.25rem;} .body{font-size:.9rem;line-height:1.6;white-space:pre-wrap;}
`;
function ObservationLog({children,changeKey,...props}) {
 const list=useRef(null);
 useEffect(()=>{if(list.current)list.current.scrollTop=list.current.scrollHeight;},[changeKey]);
 return <Observation ref={list} {...props}>{children}</Observation>;
}
const Composer = styled.form`
 display:flex;flex-wrap:wrap;align-items:flex-end;gap:.75rem;padding:1.25rem;background:white;border-top:1px solid ${t.controlBorder};flex-shrink:0;
 label{flex-basis:100%;color:${t.text};font-size:.85rem;font-weight:600;}
 textarea{flex:1;min-width:0;min-height:${({$chat})=>$chat?'44px':'120px'};max-height:${({$chat})=>$chat?'100px':'240px'};
 resize:${({$chat})=>$chat?'none':'vertical'};padding:.875rem 1.125rem;border:2px solid ${t.controlBorder};border-radius:12px;
 color:${t.text};font-family:${({$chat})=>$chat?'inherit':'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace'};font-size:.95rem;
 &:focus{outline:none;border-color:${t.brand};box-shadow:0 0 0 3px rgba(102,126,234,.1);}}
 .send{width:44px;height:44px;padding:0;border-radius:12px;}
`;
const Panel = styled.aside`
 padding:2rem;min-width:0;background:white;border:2px solid ${t.border};border-radius:16px;box-shadow:0 4px 20px rgba(0,0,0,.08);
 h2{display:flex;align-items:center;gap:.75rem;margin:0 0 1rem;color:${t.text};font-size:1.5rem;font-weight:600;}
 @media(max-width:600px){padding:1.25rem;}
`;
const ObjectiveItem = styled.div`
 position:relative;margin-top:.75rem;border:1px solid ${({$active,$completed})=>$active?t.brand:$completed?t.complete:t.controlBorder};
 border-radius:10px;background:${({$active,$completed})=>$active?'rgba(102,126,234,.08)':$completed?t.completeSurface:t.canvas};
 padding:.875rem 1.25rem;overflow-wrap:anywhere;transition:border-color .3s ease,box-shadow .3s ease,transform .3s ease;
 &:hover{border-color:${t.brand};box-shadow:0 4px 12px rgba(0,0,0,.05);transform:translateY(-2px);}
 @media(prefers-reduced-motion:reduce){transition:none;&:hover{transform:none;}}
 .select{width:100%;display:flex;gap:1rem;align-items:flex-start;border:0;background:none;color:${t.text};padding:0;text-align:left;font:inherit;cursor:pointer;min-height:44px;}
 .select:focus-visible{outline:3px solid ${t.focus};outline-offset:4px;border-radius:4px;}
 .select:disabled{cursor:not-allowed;opacity:.5;}
 .icon{width:36px;height:36px;flex-shrink:0;border-radius:50%;color:white;display:grid;place-items:center;background:${({$active,$completed})=>$active?t.brand:$completed?t.complete:'#dee2e6'};}
 .copy{min-width:0;flex:1;} .name{display:block;font-weight:600;margin-bottom:.25rem;}
 .description{display:block;font-size:.85rem;color:#666;line-height:1.4;}
 .badges{display:flex;flex-wrap:wrap;justify-content:flex-end;gap:.25rem;margin-bottom:.35rem;}
 .badge{padding:.2rem .6rem;background:${t.brand};color:white;border-radius:0 0 0 8px;font-size:.65rem;font-weight:800;letter-spacing:.05em;}
 .completed{background:${t.complete};}
 [data-objective-help-actions]{margin-left:52px;} [data-objective-help-actions] button{min-height:44px;}
`;
const Progress = styled.div`
 margin-top:1.5rem;padding-top:1.5rem;border-top:2px solid ${t.border};
 h3{display:flex;align-items:center;gap:.5rem;margin:0 0 .75rem;font-size:1.1rem;font-weight:600;color:${t.text};}
 p{font-size:.95rem;color:#666;margin:0 0 .75rem;}
 .track{height:20px;background:${t.border};border-radius:10px;overflow:hidden;}
 .fill{height:100%;border-radius:10px;background:linear-gradient(90deg,#667eea,#764ba2);transition:width .5s ease;}
 .all-complete{margin-top:1rem;padding:.75rem 1rem;border:2px solid #28a745;border-radius:10px;color:#28a745;background:rgba(40,167,69,.12);font-weight:700;display:flex;gap:.5rem;align-items:center;}
 .overall{margin-top:1rem;font-size:.85rem;} button{margin-top:.75rem;}
 @media(prefers-reduced-motion:reduce){.fill{transition:none;}}
`;
const Results = styled.section`
 padding:2rem;background:white;border:2px solid ${t.border};border-radius:16px;box-shadow:0 4px 20px rgba(0,0,0,.08);
 h2{display:flex;gap:.5rem;align-items:center;font-size:1.2rem;color:${t.text};margin:0 0 1rem;padding-bottom:1rem;border-bottom:2px solid ${t.border};}
 p{font-size:.9rem;line-height:1.6;color:#666;margin:.75rem 0;}
 @media(max-width:600px){padding:1.25rem;}
`;
export const legacyFileSsiExperience = defineWorkshop({schemaVersion:1,experienceVersion:1,
 workshopKey:'legacy_sensitive_file_ssi',template:'multi-scenario',scenarios:[
  {id:'files',label:'File traversal',workflow:'tool-workspace'},
  {id:'templates',label:'SSI templates',workflow:'tool-workspace'},
  {id:'agent',label:'File agent',workflow:'chat'},
 ].map(s=>({...s,resetPolicy:'owner-family',objectiveSource:'canonical-catalog',navigation:'manual',capabilities:{objectiveHelp:true}}))});
const SCENARIOS={path_traversal:'files',combined_traversal_ssi:'files',ssi_injection:'templates',ai_assisted_path_traversal:'agent',ai_assisted_ssi:'agent'};
const ICONS={files:FiFolder,templates:FiCode,agent:FiMessageSquare};
const LABELS={files:'Teaching file path',templates:'Template source',agent:'Message to file agent'};
const PLACEHOLDERS={files:'Enter a path inside the teaching environment…',templates:'Enter the template source to interpret…',agent:'Ask the file agent to inspect an owned teaching file…'};
const emptyWork={input:'',messages:[],feedback:[],error:''};
export default function LegacyFileSsiWorkshop({snapshot,onAttempt,onReset,onModeChange,onRefresh,loading=false,pageError=''}){
 const [scenario,setScenario]=useState('files'),[selected,setSelected]=useState({}),[work,setWork]=useState({}),
  [lastCompleted,setLastCompleted]=useState(null),[busy,setBusy]=useState(null),[pendingKey,setPendingKey]=useState(null),[modeUncertain,setModeUncertain]=useState(false),[error,setError]=useState(''),[confirm,setConfirm]=useState(false),[help,setHelp]=useState(null);
 const lock=useRef(false),mounted=useRef(true),sequence=useRef(0);
 const reduced=useReducedMotion();
 useEffect(()=>{mounted.current=true;return()=>{mounted.current=false;};},[]);
 const mode=snapshot?.mode?.effectiveMode;
 const objectives=(snapshot?.objectives||[]).filter(o=>o.enabled===true);
 const currentKey=id=>`${mode}:${id}`;
 const patch=(key,update)=>setWork(prev=>({...prev,[key]:{...(prev[key]||emptyWork),...update}}));
 const usable=snapshot?.workshopKey==='legacy_sensitive_file_ssi';
 const helpObjective=help?objectives.find(o=>o.id===help.objectiveId):null;
 const helpAllowed=helpObjective&&(help.kind==='hint'?helpObjective.showHints&&helpObjective.hint:helpObjective.showSolutions&&helpObjective.solution);
 useEffect(()=>{if(help&&!helpAllowed)setHelp(null);},[help,helpAllowed]);
 const progressCount=objectives.filter(o=>o.completed).length;
 const priorProgress=useRef(null);
 useEffect(()=>{
  if(!usable)return;
  const completed=new Set(objectives.filter(o=>o.completed).map(o=>o.id));
  const newlyCompleted=priorProgress.current&&objectives.find(o=>o.completed&&!priorProgress.current.has(o.id));
  priorProgress.current=completed;
  if(newlyCompleted)setLastCompleted({id:newlyCompleted.id,label:newlyCompleted.label});
 },[snapshot]);
 useEffect(()=>{if(!lastCompleted)return;const timer=setTimeout(()=>setLastCompleted(null),4000);return()=>clearTimeout(timer);},[lastCompleted]);
 async function attempt(event,objective,key){
  event.preventDefault();const draft=work[key]?.input||'';
  if(lock.current||modeUncertain||!mode||!objective||!draft.trim())return;
  lock.current=true;setBusy('attempt');setPendingKey(key);setError('');
  const userMessage={id:++sequence.current,user:true,content:draft.trim(),time:new Date()};
  const prior=work[key]||emptyWork;
  patch(key,{input:'',error:'',messages:[...prior.messages,userMessage]});
  try{
   const result=await onAttempt({objectiveId:objective.id,input:draft.trim()});
   if(!mounted.current)return;
   const observed=typeof result.response==='string'?result.response:typeof result.content==='string'?result.content:typeof result.rendered==='string'?result.rendered:'No response received.';
   patch(key,{messages:[...prior.messages,userMessage,{id:++sequence.current,user:false,content:observed,time:new Date()}],feedback:getJudgeFeedback(result)});
   try{if(await onRefresh()===false)throw new Error('Refresh superseded');}catch{if(mounted.current)patch(key,{error:'Response received, but progress could not be refreshed. Retry the progress check.'});}
  }catch(e){if(mounted.current)patch(key,{error:e.message||'Attempt could not be completed.'});}
  finally{lock.current=false;if(mounted.current){setBusy(null);setPendingKey(null);}}
 }
 async function reset(){
  if(lock.current)return;lock.current=true;setBusy('reset');setError('');let committed=false;
  try{await onReset();committed=true;if(!mounted.current)return;setWork({});setHelp(null);setSelected({});setLastCompleted(null);if(await onRefresh()===false)throw new Error('Refresh superseded');if(mounted.current)setConfirm(false);}
  catch(e){if(mounted.current){setError(committed?'Progress was reset, but the latest state could not be loaded. Close this dialog and retry the progress check.':e.message||'Reset could not be completed.');if(committed)setConfirm(false);}}
  finally{lock.current=false;if(mounted.current)setBusy(null);}
 }
 async function changeMode(nextMode){
  if(lock.current||!mode||nextMode===mode)return;lock.current=true;setBusy('mode');setModeUncertain(true);setError('');
  try{await onModeChange(nextMode);if(!mounted.current)return;setHelp(null);if(await onRefresh()===false)throw new Error('Refresh superseded');if(mounted.current)setModeUncertain(false);}
  catch(e){if(mounted.current){setModeUncertain(true);setError('Mode could not be confirmed. Refresh before continuing.');}}
  finally{lock.current=false;if(mounted.current)setBusy(null);}
 }
 async function refresh(){try{const refreshed=await onRefresh();if(mounted.current&&refreshed!==false){setModeUncertain(false);setError('');}}catch{/* Page owns the refresh error. */}}
 if(!usable)return <FileSsiShell><StatusNotice status={pageError?'error':'info'}>{loading?'Loading exercise…':pageError||'File and SSI workshop is unavailable.'}</StatusNotice>{!loading&&onRefresh&&<WorkshopButton onClick={()=>onRefresh().catch(()=>{})}>Retry</WorkshopButton>}</FileSsiShell>;
 return <FileSsiShell snapshot={snapshot}><MultiScenarioWorkshop definition={legacyFileSsiExperience} activeScenarioId={scenario}>
  <Intro><h2><FiMessageSquare aria-hidden="true"/>File and SSI workflows</h2>
   <p>Explore how file paths and server-side includes are interpreted inside an <strong>isolated teaching environment</strong>. Use the file and template tools directly, or ask the <strong>configured AI file agent</strong> to choose its own bounded tools.</p>
   <div className="scenario"><strong>Your task:</strong> Choose a scenario, select an objective, and inspect the actual response. A separate Judge evaluates the observed effect before progress is awarded. All files are synthetic teaching artifacts; command directives are simulated and never execute operating-system commands.</div>
   <div className="model-info" role="status"><FiInfo aria-hidden="true"/><span><strong>File agent model information unavailable.</strong> Model details are not available for this file agent. Direct file and template tools do not use the actor model. Actor availability alone would not confirm Judge readiness.</span></div>
  </Intro>
  <ScenarioNavigator definition={legacyFileSsiExperience} activeScenarioId={scenario} onScenarioChange={id=>{setScenario(id);setHelp(null);}} renderLabel={s=>{const Icon=ICONS[s.id];return <><Icon aria-hidden="true"/>{s.label}</>;}}/>
  <ModeStrip><p>One policy applies across the file, template and agent workflows. Changing mode preserves your completed objectives.</p>
   <WorkshopModeControl mode={modeUncertain?undefined:mode} allowedModes={snapshot.mode?.allowedModes} reason={snapshot.mode?.reason} pending={busy==='mode'} disabled={Boolean(busy)} onChange={changeMode} scopeLabel="File and SSI policy"/>
   {(!mode||modeUncertain)&&<StatusNotice>Mode is unavailable. Refresh before running an attempt.</StatusNotice>}
  </ModeStrip>
  {(pageError||error)&&<StatusNotice status="error">{pageError||error}</StatusNotice>}
  {legacyFileSsiExperience.scenarios.map(s=>{
   const visible=objectives.filter(o=>SCENARIOS[o.id]===s.id),objective=visible.find(o=>o.id===selected[s.id])||visible[0];
   const key=currentKey(objective?.id),state=work[key]||emptyWork,Icon=ICONS[s.id],chat=s.id==='agent';
   const completed=visible.filter(o=>o.completed).length;
   return <ScenarioWorkspace key={s.id} scenarioId={s.id} activeScenarioId={scenario}><Layout>
    <Workbench $chat={chat} aria-label={`${chat?'File agent':s.id==='templates'?'SSI template':'File traversal'} workspace`}>
     <WorkbenchHeader><div><h2><Icon aria-hidden="true"/>{s.label}{chat?' — AI Model':''}</h2><span className="active-objective">Exercise: {objective?.label||'No enabled objectives'}</span></div>
      {chat&&<WorkshopButton disabled={Boolean(busy)||!objective} onClick={()=>patch(key,{input:'',messages:[],feedback:[],error:''})}>Reset conversation</WorkshopButton>}
     </WorkbenchHeader>
     <ObservationLog changeKey={`${key}:${state.messages.length}:${busy}`} role="log" aria-live="polite" aria-label={chat?'File agent conversation':'Workflow observations'}>
      {visible.length===0?<StatusNotice>No enabled objectives in this scenario.</StatusNotice>:state.messages.length===0?<StatusNotice>{chat?'Ask the file agent about an owned teaching file. Each message starts an independent model run.':'Run an attempt to observe the selected workflow’s response.'}</StatusNotice>:null}
      {state.messages.map(message=><Message key={message.id} $user={message.user} initial={reduced?false:{opacity:0,y:12}} animate={{opacity:1,y:0}} transition={{duration:reduced?0:.3}}>
       <div className="avatar">{message.user?<FiUser aria-hidden="true"/>:chat?<FiMessageSquare aria-hidden="true"/>:<FiCode aria-hidden="true"/>}</div>
       <div className="bubble"><div className="metadata">{message.user?'You':chat?'Actor response':'Tool response'} • {message.time.toLocaleTimeString()}</div><div className="body" aria-label={!message.user?'Observed result':undefined}><SafeChatBody content={message.content} plain/></div></div>
      </Message>)}
      {busy==='attempt'&&pendingKey===key&&<StatusNotice>{chat?'Thinking...':'Running attempt…'}</StatusNotice>}
      {state.error&&<StatusNotice status="error">{state.error}</StatusNotice>}
     </ObservationLog>
     {objective&&<Composer $chat={chat} onSubmit={e=>attempt(e,objective,key)}><label htmlFor={`file-ssi-input-${s.id}`}>{LABELS[s.id]}</label>
      <textarea id={`file-ssi-input-${s.id}`} value={state.input} placeholder={PLACEHOLDERS[s.id]} disabled={Boolean(busy)||!mode||modeUncertain} onChange={e=>patch(key,{input:e.target.value})} onKeyDown={e=>{if(chat&&e.key==='Enter'&&!e.shiftKey&&!e.nativeEvent.isComposing)attempt(e,objective,key);}}/>
      <WorkshopButton className={chat?'send':undefined} type="submit" aria-label={chat?'Send message':undefined} disabled={Boolean(busy)||!mode||modeUncertain||!state.input.trim()}>{chat?<FiSend aria-hidden="true"/>:'Run attempt'}</WorkshopButton>
     </Composer>}
    </Workbench>
    <Panel aria-label="Exercise objectives"><h2><FiTarget aria-hidden="true"/>Exercise Objectives</h2>
     {visible.map(o=><ObjectiveItem key={o.id} $active={o.id===objective?.id} $completed={o.completed} data-testid={`objective-card-${o.id}`}>
      <div className="badges">{o.id===objective?.id&&<span className="badge">ACTIVE</span>}{o.completed&&<span className="badge completed">COMPLETED</span>}</div>
      <button className="select" type="button" aria-pressed={o.id===objective?.id} disabled={Boolean(busy)} onClick={()=>{setSelected(prev=>({...prev,[s.id]:o.id}));setHelp(null);}}>
       <span className="icon">{o.completed?<FiCheckCircle aria-label="Completed"/>:o.id===objective?.id?<FiTarget aria-hidden="true"/>:<FiLock aria-hidden="true"/>}</span>
       <span className="copy"><span className="name">{o.label}</span>{o.description!==o.label&&<span className="description">{o.description}</span>}</span>
      </button>
      <ObjectiveHelpActions objectiveId={o.id} hintVisible={o.showHints&&Boolean(o.hint?.hints?.length)} solutionVisible={o.showSolutions&&Boolean(o.solution)} disabled={Boolean(busy)} activeKind={help?.objectiveId===o.id?help.kind:null} onOpen={(kind,objectiveId)=>setHelp({kind,objectiveId})}/>
     </ObjectiveItem>)}
     <Progress><h3><FiZap aria-hidden="true"/>Progress</h3><p>{completed} of {visible.length} objectives completed</p>
      <div className="track" role="progressbar" aria-label={`${s.label} progress`} aria-valuemin={0} aria-valuemax={100} aria-valuenow={visible.length?Math.round(completed/visible.length*100):0}><div className="fill" style={{width:`${visible.length?completed/visible.length*100:0}%`}}/></div>
      {visible.length>0&&completed===visible.length&&<div className="all-complete"><FiCheckCircle aria-hidden="true"/>All objectives completed!</div>}
      <p className="overall">Overall exercise: {progressCount} of {objectives.length} objectives completed</p>
      <WorkshopButton variant="secondary" disabled={Boolean(busy)} onClick={()=>setConfirm(true)}>Reset Progress</WorkshopButton>
      <p className="overall">Resets all three scenarios in this exercise.</p>
     </Progress>
    </Panel>
   </Layout>
   <Results style={{marginTop:'2rem'}}><h2><FiTarget aria-hidden="true"/>Results &amp; Hints</h2>
    {lastCompleted&&SCENARIOS[lastCompleted.id]===s.id&&<StatusNotice status="success"><FiCheckCircle aria-hidden="true"/> Just completed: {lastCompleted.label}</StatusNotice>}
    {state.feedback.map((feedback,index)=><StatusNotice key={`${feedback.evaluationId||index}:${feedback.verdict}`} status={feedback.verdict==='fail'?'warning':'info'}><SafeChatBody content={feedback.content} plain/><JudgeRetryButton evaluationId={feedback.evaluationId} canRetry={feedback.canRetry} onResult={()=>onRefresh()}/></StatusNotice>)}
    <p>Inspect the actual {chat?'actor':'tool'} response and Judge feedback. Completion comes from the server’s confirmed evidence, not from text in your input.</p>
    <StatusNotice status="warning"><strong>Stuck?</strong> Use the Hint and Solution buttons under each objective when your instructor enables them.</StatusNotice>
    {chat&&<p>Reset conversation clears this objective’s local conversation and draft. Completed objectives are kept; each submitted message already starts an independent agent run.</p>}
    <WorkshopButton variant="tertiary" disabled={Boolean(busy)} onClick={refresh}>Refresh progress</WorkshopButton>
   </Results></ScenarioWorkspace>;
  })}
  <ResetConfirmation open={confirm} status={busy==='reset'?'resetting':'idle'} title="Reset File and SSI Security?" description="This resets your progress and clears the local conversations and drafts in all three File and SSI scenarios. FinFlow and other learners are preserved." error={error} onCancel={()=>!busy&&setConfirm(false)} onConfirm={reset}/>
  {help&&helpAllowed&&<ObjectiveHelpModal kind={help.kind} objective={{name:helpObjective.label}} content={help.kind==='hint'?helpObjective.hint:helpObjective.solution} appearance="legacy-light" onClose={()=>setHelp(null)} onUsePayload={help.kind==='solution'?payload=>{setScenario(SCENARIOS[helpObjective.id]);setSelected(prev=>({...prev,[SCENARIOS[helpObjective.id]]:helpObjective.id}));patch(currentKey(helpObjective.id),{input:payload});setHelp(null);}:undefined}/>}
 </MultiScenarioWorkshop></FileSsiShell>;
}
