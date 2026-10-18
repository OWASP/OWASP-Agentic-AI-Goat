import React, { useState } from 'react';
import styled from 'styled-components';
import { FiFolder, FiCode, FiMessageSquare, FiTarget, FiArrowLeft } from 'react-icons/fi';
import { defineWorkshop, workshopTokens } from '../../components/workshop/experience.mjs';
import { MultiScenarioWorkshop, ScenarioNavigator, ScenarioWorkspace, WorkshopButton,
  ExerciseProgress, StatusNotice, ToolResultPanel, ChatComposer, ResetConfirmation, WorkshopModeControl,
  ObjectiveHelpActions, ScopedResetButton, SafeChatBody, WorkspaceLayout, ActionGroup,
  ChatPanel, ObjectiveList, ObjectiveCard } from '../../components/workshop/WorkshopExperience';
import ObjectiveHelpModal from '../../components/workshop/ObjectiveHelpModal';

// Presentation shell matches DPI/IPI without introducing another visibility or
// authentication owner; the mounted Page retains those canonical checks.
const PageShell = styled.div`
 min-height: 100vh; padding: 2rem; box-sizing: border-box;
 background: ${workshopTokens.primaryGradient};
 @media (max-width: 600px) { padding: 1rem; }
`;
const PageSurface = styled.div`
 max-width: 1800px; min-width: 0; margin: 0 auto; padding: 2rem; box-sizing: border-box;
 background: rgba(255, 255, 255, 0.95); border: 1px solid rgba(255, 255, 255, 0.2);
 border-radius: 24px; box-shadow: 0 25px 50px rgba(0, 0, 0, 0.1);
 overflow-wrap: anywhere;
 @media (max-width: 600px) { padding: 1rem; }
`;
const BackLink = styled.a`
 display: inline-flex; align-items: center; gap: 0.5rem; min-height: 44px; box-sizing: border-box;
 margin-bottom: 1rem; padding: 0.75rem 1.5rem; border-radius: 12px;
 background: rgba(255, 255, 255, 0.9); color: ${workshopTokens.text}; font-weight: 600; text-decoration: none;
 &:hover { background: ${workshopTokens.surface}; box-shadow: 0 8px 25px rgba(0, 0, 0, 0.1); }
 &:focus-visible { outline: 3px solid ${workshopTokens.focus}; outline-offset: 2px; }
`;
const Hero = styled.header`
 background: rgba(255, 255, 255, 0.95); border: 1px solid rgba(255, 255, 255, 0.2);
 border-radius: 24px; padding: 2.5rem; margin-bottom: 2rem;
 box-shadow: 0 25px 50px rgba(0, 0, 0, 0.1); text-align: center; overflow-wrap: anywhere;
 h1 {
  display: flex; align-items: center; justify-content: center; gap: 0.75rem;
  margin: 0 0 1rem; font-size: 2.5rem; font-weight: 700; color: ${workshopTokens.brand};
  background: ${workshopTokens.primaryGradient}; background-clip: text;
  -webkit-background-clip: text; -webkit-text-fill-color: transparent;
 }
 p { margin: 0 auto; max-width: 800px; color: ${workshopTokens.mutedText}; font-size: 1.2rem; line-height: 1.6; }
 @media (max-width: 600px) { padding: 1.25rem; h1 { font-size: 1.75rem; flex-wrap: wrap; } }
`;
function FileSsiShell({children}) {
 return <PageShell>
  <BackLink href="/workshop/challenges"><FiArrowLeft aria-hidden="true"/>Back to Dashboard</BackLink>
  <Hero aria-labelledby="file-ssi-title"><h1 id="file-ssi-title"><FiFolder aria-hidden="true"/>File and SSI Security</h1>
   <p>Explore owned teaching files, template interpretation and a model-selected file agent.</p>
  </Hero>
  <PageSurface>{children}</PageSurface>
 </PageShell>;
}
const Intro = styled.section`
 padding: 2rem;
 border: 2px solid ${workshopTokens.brand};
 border-radius: ${workshopTokens.cardRadius};
 background: linear-gradient(135deg, rgba(102, 126, 234, 0.1), rgba(118, 75, 162, 0.1));
 h2 { margin: 0 0 1rem; color: ${workshopTokens.brand}; font-size: 1.3rem; }
 p { margin: 0 0 1.5rem; color: ${workshopTokens.mutedText}; line-height: 1.7; }
 @media (max-width: 600px) { padding: 1.25rem; }
`;
const Workbench = styled(ChatPanel)`
 display: flex;
 flex-direction: column;
 box-shadow: 0 4px 20px rgba(0, 0, 0, 0.08);
 min-height: 560px;
`;
const WorkbenchHeader = styled.div`
 background: ${workshopTokens.primaryGradient};
 color: ${workshopTokens.surface};
 padding: 1.25rem;
 h2 { display: flex; align-items: center; gap: 0.5rem; margin: 0; font-size: 1.1rem; font-weight: 600; }
`;
const Observation = styled.div`
 flex: 1;
 min-width: 0;
 padding: 1.5rem;
 display: flex;
 flex-direction: column;
 gap: 1rem;
 h3 { margin: 0; font-size: 1rem; color: ${workshopTokens.mutedText}; }
 pre, [aria-label="Observed result"] { margin: 0; }
`;
const Composer = styled(ChatComposer)`
 display: grid;
 grid-template-columns: minmax(0, 1fr) auto;
 label { grid-column: 1 / -1; color: ${workshopTokens.text}; font-weight: 600; }
 textarea {
  width: 100%; min-width: 0; min-height: 120px; box-sizing: border-box;
  border: 2px solid ${workshopTokens.controlBorder}; border-radius: ${workshopTokens.controlRadius};
  padding: 0.85rem; color: ${workshopTokens.text}; background: ${workshopTokens.surface}; font: inherit;
  &:focus-visible { outline: 3px solid ${workshopTokens.focus}; outline-offset: 2px; }
 }
 @media (max-width: 600px) { grid-template-columns: minmax(0, 1fr); }
`;
const ObjectivesPanel = styled.aside`
 min-width: 0; padding: 2rem;
 background: ${workshopTokens.surface}; border: 2px solid ${workshopTokens.border};
 border-radius: ${workshopTokens.cardRadius}; box-shadow: 0 4px 20px rgba(0, 0, 0, 0.08);
 display: flex; flex-direction: column; gap: 1.25rem;
 h2 { display: flex; align-items: center; gap: 0.75rem; margin: 0; color: ${workshopTokens.text}; font-size: 1.5rem; }
 p { margin: 0; color: ${workshopTokens.mutedText}; line-height: 1.6; }
 label { display: flex; flex-direction: column; gap: 0.5rem; color: ${workshopTokens.text}; font-weight: 600; }
 select { min-height: 44px; max-width: 100%; border: 2px solid ${workshopTokens.controlBorder}; border-radius: ${workshopTokens.controlRadius}; padding: 0.5rem; font: inherit; color: ${workshopTokens.text}; background: ${workshopTokens.surface}; }
 @media (max-width: 600px) { padding: 1.25rem; }
`;
const ObjectiveChoice = styled(ObjectiveCard)`
 display: flex; flex-direction: column; gap: 0.5rem;
 strong { font-size: 1rem; }
 span { font-size: 0.85rem; color: ${workshopTokens.mutedText}; }
`;

export const legacyFileSsiExperience = defineWorkshop({schemaVersion:1,experienceVersion:1,
  workshopKey:'legacy_sensitive_file_ssi',template:'multi-scenario',scenarios:[
    {id:'files',label:'File traversal',workflow:'tool-workspace'},
    {id:'templates',label:'SSI templates',workflow:'tool-workspace'},
    {id:'agent',label:'File agent',workflow:'chat'},
  ].map(s=>({...s,resetPolicy:'owner-family',objectiveSource:'canonical-catalog',navigation:'manual'}))});
const SCENARIOS={path_traversal:'files',combined_traversal_ssi:'files',ssi_injection:'templates',ai_assisted_path_traversal:'agent',ai_assisted_ssi:'agent'};
// Staged view: promotion supplies the authenticated canonical controller. No local
// success detector or fallback progress is permitted; totals and gates are supplied by PostgreSQL.
export default function LegacyFileSsiWorkshop({snapshot,onAttempt,onReset,onModeChange,onRefresh}){
 const [scenario,setScenario]=useState('files'),[input,setInput]=useState(''),[busy,setBusy]=useState(false),
  [output,setOutput]=useState(''),[error,setError]=useState(''),[confirm,setConfirm]=useState(false),[selected,setSelected]=useState(null),[help,setHelp]=useState(null);
 if(!snapshot||snapshot.workshopKey!=='legacy_sensitive_file_ssi')return <FileSsiShell><StatusNotice role="status">File and SSI workshop is unavailable.</StatusNotice></FileSsiShell>;
 const objectives=snapshot.objectives.filter(o=>o.enabled===true),visible=objectives.filter(o=>SCENARIOS[o.id]===scenario);
 const objective=visible.find(o=>o.id===selected)||visible[0];
 async function attempt(event){event.preventDefault();if(busy||!objective||!input.trim())return;setBusy(true);setError('');
  try{const result=await onAttempt({objectiveId:objective.id,input});const observed=typeof result.response==='string'?result.response:typeof result.content==='string'?result.content:typeof result.rendered==='string'?result.rendered:JSON.stringify(result,null,2);setOutput(observed);await onRefresh();}
  catch(e){setError(e.message||'Attempt could not be completed.');}finally{setBusy(false);}}
 async function reset(){if(busy)return;setBusy(true);setError('');try{await onReset();setInput('');setOutput('');await onRefresh();setConfirm(false);}catch(e){setError(e.message||'Reset could not be completed.');}finally{setBusy(false);}}
 async function changeMode(mode){if(busy||!snapshot.mode||mode===snapshot.mode.effectiveMode)return;setBusy(true);setError('');
  try{await onModeChange(mode);setInput('');setOutput('');setHelp(null);await onRefresh();}
  catch(e){setError(e.message||'Mode could not be changed.');}finally{setBusy(false);}}
 const helpObjective=help?objectives.find(o=>o.id===help.objectiveId):null;
 const helpContent=help&&helpObjective?(help.kind==='hint'?helpObjective.hint:helpObjective.solution):null;
 return <FileSsiShell><MultiScenarioWorkshop definition={legacyFileSsiExperience} activeScenarioId={scenario}>
  <Intro><h2>File and SSI workflows</h2><p>Choose a scenario and objective to explore the owned teaching environment. Command directives are simulated.</p>
   <ActionGroup>
    {snapshot.mode&&<WorkshopModeControl mode={snapshot.mode.effectiveMode} allowedModes={snapshot.mode.allowedModes} reason={snapshot.mode.reason} pending={busy} onChange={changeMode} scopeLabel="File and SSI workflow"/>}
    <ScopedResetButton label="Reset File and SSI exercise" disabled={busy} onClick={()=>setConfirm(true)}/>
   </ActionGroup>
  </Intro>
  <ScenarioNavigator definition={legacyFileSsiExperience} activeScenarioId={scenario} onScenarioChange={id=>{if(busy)return;setScenario(id);setSelected(null);setInput('');setOutput('');setHelp(null);}}/>
  <ScenarioWorkspace scenarioId={scenario} activeScenarioId={scenario}>
   <WorkspaceLayout>
    <Workbench aria-label={scenario==='agent'?'File agent workspace':scenario==='templates'?'SSI template workspace':'File traversal workspace'}>
     <WorkbenchHeader><h2>{scenario==='agent'?<FiMessageSquare aria-hidden="true"/>:scenario==='templates'?<FiCode aria-hidden="true"/>:<FiFolder aria-hidden="true"/>}{scenario==='agent'?'File agent':scenario==='templates'?'SSI templates':'File traversal'}</h2></WorkbenchHeader>
     <Observation>
      {visible.length===0&&<StatusNotice>No enabled objectives in this scenario.</StatusNotice>}
      {(visible.length>0||output)&&<h3>Observed result</h3>}
      {output&&<ToolResultPanel as="div" aria-label="Observed result"><SafeChatBody content={output} plain /></ToolResultPanel>}
      {!output&&visible.length>0&&<StatusNotice>Run an attempt to observe the selected workflow's response.</StatusNotice>}
      {error&&<StatusNotice status="error" role="alert">{error}</StatusNotice>}
     </Observation>
     {visible.length>0&&<Composer onSubmit={attempt}><label htmlFor="legacy-file-input">{scenario==='templates'?'Template source':scenario==='agent'?'Message to file agent':'Teaching file path'}</label>
      <textarea id="legacy-file-input" value={input} disabled={busy} onChange={e=>setInput(e.target.value)}/>
      <WorkshopButton type="submit" disabled={busy||!input.trim()}>Run attempt</WorkshopButton>
     </Composer>}
    </Workbench>
    <ObjectivesPanel aria-label="Exercise objectives">
     <h2><FiTarget aria-hidden="true"/>Exercise Objectives</h2>
     {visible.length>0&&<>
      <label>Objective <select value={objective.id} disabled={busy} onChange={e=>{setSelected(e.target.value);setHelp(null);}}>{visible.map(o=><option key={o.id} value={o.id}>{o.completed?'✓ ':''}{o.label}</option>)}</select></label>
      <ObjectiveList>{visible.map(o=><ObjectiveChoice key={o.id} type="button" $active={o.id===objective.id} $completed={o.completed} aria-pressed={o.id===objective.id} disabled={busy} onClick={()=>{setSelected(o.id);setHelp(null);}}>
       <strong>{o.label}</strong><span>{o.completed?'Completed':o.id===objective.id?'Selected objective':'Available objective'}</span>
      </ObjectiveChoice>)}</ObjectiveList>
      <p>{objective.description}</p>
      <ObjectiveHelpActions objectiveId={objective.id} hintVisible={objective.showHints&&Boolean(objective.hint)} solutionVisible={objective.showSolutions&&Boolean(objective.solution)} disabled={busy} activeKind={help?.objectiveId===objective.id?help.kind:null} onOpen={(kind,objectiveId)=>setHelp({kind,objectiveId})}/>
     </>}
     <ExerciseProgress completed={objectives.filter(o=>o.completed).length} total={objectives.length}/>
    </ObjectivesPanel>
   </WorkspaceLayout>
  </ScenarioWorkspace>
  <ResetConfirmation open={confirm} status={busy?'resetting':'idle'} title="Reset File and SSI Security?" description="Reset your file and SSI progress. FinFlow and other learners are preserved." error={error} onCancel={()=>!busy&&setConfirm(false)} onConfirm={reset}/>
  {help&&helpObjective&&<ObjectiveHelpModal kind={help.kind} objective={helpObjective} content={helpContent} appearance="legacy-light" onClose={()=>setHelp(null)} onUsePayload={payload=>{setInput(payload);setHelp(null);}}/>}
 </MultiScenarioWorkshop></FileSsiShell>;
}
