import React, { useCallback, useEffect, useRef, useState } from 'react';
import axios from 'axios';
import { FiEye, FiMail, FiSave, FiSend } from 'react-icons/fi';
import { toast } from 'react-toastify';
import HintPanel from '../../components/HintPanel';
import ObjectiveHelpModal from '../../components/workshop/ObjectiveHelpModal';
import useWorkshopResetController from '../../components/workshop/useWorkshopResetController';
import { WorkshopButton, WorkshopModeControl, ObjectiveHelpActions, ScopedResetButton, ResetConfirmation } from '../../components/workshop/WorkshopExperience';
import { useAuth } from '../../context/AuthContext';

const LEVELS = [
  { id: 'xss_email_level_1', level: 1, label: 'Basic Stored XSS (Name Field)', field: 'full_name' },
  { id: 'xss_email_level_2', level: 2, label: 'Bypass Script Filter (Signature Field)', field: 'signature_html' },
  { id: 'xss_email_level_3', level: 3, label: 'Event Handler Injection (Company Field)', field: 'company_name' },
  { id: 'xss_email_level_4', level: 4, label: 'AI Prompt + XSS Chain', field: 'prompt' },
];
const PROFILE_FIELDS = ['full_name', 'email_address', 'company_name', 'job_title', 'phone_number', 'signature_html', 'signature_plain'];
const emptyProfile = Object.fromEntries(PROFILE_FIELDS.map(field => [field, '']));

const card = { background: 'white', border: '2px solid #e9ecef', borderRadius: 16, padding: '1.25rem', boxShadow: '0 4px 20px rgba(0,0,0,0.06)' };
const input = { width: '100%', boxSizing: 'border-box', padding: '0.55rem 0.7rem', border: '1px solid #cbd5e0', borderRadius: 8, font: 'inherit' };

const PREVIEW_CSP = "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data:; connect-src 'none'; form-action 'none'; base-uri 'none'";
const withPreviewCsp = html => `<!doctype html><html><head><meta http-equiv="Content-Security-Policy" content="${PREVIEW_CSP}"></head><body>${html}</body></html>`;

export default function XssEmailBuilder({ objectives = [], revision = 0, onProgressChange }) {
  const { user } = useAuth();
  const ownerKey = user?.id == null ? '' : String(user.id);
  const ownerStamp = `${ownerKey}:${localStorage.getItem('token') || ''}`;
  const [profile, setProfile] = useState(emptyProfile);
  const [level, setLevel] = useState(1);
  const [prompt, setPrompt] = useState('Create a professional welcome email using my profile.');
  const [templateType, setTemplateType] = useState('welcome');
  const [includeSignature, setIncludeSignature] = useState(true);
  const [templates, setTemplates] = useState([]);
  const [selectedTemplate, setSelectedTemplate] = useState(null);
  const [previewHtml, setPreviewHtml] = useState('');
  const [progress, setProgress] = useState([]);
  const [judgments, setJudgments] = useState([]);
  const [generationMessage, setGenerationMessage] = useState('');
  const [solution, setSolution] = useState(null);
  const [solutionOpen, setSolutionOpen] = useState(false);
  const [solutionStatus, setSolutionStatus] = useState('loading');
  const [solutionError, setSolutionError] = useState('');
  const [busy, setBusy] = useState(false);
  const [mode, setMode] = useState('vuln');
  const [modeResolved, setModeResolved] = useState(false);
  const [modePending, setModePending] = useState(false);
  const modeGeneration = useRef(0);
  const generation = useRef(0);
  const mounted = useRef(true);
  const requestController = useRef(null);
  const requestIdentity = useRef(0);
  const solutionController = useRef(null);
  const solutionIdentity = useRef(0);
  const resetAttempt = useRef(null);
  const availableLevels = LEVELS.filter(item => objectives.some(objective => objective.id === item.id)).map(item => ({
    ...item,
    label: objectives.find(objective => objective.id === item.id)?.label || item.label,
  }));
  const selectedLevel = availableLevels.find(item => item.level === level) || availableLevels[0] || null;
  const selectedObjective = selectedLevel && objectives.find(objective => objective.id === selectedLevel.id);

  useEffect(() => { mounted.current = true; return () => { mounted.current = false; generation.current += 1; modeGeneration.current += 1; requestController.current?.abort(); }; }, []);
  useEffect(() => { generation.current += 1; modeGeneration.current += 1; requestIdentity.current += 1; requestController.current?.abort(); resetAttempt.current = null; solutionIdentity.current += 1; solutionController.current?.abort(); setBusy(false); setMode('vuln'); setModeResolved(false); setModePending(false); setProfile(emptyProfile); setTemplates([]); setSelectedTemplate(null); setPreviewHtml(''); setProgress([]); setJudgments([]); setSolution(null); setSolutionOpen(false); }, [ownerStamp]);
  useEffect(() => { generation.current += 1; requestIdentity.current += 1; requestController.current?.abort(); setBusy(false); }, [selectedLevel?.id]);
  useEffect(() => { solutionIdentity.current += 1; solutionController.current?.abort(); setSolution(null); setSolutionOpen(false); }, [selectedLevel?.id, selectedObjective?.solutionVisible, revision]);
  const beginRequest = () => {
    requestController.current?.abort();
    generation.current += 1;
    const controller = new AbortController();
    requestController.current = controller;
    const identity = ++requestIdentity.current;
    return { controller, identity };
  };

  const refreshMode = useCallback(async () => {
    const ticket = ++modeGeneration.current;
    try {
      const { data } = await axios.get('/api/xss-email/mode');
      if (!mounted.current || ticket !== modeGeneration.current) return;
      const effective = data?.effectiveMode || (data?.mode === null ? 'vuln' : data?.mode);
      if (!['vuln', 'fixed'].includes(effective) || data?.scope?.id !== 'xss_email_builder') throw Error('Invalid builder mode');
      setMode(effective); setModeResolved(true);
    } catch {
      if (mounted.current && ticket === modeGeneration.current) setModeResolved(false);
    }
  }, []);
  useEffect(() => { void refreshMode(); }, [refreshMode, ownerStamp]);

  const changeMode = async (next) => {
    if (!mounted.current || modePending || next === mode || !['vuln', 'fixed'].includes(next)) return;
    const ticket = ++modeGeneration.current;
    setModePending(true);
    try {
      const { data } = await axios.post('/api/xss-email/mode', { mode: next });
      if (!mounted.current || ticket !== modeGeneration.current) return;
      if (data?.effectiveMode !== next || data?.scope?.id !== 'xss_email_builder') throw Error('Invalid builder mode response');
      setMode(next); setModeResolved(true);
      toast.info(`Switched builder to ${next === 'fixed' ? 'Fixed' : 'Vulnerable'} mode. Saved work is kept.`);
    } catch {
      if (mounted.current && ticket === modeGeneration.current) { toast.error('Could not change builder mode.'); await refreshMode(); }
    } finally {
      if (mounted.current && (ticket === modeGeneration.current || ticket + 1 === modeGeneration.current)) setModePending(false);
    }
  };

  const load = useCallback(async (signal) => {
    if (!ownerKey) return;
    const token = generation.current;
    const id = ownerKey;
    const [profileResponse, templatesResponse, progressResponse] = await Promise.all([
      axios.get(`/api/xss-email/profile/${id}`, { signal }),
      axios.get(`/api/xss-email/templates/${id}`, { signal }),
      axios.get(`/api/xss-email/challenge/progress/${id}`, { signal }),
    ]);
    if (!mounted.current || signal.aborted || token !== generation.current) return;
    setProfile({ ...emptyProfile, ...(profileResponse.data?.profile || {}) });
    setTemplates(Array.isArray(templatesResponse.data?.templates) ? templatesResponse.data.templates : []);
    const canonical = progressResponse.data?.canonical;
    const nextProgress = Array.isArray(canonical?.objectives)
      ? canonical.objectives
      : (Array.isArray(progressResponse.data?.progress) ? progressResponse.data.progress : []);
    setProgress(nextProgress);
    onProgressChange?.(nextProgress);
  }, [onProgressChange, ownerKey]);

  useEffect(() => {
    const controller = new AbortController();
    requestController.current = controller;
    load(controller.signal).catch(error => { if (error.name !== 'CanceledError' && error.code !== 'ERR_CANCELED') toast.error('Unable to load the email builder.'); });
    return () => controller.abort();
  }, [load, revision]);

  const saveProfile = async () => {
    const { controller, identity } = beginRequest();
    const token = generation.current;
    setBusy(true);
    try { const response = await axios.put(`/api/xss-email/profile/${ownerKey}`, profile, { signal: controller.signal }); if (!mounted.current || controller.signal.aborted || token !== generation.current) return; setProfile({ ...emptyProfile, ...(response.data?.profile || profile) }); toast.success('Profile saved.'); }
    catch (error) { if (!controller.signal.aborted) toast.error(error.response?.data?.error || 'Profile update failed.'); }
    finally { if (token === generation.current && identity === requestIdentity.current) setBusy(false); }
  };

  const generate = async () => {
    const { controller, identity } = beginRequest();
    const token = generation.current;
    const modeTicket = modeGeneration.current;
    setBusy(true); setPreviewHtml('');
    setGenerationMessage(''); setJudgments([]);
    try {
      const response = await axios.post('/api/xss-email/generate', { prompt, templateType, includeSignature, challengeLevel: selectedLevel?.level }, { signal: controller.signal });
      if (!mounted.current || controller.signal.aborted || token !== generation.current || modeTicket !== modeGeneration.current) return;
      if (response.data?.mode && response.data.mode !== mode) { void refreshMode(); return; }
      if (mode === 'fixed' && response.data?.mode !== 'fixed') { void refreshMode(); return; }
      const template = response.data?.template;
      if (Array.isArray(response.data?.judgments)) setJudgments(response.data.judgments);
      if (!template) {
        setGenerationMessage(response.data?.message || response.data?.error || 'The model did not produce a template for this request.');
        return;
      }
      if (template) { setSelectedTemplate(template); setTemplates(previous => [template, ...previous.filter(item => item.id !== template.id)]); }
      if (mode === 'vuln' && Array.isArray(response.data?.completedLevels) && response.data.completedLevels.length) toast.success(`Judged levels: ${response.data.completedLevels.join(', ')}`);
      const progressResponse = await axios.get(`/api/xss-email/challenge/progress/${ownerKey}`, { signal: controller.signal });
      const canonical = progressResponse.data?.canonical;
      const nextProgress = Array.isArray(canonical?.objectives) ? canonical.objectives : (progressResponse.data?.progress || []);
      if (mounted.current && !controller.signal.aborted && token === generation.current && modeTicket === modeGeneration.current) { setProgress(nextProgress); onProgressChange?.(nextProgress); }
    } catch (error) { if (token === generation.current && modeTicket === modeGeneration.current && !controller.signal.aborted) { if (error.response?.status === 409 && error.response?.data?.code === 'XSS_MODE_STALE') void refreshMode(); toast.error(error.response?.data?.error || 'Email generation failed.'); } }
    finally { if (token === generation.current && identity === requestIdentity.current) setBusy(false); }
  };

  const preview = async () => {
    if (!selectedTemplate?.id) return;
    const { controller, identity } = beginRequest();
    const token = generation.current;
    const modeTicket = modeGeneration.current;
    setBusy(true);
    try {
      const response = await axios.post('/api/xss-email/preview/render', { templateId: selectedTemplate.id }, { responseType: 'text', signal: controller.signal });
      if (!mounted.current || controller.signal.aborted || token !== generation.current || modeTicket !== modeGeneration.current) return;
      const observed = await axios.get('/api/xss-email/mode', { signal: controller.signal });
      if (!mounted.current || controller.signal.aborted || token !== generation.current || modeTicket !== modeGeneration.current) return;
      if (observed.data?.effectiveMode !== mode || observed.data?.scope?.id !== 'xss_email_builder') { void refreshMode(); return; }
      setPreviewHtml(typeof response.data === 'string' ? response.data : '');
    } catch (error) { if (!controller.signal.aborted && modeTicket === modeGeneration.current) { if (error.response?.status === 409 && error.response?.data?.code === 'XSS_MODE_STALE') void refreshMode(); toast.error(error.response?.data?.error || 'Preview failed.'); } }
    finally { if (token === generation.current && identity === requestIdentity.current) setBusy(false); }
  };

  const resetController = useWorkshopResetController({
    owner: { attendeeId: ownerStamp, workshopKey: 'xss_email_builder', scenarioId: 'builder' },
    title: 'Reset the email builder?',
    description: 'Generated templates, previews, and judged builder progress are cleared. Saved profile inputs and other XSS scenarios are preserved.',
    operationStorageKey: ownerKey ? `owasp-ai-goat:reset:${ownerKey}:xss_email_builder` : undefined,
    onBegin: () => {
      const request = beginRequest();
      resetAttempt.current = { ...request, token: generation.current, ownerStamp };
      setBusy(true);
    },
    mutation: async ({ operationId }) => {
      const attempt = resetAttempt.current;
      if (!attempt || attempt.ownerStamp !== ownerStamp) throw new Error('Builder reset session changed.');
      await axios.post('/api/xss-email/challenge/reset', { operationId }, { signal: attempt.controller.signal });
      if (!mounted.current || attempt.controller.signal.aborted || attempt.token !== generation.current
          || attempt.ownerStamp !== `${ownerKey}:${localStorage.getItem('token') || ''}`) {
        throw new Error('Builder reset was superseded. Retry to reconcile progress.');
      }
      return attempt;
    },
    onCommit: attempt => {
      if (attempt !== resetAttempt.current || attempt.identity !== requestIdentity.current) {
        throw new Error('Builder reset was superseded. Retry to reconcile progress.');
      }
      setTemplates([]); setSelectedTemplate(null); setPreviewHtml(''); setProgress([]);
      onProgressChange?.([]); setBusy(false); resetAttempt.current = null;
      toast.success('Builder progress reset.');
    },
    onError: error => {
      const attempt = resetAttempt.current;
      if (attempt?.ownerStamp === ownerStamp) {
        if (attempt.identity === requestIdentity.current) setBusy(false);
        resetAttempt.current = null;
      }
      const message = error.response?.data?.error || error.message || 'Builder reset failed.';
      toast.error(message);
      return message;
    },
  });

  const loadSolution = async () => {
    if (!selectedLevel || selectedObjective?.solutionVisible !== true) return;
    const token = ++solutionIdentity.current;
    solutionController.current?.abort();
    const controller = new AbortController(); solutionController.current = controller;
    setSolutionOpen(true); setSolution(null); setSolutionStatus('loading'); setSolutionError('');
    try {
      const response = await axios.get(`/api/solutions/xss-email-builder/${selectedLevel.id}`, { signal: controller.signal });
      if (mounted.current && !controller.signal.aborted && token === solutionIdentity.current && selectedObjective?.solutionVisible === true) {
        setSolution(response.data?.solution || response.data || null); setSolutionStatus('ready');
      }
    } catch (error) {
      if (!mounted.current || controller.signal.aborted || token !== solutionIdentity.current) return;
      if (error.response?.status === 403) { setSolutionOpen(false); return; }
      setSolutionError(error.response?.data?.error || 'Solution unavailable.'); setSolutionStatus('error');
    }
  };

  const closeSolution = () => {
    solutionIdentity.current += 1; solutionController.current?.abort();
    setSolutionOpen(false); setSolution(null);
  };

  return <div data-testid="xss-email-builder" style={{ display: 'grid', gap: '1rem' }}>
    <div style={card}>
      <h3 style={{ margin: '0 0 0.4rem', color: '#334155' }}><FiMail /> Email Template Builder</h3>
      <p style={{ margin: 0, color: '#64748b', lineHeight: 1.5 }}>Persist a profile, ask the configured model to generate an email, and inspect the isolated teaching preview. Completion follows the workshop’s judged evidence.</p>
      <div style={{ marginTop: '0.8rem' }}><WorkshopModeControl mode={mode} allowedModes={['vuln', 'fixed']} onChange={changeMode}
        pending={modePending} disabled={!modeResolved} scopeLabel="XSS email builder" /></div>
      <p role="status" style={{ margin: '0.5rem 0 0', color: '#64748b', fontSize: '0.85rem' }}>
        {mode === 'fixed' ? 'Fixed mode shows generated email HTML as inert text. Completed objectives shown below are prior workshop progress.' : 'Vulnerable mode preserves the isolated executable email preview.'}
      </p>
    </div>
    <div style={{ ...card, display: 'grid', gap: '0.75rem' }}>
      <h4 style={{ margin: 0 }}>Objective</h4>
      <select aria-label="Email builder objective" value={selectedLevel?.level || ''} onChange={event => setLevel(Number(event.target.value))} style={input} disabled={!availableLevels.length}>
        {availableLevels.map(item => <option key={item.id} value={item.level}>{item.label}</option>)}
      </select>
      <div style={{ color: '#64748b', fontSize: '0.85rem' }}>Status: {selectedLevel && progress.find(item => (item.id || item.objective_id) === selectedLevel.id)?.completed ? 'completed' : 'not completed'}</div>
      {selectedObjective?.description && <div style={{ color: '#64748b', fontSize: '0.85rem', lineHeight: 1.5 }}>{selectedObjective.description}</div>}
      {selectedLevel && selectedObjective?.hintVisible === true && <HintPanel workshopKey="xss_email_builder" objectiveId={selectedLevel.id} accentColor="#667eea" revision={revision} />}
      {selectedLevel && <ObjectiveHelpActions objectiveId={selectedLevel.id} hintVisible={false}
        solutionVisible={selectedObjective?.solutionVisible === true}
        activeKind={solutionOpen ? 'solution' : undefined}
        onOpen={loadSolution} />}
    </div>
    <div style={{ ...card, display: 'grid', gap: '0.75rem' }}>
      <h4 style={{ margin: 0 }}>Profile fields</h4>
      {PROFILE_FIELDS.map(field => <label key={field} style={{ display: 'grid', gap: 4, color: '#475569', fontSize: '0.85rem' }}>{field.replaceAll('_', ' ')}<input aria-label={field} value={profile[field] || ''} onChange={event => setProfile(previous => ({ ...previous, [field]: event.target.value }))} style={input} /></label>)}
      <WorkshopButton type="button" onClick={saveProfile} disabled={busy}><FiSave /> Save profile</WorkshopButton>
    </div>
    <div style={{ ...card, display: 'grid', gap: '0.75rem' }}>
      <h4 style={{ margin: 0 }}>Generate template</h4>
      <textarea aria-label="Generation prompt" rows={4} value={prompt} onChange={event => setPrompt(event.target.value)} style={{ ...input, resize: 'vertical' }} />
      <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap' }}><input aria-label="Template type" value={templateType} onChange={event => setTemplateType(event.target.value)} style={{ ...input, flex: 1, minWidth: 180 }} /><label style={{ display: 'flex', alignItems: 'center', gap: 6 }}><input type="checkbox" checked={includeSignature} onChange={event => setIncludeSignature(event.target.checked)} /> Include signature</label></div>
      <WorkshopButton type="button" onClick={generate} disabled={busy || !prompt.trim() || !selectedLevel}><FiSend /> {busy ? 'Working…' : 'Generate with model'}</WorkshopButton>
      {generationMessage && <div role="status" style={{ color: '#92400e', background: '#fffbeb', border: '1px solid #fcd34d', borderRadius: 8, padding: '0.6rem' }}>{generationMessage}</div>}
      {judgments.filter(item => item.objectiveId === selectedLevel?.id || item.objective_id === selectedLevel?.id).map((judgment, index) => <div key={`${judgment.objectiveId || judgment.objective_id}-${index}`} role="status" style={{ color: judgment.verdict === 'pass' ? '#166534' : '#92400e', fontSize: '0.85rem' }}>{judgment.verdict || 'unavailable'}{judgment.explanation ? ` — ${judgment.explanation}` : ''}</div>)}
    </div>
    <div style={{ ...card, display: 'grid', gap: '0.75rem' }}>
      <h4 style={{ margin: 0 }}>Templates and isolated preview</h4>
      <select aria-label="Saved template" value={selectedTemplate?.id || ''} onChange={event => setSelectedTemplate(templates.find(item => String(item.id) === event.target.value) || null)} style={input}><option value="">Select a generated template</option>{templates.map(item => <option key={item.id} value={item.id}>{item.subject || item.template_type || item.id}</option>)}</select>
      <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}><WorkshopButton type="button" variant="secondary" onClick={preview} disabled={busy || !selectedTemplate?.id}><FiEye /> Preview</WorkshopButton><ScopedResetButton label="Reset builder" onClick={resetController.requestReset} disabled={resetController.resetting} /></div>
      {previewHtml && (mode === 'fixed'
        ? <pre data-testid="fixed-email-preview" style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere', padding: '0.8rem', background: '#f8fafc', borderRadius: 8 }}>{previewHtml}</pre>
        : <iframe title="Isolated email teaching preview" sandbox="allow-scripts allow-modals" srcDoc={withPreviewCsp(previewHtml)} style={{ width: '100%', minHeight: 260, border: '1px solid #cbd5e0', borderRadius: 8 }} />)}
    </div>
    <div style={{ ...card, color: '#64748b', fontSize: '0.85rem' }}>Completion is recorded by the workshop service after its judged evidence checks.</div>
    {solutionOpen && selectedLevel && selectedObjective?.solutionVisible === true && (
      <ObjectiveHelpModal kind="solution" appearance="legacy-light"
        objective={{ title: solution?.title || selectedLevel.label }}
        content={solution && {
          explanation: solution.description,
          approach: [solution.explanation, solution.approach].filter(Boolean).join('\n'),
          tips: Array.isArray(solution.tips) ? solution.tips : [],
          examples: Array.isArray(solution.examples) ? solution.examples.map((example, index) => ({
            title: example?.title || `Example ${index + 1}`,
            payload: typeof example === 'string' ? example : example?.payload || example?.prompt || '',
            explanation: typeof example === 'string' ? '' : example?.explanation || '',
          })) : [],
        }}
        status={solutionStatus} error={solutionError} onClose={closeSolution}
        onUsePayload={payload => { setPrompt(payload); closeSolution(); }} />
    )}
    <ResetConfirmation {...resetController.confirmation} />
  </div>;
}
