import React, { useEffect, useId, useRef } from 'react';
import { createPortal } from 'react-dom';
import styled from 'styled-components';
import { motion } from 'framer-motion';
import { FiBookOpen, FiHelpCircle, FiRefreshCw } from 'react-icons/fi';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import { getScenario, validateWorkshop, workshopTokens } from './experience.mjs';

const Content = styled.div`
  --workshop-brand: ${workshopTokens.brand};
  --workshop-brand-end: ${workshopTokens.brandEnd};
  --workshop-surface: ${workshopTokens.surface};
  --workshop-canvas: ${workshopTokens.canvas};
  --workshop-text: ${workshopTokens.text};
  --workshop-muted-text: ${workshopTokens.mutedText};
  --workshop-border: ${workshopTokens.border};
  --workshop-focus: ${workshopTokens.focus};
  display: flex;
  flex-direction: column;
  gap: 2rem;
  min-width: 0;
  > * { min-width: 0; }
`;

function assertTemplate(definition, expected) {
  validateWorkshop(definition);
  if (definition.template !== expected) {
    throw new TypeError(`${expected} workshop definition required`);
  }
}

export function WorkshopExperience({ definition, children, ...props }) {
  validateWorkshop(definition);
  return (
    <Content
      data-workshop={definition.workshopKey}
      data-workshop-template={definition.template}
      data-experience-version={definition.experienceVersion}
      {...props}
    >
      {children}
    </Content>
  );
}

export function SingleScenarioWorkshop({ definition, children, ...props }) {
  assertTemplate(definition, 'single-scenario');
  const scenario = definition.scenarios[0];
  return (
    <WorkshopExperience
      definition={definition}
      data-active-scenario={scenario.id}
      data-workflow={scenario.workflow}
      {...props}
    >
      {children}
    </WorkshopExperience>
  );
}

export function MultiScenarioWorkshop({ definition, activeScenarioId, children, ...props }) {
  assertTemplate(definition, 'multi-scenario');
  if (!getScenario(definition, activeScenarioId)) {
    throw new TypeError(`Unknown active scenario: ${activeScenarioId}`);
  }
  return (
    <WorkshopExperience
      definition={definition}
      data-active-scenario={activeScenarioId}
      {...props}
    >
      {children}
    </WorkshopExperience>
  );
}

const Navigator = styled.div`
  display: flex;
  gap: 0;
  margin-bottom: 1.5rem;
  border-bottom: 2px solid ${workshopTokens.border};
  overflow-x: auto;
`;

const ScenarioTab = styled.button`
  padding: 1rem 1.5rem;
  min-height: 44px;
  font-size: 1rem;
  font-weight: 600;
  border: none;
  background: ${({ $active }) => ($active ? workshopTokens.surface : 'transparent')};
  color: ${({ $active }) => ($active ? workshopTokens.focus : '#666666')};
  cursor: pointer;
  border-bottom: 3px solid ${({ $active }) => ($active ? workshopTokens.brand : 'transparent')};
  margin-bottom: -2px;
  display: flex;
  align-items: center;
  gap: 0.5rem;
  white-space: nowrap;
  transition: color 0.2s ease, background 0.2s ease;

  &:hover:not(:disabled) {
    color: ${workshopTokens.focus};
    background: ${({ $active }) => ($active ? workshopTokens.surface : 'rgba(102, 126, 234, 0.05)')};
  }
  &:focus-visible {
    outline: 3px solid rgba(51, 71, 176, 0.35);
    outline-offset: -3px;
  }
  &:disabled { opacity: ${workshopTokens.disabledOpacity}; cursor: not-allowed; }
  @media (prefers-reduced-motion: reduce) { transition: none; }
`;

export function ScenarioNavigator({
  definition,
  activeScenarioId,
  onScenarioChange,
  renderLabel,
  renderTab,
  labelledBy,
}) {
  assertTemplate(definition, 'multi-scenario');
  const enabledScenarios = definition.scenarios.filter((scenario) => scenario.hidden !== true);
  const moveFocus = (event, index) => {
    let nextIndex = index;
    if (event.key === 'ArrowRight') nextIndex = (index + 1) % enabledScenarios.length;
    else if (event.key === 'ArrowLeft') nextIndex = (index - 1 + enabledScenarios.length) % enabledScenarios.length;
    else if (event.key === 'Home') nextIndex = 0;
    else if (event.key === 'End') nextIndex = enabledScenarios.length - 1;
    else return;
    event.preventDefault();
    const next = enabledScenarios[nextIndex];
    onScenarioChange(next.id);
    event.currentTarget.parentElement
      ?.querySelector(`[data-scenario-tab="${next.id}"]`)
      ?.focus();
  };
  return (
    <Navigator role="tablist" aria-label={labelledBy ? undefined : 'Workshop scenarios'} aria-labelledby={labelledBy}>
      {enabledScenarios.map((scenario, index) => {
        const active = scenario.id === activeScenarioId;
        const tabProps = {
          type: 'button',
          role: 'tab',
          id: `scenario-tab-${scenario.id}`,
          'aria-controls': `scenario-panel-${scenario.id}`,
          'aria-selected': active,
          tabIndex: active ? 0 : -1,
          'data-scenario-tab': scenario.id,
          onClick: () => onScenarioChange(scenario.id),
          onKeyDown: (event) => moveFocus(event, index),
        };
        const label = renderLabel ? renderLabel(scenario) : scenario.label || scenario.id;
        return renderTab ? (
          <React.Fragment key={scenario.id}>{renderTab({ scenario, active, tabProps, label })}</React.Fragment>
        ) : (
          <ScenarioTab
            key={scenario.id}
            $active={active}
            {...tabProps}
          >
            {label}
          </ScenarioTab>
        );
      })}
    </Navigator>
  );
}

const ScenarioPanel = styled.section`
  display: ${({ $active }) => ($active ? 'block' : 'none')};
`;

export function ScenarioWorkspace({ scenarioId, activeScenarioId, children, ...props }) {
  const active = scenarioId === activeScenarioId;
  return (
    <ScenarioPanel
      id={`scenario-panel-${scenarioId}`}
      role="tabpanel"
      aria-labelledby={`scenario-tab-${scenarioId}`}
      aria-hidden={!active}
      hidden={!active}
      $active={active}
      data-scenario-workspace={scenarioId}
      {...props}
    >
      {children}
    </ScenarioPanel>
  );
}

export const WorkspaceLayout = styled.div`
  display: grid;
  grid-template-columns: minmax(0, 2fr) minmax(280px, 1fr);
  gap: 2rem;
  align-items: start;
  @media (max-width: ${workshopTokens.mainCollapse}) { grid-template-columns: minmax(0, 1fr); }
`;

export const ActionGroup = styled.div`
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 0.75rem;
`;

const ModeGroup = styled.fieldset`
  display: inline-flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 0.5rem;
  min-width: 0;
  margin: 0;
  padding: 0;
  border: 0;
  legend {
    margin-bottom: 0.35rem;
    color: ${workshopTokens.mutedText};
    font-size: 0.85rem;
    font-weight: 700;
  }
`;

const ModeOption = styled.button`
  min-height: 44px;
  padding: 0.6rem 1rem;
  border: 1px solid ${({ $selected }) => ($selected ? workshopTokens.focus : workshopTokens.controlBorder)};
  border-radius: ${workshopTokens.controlRadius};
  background: ${({ $selected }) => ($selected ? workshopTokens.focus : workshopTokens.surface)};
  color: ${({ $selected }) => ($selected ? workshopTokens.surface : workshopTokens.text)};
  font: inherit;
  font-weight: 700;
  cursor: pointer;
  &:focus-visible { outline: 3px solid rgba(51, 71, 176, 0.35); outline-offset: 2px; }
  &:disabled { cursor: not-allowed; }
  &:disabled:not([aria-pressed="true"]) { opacity: ${workshopTokens.disabledOpacity}; }
`;

const ModeExplanation = styled.span`
  flex-basis: 100%;
  color: ${workshopTokens.mutedText};
  font-size: 0.85rem;
  line-height: 1.4;
`;

const MODE_LABELS = Object.freeze({ vuln: 'Vulnerable', fixed: 'Fixed' });

export function WorkshopModeBadge({ mode, scopeLabel = 'Lab mode' }) {
  const label = MODE_LABELS[mode] || 'Unavailable';
  return <span data-workshop-mode={MODE_LABELS[mode] ? mode : 'unknown'}>{scopeLabel}: {label}</span>;
}

export function WorkshopModeControl({
  mode,
  allowedModes,
  onChange,
  pending = false,
  disabled = false,
  reason,
  scopeLabel = 'Lab mode',
  unselectedModeLabel,
}) {
  const unselected = mode === null && Array.isArray(allowedModes)
    && typeof unselectedModeLabel === 'string' && unselectedModeLabel.trim().length > 0;
  if (!MODE_LABELS[mode] && !unselected) return <WorkshopModeBadge mode={mode} scopeLabel={scopeLabel} />;
  const supported = new Set(Array.isArray(allowedModes) ? allowedModes : [mode]);
  if (!unselected) supported.add(mode);
  const fixedUnavailable = !supported.has('fixed');
  const explanation = fixedUnavailable
    ? (reason || 'Fixed mode is unavailable for this exercise.')
    : (pending ? 'Changing mode…' : '');
  return (
    <ModeGroup data-workshop-mode-control data-workshop-mode={unselected ? 'unselected' : mode}>
      <legend>{scopeLabel}</legend>
      {unselected && <ModeExplanation role="status">{unselectedModeLabel.trim()}</ModeExplanation>}
      {Object.entries(MODE_LABELS).map(([value, label]) => {
        const selected = mode === value;
        const available = supported.has(value);
        return (
          <ModeOption
            key={value}
            type="button"
            $selected={selected}
            aria-pressed={selected}
            disabled={selected || !available || pending || disabled || typeof onChange !== 'function'}
            onClick={() => onChange(value)}
          >
            {label}
          </ModeOption>
        );
      })}
      {explanation && <ModeExplanation role={fixedUnavailable ? 'status' : undefined}>{explanation}</ModeExplanation>}
    </ModeGroup>
  );
}

const buttonGradient = ({ variant, $variant }) => {
  const choice = $variant || variant || 'primary';
  if (choice === 'secondary') return workshopTokens.secondaryGradient;
  if (choice === 'success') return workshopTokens.successGradient;
  if (choice === 'danger') return workshopTokens.dangerGradient;
  if (choice === 'tertiary') return workshopTokens.surface;
  return workshopTokens.primaryGradient;
};

export const WorkshopButton = styled(motion.button).withConfig({
  shouldForwardProp: (prop) => prop !== 'variant',
})`
  background: ${buttonGradient};
  color: ${({ variant, $variant }) => (($variant || variant) === 'tertiary' ? workshopTokens.focus : 'white')};
  border: ${({ variant, $variant }) => (($variant || variant) === 'tertiary' ? `1px solid ${workshopTokens.focus}` : 'none')};
  min-height: 44px;
  padding: 0.75rem 1.5rem;
  border-radius: ${workshopTokens.controlRadius};
  font-weight: 600;
  font-size: 0.95rem;
  cursor: pointer;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 0.5rem;
  &:hover:not(:disabled) {
    transform: translateY(-2px);
    box-shadow: 0 4px 12px rgba(102, 126, 234, 0.3);
  }
  &:focus-visible { outline: 3px solid rgba(51, 71, 176, 0.35); outline-offset: 2px; }
  &:disabled { opacity: ${workshopTokens.disabledOpacity}; cursor: not-allowed; }
  &.secondary { background: ${workshopTokens.secondaryGradient}; }
  &.success { background: ${workshopTokens.successGradient}; }
  &.danger { background: ${workshopTokens.dangerGradient}; }
  &.full-width { width: 100%; justify-content: center; }
  .spin { animation: workshop-spin 1s linear infinite; }
  @keyframes workshop-spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }
  @media (prefers-reduced-motion: reduce) {
    transition: none;
    &:hover:not(:disabled) { transform: none; }
    .spin { animation: none; }
  }
`;

const HelpActions = styled.div`
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 0.5rem;
  margin-top: 0.5rem;
`;

const ObjectiveHelpButton = styled.button`
  flex: 0 0 auto;
  width: auto;
  min-height: 32px;
  padding: 0.25rem 0.625rem;
  border: 1px solid ${workshopTokens.brand};
  border-radius: 10px;
  background-color: ${workshopTokens.brand};
  background-image: ${workshopTokens.primaryGradient};
  color: white;
  font: inherit;
  font-size: 0.85rem;
  font-weight: 600;
  cursor: pointer;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 0.4rem;
  box-shadow: 0 2px 4px rgba(102, 126, 234, 0.3);

  &:hover:not(:disabled) { filter: brightness(1.05); }
  &:focus-visible { outline: 3px solid rgba(102, 126, 234, 0.35); outline-offset: 2px; }
  &:disabled { opacity: ${workshopTokens.disabledOpacity}; cursor: not-allowed; }
`;

export function ObjectiveHelpActions({
  objectiveId,
  hintVisible = false,
  solutionVisible = false,
  onOpen,
  activeKind,
  disabled = false,
}) {
  if (!hintVisible && !solutionVisible) return null;
  return (
    <HelpActions data-objective-help-actions={objectiveId} onClick={(event) => event.stopPropagation()}>
      {hintVisible && (
        <ObjectiveHelpButton
          type="button"
          data-testid={`hint-button-${objectiveId}`}
          aria-haspopup="dialog"
          aria-expanded={activeKind === 'hint'}
          disabled={disabled || typeof onOpen !== 'function'}
          onClick={() => onOpen('hint', objectiveId)}
        >
          <FiHelpCircle aria-hidden="true" /> Hint
        </ObjectiveHelpButton>
      )}
      {solutionVisible && (
        <ObjectiveHelpButton
          type="button"
          data-testid={`solution-button-${objectiveId}`}
          aria-haspopup="dialog"
          aria-expanded={activeKind === 'solution'}
          disabled={disabled || typeof onOpen !== 'function'}
          onClick={() => onOpen('solution', objectiveId)}
        >
          <FiBookOpen aria-hidden="true" /> Solution
        </ObjectiveHelpButton>
      )}
    </HelpActions>
  );
}

export function ScopedResetButton({ label, onClick, disabled = false }) {
  if (typeof label !== 'string' || !label.trim()) throw new TypeError('Scoped reset label required');
  return (
    <WorkshopButton type="button" variant="secondary" onClick={onClick} disabled={disabled || typeof onClick !== 'function'}>
      <FiRefreshCw aria-hidden="true" /> {label}
    </WorkshopButton>
  );
}

export const StatusNotice = styled.div.withConfig({
  shouldForwardProp: (prop) => prop !== 'status',
}).attrs(({ status = 'info' }) => ({
  role: status === 'error' ? 'alert' : 'status',
}))`
  padding: 0.85rem 1rem;
  border-radius: ${workshopTokens.controlRadius};
  border: 1px solid ${({ status }) => (
    status === 'error' ? workshopTokens.danger
      : status === 'success' ? workshopTokens.complete
        : status === 'warning' ? workshopTokens.warning
          : workshopTokens.border
  )};
  background: ${({ status }) => (
    status === 'error' ? 'rgba(220, 53, 69, 0.08)'
      : status === 'success' ? workshopTokens.completeSurface
        : status === 'warning' ? 'rgba(255, 193, 7, 0.12)'
          : workshopTokens.canvas
  )};
  color: ${workshopTokens.text};
`;

export const EmptyState = styled(StatusNotice)`
  text-align: center;
  padding: 1.5rem;
`;

export const ObjectiveList = styled.div`
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
`;

export const ObjectiveCard = styled(motion.button)`
  width: 100%;
  min-height: 44px;
  padding: 1rem 1.25rem;
  text-align: left;
  border-radius: 12px;
  border: 2px solid ${({ $completed, $active }) => (
    $completed ? workshopTokens.complete : $active ? workshopTokens.brand : workshopTokens.border
  )};
  background: ${({ $completed }) => ($completed ? workshopTokens.completeSurface : workshopTokens.canvas)};
  color: ${workshopTokens.text};
  cursor: pointer;
  &:focus-visible { outline: 3px solid rgba(51, 71, 176, 0.35); outline-offset: 2px; }
  &:disabled { opacity: ${workshopTokens.disabledOpacity}; cursor: not-allowed; }
`;

export function ExerciseProgress({ completed, total, label = 'objectives completed' }) {
  const safeTotal = Math.max(0, Number(total) || 0);
  const safeCompleted = Math.min(safeTotal, Math.max(0, Number(completed) || 0));
  const percent = safeTotal === 0 ? 0 : (safeCompleted / safeTotal) * 100;
  return (
    <div data-workshop-progress>
      <div>{safeCompleted} of {safeTotal} {label}</div>
      <div aria-hidden="true" style={{ height: 20, background: workshopTokens.border, borderRadius: 10, overflow: 'hidden' }}>
        <div style={{ height: '100%', width: `${percent}%`, background: workshopTokens.primaryGradient }} />
      </div>
    </div>
  );
}

export const ChatPanel = styled.section`
  min-width: 0;
  background: ${workshopTokens.surface};
  border: 2px solid ${workshopTokens.border};
  border-radius: ${workshopTokens.cardRadius};
  overflow: hidden;
`;
export const MessageList = styled.div.attrs({ role: 'log', 'aria-live': 'polite' })`
  max-height: min(60vh, 620px);
  overflow-y: auto;
  padding: 1.5rem;
`;
export const MessageBubble = styled.div`
  overflow-wrap: anywhere;
  white-space: pre-wrap;
`;

const SafeChatContent = styled.div`
  min-width: 0;
  overflow-wrap: anywhere;
  pre { max-width: 100%; overflow-x: auto; white-space: pre-wrap; overflow-wrap: anywhere; }
  code { overflow-wrap: anywhere; }
`;

export function SafeChatBody({ content, plain = false }) {
  const text = typeof content === 'string' ? content : String(content ?? '');
  return (
    <SafeChatContent data-safe-chat-body>
      {plain ? <span style={{ whiteSpace: 'pre-wrap' }}>{text}</span> : <ReactMarkdown remarkPlugins={[remarkGfm]}>{text}</ReactMarkdown>}
    </SafeChatContent>
  );
}
export const ChatComposer = styled.form`
  display: flex;
  align-items: flex-end;
  gap: 0.75rem;
  padding: 1rem;
  border-top: 1px solid ${workshopTokens.border};
  textarea { min-height: 44px; max-height: 30vh; resize: vertical; flex: 1; }
`;
export const ToolResultPanel = styled.pre`
  max-height: 24rem;
  overflow: auto;
  white-space: pre-wrap;
  overflow-wrap: anywhere;
`;

const ResetBackdrop = styled.div`
  position: fixed;
  inset: 0;
  z-index: 10000;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 1.5rem;
  background: rgba(0, 0, 0, 0.5);
`;
const ResetDialog = styled.div`
  width: min(100%, 32rem);
  padding: 1.5rem;
  border-radius: ${workshopTokens.cardRadius};
  background: ${workshopTokens.surface};
  color: ${workshopTokens.text};
  box-shadow: 0 20px 60px rgba(0, 0, 0, 0.25);
  h2 { margin: 0 0 0.75rem; font-size: 1.25rem; }
  p { margin: 0 0 1rem; line-height: 1.6; }
`;

export function ResetConfirmation({ open, status, title, description, error, onCancel, onConfirm }) {
  const confirmRef = useRef(null);
  const dialogRef = useRef(null);
  const returnFocusRef = useRef(null);
  const statusRef = useRef(status);
  statusRef.current = status;
  const id = useId().replace(/:/g, '');
  const titleId = `workshop-reset-title-${id}`;
  const descriptionId = `workshop-reset-description-${id}`;
  useEffect(() => {
    if (!open) return undefined;
    returnFocusRef.current = document.activeElement;
    confirmRef.current?.focus();
    const onKeyDown = (event) => {
      if (event.key === 'Escape' && statusRef.current !== 'resetting') onCancel();
      if (event.key !== 'Tab') return;
      const controls = [...(dialogRef.current?.querySelectorAll('button:not(:disabled)') || [])];
      if (!controls.length) return;
      const first = controls[0];
      const last = controls[controls.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    };
    document.addEventListener('keydown', onKeyDown);
    return () => {
      document.removeEventListener('keydown', onKeyDown);
      returnFocusRef.current?.focus?.();
    };
  }, [onCancel, open]);
  if (!open) return null;
  const resetting = status === 'resetting';
  return createPortal(
    <ResetBackdrop onMouseDown={(event) => {
      if (event.target === event.currentTarget && !resetting) onCancel();
    }}>
      <ResetDialog ref={dialogRef} role="alertdialog" aria-modal="true" aria-labelledby={titleId} aria-describedby={descriptionId}>
        <h2 id={titleId}>{title}</h2>
        <p id={descriptionId}>{description}</p>
        {error && <StatusNotice status="error">{error}</StatusNotice>}
        <ActionGroup style={{ justifyContent: 'flex-end', marginTop: '1rem' }}>
          <WorkshopButton type="button" variant="secondary" onClick={onCancel} disabled={resetting}>Cancel</WorkshopButton>
          <WorkshopButton ref={confirmRef} type="button" variant="danger" onClick={onConfirm} disabled={resetting}>
            {resetting ? 'Resetting…' : 'Confirm reset'}
          </WorkshopButton>
        </ActionGroup>
      </ResetDialog>
    </ResetBackdrop>, document.body
  );
}
