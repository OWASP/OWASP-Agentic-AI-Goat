import React, { useEffect, useId, useLayoutEffect, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import styled from 'styled-components';
import { FiArrowRight, FiCheck, FiX } from 'react-icons/fi';

const Backdrop = styled.div`
  position: fixed;
  inset: 0;
  z-index: 1400;
  display: grid;
  place-items: center;
  padding: 16px;
  background: ${({ $appearance }) => ($appearance === 'legacy-light'
    ? 'rgba(33, 37, 41, 0.48)'
    : 'rgba(2, 6, 15, 0.82)')};
  animation: help-backdrop-in 120ms ease-out;

  @keyframes help-backdrop-in {
    from { opacity: 0; }
    to { opacity: 1; }
  }

  @media (prefers-reduced-motion: reduce) {
    animation: none;
  }
`;

const Dialog = styled.section`
  --help-accent: ${({ $kind, $appearance }) => ($appearance === 'legacy-light'
    ? '#667eea'
    : ($kind === 'hint' ? '#f5c451' : '#67a7ff'))};
  --help-heading: ${({ $appearance }) => ($appearance === 'legacy-light' ? '#333' : '#f4f7fb')};
  --help-text: ${({ $appearance }) => ($appearance === 'legacy-light' ? '#333' : '#e7edf5')};
  --help-muted: ${({ $appearance }) => ($appearance === 'legacy-light' ? '#6c757d' : '#9eabba')};
  --help-surface: ${({ $appearance }) => ($appearance === 'legacy-light' ? 'white' : '#111927')};
  --help-surface-subtle: ${({ $appearance }) => ($appearance === 'legacy-light' ? '#f8f9fa' : '#182334')};
  --help-border: ${({ $appearance }) => ($appearance === 'legacy-light' ? '#e9ecef' : '#344256')};
  --help-control-border: ${({ $appearance }) => ($appearance === 'legacy-light' ? '#e9ecef' : '#3a485c')};
  --help-divider: ${({ $appearance }) => ($appearance === 'legacy-light' ? '#e9ecef' : '#2b3748')};
  --help-payload-bg: ${({ $appearance }) => ($appearance === 'legacy-light' ? '#f8f9fa' : '#080e18')};
  --help-payload-text: ${({ $appearance }) => ($appearance === 'legacy-light' ? '#333' : '#eef5ff')};
  --help-primary-text: ${({ $appearance }) => ($appearance === 'legacy-light' ? 'white' : '#07111f')};
  --help-error: ${({ $appearance }) => ($appearance === 'legacy-light' ? '#dc3545' : '#ff9b9b')};
  --help-state: ${({ $appearance }) => ($appearance === 'legacy-light' ? '#6c757d' : '#c5cfdb')};
  --help-hover-text: ${({ $appearance }) => ($appearance === 'legacy-light' ? '#667eea' : '#ffffff')};
  width: calc(100% - 0px);
  max-width: 480px;
  max-height: calc(100vh - 32px);
  max-height: min(680px, calc(100dvh - 32px));
  overflow: hidden;
  display: grid;
  grid-template-rows: auto minmax(0, 1fr) auto;
  color: ${({ $appearance }) => ($appearance === 'legacy-light' ? '#333' : '#e7edf5')};
  background: ${({ $appearance }) => ($appearance === 'legacy-light' ? 'white' : '#111927')};
  border: 1px solid ${({ $appearance }) => ($appearance === 'legacy-light' ? '#e9ecef' : '#344256')};
  border-top: 3px solid var(--help-accent);
  border-radius: ${({ $appearance }) => ($appearance === 'legacy-light' ? '10px' : '8px')};
  box-shadow: 0 16px 40px rgba(0, 0, 0, 0.42);
  outline: none;

  @media (min-width: 640px) {
    width: calc(100% - 48px);
  }
`;

const Header = styled.header`
  min-width: 0;
  display: grid;
  grid-template-columns: minmax(0, 1fr) 44px;
  gap: 16px;
  align-items: start;
  padding: 20px 20px 16px;
  border-bottom: 1px solid ${({ $appearance }) => ($appearance === 'legacy-light' ? '#e9ecef' : '#2b3748')};
`;

const KindLabel = styled.div`
  margin-bottom: 5px;
  color: var(--help-accent);
  font-size: 12px;
  font-weight: 800;
  letter-spacing: 0.12em;
  line-height: 1.2;
  text-transform: uppercase;
`;

const Title = styled.h2`
  margin: 0;
  color: var(--help-heading);
  font-size: 20px;
  font-weight: 700;
  letter-spacing: -0.015em;
  line-height: 1.3;
  overflow-wrap: anywhere;
`;

const IconButton = styled.button`
  width: 44px;
  min-width: 44px;
  height: 44px;
  min-height: 44px;
  display: inline-grid;
  place-items: center;
  padding: 0;
  color: var(--help-muted);
  background: var(--help-surface-subtle);
  border: 1px solid var(--help-control-border);
  border-radius: 6px;
  cursor: pointer;

  &:hover { color: var(--help-hover-text); border-color: var(--help-accent); }
  &:focus-visible { outline: 3px solid var(--help-accent); outline-offset: 2px; }
`;

const Content = styled.div`
  min-width: 0;
  overflow-y: auto;
  padding: 20px;
  color: ${({ $appearance }) => ($appearance === 'legacy-light' ? '#333' : '#d9e1eb')};
  font-size: 16px;
  line-height: 1.65;
  overflow-wrap: anywhere;
`;

const ContentTitle = styled.h3`
  margin: 0 0 16px;
  color: var(--help-heading);
  font-size: 17px;
  font-weight: 700;
  line-height: 1.4;
`;

const Progress = styled.div`
  margin-bottom: 12px;
  color: var(--help-accent);
  font-size: 13px;
  font-weight: 800;
  letter-spacing: 0.04em;
  text-transform: uppercase;
`;

const HintList = styled.ol`
  margin: 0;
  padding: 0;
  list-style: none;
  counter-reset: help-hint;
`;

const HintStep = styled.li`
  counter-increment: help-hint;
  display: grid;
  grid-template-columns: 28px minmax(0, 1fr);
  gap: 12px;
  padding: 12px 0;
  border-top: 1px solid var(--help-divider);

  &::before {
    content: counter(help-hint, decimal-leading-zero);
    color: var(--help-accent);
    font-size: 12px;
    font-weight: 800;
    line-height: 1.65rem;
  }
`;

const PayloadLabel = styled.div`
  margin-bottom: 8px;
  color: var(--help-muted);
  font-size: 13px;
  font-weight: 700;
  letter-spacing: 0.06em;
  text-transform: uppercase;
`;

const Payload = styled.pre`
  max-width: 100%;
  margin: 0 0 16px;
  padding: 14px;
  overflow-x: auto;
  color: var(--help-payload-text);
  background: var(--help-payload-bg);
  border: 1px solid var(--help-border);
  border-left: 3px solid var(--help-accent);
  border-radius: 4px;
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  font-size: 16px;
  line-height: 1.5;
  white-space: pre-wrap;
  overflow-wrap: anywhere;
  word-break: break-word;
`;

const Explanation = styled.p`
  margin: 0;
`;

const Approach = styled.p`
  margin: 0 0 16px;
  white-space: pre-line;
`;

const TipList = styled.ul`
  margin: 0 0 16px;
  padding-left: 1.5rem;
  li + li { margin-top: 0.5rem; }
`;

const ExampleList = styled.div`
  display: grid;
  gap: 14px;
`;

const SupplementaryActions = styled.div`
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  margin-top: 16px;
  > button { min-height: 44px; }
`;

const ExampleBlock = styled.section`
  padding: 14px;
  background: var(--help-surface-subtle);
  border: 1px solid var(--help-border);
  border-radius: 8px;
`;

const ExampleTitle = styled.h4`
  margin: 0 0 10px;
  color: var(--help-heading);
  font-size: 15px;
  line-height: 1.4;
`;

const ExampleAction = styled.button`
  min-height: 44px;
  margin-top: 12px;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 8px;
  padding: 10px 16px;
  color: var(--help-primary-text);
  background-color: var(--help-accent);
  background-image: ${({ $appearance }) => ($appearance === 'legacy-light'
    ? 'linear-gradient(135deg, #667eea, #764ba2)'
    : 'none')};
  border: 1px solid var(--help-accent);
  border-radius: 8px;
  font: inherit;
  font-size: 14px;
  font-weight: 750;
  cursor: pointer;

  &:focus-visible { outline: 3px solid var(--help-accent); outline-offset: 2px; }
`;

const StateMessage = styled.div`
  min-height: 88px;
  display: flex;
  align-items: center;
  color: ${({ $error }) => ($error ? 'var(--help-error)' : 'var(--help-state)')};
`;

const Footer = styled.footer`
  display: flex;
  flex-wrap: wrap;
  justify-content: flex-end;
  gap: 8px;
  padding: 12px 20px 16px;
  border-top: 1px solid var(--help-divider);
`;

const Action = styled.button`
  min-height: 44px;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 8px;
  padding: 10px 16px;
  color: ${({ $primary }) => ($primary ? 'var(--help-primary-text)' : 'var(--help-text)')};
  background: ${({ $primary }) => ($primary ? 'var(--help-accent)' : 'var(--help-surface-subtle)')};
  border: 1px solid ${({ $primary }) => ($primary ? 'var(--help-accent)' : 'var(--help-control-border)')};
  border-radius: 6px;
  font: inherit;
  font-size: 14px;
  font-weight: 750;
  cursor: pointer;

  &:hover { border-color: var(--help-accent); }
  &:focus-visible { outline: 3px solid var(--help-accent); outline-offset: 2px; }
`;

const FOCUSABLE = [
  'button:not([disabled])',
  'a[href]',
  'input:not([disabled])',
  'select:not([disabled])',
  'textarea:not([disabled])',
  '[tabindex]:not([tabindex="-1"])',
].join(',');

function objectiveName(objective) {
  if (typeof objective === 'string') return objective;
  return objective?.name || objective?.title || objective?.text || objective?.id || 'Objective';
}

function stateCopy(kind, status, error) {
  if (status === 'loading') return `Loading ${kind}…`;
  if (status === 'error') return error || `Could not load this ${kind}. Try again.`;
  if (status === 'revoked') return `This ${kind} is no longer available.`;
  return `No ${kind} content is available.`;
}

export default function ObjectiveHelpModal({
  kind,
  objective,
  content,
  onClose,
  onUsePayload,
  actions,
  status = 'ready',
  error,
  appearance = 'default',
}) {
  const dialogRef = useRef(null);
  const closeRef = useRef(null);
  const priorFocusRef = useRef(null);
  const onCloseRef = useRef(onClose);
  const [revealCount, setRevealCount] = useState(1);
  const reactId = useId();
  const titleId = `objective-help-title-${reactId.replace(/:/g, '')}`;
  const descriptionId = `objective-help-content-${reactId.replace(/:/g, '')}`;
  const normalizedKind = kind === 'solution' ? 'solution' : 'hint';
  const label = normalizedKind === 'hint' ? 'Hint' : 'Solution';
  const hints = Array.isArray(content?.hints)
    ? content.hints.filter((hint) => typeof hint === 'string' && hint.trim())
    : [];
  const payload = typeof content?.payload === 'string' ? content.payload.trim() : '';
  const explanation = typeof content?.explanation === 'string' ? content.explanation.trim() : '';
  const approach = typeof content?.approach === 'string' ? content.approach.trim() : '';
  const tips = Array.isArray(content?.tips)
    ? content.tips.filter((tip) => typeof tip === 'string' && tip.trim()).map((tip) => tip.trim())
    : [];
  const authoredExamples = Array.isArray(content?.examples)
    ? content.examples.map((example, index) => ({
        title: typeof example?.title === 'string' && example.title.trim()
          ? example.title.trim()
          : `Example ${index + 1}`,
        payload: typeof example?.payload === 'string' ? example.payload.trim() : '',
        explanation: typeof example?.explanation === 'string' ? example.explanation.trim() : '',
      })).filter((example) => example.payload || example.explanation)
    : [];
  const solutionExamples = authoredExamples.length > 0
    ? authoredExamples
    : (payload ? [{ title: 'Example payload', payload, explanation }] : []);
  const isEmpty = status === 'empty'
    || (status === 'ready' && normalizedKind === 'hint' && hints.length === 0)
    || (status === 'ready' && normalizedKind === 'solution' && solutionExamples.length === 0 && !explanation && !approach && tips.length === 0);
  const displayStatus = isEmpty ? 'empty' : status;

  useEffect(() => {
    onCloseRef.current = onClose;
  }, [onClose]);

  useEffect(() => {
    setRevealCount(1);
  }, [content, normalizedKind]);

  useLayoutEffect(() => {
    if (typeof document === 'undefined') return undefined;
    priorFocusRef.current = document.activeElement;
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    closeRef.current?.focus();

    const handleKeyDown = (event) => {
      if (event.key === 'Escape') {
        event.preventDefault();
        event.stopPropagation();
        onCloseRef.current?.();
        return;
      }
      if (event.key !== 'Tab') return;

      const focusable = [...(dialogRef.current?.querySelectorAll(FOCUSABLE) || [])];
      if (!focusable.length) {
        event.preventDefault();
        dialogRef.current?.focus();
        return;
      }
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (event.shiftKey && (document.activeElement === first || !dialogRef.current?.contains(document.activeElement))) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && (document.activeElement === last || !dialogRef.current?.contains(document.activeElement))) {
        event.preventDefault();
        first.focus();
      }
    };

    document.addEventListener('keydown', handleKeyDown);
    return () => {
      document.removeEventListener('keydown', handleKeyDown);
      document.body.style.overflow = previousOverflow;
      priorFocusRef.current?.focus?.();
    };
  }, []);

  if (typeof document === 'undefined') return null;

  const showReadyHint = displayStatus === 'ready' && normalizedKind === 'hint';
  const showReadySolution = displayStatus === 'ready' && normalizedKind === 'solution';

  return createPortal(
    <Backdrop
      $appearance={appearance}
      data-testid="objective-help-backdrop"
      onClick={(event) => {
        if (event.target === event.currentTarget) onClose?.();
      }}
    >
      <Dialog
        ref={dialogRef}
        $kind={normalizedKind}
        $appearance={appearance}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        aria-describedby={descriptionId}
        tabIndex={-1}
        data-testid="objective-help-modal"
        data-help-kind={normalizedKind}
      >
        <Header $appearance={appearance}>
          <div>
            <KindLabel>{label}</KindLabel>
            <Title id={titleId}>{label} · {objectiveName(objective)}</Title>
          </div>
          <IconButton ref={closeRef} type="button" aria-label={`Close ${normalizedKind}`} onClick={onClose}>
            <FiX size={20} aria-hidden="true" />
          </IconButton>
        </Header>

        <Content $appearance={appearance} id={descriptionId} data-testid="objective-help-content">
          {showReadyHint && (
            <>
              {content?.title && <ContentTitle>{content.title}</ContentTitle>}
              <Progress>Hint {Math.min(revealCount, hints.length)} of {hints.length}</Progress>
              <HintList>
                {hints.slice(0, revealCount).map((hint, index) => <HintStep key={`${index}-${hint}`}>{hint}</HintStep>)}
              </HintList>
            </>
          )}

          {showReadySolution && (
            <>
              {content?.title && <ContentTitle>{content.title}</ContentTitle>}
              {explanation && <Approach>{explanation}</Approach>}
              {approach && <><ContentTitle>Approach</ContentTitle><Approach>{approach}</Approach></>}
              <ExampleList>
                {solutionExamples.map((example, index) => (
                  <ExampleBlock key={`${index}-${example.payload}`} data-testid="solution-example">
                    <ExampleTitle>{example.title}</ExampleTitle>
                    {example.payload && <><PayloadLabel>Payload</PayloadLabel><Payload><code>{example.payload}</code></Payload></>}
                    {example.explanation && <Explanation>{example.explanation}</Explanation>}
                    {example.payload && onUsePayload && (
                      <ExampleAction
                        type="button"
                        $appearance={appearance}
                        onClick={() => onUsePayload(example.payload)}
                      >
                        <FiCheck aria-hidden="true" /> Use this payload
                      </ExampleAction>
                    )}
                  </ExampleBlock>
                ))}
              </ExampleList>
              {tips.length > 0 && <><ContentTitle>Tips</ContentTitle><TipList>{tips.map((tip, index) => <li key={`${index}-${tip}`}>{tip}</li>)}</TipList></>}
              {actions && <SupplementaryActions data-testid="objective-help-actions">{actions}</SupplementaryActions>}
            </>
          )}

          {displayStatus !== 'ready' && (
            <StateMessage
              role={displayStatus === 'error' || displayStatus === 'revoked' ? 'alert' : 'status'}
              $error={displayStatus === 'error' || displayStatus === 'revoked'}
            >
              {stateCopy(normalizedKind, displayStatus, error)}
            </StateMessage>
          )}
        </Content>

        <Footer>
          {showReadyHint && revealCount < hints.length && (
            <Action type="button" $primary onClick={() => setRevealCount((count) => Math.min(count + 1, hints.length))}>
              Next hint <FiArrowRight aria-hidden="true" />
            </Action>
          )}
          <Action type="button" onClick={onClose}>Close</Action>
        </Footer>
      </Dialog>
    </Backdrop>,
    document.body,
  );
}
