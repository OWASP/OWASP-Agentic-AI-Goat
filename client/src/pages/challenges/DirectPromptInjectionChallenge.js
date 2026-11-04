import { readSelectedLesson, describeSelectedLesson } from '../../utils/dpiSelectedLesson';
/**
 * Direct Prompt Injection Challenge - Enhanced
 * Matches XSS vulnerability page styling and uses canonical objective availability
 * with Exercise Objectives Progress and Overall Exercise Progress UI.
 */
import React, { useState, useEffect, useMemo, useRef, useCallback } from 'react';
import styled from 'styled-components';
import {
  FiSend, FiUser, FiShield, FiAlertTriangle, FiCode, FiTarget, FiActivity,
  FiCheckCircle, FiLock, FiUnlock, FiMessageSquare, FiChevronDown, FiChevronUp,
  FiZap
} from 'react-icons/fi';
import { toast } from 'react-toastify';
import { getJudgeFeedback, isGradingUnqualified } from '../../utils/judgeFeedback.mjs';
import JudgeRetryButton from '../../components/workshop/JudgeRetryButton';
import ChatActivityTabs from '../../components/workshop/ChatActivityTabs';
import { motion, AnimatePresence } from 'framer-motion';
import axios from 'axios';
import VulnerabilityTemplate from '../../components/VulnerabilityTemplate';
import {
  ResetConfirmation,
  SingleScenarioWorkshop,
  SafeChatBody,
  ObjectiveHelpActions,
  WorkshopModeControl,
  WorkshopButton as Button,
} from '../../components/workshop/WorkshopExperience';
import { directPromptInjectionExperience, workshopTokens } from '../../components/workshop/experience.mjs';
import useWorkshopResetController from '../../components/workshop/useWorkshopResetController';
import ObjectiveHelpModal from '../../components/workshop/ObjectiveHelpModal';
import useWorkshopHeartbeat from '../../hooks/useWorkshopHeartbeat';
import useChangePolling from '../../hooks/useChangePolling';
import useReconciliationGuard, { useGuardedSetter } from '../../hooks/useReconciliationGuard';
import { useWorkshopConfig } from '../../context/WorkshopConfigContext';
import {
  deriveDpiVisibility,
  isDpiExerciseUsable,
  reconcileDpiActiveObjective,
} from './directPromptInjectionVisibility';
import {
  appendToTranscript,
  buildConversationHistory,
  createObjectiveTranscript,
  getVisibleObjectives,
  normalizeSolution,
  readDpiToolActivity,
} from './directPromptInjectionState';

// ----- Styled components matching XSS vulnerability page -----


const SectionTitle = styled.h2`
  color: ${workshopTokens.text};
  margin: 0 0 1rem 0;
  font-size: 1.5rem;
  font-weight: 600;
  display: flex;
  align-items: center;
  gap: 0.75rem;
`;

const IntroSection = styled.div`
  background: linear-gradient(135deg, rgba(102, 126, 234, 0.1), rgba(118, 75, 162, 0.1));
  border: 2px solid #667eea;
  border-radius: ${workshopTokens.cardRadius};
  padding: 2rem;
  margin-bottom: 2rem;

  h3 {
    color: #667eea;
    font-size: 1.3rem;
    margin: 0 0 1rem 0;
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }

  p {
    color: ${workshopTokens.mutedText};
    line-height: 1.7;
    margin: 0.5rem 0;
  }

  .scenario {
    background: rgba(255, 255, 255, 0.8);
    border-left: 4px solid #667eea;
    padding: 1rem;
    margin: 1rem 0;
    border-radius: 8px;
    strong { color: #667eea; }
  }
`;

const TwoColumnLayout = styled.div`
  display: grid;
  grid-template-columns: minmax(0, 2fr) minmax(0, 1fr);
  gap: 2rem;
  margin-bottom: 2rem;
  align-items: stretch;
  @media (max-width: 1024px) {
    grid-template-columns: minmax(0, 1fr);
  }
`;

const Panel = styled.div`
  background: white;
  border: 2px solid ${workshopTokens.border};
  border-radius: ${workshopTokens.cardRadius};
  padding: 2rem;
  box-shadow: 0 4px 20px rgba(0, 0, 0, 0.08);
  display: flex;
  flex-direction: column;
  min-height: 560px;
  &.highlight {
    border-color: #667eea;
    box-shadow: 0 4px 20px rgba(102, 126, 234, 0.15);
  }
`;

const PanelHeader = styled.div`
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 1.5rem;
  padding-bottom: 1rem;
  border-bottom: 2px solid #e9ecef;
  h3 {
    margin: 0;
    color: ${workshopTokens.text};
    font-size: 1.2rem;
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }
`;

const ChatSection = styled.div`
  background: white;
  border-radius: ${workshopTokens.cardRadius};
  box-shadow: 0 4px 20px rgba(0, 0, 0, 0.08);
  overflow: hidden;
  display: flex;
  flex-direction: column;
  height: 600px;
`;

const ChatHeader = styled.div`
  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
  color: white;
  padding: 1.25rem;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 0.75rem;
  flex-shrink: 0;
  @media (max-width: 600px) {
    flex-wrap: wrap;
    > div { min-width: 0; flex-wrap: wrap; }
  }
  h3 {
    margin: 0;
    font-size: 1.1rem;
    font-weight: 600;
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }
`;

const StatusIndicator = styled.div`
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background: #4ade80;
  box-shadow: 0 0 8px #4ade80;
  animation: pulse 2s infinite;
  @keyframes pulse {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.5; }
  }
`;

// Progress block (lives inside right panel with the enabled objective count)
const ProgressBlock = styled.div`
  margin-top: 1.5rem;
  padding-top: 1.5rem;
  border-top: 2px solid #e9ecef;

  .progress-title {
    font-size: 1.1rem;
    font-weight: 600;
    color: ${workshopTokens.text};
    margin-bottom: 0.75rem;
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }
  .progress-text {
    font-size: 0.95rem;
    color: #666;
    margin-bottom: 0.75rem;
  }
  .progress-bar-track {
    height: 20px;
    background: #e9ecef;
    border-radius: 10px;
    overflow: hidden;
  }
  .progress-bar-fill {
    height: 100%;
    background: linear-gradient(90deg, #667eea, #764ba2);
    border-radius: 10px;
    transition: width 0.5s ease;
  }
  .progress-complete {
    margin-top: 1rem;
    padding: 0.75rem 1rem;
    background: linear-gradient(135deg, rgba(40, 167, 69, 0.12), rgba(32, 201, 151, 0.12));
    border: 2px solid #28a745;
    border-radius: 10px;
    color: #28a745;
    font-weight: 700;
    font-size: 0.95rem;
    text-align: center;
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 0.5rem;
  }
`;

// Wrapper for objectives list (used inside right panel)
const ObjectivesListWrapper = styled.div`
  .objectives-list {
    display: flex;
    flex-direction: column;
    gap: 0.75rem;
    margin-top: 0.5rem;
  }
`;

const ObjectiveItem = styled(motion.div)`
  display: flex;
  align-items: flex-start;
  gap: 1rem;
  padding: 0.875rem 1.25rem;
  background: ${props => props.$active ? 'rgba(102, 126, 234, 0.08)' : props.$completed ? '#f0fdf4' : '#f8f9fa'};
  border: 1px solid ${props => props.$active ? '#667eea' : props.$completed ? '#22c55e' : '#e2e8f0'};
  border-radius: 10px;
  cursor: pointer;
  transition: all 0.3s ease;
  position: relative;
  overflow: hidden;

  &:hover {
    transform: translateY(-2px);
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.05);
    border-color: ${props => props.$active ? '#667eea' : '#667eea'};
  }

  .status-badge {
    position: absolute;
    top: 0;
    right: 0;
    padding: 0.2rem 0.6rem;
    font-size: 0.65rem;
    font-weight: 800;
    letter-spacing: 0.05em;
    border-bottom-left-radius: 8px;
    color: white;
    background: ${props => props.$active ? '#667eea' : props.$completed ? '#22c55e' : '#dee2e6'};
  }

  .obj-icon {
    flex-shrink: 0;
    width: 36px;
    height: 36px;
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 1.1rem;
    background: ${props => props.$active ? '#667eea' : props.$completed ? '#22c55e' : '#dee2e6'};
    color: white;
  }
  .obj-content {
    flex: 1;
  }
  .obj-name {
    font-weight: 600;
    color: ${workshopTokens.text};
    margin-bottom: 0.25rem;
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }
  .obj-desc {
    font-size: 0.85rem;
    color: #666;
    line-height: 1.4;
  }
`;

const ChatContainer = styled.div`
  flex: 1;
  min-height: 0;
  display: flex;
  flex-direction: column;
  background: #f8f9fa;
`;

const MessageList = styled.div`
  flex: 1;
  overflow-y: auto;
  min-height: 0;
  padding: 1.5rem;
  padding-right: 0.5rem;
  &::-webkit-scrollbar { width: 8px; }
  &::-webkit-scrollbar-track { background: rgba(0,0,0,0.05); border-radius: 4px; }
  &::-webkit-scrollbar-thumb { background: rgba(102, 126, 234, 0.3); border-radius: 4px; }
`;

const Message = styled(motion.div)`
  margin-bottom: 1rem;
  display: flex;
  align-items: flex-start;
  gap: 0.75rem;
  &.user {
    flex-direction: row-reverse;
    .message-content {
      background: linear-gradient(135deg, #667eea, #764ba2);
      color: white;
      margin-left: auto;
      border-radius: 18px 18px 4px 18px;
      box-shadow: 0 2px 8px rgba(0, 0, 0, 0.06);
    }
  }
  &.ai .message-content {
    background: white;
    border: 1px solid #e2e8f0;
    border-radius: 18px 18px 18px 4px;
    box-shadow: 0 2px 8px rgba(0, 0, 0, 0.06);
  }
  &.system .message-content {
    background: rgba(255, 193, 7, 0.1);
    border: 1px solid #ffc107;
    color: ${workshopTokens.text};
    border-radius: 12px;
    box-shadow: 0 2px 8px rgba(0, 0, 0, 0.06);
  }
  &.objective-complete .message-content {
    background: rgba(40, 167, 69, 0.1);
    border: 1px solid #28a745;
    border-radius: 12px;
    box-shadow: 0 2px 8px rgba(0, 0, 0, 0.06);
  }
  .message-icon {
    flex-shrink: 0;
    width: 36px;
    height: 36px;
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 1.1rem;
  }
  .message-icon.user-avatar {
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    color: white;
  }
  .message-icon.ai-avatar {
    background: linear-gradient(135deg, #06b6d4 0%, #3b82f6 100%);
    color: white;
  }
  .message-icon.system-avatar {
    background: linear-gradient(135deg, #f59e0b 0%, #ef4444 100%);
    color: white;
  }
  .message-icon.success-avatar {
    background: linear-gradient(135deg, #22c55e 0%, #16a34a 100%);
    color: white;
  }
  .message-content {
    flex: 1;
    padding: 0.875rem 1.125rem;
    max-width: 85%;
    min-width: 0;
    word-wrap: break-word;
    overflow-wrap: break-word;
  }
  .message-header {
    font-size: 0.75rem;
    opacity: 0.9;
    margin-bottom: 0.25rem;
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }
  .message-text {
    font-size: 0.9rem;
    line-height: 1.6;
    word-break: break-word;
    overflow-wrap: break-word;
    p { margin: 0 0 0.5rem 0; }
    p:last-child { margin-bottom: 0; }
    ul, ol { margin: 0.25rem 0 0.5rem 1.25rem; padding: 0; }
    li { margin-bottom: 0.2rem; }
    strong, b { font-weight: 700; }
    em, i { font-style: italic; }
    code { font-family: monospace; background: rgba(0,0,0,0.08); padding: 0.1rem 0.3rem; border-radius: 3px; font-size: 0.85em; }
    pre { background: rgba(0,0,0,0.08); padding: 0.5rem; border-radius: 4px; overflow-x: auto; margin: 0.4rem 0; }
    pre code { background: none; padding: 0; }
    h1, h2, h3 { font-weight: 700; margin: 0.5rem 0 0.25rem; }
  }
  .objective-badge {
    display: inline-flex;
    align-items: center;
    gap: 0.25rem;
    font-size: 0.7rem;
    font-weight: 700;
    color: ${workshopTokens.text};
    background: #e2e8f0;
    &.objective-badge--completed {
      color: #28a745;
      background: rgba(40, 167, 69, 0.2);
    }
    padding: 0.2rem 0.5rem;
    border-radius: 6px;
    margin-top: 0.5rem;
  }
`;

const InputContainer = styled.form`
  display: flex;
  gap: 0.75rem;
  align-items: flex-end;
  padding: 1.25rem;
  background: white;
  border-top: 1px solid #e2e8f0;
  flex-shrink: 0;
`;

const MessageInput = styled.textarea`
  flex: 1;
  padding: 0.875rem 1.125rem;
  border: 2px solid #e2e8f0;
  border-radius: 12px;
  font-size: 0.95rem;
  resize: none;
  min-height: 44px;
  max-height: 100px;
  transition: all 0.3s ease;
  &:focus {
    outline: none;
    border-color: #667eea;
    box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
  }
  &::placeholder { color: #6c757d; }
`;

const SendButton = styled(motion.button)`
  background: linear-gradient(135deg, #667eea, #764ba2);
  color: white;
  border: none;
  border-radius: 12px;
  width: 44px;
  height: 44px;
  display: flex;
  align-items: center;
  justify-content: center;
  cursor: pointer;
  flex-shrink: 0;
  transition: all 0.3s ease;
  &:hover:not(:disabled) {
    transform: translateY(-2px);
    box-shadow: 0 6px 20px rgba(102, 126, 234, 0.4);
  }
  &:disabled { opacity: 0.5; cursor: not-allowed; }
`;



// eslint-disable-next-line no-unused-vars -- retained to preserve the baseline styled-component surface.
const FormGroup = styled.div`
  margin-bottom: 1.5rem;
  label {
    display: block;
    font-weight: 600;
    color: ${workshopTokens.text};
    margin-bottom: 0.5rem;
    font-size: 0.9rem;
  }
  input, textarea {
    width: 100%;
    padding: 0.75rem;
    border: 2px solid ${workshopTokens.border};
    border-radius: 8px;
    font-size: 0.95rem;
    transition: border-color 0.3s ease;
    &:focus { outline: none; border-color: #667eea; }
    &::placeholder { color: #999; }
  }
  textarea { min-height: 80px; resize: vertical; }
`;

const TechniquesPanel = styled.div`
  background: #f8f9fa;
  border-radius: 12px;
  padding: 1.5rem;
  margin-top: 1rem;
  .technique-item {
    background: white;
    border: 1px solid #dee2e6;
    border-radius: 8px;
    padding: 1rem;
    margin-bottom: 0.75rem;
    cursor: pointer;
    transition: all 0.2s ease;
    &:hover {
      border-color: #667eea;
      box-shadow: 0 2px 8px rgba(102, 126, 234, 0.15);
    }
    .technique-title { font-weight: 600; color: ${workshopTokens.text}; margin-bottom: 0.25rem; display: flex; align-items: center; gap: 0.5rem; }
    .technique-desc { font-size: 0.85rem; color: #666; }
  }
`;

// ----- Objective renderers; availability and labels come from the catalog -----
const OBJECTIVE_IDS = {
  INTERACT: 'interact',
  FORMAT_OVERRIDE: 'format_override',
  CLASSIFICATION_OVERRIDE: 'classification_override',
  SYSTEM_PROMPT: 'system_prompt',
  JAILBREAK: 'jailbreak',
  MULTI_LANGUAGE: 'multi_language',
  VIRTUALIZATION: 'virtualization',
  ROLE_PLAYING: 'role_playing',
  SIDE_STEPPING: 'side_stepping',
  OBFUSCATION: 'obfuscation'
};

const OBJECTIVES = [
  { id: OBJECTIVE_IDS.INTERACT, name: 'Practice Mode', description: 'Ask two AWS questions to complete practice.', icon: FiMessageSquare, isPractice: true },
  { id: OBJECTIVE_IDS.FORMAT_OVERRIDE, name: 'Output Format Attack', description: 'Make the formatter reply with exactly GOAT FORMAT OVERRIDDEN as plain text.', icon: FiCode },
  { id: OBJECTIVE_IDS.CLASSIFICATION_OVERRIDE, name: 'Classification Attack', description: 'Make ticket LAB-204 return APPROVED instead of REVIEW.', icon: FiTarget },
  { id: OBJECTIVE_IDS.SYSTEM_PROMPT, name: 'System Prompt Extraction', description: 'Get the assistant to reveal its hidden instructions.', icon: FiShield },
  { id: OBJECTIVE_IDS.JAILBREAK, name: 'Jailbreak Attack', description: 'Override the rules and get an answer about a non-AWS topic.', icon: FiUnlock },
  { id: OBJECTIVE_IDS.MULTI_LANGUAGE, name: 'Multi-Language Attack', description: 'Ask a non-AWS question in another language.', icon: FiActivity },
  { id: OBJECTIVE_IDS.VIRTUALIZATION, name: 'Virtualization Attack', description: 'Use a hypothetical scenario to get a non-AWS answer.', icon: FiZap },
  { id: OBJECTIVE_IDS.ROLE_PLAYING, name: 'Role Playing Attack', description: 'Assign a new role and ask a non-AWS question.', icon: FiUser },
  { id: OBJECTIVE_IDS.SIDE_STEPPING, name: 'Side Stepping Attack', description: 'Use an AWS comparison or migration question to get competitor details.', icon: FiTarget },
  { id: OBJECTIVE_IDS.OBFUSCATION, name: 'Obfuscation Attack', description: 'Encode a non-AWS question and get the assistant to answer it.', icon: FiCode }
];
const OBJECTIVE_ID_ORDER = OBJECTIVES.map(({ id }) => id);
const MODE_ENDPOINT = '/api/workshop/prompt-injection/mode';
const transcriptKey = (mode, objectiveId) => `${mode}:${objectiveId}`;
const readMode = (data) => {
  const effectiveMode = data?.effectiveMode || data?.mode;
  const selectableModes = data?.selectableModes || data?.allowedModes;
  if (!['vuln', 'fixed'].includes(effectiveMode)
    || !Array.isArray(selectableModes)
    || !selectableModes.includes(effectiveMode)
    || (data?.scope && data.scope.id !== 'direct_prompt_injection')) {
    throw new Error('Invalid workshop mode response');
  }
  return { mode: effectiveMode, selectableModes, reason: data?.reason || '' };
};

// Objective credit comes from canonical server-side Judge and owned evidence.

const EMPTY_HELP = {
  open: false,
  kind: null,
  objectiveId: null,
  content: null,
  status: 'loading',
  error: '',
};

const completedFromProgress = (progress) => {
  const completed = {};
  OBJECTIVES.forEach((objective) => {
    if (progress?.objectives?.[objective.id]?.completed) completed[objective.id] = true;
  });
  return completed;
};

const DirectPromptInjectionChallenge = () => {
  const { snapshot, revision } = useWorkshopConfig();
  const platformToken = localStorage.getItem('token');
  const ownerTokenRef = useRef(platformToken);
  const resetIdentityRef = useRef({ token: platformToken, generation: 0 });
  if (resetIdentityRef.current.token !== platformToken) {
    resetIdentityRef.current = { token: platformToken, generation: resetIdentityRef.current.generation + 1 };
  }
  const ownerIsCurrent = () => platformToken === localStorage.getItem('token');
  const dpiVisibility = useMemo(() => deriveDpiVisibility(snapshot), [snapshot]);
  const catalogObjectives = useMemo(() => OBJECTIVES.map(objective => ({
    ...objective,
    name: dpiVisibility.objectives[objective.id]?.label || objective.name,
    description: dpiVisibility.objectives[objective.id]?.description || objective.description,
  })), [dpiVisibility]);
  const dpiVisibilityRef = useRef(dpiVisibility);
  dpiVisibilityRef.current = dpiVisibility;
  const [transcripts, setTranscripts] = useState({});
  const [modeState, setModeState] = useState(null);
  const [modePending, setModePending] = useState(false);
  const [modeError, setModeError] = useState(false);
  const modeStateRef = useRef(null);
  const modeTicketRef = useRef(0);
  const modeEpochRef = useRef(0);
  const modeBusyRef = useRef(false);
  const modeControllerRef = useRef(null);
  const modeReady = modeState?.ownerToken === platformToken;
  const labMode = modeReady ? modeState.mode : null;
  const [inputMessage, setInputMessage] = useState('');
  const [loadingObjectives, setLoadingObjectives] = useState({});
  const [activeObjectiveId, setActiveObjectiveId] = useState(OBJECTIVE_IDS.INTERACT);
  const activeObjectiveIdRef = useRef(activeObjectiveId);
  activeObjectiveIdRef.current = activeObjectiveId;
  const progressGuard = useReconciliationGuard();
  const [completedObjectives, setCompletedObjectivesFromPoll] = useState({});
  const setCompletedObjectives = useGuardedSetter(setCompletedObjectivesFromPoll, progressGuard);
  const [lastCompletedObjectiveId, setLastCompletedObjectiveId] = useState(null);
  const navigationGenerationRef = useRef(0);
  const navigationTimersRef = useRef(new Set());
  const retireCompletionNavigation = useCallback(() => {
    navigationGenerationRef.current += 1;
    navigationTimersRef.current.forEach(timer => clearTimeout(timer));
    navigationTimersRef.current.clear();
  }, []);
  const cancelCompletionNavigation = useCallback(() => {
    retireCompletionNavigation();
    setLastCompletedObjectiveId(null);
  }, [retireCompletionNavigation]);
  const [progressLoading, setProgressLoading] = useState(true);
  const [help, setHelp] = useState(EMPTY_HELP);
  const [expandedTechniques, setExpandedTechniques] = useState({});
  const [llmStatus, setLlmStatus] = useState({
    available: false,
    provider: 'unknown',
    providerName: 'AI provider',
    model: null,
    message: '',
    ollamaBaseURL: null,
    ollamaVersion: null,
    availableModels: []
  });
  const messageListRef = useRef(null);
  const nextIdRef = useRef(3);
  const completedInteractRef = useRef(false);
  const requestSequenceRef = useRef(0);
  const requestGenerationsRef = useRef({});
  const requestsRef = useRef({});
  const helpRequestRef = useRef(0);
  const pendingHelpRef = useRef(null);

  const applyMode = (data) => {
    const next = { ...readMode(data), ownerToken: platformToken };
    const prior = modeStateRef.current;
    if (prior?.ownerToken === platformToken && prior.mode !== next.mode) {
      modeEpochRef.current += 1;
      retireCompletionNavigation();
      setLastCompletedObjectiveId(null);
      Object.keys(requestsRef.current).forEach(objectiveId => {
        requestGenerationsRef.current[objectiveId] = (requestGenerationsRef.current[objectiveId] || 0) + 1;
        requestsRef.current[objectiveId]?.controller?.abort?.();
      });
      requestsRef.current = {};
      setLoadingObjectives({});
      setInputMessage('');
    }
    modeStateRef.current = next;
    setModeState(next);
    setModeError(false);
  };

  const refreshMode = async () => {
    const ticket = ++modeTicketRef.current;
    modeControllerRef.current?.abort?.();
    const controller = typeof AbortController === 'undefined' ? null : new AbortController();
    modeControllerRef.current = controller;
    try {
      const response = await axios.get(MODE_ENDPOINT, controller ? { signal: controller.signal } : undefined);
      if (!ownerIsCurrent() || controller?.signal.aborted || ticket !== modeTicketRef.current) return;
      applyMode(response.data);
    } catch {
      if (!ownerIsCurrent() || controller?.signal.aborted || ticket !== modeTicketRef.current) return;
      modeStateRef.current = null;
      setModeState(null);
      setModeError(true);
    }
  };

  useEffect(() => {
    if (ownerTokenRef.current === platformToken) return;
    ownerTokenRef.current = platformToken;
    modeTicketRef.current += 1;
    modeControllerRef.current?.abort?.();
    modeStateRef.current = null;
    modeEpochRef.current += 1;
    modeBusyRef.current = false;
    setModeState(null);
    setModePending(false);
    setModeError(false);
    Object.keys(requestsRef.current).forEach(objectiveId => {
      requestGenerationsRef.current[objectiveId] = (requestGenerationsRef.current[objectiveId] || 0) + 1;
      requestsRef.current[objectiveId]?.controller?.abort?.();
    });
    requestsRef.current = {};
    retireCompletionNavigation();
    progressGuard.mark('progress');
    progressGuard.mark('help');
    helpRequestRef.current += 1;
    pendingHelpRef.current = null;
    completedInteractRef.current = false;
    setTranscripts({});
    setLoadingObjectives({});
    setCompletedObjectivesFromPoll({});
    setLastCompletedObjectiveId(null);
    setInputMessage('');
    setHelp(EMPTY_HELP);
    setActiveObjectiveId(OBJECTIVE_IDS.INTERACT);
  }, [platformToken, progressGuard, retireCompletionNavigation]);

  useEffect(() => {
    void refreshMode();
    return () => {
      modeTicketRef.current += 1;
      modeControllerRef.current?.abort?.();
    };
    // The owner token is the mode request's lifecycle boundary.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [platformToken]);

  useWorkshopHeartbeat('direct_prompt_injection');
  useChangePolling(async (_next, _previous, { signal } = {}) => {
    if (!ownerIsCurrent()) return;
    const modeTicket = modeBusyRef.current || !modeStateRef.current ? null : ++modeTicketRef.current;
    const progressGeneration = progressGuard.begin('progress');
    const helpDisclosure = help.open ? help : pendingHelpRef.current;
    const helpGeneration = helpDisclosure ? progressGuard.begin('help') : null;
    const gate = helpDisclosure
      ? dpiVisibilityRef.current.objectives[helpDisclosure.objectiveId]
      : null;
    const helpVisible = helpDisclosure?.kind === 'hint' ? gate?.hintVisible : gate?.solutionVisible;
    const helpEndpoint = helpDisclosure?.kind === 'hint'
      ? `/api/hints/direct_prompt_injection/${helpDisclosure.objectiveId}`
      : `/api/solutions/prompt-injection/${helpDisclosure?.objectiveId}`;
    const [progressResponse, helpResponse, modeResponse] = await Promise.all([
      axios.get('/api/workshop/prompt-injection/progress', { signal }),
      helpDisclosure && dpiVisibilityRef.current.isVisible && gate?.isVisible && helpVisible
        ? axios.get(helpEndpoint, { signal })
        : Promise.resolve(null),
      modeTicket === null ? Promise.resolve(null)
        : axios.get(MODE_ENDPOINT, { signal }).catch(() => null),
    ]);
    if (!ownerIsCurrent() || signal?.aborted) return;
    if (modeResponse && modeTicket === modeTicketRef.current && !modeBusyRef.current) {
      try { applyMode(modeResponse.data); } catch { /* retain the last valid canonical mode */ }
    }
    progressGuard.commit('progress', progressGeneration, () => {
      setCompletedObjectivesFromPoll(completedFromProgress(progressResponse.data));
    });
    if (helpGeneration !== null) progressGuard.commit('help', helpGeneration, () => {
      if (!dpiVisibilityRef.current.isVisible || !gate?.isVisible || !helpVisible) {
        closeHelp();
      } else if (helpResponse) {
        const content = helpDisclosure.kind === 'hint'
          ? {
              title: helpResponse.data?.hint?.title || 'Hint',
              hints: Array.isArray(helpResponse.data?.hint?.hints) ? helpResponse.data.hint.hints : []
            }
          : normalizeSolution(helpResponse.data?.solution);
        pendingHelpRef.current = null;
        setHelp(current => {
          if (!current.open || current.kind !== helpDisclosure.kind
              || current.objectiveId !== helpDisclosure.objectiveId) return current;
          // Keep the modal's revealed hints and reading position across an
          // unchanged background refresh. Changed instructor content still resets it.
          if (current.status === 'ready' && !current.error
              && JSON.stringify(current.content) === JSON.stringify(content)) return current;
          return { ...current, content, status: 'ready', error: '' };
        });
      }
    });
  }, ['direct_prompt_injection']);

  // Challenges progress (excluding practice mode)
  const visibleObjectives = useMemo(
    () => getVisibleObjectives(catalogObjectives, dpiVisibility),
    [catalogObjectives, dpiVisibility]
  );
  const challengeObjectives = useMemo(
    () => visibleObjectives.filter(o => !o.isPractice),
    [visibleObjectives]
  );
  const exerciseUsable = isDpiExerciseUsable(dpiVisibility, activeObjectiveId);
  const messages = useMemo(
    () => (activeObjectiveId && labMode ? (transcripts[transcriptKey(labMode, activeObjectiveId)] || []) : []),
    [activeObjectiveId, labMode, transcripts]
  );
  const loading = Boolean(activeObjectiveId && loadingObjectives[activeObjectiveId]);
  const toolActivity = useMemo(() => messages.flatMap(message => message.toolActivity || []), [messages]);
  const anySubmitting = Object.keys(loadingObjectives).length > 0;
  const completedCount = visibleObjectives.filter(o => completedObjectives[o.id]).length;
  const allComplete = visibleObjectives.length > 0 && completedCount === visibleObjectives.length;
  const allChallengesComplete = challengeObjectives.length > 0
    && challengeObjectives.every(o => completedObjectives[o.id]);

  const ensureTranscript = (objectiveId, mode = labMode) => {
    if (!mode) return;
    const objective = catalogObjectives.find(candidate => candidate.id === objectiveId);
    if (!objective) return;
    const key = transcriptKey(mode, objectiveId);
    setTranscripts(current => current[key]
      ? current
      : { ...current, [key]: createObjectiveTranscript(objective) });
  };

  const cancelObjectiveRequest = (objectiveId) => {
    if (!objectiveId) return;
    requestGenerationsRef.current[objectiveId] = (requestGenerationsRef.current[objectiveId] || 0) + 1;
    requestsRef.current[objectiveId]?.controller?.abort?.();
    delete requestsRef.current[objectiveId];
    setLoadingObjectives(current => {
      if (!current[objectiveId]) return current;
      const next = { ...current };
      delete next[objectiveId];
      return next;
    });
  };

  const closeHelp = () => {
    pendingHelpRef.current = null;
    progressGuard.mark('help');
    helpRequestRef.current += 1;
    setHelp(EMPTY_HELP);
  };

  // Scroll only the chat message list to bottom (avoids page jump)
  useEffect(() => {
    const el = messageListRef.current;
    if (!el) return;
    const scrollToBottom = () => {
      el.scrollTop = el.scrollHeight;
    };
    requestAnimationFrame(scrollToBottom);
  }, [messages, loading]);

  useEffect(() => {
    axios.get('/api/workshop/prompt-injection/llm-status')
      .then(res => setLlmStatus({
        available: res.data.available,
        provider: res.data.provider || 'unknown',
        providerName: res.data.providerName || 'AI provider',
        model: res.data.model,
        message: res.data.message || '',
        ollamaBaseURL: res.data.ollamaBaseURL || null,
        ollamaVersion: res.data.ollamaVersion || null,
        availableModels: Array.isArray(res.data.availableModels) ? res.data.availableModels : []
      }))
      .catch(() => setLlmStatus({
        available: false,
        provider: 'unknown',
        providerName: 'AI provider',
        model: null,
        message: 'Could not check AI provider status.',
        ollamaBaseURL: null,
        ollamaVersion: null,
        availableModels: []
      }));
  }, []);

  useEffect(() => {
    setActiveObjectiveId(current => {
      if (isDpiExerciseUsable(dpiVisibility, current)) return current;
      return OBJECTIVE_ID_ORDER.find(objectiveId => (
        dpiVisibility.isVisible
        && dpiVisibility.objectives[objectiveId]?.isVisible
        && !completedObjectives[objectiveId]
      )) || reconcileDpiActiveObjective(dpiVisibility, null, OBJECTIVE_ID_ORDER);
    });
    setHelp(current => {
      if (!current.open) return current;
      const gate = dpiVisibility.objectives[current.objectiveId];
      const visible = current.kind === 'hint' ? gate?.hintVisible : gate?.solutionVisible;
      if (dpiVisibility.isVisible && gate?.isVisible && visible) return current;
      helpRequestRef.current += 1;
      return EMPTY_HELP;
    });
    Object.keys(requestsRef.current).forEach(objectiveId => {
      if (isDpiExerciseUsable(dpiVisibility, objectiveId)) return;
      requestGenerationsRef.current[objectiveId] = (requestGenerationsRef.current[objectiveId] || 0) + 1;
      requestsRef.current[objectiveId]?.controller?.abort?.();
      delete requestsRef.current[objectiveId];
      setLoadingObjectives(current => {
        const next = { ...current };
        delete next[objectiveId];
        return next;
      });
    });
  }, [completedObjectives, dpiVisibility, revision]);

  useEffect(() => {
    const objective = catalogObjectives.find(candidate => candidate.id === activeObjectiveId);
    if (!objective || !labMode) return;
    const key = transcriptKey(labMode, activeObjectiveId);
    setTranscripts(current => current[key]
      ? current
      : { ...current, [key]: createObjectiveTranscript(objective) });
  }, [activeObjectiveId, catalogObjectives, labMode]);

  useEffect(() => {
    setTranscripts(current => {
      let changed = false;
      const next = { ...current };
      for (const [key, transcript] of Object.entries(current)) {
        const objectiveId = key.slice(key.indexOf(':') + 1);
        const objective = catalogObjectives.find(candidate => candidate.id === objectiveId);
        if (!objective) continue;
        const expected = `Exercise: ${objective.name}`;
        const index = transcript.findIndex(message => message.id === `${objectiveId}-system`);
        if (index < 0 || transcript[index].content === expected) continue;
        const updated = [...transcript];
        updated[index] = { ...updated[index], content: expected };
        next[key] = updated;
        changed = true;
      }
      return changed ? next : current;
    });
  }, [catalogObjectives]);

  useEffect(() => () => {
    modeTicketRef.current += 1;
    modeControllerRef.current?.abort?.();
    Object.entries(requestsRef.current).forEach(([objectiveId, request]) => {
      requestGenerationsRef.current[objectiveId] = (requestGenerationsRef.current[objectiveId] || 0) + 1;
      delete requestsRef.current[objectiveId];
      request.controller?.abort?.();
    });
    helpRequestRef.current += 1;
    retireCompletionNavigation();
  }, [retireCompletionNavigation]);

  // Load persisted progress on mount
  useEffect(() => {
    const progressGeneration = progressGuard.begin('progress');
    setProgressLoading(true);
    axios.get('/api/workshop/prompt-injection/progress')
      .then(res => {
        if (!ownerIsCurrent()) return;
        progressGuard.commit('progress', progressGeneration, () => {
          setCompletedObjectivesFromPoll(completedFromProgress(res.data));
        });
      })
      .catch(() => { /* keep default state on error */ })
      .finally(() => { if (ownerIsCurrent()) setProgressLoading(false); });
  }, [progressGuard, platformToken]);

  useEffect(() => {
    if (!lastCompletedObjectiveId) return;
    const t = setTimeout(() => setLastCompletedObjectiveId(null), 4000);
    return () => clearTimeout(t);
  }, [lastCompletedObjectiveId]);

  // Auto-progress to next incomplete objective after completing one (2s delay)
  useEffect(() => {
    if (!lastCompletedObjectiveId || allChallengesComplete) return;
    const generation = navigationGenerationRef.current;
    const timer = setTimeout(() => {
      navigationTimersRef.current.delete(timer);
      if (!ownerIsCurrent() || navigationGenerationRef.current !== generation) return;
      const challengeList = challengeObjectives;
      // For the practice (interact) objective, start searching from the beginning of the challenge list
      const currentIndex = lastCompletedObjectiveId === OBJECTIVE_IDS.INTERACT
        ? -1
        : challengeList.findIndex(o => o.id === lastCompletedObjectiveId);
      let nextId = null;
      for (let i = currentIndex + 1; i < challengeList.length; i++) {
        if (!completedObjectives[challengeList[i].id]) {
          nextId = challengeList[i].id;
          break;
        }
      }
      if (nextId) {
        const obj = catalogObjectives.find(o => o.id === nextId);
        setActiveObjectiveId(nextId);
        // Fresh conversation for the next objective (no persona/history carry-over).
        startObjectiveConversation(obj);
        toast.info(`Switched to: ${obj.name} — fresh conversation started`);
      }
    }, 2000);
    navigationTimersRef.current.add(timer);
    return () => { clearTimeout(timer); navigationTimersRef.current.delete(timer); };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [lastCompletedObjectiveId, allChallengesComplete, completedObjectives, challengeObjectives]);

  // Keep each objective's conversation independent while preserving it for return visits.
  const startObjectiveConversation = (obj) => {
    ensureTranscript(obj.id);
    completedInteractRef.current = false;
  };

  const handleObjectiveClick = (id) => {
    if (modeBusyRef.current || progressReset.resetting) return;
    if (!isDpiExerciseUsable(dpiVisibilityRef.current, id)) return;
    if (id === activeObjectiveId) return;

    cancelCompletionNavigation();
    const obj = catalogObjectives.find(o => o.id === id);
    setActiveObjectiveId(id);
    startObjectiveConversation(obj);
    toast.info(`Switched to: ${obj.name} — fresh conversation started`);
  };

  const retryNavigationGeneration = navigationGenerationRef.current;
  const retryModeEpoch = modeEpochRef.current;
  const retryRequestGenerations = { ...requestGenerationsRef.current };
  const handleJudgeRetryResult = async (objectiveId, data, { signal } = {}) => {
    const isCurrent = () => ownerIsCurrent() && !signal?.aborted
      && navigationGenerationRef.current === retryNavigationGeneration
      && modeEpochRef.current === retryModeEpoch
      && (requestGenerationsRef.current[objectiveId] || 0) === (retryRequestGenerations[objectiveId] || 0)
      && isDpiExerciseUsable(dpiVisibilityRef.current, objectiveId);
    if (!isCurrent()) return;
    for (const feedback of getJudgeFeedback(data)) {
      setTranscripts(current => appendToTranscript(current, transcriptKey(labMode, objectiveId), {
        id: nextIdRef.current++, type: 'system', plain: true, content: feedback.content,
        timestamp: new Date(), judgeVerdict: feedback.verdict,
        evaluationId: feedback.evaluationId, canRetry: feedback.canRetry,
      }));
    }
    const progressGeneration = progressGuard.begin('progress');
    try {
      const response = await axios.get('/api/workshop/prompt-injection/progress', { signal });
      if (!isCurrent()) return;
      if (progressGuard.capture('progress') === progressGeneration) {
        progressGuard.commit('progress', progressGeneration, () => {
          setCompletedObjectivesFromPoll(completedFromProgress(response.data));
        });
      }
      if (data.completed === true && !isGradingUnqualified(data)) toast.success('Objective evaluation passed.');
    } catch {
      if (isCurrent()) toast.error('Evaluation finished, but progress could not be refreshed.');
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    const objectiveId = activeObjectiveId;
    if (!modeReady || modeBusyRef.current || progressReset.resetting
      || !isDpiExerciseUsable(dpiVisibilityRef.current, objectiveId)) return;
    if (!inputMessage.trim() || requestsRef.current[objectiveId]) return;

    const requestMode = labMode;
    const requestModeEpoch = modeEpochRef.current;
    const key = transcriptKey(requestMode, objectiveId);
    const userContent = inputMessage.trim();
    const objective = catalogObjectives.find(candidate => candidate.id === objectiveId);
    const transcript = transcripts[key] || createObjectiveTranscript(objective);
    const conversationHistory = buildConversationHistory(transcript);
    const userMsg = {
      id: nextIdRef.current++,
      type: 'user',
      content: userContent,
      timestamp: new Date()
    };
    setTranscripts(current => appendToTranscript(
      current[key] ? current : { ...current, [key]: transcript },
      key,
      userMsg
    ));
    setInputMessage('');

    const requestId = ++requestSequenceRef.current;
    const generation = requestGenerationsRef.current[objectiveId] || 0;
    requestGenerationsRef.current[objectiveId] = generation;
    const controller = typeof AbortController === 'undefined' ? null : new AbortController();
    requestsRef.current[objectiveId] = { requestId, objectiveId, generation, controller };
    setLoadingObjectives(current => ({ ...current, [objectiveId]: true }));

    const isCurrentRequest = () => (
      ownerIsCurrent() && !controller?.signal.aborted
      && modeEpochRef.current === requestModeEpoch
      && requestsRef.current[objectiveId]?.requestId === requestId
      && requestGenerationsRef.current[objectiveId] === generation
      && isDpiExerciseUsable(dpiVisibilityRef.current, objectiveId)
    );

    try {
      const res = await axios.post('/api/workshop/prompt-injection/chat', {
        userMessage: userContent,
        conversationHistory,
        completedObjectives,
        activeObjectiveId: objectiveId
      }, {
        timeout: 330000,
        ...(controller ? { signal: controller.signal } : {})
      });

      if (!isCurrentRequest()) return;

      const data = res.data;
      const aiContent = data.response || "I'm sorry, I couldn't generate a response.";
      const committedObjectives = data.progress?.objectives || null;
      const committedCompleted = committedObjectives
        ? completedFromProgress(data.progress)
        : null;
      if (committedObjectives) {
        setCompletedObjectives(current => ({ ...current, ...committedCompleted }));
      }
      const completedId = !isGradingUnqualified(data) && data.completedObjectiveId
        && committedObjectives?.[data.completedObjectiveId]?.completed
        ? data.completedObjectiveId
        : null;

      const aiMsg = {
        id: nextIdRef.current++,
        type: 'ai',
        displayType: completedId ? 'objective-complete' : undefined,
        content: aiContent,
        selectedLesson: readSelectedLesson(data.selectedLesson, objectiveId),
        toolActivity: readDpiToolActivity(data.toolActivity),
        timestamp: new Date(),
        objectiveId: completedId || undefined
      };
      setTranscripts(current => appendToTranscript(current, key, aiMsg));
      for (const feedback of getJudgeFeedback(data)) {
        setTranscripts(current => appendToTranscript(current, key, {
          id: nextIdRef.current++, type: 'system', plain: true, content: feedback.content,
          timestamp: new Date(), judgeVerdict: feedback.verdict,
          objectiveId, evaluationId: feedback.evaluationId, canRetry: feedback.canRetry,
        }));
      }

      const practiceProgress = committedObjectives?.interact;
      if (objectiveId === OBJECTIVE_IDS.INTERACT
        && !practiceProgress?.completed
        && Number(practiceProgress?.interactionCount) > 0) {
        setTranscripts(current => appendToTranscript(current, key, {
          id: nextIdRef.current++,
          type: 'system',
          plain: true,
          content: `Practice progress: ${Number(practiceProgress.interactionCount)} of 2 valid responses.`,
          timestamp: new Date(),
        }));
      }

      // Practice progress is graded and committed by the chat endpoint.
      if (objectiveId === OBJECTIVE_IDS.INTERACT && committedObjectives?.interact) {
        if (committedObjectives.interact.completed && !completedInteractRef.current) {
          completedInteractRef.current = true;
          setTranscripts(current => appendToTranscript(current, key, {
            id: nextIdRef.current++,
            type: 'system',
            content: "✅ You've completed the practice! You understand how the AWS Assistant works. Moving to the next challenge...",
            timestamp: new Date()
          }));
          toast.success("✅ Practice complete! Moving to Direct System Prompt Extraction.");
          window.dispatchEvent(new Event('objectiveCompleted'));
          if (activeObjectiveIdRef.current === objectiveId) {
            const generation = navigationGenerationRef.current;
            const timer = setTimeout(() => {
              navigationTimersRef.current.delete(timer);
              if (!ownerIsCurrent() || navigationGenerationRef.current !== generation || activeObjectiveIdRef.current !== objectiveId) return;
              const nextObj = catalogObjectives.find(o => (
                !o.isPractice && dpiVisibilityRef.current.objectives[o.id]?.isVisible
              ));
              if (!nextObj) return;
              setActiveObjectiveId(nextObj.id);
              startObjectiveConversation(nextObj);
              toast.info(`Switched to: ${nextObj.name} — fresh conversation started`);
            }, 2000);
            navigationTimersRef.current.add(timer);
          }
        }
      }

      // Canonical server-confirmed objective completion
      if (completedId) {
        const nextCompleted = committedCompleted || completedObjectives;
        if (activeObjectiveIdRef.current === objectiveId) {
          setLastCompletedObjectiveId(completedId);
        }
        const obj = catalogObjectives.find(o => o.id === completedId);

        // Only promise "moving to the next objective" if one actually remains —
        // otherwise the message lies and the objective looks stuck (completed + active).
        const challengeList = challengeObjectives;
        const hasNextIncomplete = challengeList.some(o => o.id !== completedId && !nextCompleted[o.id]);
        const successMsg = {
          id: nextIdRef.current++,
          type: 'system',
          content: hasNextIncomplete
            ? `🎉 Success! You've completed: ${obj.name}\n\nStarting a fresh conversation for the next objective…`
            : `🎉 Success! You've completed: ${obj.name}\n\nThat was the last remaining objective — great work! Pick any objective on the right to revisit it.`,
          timestamp: new Date()
        };
        setTranscripts(current => appendToTranscript(current, key, successMsg));

        toast.success(`🎯 ${obj ? obj.name : completedId} — Objective completed!`);
        window.dispatchEvent(new Event('objectiveCompleted'));
      }
    } catch (err) {
      if (!isCurrentRequest()) return;
      const status = err.response?.status;
      const body = err.response?.data;
      const errorMsg = body?.error || err.message || 'Request failed';
      const ollamaUrl = body?.ollamaBaseURL || null;
      const hint = body?.hint || '';
      let displayMsg = `Error: ${errorMsg}`;
      if (status === 404) {
        displayMsg += hint ? `\n\n${hint}` : '\n\nThe chat API returned 404. Check that the backend is running.';
      } else if (ollamaUrl) {
        displayMsg += `\n\nServer is trying Ollama at: ${ollamaUrl}. If Ollama runs elsewhere, set OLLAMA_BASE_URL in the server's .env.`;
      }
      // Transport/provider diagnostics are UI state, not assistant turns.
      // Keep the learner's request while excluding fabricated model history on retry.
      const diagnostic = {
        id: nextIdRef.current++,
        type: 'system',
        plain: true,
        content: displayMsg,
        toolActivity: readDpiToolActivity(body?.toolActivity),
        timestamp: new Date()
      };
      setTranscripts(current => appendToTranscript(current, key, diagnostic));
      toast.error(status === 404 ? 'Chat API returned 404.' : errorMsg);
    } finally {
      if (requestsRef.current[objectiveId]?.requestId === requestId) {
        delete requestsRef.current[objectiveId];
        setLoadingObjectives(current => {
          const next = { ...current };
          delete next[objectiveId];
          return next;
        });
      }
    }
  };

  const handleResetConversation = () => {
    if (!modeReady || modeBusyRef.current || !isDpiExerciseUsable(dpiVisibilityRef.current, activeObjectiveId)) return;
    const objective = catalogObjectives.find(candidate => candidate.id === activeObjectiveId);
    cancelCompletionNavigation();
    cancelObjectiveRequest(activeObjectiveId);
    setTranscripts(current => ({
      ...current,
      [transcriptKey(labMode, activeObjectiveId)]: createObjectiveTranscript(objective)
    }));
    completedInteractRef.current = false;
    toast.info('Conversation reset. Your completed objectives are kept.');
  };

  const handleResetProgress = () => {
    if (!modeReady || modeBusyRef.current || !isDpiExerciseUsable(dpiVisibilityRef.current, activeObjectiveId)) return;
    progressReset.requestReset();
  };

  const commitProgressReset = (res) => {
        if (!ownerIsCurrent()) return;
        cancelCompletionNavigation();
        const committedCompleted = completedFromProgress(res.data.progress || res.data);
        const firstObjectiveId = reconcileDpiActiveObjective(
          dpiVisibilityRef.current,
          null,
          OBJECTIVE_ID_ORDER
        );
        const firstObjective = catalogObjectives.find(candidate => candidate.id === firstObjectiveId);
        setCompletedObjectives(committedCompleted);
        completedInteractRef.current = false;
        setActiveObjectiveId(firstObjectiveId);
        const currentMode = modeStateRef.current?.ownerToken === platformToken
          ? modeStateRef.current.mode : null;
        setTranscripts(firstObjective && currentMode ? {
          [transcriptKey(currentMode, firstObjectiveId)]: createObjectiveTranscript(firstObjective)
        } : {});
        setInputMessage('');
        closeHelp();
        toast.success('Progress reset. Starting from the beginning.');
  };

  const progressReset = useWorkshopResetController({
    owner: {
      attendeeId: `platform-session-${resetIdentityRef.current.generation}`,
      workshopKey: directPromptInjectionExperience.workshopKey,
      scenarioId: directPromptInjectionExperience.scenarios[0].id,
    },
    title: 'Reset Direct Prompt Injection progress?',
    description: 'This clears this exercise’s objective progress and conversations. Workshop time and other exercises are preserved.',
    onBegin: () => {
      cancelCompletionNavigation();
      Object.keys(requestsRef.current).forEach(cancelObjectiveRequest);
    },
    mutation: () => axios.post('/api/workshop/prompt-injection/progress/reset'),
    onCommit: commitProgressReset,
    onError: (err) => {
      if (!ownerIsCurrent()) return;
      const msg = err.response?.status === 403
        ? (err.response?.data?.error || 'Only the account owner or an admin can reset progress.')
        : 'Failed to reset progress.';
      toast.error(msg);
      return msg;
    },
  });

  const changeMode = async (nextMode) => {
    if (!modeReady || modeBusyRef.current || progressReset.resetting
      || Object.keys(requestsRef.current).length > 0
      || nextMode === labMode || !modeState.selectableModes.includes(nextMode)) return;
    const ticket = ++modeTicketRef.current;
    modeControllerRef.current?.abort?.();
    modeBusyRef.current = true;
    modeEpochRef.current += 1;
    retireCompletionNavigation();
    setModePending(true);
    let needsRefresh = false;
    try {
      const response = await axios.post(MODE_ENDPOINT, { mode: nextMode });
      if (!ownerIsCurrent() || ticket !== modeTicketRef.current) return;
      if (readMode(response.data).mode !== nextMode) throw new Error('Mode was not committed');
      applyMode(response.data);
      toast.info(`Switched to ${nextMode === 'fixed' ? 'Fixed' : 'Vulnerable'} mode.`);
    } catch {
      if (!ownerIsCurrent() || ticket !== modeTicketRef.current) return;
      modeStateRef.current = null;
      setModeState(null);
      setModeError(true);
      toast.error('Could not change workshop mode. Checking the current setting.');
      needsRefresh = true;
    } finally {
      if (ownerIsCurrent() && ticket === modeTicketRef.current) {
        modeBusyRef.current = false;
        setModePending(false);
      }
    }
    if (needsRefresh && ownerIsCurrent()) await refreshMode();
  };

  const handleOpenHelp = async (kind, objectiveId) => {
    const gate = dpiVisibilityRef.current.objectives[objectiveId];
    const contentVisible = kind === 'hint' ? gate?.hintVisible : gate?.solutionVisible;
    if (!dpiVisibilityRef.current.isVisible || !gate?.isVisible || !contentVisible) return;

    const helpGeneration = progressGuard.begin('help');
    const requestId = ++helpRequestRef.current;
    pendingHelpRef.current = { kind, objectiveId };
    setHelp({ open: true, kind, objectiveId, content: null, status: 'loading', error: '' });
    const endpoint = kind === 'hint'
      ? `/api/hints/direct_prompt_injection/${objectiveId}`
      : `/api/solutions/prompt-injection/${objectiveId}`;
    try {
      const response = await axios.get(endpoint);
      if (helpRequestRef.current !== requestId) return;
      const currentGate = dpiVisibilityRef.current.objectives[objectiveId];
      const stillVisible = kind === 'hint' ? currentGate?.hintVisible : currentGate?.solutionVisible;
      if (!dpiVisibilityRef.current.isVisible || !currentGate?.isVisible || !stillVisible) {
        closeHelp();
        return;
      }
      const content = kind === 'hint'
        ? {
            title: response.data?.hint?.title || 'Hint',
            hints: Array.isArray(response.data?.hint?.hints) ? response.data.hint.hints : []
          }
        : normalizeSolution(response.data?.solution);
      progressGuard.commit('help', helpGeneration, () => {
        pendingHelpRef.current = null;
        setHelp({ open: true, kind, objectiveId, content, status: 'ready', error: '' });
      });
    } catch (error) {
      if (error.code === 'STALE_RECONCILIATION') return;
      if (helpRequestRef.current !== requestId) return;
      if (error.response?.status === 403) {
        closeHelp();
        return;
      }
      progressGuard.commit('help', helpGeneration, () => {
        pendingHelpRef.current = null;
        setHelp(current => ({
          ...current,
          content: null,
          status: error.response?.status === 404 ? 'empty' : 'error',
          error: `Could not load this ${kind}. Try again.`
        }));
      });
    }
  };

  const tryExample = (prompt) => {
    const objectiveId = help.objectiveId;
    const gate = dpiVisibilityRef.current.objectives[objectiveId];
    if (!dpiVisibilityRef.current.isVisible || !gate?.isVisible || !gate?.solutionVisible) {
      closeHelp();
      return;
    }
    ensureTranscript(objectiveId);
    setActiveObjectiveId(objectiveId);
    setInputMessage(prompt);
    closeHelp();
    toast.info('Example copied to input. Switch to the challenge and send it.');
  };

  const handleKeyPress = (e) => {
    if (e.key === 'Enter' && !e.shiftKey && !e.nativeEvent?.isComposing) {
      e.preventDefault();
      handleSubmit(e);
    }
  };

  const activeObj = catalogObjectives.find(o => o.id === activeObjectiveId);

  const techniques = challengeObjectives.map((obj) => ({
    objectiveId: obj.id,
    title: obj.name,
    description: obj.description,
    hintVisible: dpiVisibility.objectives[obj.id]?.hintVisible === true,
  }));

  return (
    <VulnerabilityTemplate challengeId="direct_prompt_injection" icon={FiShield} hideSidePanel={true}>
      <SingleScenarioWorkshop definition={directPromptInjectionExperience}>
        <IntroSection>
          <h3><FiMessageSquare /> Prompt Injection Workshop — Live AI</h3>
          <p>
            This workshop uses the <strong>configured AI provider</strong> as an <strong>AWS Assistant</strong>,
            a JSON formatter, or a synthetic ticket classifier, depending on the selected objective.
            After practice, explore <strong>{challengeObjectives.length} prompt injection lesson{challengeObjectives.length === 1 ? '' : 's'}</strong> involving output formatting, ticket classification, protected instructions,
            deliberately weakened AWS-only policies, and decoded tool output promoted into instructions.
            Each objective selects its own application policy. Following a built-in exception demonstrates that
            policy weakness; it does not prove the model disobeyed its governing instructions.
          </p>
          <div className="scenario">
            <strong>Practice Mode:</strong> Get two valid AWS answers to complete practice. Then,
            <strong> click on a specific challenge</strong> from the objectives list to target a specific vulnerability. 
            Start with Output format, which requires a JSON response, or Ticket classification, which requires REVIEW for a synthetic duplicate-charge ticket. Try to redirect the actual model response, then inspect the Judge result.
            Several objectives deliberately weaken the AWS-only policy. In obfuscation, the model can select a decoder tool; vulnerable mode deliberately promotes the decoded output above the AWS-only restriction.
            The configured model answers first. The server records that response, and a separate Judge checks whether it demonstrates the selected objective. A refusal or unrelated answer earns no credit.
          </div>
          {llmStatus.available ? (
            <p style={{ marginTop: '1rem', color: '#28a745', fontWeight: 600, display: 'flex', flexDirection: 'column', gap: '0.25rem' }}>
              <span style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <FiCheckCircle /> {llmStatus.providerName || 'AI'} actor available
                {llmStatus.model && <> — model: <strong>{llmStatus.model}</strong></>}
                {llmStatus.ollamaVersion && <> (Ollama {llmStatus.ollamaVersion})</>}
              </span>
              <span style={{ fontSize: '0.85rem', fontWeight: 'normal', opacity: 0.9 }}>
                Actor availability does not confirm Judge readiness. Objective credit requires a successful Judge assessment of a genuine model response.
              </span>
              {llmStatus.availableModels?.length > 0 && (
                <span style={{ fontSize: '0.85rem', fontWeight: 'normal', opacity: 0.9 }}>
                  Available models: {llmStatus.availableModels.slice(0, 6).join(', ')}{llmStatus.availableModels.length > 6 ? '…' : ''}
                </span>
              )}
            </p>
          ) : (
            <p style={{ marginTop: '1rem', color: '#dc3545', fontWeight: 600, display: 'flex', flexDirection: 'column', gap: '0.25rem' }}>
              <span style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <FiAlertTriangle /> {llmStatus.providerName || 'AI'} unavailable
              </span>
              <span style={{ fontSize: '0.9rem', fontWeight: 'normal' }}>
                {llmStatus.message || 'AI provider is not reachable. Please check server configuration.'}
              </span>
              {llmStatus.ollamaBaseURL && (
                <span style={{ fontSize: '0.85rem', fontWeight: 'normal', opacity: 0.9 }}>
                  Server is trying: {llmStatus.ollamaBaseURL}. If Ollama runs elsewhere, set OLLAMA_BASE_URL in the server .env and restart.
                </span>
              )}
            </p>
          )}
        </IntroSection>

        {/* Side-by-side: Chat (left) | Exercise Objectives + Progress (right) */}
        <TwoColumnLayout>
          <ChatSection>
            <ChatHeader>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                {llmStatus.available && <StatusIndicator />}
                <h3>
                  <FiCode /> Prompt Injection Workshop — {llmStatus.providerName || 'AI Model'}
                </h3>
                <span data-testid="dpi-active-objective" style={{ fontSize: '0.85rem', opacity: 0.95 }}>
                  Exercise: {activeObj?.name}
                </span>
              </div>
              <Button variant="secondary" onClick={handleResetConversation} disabled={!modeReady || modePending || !exerciseUsable} style={{ padding: '0.5rem 1rem', fontSize: '0.85rem', background: 'rgba(255,255,255,0.2)', color: 'white', border: '1px solid rgba(255,255,255,0.5)' }}>
                Reset conversation
              </Button>
            </ChatHeader>
            <div style={{ padding: '0.75rem 1.25rem', borderBottom: '1px solid #e9ecef', background: '#f8f9ff' }}>
              <WorkshopModeControl mode={labMode} allowedModes={modeState?.selectableModes}
                onChange={changeMode} pending={modePending}
                disabled={anySubmitting || progressReset.resetting}
                reason={modeState?.reason} scopeLabel="Prompt injection policy" />
              {!modeReady && (
                <div role="status" style={{ marginTop: '0.5rem', color: '#856404' }}>
                  {modeError ? 'Mode is unavailable. ' : 'Checking your workshop mode…'}
                  {modeError && <button type="button" onClick={() => { void refreshMode(); }}>Retry mode check</button>}
                </div>
              )}
            </div>
            <ChatActivityTabs activity={toolActivity}>
            <ChatContainer>
              {!exerciseUsable && (
                <div role="status" style={{ padding: '1rem 1.25rem', color: '#856404', background: '#fff3cd', borderBottom: '1px solid #ffe69c' }}>
                  This exercise is disabled by your instructor. Chat will be available when an objective is enabled.
                </div>
              )}
              <MessageList ref={messageListRef} data-testid="active-transcript" role="log" aria-live="polite">
                {messages.map(msg => {
                  const messageType = msg.displayType || msg.type;
                  return (
                  <Message
                    key={msg.id}
                    className={messageType}
                    initial={{ opacity: 0, y: 12 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ duration: 0.3 }}
                  >
                    <div
                      className={`message-icon ${
                        messageType === 'user' ? 'user-avatar' :
                        messageType === 'system' ? 'system-avatar' :
                        messageType === 'objective-complete' ? 'success-avatar' : 'ai-avatar'
                      }`}
                    >
                      {messageType === 'user' ? <FiUser /> : messageType === 'system' ? <FiShield /> : messageType === 'objective-complete' ? <FiCheckCircle /> : <FiMessageSquare />}
                    </div>
                    <div className="message-content">
                      <div className="message-header">
                        {messageType === 'user' ? 'You' : messageType === 'system' ? 'Agent' : messageType === 'objective-complete' ? 'Actor response • Objective completed' : 'Actor response'}
                        {' • '}{msg.timestamp.toLocaleTimeString()}
                      </div>
                      {msg.selectedLesson && <div className="message-header" data-testid="dpi-selected-lesson">{describeSelectedLesson(msg.selectedLesson)}</div>}
                      <div className="message-text">
                        <SafeChatBody content={msg.content} plain={msg.plain} />
                      </div>
                      <JudgeRetryButton
                        evaluationId={msg.evaluationId}
                        canRetry={msg.canRetry}
                        onResult={(data, options) => handleJudgeRetryResult(msg.objectiveId || activeObjectiveId, data, options)}
                      />
                      {msg.objectiveId && catalogObjectives.find(o => o.id === msg.objectiveId) && (
                        <div className={`objective-badge${messageType === 'objective-complete' ? ' objective-badge--completed' : ''}`}>
                          {messageType === 'objective-complete' ? <FiCheckCircle aria-label="Completed objective" /> : <FiTarget aria-label="Associated objective" />} Objective: {catalogObjectives.find(o => o.id === msg.objectiveId).name}
                        </div>
                      )}
                    </div>
                  </Message>
                  );
                })}
                {loading && (
                  <Message className="ai">
                    <div className="message-icon ai-avatar"><FiMessageSquare /></div>
                    <div className="message-content">
                      <div className="message-text">Thinking...</div>
                    </div>
                  </Message>
                )}
              </MessageList>
              <InputContainer onSubmit={handleSubmit}>
                <MessageInput
                  aria-label="Message to the AWS assistant"
                  value={inputMessage}
                  onChange={e => setInputMessage(e.target.value)}
                  onKeyDown={handleKeyPress}
                  placeholder={activeObj?.isPractice ? "Ask an AWS question..." : `Try to ${activeObj?.name.toLowerCase()}...`}
                  disabled={loading || !modeReady || modePending || progressReset.resetting || !exerciseUsable}
                />
                <SendButton type="submit" aria-label="Send message" disabled={loading || !modeReady || modePending || progressReset.resetting || !exerciseUsable || !inputMessage.trim()} whileHover={{ scale: 1.05 }} whileTap={{ scale: 0.95 }}>
                  <FiSend />
                </SendButton>
              </InputContainer>
            </ChatContainer>
            </ChatActivityTabs>
          </ChatSection>

          {/* Right column: Exercise Objectives + Progress (same white box style as XSS) */}
          <Panel>
            <SectionTitle style={{ marginBottom: '1rem' }}><FiTarget /> Exercise Objectives</SectionTitle>
            {progressLoading && <div style={{ fontSize: '0.85rem', color: '#666', marginBottom: '0.5rem' }}>Loading progress...</div>}
            <ObjectivesListWrapper>
              <div className="objectives-list">
                {visibleObjectives.map((obj, idx) => (
                  <ObjectiveItem
                    key={obj.id}
                    data-testid={`objective-card-${obj.id}`}
                    $completed={completedObjectives[obj.id]}
                    $active={activeObjectiveId === obj.id}
                    onClick={() => handleObjectiveClick(obj.id)}
                    initial={{ opacity: 0, x: -10 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: idx * 0.05 }}
                    whileHover={{ scale: 1.02 }}
                    whileTap={{ scale: 0.98 }}
                  >
                    {activeObjectiveId === obj.id && <div className="status-badge">ACTIVE</div>}
                    {completedObjectives[obj.id] && !obj.isPractice && <div className="status-badge" style={{ right: activeObjectiveId === obj.id ? '60px' : '0' }}>COMPLETED</div>}
                    {obj.isPractice && !completedObjectives[obj.id] && <div className="status-badge" style={{ background: '#6c757d' }}>PRACTICE</div>}
                    {obj.isPractice && completedObjectives[obj.id] && <div className="status-badge" style={{ right: activeObjectiveId === obj.id ? '60px' : '0', background: '#28a745' }}>DONE</div>}
                    
                    <div className="obj-icon">
                      {completedObjectives[obj.id] ? <FiCheckCircle /> : activeObjectiveId === obj.id ? <FiTarget /> : obj.isPractice ? <FiMessageSquare /> : <FiLock />}
                    </div>
                    <div className="obj-content">
                      <div className="obj-name">
                        {obj.name}
                      </div>
                      <div className="obj-desc">{obj.description}</div>
                      {(dpiVisibility.objectives[obj.id]?.hintVisible
                        || dpiVisibility.objectives[obj.id]?.solutionVisible) && (
                        <ObjectiveHelpActions
                          objectiveId={obj.id}
                          hintVisible={dpiVisibility.objectives[obj.id]?.hintVisible}
                          solutionVisible={dpiVisibility.objectives[obj.id]?.solutionVisible}
                          activeKind={help.open && help.objectiveId === obj.id ? help.kind : undefined}
                          onOpen={handleOpenHelp}
                        />
                      )}
                    </div>
                  </ObjectiveItem>
                ))}
              </div>
            </ObjectivesListWrapper>
            <ProgressBlock>
              <div className="progress-title"><FiZap /> Progress</div>
              <div className="progress-text">{completedCount} of {visibleObjectives.length} objectives completed</div>
              <div className="progress-bar-track">
                <motion.div
                  className="progress-bar-fill"
                  initial={{ width: 0 }}
                  animate={{ width: `${visibleObjectives.length > 0 ? (completedCount / visibleObjectives.length) * 100 : 0}%` }}
                  transition={{ duration: 0.5, ease: 'easeOut' }}
                />
              </div>
              {allComplete && (
                <motion.div
                  className="progress-complete"
                  initial={{ opacity: 0, scale: 0.95 }}
                  animate={{ opacity: 1, scale: 1 }}
                  transition={{ duration: 0.4 }}
                >
                  <FiCheckCircle size={20} /> All objectives completed!
                </motion.div>
              )}
              <div style={{ marginTop: '0.75rem' }}>
                <Button variant="secondary" onClick={handleResetProgress} disabled={!modeReady || modePending || !exerciseUsable || anySubmitting} style={{ padding: '0.5rem 1rem', fontSize: '0.85rem' }}>
                  Reset Progress
                </Button>
              </div>
            </ProgressBlock>
          </Panel>
        </TwoColumnLayout>

        {/* Results & Hints - full width panel */}
        <Panel>
          <PanelHeader>
            <h3><FiTarget /> Results & Hints</h3>
          </PanelHeader>
          {lastCompletedObjectiveId && (
              <motion.div
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                style={{
                  background: 'rgba(40, 167, 69, 0.1)',
                  border: '2px solid #28a745',
                  borderRadius: '12px',
                  padding: '1rem',
                  marginBottom: '1rem',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.5rem',
                  color: '#28a745',
                  fontWeight: 600
                }}
              >
                <FiCheckCircle /> Just completed: {catalogObjectives.find(o => o.id === lastCompletedObjectiveId)?.name}
              </motion.div>
            )}
            <p style={{ color: '#666', fontSize: '0.9rem', marginBottom: '1rem' }}>
              Submit injection attempts in the chat, inspect the model's actual response, and review the Judge feedback. Example payloads demonstrate the lab's deliberately weakened instructions, but the selected model may refuse or answer incorrectly.
            </p>
            <p style={{ color: '#856404', fontSize: '0.85rem', background: 'rgba(255, 193, 7, 0.1)', border: '1px solid #ffc107', borderRadius: '8px', padding: '0.65rem 0.85rem', margin: 0 }}>
              💡 <strong>Stuck?</strong> When your instructor enables hints, a <strong>Hint</strong> button appears under each objective in the list above — click it for progressive, step-by-step guidance for that specific objective.
            </p>
        </Panel>

        {/* Techniques Arsenal - full width */}
        <Panel>
          <SectionTitle><FiTarget /> Injection Techniques Arsenal</SectionTitle>
          <TechniquesPanel>
            {techniques.map((t, index) => (
              <div
                key={t.title}
                data-testid={`arsenal-item-${t.objectiveId}`}
                className="technique-item"
                onClick={() => t.hintVisible && setExpandedTechniques(prev => ({ ...prev, [index]: !prev[index] }))}
              >
                <div className="technique-title">
                  {t.hintVisible && (expandedTechniques[index] ? <FiChevronUp size={18} /> : <FiChevronDown size={18} />)}
                  {t.title}
                </div>
                <div className="technique-desc">{t.description}</div>
                {t.hintVisible && expandedTechniques[index] && (
                    <motion.div
                      initial={{ opacity: 0 }}
                      animate={{ opacity: 1 }}
                      exit={{ opacity: 0 }}
                      style={{ marginTop: '0.5rem', fontStyle: 'italic', color: '#667eea', fontSize: '0.85rem' }}
                    >
                      <button
                        type="button"
                        data-testid={`arsenal-hint-${t.objectiveId}`}
                        style={{ border: 0, padding: 0, background: 'transparent', color: 'inherit', font: 'inherit', fontStyle: 'inherit', textDecoration: 'underline', cursor: 'pointer' }}
                        onClick={(event) => {
                          event.stopPropagation();
                          handleOpenHelp('hint', t.objectiveId);
                        }}
                      >
                        Open the instructor-provided hint
                      </button>
                    </motion.div>
                )}
              </div>
            ))}
          </TechniquesPanel>
        </Panel>

        {help.open && (
          <ObjectiveHelpModal
            kind={help.kind}
            appearance="legacy-light"
            objective={catalogObjectives.find(objective => objective.id === help.objectiveId)}
            content={help.content}
            status={help.status}
            error={help.error}
            onClose={closeHelp}
            onUsePayload={help.kind === 'solution' ? tryExample : undefined}
          />
        )}
        <ResetConfirmation {...progressReset.confirmation} />
      </SingleScenarioWorkshop>
    </VulnerabilityTemplate>
  );
};

export default DirectPromptInjectionChallenge;
