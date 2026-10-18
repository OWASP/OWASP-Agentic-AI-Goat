import React, { useState, useRef, useEffect, useLayoutEffect, useCallback, useMemo } from 'react';
import axios from 'axios';
import styled, { keyframes } from 'styled-components';
import { motion, AnimatePresence } from 'framer-motion';
import {
  FiSend, FiRefreshCw,
  FiZap, FiCheckCircle, FiLock, FiUnlock, FiEye, FiShield, FiDatabase,
  FiTarget, FiMessageSquare, FiUser
} from 'react-icons/fi';
import { toast } from 'react-toastify';
import VulnerabilityTemplate from '../../components/VulnerabilityTemplate';
import useWorkshopHeartbeat from '../../hooks/useWorkshopHeartbeat';
import useChangePolling from '../../hooks/useChangePolling';
import useReconciliationGuard, { useGuardedSetter } from '../../hooks/useReconciliationGuard';
import { useAuth } from '../../context/AuthContext';
import { useWorkshopConfig } from '../../context/WorkshopConfigContext';
import {
  SingleScenarioWorkshop, WorkshopButton as WorkshopButtonBase,
  WorkshopModeControl, ScopedResetButton, ResetConfirmation, ObjectiveHelpActions, SafeChatBody,
} from '../../components/workshop/WorkshopExperience';
import useWorkshopResetController from '../../components/workshop/useWorkshopResetController';
import { noSqlWorkshopExperience } from '../../components/workshop/experience.mjs';
import HintPanel from '../../components/HintPanel';
import JudgeRetryButton from '../../components/workshop/JudgeRetryButton';
import ObjectiveHelpModal from '../../components/workshop/ObjectiveHelpModal';
import { getJudgeFeedback } from '../../utils/judgeFeedback.mjs';

// ── Animations ──────────────────────────────────────────────────────────────────

const pulse = keyframes`
  0%, 100% { opacity: 1; }
  50% { opacity: 0.4; }
`;

// ── Layout ──────────────────────────────────────────────────────────────────────

const ChallengeContent = styled.div`
  display: flex;
  flex-direction: column;
  gap: 2rem;
`;

const LabModeBadge = styled.div`
  display: flex;
  align-items: center;
  gap: 0.4rem;
  padding: 0.4rem 0.9rem;
  border-radius: 20px;
  font-size: 0.8rem;
  font-weight: 700;
  letter-spacing: 0.03em;
  cursor: pointer;
  ${({ $vuln }) => $vuln
    ? 'background: #fff5f5; color: #c53030; border: 1.5px solid #feb2b2;'
    : 'background: #f0fff4; color: #276749; border: 1.5px solid #9ae6b4;'}
`;

const TwoColumnLayout = styled.div`
  display: grid;
  grid-template-columns: 2fr 1fr;
  gap: 2rem;
  margin-bottom: 2rem;
  align-items: stretch;
  @media (max-width: 1024px) { grid-template-columns: 1fr; }
`;

// ── Chat Section ────────────────────────────────────────────────────────────────

const ChatSection = styled.div`
  background: white;
  border-radius: 16px;
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
  .agent-info { display: flex; align-items: center; gap: 0.75rem; }
  .agent-avatar {
    width: 36px; height: 36px;
    background: rgba(255,255,255,0.2);
    border-radius: 50%;
    display: flex; align-items: center; justify-content: center;
    font-size: 1rem;
  }
  .agent-name { font-weight: 700; font-size: 0.95rem; line-height: 1.2; }
  .agent-sub  { font-size: 0.75rem; opacity: 0.85; }
  .header-right { display: flex; align-items: center; gap: 0.6rem; }
`;

const StatusIndicator = styled.div`
  width: 8px; height: 8px;
  border-radius: 50%;
  background: ${({ $available }) => ($available ? '#4ade80' : '#f87171')};
  box-shadow: ${({ $available }) => ($available ? '0 0 8px #4ade80' : 'none')};
  animation: ${({ $available }) => ($available ? pulse : 'none')} 2s infinite;
  flex-shrink: 0;
`;

const SmallBtn = styled.button`
  background: rgba(255,255,255,0.15);
  border: 1px solid rgba(255,255,255,0.3);
  color: white;
  border-radius: 8px;
  padding: 0.35rem 0.65rem;
  font-size: 0.78rem;
  cursor: pointer;
  display: flex; align-items: center; gap: 0.35rem;
  transition: background 0.2s;
  &:hover { background: rgba(255,255,255,0.25); }
`;

const ChatContainer = styled.div`
  flex: 1; min-height: 0;
  display: flex; flex-direction: column;
  background: #f8f9fa;
`;

const MessageList = styled.div`
  flex: 1; overflow-y: auto; min-height: 0;
  padding: 1.5rem; padding-right: 0.5rem;
  display: flex; flex-direction: column; gap: 0.7rem;
  &::-webkit-scrollbar { width: 8px; }
  &::-webkit-scrollbar-track { background: rgba(0,0,0,0.05); border-radius: 4px; }
  &::-webkit-scrollbar-thumb { background: rgba(102, 126, 234, 0.3); border-radius: 4px; }
`;

const Message = styled(motion.div)`
  display: flex; align-items: flex-start; gap: 0.75rem;
  margin-bottom: 0.25rem;
  ${({ $type }) => $type === 'user' && 'flex-direction: row-reverse;'}
  .avatar {
    width: 36px; height: 36px; border-radius: 50%;
    display: flex; align-items: center; justify-content: center;
    font-size: 1.1rem; flex-shrink: 0;
    ${({ $type }) => $type === 'user'
      ? 'background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white;'
      : $type === 'system'
      ? 'background: linear-gradient(135deg, #f59e0b 0%, #ef4444 100%); color: white;'
      : 'background: linear-gradient(135deg, #06b6d4 0%, #3b82f6 100%); color: white;'}
  }
  .bubble {
    max-width: 85%;
    padding: 0.875rem 1.125rem;
    border-radius: ${({ $type }) => $type === 'user' ? '18px 18px 4px 18px' : '18px 18px 18px 4px'};
    font-size: 0.9rem; line-height: 1.6;
    box-shadow: 0 2px 8px rgba(0, 0, 0, 0.06);
    ${({ $type }) => $type === 'user'
      ? 'background: linear-gradient(135deg, #667eea, #764ba2); color: white; margin-left: auto;'
      : $type === 'system'
      ? 'background: rgba(255, 193, 7, 0.1); border: 1px solid #ffc107; color: #333;'
      : 'background: white; border: 1px solid #e2e8f0; color: #2d3748;'}
    .meta { font-size: 0.75rem; opacity: 0.9; margin-bottom: 0.25rem; display: flex; align-items: center; gap: 0.5rem; }
    p { margin: 0 0 0.5rem; }
    p:last-child { margin-bottom: 0; }
    code { background: rgba(0,0,0,0.08); padding: 0.1rem 0.3rem; border-radius: 3px; font-size: 0.85em; font-family: monospace; }
    pre { background: rgba(0,0,0,0.08); padding: 0.5rem; border-radius: 4px; overflow-x: auto; margin: 0.4rem 0; }
    pre code { background: none; padding: 0; }
    ul, ol { margin: 0.25rem 0 0.5rem 1.25rem; padding: 0; }
    li { margin-bottom: 0.2rem; }
    strong, b { font-weight: 700; }
    /* GFM tables — query results render as real tables (remark-gfm). */
    table { border-collapse: collapse; width: 100%; margin: 0.5rem 0; font-size: 0.82rem; display: block; overflow-x: auto; }
    th, td { border: 1px solid #e2e8f0; padding: 0.35rem 0.55rem; text-align: left; white-space: nowrap; }
    th { background: #f1f5f9; font-weight: 700; }
    tr:nth-child(even) td { background: #f8fafc; }
    h1, h2, h3, h4 { margin: 0.5rem 0 0.35rem; line-height: 1.3; }
    h1 { font-size: 1.1rem; } h2 { font-size: 1.03rem; } h3 { font-size: 0.96rem; } h4 { font-size: 0.9rem; }
    blockquote { margin: 0.4rem 0; padding: 0.25rem 0.75rem; border-left: 3px solid #cbd5e0; color: #4a5568; }
    a { color: #667eea; text-decoration: underline; }
    hr { border: none; border-top: 1px solid #e2e8f0; margin: 0.6rem 0; }
  }
`;

const TypingIndicator = styled.div`
  display: flex; align-items: center; gap: 0.4rem;
  padding: 0.4rem 0; color: #718096; font-size: 0.82rem;
  span {
    display: inline-block; width: 5px; height: 5px;
    background: #667eea; border-radius: 50%;
    animation: ${pulse} 1.2s infinite;
    &:nth-child(2) { animation-delay: 0.2s; }
    &:nth-child(3) { animation-delay: 0.4s; }
  }
`;

const InjectionBanner = styled.div`
  background: linear-gradient(135deg, #fff5f5, #fed7d7);
  border-top: 1px solid #feb2b2;
  padding: 0.5rem 1.1rem;
  font-size: 0.78rem;
  color: #c53030;
  display: flex; align-items: center; gap: 0.4rem;
  flex-shrink: 0;
`;

const InputArea = styled.div`
  border-top: 1px solid #e2e8f0;
  background: white; flex-shrink: 0;
`;

const SuggestionChips = styled.div`
  display: flex; flex-wrap: wrap; gap: 0.4rem;
  padding: 0.6rem 1.1rem 0;
`;

const Chip = styled.button`
  background: ${({ $injection }) => $injection ? '#fff5f5' : 'white'};
  border: 1px solid ${({ $injection }) => $injection ? '#feb2b2' : '#e2e8f0'};
  border-radius: 20px;
  padding: 0.3rem 0.75rem;
  font-size: 0.77rem;
  color: ${({ $injection }) => $injection ? '#c53030' : '#4a5568'};
  cursor: pointer;
  font-family: ${({ $injection }) => $injection ? 'monospace' : 'inherit'};
  white-space: nowrap;
  transition: all 0.2s;
  &:hover {
    border-color: ${({ $injection }) => $injection ? '#fc8181' : '#667eea'};
    color: ${({ $injection }) => $injection ? '#9b2c2c' : '#667eea'};
    background: ${({ $injection }) => $injection ? '#fff0f0' : 'rgba(102, 126, 234, 0.07)'};
  }
`;

const InputContainer = styled.div`
  display: flex; gap: 0.6rem; align-items: flex-end;
  padding: 0.75rem 1.1rem;
`;

const MessageInput = styled.textarea`
  flex: 1;
  padding: 0.7rem 0.9rem;
  border: 2px solid #e2e8f0; border-radius: 12px;
  font-size: 0.88rem; resize: none;
  min-height: 40px; max-height: 100px;
  font-family: inherit;
  transition: border-color 0.2s;
  &:focus { outline: none; border-color: #667eea; box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1); }
`;

const SendButton = styled(WorkshopButtonBase)`
  background: linear-gradient(135deg, #667eea, #764ba2);
  color: white; border: none; border-radius: 12px;
  width: 44px; height: 44px;
  display: flex; align-items: center; justify-content: center;
  cursor: pointer; flex-shrink: 0;
  transition: all 0.3s ease;
  &:hover:not(:disabled) {
    transform: translateY(-2px);
    box-shadow: 0 6px 20px rgba(102, 126, 234, 0.4);
  }
  &:disabled { opacity: 0.5; cursor: not-allowed; }
`;

const WelcomeState = styled.div`
  display: flex; flex-direction: column;
  align-items: center; justify-content: center;
  height: 100%; text-align: center; padding: 2rem; gap: 0.75rem;
  .icon-circle {
    width: 68px; height: 68px;
    background: linear-gradient(135deg, rgba(102, 126, 234, 0.12), rgba(118, 75, 162, 0.15));
    border-radius: 50%;
    display: flex; align-items: center; justify-content: center;
    font-size: 1.7rem;
  }
  h3 { font-size: 1.15rem; font-weight: 700; color: #1a202c; margin: 0; }
  p { color: #718096; font-size: 0.88rem; margin: 0; max-width: 300px; }
`;

// ── Side Panel ──────────────────────────────────────────────────────────────────

const IntroSection = styled.div`
  background: linear-gradient(135deg, rgba(102, 126, 234, 0.1), rgba(118, 75, 162, 0.1));
  border: 2px solid #667eea;
  border-radius: 16px;
  padding: 2rem;
  margin-bottom: 2rem;
  h3 {
    color: #667eea;
    font-size: 1.3rem;
    margin: 0 0 1rem 0;
    display: flex; align-items: center; gap: 0.5rem;
  }
  p { color: #555; line-height: 1.7; margin: 0.5rem 0; }
  .scenario {
    background: rgba(255, 255, 255, 0.8);
    border-left: 4px solid #667eea;
    padding: 1rem;
    margin: 1rem 0 0;
    border-radius: 8px;
    font-size: 0.95rem;
    color: #444;
    strong { color: #667eea; }
    code { background: #f7fafc; padding: 0.1rem 0.3rem; border-radius: 3px; font-size: 0.85rem; }
  }
`;

const Panel = styled.div`
  background: white;
  border: 2px solid #e9ecef;
  border-radius: 16px;
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

const ObjectiveItem = styled(motion.div)`
  position: relative;
  display: flex; align-items: flex-start; gap: 1rem;
  padding: 0.875rem 1.25rem;
  border-radius: 10px;
  border: 1px solid ${({ $completed }) => $completed ? '#22c55e' : '#e2e8f0'};
  background: ${({ $completed }) => $completed ? '#f0fdf4' : '#f8f9fa'};
  margin-bottom: 0.75rem;
  cursor: default;
  transition: all 0.3s ease;
  overflow: hidden;
  &:hover {
    transform: translateY(-2px);
    background: ${({ $completed }) => $completed ? '#dcfce7' : 'rgba(102, 126, 234, 0.08)'};
    box-shadow: 0 4px 12px rgba(0,0,0,0.05);
    border-color: #667eea;
  }
  .status-badge {
    position: absolute; top: 0; right: 0;
    font-size: 0.65rem; font-weight: 800; letter-spacing: 0.05em;
    padding: 0.2rem 0.6rem;
    border-bottom-left-radius: 8px;
    background: ${({ $completed }) => $completed ? '#22c55e' : '#667eea'};
    color: white;
  }
  .obj-icon {
    flex-shrink: 0;
    width: 36px; height: 36px; border-radius: 50%;
    display: flex; align-items: center; justify-content: center;
    font-size: 1.1rem;
    background: ${({ $completed }) => $completed
      ? '#22c55e'
      : '#dee2e6'};
    color: white;
  }
  .obj-content {
    flex: 1; min-width: 0;
    .obj-name { font-size: 0.85rem; font-weight: 600; color: #333; line-height: 1.3; margin-bottom: 0.25rem; display: flex; align-items: center; gap: 0.5rem; }
    .obj-technique { font-size: 0.73rem; color: #666; font-weight: 500; line-height: 1.4; }
  }
`;

const ProgressBlock = styled.div`
  margin-top: 1.5rem;
  padding-top: 1.5rem;
  border-top: 2px solid #e9ecef;
  .progress-title {
    font-size: 1.1rem; font-weight: 600; color: #333;
    margin-bottom: 0.75rem;
    display: flex; align-items: center; gap: 0.5rem;
  }
  .progress-text { font-size: 0.95rem; color: #666; margin-bottom: 0.75rem; }
  .progress-bar-track {
    height: 20px; background: #e9ecef; border-radius: 10px; overflow: hidden;
  }
  .progress-bar-fill {
    height: 100%;
    background: linear-gradient(90deg, #667eea, #764ba2);
    border-radius: 10px;
    transition: width 0.5s ease;
  }
  .progress-complete {
    margin-top: 1rem; padding: 0.75rem 1rem;
    background: linear-gradient(135deg, rgba(40,167,69,0.12), rgba(32,201,151,0.12));
    border: 2px solid #28a745; border-radius: 10px;
    color: #28a745; font-weight: 700; font-size: 0.95rem;
    text-align: center;
    display: flex; align-items: center; justify-content: center; gap: 0.5rem;
  }
`;

const ResetBtn = styled(motion.button)`
  background: linear-gradient(135deg, #6c757d, #495057);
  color: white;
  border: none;
  padding: 0.5rem 1rem;
  border-radius: 8px;
  font-weight: 600;
  font-size: 0.85rem;
  cursor: pointer;
  display: inline-flex; align-items: center; gap: 0.5rem;
  &:hover:not(:disabled) {
    transform: translateY(-2px);
    box-shadow: 0 4px 12px rgba(108, 117, 125, 0.3);
  }
`;

// ── Constants ──────────────────────────────────────────────────────────────────

const OBJECTIVES = [
  { id: 'nosqli_1',  num: 1,  name: 'Trigger NoSQL Error',                technique: 'Error-Based' },
  { id: 'nosqli_2',  num: 2,  name: 'Boolean Operator Bypass ($gt)',       technique: 'Boolean' },
  { id: 'nosqli_3',  num: 3,  name: 'Regex Wildcard Injection ($regex)',   technique: 'Regex' },
  { id: 'nosqli_4',  num: 4,  name: 'Database Version Extraction',          technique: '$where / Recon' },
  { id: 'nosqli_5',  num: 5,  name: 'Collection Schema Extraction',        technique: '$where / Schema' },
  { id: 'nosqli_6',  num: 6,  name: 'Not-Equal Operator Bypass ($ne)',     technique: '$ne' },
  { id: 'nosqli_7',  num: 7,  name: 'Where Clause Injection ($where)',     technique: '$where' },
  { id: 'nosqli_8',  num: 8,  name: 'Array Query Injection ($in)',         technique: '$in' },
  { id: 'nosqli_9',  num: 9,  name: 'Extract Author Contact Data',         technique: 'Exfiltration' },
  { id: 'nosqli_10', num: 10, name: 'Extract Restricted Research Data',    technique: 'Access Bypass' },
];


const NORMAL_CHIPS = [
  { label: 'Show trending topics', payload: 'Show trending topics' },
  { label: 'Search ML papers',     payload: 'Search machine learning papers' },
  { label: 'View reading list',    payload: 'View my reading list' },
];

const LS_KEY_COMPLETED = 'nosqli_workshop_completed';
const OBJECTIVE_IDS = new Set(OBJECTIVES.map(({ id }) => id));
const EMPTY_COMPLETED_OBJECTIVES = new Set();
const EMPTY_CHAT_MESSAGES = [];
const JUDGMENT_FEEDBACK_VERDICTS = new Set(['fail', 'inconclusive', 'unavailable']);
const validObjectiveIds = (ids) => new Set(
  (Array.isArray(ids) ? ids : []).filter(id => typeof id === 'string' && OBJECTIVE_IDS.has(id)),
);
const writeCompletedCache = (cacheKey, objectives) => {
  if (!cacheKey) return;
  try {
    localStorage.setItem(cacheKey, JSON.stringify([...objectives]));
  } catch (_) {}
};
const removeCompletedCache = (cacheKey) => {
  if (!cacheKey) return;
  try {
    localStorage.removeItem(cacheKey);
  } catch (_) {}
};

// ── Component ──────────────────────────────────────────────────────────────────

export default function NoSQLWorkshop({ embedded = false }) {
  const { user } = useAuth();
  const { snapshot, revision } = useWorkshopConfig();
  const nosqlExercise = snapshot?.exercises?.nosql_injection_workshop;
  const visibleObjectives = useMemo(() => (
    nosqlExercise?.isVisible === true
      ? OBJECTIVES.filter(objective => nosqlExercise.objectives?.[objective.id]?.isVisible === true)
        .map(objective => {
          const configured = nosqlExercise.objectives[objective.id];
          return { ...objective, name: configured.label || objective.name,
            description: configured.description?.trim() || objective.technique };
        })
      : []
  ), [nosqlExercise]);
  const visibleObjectiveIds = useMemo(
    () => new Set(visibleObjectives.map(objective => objective.id)),
    [visibleObjectives],
  );
  const completedCacheKey = user?.id == null
    ? null
    : `${LS_KEY_COMPLETED}:user:${encodeURIComponent(String(user.id))}`;
  const sessionToken = localStorage.getItem('token');
  const identityRef = useRef({ cacheKey: completedCacheKey, sessionToken, generation: 0 });
  if (identityRef.current.cacheKey !== completedCacheKey || identityRef.current.sessionToken !== sessionToken) {
    identityRef.current = {
      cacheKey: completedCacheKey,
      sessionToken,
      generation: identityRef.current.generation + 1,
    };
  }
  const identityGeneration = identityRef.current.generation;
  const isCurrentIdentity = useCallback(
    generation => identityRef.current.generation === generation && identityRef.current.sessionToken === localStorage.getItem('token'),
    [],
  );
  const [messagesState, setMessagesState] = useState(() => ({
    identityGeneration,
    messages: EMPTY_CHAT_MESSAGES,
  }));
  const messages = messagesState.identityGeneration === identityGeneration
    ? messagesState.messages
    : EMPTY_CHAT_MESSAGES;
  const setMessages = useCallback(value => {
    setMessagesState(current => {
      const ownedMessages = current.identityGeneration === identityGeneration
        ? current.messages
        : EMPTY_CHAT_MESSAGES;
      return {
        identityGeneration,
        messages: typeof value === 'function' ? value(ownedMessages) : value,
      };
    });
  }, [identityGeneration]);
  const [inputState, setInputState] = useState(() => ({
    identityGeneration,
    value: '',
  }));
  const inputMessage = inputState.identityGeneration === identityGeneration
    ? inputState.value
    : '';
  const setInputMessage = useCallback(value => {
    setInputState({ identityGeneration, value });
  }, [identityGeneration]);
  const [loading, setLoading]                   = useState(false);
  const chatLifecycle = useRef({ generation: 0, controller: null, mounted: true, resetting: false });
  const retireChat = useCallback(() => {
    const current = chatLifecycle.current;
    current.generation += 1;
    current.controller?.abort();
    current.controller = null;
    current.resetting = false;
    return current.generation;
  }, []);
  useEffect(() => {
    chatLifecycle.current.mounted = true;
    setLoading(false);
    return () => { chatLifecycle.current.mounted = false; retireChat(); };
  }, [identityGeneration, retireChat]);
  const [llmStatus, setLlmStatus]               = useState({ available: false, model: '' });
  const [labMode, setLabMode]                   = useState('fixed');
  const [modePending, setModePending]           = useState(false);
  const progressGuard = useReconciliationGuard();
  const [completedState, setCompletedState] = useState(() => ({
    ownerKey: completedCacheKey,
    identityGeneration,
    objectives: EMPTY_COMPLETED_OBJECTIVES,
  }));
  const completedObjectives = completedState.ownerKey === completedCacheKey
    && completedState.identityGeneration === identityGeneration
    ? completedState.objectives
    : EMPTY_COMPLETED_OBJECTIVES;
  const setCompletedFromPoll = useCallback((value) => {
    setCompletedState(current => {
      const ownedObjectives = current.ownerKey === completedCacheKey
        && current.identityGeneration === identityGeneration
        ? current.objectives
        : EMPTY_COMPLETED_OBJECTIVES;
      return {
        ownerKey: completedCacheKey,
        identityGeneration,
        objectives: typeof value === 'function' ? value(ownedObjectives) : value,
      };
    });
  }, [completedCacheKey, identityGeneration]);
  const setCompleted = useGuardedSetter(setCompletedFromPoll, progressGuard);
  const [solutionsEnabled, setSolutionsEnabled] = useState({});
  const [hintState, setHintState] = useState({ identityGeneration, objectives: {} });
  const [hintEpoch, setHintEpoch] = useState(0);
  const [hintResetting, setHintResetting] = useState(false);
  const hintsEnabled = hintState.identityGeneration === identityGeneration ? hintState.objectives : {};

  const [viewingSolutionState, setViewingSolutionState] = useState(() => ({
    identityGeneration,
    solution: null,
  }));
  const viewingSolution = viewingSolutionState.identityGeneration === identityGeneration
    ? viewingSolutionState.solution
    : null;
  const setViewingSolution = useCallback(solution => {
    setViewingSolutionState({ identityGeneration, solution });
  }, [identityGeneration]);
  const pendingSolutionRef = useRef(null);
  const messageListRef = useRef(null);
  const nextIdRef      = useRef(1);
  const nextId = () => nextIdRef.current++;

  useLayoutEffect(() => {
    progressGuard.mark('solutionModal');
    pendingSolutionRef.current = null;
    setViewingSolutionState({ identityGeneration, solution: null });
    setMessagesState({ identityGeneration, messages: EMPTY_CHAT_MESSAGES });
    setInputState({ identityGeneration, value: '' });
    nextIdRef.current = 1;
    setLoading(false);
    setHintResetting(false);
  }, [identityGeneration, progressGuard]);

  useLayoutEffect(() => {
    const disclosureId = viewingSolution?.objectiveId || pendingSolutionRef.current;
    if (disclosureId && !visibleObjectiveIds.has(disclosureId)) {
      pendingSolutionRef.current = null;
      progressGuard.mark('solutionModal');
      setViewingSolution(null);
    }
  }, [progressGuard, revision, setViewingSolution, viewingSolution, visibleObjectiveIds]);

  useEffect(() => {
    if (!user?.id) return undefined;
    const controller = new AbortController();
    const generation = chatLifecycle.current.generation;
    const isCurrent = () => !controller.signal.aborted
      && isCurrentIdentity(identityGeneration) && chatLifecycle.current.mounted
      && chatLifecycle.current.generation === generation;
    axios.get(`/api/workshop/nosql/history/${encodeURIComponent(user.id)}`, { signal: controller.signal })
      .then(({ data }) => {
        if (!isCurrent() || data?.success !== true || !Array.isArray(data.history)) return;
        const restored = data.history.filter(row => ['user', 'assistant'].includes(row?.message_type)
          && typeof row.message === 'string').map(row => ({
          id: nextIdRef.current++, type: row.message_type === 'assistant' ? 'ai' : 'user',
          content: row.message,
        }));
        setMessagesState({ identityGeneration, messages: restored });
      })
      .catch(() => { if (isCurrent()) toast.error('Unable to load saved conversation.'); });
    return () => controller.abort();
  }, [identityGeneration, isCurrentIdentity, user?.id]);

  useWorkshopHeartbeat('nosql_injection_workshop');
  useChangePolling(async (_next, _previous, { signal } = {}) => {
    const requestIdentityGeneration = identityGeneration;
    const modeGeneration = progressGuard.beginRequiredBackground('mode');
    const progressGeneration = progressGuard.begin('progress');
    const gatesGeneration = progressGuard.begin('solutionVisibility');
    const hintGeneration = progressGuard.begin('hintVisibility');
    const solutionDisclosureId = viewingSolution?.objectiveId || pendingSolutionRef.current;
    const modalGeneration = solutionDisclosureId
      ? progressGuard.begin('solutionModal')
      : null;
    const [solutionResponse, hintResponse, progressResponse, modeResponse] = await Promise.all([
      axios.get('/api/solutions/nosql-injection/status', { signal }),
      axios.get('/api/hints/nosql_injection_workshop/status', { signal }),
      axios.get('/api/workshop/nosql/progress', { signal }),
      axios.get('/api/workshop/nosql/mode', { signal }),
    ]);
    const nextSolutions = solutionResponse.data.objectives || {};
    const refreshedSolution = solutionDisclosureId && nextSolutions[solutionDisclosureId]
      ? await axios.get(`/api/solutions/nosql-injection/${solutionDisclosureId}`, { signal })
      : null;
    if (!isCurrentIdentity(requestIdentityGeneration)) return;
    const raw = progressResponse.data?.objectives || {};
    const completed = validObjectiveIds(Object.keys(raw).filter((key) => raw[key]?.completed));
    progressGuard.commit('hintVisibility', hintGeneration, () => {
      setHintState({ identityGeneration, objectives: hintResponse.data.objectives || {} });
      setHintEpoch(value => value + 1);
    });
    progressGuard.commit('solutionVisibility', gatesGeneration, () => {
      setSolutionsEnabled(nextSolutions);
      if (solutionDisclosureId && !nextSolutions[solutionDisclosureId]) {
        pendingSolutionRef.current = null;
        progressGuard.mark('solutionModal');
        setViewingSolution(null);
      }
    });
    progressGuard.commit('progress', progressGeneration, () => {
      setCompletedFromPoll(completed);
      writeCompletedCache(completedCacheKey, completed);
    });
    progressGuard.commit('mode', modeGeneration, () => setLabMode(modeResponse.data.mode || 'fixed'));
    if (modalGeneration !== null && refreshedSolution && nextSolutions[solutionDisclosureId]) {
      progressGuard.commit('solutionModal', modalGeneration, () => {
        pendingSolutionRef.current = null;
        setViewingSolution({ ...refreshedSolution.data.solution, objectiveId: solutionDisclosureId });
      });
    }
  }, ['nosql_injection_workshop']);

  // ── Init ────────────────────────────────────────────────────────────────────

  useEffect(() => {
    const requestIdentityGeneration = identityGeneration;
    const gatesGeneration = progressGuard.begin('solutionVisibility');
    const hintGeneration = progressGuard.begin('hintVisibility');
    const progressGeneration = progressGuard.begin('progress');
    const modeGeneration = progressGuard.begin('mode');
    progressGuard.commit('progress', progressGeneration, () => {
      setCompletedFromPoll(new Set());
    });
    axios.get('/api/workshop/nosql/llm-status')
      .then(r => setLlmStatus({ available: r.data.available, model: r.data.model || 'llama3.1:8b' }))
      .catch(() => setLlmStatus({ available: false, model: 'unavailable' }));

    axios.get('/api/workshop/nosql/mode')
      .then(r => progressGuard.commit('mode', modeGeneration, () => setLabMode(r.data.mode || 'fixed')))
      .catch(() => {});

    axios.get('/api/hints/nosql_injection_workshop/status')
      .then(r => { if (isCurrentIdentity(requestIdentityGeneration)) progressGuard.commit('hintVisibility', hintGeneration, () => setHintState({ identityGeneration, objectives: r.data.objectives || {} })); })
      .catch(() => {});

    axios.get('/api/solutions/nosql-injection/status')
      .then(r => progressGuard.commit('solutionVisibility', gatesGeneration, () => {
        setSolutionsEnabled(r.data.objectives || {});
      }))
      .catch(() => {});

    // Fetch server-side progress (authoritative); use localStorage only if the server is unavailable.
    axios.get('/api/workshop/nosql/progress')
      .then(r => {
        if (!isCurrentIdentity(requestIdentityGeneration)) return;
        const raw = r.data?.objectives || {};
        const ids = validObjectiveIds(Object.keys(raw).filter(k => raw[k]?.completed));
        progressGuard.commit('progress', progressGeneration, () => {
          setCompletedFromPoll(ids);
          writeCompletedCache(completedCacheKey, ids);
        });
      })
      .catch((error) => {
        if (error.code === 'STALE_RECONCILIATION') return;
        if (!isCurrentIdentity(requestIdentityGeneration)) return;
        let cached = new Set();
        try {
          const saved = completedCacheKey && localStorage.getItem(completedCacheKey);
          const parsed = saved ? JSON.parse(saved) : [];
          cached = validObjectiveIds(parsed);
        } catch (_) {}
        progressGuard.commit('progress', progressGeneration, () => {
          setCompletedFromPoll(cached);
        });
      });
  }, [completedCacheKey, identityGeneration, isCurrentIdentity, progressGuard, setCompletedFromPoll]);

  useEffect(() => {
    if (messageListRef.current) {
      messageListRef.current.scrollTop = messageListRef.current.scrollHeight;
    }
  }, [messages, loading]);

  // ── Helpers ─────────────────────────────────────────────────────────────────

  const addMessage = useCallback((type, content, metadata = {}) => {
    setMessages(prev => [...prev, { id: nextId(), type, content, time: new Date().toLocaleTimeString(), ...metadata }]);
  }, [setMessages]);

  const markCompleted = useCallback((ids) => {
    const normalizedIds = [...validObjectiveIds(ids)];
    if (normalizedIds.length === 0) return;
    setCompleted(prev => {
      const next = new Set(prev);
      normalizedIds.forEach(id => next.add(id));
      writeCompletedCache(completedCacheKey, next);
      return next;
    });
    window.dispatchEvent(new Event('objectiveCompleted'));
  }, [completedCacheKey, setCompleted]);

  const refreshAuthoritativeProgress = useCallback(async (isCurrent) => {
    const requestIdentityGeneration = identityGeneration;
    const progressGeneration = progressGuard.begin('progress');
    const response = await axios.get('/api/workshop/nosql/progress');
    if (!isCurrent() || !isCurrentIdentity(requestIdentityGeneration)) return;
    const raw = response.data?.objectives || {};
    const ids = validObjectiveIds(Object.keys(raw).filter(key => raw[key]?.completed));
    progressGuard.commit('progress', progressGeneration, () => {
      setCompletedFromPoll(ids);
      writeCompletedCache(completedCacheKey, ids);
    });
  }, [completedCacheKey, identityGeneration, isCurrentIdentity, progressGuard, setCompletedFromPoll]);

  const retryGeneration = chatLifecycle.current.generation;
  const handleJudgeRetryResult = useCallback(async (data, { signal } = {}) => {
    const isCurrent = () => !signal?.aborted && isCurrentIdentity(identityGeneration)
      && chatLifecycle.current.mounted && !chatLifecycle.current.resetting
      && chatLifecycle.current.generation === retryGeneration;
    if (!isCurrent()) return;
    getJudgeFeedback(data).forEach(feedback => addMessage('system', feedback.content, {
      plain: true, judgmentVerdict: feedback.verdict,
      evaluationId: feedback.evaluationId, canRetry: feedback.canRetry,
    }));
    await refreshAuthoritativeProgress(isCurrent);
    if (!isCurrent()) return;
    if (data.completed === true) toast.success('Objective evaluation passed.');
  }, [addMessage, refreshAuthoritativeProgress, identityGeneration, isCurrentIdentity, retryGeneration]);

  // ── Send Message ─────────────────────────────────────────────────────────────

  const sendMessage = useCallback(async (text) => {
    const requestIdentityGeneration = identityGeneration;
    const msg = (text || inputMessage).trim();
    if (!msg || loading || chatLifecycle.current.resetting || !chatLifecycle.current.mounted) return;
    const generation = retireChat();
    const controller = new AbortController();
    chatLifecycle.current.controller = controller;
    const isCurrent = () => isCurrentIdentity(requestIdentityGeneration)
      && chatLifecycle.current.mounted && chatLifecycle.current.generation === generation
      && chatLifecycle.current.controller === controller && !controller.signal.aborted;
    setInputMessage('');
    addMessage('user', msg);
    setLoading(true);

    try {
      const res = await axios.post('/api/workshop/nosql/chat', { userMessage: msg }, { signal: controller.signal });
      if (!isCurrent()) return;
      const data = res.data;
      if (data.success) {
        addMessage('ai', data.response);
        (Array.isArray(data.judgments) ? data.judgments : []).forEach(judgment => {
          if (!JUDGMENT_FEEDBACK_VERDICTS.has(judgment?.verdict)) return;
          const objective = visibleObjectives.find(item => item.id === judgment.objectiveId);
          const explanation = typeof judgment.explanation === 'string'
            ? judgment.explanation.replace(/\s+/g, ' ').trim().slice(0, 300)
            : '';
          const label = judgment.verdict === 'fail' ? 'not completed'
            : judgment.verdict === 'inconclusive' ? 'needs more evidence'
              : 'evaluation unavailable';
          addMessage('system', `${objective?.name || 'Objective'}: ${label}.${explanation ? ` ${explanation}` : ''}`, {
            plain: true,
            judgmentVerdict: judgment.verdict,
            evaluationId: judgment.evaluationId,
            canRetry: judgment.verdict === 'unavailable' && judgment.canRetry === true,
          });
        });
        if (data.completedObjectives && data.completedObjectives.length > 0) {
          markCompleted(data.completedObjectives);
          data.completedObjectives.forEach(id => {
            const obj = visibleObjectives.find(o => o.id === id);
            if (obj) toast.success(`✓ Objective completed: ${obj.name}`, { autoClose: 3000 });
          });
        }
      } else {
        addMessage('system', data.message || 'Something went wrong.');
      }
    } catch (err) {
      if (!isCurrent()) return;
      addMessage('system', err.response?.data?.message || 'Connection error. Please try again.');
    } finally {
      if (isCurrent()) { chatLifecycle.current.controller = null; setLoading(false); }
    }
  }, [retireChat, identityGeneration, inputMessage, isCurrentIdentity, loading, addMessage, markCompleted, setInputMessage]);

  const handleKeyDown = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendMessage(); }
  };

  // ── Reset ────────────────────────────────────────────────────────────────────

  const resetAttempt = useRef(null);
  const reset = useWorkshopResetController({
    owner: { attendeeId: `${user?.id ?? 'unknown'}:${identityGeneration}`, workshopKey: 'nosql_injection_workshop', scenarioId: 'research-vault' },
    title: 'Reset chat, reading list & progress?',
    description: 'This clears your NoSQL workshop conversation, reading list, and objective progress for this account.',
    onBegin: () => {
      if (!isCurrentIdentity(identityGeneration)) throw new Error('Session changed. Open reset again.');
      const generation = retireChat();
      resetAttempt.current = { identityGeneration, generation };
      chatLifecycle.current.resetting = true;
      setLoading(false);
      setHintEpoch(value => value + 1);
      setHintResetting(true);
    },
    mutation: () => axios.post('/api/workshop/nosql/reset', {}),
    onCommit: () => {
      const attempt = resetAttempt.current;
      if (!attempt || !isCurrentIdentity(attempt.identityGeneration)
        || !chatLifecycle.current.mounted || chatLifecycle.current.generation !== attempt.generation) return;
      setMessages([]);
      setCompleted(new Set());
      removeCompletedCache(completedCacheKey);
      chatLifecycle.current.resetting = false;
      setHintResetting(false);
      toast.success('Conversation, reading list, and progress cleared');
    },
    onError: (error) => {
      const attempt = resetAttempt.current;
      if (attempt && isCurrentIdentity(attempt.identityGeneration)
        && chatLifecycle.current.mounted && chatLifecycle.current.generation === attempt.generation) {
        chatLifecycle.current.resetting = false;
        setHintResetting(false);
        toast.error('Failed to reset');
      }
      return error?.message || 'Failed to reset. Try again.';
    },
  });

  // ── View Solution ────────────────────────────────────────────────────────────

  const handleViewSolution = async (objectiveId) => {
    if (!visibleObjectiveIds.has(objectiveId)) return;
    const requestIdentityGeneration = identityGeneration;
    const modalGeneration = progressGuard.begin('solutionModal');
    pendingSolutionRef.current = objectiveId;
    try {
      const res = await axios.get(`/api/solutions/nosql-injection/${objectiveId}`);
      if (!isCurrentIdentity(requestIdentityGeneration)) return;
      progressGuard.commit('solutionModal', modalGeneration, () => {
        pendingSolutionRef.current = null;
        setViewingSolution({ ...res.data.solution, objectiveId });
      });
    } catch (err) {
      if (!isCurrentIdentity(requestIdentityGeneration)) return;
      if (err.code === 'STALE_RECONCILIATION') return;
      if (err.response?.status === 403) toast.warning('Solutions are disabled by your instructor.');
      else toast.error('Failed to load solution.');
    } finally {
      if (isCurrentIdentity(requestIdentityGeneration)
        && progressGuard.capture('solutionModal') === modalGeneration) {
        pendingSolutionRef.current = null;
      }
    }
  };

  const closeSolution = () => {
    pendingSolutionRef.current = null;
    progressGuard.mark('solutionModal');
    setViewingSolution(null);
  };

  const toggleLabMode = async (newMode = labMode === 'vuln' ? 'fixed' : 'vuln') => {
    if (modePending || !['vuln', 'fixed'].includes(newMode) || newMode === labMode) return;
    const modeGeneration = progressGuard.beginForeground('mode');
    setModePending(true);
    try {
      const response = await axios.post('/api/workshop/nosql/mode', { mode: newMode });
      progressGuard.commit('mode', modeGeneration, () => setLabMode(response.data.mode));
    } catch (err) {
      if (err.code === 'STALE_RECONCILIATION') return;
      console.error('Failed to toggle lab mode', err);
    } finally {
      progressGuard.endForeground('mode', modeGeneration);
      setModePending(false);
    }
  };

  // ── Render ───────────────────────────────────────────────────────────────────

  const completedCount = visibleObjectives.filter(objective => completedObjectives.has(objective.id)).length;
  const totalCount = visibleObjectives.length;
  const isVuln = labMode === 'vuln';

  const avatarContent = (type) => {
    if (type === 'user') return <FiUser />;
    if (type === 'system') return <FiShield />;
    return <FiMessageSquare />;
  };

  const innerContent = (
    <SingleScenarioWorkshop definition={noSqlWorkshopExperience}>
      <IntroSection>
        <h3><FiMessageSquare /> NoSQL Injection Workshop — NOVA ResearchVault</h3>
        <p>
          Practice <strong>MongoDB-style operator injection</strong> against NOVA, ResearchVault's
          AI research library assistant. This lab simulates selected operators over real PostgreSQL
          records. In vulnerable mode, the <code>search_papers</code> tool interprets injected operators
          without enforcing the normal access filter. It does not run MongoDB or execute JavaScript.
        </p>
        <div className="scenario">
          <strong>How to attack:</strong> Inject MongoDB-style operators (<code>$gt</code>,{' '}
          <code>$ne</code>, <code>$regex</code>, <code>$where</code>, <code>$in</code>) to bypass
          access controls and expose synthetic restricted records and database metadata. The chips
          below send normal queries; example attack payloads appear in objective solutions when
          enabled by your instructor. Complete the enabled objectives in vulnerable mode.
        </div>
        <div style={{ marginTop: '1rem', display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          <WorkshopModeControl mode={labMode} allowedModes={['vuln', 'fixed']} onChange={toggleLabMode} pending={modePending} scopeLabel="NoSQL Injection" />
          {llmStatus.available ? (
            <span style={{ color: '#28a745', fontWeight: 600, fontSize: '0.9rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <FiCheckCircle /> LLM ready — {llmStatus.model}
            </span>
          ) : (
            <span style={{ color: '#dc3545', fontWeight: 600, fontSize: '0.9rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <FiShield /> LLM unavailable
            </span>
          )}
        </div>
      </IntroSection>

      <TwoColumnLayout>
        {/* ── Left: Chat ── */}
        <ChatSection>
          <ChatHeader>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
              {llmStatus.available && <StatusIndicator $available={llmStatus.available} />}
              <h3 style={{ margin: 0, fontSize: '1.1rem', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <FiDatabase /> NOVA — ResearchVault Assistant
              </h3>
              <span style={{ fontSize: '0.85rem', opacity: 0.95 }}>
                {isVuln ? 'Vulnerable Mode' : 'Fixed Mode'}
              </span>
            </div>
            <ScopedResetButton label="Reset chat, reading list & progress" onClick={reset.requestReset} disabled={reset.resetting} />
          </ChatHeader>

          {isVuln && (
            <InjectionBanner>
              ⚠ Injection point active — paper search passes user input directly into query operators
            </InjectionBanner>
          )}

          <ChatContainer>
            <MessageList ref={messageListRef}>
              {messages.length === 0 ? (
                <WelcomeState>
                  <div className="icon-circle">🔬</div>
                  <h3>Hello! I'm NOVA</h3>
                  <p>
                    {isVuln
                      ? 'Vulnerable mode is active. Use NoSQL injection operators in the paper search to complete the objectives.'
                      : 'Fixed mode is active. Paper search uses parameterized queries — injection operators will not work.'}
                  </p>
                </WelcomeState>
              ) : (
                <>
                  <AnimatePresence>
                    {messages.map(msg => (
                      <Message key={msg.id} $type={msg.type}
                        data-message-id={msg.id}
                        initial={{ opacity: 0, y: 8 }}
                        animate={{ opacity: 1, y: 0 }}
                        transition={{ duration: 0.2 }}
                      >
                        <div className="avatar">{avatarContent(msg.type)}</div>
                        <div className="bubble">
                          <div className="meta">
                            {msg.type === 'user' ? 'You' : msg.type === 'system' ? 'System' : 'NOVA'} · {msg.time}
                          </div>
                          <div role={msg.plain ? (msg.judgmentVerdict === 'unavailable' ? 'alert' : 'status') : undefined}>
                            <SafeChatBody content={msg.content} plain={msg.plain} />
                          </div>
                          <JudgeRetryButton evaluationId={msg.evaluationId} canRetry={msg.canRetry} onResult={handleJudgeRetryResult} />
                        </div>
                      </Message>
                    ))}
                  </AnimatePresence>
                  {loading && (
                    <TypingIndicator>
                      <span /><span /><span /> NOVA is thinking...
                    </TypingIndicator>
                  )}
                </>
              )}
            </MessageList>

            <InputArea>
              {isVuln && (
                <SuggestionChips>
                  {/* Only benign starter chips here. The working NoSQLi payloads are
                      NOT exposed as one-click chips — they live in the per-objective
                      Solution panel ("Example Payloads → Try this payload"), gated by
                      the admin Solutions toggle, matching DPI/XSS/other exercises. */}
                  {NORMAL_CHIPS.map(c => (
                    <Chip key={c.label} onClick={() => sendMessage(c.payload)}>{c.label}</Chip>
                  ))}
                </SuggestionChips>
              )}
              {!isVuln && (
                <SuggestionChips>
                  {[...NORMAL_CHIPS, { label: 'Papers on AI safety', payload: 'Papers on AI safety' }].map(c => (
                    <Chip key={c.label} onClick={() => sendMessage(c.payload)}>{c.label}</Chip>
                  ))}
                </SuggestionChips>
              )}
              <InputContainer>
                <MessageInput
                  value={inputMessage}
                  onChange={e => setInputMessage(e.target.value)}
                  onKeyDown={handleKeyDown}
                  placeholder={isVuln ? 'Enter injection payload or ask NOVA about papers/authors…' : 'Ask NOVA about research papers, authors, or topics…'}
                  rows={1}
                  disabled={loading}
                />
                <SendButton
                  onClick={() => sendMessage()}
                  disabled={loading || !inputMessage.trim()}
                  whileHover={{ scale: 1.05 }}
                  whileTap={{ scale: 0.95 }}
                >
                  <FiSend size={15} />
                </SendButton>
              </InputContainer>
            </InputArea>
          </ChatContainer>
        </ChatSection>

        {/* ── Right: Exercise Objectives + Progress ── */}
        <Panel>
          <h2 style={{ color: '#333', margin: '0 0 1rem 0', fontSize: '1.5rem', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            <FiTarget /> Exercise Objectives
          </h2>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem', marginTop: '0.5rem' }}>
            {visibleObjectives.map((obj, idx) => {
              const done = completedObjectives.has(obj.id);
              return (
                <ObjectiveItem
                  key={obj.id}
                  $completed={done}
                  initial={{ opacity: 0, x: -10 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: idx * 0.05 }}
                  whileHover={{ scale: 1.02 }}
                  whileTap={{ scale: 0.98 }}
                >
                  {done && <div className="status-badge">COMPLETED</div>}
                  <div className="obj-icon">
                    {done ? <FiCheckCircle /> : <FiLock />}
                  </div>
                  <div className="obj-content">
                    <div className="obj-name">{obj.name}</div>
                    <div className="obj-technique">{obj.description}</div>
                    {hintsEnabled[obj.id] && !hintResetting && (
                      <HintPanel
                        key={`${identityGeneration}:${hintEpoch}:${revision}:${obj.id}`}
                        workshopKey="nosql_injection_workshop"
                        objectiveId={obj.id}
                        objective={obj}
                        accentColor="#667eea"
                        revision={revision}
                      />
                    )}
                    <ObjectiveHelpActions objectiveId={obj.id} hintVisible={false}
                      solutionVisible={solutionsEnabled[obj.id] === true}
                      onOpen={(kind, id) => { if (kind === 'solution') handleViewSolution(id); }} />
                  </div>
                </ObjectiveItem>
              );
            })}
          </div>

          <ProgressBlock>
            <div className="progress-title"><FiZap /> Progress</div>
            <div className="progress-text">{completedCount} of {totalCount} objectives completed</div>
            <div className="progress-bar-track">
              <motion.div
                className="progress-bar-fill"
                initial={{ width: 0 }}
                animate={{ width: `${totalCount > 0 ? (completedCount / totalCount) * 100 : 0}%` }}
                transition={{ duration: 0.5, ease: 'easeOut' }}
              />
            </div>
            {completedCount === totalCount && totalCount > 0 && (
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
              <ScopedResetButton label="Reset chat, reading list & progress" onClick={reset.requestReset} disabled={reset.resetting} />
            </div>
          </ProgressBlock>
        </Panel>
      </TwoColumnLayout>

      {viewingSolution && visibleObjectiveIds.has(viewingSolution.objectiveId) && (
        <ObjectiveHelpModal
          key={`${identityGeneration}:${viewingSolution.objectiveId}`}
          kind="solution"
          appearance="legacy-light"
          objective={visibleObjectives.find(objective => objective.id === viewingSolution.objectiveId)}
          content={{
            title: viewingSolution.title,
            explanation: hintsEnabled[viewingSolution.objectiveId] === true
              && Array.isArray(viewingSolution.hints) && viewingSolution.hints.length > 0
              ? `Progressive hints\n${viewingSolution.hints.map((hint, index) => `${index + 1}. ${hint}`).join('\n')}`
              : (viewingSolution.approach || viewingSolution.tips?.length || viewingSolution.examples?.length
                ? '' : viewingSolution.title),
            approach: viewingSolution.approach,
            tips: viewingSolution.tips,
            examples: (Array.isArray(viewingSolution.examples) ? viewingSolution.examples : []).map((example, index) => (
              typeof example === 'string'
                ? { title: `Example ${index + 1}`, payload: example }
                : {
                    title: example.title || `Example ${index + 1}`,
                    payload: example.payload || example.prompt || '',
                    explanation: example.explanation || example.note || '',
                  }
            )),
          }}
          onUsePayload={payload => {
            const objectiveId = viewingSolution.objectiveId;
            if (!isCurrentIdentity(identityGeneration) || !visibleObjectiveIds.has(objectiveId)
              || solutionsEnabled[objectiveId] !== true) { closeSolution(); return; }
            setInputMessage(payload);
            closeSolution();
          }}
          onClose={closeSolution}
        />
      )}
      <ResetConfirmation {...reset.confirmation} />
    </SingleScenarioWorkshop>
  );

  if (embedded) {
    return (
      <div style={{ padding: '1rem' }}>
        {innerContent}
      </div>
    );
  }

  return (
    <VulnerabilityTemplate challengeId="nosql_injection_workshop" icon={FiDatabase} hideSidePanel={true}>
      {innerContent}
    </VulnerabilityTemplate>
  );
}
