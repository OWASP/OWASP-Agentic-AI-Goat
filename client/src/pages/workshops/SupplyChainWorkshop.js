import React, { useState, useEffect, useRef, useMemo } from 'react';
import styled from 'styled-components';
import {
  FiSend, FiShield, FiAlertTriangle, FiTarget, FiActivity,
  FiCheckCircle, FiUnlock, FiMessageSquare, FiPackage,
  FiZap, FiRefreshCw, FiChevronDown, FiChevronUp, FiTerminal,
  FiSearch, FiLock
} from 'react-icons/fi';
import { toast } from 'react-toastify';
import { getJudgeFeedback } from '../../utils/judgeFeedback.mjs';
import JudgeRetryButton from '../../components/workshop/JudgeRetryButton';
import { motion, AnimatePresence } from 'framer-motion';
import axios from 'axios';
import ReactMarkdown from 'react-markdown';
import VulnerabilityTemplate from '../../components/VulnerabilityTemplate';
import HintPanel from '../../components/HintPanel';
import ObjectiveHelpModal from '../../components/workshop/ObjectiveHelpModal';
import { SingleScenarioWorkshop, WorkshopButton as WorkshopButtonBase, WorkshopModeControl, ScopedResetButton, ObjectiveHelpActions, ResetConfirmation } from '../../components/workshop/WorkshopExperience';
import { supplyChainWorkshopExperience } from '../../components/workshop/experience.mjs';
import useWorkshopHeartbeat from '../../hooks/useWorkshopHeartbeat';
import useChangePolling from '../../hooks/useChangePolling';
import useReconciliationGuard, { useGuardedSetter } from '../../hooks/useReconciliationGuard';
import { useWorkshopConfig } from '../../context/WorkshopConfigContext';

const SC_API = '/api/workshop/supply-chain';

function createIdempotencyKey() {
  if (typeof globalThis.crypto?.randomUUID === 'function') {
    return globalThis.crypto.randomUUID();
  }
  const bytes = new Uint8Array(16);
  globalThis.crypto.getRandomValues(bytes);
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = [...bytes].map(byte => byte.toString(16).padStart(2, '0')).join('');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

// ── Styled components (matching DPI exactly) ───────────────────────────────

const ChallengeContent = styled.div`
  display: flex;
  flex-direction: column;
  gap: 2rem;
`;

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
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }
  p {
    color: #555;
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
  .llm-status {
    display: inline-flex;
    align-items: center;
    gap: 0.5rem;
    font-size: 0.85rem;
    color: #666;
    margin-top: 0.5rem;
    padding: 0.4rem 0.75rem;
    background: rgba(255,255,255,0.7);
    border-radius: 20px;
    border: 1px solid #e2e8f0;
  }
`;

const StatusDot = styled.span`
  display: inline-block;
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background: ${p => p.ok ? '#4ade80' : '#f87171'};
  box-shadow: 0 0 8px ${p => p.ok ? '#4ade80' : '#f87171'};
  @keyframes pulse {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.5; }
  }
  animation: pulse 2s infinite;
`;

const TwoColumnLayout = styled.div`
  display: grid;
  grid-template-columns: 2fr 1fr;
  gap: 2rem;
  margin-bottom: 2rem;
  align-items: stretch;
  @media (max-width: 1024px) {
    grid-template-columns: 1fr;
  }
`;

const Panel = styled.div`
  background: white;
  border: 2px solid #e9ecef;
  border-radius: 16px;
  padding: 2rem;
  box-shadow: 0 4px 20px rgba(0,0,0,0.08);
  display: flex;
  flex-direction: column;
  min-height: 560px;
  &.highlight {
    border-color: #667eea;
    box-shadow: 0 4px 20px rgba(102,126,234,0.15);
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
    color: #333;
    font-size: 1.2rem;
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }
`;

const ChatSection = styled.div`
  background: white;
  border-radius: 16px;
  box-shadow: 0 4px 20px rgba(0,0,0,0.08);
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
  h3 {
    margin: 0;
    font-size: 1.1rem;
    font-weight: 600;
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }
`;

const HeaderStatus = styled.div`
  display: flex;
  align-items: center;
  gap: 0.5rem;
  font-size: 0.8rem;
  opacity: 0.9;
`;

const StatusIndicator = styled.div`
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background: #4ade80;
  box-shadow: 0 0 8px #4ade80;
  @keyframes pulse {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.5; }
  }
  animation: pulse 2s infinite;
`;

const ModeToggle = styled.button`
  background: rgba(255,255,255,0.2);
  color: white;
  border: 1px solid rgba(255,255,255,0.4);
  border-radius: 20px;
  padding: 0.3rem 0.85rem;
  font-size: 0.78rem;
  font-weight: 700;
  cursor: pointer;
  transition: all 0.2s;
  &:hover { background: rgba(255,255,255,0.3); }
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
  &::-webkit-scrollbar-thumb { background: rgba(102,126,234,0.3); border-radius: 4px; }
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
      box-shadow: 0 2px 8px rgba(0,0,0,0.06);
    }
  }
  &.ai .message-content {
    background: white;
    border: 1px solid #e2e8f0;
    border-radius: 18px 18px 18px 4px;
    box-shadow: 0 2px 8px rgba(0,0,0,0.06);
  }
  &.system .message-content {
    background: rgba(255,193,7,0.1);
    border: 1px solid #ffc107;
    color: #333;
    border-radius: 12px;
  }
  &.objective-complete .message-content {
    background: rgba(40,167,69,0.1);
    border: 1px solid #28a745;
    border-radius: 12px;
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
    background: linear-gradient(135deg, #667eea, #764ba2);
    color: white;
  }
  .message-icon.ai-avatar {
    background: linear-gradient(135deg, #06b6d4, #3b82f6);
    color: white;
  }
  .message-icon.system-avatar {
    background: linear-gradient(135deg, #f59e0b, #ef4444);
    color: white;
  }
  .message-icon.success-avatar {
    background: linear-gradient(135deg, #22c55e, #16a34a);
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
    table { border-collapse: collapse; width: 100%; margin: 0.5rem 0; font-size: 0.85em; }
    th, td { border: 1px solid #e2e8f0; padding: 0.4rem 0.6rem; text-align: left; }
    th { background: rgba(102,126,234,0.08); font-weight: 700; }
  }
  .objective-badge {
    display: inline-flex;
    align-items: center;
    gap: 0.25rem;
    font-size: 0.7rem;
    font-weight: 700;
    color: #28a745;
    background: rgba(40,167,69,0.2);
    padding: 0.2rem 0.5rem;
    border-radius: 6px;
    margin-top: 0.5rem;
  }
`;

const ToolCallBlock = styled.div`
  margin-top: 0.75rem;
  border: 1px solid ${p =>
    p.security === 'rce_executed' ? '#f97316' :
    p.security === 'blocked' ? '#e3b341' :
    '#e2e8f0'};
  border-radius: 8px;
  overflow: hidden;
  font-size: 0.82rem;
  background: #f8f9fa;
`;

const ToolCallHeader = styled.div`
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0.5rem 0.75rem;
  background: ${p =>
    p.security === 'rce_executed' ? 'rgba(249,115,22,0.08)' :
    p.security === 'blocked' ? 'rgba(227,179,65,0.08)' :
    '#f1f5f9'};
  cursor: pointer;
  user-select: none;
`;

const ToolCallLabel = styled.span`
  display: flex;
  align-items: center;
  gap: 0.4rem;
  font-weight: 600;
  color: ${p =>
    p.security === 'rce_executed' ? '#ea580c' :
    p.security === 'blocked' ? '#b45309' :
    '#475569'};
`;

const SecurityBadge = styled.span`
  font-size: 0.68rem;
  padding: 0.15rem 0.5rem;
  border-radius: 20px;
  font-weight: 800;
  letter-spacing: 0.03em;
  background: ${p =>
    p.security === 'rce_executed' ? 'rgba(249,115,22,0.15)' :
    p.security === 'blocked' ? 'rgba(227,179,65,0.15)' :
    'rgba(34,197,94,0.15)'};
  color: ${p =>
    p.security === 'rce_executed' ? '#ea580c' :
    p.security === 'blocked' ? '#b45309' :
    '#15803d'};
`;

const ToolCallBody = styled.div`
  padding: 0.6rem 0.75rem;
  background: #1e293b;
  color: #94a3b8;
  font-family: 'Courier New', monospace;
  font-size: 0.78rem;
  white-space: pre-wrap;
  word-break: break-all;
  max-height: 220px;
  overflow-y: auto;
`;

const InputContainer = styled.form`
  display: flex;
  flex-direction: column;
  gap: 0.6rem;
  padding: 1.25rem;
  background: white;
  border-top: 1px solid #e2e8f0;
  flex-shrink: 0;
`;

const PayloadButtons = styled.div`
  display: flex;
  gap: 0.5rem;
  flex-wrap: wrap;
`;

const PayloadBtn = styled.button`
  padding: 0.3rem 0.75rem;
  font-size: 0.78rem;
  border-radius: 20px;
  border: 1px solid #e2e8f0;
  background: #f8f9fa;
  color: #667eea;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.2s;
  &:hover {
    background: rgba(102,126,234,0.08);
    border-color: #667eea;
  }
`;

const InputRow = styled.div`
  display: flex;
  gap: 0.75rem;
  align-items: flex-end;
`;

const MessageInput = styled.textarea`
  flex: 1;
  padding: 0.875rem 1.125rem;
  border: 2px solid #e2e8f0;
  border-radius: 12px;
  font-size: 0.95rem;
  font-family: inherit;
  resize: none;
  min-height: 44px;
  max-height: 100px;
  transition: all 0.3s ease;
  &:focus {
    outline: none;
    border-color: #667eea;
    box-shadow: 0 0 0 3px rgba(102,126,234,0.1);
  }
  &::placeholder { color: #6c757d; }
`;

const SendButton = styled(WorkshopButtonBase)`
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
  &:hover:not(:disabled) {
    transform: translateY(-2px);
    box-shadow: 0 6px 20px rgba(102,126,234,0.4);
  }
  &:disabled { opacity: 0.5; cursor: not-allowed; }
`;

const ProgressBlock = styled.div`
  margin-top: 1.5rem;
  padding-top: 1.5rem;
  border-top: 2px solid #e9ecef;
  .progress-title {
    font-size: 1.1rem;
    font-weight: 600;
    color: #333;
    margin-bottom: 0.75rem;
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }
  .progress-text { font-size: 0.95rem; color: #666; margin-bottom: 0.75rem; }
  .progress-bar-track { height: 20px; background: #e9ecef; border-radius: 10px; overflow: hidden; }
  .progress-bar-fill {
    height: 100%;
    background: linear-gradient(90deg, #667eea, #764ba2);
    border-radius: 10px;
    transition: width 0.5s ease;
  }
  .progress-complete {
    margin-top: 1rem;
    padding: 0.75rem 1rem;
    background: linear-gradient(135deg, rgba(40,167,69,0.12), rgba(32,201,151,0.12));
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
  background: ${p => p.$active ? 'rgba(102,126,234,0.08)' : p.$completed ? '#f0fdf4' : '#f8f9fa'};
  border: 1px solid ${p => p.$active ? '#667eea' : p.$completed ? '#22c55e' : '#e2e8f0'};
  border-radius: 10px;
  cursor: pointer;
  transition: all 0.3s ease;
  position: relative;
  overflow: hidden;

  &:hover {
    transform: translateY(-2px);
    box-shadow: 0 4px 12px rgba(0,0,0,0.05);
    border-color: #667eea;
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
    background: ${p => p.$active ? '#667eea' : p.$completed ? '#22c55e' : '#dee2e6'};
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
    background: ${p => p.$active ? '#667eea' : p.$completed ? '#22c55e' : '#dee2e6'};
    color: white;
  }
  .obj-content { flex: 1; }
  .obj-name {
    font-weight: 600;
    color: #333;
    margin-bottom: 0.25rem;
    display: flex;
    align-items: center;
    gap: 0.5rem;
    font-size: 0.9rem;
  }
  .obj-desc { font-size: 0.8rem; color: #666; line-height: 1.4; }
  .obj-category {
    display: inline-block;
    font-size: 0.65rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    padding: 0.15rem 0.45rem;
    border-radius: 20px;
    margin-top: 0.35rem;
    background: ${p => p.category === 'recon' ? 'rgba(59,130,246,0.12)' : p.category === 'exploit' ? 'rgba(249,115,22,0.12)' : 'rgba(34,197,94,0.12)'};
    color: ${p => p.category === 'recon' ? '#2563eb' : p.category === 'exploit' ? '#ea580c' : '#15803d'};
  }
`;

const ThinkingBubble = styled.div`
  display: flex;
  align-items: center;
  gap: 0.75rem;
  margin-bottom: 1rem;

  .dots {
    display: flex;
    gap: 4px;
    background: white;
    border: 1px solid #e2e8f0;
    border-radius: 18px 18px 18px 4px;
    padding: 0.875rem 1.125rem;
    box-shadow: 0 2px 8px rgba(0,0,0,0.06);
    span {
      display: block;
      width: 6px;
      height: 6px;
      background: #667eea;
      border-radius: 50%;
      @keyframes blink { 0%,100%{opacity:1} 50%{opacity:0.2} }
      animation: blink 1.2s infinite;
      &:nth-child(2) { animation-delay: 0.2s; }
      &:nth-child(3) { animation-delay: 0.4s; }
    }
  }
`;

// ── Constants ─────────────────────────────────────────────────────────────

const OBJECTIVES = [
  {
    id: 'tool_list',
    name: 'Enumerate Available Tools',
    description: 'Ask CodeBot to list its tools and capabilities',
    icon: FiTerminal,
    category: 'recon',
  },
  {
    id: 'pkg_discover',
    name: 'Identify Vulnerable Package',
    description: 'Discover that check_dependencies uses pkg-parse@1.2.0 internally',
    icon: FiSearch,
    category: 'recon',
  },
  {
    id: 'clean_request',
    name: 'Send a Clean Manifest',
    description: 'Submit a valid package.json to understand normal tool behavior',
    icon: FiPackage,
    category: 'setup',
  },
  {
    id: 'rce_env',
    name: 'Read .env Secrets via RCE',
    description: 'Exploit eval() in the transform field to exfiltrate /app/config/.env',
    icon: FiUnlock,
    category: 'exploit',
  },
  {
    id: 'rce_ssh',
    name: 'Steal SSH Private Key',
    description: 'Use the same transform exploit to read /app/.ssh/id_rsa',
    icon: FiAlertTriangle,
    category: 'exploit',
  },
  {
    id: 'rce_cmd',
    name: 'Execute Arbitrary JavaScript',
    description: 'Exploit the transform field and return a value from the isolated Node.js runtime',
    icon: FiTerminal,
    category: 'exploit',
  },
];

const OBJ_LABELS = {
  tool_list: 'Enumerate Tools',
  pkg_discover: 'Identify Package',
  clean_request: 'Clean Manifest',
  rce_cmd: 'JavaScript Eval',
  rce_env: 'Read .env',
  rce_ssh: 'Steal SSH Key',
};

// ── Component ─────────────────────────────────────────────────────────────

export default function SupplyChainWorkshop() {
  const { snapshot } = useWorkshopConfig();
  const exerciseConfig = snapshot?.exercises?.supply_chain_rce;
  const visibleObjectives = useMemo(() => (
    exerciseConfig?.isVisible === true
      ? OBJECTIVES.filter(objective => exerciseConfig.objectives?.[objective.id]?.isVisible === true)
        .map(objective => ({ ...objective, name: exerciseConfig.objectives[objective.id].label || objective.name,
          description: exerciseConfig.objectives[objective.id].description ?? objective.description }))
      : []
  ), [exerciseConfig]);
  const visibleObjectiveIds = useMemo(
    () => new Set(visibleObjectives.map(objective => objective.id)),
    [visibleObjectives]
  );
  const [messages, setMessages] = useState([
    {
      id: 1,
      type: 'system',
      content: '**Welcome to the Supply Chain RCE Lab.** CodeBot is an AI dependency checker. Your goal: discover that its `check_dependencies` tool uses the fictional training package `pkg-parse@1.2.0`, whose transform behavior is executed in a disposable lab. Start by asking CodeBot what tools it has.',
      timestamp: new Date(),
    },
  ]);
  const [inputMessage, setInputMessage] = useState('');
  const [loading, setLoading] = useState(false);
  const progressGuard = useReconciliationGuard();
  const [completedObjectives, setCompletedObjectivesFromPoll] = useState({});
  const setCompletedObjectives = useGuardedSetter(setCompletedObjectivesFromPoll, progressGuard);
  const [activeObjectiveId, setActiveObjectiveId] = useState('tool_list');
  const [mode, setMode] = useState('vulnerable');
  const [modePending, setModePending] = useState(false);
  const [llmStatus, setLlmStatus] = useState({ available: null, provider: null, model: null, message: '', ollamaBaseURL: null, ollamaVersion: null, availableModels: [], region: null });
  const [expandedTools, setExpandedTools] = useState({});
  const [solutionVisibility, setSolutionVisibility] = useState({});
  const [hintsEnabled, setHintsEnabled] = useState({});
  const [hintRefreshRevision, setHintRefreshRevision] = useState(0);
  const [viewingSolution, setViewingSolution] = useState(null);
  const pendingSolutionRef = useRef(null);
  const messageListRef = useRef(null);
  const nextIdRef = useRef(2);
  const pendingChatAttemptRef = useRef(null);
  const chatLifecycleRef = useRef(0);
  const resetAttemptRef = useRef(null);
  const resetConfirmationInFlight = useRef(false);
  const resetUiMountedRef = useRef(true);
  const [resetConfirmation, setResetConfirmation] = useState(null);
  const renderChatLifecycle = chatLifecycleRef.current;

  useEffect(() => () => {
    resetUiMountedRef.current = false;
    chatLifecycleRef.current += 1;
    pendingChatAttemptRef.current = null;
    resetAttemptRef.current = null;
  }, []);

  useWorkshopHeartbeat('supply_chain_rce');
  useChangePolling(async (_next, _previous, { signal } = {}) => {
    const modeGeneration = progressGuard.beginRequiredBackground('mode');
    const progressGeneration = progressGuard.begin('progress');
    const solutionGeneration = progressGuard.begin('solutionVisibility');
    const hintGeneration = progressGuard.begin('hintVisibility');
    const solutionDisclosureId = viewingSolution?.id || pendingSolutionRef.current;
    const modalGeneration = solutionDisclosureId
      ? progressGuard.begin('solutionModal')
      : null;
    const [solutionResponse, hintResponse, progressResponse, modeResponse] = await Promise.all([
      axios.get('/api/solutions/supply-chain/status', { signal }),
      axios.get('/api/hints/supply_chain_rce/status', { signal }),
      axios.get(`${SC_API}/progress/current`, { signal }),
      axios.get(`${SC_API}/mode`, { signal }),
    ]);
    const nextSolutions = solutionResponse.data.objectives || {};
    const refreshedSolution = solutionDisclosureId && nextSolutions[solutionDisclosureId]
      ? await axios.get(`/api/solutions/supply-chain/${solutionDisclosureId}`, { signal })
      : null;
    const completed = {};
    (progressResponse.data.progress || []).forEach((entry) => {
      if (entry.status === 'completed') completed[entry.objective_id] = true;
    });
    progressGuard.commit('solutionVisibility', solutionGeneration, () => {
      setSolutionVisibility(nextSolutions);
      if (solutionDisclosureId && !nextSolutions[solutionDisclosureId]) {
        pendingSolutionRef.current = null;
        progressGuard.mark('solutionModal');
        setViewingSolution(null);
      }
    });
    progressGuard.commit('hintVisibility', hintGeneration, () => {
      setHintsEnabled(hintResponse.data.objectives || {});
      setHintRefreshRevision(current => current + 1);
    });
    progressGuard.commit('progress', progressGeneration, () => {
      setCompletedObjectivesFromPoll(completed);
    });
    progressGuard.commit('mode', modeGeneration, () => setMode(modeResponse.data.mode || 'vulnerable'));
    if (modalGeneration !== null && refreshedSolution && nextSolutions[solutionDisclosureId]) {
      progressGuard.commit('solutionModal', modalGeneration, () => {
        pendingSolutionRef.current = null;
        setViewingSolution({ id: solutionDisclosureId, ...refreshedSolution.data.solution });
      });
    }
  }, ['supply_chain_rce']);

  useEffect(() => {
    setActiveObjectiveId(current => (
      current && visibleObjectiveIds.has(current) ? current : (visibleObjectives[0]?.id || null)
    ));
    const disclosureId = viewingSolution?.id || pendingSolutionRef.current;
    if (disclosureId && !visibleObjectiveIds.has(disclosureId)) {
      pendingSolutionRef.current = null;
      progressGuard.mark('solutionModal');
      setViewingSolution(null);
    }
  }, [progressGuard, viewingSolution?.id, visibleObjectiveIds, visibleObjectives]);

  // Init
  useEffect(() => {
    const progressGeneration = progressGuard.begin('progress');
    const solutionGeneration = progressGuard.begin('solutionVisibility');
    const hintGeneration = progressGuard.begin('hintVisibility');
    const modeGeneration = progressGuard.begin('mode');
    axios.post(`${SC_API}/init`, {})
      .then(r => {
        if (r.data.progress) {
          const completed = {};
          r.data.progress.forEach(p => {
            if (p.status === 'completed') completed[p.objective_id] = true;
          });
          progressGuard.commit('progress', progressGeneration, () => {
            setCompletedObjectivesFromPoll(completed);
            // Set active to first incomplete
            const firstIncomplete = visibleObjectives.find(o => !completed[o.id]);
            if (firstIncomplete) setActiveObjectiveId(firstIncomplete.id);
          });
        }
      })
      .catch(() => {});

    axios.get(`${SC_API}/mode`)
      .then(r => progressGuard.commit('mode', modeGeneration, () => setMode(r.data.mode || 'vulnerable')))
      .catch(() => {});

    axios.get(`${SC_API}/llm-status`)
      .then(r => setLlmStatus({
        available: r.data.available ?? null,
        provider: r.data.provider || null,
        model: r.data.model || null,
        message: r.data.message || '',
        ollamaBaseURL: r.data.ollamaBaseURL || null,
        ollamaVersion: r.data.ollamaVersion || null,
        availableModels: Array.isArray(r.data.availableModels) ? r.data.availableModels : [],
        region: r.data.region || null
      }))
      .catch(() => {});

    axios.get('/api/solutions/supply-chain/status')
      .then(r => progressGuard.commit('solutionVisibility', solutionGeneration, () => {
        setSolutionVisibility(r.data.objectives || {});
      }))
      .catch(() => {});

    // Per-objective HINT visibility — a SEPARATE admin toggle from solutions.
    // (Previously the hint toggle just revealed the Solution button, so enabling
    // hints exposed solutions and there were no real hints.)
    axios.get('/api/hints/supply_chain_rce/status')
      .then(r => progressGuard.commit('hintVisibility', hintGeneration, () => {
        setHintsEnabled(r.data.objectives || {});
      }))
      .catch(() => {});
  }, [progressGuard]);

  useEffect(() => {
    const messageList = messageListRef.current;
    if (messageList) {
      requestAnimationFrame(() => {
        messageList.scrollTop = messageList.scrollHeight;
      });
    }
  }, [messages, loading]);

  function addMessage(type, content, extra = {}) {
    const id = nextIdRef.current++;
    setMessages(prev => [...prev, { id, type, content, timestamp: new Date(), ...extra }]);
    return id;
  }

  async function handleJudgeRetryResult(data, { signal } = {}) {
    const lifecycle = renderChatLifecycle;
    const isCurrent = () => chatLifecycleRef.current === lifecycle && !signal?.aborted;
    if (!isCurrent()) return;
    getJudgeFeedback(data).forEach(feedback => addMessage('system', feedback.content, {
      judgeVerdict: feedback.verdict, plain: true,
      evaluationId: feedback.evaluationId, canRetry: feedback.canRetry,
    }));
    const progressGeneration = progressGuard.begin('progress');
    try {
      const response = await axios.get(`${SC_API}/progress/current`, { signal });
      if (!isCurrent()) return;
      if (progressGuard.capture('progress') !== progressGeneration) return;
      const completed = {};
      (response.data.progress || []).forEach(entry => {
        if (entry.status === 'completed') completed[entry.objective_id] = true;
      });
      progressGuard.commit('progress', progressGeneration, () => {
        if (isCurrent()) setCompletedObjectivesFromPoll(completed);
      });
      if (isCurrent() && data.completed === true) toast.success('Objective evaluation passed.');
    } catch {
      if (!isCurrent()) return;
      if (progressGuard.capture('progress') !== progressGeneration) return;
      toast.error('Evaluation finished, but progress could not be refreshed.');
    }
  }

  async function handleSubmit(e) {
    e && e.preventDefault();
    if (!inputMessage.trim() || loading || pendingChatAttemptRef.current?.inFlight || resetAttemptRef.current) return;

    const userMsg = inputMessage.trim();
    const existingAttempt = pendingChatAttemptRef.current;
    const retrying = existingAttempt?.retryable === true && existingAttempt.body.userMessage === userMsg;
    const attempt = retrying ? existingAttempt : {
      idempotencyKey: createIdempotencyKey(),
      body: {
        userMessage: userMsg,
        conversationHistory: messages
          .filter(m => m.type === 'user' || m.type === 'ai')
          .slice(-8)
          .map(m => ({ role: m.type === 'user' ? 'user' : 'assistant', content: m.content })),
      },
      lifecycle: chatLifecycleRef.current,
      retryable: false,
      inFlight: false,
    };
    attempt.inFlight = true;
    pendingChatAttemptRef.current = attempt;
    setInputMessage('');
    if (!retrying) addMessage('user', userMsg);
    setLoading(true);

    try {
      const res = await axios.post(`${SC_API}/chat`, attempt.body, {
        headers: { 'Idempotency-Key': attempt.idempotencyKey },
      });
      if (chatLifecycleRef.current !== attempt.lifecycle || pendingChatAttemptRef.current !== attempt) return;

      const { response, toolCalls = [], newlyCompletedObjectives = [] } = res.data;

      addMessage('ai', response, { toolCalls });
      getJudgeFeedback(res.data).forEach(feedback => addMessage('system', feedback.content, {
        judgeVerdict: feedback.verdict, plain: true,
        evaluationId: feedback.evaluationId, canRetry: feedback.canRetry,
      }));

      // Handle newly completed objectives
      if (newlyCompletedObjectives.length > 0) {
        const updated = { ...completedObjectives };
        newlyCompletedObjectives.forEach(id => { updated[id] = true; });
        setCompletedObjectives(updated);

        newlyCompletedObjectives.forEach(id => {
          const obj = visibleObjectives.find(o => o.id === id);
          addMessage('objective-complete', `✅ Objective completed: **${obj?.name || id}**`, { objectiveId: id });
          toast.success(`🎯 ${obj?.name || id}`, { autoClose: 3500 });
        });

        // Auto-advance active objective
        setTimeout(() => {
          if (chatLifecycleRef.current !== attempt.lifecycle) return;
          const allCompleted = { ...completedObjectives, ...newlyCompletedObjectives.reduce((a,id) => ({...a,[id]:true}),{}) };
          const next = visibleObjectives.find(o => !allCompleted[o.id]);
          if (next) setActiveObjectiveId(next.id);
        }, 1500);
      }
    } catch (err) {
      if (chatLifecycleRef.current !== attempt.lifecycle || pendingChatAttemptRef.current !== attempt) return;
      const msg = err.response?.data?.error || 'Connection error — is the server running?';
      addMessage('system', `⚠️ ${msg}`);
      // A missing response means the server may have applied the request. Preserve
      // the exact body and key so submitting the restored text retries safely.
      if (!err.response || err.response.status >= 500) {
        attempt.retryable = true;
        setInputMessage(attempt.body.userMessage);
      } else {
        pendingChatAttemptRef.current = null;
      }
    } finally {
      if (pendingChatAttemptRef.current === attempt) {
        attempt.inFlight = false;
        if (!attempt.retryable) pendingChatAttemptRef.current = null;
      }
      if (chatLifecycleRef.current === attempt.lifecycle) setLoading(false);
    }
  }

  function handleKeyDown(e) {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSubmit();
    }
  }

  async function handleViewSolution(objId) {
    if (!visibleObjectiveIds.has(objId) || solutionVisibility[objId] !== true) return;
    const modalGeneration = progressGuard.begin('solutionModal');
    const lifecycle = chatLifecycleRef.current;
    pendingSolutionRef.current = objId;
    try {
      const r = await axios.get(`/api/solutions/supply-chain/${objId}`);
      progressGuard.commit('solutionModal', modalGeneration, () => {
        pendingSolutionRef.current = null;
        setViewingSolution({ id: objId, ...r.data.solution });
      });
    } catch (error) {
      if (error.code === 'STALE_RECONCILIATION'
        || progressGuard.capture('solutionModal') !== modalGeneration
        || chatLifecycleRef.current !== lifecycle) return;
      toast.error('Solution not available for this objective.');
    } finally {
      if (progressGuard.capture('solutionModal') === modalGeneration) pendingSolutionRef.current = null;
    }
  }

  function closeSolution() {
    pendingSolutionRef.current = null;
    progressGuard.mark('solutionModal');
    setViewingSolution(null);
  }

  async function handleReset() {
    if (resetAttemptRef.current) return false;
    const resetAttempt = { generation: chatLifecycleRef.current + 1 };
    const interruptedAttempt = pendingChatAttemptRef.current;
    resetAttemptRef.current = resetAttempt;
    chatLifecycleRef.current = resetAttempt.generation;
    pendingChatAttemptRef.current = null;
    setLoading(false);
    try {
      await axios.post(`${SC_API}/progress/reset`, {});
      if (resetAttemptRef.current !== resetAttempt || chatLifecycleRef.current !== resetAttempt.generation) return;
      setCompletedObjectives({});
      setActiveObjectiveId(visibleObjectives[0]?.id || null);
      setInputMessage('');
      setMessages([{
        id: nextIdRef.current++,
        type: 'system',
        content: 'Progress reset. Start by submitting a clean package.json to understand normal tool behavior.',
        timestamp: new Date(),
      }]);
      toast.info('Progress reset.');
      return true;
    } catch (_) {
      if (resetAttemptRef.current !== resetAttempt || chatLifecycleRef.current !== resetAttempt.generation) return;
      toast.error('Reset could not be confirmed. Please try again.');
      if (!interruptedAttempt) return false;
      // The reset did not reach a terminal result. It is still safe to resend the
      // interrupted request because its original idempotency key is retained.
      const recoveredAttempt = {
        ...interruptedAttempt,
        lifecycle: chatLifecycleRef.current,
        inFlight: false,
        retryable: true,
      };
      pendingChatAttemptRef.current = recoveredAttempt;
      setInputMessage(recoveredAttempt.body.userMessage);
      return false;
    } finally {
      if (resetAttemptRef.current === resetAttempt) resetAttemptRef.current = null;
    }
  }

  function requestReset() {
    if (resetAttemptRef.current || resetConfirmationInFlight.current) return;
    setResetConfirmation({ status: 'confirming', error: '' });
  }

  async function confirmReset() {
    if (!resetConfirmation || resetConfirmationInFlight.current) return;
    resetConfirmationInFlight.current = true;
    setResetConfirmation({ status: 'resetting', error: '' });
    let succeeded = false;
    try { succeeded = await handleReset(); }
    finally {
      resetConfirmationInFlight.current = false;
      if (resetUiMountedRef.current) setResetConfirmation(succeeded ? null : { status: 'failed', error: 'Reset could not be confirmed. Retry this reset.' });
    }
  }

  async function toggleMode(selectedMode) {
    const next = selectedMode === 'vuln' ? 'vulnerable' : selectedMode;
    if (!['vulnerable', 'fixed'].includes(next) || next === mode || modePending) return;
    const modeGeneration = progressGuard.beginForeground('mode');
    setModePending(true);
    try {
      const response = await axios.post(`${SC_API}/mode`, { mode: next });
      progressGuard.commit('mode', modeGeneration, () => setMode(response.data.mode));
      addMessage('system', response.data.mode === 'fixed'
        ? '🛡️ **Fixed mode activated.** pkg-parse now validates manifests strictly — transform fields are blocked.'
        : '🔓 **Vulnerable mode activated.** pkg-parse@1.2.0 processes the transform field via eval().'
      );
    } catch (error) {
      if (error.code !== 'STALE_RECONCILIATION') toast.error('Failed to change mode');
    } finally {
      progressGuard.endForeground('mode', modeGeneration);
      setModePending(false);
    }
  }

  function toggleTool(key) {
    setExpandedTools(prev => ({ ...prev, [key]: !prev[key] }));
  }

  const completedCount = visibleObjectives.filter(objective => completedObjectives[objective.id]).length;
  const allComplete = visibleObjectives.length > 0 && completedCount === visibleObjectives.length;
  const progressPercent = visibleObjectives.length ? (completedCount / visibleObjectives.length) * 100 : 0;

  return (
    <VulnerabilityTemplate challengeId="supply_chain_rce" icon={FiPackage} hideSidePanel={true}>
      <SingleScenarioWorkshop definition={supplyChainWorkshopExperience}>
        {/* Intro section */}
        <IntroSection>
          <h3><FiPackage /> Supply Chain RCE Lab</h3>
          <p>
            A real-world attack scenario: <strong>CodeBot</strong> is an AI-powered dependency checker used by your
            development team. This exercise uses <strong>pkg-parse@1.2.0</strong>, a fictional transitive dependency
            created for the curriculum. Its vulnerable transform behavior calls <code>eval()</code> on the
            <code>"transform"</code> field inside a disposable isolated runner, enabling a real lab RCE effect.
          </p>
          <div className="scenario">
            <strong>Your mission:</strong> Enumerate CodeBot's tools, identify the vulnerable package, craft malicious
            package.json payloads, and exfiltrate secrets from the server. Then switch to Fixed mode to see the
            patch in action.
          </div>
          {llmStatus.available === true ? (
            <p style={{ marginTop: '1rem', color: '#28a745', fontWeight: 600, display: 'flex', flexDirection: 'column', gap: '0.25rem' }}>
              <span style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <FiCheckCircle /> AI ready
                {llmStatus.model && <> — model: <strong>{llmStatus.model}</strong></>}
                {llmStatus.ollamaVersion && <> (Ollama {llmStatus.ollamaVersion})</>}
                {llmStatus.region && <> · region: <strong>{llmStatus.region}</strong></>}
              </span>
              {llmStatus.availableModels?.length > 0 && (
                <span style={{ fontSize: '0.85rem', fontWeight: 'normal', opacity: 0.9 }}>
                  Available models: {llmStatus.availableModels.slice(0, 6).join(', ')}{llmStatus.availableModels.length > 6 ? '…' : ''}
                </span>
              )}
            </p>
          ) : llmStatus.available === false ? (
            <p style={{ marginTop: '1rem', color: '#dc3545', fontWeight: 600, display: 'flex', flexDirection: 'column', gap: '0.25rem' }}>
              <span style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <FiAlertTriangle /> AI unavailable
              </span>
              <span style={{ fontSize: '0.9rem', fontWeight: 'normal' }}>
                {llmStatus.message || 'AI provider offline — static responses active'}
              </span>
              {llmStatus.ollamaBaseURL && (
                <span style={{ fontSize: '0.85rem', fontWeight: 'normal', opacity: 0.9 }}>
                  Server is trying: {llmStatus.ollamaBaseURL}. If Ollama runs elsewhere, set OLLAMA_BASE_URL in server .env and restart.
                </span>
              )}
            </p>
          ) : null}
        </IntroSection>

        <TwoColumnLayout>
          {/* LEFT: Chat */}
          <ChatSection>
            <ChatHeader>
              <h3><FiTerminal /> CodeBot <span style={{ fontSize: '0.8rem', opacity: 0.8, fontWeight: 400 }}>— AI Dependency Analyzer</span></h3>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                <HeaderStatus>
                  <StatusIndicator />
                  <span>pkg-parse@1.2.0</span>
                </HeaderStatus>
                <WorkshopModeControl mode={mode === 'vulnerable' ? 'vuln' : mode} allowedModes={['vuln', 'fixed']} onChange={toggleMode} pending={modePending} scopeLabel="Supply Chain runner" />
                <ScopedResetButton label="Reset" onClick={requestReset} disabled={!!resetAttemptRef.current} />
              </div>
            </ChatHeader>

            <ChatContainer>
              <MessageList ref={messageListRef}>
                <AnimatePresence initial={false}>
                  {messages.map(msg => (
                    <Message
                      key={msg.id}
                      className={msg.type}
                      initial={{ opacity: 0, y: 12 }}
                      animate={{ opacity: 1, y: 0 }}
                      transition={{ duration: 0.25 }}
                    >
                      <div className={`message-icon ${
                        msg.type === 'user' ? 'user-avatar' :
                        msg.type === 'ai' ? 'ai-avatar' :
                        msg.type === 'objective-complete' ? 'success-avatar' :
                        'system-avatar'
                      }`}>
                        {msg.type === 'user' ? '👤' :
                         msg.type === 'ai' ? '🤖' :
                         msg.type === 'objective-complete' ? '✅' : '⚠️'}
                      </div>
                      <div className="message-content">
                        <div className="message-header">
                          <span>
                            {msg.type === 'user' ? 'You' :
                             msg.type === 'ai' ? 'CodeBot' :
                             msg.type === 'objective-complete' ? 'Objective Complete' :
                             'System'}
                          </span>
                          <span style={{ opacity: 0.6 }}>{msg.timestamp.toLocaleTimeString()}</span>
                        </div>
                        <div className="message-text">
                          {msg.plain
                            ? <span style={{ whiteSpace: 'pre-wrap' }}>{msg.content}</span>
                            : <ReactMarkdown>{msg.content}</ReactMarkdown>}
                        </div>
                        <JudgeRetryButton
                          evaluationId={msg.evaluationId}
                          canRetry={msg.canRetry}
                          onResult={handleJudgeRetryResult}
                        />


                        {msg.objectiveId && (
                          <div className="objective-badge">
                            <FiCheckCircle size={10} /> {OBJ_LABELS[msg.objectiveId] || msg.objectiveId}
                          </div>
                        )}
                      </div>
                    </Message>
                  ))}
                </AnimatePresence>

                {loading && (
                  <ThinkingBubble>
                    <div style={{ width: 36, height: 36, borderRadius: '50%', background: 'linear-gradient(135deg,#06b6d4,#3b82f6)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'white', flexShrink: 0 }}>🤖</div>
                    <div className="dots"><span/><span/><span/></div>
                  </ThinkingBubble>
                )}
              </MessageList>
            </ChatContainer>

            <InputContainer onSubmit={handleSubmit}>
              <InputRow>
                <MessageInput
                  value={inputMessage}
                  onChange={e => setInputMessage(e.target.value)}
                  onKeyDown={handleKeyDown}
                  placeholder="Ask CodeBot about its tools, or send a package.json to check..."
                  rows={2}
                />
                <SendButton
                  type="submit"
                  disabled={!inputMessage.trim() || loading}
                  whileHover={{ scale: 1.05 }}
                  whileTap={{ scale: 0.95 }}
                >
                  <FiSend size={18} />
                </SendButton>
              </InputRow>
            </InputContainer>
          </ChatSection>

          {/* RIGHT: Objectives + Progress */}
          <Panel>
            <PanelHeader>
              <h3><FiTarget /> Exercise Objectives</h3>
            </PanelHeader>

            <ObjectivesListWrapper>
              <div className="objectives-list">
                {visibleObjectives.map((obj, idx) => {
                  const isCompleted = !!completedObjectives[obj.id];
                  const isActive = activeObjectiveId === obj.id && !isCompleted;
                  return (
                    <ObjectiveItem
                      key={obj.id}
                      $active={isActive}
                      $completed={isCompleted}
                      category={obj.category}
                      onClick={() => setActiveObjectiveId(obj.id)}
                      initial={{ opacity: 0, x: -10 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ delay: idx * 0.05 }}
                      whileHover={{ scale: 1.02 }}
                      whileTap={{ scale: 0.98 }}
                    >
                      {isActive && <div className="status-badge">ACTIVE</div>}
                      {isCompleted && <div className="status-badge" style={{ right: isActive ? '60px' : '0' }}>COMPLETED</div>}
                      <div className="obj-icon">
                        {isCompleted ? <FiCheckCircle /> : isActive ? <FiTarget /> : <FiLock />}
                      </div>
                      <div className="obj-content">
                        <div className="obj-name">{obj.name}</div>
                        <div className="obj-desc">{obj.description}</div>
                        {/* Solution button — gated ONLY by the solutions toggle (no
                            longer revealed by the hints toggle). */}
                        <div onClick={(event) => event.stopPropagation()}>
                          <ObjectiveHelpActions objectiveId={obj.id} hintVisible={false}
                            solutionVisible={solutionVisibility[obj.id] === true}
                            onOpen={(_kind, objectiveId) => handleViewSolution(objectiveId)} />
                        </div>
                        {/* Real per-objective progressive HINTS — a separate, admin-
                            gated feature from solutions (fixes "no hints" + coupling). */}
                        {hintsEnabled[obj.id] === true && (
                          <div onClick={(e) => e.stopPropagation()}>
                            <HintPanel workshopKey="supply_chain_rce" objectiveId={obj.id} accentColor="#667eea" revision={hintRefreshRevision} />
                          </div>
                        )}
                      </div>
                    </ObjectiveItem>
                  );
                })}
              </div>
            </ObjectivesListWrapper>

            <ProgressBlock>
              <div className="progress-title"><FiActivity /> Overall Progress</div>
              <div className="progress-text">{completedCount} of {visibleObjectives.length} objectives completed</div>
              <div className="progress-bar-track">
                <div className="progress-bar-fill" style={{ width: `${progressPercent}%` }} />
              </div>
              {allComplete && (
                <div className="progress-complete">
                  <FiCheckCircle /> All objectives completed! 🎉
                </div>
              )}
              <div style={{ marginTop: '0.75rem' }}>
                <ScopedResetButton label="Reset Progress" onClick={requestReset} disabled={!!resetAttemptRef.current} />
              </div>
            </ProgressBlock>
          </Panel>
        </TwoColumnLayout>
      </SingleScenarioWorkshop>

      {viewingSolution && visibleObjectiveIds.has(viewingSolution.id) && solutionVisibility[viewingSolution.id] === true && (
        <ObjectiveHelpModal kind="solution" appearance="legacy-light"
          objective={{ name: visibleObjectives.find((objective) => objective.id === viewingSolution.id)?.name || viewingSolution.title }}
          content={{ ...viewingSolution, explanation: viewingSolution.explanation || viewingSolution.description,
            examples: Array.isArray(viewingSolution.examples)
              ? viewingSolution.examples.map((example, index) => ({
                title: example.title || `Example ${index + 1}`,
                payload: example.prompt,
                explanation: example.explanation,
              })) : [],
          }}
          onUsePayload={(prompt) => { setInputMessage(prompt); closeSolution(); }}
          onClose={closeSolution} />
      )}
      <ResetConfirmation open={Boolean(resetConfirmation)} status={resetConfirmation?.status || 'idle'}
        title="Reset Supply Chain progress?"
        description="Clear your CodeBot conversation and objective progress for this workshop. The current request will be retired."
        error={resetConfirmation?.error}
        onCancel={() => { if (!resetConfirmationInFlight.current) setResetConfirmation(null); }}
        onConfirm={confirmReset} />
    </VulnerabilityTemplate>
  );
}
