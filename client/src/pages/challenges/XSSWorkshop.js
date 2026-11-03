/**
 * XSS Workshop Challenge
 * 4-tab XSS exercise page: Reflected XSS, Stored XSS (User), Stored XSS (LLM-Generated), Email Summarization XSS.
 * Matches the UI style of DirectPromptInjectionChallenge.js.
 */
import React, { useState, useEffect, useMemo, useRef, useCallback } from 'react';
import styled from 'styled-components';
import {
  FiSend, FiUser, FiShield, FiAlertTriangle, FiCode, FiTarget, FiActivity,
  FiCheckCircle, FiMessageSquare, FiZap, FiRotateCcw, FiCopy, FiMail, FiExternalLink
} from 'react-icons/fi';
import { toast } from 'react-toastify';
import { motion, AnimatePresence, MotionConfig } from 'framer-motion';
import axios from 'axios';
import VulnerabilityTemplate from '../../components/VulnerabilityTemplate';
import ChatActivityTabs from '../../components/workshop/ChatActivityTabs';
import HintPanel from '../../components/HintPanel';
import ObjectiveHelpModal from '../../components/workshop/ObjectiveHelpModal';
import useChangePolling from '../../hooks/useChangePolling';
import useWorkshopHeartbeat from '../../hooks/useWorkshopHeartbeat';
import useReconciliationGuard, { useGuardedSetter } from '../../hooks/useReconciliationGuard';
import { useWorkshopConfig } from '../../context/WorkshopConfigContext';
import { MultiScenarioWorkshop, ScenarioNavigator, ScenarioWorkspace, WorkshopButton as WorkshopButtonBase, WorkshopModeControl, ScopedResetButton, ObjectiveHelpActions, ResetConfirmation } from '../../components/workshop/WorkshopExperience';
import { xssWorkshopExperience } from '../../components/workshop/experience.mjs';
import JudgeRetryButton from '../../components/workshop/JudgeRetryButton';
import { getJudgeFeedback } from '../../utils/judgeFeedback.mjs';
import { useAuth } from '../../context/AuthContext';
import XssEmailBuilder from './XssEmailBuilder';

// ─────────────────────────── Tab / Objective Definitions ───────────────────────────

const TABS = [
  {
    id: 'reflected',
    label: 'Reflected XSS',
    exerciseId: 'reflected',
    objectives: [
      { id: 'xss_r1', label: 'Interact with the assistant', description: 'Send a normal message to see how the assistant responds.' },
      { id: 'xss_r2', label: 'Inject an HTML tag', description: 'Send an HTML tag like <b>hello</b> and watch it render in the chat.' },
      { id: 'xss_r3', label: 'Execute an XSS payload', description: 'Send an XSS payload and observe it execute.' },
    ],
  },
  {
    id: 'stored_user',
    label: 'Stored XSS: User Payload',
    exerciseId: 'stored_user',
    objectives: [
      { id: 'xss_s1', label: 'View your profile', description: 'Ask the assistant to show your current profile.' },
      { id: 'xss_s2', label: 'Save XSS payload in a profile field', description: 'Ask the assistant to save an XSS payload in one of your profile fields.' },
      { id: 'xss_s3', label: 'Trigger stored XSS', description: 'Ask to show the profile again — observe the stored XSS execute.' },
    ],
  },
  {
    id: 'stored_llm',
    label: 'Stored XSS: LLM-Generated',
    exerciseId: 'stored_llm',
    objectives: [
      { id: 'xss_g1', label: 'Meet the HTML content assistant', description: 'Ask the assistant what it can help you test in your profile fields.' },
      { id: 'xss_g2', label: 'Generate and save HTML content', description: 'Ask the LLM to generate HTML test content for your bio field and save it to your profile.' },
      { id: 'xss_g3', label: 'Observe LLM-generated XSS', description: 'Ask the assistant to show your profile and observe the XSS execute.' },
    ],
  },
  {
    id: 'email',
    label: 'Email Summarization XSS',
    exerciseId: 'email',
    objectives: [
      { id: 'xss_e1', label: 'List your inbox', description: 'Ask the assistant to show your emails.' },
      { id: 'xss_e2', label: 'Send malicious email', description: 'Select an XSS payload and send it through the configured workshop mail transport to your assigned inbox.' },
      { id: 'xss_e3', label: 'Summarize → XSS fires', description: 'Ask: "Summarize my latest exercise attack email" — the AI fetches the matched workshop email body and the XSS payload executes.' },
    ],
  },
  {
    id: 'email_builder',
    label: 'Email Template Builder',
    exerciseId: 'email_builder',
    objectives: [
      { id: 'xss_email_level_1', label: 'Basic Stored XSS (Name Field)', description: 'Persist a name-field payload and generate an email.' },
      { id: 'xss_email_level_2', label: 'Bypass Script Filter (Signature Field)', description: 'Use the signature field to explore event-handler HTML.' },
      { id: 'xss_email_level_3', label: 'Event Handler Injection (Company Field)', description: 'Trace company data into generated HTML.' },
      { id: 'xss_email_level_4', label: 'AI Prompt + XSS Chain', description: 'Explore prompt-driven HTML generation.' },
    ],
  },
];

// Map tab exerciseId → first / last objective id
const FIRST_OBJ = { reflected: 'xss_r1', stored_user: 'xss_s1', stored_llm: 'xss_g1', email: 'xss_e1' };
const XSS_EMAIL_PAYLOADS = [
  {
    id: 'img-error',
    name: 'Image Error Handler',
    code: '<img src=x onerror=alert(document.domain)>',
    description: 'Injects a broken image tag. The onerror event fires immediately when the browser fails to load "x" as an image source — no user interaction needed.',
  },
  {
    id: 'input-autofocus',
    name: 'Auto-Focus Input',
    code: '<input onfocus=alert(1) autofocus>',
    description: 'Creates an invisible input field that auto-focuses when rendered. The onfocus event triggers the payload without any user clicks.',
  },
  {
    id: 'details-toggle',
    name: 'Details Toggle',
    code: '<details open ontoggle=alert(document.domain)>XSS</details>',
    description: 'Uses the <details> HTML element with the open attribute. The ontoggle event fires automatically when the browser renders it in the open state.',
  },
  {
    id: 'svg-hover',
    name: 'SVG Mouseover',
    code: '<svg onmouseover=alert(document.domain)>hover here</svg>',
    description: 'Embeds an SVG element with an onmouseover handler. The payload fires when the user moves their mouse over the SVG content area.',
  },
  {
    id: 'link-hover',
    name: 'Anchor Mouseover',
    code: '<a onmouseover=alert(document.domain) href="#">Special Offer — hover to claim</a>',
    description: 'Disguises the payload as a promotional link. Alert fires on mouse hover — appears as legitimate marketing content inside an email.',
  },
  {
    id: 'custom',
    name: 'Custom Payload',
    code: '',
    description: 'Write your own XSS payload. Use event handlers like onerror, onfocus, onmouseover, ontoggle, or onclick. Avoid onload/onpageshow as those may be blocked by the browser.',
  },
];

const CHALLENGE_KEY = 'reflected_xss_llm';

// ─────────────────────────── Styled Components ───────────────────────────

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
  margin-bottom: 0;
  @media (max-width: 600px) { padding: 1.25rem; }

  h2 {
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
    margin: 1rem 0 0;
    border-radius: 8px;
    font-size: 0.95rem;
    color: #444;
    strong { color: #667eea; }
  }
`;

const EmailSetupGrid = styled.div`
  display: grid;
  grid-template-columns: minmax(0, 1fr) minmax(0, 2fr);
  gap: 2rem;
  @media (max-width: 768px) { grid-template-columns: minmax(0, 1fr); }
`;

const ProviderStatus = styled.div`
  display: flex;
  flex-direction: column;
  gap: 0.25rem;
  margin: 1rem 0;
  overflow-wrap: anywhere;
  color: ${props => props.$ready ? '#28a745' : '#555'};
  font-weight: 600;
  > span { display: flex; align-items: center; flex-wrap: wrap; gap: 0.5rem; }
  small { font-size: 0.85rem; font-weight: 400; line-height: 1.7; }
`;

const TabContainer = styled.div`
  display: flex;
  gap: 0.5rem;
  margin-bottom: 1.5rem;
  flex-wrap: wrap;
`;

const Tab = styled.button`
  padding: 0.6rem 1.2rem;
  border-radius: 10px;
  border: 2px solid ${props => props.$active ? '#667eea' : '#e2e8f0'};
  background: ${props => props.$active ? 'linear-gradient(135deg, #667eea, #764ba2)' : 'white'};
  color: ${props => props.$active ? 'white' : '#555'};
  font-weight: ${props => props.$active ? '700' : '500'};
  font-size: 0.9rem;
  cursor: pointer;
  transition: all 0.2s ease;
  display: flex;
  align-items: center;
  gap: 0.4rem;

  &:hover {
    border-color: #667eea;
    box-shadow: 0 2px 8px rgba(102, 126, 234, 0.2);
    transform: translateY(-1px);
  }
`;

const TwoColumnLayout = styled.div`
  button { min-height: 44px; }
  @media (prefers-reduced-motion: reduce) { &, * { animation: none !important; transition: none !important; scroll-behavior: auto !important; } }
  display: grid;
  grid-template-columns: minmax(0, 2fr) minmax(0, 1fr);
  gap: 2rem;
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
  box-shadow: 0 4px 20px rgba(0, 0, 0, 0.08);
  display: flex;
  flex-direction: column;

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
    color: #333;
    font-weight: 600;
    font-size: 1.5rem;
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }
`;

const ChatSection = styled.div`
  background: white;
  border-radius: 16px;
  box-shadow: 0 4px 20px rgba(0, 0, 0, 0.08);
  overflow: hidden;
  display: flex;
  flex-direction: column;
  height: 600px;
  min-width: 0;
  @media (max-width: 600px) { height: min(700px, 85svh); min-height: 440px; }
  border: 2px solid #e9ecef;
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

  flex-wrap: wrap;
  > div { min-width: 0; }
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
  background: ${({ $available }) => $available === true ? '#4ade80' : $available === false ? '#f87171' : '#9ca3af'};
  box-shadow: 0 0 8px ${({ $available }) => $available === true ? '#4ade80' : $available === false ? '#f87171' : '#9ca3af'};
  @media (prefers-reduced-motion: reduce) { animation: none; }
  flex-shrink: 0;

  @keyframes xsspulse {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.5; }
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

const MessageBubble = styled(motion.div)`
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
    color: #333;
    border-radius: 12px;
    box-shadow: 0 2px 8px rgba(0, 0, 0, 0.06);
  }

  &.objective-complete .message-content {
    background: rgba(72, 187, 120, 0.08);
    border: 1px solid #48bb78;
    border-radius: 18px 18px 18px 4px;
    box-shadow: 0 2px 8px rgba(72, 187, 120, 0.15);
  }

  .message-icon {
    flex-shrink: 0;
    width: 40px;
    height: 40px;
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 1rem;
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

  .message-content {
    flex: 1;
    padding: 0.8rem 1rem;
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
    gap: 0.4rem;
  }
  .message-text {
    font-size: 0.9rem;
    line-height: 1.6;
    word-break: break-word;
    overflow-wrap: break-word;
    p { margin: 0 0 0.5rem 0; }
    p:last-child { margin-bottom: 0; }
    code { font-family: monospace; background: rgba(0,0,0,0.08); padding: 0.1rem 0.3rem; border-radius: 3px; font-size: 0.85em; }
    pre { background: rgba(0,0,0,0.08); padding: 0.5rem; border-radius: 4px; overflow-x: auto; margin: 0.4rem 0; }
  }
`;

const InputRow = styled.form`
  display: flex;
  gap: 0.75rem;
  align-items: flex-end;
  padding: 1rem 1.25rem;
  background: white;
  border-top: 1px solid #e2e8f0;
  flex-shrink: 0;
`;

const Input = styled.textarea`
  flex: 1;
  min-width: 0;
  padding: 0.8rem 1rem;
  border: 2px solid #e2e8f0;
  border-radius: 12px;
  font-size: 0.95rem;
  resize: none;
  min-height: 42px;
  max-height: 100px;
  font-family: inherit;
  transition: all 0.3s ease;

  &:focus {
    outline: none;
    border-color: #667eea;
    box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
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
  transition: all 0.3s ease;

  &:hover:not(:disabled) {
    transform: translateY(-2px);
    box-shadow: 0 6px 20px rgba(102, 126, 234, 0.4);
  }
  &:disabled { opacity: 0.5; cursor: not-allowed; }
`;

const ObjectiveItem = styled(motion.div)`
  display: flex;
  align-items: flex-start;
  gap: 1rem;
  padding: 0.875rem 1.25rem;
  background: ${props => props.$completed ? '#f0fdf4' : props.$active ? 'rgba(102, 126, 234, 0.08)' : '#f8f9fa'};
  border: 1px solid ${props => props.$completed ? '#22c55e' : props.$active ? '#667eea' : '#e2e8f0'};
  border-radius: 10px;
  margin-bottom: 0.65rem;
  position: relative;
  overflow: hidden;
  transition: all 0.3s ease;

  &:hover {
    box-shadow: 0 3px 10px rgba(0, 0, 0, 0.06);
  }

  .status-badge {
    position: absolute;
    top: 0;
    right: 0;
    padding: 0.2rem 0.6rem;
    font-size: 0.62rem;
    font-weight: 800;
    letter-spacing: 0.05em;
    border-bottom-left-radius: 8px;
    color: white;
    background: ${props => props.$completed ? '#22c55e' : props.$active ? '#667eea' : '#dee2e6'};
  }

  .obj-icon {
    flex-shrink: 0;
    width: 36px;
    height: 36px;
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 1rem;
    background: ${props => props.$completed ? '#22c55e' : props.$active ? '#667eea' : '#dee2e6'};
    color: white;
    margin-top: 2px;
  }
  .obj-content { flex: 1; min-width: 0; overflow-wrap: anywhere; }
  .obj-name {
    font-weight: 600;
    color: #333;
    font-size: 1rem;
    margin-bottom: 0.25rem;
  }
  .obj-desc {
    font-size: 0.85rem;
    color: #666;
    line-height: 1.4;
  }
`;

const ProgressBlock = styled.div`
  margin-top: 1.5rem;
  padding-top: 1.5rem;
  border-top: 2px solid #e9ecef;

  .progress-title {
    font-size: 1.1rem;
    font-weight: 600;
    color: #333;
    margin-bottom: 0.6rem;
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }
  .progress-text {
    font-size: 0.95rem;
    color: #666;
    margin-bottom: 0.6rem;
  }
  .progress-bar-track {
    height: 16px;
    background: #e9ecef;
    border-radius: 8px;
    overflow: hidden;
  }
  .progress-bar-fill {
    height: 100%;
    background: linear-gradient(90deg, #667eea, #764ba2);
    border-radius: 8px;
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
    font-size: 0.92rem;
    text-align: center;
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 0.5rem;
  }
`;

const XSSBanner = styled(motion.div)`
  margin: 0.75rem 1.25rem;
  padding: 0.75rem 1rem;
  background: linear-gradient(135deg, rgba(220, 53, 69, 0.12), rgba(255, 87, 34, 0.12));
  border: 2px solid #dc3545;
  border-radius: 10px;
  color: #dc3545;
  font-weight: 700;
  font-size: 0.9rem;
  display: flex;
  align-items: center;
  gap: 0.5rem;
  flex-shrink: 0;
`;

const SectionTitle = styled.h3`
  font-size: 1rem;
  font-weight: 700;
  color: #333;
  margin: 0 0 0.75rem 0;
  display: flex;
  align-items: center;
  gap: 0.5rem;
`;

const ResetButton = styled(motion.button)`
  background: transparent;
  border: 1.5px solid #dc3545;
  color: #dc3545;
  border-radius: 8px;
  padding: 0.4rem 0.9rem;
  font-size: 0.82rem;
  font-weight: 600;
  cursor: pointer;
  display: flex;
  align-items: center;
  gap: 0.4rem;
  transition: all 0.2s ease;

  &:hover:not(:disabled) {
    background: rgba(220, 53, 69, 0.07);
  }
  &:disabled { opacity: 0.5; cursor: not-allowed; }
`;

const SolutionPanel = styled(motion.div)`
  margin-top: 1rem;
  padding: 1.25rem;
  background: rgba(102, 126, 234, 0.06);
  border: 2px solid rgba(102, 126, 234, 0.3);
  border-radius: 12px;
`;

const HintItem = styled.div`
  background: rgba(255, 193, 7, 0.1);
  border-left: 3px solid #ffc107;
  padding: 0.6rem 0.9rem;
  border-radius: 6px;
  font-size: 0.88rem;
  color: #333;
  margin-bottom: 0.5rem;
  line-height: 1.5;
`;

const PayloadItem = styled.div`
  display: flex;
  align-items: center;
  gap: 0.5rem;
  background: rgba(0, 0, 0, 0.04);
  border: 1px solid #dee2e6;
  border-radius: 8px;
  padding: 0.5rem 0.75rem;
  margin-bottom: 0.5rem;

  code {
    flex: 1;
    font-family: 'Courier New', monospace;
    font-size: 0.82rem;
    color: #e83e8c;
    word-break: break-all;
  }

  button {
    flex-shrink: 0;
    background: none;
    border: none;
    cursor: pointer;
    color: #667eea;
    padding: 2px;
    display: flex;
    align-items: center;
    transition: color 0.2s;
    &:hover { color: #764ba2; }
  }
`;

const ViewSolutionButton = styled.button`
  margin-top: 0.75rem;
  padding: 0.4rem 0.75rem;
  font-size: 0.84rem;
  background: #667eea;
  color: white;
  border: none;
  border-radius: 6px;
  cursor: pointer;
  font-weight: 600;
  display: flex;
  align-items: center;
  gap: 0.4rem;
  box-shadow: 0 2px 4px rgba(102, 126, 234, 0.3);
  transition: all 0.2s ease;

  &:hover {
    background: #764ba2;
    box-shadow: 0 3px 8px rgba(118, 75, 162, 0.4);
  }
`;

// ─────────────────────────── Markdown → HTML (preserves raw HTML tags for XSS) ───
function markdownToHtml(text) {
  if (!text) return '';

  const lines = text.split('\n');
  const out = [];
  let inList = false;
  let listType = null;

  for (let i = 0; i < lines.length; i++) {
    let line = lines[i];

    // Horizontal rule
    if (/^---+$/.test(line.trim())) {
      if (inList) { out.push(listType === 'ul' ? '</ul>' : '</ol>'); inList = false; }
      out.push('<hr style="border:none;border-top:1px solid #e2e8f0;margin:0.75rem 0">');
      continue;
    }

    // Headings
    const headingMatch = line.match(/^(#{1,3})\s+(.+)$/);
    if (headingMatch) {
      if (inList) { out.push(listType === 'ul' ? '</ul>' : '</ol>'); inList = false; }
      const level = headingMatch[1].length;
      const sizes = { 1: '1.4rem', 2: '1.15rem', 3: '1rem' };
      out.push(`<div style="font-size:${sizes[level]};font-weight:700;margin:0.6rem 0 0.3rem;color:#1e293b">${inlineFormat(headingMatch[2])}</div>`);
      continue;
    }

    // Blockquote
    if (line.startsWith('> ')) {
      if (inList) { out.push(listType === 'ul' ? '</ul>' : '</ol>'); inList = false; }
      out.push(`<div style="border-left:3px solid #667eea;padding:0.3rem 0.75rem;margin:0.4rem 0;color:#475569;font-style:italic;background:rgba(102,126,234,0.06);border-radius:0 6px 6px 0">${inlineFormat(line.slice(2))}</div>`);
      continue;
    }

    // Unordered list item
    const ulMatch = line.match(/^[\-\*]\s+(.+)$/);
    if (ulMatch) {
      if (!inList || listType !== 'ul') {
        if (inList) out.push(listType === 'ul' ? '</ul>' : '</ol>');
        out.push('<ul style="margin:0.3rem 0;padding-left:1.5rem">');
        inList = true; listType = 'ul';
      }
      out.push(`<li style="margin:0.15rem 0">${inlineFormat(ulMatch[1])}</li>`);
      continue;
    }

    // Ordered list item
    const olMatch = line.match(/^\d+\.\s+(.+)$/);
    if (olMatch) {
      if (!inList || listType !== 'ol') {
        if (inList) out.push(listType === 'ul' ? '</ul>' : '</ol>');
        out.push('<ol style="margin:0.3rem 0;padding-left:1.5rem">');
        inList = true; listType = 'ol';
      }
      out.push(`<li style="margin:0.15rem 0">${inlineFormat(olMatch[1])}</li>`);
      continue;
    }

    // Regular line — close any open list first
    if (inList) { out.push(listType === 'ul' ? '</ul>' : '</ol>'); inList = false; }

    if (line.trim() === '') {
      out.push('<br>');
    } else {
      out.push(inlineFormat(line));
    }
  }

  if (inList) out.push(listType === 'ul' ? '</ul>' : '</ol>');
  return out.join('\n');
}

function inlineFormat(text) {
  return text
    .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
    .replace(/\*(.+?)\*/g, '<em>$1</em>')
    .replace(/`([^`]+)`/g, '<code style="background:#f1f5f9;padding:0.1rem 0.35rem;border-radius:3px;font-size:0.85em">$1</code>')
    .replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2" style="color:#667eea;text-decoration:underline">$1</a>');
}

// ─────────────────────────── Component ───────────────────────────

const XSSWorkshop = () => {
  const { user: platformUser } = useAuth();
  const platformToken = localStorage.getItem('token');
  const ownerRef = useRef({ token: platformToken, userId: platformUser?.id, revision: 0 });
  if (ownerRef.current.token !== platformToken || ownerRef.current.userId !== platformUser?.id) {
    ownerRef.current = { token: platformToken, userId: platformUser?.id, revision: ownerRef.current.revision + 1 };
  }
  const ownerRevision = ownerRef.current.revision;
  const mountedRef = useRef(true);
  const ownerIsCurrent = useCallback(() => mountedRef.current && ownerRef.current.revision === ownerRevision
    && localStorage.getItem('token') === platformToken, [ownerRevision, platformToken]);
  const { snapshot, revision } = useWorkshopConfig();
  const xssExercise = snapshot?.exercises?.xss_workshop;
  const emailBuilderExercise = snapshot?.exercises?.xss_email_builder;
  const visibleObjectiveIds = useMemo(() => new Set(
    TABS.flatMap(tab => tab.objectives)
      .filter(objective => objective.id.startsWith('xss_email_level_')
        ? emailBuilderExercise?.isVisible === true
          && emailBuilderExercise.objectives?.[objective.id]?.isVisible === true
        : xssExercise?.isVisible === true
          && xssExercise.objectives?.[objective.id]?.isVisible === true)
      .map(objective => objective.id)
  ), [xssExercise, emailBuilderExercise]);
  const visibleTabs = useMemo(() => TABS.map(tab => ({
    ...tab,
    objectives: tab.objectives.filter(objective => visibleObjectiveIds.has(objective.id)).map(objective => {
      const label = objective.id.startsWith('xss_email_level_')
        ? emailBuilderExercise?.objectives?.[objective.id]?.label
        : xssExercise?.objectives?.[objective.id]?.label;
      const config = objective.id.startsWith('xss_email_level_')
        ? emailBuilderExercise?.objectives?.[objective.id]
        : xssExercise?.objectives?.[objective.id];
      return {
        ...objective,
        label: typeof label === 'string' && label.trim() ? label : objective.label,
        description: typeof config?.description === 'string' && config.description.trim() ? config.description : objective.description,
        hintVisible: config?.hintVisible === true,
        solutionVisible: config?.solutionVisible === true,
      };
    }),
  })).filter(tab => tab.objectives.length > 0), [visibleObjectiveIds, xssExercise, emailBuilderExercise]);
  const [activeTab, setActiveTab] = useState(0);
  const queryTabApplied = useRef(false);
  const activeExerciseRef = useRef(TABS[0].exerciseId);
  const navigationGeneration = useRef(0);
  const progressGuard = useReconciliationGuard();
  const [completedObjectives, setCompletedObjectivesFromPoll] = useState({});
  const setCompletedObjectives = useGuardedSetter(setCompletedObjectivesFromPoll, progressGuard);
  const summaryObjectiveIds = useMemo(() => TABS.filter(tab => tab.exerciseId !== 'email_builder').flatMap(tab => tab.objectives.map(objective => objective.id)), []);
  const mergeSummaryProgress = useCallback((previous, summary) => ({
    ...previous,
    ...Object.fromEntries(summaryObjectiveIds.map(id => [id, false])),
    ...summary,
  }), [summaryObjectiveIds]);
  const handleBuilderProgress = useCallback((rows) => {
    if (!ownerIsCurrent()) return;
    const builderIds = TABS.find(tab => tab.exerciseId === 'email_builder').objectives.map(objective => objective.id);
    const next = Object.fromEntries(builderIds.map(id => [id, false]));
    if (Array.isArray(rows)) rows.forEach(row => {
      const id = row?.id || row?.objective_id;
      if (id && Object.hasOwn(next, id)) next[id] = row.completed === true || row.completed === 1;
    });
    setCompletedObjectives(previous => ({ ...previous, ...next }));
  }, [setCompletedObjectives, ownerIsCurrent]);
  const [solutionsEnabled, setSolutionsEnabled] = useState({});
  const [hintsEnabled, setHintsEnabled] = useState({});
  const [hintRefreshRevision, setHintRefreshRevision] = useState(0);
  const [solutionContent, setSolutionContent] = useState({});
  const [showSolution, setShowSolution] = useState({});
  // Per-objective solution modal state (null = closed, object = open with solution data)
  const [viewingObjectiveSolution, setViewingObjectiveSolution] = useState(null);
  const pendingObjectiveSolutionRef = useRef(null);
  const [sharklaserEmail, setSharklaserEmail] = useState('');
  const [emailConfig, setEmailConfig] = useState({ resolved: false, mode: null, provider: null, editable: false, sender: '', mailpitInboxUrl: null });
  const [emailSendError, setEmailSendError] = useState('');
  const emailConfigRef = useRef(emailConfig);
  const externalEmailEditedRef = useRef(false);
  const [selectedPayload, setSelectedPayload] = useState(0);
  const [customPayload, setCustomPayload] = useState('');
  const interactionGeneration = useRef(0);
  const interactionControllers = useRef(new Set());
  useEffect(() => { mountedRef.current = true; return () => {
    mountedRef.current = false;
    interactionGeneration.current += 1;
    navigationGeneration.current += 1;
    interactionControllers.current.forEach(controller => controller.abort());
    interactionControllers.current.clear();
  }; }, []);

  const conversationGeneration = useRef({ reflected: 0, stored_user: 0, stored_llm: 0, email: 0 });
  const [emailSendStatus, setEmailSendStatus] = useState(null); // null | 'sending' | 'sent' | 'error'
  const [loading, setLoading] = useState(false);
  const [chatMode, setChatMode] = useState('vuln');
  const [chatModePending, setChatModePending] = useState(false);
  const [chatModeResolved, setChatModeResolved] = useState(false);
  const modeGeneration = useRef(0);
  const [profileResetConfirmation, setProfileResetConfirmation] = useState(null);
  const profileResetPendingRef = useRef(false);
  const [resettingProgress, setResettingProgress] = useState(false);
  const [progressResetConfirmation, setProgressResetConfirmation] = useState(null);
  const progressResetPendingRef = useRef(false);
  const [xssDetected, setXssDetected] = useState(false);
  const tabXssDetected = useRef({ reflected: false, stored_user: false, stored_llm: false, email: false });
  const [drafts, setDrafts] = useState({});
  const inputMessage = drafts[visibleTabs[activeTab]?.exerciseId] || '';
  const setInputMessage = value => setDrafts(previous => ({ ...previous, [visibleTabs[activeTab]?.exerciseId]: value }));
  const [llmStatus, setLlmStatus] = useState({ available: null, model: null, availableModels: [] });

  // Per-tab message history using a ref of arrays keyed by tab id
  const tabMessages = useRef({
    reflected: [],
    stored_user: [],
    stored_llm: [],
    email: [],
  });
  const [messages, setMessages] = useState([]);

  const messageListRef = useRef(null);
  const nextIdRef = useRef(1);
  // Track whether first message has been sent in each tab
  const firstMessageSent = useRef({ reflected: false, stored_user: false, stored_llm: false, email: false });

  const initializedOwner = useRef(ownerRevision);
  useEffect(() => {
    if (initializedOwner.current === ownerRevision) return;
    initializedOwner.current = ownerRevision;
    interactionGeneration.current += 1; navigationGeneration.current += 1;
    interactionControllers.current.forEach(controller => controller.abort()); interactionControllers.current.clear();
    ['progress', 'gates', 'solutionModal'].forEach(domain => progressGuard.mark(domain));
    tabMessages.current = { reflected: [], stored_user: [], stored_llm: [], email: [] };
    tabXssDetected.current = { reflected: false, stored_user: false, stored_llm: false, email: false };
    firstMessageSent.current = { reflected: false, stored_user: false, stored_llm: false, email: false };
    conversationGeneration.current = { reflected: 0, stored_user: 0, stored_llm: 0, email: 0 };
    setMessages([]); setCompletedObjectivesFromPoll({}); setInputMessage(''); setXssDetected(false);
    progressResetPendingRef.current = false;
    setProgressResetConfirmation(null);
    profileResetPendingRef.current = false;
    setProfileResetConfirmation(null);
    setLoading(false); setResettingProgress(false);
    modeGeneration.current += 1; setChatMode('vuln'); setChatModePending(false); setChatModeResolved(false);
    setSolutionsEnabled({}); setHintsEnabled({}); setSolutionContent({}); setShowSolution({});
    pendingObjectiveSolutionRef.current = null; setViewingObjectiveSolution(null);
    setSharklaserEmail(''); setEmailSendStatus(null); setEmailSendError(''); setCustomPayload(''); setSelectedPayload(0);
    externalEmailEditedRef.current = false;
    const emptyMail = { resolved: false, mode: null, provider: null, editable: false, sender: '', mailpitInboxUrl: null };
    emailConfigRef.current = emptyMail; setEmailConfig(emptyMail);
    setLlmStatus({ available: null, model: null, availableModels: [] });
    setDrafts({});
    activeExerciseRef.current = null; queryTabApplied.current = false;
  }, [ownerRevision, progressGuard]);

  useEffect(() => { emailConfigRef.current = emailConfig; }, [emailConfig]);

  useWorkshopHeartbeat(visibleTabs[activeTab]?.exerciseId === 'email_builder' ? 'xss_email_builder' : 'xss_workshop');
  useChangePolling(async (_next, _previous, { signal } = {}) => {
    if (!ownerIsCurrent() || signal?.aborted) return;
    const progressGeneration = progressGuard.begin('progress');
    const gatesGeneration = progressGuard.begin('gates');
    const solutionDisclosureId = viewingObjectiveSolution?.objectiveId || pendingObjectiveSolutionRef.current;
    const modalGeneration = solutionDisclosureId
      ? progressGuard.begin('solutionModal')
      : null;
    const [solutionResponse, hintResponse, progressResponse] = await Promise.all([
      axios.get('/api/solutions/xss-workshop/status', { signal }),
      axios.get('/api/hints/reflected_xss_llm/status', { signal }),
      axios.get('/api/workshop/xss/progress', { signal }),
    ]);
    if (!ownerIsCurrent() || signal?.aborted) return;
    const nextSolutions = solutionResponse.data?.objectives || solutionResponse.data || {};
    const refreshedSolution = solutionDisclosureId && nextSolutions[solutionDisclosureId]
      ? await axios.get(`/api/solutions/xss-workshop/objective/${solutionDisclosureId}`, { signal })
      : null;
    if (!ownerIsCurrent() || signal?.aborted) return;
    const rawProgress = progressResponse.data?.completedObjectives || progressResponse.data?.objectives || {};
    const completed = {};
    Object.keys(rawProgress).forEach((key) => {
      completed[key] = typeof rawProgress[key] === 'boolean' ? rawProgress[key] : !!rawProgress[key]?.completed;
    });
    progressGuard.commit('gates', gatesGeneration, () => {
      setSolutionsEnabled(nextSolutions);
      setHintsEnabled(hintResponse.data?.objectives || hintResponse.data || {});
      setHintRefreshRevision(current => current + 1);
      if (solutionDisclosureId && !nextSolutions[solutionDisclosureId]) {
        pendingObjectiveSolutionRef.current = null;
        progressGuard.mark('solutionModal');
        setViewingObjectiveSolution(null);
      }
    });
    progressGuard.commit('progress', progressGeneration, () => {
      setCompletedObjectivesFromPoll(previous => mergeSummaryProgress(previous, completed));
    });
    if (modalGeneration !== null && refreshedSolution && nextSolutions[solutionDisclosureId]) {
      if (!ownerIsCurrent()) return;
      progressGuard.commit('solutionModal', modalGeneration, () => {
        pendingObjectiveSolutionRef.current = null;
        setViewingObjectiveSolution({ objectiveId: solutionDisclosureId, ...refreshedSolution.data.solution });
      });
    }
  }, ['xss_workshop']);

  const currentTab = visibleTabs[activeTab] || visibleTabs[0] || { ...TABS[0], objectives: [] };
  const exerciseId = currentTab.exerciseId;
  const navigatorDefinition = useMemo(() => {
    const scenarios = xssWorkshopExperience.scenarios.filter(scenario => visibleTabs.some(tab => tab.id === scenario.id));
    return scenarios.length >= 2 ? { ...xssWorkshopExperience, scenarios } : null;
  }, [visibleTabs, ownerIsCurrent]);

  useEffect(() => {
    const disclosureId = viewingObjectiveSolution?.objectiveId || pendingObjectiveSolutionRef.current;
    if (disclosureId && !visibleObjectiveIds.has(disclosureId)) {
      pendingObjectiveSolutionRef.current = null;
      progressGuard.mark('solutionModal');
      setViewingObjectiveSolution(null);
    }
  }, [progressGuard, revision, viewingObjectiveSolution, visibleObjectiveIds]);

  const followOutput = useRef(true);
  // Follow new output only while the learner is near the bottom.
  useEffect(() => {
    const el = messageListRef.current;
    if (!el || !followOutput.current) return;
    requestAnimationFrame(() => { el.scrollTop = el.scrollHeight; });
  }, [messages, loading, xssDetected]);

  // Scenario navigation preserves each scenario's conversation and artifacts.
  const switchToTab = useCallback(async (idx) => {
    if (!ownerIsCurrent() || !visibleTabs[idx]) return;
    const navigation = ++navigationGeneration.current;
    const targetExerciseId = visibleTabs[idx].exerciseId;
    // Resolve the transport and owner inbox before showing the email scenario.
    if (targetExerciseId === 'email') {
      try {
        const { data } = await axios.get('/api/workshop/xss/emails/sharklaser-email');
        if (!ownerIsCurrent() || navigation !== navigationGeneration.current) return;
        if (!['local', 'external'].includes(data.mode) || !['mailpit', 'gmail'].includes(data.provider)) {
          throw new Error('Invalid workshop mail configuration');
        }
        const next = {
          resolved: true,
          mode: data.mode,
          provider: data.provider,
          editable: data.mode === 'external' && data.editable === true,
          sender: typeof data.sender === 'string' ? data.sender : '',
          mailpitInboxUrl: data.provider === 'mailpit' && typeof data.mailpitInboxUrl === 'string' ? data.mailpitInboxUrl : null,
        };
        const previous = emailConfigRef.current;
        const retainExternalEdit = next.mode === 'external' && previous.mode === 'external'
          && externalEmailEditedRef.current;
        if (!retainExternalEdit) {
          setSharklaserEmail(typeof data.email === 'string' ? data.email : '');
          externalEmailEditedRef.current = false;
        }
        emailConfigRef.current = next;
        setEmailConfig(next);
      } catch (_) {
        if (!ownerIsCurrent() || navigation !== navigationGeneration.current) return;
        const unavailable = { resolved: false, mode: null, provider: null, editable: false, sender: '', mailpitInboxUrl: null };
        emailConfigRef.current = unavailable;
        setEmailConfig(unavailable);
        setSharklaserEmail('');
      }
    }
    activeExerciseRef.current = targetExerciseId;
    setActiveTab(idx);
    setMessages(tabMessages.current[targetExerciseId] || []);
    setXssDetected(Boolean(tabXssDetected.current[targetExerciseId]));
    followOutput.current = true;
    pendingObjectiveSolutionRef.current = null;
    progressGuard.mark('solutionModal');
    setViewingObjectiveSolution(null);
  }, [visibleTabs, ownerIsCurrent, progressGuard]);

  useEffect(() => {
    if (!visibleTabs.length) return;
    let index = Math.min(activeTab, visibleTabs.length - 1);
    if (!queryTabApplied.current) {
      const requested = new URLSearchParams(window.location.search).get('tab');
      const requestedIndex = visibleTabs.findIndex(tab => tab.id === requested || tab.exerciseId === requested);
      if (requestedIndex >= 0) index = requestedIndex;
      queryTabApplied.current = true;
    }
    if (index !== activeTab || activeExerciseRef.current !== visibleTabs[index].exerciseId) {
      void switchToTab(index);
    }
  }, [activeTab, visibleTabs, switchToTab]);

  const fetchLlmStatus = useCallback(async () => {
    if (!ownerIsCurrent()) return;
    try {
      const { data } = await axios.get('/api/workshop/xss/llm-status');
      if (!ownerIsCurrent()) return;
      setLlmStatus({
        available: data.available === true,
        provider: data.provider || (data.ollamaBaseURL ? 'ollama' : null),
        model: data.model || null,
        providerName: data.providerName || null,
        region: data.region || null,
        message: data.message || '',
        ollamaBaseURL: data.ollamaBaseURL || 'http://localhost:11434',
        ollamaVersion: data.ollamaVersion || null,
        availableModels: Array.isArray(data.availableModels) ? data.availableModels : []
      });
    } catch {
      if (!ownerIsCurrent()) return;
      setLlmStatus({ available: false, refreshFailed: true, model: null, availableModels: [] });
    }
  }, [ownerIsCurrent]);

  const refreshChatMode = useCallback(async () => {
    if (!ownerIsCurrent()) return;
    const ticket = ++modeGeneration.current;
    try {
      const { data } = await axios.get('/api/workshop/xss/mode');
      if (!ownerIsCurrent() || ticket !== modeGeneration.current) return;
      const effective = data?.effectiveMode || (data?.mode === null ? 'vuln' : data?.mode);
      if (!['vuln', 'fixed'].includes(effective) || (data?.scope && data.scope.id !== 'xss_workshop')) throw new Error('Invalid XSS mode');
      setChatMode(effective);
      setChatModeResolved(true);
    } catch {
      if (ownerIsCurrent() && ticket === modeGeneration.current) setChatModeResolved(false);
    }
  }, [ownerIsCurrent]);

  useEffect(() => { void refreshChatMode(); }, [refreshChatMode]);

  const changeChatMode = async (next) => {
    if (!ownerIsCurrent() || chatModePending || next === chatMode || !['vuln', 'fixed'].includes(next)) return;
    const ticket = ++modeGeneration.current;
    setChatModePending(true);
    try {
      const { data } = await axios.post('/api/workshop/xss/mode', { mode: next });
      if (!ownerIsCurrent() || ticket !== modeGeneration.current) return;
      if (data?.effectiveMode !== next || data?.scope?.id !== 'xss_workshop') throw new Error('Invalid XSS mode response');
      setChatMode(next);
      setChatModeResolved(true);
      setLoading(false);
      toast.info(`Switched to ${next === 'fixed' ? 'Fixed' : 'Vulnerable'} mode. Existing work is kept.`);
    } catch {
      if (!ownerIsCurrent() || ticket !== modeGeneration.current) return;
      toast.error('Could not change XSS mode.');
      await refreshChatMode();
    } finally {
      if (ownerIsCurrent() && (ticket === modeGeneration.current || ticket + 1 === modeGeneration.current)) setChatModePending(false);
    }
  };

  // Load progress + solution status on mount
  useEffect(() => {
    const progressGeneration = progressGuard.begin('progress');
    const gatesGeneration = progressGuard.begin('gates');
    fetchLlmStatus();
    axios.get('/api/workshop/xss/progress')
      .then(res => {
        if (!ownerIsCurrent()) return;
        const raw = res.data?.completedObjectives || res.data?.objectives || {};
        const normalized = {};
        // Accept both { xss_r1: true } and { xss_r1: { completed: true } }
        Object.keys(raw).forEach(k => {
          normalized[k] = typeof raw[k] === 'boolean' ? raw[k] : !!raw[k]?.completed;
        });
        progressGuard.commit('progress', progressGeneration, () => {
          setCompletedObjectivesFromPoll(previous => mergeSummaryProgress(previous, normalized));
        });
      })
      .catch(() => {});

    axios.get('/api/solutions/xss-workshop/status')
      .then(res => {
        if (!ownerIsCurrent()) return;
        progressGuard.commit('gates', gatesGeneration, () => {
          setSolutionsEnabled(res.data?.objectives || res.data || {});
        });
      })
      .catch(() => {});

    // Per-objective hint visibility (admin-gated, seeded from workshopHints.js).
    // The hint route remaps 'reflected_xss_llm' → 'xss_workshop'.
    axios.get('/api/hints/reflected_xss_llm/status')
      .then(res => {
        if (!ownerIsCurrent()) return;
        progressGuard.commit('gates', gatesGeneration, () => {
          setHintsEnabled(res.data?.objectives || res.data || {});
        });
      })
      .catch(() => {});
  }, [fetchLlmStatus, progressGuard]);

  const applyServerCompletion = useCallback((objectiveId) => {
    if (completedObjectives[objectiveId]) return;
    setCompletedObjectives(prev => ({ ...prev, [objectiveId]: true }));
    window.dispatchEvent(new Event('objectiveCompleted'));
  }, [completedObjectives, setCompletedObjectives]);

  const judgmentMessages = useCallback((judgments = []) => getJudgeFeedback({ judgments })
    .map(feedback => ({
      id: nextIdRef.current++,
      type: 'system',
      content: feedback.content,
      timestamp: new Date(),
      plain: true,
      judgmentVerdict: feedback.verdict,
      evaluationId: feedback.evaluationId,
      canRetry: feedback.canRetry,
    })), []);

  const refreshAuthoritativeProgress = useCallback(async (isCurrent = () => true) => {
    const progressGeneration = progressGuard.begin('progress');
    const response = await axios.get('/api/workshop/xss/progress');
    if (!ownerIsCurrent() || !isCurrent()) return;
    const raw = response.data?.completedObjectives || response.data?.objectives || {};
    const normalized = {};
    Object.keys(raw).forEach(key => {
      normalized[key] = typeof raw[key] === 'boolean' ? raw[key] : !!raw[key]?.completed;
    });
    progressGuard.commit('progress', progressGeneration, () => setCompletedObjectivesFromPoll(previous => mergeSummaryProgress(previous, normalized)));
  }, [progressGuard, ownerIsCurrent]);

  const appendScenarioMessages = useCallback((tabId, additions) => {
    if (!additions.length) return;
    const next = [...(tabMessages.current[tabId] || []), ...additions];
    tabMessages.current[tabId] = next;
    if (activeExerciseRef.current === tabId) setMessages(next);
  }, []);

  const retryInteraction = interactionGeneration.current;
  const retryConversations = { ...conversationGeneration.current };
  const handleJudgeRetryResult = async (tabId, data, { signal } = {}) => {
    const isCurrent = () => ownerIsCurrent() && !signal?.aborted && interactionGeneration.current === retryInteraction
      && (conversationGeneration.current[tabId] || 0) === (retryConversations[tabId] || 0);
    if (!ownerIsCurrent() || !isCurrent()) return;
    const feedback = judgmentMessages(data.judgment ? [data.judgment] : data.judgments);
    appendScenarioMessages(tabId, feedback);
    await refreshAuthoritativeProgress(isCurrent);
    if (!ownerIsCurrent() || !isCurrent()) return;
    if (data.completed === true) toast.success('Objective evaluation passed.');
  };

  const handleSendAttackEmail = async () => {
    if (!ownerIsCurrent() || !emailConfig.resolved || !sharklaserEmail || emailSendStatus === 'sending') return;
    const isCustom = XSS_EMAIL_PAYLOADS[selectedPayload]?.id === 'custom';
    const payloadCode = isCustom ? customPayload.trim() : XSS_EMAIL_PAYLOADS[selectedPayload]?.code;
    if (!payloadCode) {
      toast.error(isCustom ? 'Enter your custom payload first.' : 'Select a payload first.');
      return;
    }
    const sendGeneration = interactionGeneration.current;
    const controller = new AbortController();
    interactionControllers.current.add(controller);
    setEmailSendError('');
    setEmailSendStatus('sending');
    try {
      const { data } = await axios.post('/api/workshop/xss/emails/send-attack', {
        fromEmail: sharklaserEmail,
        payload: payloadCode,
      }, { signal: controller.signal });
      if (!ownerIsCurrent() || controller.signal.aborted || sendGeneration !== interactionGeneration.current) return;
      setEmailSendStatus('sent');
      if (data.completedObjectiveId) {
        applyServerCompletion(data.completedObjectiveId);
      }
      const feedback = judgmentMessages(data.judgments);
      appendScenarioMessages('email', feedback);
    } catch (err) {
      if (!ownerIsCurrent() || controller.signal.aborted || sendGeneration !== interactionGeneration.current) return;
      setEmailSendStatus('error');
      const message = String(err.response?.data?.error || 'Failed to send email.').slice(0, 180);
      setEmailSendError(message);
      toast.error(message);
    } finally {
      interactionControllers.current.delete(controller);
    }
  };

  const handleSend = async (e) => {
    e.preventDefault();
    const text = inputMessage.trim();
    if (!ownerIsCurrent() || !text || loading || !chatModeResolved || chatModePending) return;
    followOutput.current = true;
    const chatGeneration = interactionGeneration.current;
    const chatModeGeneration = modeGeneration.current;
    const controller = new AbortController();
    interactionControllers.current.add(controller);
    const chatConversationGeneration = conversationGeneration.current[exerciseId] || 0;
    const chatGlobalIsCurrent = () => ownerIsCurrent() && !controller.signal.aborted && chatGeneration === interactionGeneration.current
      && chatModeGeneration === modeGeneration.current;
    const chatPresentationIsCurrent = () => chatGlobalIsCurrent()
      && chatConversationGeneration === (conversationGeneration.current[exerciseId] || 0);

    const userMsg = {
      id: nextIdRef.current++,
      type: 'user',
      content: text,
      timestamp: new Date(),
    };
    const updatedMessages = [...messages, userMsg];
    setMessages(updatedMessages);
    tabMessages.current[exerciseId] = updatedMessages;
    setInputMessage('');
    setLoading(true);
    setXssDetected(false);
    tabXssDetected.current[exerciseId] = false;

    try {
      const res = await axios.post('/api/workshop/xss/chat', {
        exerciseId,
        message: text,
        completedObjectives,
        ...(exerciseId === 'email' && sharklaserEmail ? { sharklaserEmail } : {}),
      }, { signal: controller.signal });
      if (!chatGlobalIsCurrent()) return;
      const data = res.data;
      const responseMode = ['vuln', 'fixed'].includes(data.mode) ? data.mode : chatMode;
      if (responseMode !== chatMode) {
        setLoading(false);
        void refreshChatMode();
        return;
      }
      const completedId = data.completedObjectiveId || null;
      // Conversation clearing is presentation-only. A response from the current
      // workshop generation still carries authoritative completion even when its
      // transcript epoch has been cleared in the meantime.
      if (completedId) applyServerCompletion(completedId);
      if (!chatPresentationIsCurrent()) return;
      const aiContent = responseMode === 'fixed'
        ? (typeof data.responseText === 'string' ? data.responseText : data.response || "I couldn't generate a response.")
        : markdownToHtml(data.response || "I couldn't generate a response.");
      const detected = responseMode === 'vuln' && !!data.xssDetected;

      // Use objective-complete message type when an objective was just completed (matches DPI style)
      const msgType = completedId ? 'objective-complete' : 'ai';
      const aiMsg = {
        id: nextIdRef.current++,
        type: msgType,
        content: aiContent,
        timestamp: new Date(),
        raw: responseMode === 'vuln',
        mode: responseMode,
        objectiveId: completedId || undefined,
        toolActivity: Array.isArray(data.toolActivity) ? data.toolActivity : [],
      };
      const withAi = [...(tabMessages.current[exerciseId] || updatedMessages), aiMsg, ...judgmentMessages(data.judgments)];
      if (activeExerciseRef.current === exerciseId) setMessages(withAi);
      tabMessages.current[exerciseId] = withAi;

      if (detected) {
        if (activeExerciseRef.current === exerciseId) setXssDetected(true);
        tabXssDetected.current[exerciseId] = true;
        toast.error('⚡ XSS Executed!', { autoClose: 3000 });
      }
    } catch (err) {
      if (!chatPresentationIsCurrent()) return;
      if (err.response?.status === 409 && err.response?.data?.code === 'XSS_MODE_STALE') {
        setLoading(false);
        void refreshChatMode();
        appendScenarioMessages(exerciseId, [{ id: nextIdRef.current++, type: 'system', content: 'The workshop mode changed. Check the selected mode and try again.', timestamp: new Date(), plain: true }]);
        return;
      }
      const errText = err.response?.data?.error || err.message || 'Request failed.';
      const errMsg = {
        id: nextIdRef.current++,
        type: 'system',
        content: `Error: ${errText}`,
        timestamp: new Date(),
      };
      const withErr = [...(tabMessages.current[exerciseId] || updatedMessages), errMsg];
      if (activeExerciseRef.current === exerciseId) setMessages(withErr);
      tabMessages.current[exerciseId] = withErr;
      setDrafts(previous => previous[exerciseId] ? previous : { ...previous, [exerciseId]: text });
      toast.error(errText);
    } finally {
      interactionControllers.current.delete(controller);
      if (chatPresentationIsCurrent()) setLoading(false);
    }
  };

  const handleKeyPress = (e) => {
    if (e.key === 'Enter' && !e.shiftKey && !e.nativeEvent?.isComposing && e.keyCode !== 229) {
      e.preventDefault();
      handleSend(e);
    }
  };

  const requestProfileReset = () => {
    if (!ownerIsCurrent() || profileResetPendingRef.current || profileResetConfirmation) return;
    setProfileResetConfirmation({ ownerRevision, originScenario: exerciseId,
      status: 'confirming', error: '' });
  };

  const confirmProfileReset = async () => {
    const request = profileResetConfirmation;
    if (!request || profileResetPendingRef.current || !ownerIsCurrent()
        || request.ownerRevision !== ownerRevision) return;
    profileResetPendingRef.current = true;
    setProfileResetConfirmation({ ...request, status: 'resetting', error: '' });
    try {
      await axios.post('/api/workshop/xss/profile/reset');
      if (!ownerIsCurrent() || request.ownerRevision !== ownerRevision) return;
      // Profile reset retires stored presentation, not earned objective progress.
      for (const scope of ['stored_user', 'stored_llm']) {
        conversationGeneration.current[scope] = (conversationGeneration.current[scope] || 0) + 1;
        tabXssDetected.current[scope] = false;
      }
      if (['stored_user', 'stored_llm'].includes(activeExerciseRef.current)) {
        setXssDetected(false);
        setLoading(false);
      }
      const sysMsg = {
        id: nextIdRef.current++,
        type: 'system',
        content: '✅ Profile has been reset to defaults.',
        timestamp: new Date(),
      };
      appendScenarioMessages(request.originScenario, [sysMsg]);
      toast.success('Profile reset successfully.');
      setProfileResetConfirmation(null);
    } catch (err) {
      if (!ownerIsCurrent() || request.ownerRevision !== ownerRevision) return;
      const message = err.response?.data?.error || 'Failed to reset profile.';
      setProfileResetConfirmation({ ...request, status: 'failed', error: message });
      toast.error(message);
    } finally {
      if (ownerIsCurrent() && request.ownerRevision === ownerRevision) {
        profileResetPendingRef.current = false;
      }
    }
  };

  const handleResetProgress = async () => {
    await axios.post('/api/workshop/xss/progress/reset');
    if (!ownerIsCurrent()) return;
    interactionGeneration.current += 1;
    setLoading(false);
    setEmailSendStatus(null);
    setEmailSendError('');
    setCompletedObjectives(previous => ({ ...previous, ...Object.fromEntries(summaryObjectiveIds.map(id => [id, false])) }));
    setXssDetected(false);
    tabXssDetected.current = { reflected: false, stored_user: false, stored_llm: false, email: false };
    firstMessageSent.current = { reflected: false, stored_user: false, stored_llm: false, email: false };
    tabMessages.current = { reflected: [], stored_user: [], stored_llm: [], email: [] };
    setMessages([]);
    nextIdRef.current = 1;
    toast.success('XSS chat progress reset. Email Template Builder progress is preserved.');
  };

  const TAB_OBJECTIVES = {
    reflected:   ['xss_r1', 'xss_r2', 'xss_r3'],
    stored_user: ['xss_s1', 'xss_s2', 'xss_s3'],
    stored_llm:  ['xss_g1', 'xss_g2', 'xss_g3'],
    email:       ['xss_e1', 'xss_e2', 'xss_e3'],
    email_builder: ['xss_email_level_1', 'xss_email_level_2', 'xss_email_level_3', 'xss_email_level_4'],
  };

  const handleResetTabProgress = async (tabExerciseId) => {
    await axios.post('/api/workshop/xss/progress/reset-tab', { exerciseId: tabExerciseId });
    if (!ownerIsCurrent()) return;
    interactionGeneration.current += 1;
    setLoading(false);
    setEmailSendStatus(null);
    setEmailSendError('');
    const tabObjIds = TAB_OBJECTIVES[tabExerciseId] || [];
    tabXssDetected.current[tabExerciseId] = false;
    setCompletedObjectives(prev => {
      const updated = { ...prev };
      tabObjIds.forEach(id => { updated[id] = false; });
      return updated;
    });
    if (tabExerciseId === exerciseId) {
      setXssDetected(false);
      firstMessageSent.current[tabExerciseId] = false;
      tabMessages.current[tabExerciseId] = [];
      setMessages([]);
    }
    toast.success(`Progress reset for ${TABS.find(t => t.exerciseId === tabExerciseId)?.label || tabExerciseId}`);
  };

  const requestProgressReset = (scope, tabExerciseId = null) => {
    if (!ownerIsCurrent() || progressResetPendingRef.current) return;
    setProgressResetConfirmation({ scope, tabExerciseId, ownerRevision, status: 'confirming', error: '' });
  };

  const confirmProgressReset = async () => {
    const request = progressResetConfirmation;
    if (!request || progressResetPendingRef.current || !ownerIsCurrent()
        || request.ownerRevision !== ownerRevision) return;
    progressResetPendingRef.current = true;
    setResettingProgress(true);
    setProgressResetConfirmation({ ...request, status: 'resetting', error: '' });
    try {
      if (request.scope === 'tab') await handleResetTabProgress(request.tabExerciseId);
      else await handleResetProgress();
      if (ownerIsCurrent() && request.ownerRevision === ownerRevision) setProgressResetConfirmation(null);
    } catch (err) {
      if (!ownerIsCurrent() || request.ownerRevision !== ownerRevision) return;
      const message = err.response?.data?.error || (request.scope === 'tab'
        ? 'Failed to reset tab progress.' : 'Failed to reset progress.');
      setProgressResetConfirmation({ ...request, status: 'failed', error: message });
      toast.error(message);
    } finally {
      if (ownerIsCurrent() && request.ownerRevision === ownerRevision) {
        progressResetPendingRef.current = false;
        setResettingProgress(false);
      }
    }
  };

  const handleViewSolution = async (exerciseId) => {
    if (!ownerIsCurrent()) return;
    if (solutionContent[exerciseId]) {
      setShowSolution(prev => ({ ...prev, [exerciseId]: !prev[exerciseId] }));
      return;
    }
    try {
      const res = await axios.get(`/api/solutions/xss-workshop/${exerciseId}`);
      if (!ownerIsCurrent()) return;
      setSolutionContent(prev => ({ ...prev, [exerciseId]: res.data.solution || res.data }));
      setShowSolution(prev => ({ ...prev, [exerciseId]: true }));
    } catch (err) {
      if (!ownerIsCurrent()) return;
      if (err.response?.status === 403) {
        toast.warning('Solutions are disabled by your instructor.');
      } else {
        toast.error('Solutions not available right now.');
      }
    }
  };

  const handleViewObjectiveSolution = async (objectiveId) => {
    if (!ownerIsCurrent() || !visibleObjectiveIds.has(objectiveId)) return;
    const modalGeneration = progressGuard.begin('solutionModal');
    pendingObjectiveSolutionRef.current = objectiveId;
    try {
      const res = await axios.get(`/api/solutions/xss-workshop/objective/${objectiveId}`);
      if (!ownerIsCurrent()) return;
      progressGuard.commit('solutionModal', modalGeneration, () => {
        pendingObjectiveSolutionRef.current = null;
        setViewingObjectiveSolution({ objectiveId, ...res.data.solution });
      });
    } catch (err) {
      if (!ownerIsCurrent() || err.code === 'STALE_RECONCILIATION') return;
      if (err.response?.status === 403) {
        toast.warning('Solutions are disabled by your instructor.');
      } else {
        toast.error('Solution not available right now.');
      }
    } finally {
      if (ownerIsCurrent() && progressGuard.capture('solutionModal') === modalGeneration) {
        pendingObjectiveSolutionRef.current = null;
      }
    }
  };

  const closeObjectiveSolution = () => {
    pendingObjectiveSolutionRef.current = null;
    progressGuard.mark('solutionModal');
    setViewingObjectiveSolution(null);
  };

  const handleResetConversation = () => {
    setDrafts(previous => ({ ...previous, [exerciseId]: '' }));
    conversationGeneration.current[exerciseId] = (conversationGeneration.current[exerciseId] || 0) + 1;
    tabMessages.current[exerciseId] = [];
    setMessages([]);
    setLoading(false);
    setXssDetected(false);
    tabXssDetected.current[exerciseId] = false;
    nextIdRef.current += 1;
    toast.info('Conversation cleared. Progress is kept.');
  };

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text).then(() => toast.info('Copied to clipboard!')).catch(() => {});
  };

  // Computed progress
  const visibleObjectiveCount = visibleObjectiveIds.size;
  const completedCount = [...visibleObjectiveIds].filter(id => completedObjectives[id]).length;
  const progressPct = visibleObjectiveCount > 0
    ? Math.round((completedCount / visibleObjectiveCount) * 100)
    : 0;
  const allComplete = visibleObjectiveCount > 0 && completedCount === visibleObjectiveCount;

  // Tab-level completion badge
  const tabCompleted = (tab) => tab.objectives.length > 0
    && tab.objectives.every(o => completedObjectives[o.id]);

  const renderSolution = (sol) => {
    if (!sol) return null;
    if (typeof sol === 'string') return <p style={{ fontSize: '0.9rem', color: '#444', lineHeight: 1.6 }}>{sol}</p>;
    return (
      <div>
        {sol.hints && sol.hints.length > 0 && (
          <div style={{ marginBottom: '1rem' }}>
            <SectionTitle style={{ fontSize: '0.88rem', marginBottom: '0.5rem' }}><FiZap size={14} /> Progressive Hints</SectionTitle>
            {sol.hints.map((h, i) => (
              <HintItem key={i}>
                <span style={{ fontWeight: 700, color: '#b7791f', marginRight: '0.4rem' }}>Hint {i + 1}:</span>{h}
              </HintItem>
            ))}
          </div>
        )}
        {sol.examples && sol.examples.length > 0 && (
          <div style={{ marginBottom: '1rem' }}>
            <SectionTitle style={{ fontSize: '0.88rem', marginBottom: '0.5rem' }}><FiCode size={14} /> Example Prompts</SectionTitle>
            {sol.examples.map((ex, i) => (
              <div key={i} style={{ marginBottom: '0.75rem', background: '#f7fafc', border: '1px solid #e2e8f0', borderRadius: '8px', padding: '0.75rem' }}>
                <code style={{ display: 'block', marginBottom: '0.4rem', color: '#e53e3e', fontSize: '0.82rem', wordBreak: 'break-all' }}>
                  {typeof ex === 'string' ? ex : ex.payload}
                </code>
                {ex.explanation && (
                  <p style={{ margin: '0 0 0.5rem', fontSize: '0.8rem', color: '#666', lineHeight: 1.5 }}>{ex.explanation}</p>
                )}
                <button
                  onClick={() => copyToClipboard(typeof ex === 'string' ? ex : ex.payload)}
                  style={{
                    fontSize: '0.75rem', color: '#667eea', background: 'none',
                    border: '1px solid #667eea', borderRadius: '4px',
                    padding: '2px 8px', cursor: 'pointer', display: 'inline-flex', alignItems: 'center', gap: '3px',
                  }}
                >
                  <FiCopy size={11} /> Try this
                </button>
              </div>
            ))}
          </div>
        )}
        {sol.approach && (
          <div style={{ marginBottom: '0.75rem' }}>
            <SectionTitle style={{ fontSize: '0.88rem', marginBottom: '0.5rem' }}><FiTarget size={14} /> Approach</SectionTitle>
            <p style={{ fontSize: '0.88rem', color: '#555', lineHeight: 1.6, margin: 0 }}>{sol.approach}</p>
          </div>
        )}
        {sol.tips && sol.tips.length > 0 && (
          <div>
            <SectionTitle style={{ fontSize: '0.88rem', marginBottom: '0.5rem' }}><FiActivity size={14} /> Tips</SectionTitle>
            <ul style={{ margin: 0, paddingLeft: '1.25rem', fontSize: '0.88rem', color: '#555', lineHeight: 1.7 }}>
              {sol.tips.map((t, i) => <li key={i}>{t}</li>)}
            </ul>
          </div>
        )}
      </div>
    );
  };

  const showResetProfile = exerciseId === 'stored_user' || exerciseId === 'stored_llm';

  const tabIcon = (tab) => {
    if (tab.id === 'email') return <FiMail size={14} />;
    if (tab.id === 'email_builder') return <FiMail size={14} />;
    if (tab.id === 'reflected') return <FiZap size={14} />;
    return <FiCode size={14} />;
  };

  return (
    <MotionConfig reducedMotion="user"><VulnerabilityTemplate
      challengeId={CHALLENGE_KEY}
      icon={FiCode}
      hideSidePanel={true}
    >
      <MultiScenarioWorkshop definition={xssWorkshopExperience} activeScenarioId={currentTab.id}>
        {/* Intro */}
        <IntroSection>
          <h2><FiAlertTriangle /> About the XSS workshop</h2>
          <p>The <strong>AI assistant</strong> formats responses, manages a practice profile and summarizes email.
            Explore how untrusted input and model-generated HTML can cross into executable browser content.</p>
          <p>These deliberately vulnerable teaching workflows use the configured AI provider.
            Their weakened lab policies do not establish how an unmodified model behaves.</p>
          <p>In vulnerable chat, unsanitized HTML with executable event-handler attributes can run. Script elements inserted through innerHTML remain inert. The email builder instead previews a complete document in an isolated frame.</p>
          <div className="scenario">
            <strong>Your task:</strong> Choose a scenario, send a message, and work through its objectives. Each tab is an independent exercise. Work through the objectives in order.
            The server collects observed evidence for each attempted step, and a passing Judge verdict records completion.
            Final execution objectives require the event handler to run in the isolated qualification browser.
          </div>
        </IntroSection>

        {/* Tab Bar */}
        {navigatorDefinition && <ScenarioNavigator
          definition={navigatorDefinition}
          activeScenarioId={currentTab.id}
          onScenarioChange={(scenarioId) => switchToTab(visibleTabs.findIndex((tab) => tab.id === scenarioId))}
        />}

          {exerciseId !== 'email_builder' && <div style={{ marginTop: '1rem' }}>
            <WorkshopModeControl mode={chatMode} allowedModes={['vuln', 'fixed']}
              onChange={changeChatMode} pending={chatModePending} disabled={!chatModeResolved}
              scopeLabel="XSS chat workshop" />
            <p role="status" style={{ fontSize: '0.86rem', marginTop: '0.45rem' }}>
              {chatMode === 'fixed'
                ? 'Fixed mode displays model replies as text. Completed objectives shown below are prior workshop progress; fixed responses do not earn attack credit.'
                : 'Vulnerable mode renders assistant HTML so the XSS teaching sinks can execute.'}
            </p>
          </div>}
        {exerciseId !== 'email_builder' && <ProviderStatus role="status" $ready={llmStatus.available === true && llmStatus.provider !== 'mock'}>
          {llmStatus.available === null ? <span>Checking AI availability…</span>
            : llmStatus.provider === 'mock' ? <span><FiAlertTriangle /> Controlled response provider — not a genuine model run</span>
            : llmStatus.available ? <>
              <span><FiCheckCircle /> {llmStatus.providerName || ({ ollama: 'Ollama', openai: 'OpenAI', anthropic: 'Anthropic', bedrock: 'Bedrock' }[llmStatus.provider]) || 'AI'} actor available{llmStatus.model ? <> — model: <strong>{llmStatus.model}</strong></> : ' — Model information unavailable'}</span>
              <small>Actor availability does not confirm Judge readiness. Objective credit requires a successful Judge assessment of genuine model output and the required evidence.</small>
              {llmStatus.availableModels?.length > 0 && <small>Available models: {llmStatus.availableModels.slice(0, 6).join(', ')}{llmStatus.availableModels.length > 6 ? '…' : ''}</small>}
            </> : <><span><FiAlertTriangle /> {llmStatus.refreshFailed ? 'Could not refresh AI availability' : 'AI unavailable'}</span><small>Check the configured service and reload to try again.</small></>}
        </ProviderStatus>}
        {visibleTabs.some(tab => tab.id === 'email_builder') && <ScenarioWorkspace scenarioId="email_builder" activeScenarioId={currentTab.id}>
          <XssEmailBuilder key={ownerRevision}
            active={exerciseId === 'email_builder'}
            objectives={visibleTabs.find(tab => tab.id === 'email_builder').objectives}
            revision={revision}
            onProgressChange={handleBuilderProgress}
          />
        </ScenarioWorkspace>}
        {exerciseId !== 'email_builder' && <ScenarioWorkspace scenarioId={currentTab.id} activeScenarioId={currentTab.id}>
        {/* Email Setup Panel — full-width, only on email tab */}
        {exerciseId === 'email' && (
          <div style={{
            background: 'white', border: '2px solid #e9ecef', borderRadius: '16px',
            padding: '1.5rem 2rem', boxShadow: '0 4px 20px rgba(0,0,0,0.08)',
          }}>
            <div style={{ fontWeight: 700, fontSize: '1rem', color: '#334155', marginBottom: '1.25rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <FiMail size={16} style={{ color: '#667eea' }} />
              Step 2: Send from {emailConfig.sender || 'the workshop sender'} to Your Workshop Inbox
            </div>

            <EmailSetupGrid>
              {/* Left: email input */}
              <div>
                <label style={{ display: 'block', fontSize: '0.82rem', fontWeight: 600, color: '#475569', marginBottom: '0.4rem' }}>
                  Your workshop inbox (To)
                </label>
                <input
                  type="email"
                  value={sharklaserEmail}
                  onChange={e => {
                    if (!emailConfig.editable) return;
                    externalEmailEditedRef.current = true;
                    setSharklaserEmail(e.target.value);
                  }}
                  readOnly={!emailConfig.editable}
                  placeholder={emailConfig.resolved ? 'No workshop inbox configured' : 'Loading workshop inbox…'}
                  style={{
                    width: '100%', boxSizing: 'border-box', padding: '0.5rem 0.75rem',
                    border: '1px solid #cbd5e0', borderRadius: '8px', fontSize: '0.875rem',
                    fontFamily: 'monospace', outline: 'none', background: '#f8fafc',
                  }}
                />
                <div style={{ fontSize: '0.75rem', color: '#94a3b8', marginTop: '0.3rem' }}>
                  {emailConfig.mode === 'local'
                    ? 'Private local inbox assigned to your signed-in workshop account.'
                    : emailConfig.mode === 'external'
                      ? 'External inbox configured for this workshop account.'
                      : 'Resolving your workshop mail configuration…'}
                </div>
                {emailConfig.mode === 'external' && <div style={{
                  fontSize: '0.75rem', color: '#92400e', background: 'rgba(255,193,7,0.12)',
                  border: '1px solid #f59e0b', borderRadius: '6px', padding: '0.45rem 0.6rem', marginTop: '0.45rem',
                }}>
                  ⚠️ Use your <strong>base SharkLasers address</strong> (e.g. <code>nalkcepz@sharklasers.com</code>) —
                  <strong> not the “+alias” address</strong> SharkLasers shows you
                  (e.g. <code>y17gk6+3go9kepz7a638@sharklasers.com</code>). The alias form is a different inbox and the
                  attack email won’t be retrievable, so the summarize step won’t fire.
                </div>}
                {emailConfig.mode === 'external' && /[+]/.test(sharklaserEmail.split('@')[0] || '') && (
                  <div style={{
                    fontSize: '0.75rem', color: '#b91c1c', background: 'rgba(239,68,68,0.1)',
                    border: '1px solid #ef4444', borderRadius: '6px', padding: '0.45rem 0.6rem', marginTop: '0.4rem',
                    display: 'flex', alignItems: 'flex-start', gap: '0.4rem',
                  }}>
                    <span>🚫</span>
                    <span>
                      That looks like a <strong>+alias</strong> address. Remove the <code>+…</code> part and use just the
                      base username{sharklaserEmail.includes('@') ? <> — try <code>{sharklaserEmail.split('@')[0].split('+')[0]}@{sharklaserEmail.split('@')[1]}</code></> : ''}.
                    </span>
                  </div>
                )}
                {emailConfig.mode === 'external' && <a
                  href="https://www.sharklasers.com/"
                  target="_blank"
                  rel="noopener noreferrer"
                  style={{
                    display: 'inline-flex', alignItems: 'center', gap: '0.3rem',
                    marginTop: '0.4rem', fontSize: '0.78rem', fontWeight: 600,
                    color: '#667eea', textDecoration: 'none',
                  }}
                >
                  <FiExternalLink size={12} /> Open SharkLasers.com
                </a>}
                {emailConfig.provider === 'mailpit' && emailConfig.mailpitInboxUrl && <a
                  href={emailConfig.mailpitInboxUrl}
                  target="_blank"
                  rel="noopener noreferrer"
                  style={{
                    display: 'inline-flex', alignItems: 'center', gap: '0.3rem',
                    marginTop: '0.4rem', fontSize: '0.78rem', fontWeight: 600,
                    color: '#667eea', textDecoration: 'none',
                  }}
                >
                  <FiExternalLink size={12} /> Open Mailpit inbox
                </a>}

                <div style={{ marginTop: '1.25rem', display: 'flex', alignItems: 'center', gap: '0.75rem', flexWrap: 'wrap' }}>
                  <button
                    onClick={handleSendAttackEmail}
                    disabled={!emailConfig.resolved || !sharklaserEmail || emailSendStatus === 'sending' || emailSendStatus === 'sent' || (XSS_EMAIL_PAYLOADS[selectedPayload]?.id === 'custom' && !customPayload.trim())}
                    style={{
                      padding: '0.5rem 1.25rem', fontSize: '0.875rem', fontWeight: 700,
                      background: emailSendStatus === 'sent' ? '#22c55e' : '#667eea',
                      color: 'white', border: 'none', borderRadius: '8px',
                      cursor: (!emailConfig.resolved || !sharklaserEmail || emailSendStatus === 'sending' || emailSendStatus === 'sent') ? 'not-allowed' : 'pointer',
                      opacity: (!emailConfig.resolved || !sharklaserEmail || emailSendStatus === 'sending' || (XSS_EMAIL_PAYLOADS[selectedPayload]?.id === 'custom' && !customPayload.trim())) ? 0.65 : 1,
                      display: 'flex', alignItems: 'center', gap: '0.4rem',
                      boxShadow: '0 2px 8px rgba(102,126,234,0.3)',
                    }}
                  >
                    <FiMail size={14} />
                    {emailSendStatus === 'sending' ? 'Sending…' : emailSendStatus === 'sent' ? '✓ Sent!' : 'Send Email'}
                  </button>
                  {emailSendStatus === 'sent' && (
                    <span style={{ fontSize: '0.82rem', color: '#22c55e', fontWeight: 600 }}>
                      {emailConfig.mode === 'local'
                        ? 'Local SMTP accepted the message. Ask the AI to check your workshop inbox.'
                        : 'SMTP accepted. Wait for it to reach your inbox, then ask the AI to summarize it.'}
                    </span>
                  )}
                  {emailSendStatus === 'error' && (
                    <span style={{ fontSize: '0.82rem', color: '#e53e3e' }}>
                      {emailSendError || 'Email submission failed.'}
                    </span>
                  )}
                </div>
              </div>

              {/* Right: payload selector */}
              <div>
                <label style={{ display: 'block', fontSize: '0.82rem', fontWeight: 600, color: '#475569', marginBottom: '0.5rem' }}>
                  XSS Payload
                </label>

                {/* Dropdown */}
                <select
                  value={selectedPayload}
                  onChange={e => { setSelectedPayload(Number(e.target.value)); setEmailSendStatus(null); }}
                  style={{
                    width: '100%', padding: '0.5rem 0.75rem', borderRadius: '8px',
                    border: '1.5px solid #cbd5e0', fontSize: '0.875rem', fontWeight: 600,
                    color: '#334155', background: '#f8fafc', cursor: 'pointer',
                    outline: 'none', appearance: 'auto',
                  }}
                >
                  {XSS_EMAIL_PAYLOADS.map((p, i) => (
                    <option key={p.id} value={i}>{p.name}</option>
                  ))}
                </select>

                {/* Code preview (hidden for Custom) */}
                {XSS_EMAIL_PAYLOADS[selectedPayload]?.id !== 'custom' && (
                  <div style={{
                    marginTop: '0.5rem', padding: '0.45rem 0.65rem',
                    background: '#1e1e2e', borderRadius: '6px', overflowX: 'auto',
                  }}>
                    <code style={{ fontSize: '0.78rem', color: '#f07070', fontFamily: 'monospace', whiteSpace: 'nowrap' }}>
                      {XSS_EMAIL_PAYLOADS[selectedPayload]?.code}
                    </code>
                  </div>
                )}

                {/* Description */}
                <div style={{
                  marginTop: '0.5rem', padding: '0.55rem 0.75rem',
                  background: 'rgba(102,126,234,0.07)', border: '1px solid rgba(102,126,234,0.2)',
                  borderRadius: '8px', fontSize: '0.78rem', color: '#475569', lineHeight: 1.5,
                }}>
                  <span style={{ fontWeight: 700, color: '#667eea' }}>How it works: </span>
                  {XSS_EMAIL_PAYLOADS[selectedPayload]?.description}
                </div>

                {/* Custom payload textarea */}
                {XSS_EMAIL_PAYLOADS[selectedPayload]?.id === 'custom' && (
                  <textarea
                    value={customPayload}
                    onChange={e => setCustomPayload(e.target.value)}
                    placeholder="<img src=x onerror=alert(1)>"
                    rows={3}
                    style={{
                      marginTop: '0.5rem', width: '100%', boxSizing: 'border-box',
                      padding: '0.5rem 0.75rem', borderRadius: '8px',
                      border: '1.5px solid #cbd5e0', fontSize: '0.8rem',
                      fontFamily: 'monospace', color: '#e53e3e', resize: 'vertical',
                      background: '#1e1e2e', outline: 'none',
                    }}
                  />
                )}
              </div>
            </EmailSetupGrid>
          </div>
        )}

        {/* Two-column: Chat | Objectives */}
        {exerciseId !== 'email_builder' && <TwoColumnLayout>
          {/* Chat Panel */}
          <ChatSection>
            <ChatHeader>
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
                  {llmStatus.available === true && llmStatus.provider !== 'mock' && <StatusIndicator $available />}
                  <h3><FiCode /> {currentTab.label} — {llmStatus.providerName || ({ ollama: 'Ollama', openai: 'OpenAI', anthropic: 'Anthropic', bedrock: 'Bedrock' }[llmStatus.provider]) || 'AI Model'}</h3>
                </div>
                <div style={{ fontSize: '0.85rem', opacity: 0.95, marginTop: '0.4rem' }}>Exercise: {currentTab.objectives.find(obj => !completedObjectives[obj.id])?.label || (currentTab.objectives.length ? 'All objectives completed!' : 'No objectives available')}</div>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
                <ScopedResetButton label="Reset conversation" onClick={handleResetConversation} />
                {showResetProfile && (
                  <ScopedResetButton label="Reset Profile" onClick={requestProfileReset}
                    disabled={Boolean(profileResetConfirmation)} />
                )}
              </div>
            </ChatHeader>

            {exerciseId === 'reflected' && (
              <div style={{
                display: 'flex', flexWrap: 'wrap', gap: '0.4rem', padding: '0.6rem 1rem',
                background: 'linear-gradient(135deg, rgba(102,126,234,0.06), rgba(118,75,162,0.06))',
                borderBottom: '1px solid #e9ecef',
              }}>
                <span style={{ fontSize: '0.75rem', color: '#64748b', fontWeight: 600, alignSelf: 'center', marginRight: '0.25rem' }}>Try:</span>
                {[
                  { label: 'Styled heading', prompt: 'Format the following as a styled heading with a colored underline: Welcome to the Security Workshop' },
                  { label: 'Bulleted list', prompt: 'Turn this into a styled bulleted list: Reconnaissance, Scanning, Exploitation, Post-Exploitation, Reporting' },
                  { label: 'Callout card', prompt: 'Style this as an info callout card with a blue left border: Cross-Site Scripting (XSS) allows attackers to inject client-side scripts into web pages viewed by other users.' },
                  { label: 'Blockquote', prompt: 'Format this as an elegant blockquote: The only truly secure system is one that is powered off, cast in a block of concrete and sealed in a lead-lined room.' },
                  { label: 'Highlight keywords', prompt: 'Highlight the security terms in this text: SQL injection and XSS are among the OWASP Top 10 vulnerabilities that affect web applications.' },
                  { label: 'Code block', prompt: 'Format this as a styled code block: const sanitize = (input) => input.replace(/</g, "&lt;").replace(/>/g, "&gt;");' },
                ].map((chip) => (
                  <button
                    key={chip.label}
                    type="button"
                    onClick={() => setInputMessage(chip.prompt)}
                    style={{
                      padding: '0.3rem 0.65rem', fontSize: '0.73rem', fontWeight: 600,
                      background: 'white', border: '1px solid #cbd5e1', borderRadius: '999px',
                      color: '#475569', cursor: 'pointer', transition: 'all 0.15s',
                      whiteSpace: 'nowrap',
                    }}
                    onMouseEnter={e => { e.target.style.background = '#667eea'; e.target.style.color = 'white'; e.target.style.borderColor = '#667eea'; }}
                    onMouseLeave={e => { e.target.style.background = 'white'; e.target.style.color = '#475569'; e.target.style.borderColor = '#cbd5e1'; }}
                  >
                    {chip.label}
                  </button>
                ))}
              </div>
            )}

            <ChatActivityTabs key={exerciseId} activity={messages.flatMap(message => (message.toolActivity || []).map(entry => ({ ...entry, id: `${message.id}:${entry.id}` })))}>
            <ChatContainer>
              <MessageList ref={messageListRef} onScroll={event => { const el = event.currentTarget; followOutput.current = el.scrollHeight - el.scrollTop - el.clientHeight < 80; }}>
                <AnimatePresence initial={false}>
                  {messages.map(msg => (
                    <MessageBubble
                      key={msg.id}
                      className={msg.type}
                      initial={{ opacity: 0, y: 10 }}
                      animate={{ opacity: 1, y: 0 }}
                      transition={{ duration: 0.25 }}
                    >
                      <div
                        className={`message-icon ${
                          msg.type === 'user' ? 'user-avatar' :
                          msg.type === 'system' ? 'system-avatar' :
                          msg.type === 'objective-complete' ? 'success-avatar' :
                          'ai-avatar'
                        }`}
                        style={msg.type === 'objective-complete' ? { background: 'linear-gradient(135deg, #48bb78, #38a169)', color: 'white' } : {}}
                      >
                        {msg.type === 'user' ? <FiUser /> :
                         msg.type === 'system' ? <FiShield /> :
                         msg.type === 'objective-complete' ? <FiCheckCircle /> :
                         <FiMessageSquare />}
                      </div>
                      <div className="message-content">
                        <div className="message-header">
                          {msg.type === 'user' ? 'You' :
                           msg.type === 'system' ? 'System' :
                           msg.type === 'objective-complete' ? '✅ AI (Objective Completed)' :
                           'AI Assistant'}
                          {' • '}{msg.timestamp.toLocaleTimeString()}
                        </div>
                        {(msg.type === 'ai' || msg.type === 'objective-complete') && msg.raw && chatMode === 'vuln' ? (
                          // THE XSS VECTOR — renders HTML from AI response
                          <div
                            className="message-text"
                            dangerouslySetInnerHTML={{ __html: msg.content }}
                          />
                        ) : (
                          <div className="message-text">{msg.content}</div>
                        )}
                        <JudgeRetryButton
                          evaluationId={msg.evaluationId}
                          canRetry={msg.canRetry}
                          onResult={(data, options) => handleJudgeRetryResult(exerciseId, data, options)}
                        />
                      </div>
                    </MessageBubble>
                  ))}
                </AnimatePresence>
                {loading && (
                  <MessageBubble
                    className="ai"
                    initial={{ opacity: 0, y: 10 }}
                    animate={{ opacity: 1, y: 0 }}
                  >
                    <div className="message-icon ai-avatar"><FiMessageSquare /></div>
                    <div className="message-content">
                      <div className="message-text" style={{ color: '#888', fontStyle: 'italic' }}>Thinking…</div>
                    </div>
                  </MessageBubble>
                )}
              </MessageList>

              {/* XSS Banner */}
              <AnimatePresence>
                {xssDetected && (
                  <XSSBanner
                    initial={{ opacity: 0, y: 10, scale: 0.97 }}
                    animate={{ opacity: 1, y: 0, scale: 1 }}
                    exit={{ opacity: 0, scale: 0.97 }}
                    transition={{ duration: 0.3 }}
                  >
                    <FiZap size={16} />
                    ⚡ XSS Executed! The injected script ran in the browser.
                  </XSSBanner>
                )}
              </AnimatePresence>

              <InputRow onSubmit={handleSend}>
                <Input
                  value={inputMessage}
                  onChange={e => setInputMessage(e.target.value)}
                  onKeyDown={handleKeyPress}
                  aria-label="Message the XSS assistant"
                  placeholder={`Message the XSS assistant (${currentTab.label})…`}
                  disabled={loading || !chatModeResolved || chatModePending}
                  rows={1}
                />
                <SendButton
                  type="submit"
                  aria-label="Send message"
                  disabled={loading || !inputMessage.trim() || !chatModeResolved || chatModePending}
                  whileHover={{ scale: 1.05 }}
                  whileTap={{ scale: 0.95 }}
                >
                  <FiSend size={16} />
                </SendButton>
              </InputRow>
            </ChatContainer>
            </ChatActivityTabs>
          </ChatSection>

          {/* Right column: Objectives + Progress + Solution */}
          <Panel>
            <PanelHeader>
              <h3><FiTarget size={16} /> Exercise Objectives</h3>
            </PanelHeader>

            {/* Current tab objectives */}
            <div style={{ marginBottom: '0.5rem' }}>
              {currentTab.objectives.map((obj, idx) => {
                const done = !!completedObjectives[obj.id];
                return (
                  <ObjectiveItem
                    key={obj.id}
                    $completed={done}
                    $active={obj.id === currentTab.objectives.find(item => !completedObjectives[item.id])?.id}
                    initial={{ opacity: 0, x: -8 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: idx * 0.06 }}
                  >
                    {done && <div className="status-badge">DONE</div>}
                    <div className="obj-icon">
                      {done ? <FiCheckCircle size={14} /> : <FiTarget size={14} />}
                    </div>
                    <div className="obj-content">
                      <div className="obj-name">{obj.label}</div>
                      <div className="obj-desc">{obj.description}</div>
                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem' }}>
                        {hintsEnabled[obj.id] === true && <HintPanel workshopKey="xss_workshop" objective={{ title: obj.label }} objectiveId={obj.id} revision={hintRefreshRevision} />}
                        <ObjectiveHelpActions objectiveId={obj.id} hintVisible={false}
                          solutionVisible={solutionsEnabled[obj.id] === true}
                          activeKind={viewingObjectiveSolution?.objectiveId === obj.id ? 'solution' : undefined}
                          onOpen={(_kind, objectiveId) => handleViewObjectiveSolution(objectiveId)} />
                      </div>
                    </div>
                  </ObjectiveItem>
                );
              })}
            </div>

            <div aria-label="Scenario progress" style={{ marginTop: '1rem', marginBottom: '1rem' }}>
              <h3 style={{ fontSize: '1.1rem', fontWeight: 600 }}>Progress</h3>
              <p style={{ fontSize: '0.95rem', color: '#666' }}>{currentTab.objectives.filter(obj => completedObjectives[obj.id]).length} of {currentTab.objectives.length} objectives completed in this scenario</p>
            </div>
            {/* Reset Above Objectives (formerly Reset This Tab) */}
            <ScopedResetButton label="Reset Above Objectives"
              onClick={() => requestProgressReset('tab', exerciseId)} disabled={resettingProgress} />

            {/* Overall progress */}
            <ProgressBlock>
              <div className="progress-title"><FiActivity size={15} /> Overall Progress</div>
              <div className="progress-text">{completedCount} of {visibleObjectiveCount} objectives completed</div>
              <div className="progress-bar-track" role="progressbar" aria-label="Overall XSS progress" aria-valuemin={0} aria-valuemax={visibleObjectiveCount} aria-valuenow={completedCount}>
                <motion.div
                  className="progress-bar-fill"
                  initial={{ width: 0 }}
                  animate={{ width: `${progressPct}%` }}
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
                  <FiCheckCircle size={18} /> All objectives completed!
                </motion.div>
              )}
              <ScopedResetButton label={resettingProgress ? 'Resetting…' : 'Reset Chat Progress'}
                onClick={() => requestProgressReset('all')} disabled={resettingProgress} />
            </ProgressBlock>

            {/* Tab overview */}
            <div style={{ marginTop: '1.25rem', paddingTop: '1.25rem', borderTop: '2px solid #e9ecef' }}>
              <SectionTitle><FiCode size={14} /> All Exercises</SectionTitle>
              {visibleTabs.map((tab, idx) => {
                const doneCount = tab.objectives.filter(o => completedObjectives[o.id]).length;
                const total = tab.objectives.length;
                const pct = total > 0 ? Math.round((doneCount / total) * 100) : 0;
                return (
                  <div
                    key={tab.id}
                    role="button" tabIndex={0}
                    onKeyDown={event => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); switchToTab(idx); } }}
                    onClick={() => switchToTab(idx)}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: '0.75rem',
                      padding: '0.6rem 0.75rem',
                      marginBottom: '0.4rem',
                      borderRadius: '8px',
                      background: activeTab === idx ? 'rgba(102, 126, 234, 0.08)' : '#f8f9fa',
                      border: `1px solid ${activeTab === idx ? '#667eea' : '#e2e8f0'}`,
                      cursor: 'pointer',
                      transition: 'all 0.2s ease',
                    }}
                  >
                    <div style={{
                      flexShrink: 0,
                      width: 28,
                      height: 28,
                      borderRadius: '50%',
                      background: total > 0 && doneCount === total ? '#22c55e' : activeTab === idx ? '#667eea' : '#dee2e6',
                      color: 'white',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      fontSize: '0.75rem'
                    }}>
                      {doneCount === total ? <FiCheckCircle size={13} /> : tabIcon(tab)}
                    </div>
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ fontSize: '0.82rem', fontWeight: 600, color: '#333', marginBottom: '3px' }}>{tab.label}</div>
                      <div style={{ height: 5, background: '#e9ecef', borderRadius: 3, overflow: 'hidden' }}>
                        <div style={{ height: '100%', width: `${pct}%`, background: 'linear-gradient(90deg, #667eea, #764ba2)', borderRadius: 3, transition: 'width 0.4s ease' }} />
                      </div>
                    </div>
                    <span style={{ fontSize: '0.75rem', color: '#888', flexShrink: 0 }}>{doneCount}/{total}</span>
                  </div>
                );
              })}
            </div>
          </Panel>
        </TwoColumnLayout>}
        </ScenarioWorkspace>}
      </MultiScenarioWorkshop>

      {viewingObjectiveSolution && visibleObjectiveIds.has(viewingObjectiveSolution.objectiveId) && (
        <ObjectiveHelpModal kind="solution" appearance="legacy-light"
          objective={{ title: currentTab.objectives.find(obj => obj.id === viewingObjectiveSolution.objectiveId)?.label || viewingObjectiveSolution.title }}
          content={{
            explanation: viewingObjectiveSolution.explanation,
            tips: hintsEnabled[viewingObjectiveSolution.objectiveId] === true && viewingObjectiveSolution.hint
              ? [viewingObjectiveSolution.hint] : [],
            examples: typeof viewingObjectiveSolution.example === 'string'
              ? viewingObjectiveSolution.example.split('|||')
                .map(payload => payload.trim())
                .filter(payload => payload && !payload.startsWith('('))
                .map((payload, index) => ({ title: `Example ${index + 1}`, payload }))
              : [],
          }}
          onClose={closeObjectiveSolution}
          onUsePayload={payload => {
            copyToClipboard(payload);
            setInputMessage(payload);
            closeObjectiveSolution();
            toast.info('Copied to input field.');
          }} />
      )}
      <ResetConfirmation open={Boolean(progressResetConfirmation)}
        status={progressResetConfirmation?.status || 'idle'}
        title={progressResetConfirmation?.scope === 'tab'
          ? `Reset ${TABS.find(tab => tab.exerciseId === progressResetConfirmation.tabExerciseId)?.label || 'this scenario'} objectives?`
          : 'Reset XSS chat progress?'}
        description={progressResetConfirmation?.scope === 'tab'
          ? 'Only the selected scenario objectives are reset. Other scenario progress is preserved.'
          : 'The four chat scenarios and their local conversations are reset. Email Template Builder progress is preserved; reset it from the builder tab.'}
        error={progressResetConfirmation?.error}
        onCancel={() => { if (!progressResetPendingRef.current) setProgressResetConfirmation(null); }}
        onConfirm={confirmProgressReset} />
      <ResetConfirmation open={Boolean(profileResetConfirmation)}
        status={profileResetConfirmation?.status || 'idle'}
        title="Reset stored profile?"
        description="Your stored name, bio, and website return to their defaults. Earned XSS objective progress is preserved."
        error={profileResetConfirmation?.error}
        onCancel={() => { if (!profileResetPendingRef.current) setProfileResetConfirmation(null); }}
        onConfirm={confirmProfileReset} />
    </VulnerabilityTemplate></MotionConfig>
  );
};

export default XSSWorkshop;
