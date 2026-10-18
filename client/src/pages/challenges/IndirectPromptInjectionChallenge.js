/**
 * Indirect Prompt Injection Workshop
 * Two tabs: Document Upload (RAG) and Email Agent
 * Both demonstrate indirect prompt injection attacks.
 */
import React, { useState, useEffect, useMemo, useRef } from 'react';
import styled from 'styled-components';
import {
  FiUpload, FiMessageSquare, FiAlertTriangle, FiCheckCircle, FiFileText, FiSend, FiDownload, FiTarget, FiZap, FiMail, FiCopy, FiExternalLink, FiShield, FiEye, FiRefreshCw
} from 'react-icons/fi';
import { toast } from 'react-toastify';
import { motion } from 'framer-motion';
import axios from 'axios';
import VulnerabilityTemplate from '../../components/VulnerabilityTemplate';
import {
  MultiScenarioWorkshop,
  SafeChatBody,
  ObjectiveHelpActions,
  ResetConfirmation,
  WorkshopModeControl,
  ScenarioNavigator,
  ScenarioWorkspace,
  WorkshopButton as Button,
} from '../../components/workshop/WorkshopExperience';
import { indirectPromptInjectionExperience, workshopTokens } from '../../components/workshop/experience.mjs';
import useWorkshopResetController from '../../components/workshop/useWorkshopResetController';
import useChangePolling from '../../hooks/useChangePolling';
import useWorkshopHeartbeat from '../../hooks/useWorkshopHeartbeat';
import useReconciliationGuard, { useGuardedSetter } from '../../hooks/useReconciliationGuard';
import { useWorkshopConfig } from '../../context/WorkshopConfigContext';
import { useAuth } from '../../context/AuthContext';
import HintPanel from '../../components/HintPanel';
import ObjectiveHelpModal from '../../components/workshop/ObjectiveHelpModal';
import { normalizeSolution } from './directPromptInjectionState';
import JudgeRetryButton from '../../components/workshop/JudgeRetryButton';
import { getJudgeFeedback } from '../../utils/judgeFeedback.mjs';



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
  margin-bottom: 1rem;

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
`;

const Panel = styled.div`
  background: white;
  border: 2px solid ${workshopTokens.border};
  border-radius: ${workshopTokens.cardRadius};
  padding: 2rem;
  box-shadow: 0 4px 16px rgba(0, 0, 0, 0.05);
`;

const TheoryBox = styled.div`
  background: rgba(255, 193, 7, 0.08);
  border: 2px solid #ffc107;
  border-radius: 12px;
  padding: 1.25rem;
  margin-bottom: 2rem;
  h4 { margin: 0 0 0.5rem 0; color: #856404; display: flex; align-items: center; gap: 0.5rem; }
  p { margin: 0; color: ${workshopTokens.text}; font-size: 0.95rem; line-height: 1.6; }
`;

const ModeControl = styled.div`
  background: #f8fafc;
  border: 1px solid #cbd5e1;
  border-radius: 12px;
  padding: 1rem 1.25rem;
  margin: 0 0 1.5rem;
  .mode-description { color: ${workshopTokens.mutedText}; font-size: 0.9rem; line-height: 1.5; margin: 0 0 0.75rem; }
  .mode-error { color: #9f1239; margin-top: 0.6rem; font-size: 0.9rem; }
`;

const UploadRow = styled.div`
  display: flex;
  align-items: center;
  gap: 1rem;
  flex-wrap: wrap;
  margin-bottom: 1rem;
  input[type="file"] { max-width: 280px; }
`;



const SampleButtons = styled.div`
  display: flex;
  gap: 0.75rem;
  flex-wrap: wrap;
  margin-top: 1rem;
`;

const DownloadSection = styled.div`
  margin-top: 1.25rem;
  padding-top: 1.25rem;
  padding-bottom: 1.25rem;
  border-top: 1px solid #e9ecef;
  border-bottom: 1px solid #e9ecef;
  .download-label {
    font-size: 0.9rem;
    font-weight: 600;
    color: ${workshopTokens.mutedText};
    margin-bottom: 0.75rem;
  }
  .download-links {
    display: flex;
    flex-wrap: wrap;
    gap: 0.75rem;
    align-items: center;
  }
  a.download-link {
    display: inline-flex;
    align-items: center;
    gap: 0.4rem;
    padding: 0.5rem 1rem;
    font-size: 0.9rem;
    color: #667eea;
    text-decoration: none;
    border: 1px solid #667eea;
    border-radius: 8px;
    background: rgba(102, 126, 234, 0.06);
    transition: background 0.2s, color 0.2s;
  }
  a.download-link:hover {
    background: rgba(102, 126, 234, 0.12);
    color: #5568d3;
  }
`;

const UploadStatus = styled.div`
  margin-top: 1rem;
  padding: 0.75rem 1rem;
  background: rgba(40, 167, 69, 0.1);
  border: 1px solid #28a745;
  border-radius: 8px;
  color: #155724;
  font-size: 0.9rem;
  display: flex;
  align-items: center;
  gap: 0.5rem;
`;

const QuestionRow = styled.form`
  display: flex;
  min-width: 0;
  gap: 0.75rem;
  align-items: flex-end;
  margin-bottom: 1.5rem;
  input {
    flex: 1;
    min-width: 0;
    width: 100%;
    box-sizing: border-box;
    padding: 0.75rem 1rem;
    border: 2px solid ${workshopTokens.border};
    border-radius: 8px;
    font-size: 0.95rem;
    &:focus { outline: none; border-color: #667eea; }
  }
`;

const ChunkList = styled.div`
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
  margin-bottom: 1.5rem;
`;

const ChunkCard = styled.div`
  padding: 1rem;
  border-radius: 8px;
  border: 2px solid ${workshopTokens.border};
  background: #f8f9fa;
  font-size: 0.9rem;
  line-height: 1.5;
  white-space: pre-wrap;
  word-break: break-word;
  overflow-wrap: break-word;
  &.injected {
    border-color: #dc3545;
    background: rgba(220, 53, 69, 0.08);
  }
  .chunk-meta { font-size: 0.8rem; color: #666; margin-bottom: 0.5rem; }
  .chunk-body { white-space: pre-wrap; word-break: break-word; overflow-wrap: break-word; }
`;

const AttackBanner = styled(motion.div)`
  padding: 1rem 1.25rem;
  background: rgba(220, 53, 69, 0.12);
  border: 2px solid #dc3545;
  border-radius: 12px;
  color: #721c24;
  margin-bottom: 1.5rem;
  display: flex;
  align-items: center;
  gap: 0.75rem;
  font-weight: 600;
`;

const SuccessBanner = styled(motion.div)`
  padding: 1rem 1.25rem;
  background: rgba(40, 167, 69, 0.12);
  border: 2px solid #28a745;
  border-radius: 12px;
  color: #155724;
  margin-bottom: 1.5rem;
  display: flex;
  align-items: center;
  gap: 0.75rem;
  font-weight: 600;
`;

const AnswerBox = styled.div`
  padding: 1.25rem;
  background: #f8f9fa;
  border: 2px solid ${workshopTokens.border};
  border-radius: 12px;
  font-size: 0.95rem;
  line-height: 1.6;
  word-break: break-word;
  overflow-wrap: break-word;

  p { margin: 0 0 0.75rem 0; }
  p:last-child { margin-bottom: 0; }
  ul, ol { margin: 0.5rem 0 0.75rem 1.25rem; padding: 0; }
  li { margin-bottom: 0.25rem; }
  strong { font-weight: 600; }
  em { font-style: italic; }
  code { background: #e9ecef; border-radius: 3px; padding: 0.1em 0.35em; font-size: 0.88em; font-family: monospace; }
  pre { background: #e9ecef; border-radius: 6px; padding: 0.75rem; overflow-x: auto; margin: 0.5rem 0 0.75rem 0; }
  pre code { background: none; padding: 0; }
  h1, h2, h3 { margin: 0.75rem 0 0.4rem 0; font-weight: 600; }
  blockquote { border-left: 3px solid #667eea; margin: 0.5rem 0; padding-left: 0.75rem; color: ${workshopTokens.mutedText}; }
`;

const CurrentDocBar = styled.div`
  padding: 0.75rem 1rem;
  border-radius: 10px;
  font-size: 0.95rem;
  display: flex;
  align-items: center;
  gap: 0.5rem;
  margin-bottom: 1.5rem;
  background: ${props => props.$isEmpty ? 'rgba(108, 117, 125, 0.12)' : 'rgba(40, 167, 69, 0.1)'};
  border: 1px solid ${props => props.$isEmpty ? '#6c757d' : '#28a745'};
  color: ${props => props.$isEmpty ? '#495057' : '#155724'};
`;

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
  padding: 1rem 1.25rem;
  background: ${props => props.$completed ? 'rgba(40, 167, 69, 0.08)' : '#f8f9fa'};
  border: 2px solid ${props => props.$completed ? '#28a745' : '#e9ecef'};
  border-radius: 12px;
  transition: all 0.3s ease;
  position: relative;
  overflow: hidden;

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
    background: ${props => props.$completed ? '#28a745' : '#dee2e6'};
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
    background: ${props => props.$completed ? '#28a745' : '#dee2e6'};
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

const TwoColumnLayout = styled.div`
  display: grid;
  grid-template-columns: minmax(0, 1fr) minmax(0, 1fr);
  gap: 2rem;
  align-items: start;
  > * { min-width: 0; }
  @media (max-width: 1024px) { grid-template-columns: minmax(0, 1fr); }
`;

const EmailCard = styled.div`
  background: white;
  border: 2px solid ${workshopTokens.border};
  border-radius: 12px;
  padding: 1.5rem;
  margin: 1rem 0;

  .email-header {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
    margin-bottom: 1rem;
    padding-bottom: 1rem;
    border-bottom: 1px solid #e9ecef;
  }

  .email-field {
    display: flex;
    gap: 0.5rem;
    font-size: 0.9rem;
    .label { color: #666; font-weight: 600; min-width: 70px; }
    .value { color: ${workshopTokens.text}; }
  }

  .email-body {
    background: #f8f9fa;
    border-radius: 8px;
    padding: 1rem;
    font-size: 0.9rem;
    line-height: 1.6;
    white-space: pre-wrap;
    word-break: break-word;
  }

  .suspicious-highlight {
    background: rgba(255, 193, 7, 0.3);
    padding: 0.1rem 0.25rem;
    border-radius: 3px;
  }
`;

const InstructionPanel = styled.div`
  background: linear-gradient(135deg, rgba(23, 162, 184, 0.08), rgba(32, 201, 151, 0.08));
  border: 2px solid #17a2b8;
  border-radius: 12px;
  padding: 1.5rem;
  margin-bottom: 1.5rem;

  h4 {
    color: #0c5460;
    margin: 0 0 1rem 0;
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }

  .step {
    display: flex;
    gap: 0.75rem;
    margin-bottom: 0.75rem;
    align-items: flex-start;
  }

  .step-number {
    background: #17a2b8;
    color: white;
    width: 24px;
    height: 24px;
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 0.8rem;
    font-weight: 700;
    flex-shrink: 0;
  }

  .step-content {
    flex: 1;
    color: ${workshopTokens.text};
    font-size: 0.95rem;
    line-height: 1.5;
  }
`;

const TargetEmailBox = styled.div`
  background: rgba(102, 126, 234, 0.08);
  border: 2px solid #667eea;
  border-radius: 12px;
  padding: 1.25rem;
  margin: 1rem 0;
  display: flex;
  align-items: center;
  justify-content: space-between;
  flex-wrap: wrap;
  gap: 1rem;

  .email-display {
    font-family: monospace;
    font-size: 1.1rem;
    font-weight: 600;
    color: #667eea;
  }
`;

const ExternalLinks = styled.div`
  display: flex;
  flex-wrap: wrap;
  gap: 0.75rem;
  margin: 1rem 0;

  a {
    display: inline-flex;
    align-items: center;
    gap: 0.4rem;
    padding: 0.6rem 1rem;
    font-size: 0.9rem;
    color: white;
    text-decoration: none;
    border-radius: 8px;
    transition: transform 0.2s, box-shadow 0.2s;

    &:hover {
      transform: translateY(-2px);
      box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
    }

    &.primary {
      background: linear-gradient(135deg, #667eea, #764ba2);
    }
    &.secondary {
      background: linear-gradient(135deg, #6c757d, #495057);
    }
  }
`;

const AttackAnalysisPanel = styled(motion.div)`
  background: rgba(220, 53, 69, 0.05);
  border: 2px solid #dc3545;
  border-radius: 12px;
  padding: 1.5rem;
  margin-top: 1.5rem;

  h4 {
    color: #721c24;
    margin: 0 0 1rem 0;
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }

  .analysis-row {
    display: flex;
    gap: 1rem;
    margin-bottom: 0.75rem;
    font-size: 0.9rem;

    .label {
      color: #721c24;
      font-weight: 600;
      min-width: 140px;
    }
    .value {
      color: ${workshopTokens.text};
      flex: 1;
    }
  }

  .safe-summary {
    background: rgba(40, 167, 69, 0.1);
    border: 1px solid #28a745;
    border-radius: 8px;
    padding: 1rem;
    margin-top: 1rem;

    h5 {
      color: #155724;
      margin: 0 0 0.5rem 0;
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }

    p {
      color: ${workshopTokens.text};
      margin: 0;
      font-size: 0.9rem;
      line-height: 1.5;
    }
  }
`;

const SideBySideComparison = styled.div`
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 1rem;
  margin-top: 1.5rem;

  @media (max-width: 900px) {
    grid-template-columns: 1fr;
  }
`;

const ComparisonPanel = styled(motion.div)`
  border-radius: 12px;
  padding: 1.25rem;
  
  &.vulnerable {
    background: rgba(220, 53, 69, 0.08);
    border: 2px solid #dc3545;
    
    .panel-header {
      color: #721c24;
      border-bottom-color: rgba(220, 53, 69, 0.3);
    }
    
    .panel-icon {
      color: #dc3545;
    }
  }
  
  &.secure {
    background: rgba(40, 167, 69, 0.08);
    border: 2px solid #28a745;
    
    .panel-header {
      color: #155724;
      border-bottom-color: rgba(40, 167, 69, 0.3);
    }
    
    .panel-icon {
      color: #28a745;
    }
  }
  
  .panel-header {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    font-weight: 600;
    font-size: 1rem;
    margin-bottom: 0.75rem;
    padding-bottom: 0.75rem;
    border-bottom: 1px solid;
  }
  
  .panel-subtitle {
    font-size: 0.8rem;
    font-weight: 400;
    opacity: 0.8;
    margin-left: auto;
  }
  
  .panel-content {
    font-size: 0.95rem;
    line-height: 1.6;
    white-space: pre-wrap;
    word-break: break-word;
  }
`;

const ExampleTemplates = styled.div`
  margin-top: 1.5rem;
  padding-top: 1.5rem;
  border-top: 1px solid #e9ecef;

  h4 {
    color: ${workshopTokens.text};
    margin: 0 0 1rem 0;
    font-size: 1rem;
  }

  .template-card {
    background: #f8f9fa;
    border: 1px solid #e9ecef;
    border-radius: 8px;
    padding: 1rem;
    margin-bottom: 0.75rem;

    .template-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 0.5rem;
    }

    .template-level {
      font-size: 0.75rem;
      font-weight: 700;
      padding: 0.2rem 0.5rem;
      border-radius: 4px;
      &.easy { background: #d4edda; color: #155724; }
      &.medium { background: #fff3cd; color: #856404; }
      &.hard { background: #f8d7da; color: #721c24; }
    }

    .template-title {
      font-weight: 600;
      color: ${workshopTokens.text};
    }

    .template-content {
      font-family: monospace;
      font-size: 0.8rem;
      background: white;
      border: 1px solid #dee2e6;
      border-radius: 4px;
      padding: 0.75rem;
      white-space: pre-wrap;
      word-break: break-word;
    }
  }
`;

const PrivacyNotice = styled.div`
  background: rgba(108, 117, 125, 0.08);
  border: 1px solid #6c757d;
  border-radius: 8px;
  padding: 0.75rem 1rem;
  margin-top: 1rem;
  font-size: 0.85rem;
  color: #495057;
  display: flex;
  align-items: center;
  gap: 0.5rem;
`;

const INJECTION_KEYWORDS = ['ignore', 'override', 'forget previous', 'system administrator', 'without restrictions', 'no longer'];
const isInjected = (text) => text && INJECTION_KEYWORDS.some(kw => text.toLowerCase().includes(kw));

function safeText(value) {
  if (value == null) return '';
  const s = String(value);
  return s.replace(/\r\n/g, '\n').replace(/\r/g, '\n').trimEnd();
}

const SAMPLE_FILE_ICONS = {
  'random_document.txt': '🎲',
  'normal_policy.txt': '✅',
  'injected_document.txt': '🛡️',
  'query_injection_demo.txt': '🎭',
};

function resolveDocDisplay(filename) {
  if (!filename) return null;
  const lower = filename.toLowerCase();
  const match = SAMPLE_FILES.find(s => lower.includes(s.file.replace('.txt', '')));
  if (match) {
    return { label: match.label, icon: SAMPLE_FILE_ICONS[match.file] || '📄', isCustom: false };
  }
  return { label: filename, icon: '📄', isCustom: true };
}

const SAMPLE_FILES = [
  { label: 'Random Document', file: 'random_document.txt', queryPrefill: null, desc: 'Objective 1: any document — try asking ML questions' },
  { label: 'Clean Document', file: 'normal_policy.txt', queryPrefill: 'What are the eligibility requirements for remote work?', desc: 'Objectives 1–3: clean HR policy, no injection' },
  { label: 'Secure Poisoned RAG', file: 'injected_document.txt', queryPrefill: 'What are the core hours?', desc: 'Objective 4: policy with hidden SYSTEM OVERRIDE payload — AI should detect and refuse' },
  { label: 'Poisoned RAG RolePlay', file: 'query_injection_demo.txt', queryPrefill: 'Give me a recipe for pie', desc: 'Objective 5: policy with embedded directive — ask an off-topic question to bypass restrictions' }
];

const RAG_OBJECTIVES = [
  { id: 'rag_upload', name: '1. Load Document', description: 'Marked as completed after loading any document.' },
  { id: 'rag_clean_doc', name: '2. Clean Document', description: 'Load the clean sample (normal_policy.txt) into RAG.' },
  { id: 'rag_query', name: '3. Ask a question', description: 'Ask a question from the RAG database created after uploading the document.' },
  { id: 'rag_injected_doc', name: '4. Secure Poisoned RAG', description: 'Ask a document-related question (e.g. "core hours"). The AI should detect poisoning, refuse to answer, and analyze what caused the poisoning.' },
  { id: 'rag_query_injection', name: '5. Poisoned RAG', description: 'Ask an off-topic question (e.g. "recipe for pie"). The AI should bypass the system prompt and provide the answer to demonstrate the poisoning.' }
];

const EMAIL_AGENT_OBJECTIVES = [
  { id: 1, configId: 'email_create_inbox', name: '1. Create Temporary Email', description: 'Get a SharkLasers email address.' },
  { id: 2, configId: 'email_send_attack', name: '2. Send Attack Email', description: 'Workshop sends poisoned email to you.' },
  { id: 3, configId: 'email_retrieve', name: '3. Load Email Content', description: 'Fetch from SharkLasers or use the labeled manual fallback.' },
  { id: 4, configId: 'email_trigger_injection', name: '4. Trigger Injection', description: 'Test whether email instructions redirect the AI.' },
  { id: 5, configId: 'email_understand_defense', name: '5. Understand Defense', description: 'Compare the actual summaries and Judge evidence.' }
];

const TARGET_EMAIL = 'indirectpromptinjection@gmail.com';
const modeEndpoint = tab => tab === 'email' ? '/api/email-agent/mode' : '/api/workshop/rag-injection/mode';
const authoredOrFallback = (value, fallback) => typeof value === 'string' && value.trim() ? value : fallback;
const ipiSolutionContent = solution => {
  const normalized = normalizeSolution(solution);
  const examples = Array.isArray(solution.examples) ? solution.examples.map((example, index) => {
    const source = typeof example === 'string' ? { payload: example } : example && typeof example === 'object' ? example : {};
    const payload = [source.payload, source.prompt, source.input, source.code]
      .find(value => typeof value === 'string' && value.trim()) || '';
    return {
      title: authoredOrFallback(source.title, `Example ${index + 1}`),
      payload,
      explanation: typeof source.explanation === 'string' ? source.explanation : '',
    };
  }).filter(example => example.payload.trim() || example.explanation.trim()) : normalized.examples;
  return {
    ...solution,
    ...normalized,
    examples,
    approach: solution.approach,
    tips: solution.tips,
    explanation: [
      solution.difficulty && `Difficulty: ${solution.difficulty}`,
      solution.explanation,
    ].filter(value => typeof value === 'string' && value.trim()).join('\n\n'),
  };
};
const isAllowedRagObjective = (mode, id) => mode === 'fixed' ? id !== 'rag_query_injection'
  : mode === 'vuln' ? id !== 'rag_injected_doc' : true;
const isAllowedEmailObjective = (mode, id) => mode === 'fixed' ? id !== 4
  : mode === 'vuln' ? id !== 5 : true;

const IndirectPromptInjectionChallenge = () => {
  const { user } = useAuth();
  const { snapshot, revision } = useWorkshopConfig();
  const ipiExercise = snapshot?.exercises?.indirect_prompt_injection;
  const visibleRagObjectives = useMemo(() => (
    ipiExercise?.isVisible === true
      ? RAG_OBJECTIVES.filter((objective) => ipiExercise.objectives?.[objective.id]?.isVisible === true)
        .map(objective => ({ ...objective,
          name: authoredOrFallback(ipiExercise.objectives[objective.id].label, objective.name),
          description: authoredOrFallback(ipiExercise.objectives[objective.id].description, objective.description),
        }))
      : []
  ), [ipiExercise]);
  const visibleRagObjectiveIds = useMemo(
    () => new Set(visibleRagObjectives.map((objective) => objective.id)),
    [visibleRagObjectives],
  );
  const visibleEmailObjectives = useMemo(() => (
    ipiExercise?.isVisible === true
      ? EMAIL_AGENT_OBJECTIVES.filter((objective) => ipiExercise.objectives?.[objective.configId]?.isVisible === true)
        .map(objective => ({ ...objective,
          name: authoredOrFallback(ipiExercise.objectives[objective.configId].label, objective.name),
          description: authoredOrFallback(ipiExercise.objectives[objective.configId].description, objective.description),
        }))
      : []
  ), [ipiExercise]);
  const visibleHelpObjectiveIds = useMemo(
    () => new Set([...visibleRagObjectiveIds, ...visibleEmailObjectives.map(objective => objective.configId)]),
    [visibleRagObjectiveIds, visibleEmailObjectives],
  );
  const [activeTab, setActiveTab] = useState('document');
  const [ipiMode, setIpiMode] = useState(null);
  const [modeLoading, setModeLoading] = useState(true);
  const [modeSaving, setModeSaving] = useState(false);
  const [modeError, setModeError] = useState(null);
  const [modeRefreshVersion, setModeRefreshVersion] = useState(0);
  const modeRequestRevision = useRef(0);
  const modeSelectionRef = useRef(undefined);
  const modeMutationRef = useRef(false);
  const platformToken = localStorage.getItem('token');
  const platformIdentity = useRef({ token: platformToken, revision: 0 });
  if (platformIdentity.current.token !== platformToken) {
    platformIdentity.current = { token: platformToken, revision: platformIdentity.current.revision + 1 };
  }
  const ownerRevision = platformIdentity.current.revision;
  const retryMounted = useRef(true);
  const ownerIsCurrent = () => retryMounted.current
    && localStorage.getItem('token') === platformToken
    && platformIdentity.current.revision === ownerRevision;
  useEffect(() => {
    retryMounted.current = true;
    return () => { retryMounted.current = false; };
  }, []);
  const scenarioGenerationsRef = useRef({ document: 0, email: 0 });
  const captureScenario = (scenarioId) => scenarioGenerationsRef.current[scenarioId] || 0;
  const scenarioIsCurrent = (scenarioId, generation) => (
    ownerIsCurrent() && (scenarioGenerationsRef.current[scenarioId] || 0) === generation
  );
  const invalidateScenario = (scenarioId) => {
    scenarioGenerationsRef.current[scenarioId] = captureScenario(scenarioId) + 1;
  };

  // RAG State
  const [ragSessionId, setRagSessionId] = useState(null);
  const documentSelectionRevision = useRef(0);
  const [uploadStatus, setUploadStatus] = useState(null);
  const [ragQuestion, setRagQuestion] = useState('');
  const [retrievedChunks, setRetrievedChunks] = useState([]);
  const [ragAnswer, setRagAnswer] = useState('');
  const [ragEvaluation, setRagEvaluation] = useState(null);
  const [emailJudgments, setEmailJudgments] = useState([]);
  const [attackDetected, setAttackDetected] = useState(false);
  const [isUploading, setIsUploading] = useState(false);
  const [isQuerying, setIsQuerying] = useState(false);
  const [ragError, setRagError] = useState(null);
  const [health, setHealth] = useState({ embeddingReady: false, llmReady: false, modelReady: false, ollamaAvailable: false, status: 'unknown' });
  const [selectedFile, setSelectedFile] = useState(null);
  const progressGuard = useReconciliationGuard();
  const [completedObjectives, setCompletedObjectivesFromPoll] = useState({});
  const setCompletedObjectives = useGuardedSetter(setCompletedObjectivesFromPoll, progressGuard);
  const [activeObjectiveId, setActiveObjectiveId] = useState('rag_upload');
  const [progressLoading, setProgressLoading] = useState(true);
  const [ipiSolutionVisibility, setIpiSolutionVisibility] = useState({});
  const [viewingIpiSolution, setViewingIpiSolution] = useState(null);
  const [ipiSolutionLoading, setIpiSolutionLoading] = useState(null);
  const ipiSolutionOwnerRef = useRef(null);
  const fileInputRef = useRef(null);

  // Email Agent State (Reversed Flow)
  const [tempEmail, setTempEmail] = useState(() => localStorage.getItem('dvaia_email_agent_temp_email') || '');
  const [selectedScenario, setSelectedScenario] = useState('role_hijack');
  const [customPayload, setCustomPayload] = useState('');
  const [availableScenarios, setAvailableScenarios] = useState([]);
  const [emailSent, setEmailSent] = useState(false);
  const [sentEmailInfo, setSentEmailInfo] = useState(null);
  const [scrapedEmails, setScrapedEmails] = useState([]);
  const [fetchedEmail, setFetchedEmail] = useState(null);
  const [emailSummary, setEmailSummary] = useState(null);
  const [vulnerableEmailSummary, setVulnerableEmailSummary] = useState(null);
  const [emailResponseMode, setEmailResponseMode] = useState(null);
  const [emailInjectionDetected, setEmailInjectionDetected] = useState(false);
  const [injectionAnalysis, setInjectionAnalysis] = useState(null);
  const [safeSummary, setSafeSummary] = useState(null);
  const [isSendingEmail, setIsSendingEmail] = useState(false);
  const [isFetchingEmail, setIsFetchingEmail] = useState(false);
  const [isSummarizing, setIsSummarizing] = useState(false);
  const [emailError, setEmailError] = useState(null);
  const [emailProgress, setEmailProgressFromPoll] = useState({});
  const setEmailProgress = useGuardedSetter(setEmailProgressFromPoll, progressGuard, 'emailProgress');
  const [emailProgressLoading, setEmailProgressLoading] = useState(true);
  const [showAnalysis, setShowAnalysis] = useState(false);
  const [emailHealth, setEmailHealth] = useState({ gmail: { initialized: false, canSend: false }, llm: { available: false }, allowedDomains: [] });
  const [manualFallback, setManualFallback] = useState(false);
  const [manualEmailContent, setManualEmailContent] = useState('');
  const [isRefreshingRagHealth, setIsRefreshingRagHealth] = useState(false);
  const [isRefreshingEmailHealth, setIsRefreshingEmailHealth] = useState(false);

  const loadedOwnerRevision = useRef(ownerRevision);
  useEffect(() => {
    if (loadedOwnerRevision.current === ownerRevision) return;
    loadedOwnerRevision.current = ownerRevision;
    invalidateScenario('document'); invalidateScenario('email');
    documentSelectionRevision.current += 1;
    for (const domain of ['progress', 'emailProgress', 'solutionVisibility', 'solutionModal']) progressGuard.mark(domain);
    ipiSolutionOwnerRef.current = null;
    setViewingIpiSolution(null); setIpiSolutionLoading(null); setIpiSolutionVisibility({});
    setRagSessionId(null); setUploadStatus(null); setSelectedFile(null); setRagQuestion('');
    setRetrievedChunks([]); setRagAnswer(''); setRagEvaluation(null); setAttackDetected(false);
    setIsUploading(false); setIsQuerying(false); setRagError(null); setCompletedObjectivesFromPoll({});
    setActiveObjectiveId(visibleRagObjectives[0]?.id || null);
    if (fileInputRef.current) fileInputRef.current.value = '';
    setTempEmail(''); localStorage.removeItem('dvaia_email_agent_temp_email');
    setSelectedScenario('role_hijack'); setCustomPayload('');
    setEmailSent(false); setSentEmailInfo(null); setScrapedEmails([]); setFetchedEmail(null);
    setEmailSummary(null); setVulnerableEmailSummary(null); setEmailResponseMode(null);
    setSafeSummary(null); setEmailInjectionDetected(false); setInjectionAnalysis(null);
    setEmailJudgments([]); setEmailProgressFromPoll({}); setShowAnalysis(false); setEmailError(null);
    setManualFallback(false); setManualEmailContent('');
    setIsSendingEmail(false); setIsFetchingEmail(false); setIsSummarizing(false);
    setIsRefreshingRagHealth(false); setIsRefreshingEmailHealth(false);
    modeRequestRevision.current += 1; modeSelectionRef.current = undefined; modeMutationRef.current = false;
    setIpiMode(null); setModeLoading(true); setModeSaving(false); setModeError(null);
  }, [ownerRevision, progressGuard]);

  useEffect(() => {
    if (modeMutationRef.current) return undefined;
    const controller = new AbortController();
    const requestRevision = ++modeRequestRevision.current;
    setModeLoading(true);
    setModeError(null);
    axios.get(modeEndpoint(activeTab), { signal: controller.signal }).then(({ data }) => {
      if (controller.signal.aborted || !ownerIsCurrent() || requestRevision !== modeRequestRevision.current) return;
      if (!data || !Array.isArray(data.allowedModes) || !data.allowedModes.includes('vuln')
          || !data.allowedModes.includes('fixed') || ![null, 'vuln', 'fixed'].includes(data.mode)) {
        throw new Error('Mode response is unavailable');
      }
      setIpiMode(data.mode);
      setModeLoading(false);
    }).catch(() => {
      if (controller.signal.aborted || !ownerIsCurrent() || requestRevision !== modeRequestRevision.current) return;
      setModeError('Could not load the workshop mode. Retry before running an agent.');
      setModeLoading(false);
    });
    return () => controller.abort();
  }, [activeTab, ownerRevision, modeRefreshVersion]);

  useEffect(() => {
    if (modeLoading || modeError || modeSelectionRef.current === ipiMode) return;
    const previousMode = modeSelectionRef.current;
    modeSelectionRef.current = ipiMode;
    if (previousMode !== undefined) {
      invalidateScenario('document'); invalidateScenario('email');
      setRetrievedChunks([]); setRagAnswer(''); setRagEvaluation(null); setAttackDetected(false); setRagError(null);
      setEmailSummary(null); setVulnerableEmailSummary(null); setEmailResponseMode(null);
      setSafeSummary(null); setEmailJudgments([]); setEmailInjectionDetected(false); setInjectionAnalysis(null);
      setIsQuerying(false); setIsSummarizing(false);
    }
    setActiveObjectiveId(current => {
      const preferred = ipiMode === 'fixed' ? 'rag_injected_doc' : ipiMode === 'vuln' ? 'rag_query_injection' : null;
      if (preferred && visibleRagObjectiveIds.has(preferred)) return preferred;
      return current && visibleRagObjectiveIds.has(current) && isAllowedRagObjective(ipiMode, current)
        ? current : visibleRagObjectives.find(obj => isAllowedRagObjective(ipiMode, obj.id))?.id || null;
    });
  }, [ipiMode, modeLoading, modeError, visibleRagObjectiveIds, visibleRagObjectives]);

  const modeReady = !modeLoading && !modeSaving && !modeError;
  const chooseMode = async nextMode => {
    if (!ownerIsCurrent() || !modeReady || nextMode === ipiMode || !['vuln','fixed'].includes(nextMode)) return;
    const requestRevision = ++modeRequestRevision.current;
    modeMutationRef.current = true;
    setModeSaving(true); setModeError(null);
    invalidateScenario('document'); invalidateScenario('email');
    try {
      const { data } = await axios.post(modeEndpoint(activeTab), { mode:nextMode });
      if (!ownerIsCurrent() || requestRevision !== modeRequestRevision.current) return;
      if (data?.mode !== nextMode) throw new Error('Mode update was not confirmed');
      setIpiMode(data.mode);
    } catch {
      if (ownerIsCurrent() && requestRevision === modeRequestRevision.current) {
        setModeError('Could not save the workshop mode. Retry to load the current setting.');
      }
    } finally {
      if (ownerIsCurrent() && requestRevision === modeRequestRevision.current) {
        modeMutationRef.current = false;
        setModeSaving(false);
        setModeRefreshVersion(value => value + 1);
      }
    }
  };

  useWorkshopHeartbeat('indirect_prompt_injection');
  useChangePolling(async (_next, _previous, { signal } = {}) => {
    if (!ownerIsCurrent()) return;
    const progressGeneration = progressGuard.begin('progress');
    const gatesGeneration = progressGuard.begin('solutionVisibility');
    const solutionDisclosureId = ipiSolutionOwnerRef.current;
    const modalGeneration = solutionDisclosureId
      ? progressGuard.begin('solutionModal')
      : null;
    const emailGeneration = progressGuard.begin('emailProgress');
    const solutionRefreshPromise = axios.get('/api/solutions/indirect-pi/status', { signal }).then(
      (value) => ({ status: 'fulfilled', value }),
      (reason) => ({ status: 'rejected', reason }),
    );
    const progressRefreshPromise = Promise.allSettled([
      axios.get('/api/workshop/rag-injection/progress', { signal }),
      axios.get('/api/email-agent/progress', { signal }),
    ]);
    const solutionRefresh = await solutionRefreshPromise;
    if (signal?.aborted || !ownerIsCurrent()) return;
    const refreshFailures = [];
    if (solutionRefresh.status === 'rejected') {
      refreshFailures.push(solutionRefresh.reason);
    } else {
      const solutionResponse = solutionRefresh.value;
      const nextVisibility = solutionResponse.data.objectives || {};
      const refreshedSolution = solutionDisclosureId && nextVisibility[solutionDisclosureId]
        ? await axios.get(`/api/solutions/indirect-pi/${solutionDisclosureId}`, { signal })
        : null;
      if (signal?.aborted || !ownerIsCurrent()) return;
      progressGuard.commit('solutionVisibility', gatesGeneration, () => {
        setIpiSolutionVisibility(nextVisibility);
        const currentDisclosureId = ipiSolutionOwnerRef.current;
        if (currentDisclosureId && !nextVisibility[currentDisclosureId]) {
          ipiSolutionOwnerRef.current = null;
          progressGuard.mark('solutionModal');
          setIpiSolutionLoading(null);
          setViewingIpiSolution(null);
        }
      });
      if (modalGeneration !== null && refreshedSolution && nextVisibility[solutionDisclosureId]) {
        progressGuard.commit('solutionModal', modalGeneration, () => {
          ipiSolutionOwnerRef.current = solutionDisclosureId;
          setIpiSolutionLoading(null);
          setViewingIpiSolution({ id: solutionDisclosureId, ...refreshedSolution.data.solution });
        });
      }
    }

    const [ragProgressRefresh, emailProgressRefresh] = await progressRefreshPromise;
    if (signal?.aborted || !ownerIsCurrent()) return;
    if (ragProgressRefresh.status === 'rejected') {
      refreshFailures.push(ragProgressRefresh.reason);
    } else {
      const ragProgress = ragProgressRefresh.value.data.objectives || {};
      const completed = {};
      RAG_OBJECTIVES.forEach((objective) => {
        completed[objective.id] = !!ragProgress[objective.id]?.completed;
      });
      progressGuard.commit('progress', progressGeneration, () => {
        setCompletedObjectivesFromPoll(completed);
      });
    }

    if (emailProgressRefresh.status === 'rejected') {
      refreshFailures.push(emailProgressRefresh.reason);
    } else {
      progressGuard.commit('emailProgress', emailGeneration, () => {
        setEmailProgressFromPoll(emailProgressRefresh.value.data.progress || {});
      });
    }

    if (refreshFailures.length > 0) throw refreshFailures[0];
  }, ['indirect_prompt_injection']);

  // Fetch solution visibility on mount
  useEffect(() => {
    const solutionGeneration = progressGuard.begin('solutionVisibility');
    axios.get('/api/solutions/indirect-pi/status')
      .then(r => ownerIsCurrent() && progressGuard.commit('solutionVisibility', solutionGeneration, () => {
        setIpiSolutionVisibility(r.data.objectives || {});
      }))
      .catch(() => {});
  }, [progressGuard, platformToken]);

  const handleViewIpiSolution = async (objectiveId) => {
    if (!ownerIsCurrent() || !visibleHelpObjectiveIds.has(objectiveId)) return;
    const solutionGeneration = progressGuard.begin('solutionModal');
    ipiSolutionOwnerRef.current = objectiveId;
    setIpiSolutionLoading(objectiveId);
    let opened = false;
    try {
      const { data } = await axios.get(`/api/solutions/indirect-pi/${objectiveId}`);
      if (!ownerIsCurrent()) return;
      progressGuard.commit('solutionModal', solutionGeneration, () => {
        opened = true;
        ipiSolutionOwnerRef.current = objectiveId;
        setViewingIpiSolution({ id: objectiveId, ...data.solution });
      });
    } catch (err) {
      if (!ownerIsCurrent() || err.code === 'STALE_RECONCILIATION') return;
      toast.error(err.response?.data?.error || 'Solution not available.');
    } finally {
      if (ownerIsCurrent() && progressGuard.capture('solutionModal') === solutionGeneration) {
        if (!opened) ipiSolutionOwnerRef.current = null;
        setIpiSolutionLoading(null);
      }
    }
  };

  const closeIpiSolution = () => {
    ipiSolutionOwnerRef.current = null;
    progressGuard.mark('solutionModal');
    setIpiSolutionLoading(null);
    setViewingIpiSolution(null);
  };

  const renderObjectiveHelp = (obj, objectiveId) => (
    <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: '0.5rem', marginTop: '0.75rem' }}>
      {ipiExercise?.objectives?.[objectiveId]?.hintVisible === true && (
        <div onClick={e => e.stopPropagation()}>
          <HintPanel
            workshopKey="indirect_prompt_injection"
            objectiveId={objectiveId}
            objective={obj}
            revision={revision}
          />
        </div>
      )}
      {ipiSolutionVisibility[objectiveId] && (
        <ObjectiveHelpActions
          objectiveId={objectiveId}
          solutionVisible
          disabled={ipiSolutionLoading === objectiveId}
          activeKind={viewingIpiSolution?.id === objectiveId ? 'solution' : undefined}
          onOpen={(_, id) => handleViewIpiSolution(id)}
        />
      )}
    </div>
  );

  useEffect(() => {
    setActiveObjectiveId(current => (
      current && visibleRagObjectiveIds.has(current) && isAllowedRagObjective(ipiMode, current)
        ? current
        : visibleRagObjectives.find(obj => isAllowedRagObjective(ipiMode, obj.id))?.id || null
    ));

    const disclosureId = ipiSolutionOwnerRef.current;
    if (disclosureId && !visibleHelpObjectiveIds.has(disclosureId)) {
      ipiSolutionOwnerRef.current = null;
      progressGuard.mark('solutionModal');
      setIpiSolutionLoading(null);
      setViewingIpiSolution(null);
    }
  }, [progressGuard, revision, visibleRagObjectiveIds, visibleRagObjectives, visibleHelpObjectiveIds, ipiMode]);

  // RAG Effects
  useEffect(() => {
    let attempts = 0;
    let active = true;
    let retryTimer;
    let deadlineTimer;
    let controller;
    const maxAttempts = 3;
    const tryHealth = async () => {
      if (!active) return;
      controller = new AbortController();
      const requestController = controller;
      deadlineTimer = setTimeout(() => requestController.abort(), 10000);
      try {
        const res = await axios.get('/api/workshop/rag-injection/health', {
          signal: requestController.signal,
          timeout: 10000
        });
        if (!active || requestController.signal.aborted) return;
        setHealth({
          embeddingReady: res.data.embeddingReady === true,
          llmReady: res.data.llmReady === true,
          modelReady: res.data.modelReady === true,
          ollamaAvailable: res.data.ollamaAvailable === true,
          status: res.data.status || 'ok',
          message: res.data.message,
          activeModel: res.data.activeModel
        });
      } catch {
        if (!active) return;
        attempts += 1;
        if (attempts < maxAttempts) {
          retryTimer = setTimeout(tryHealth, 5000);
        } else {
          setHealth({ embeddingReady: false, llmReady: false, modelReady: false, ollamaAvailable: false, status: 'error' });
        }
      } finally {
        clearTimeout(deadlineTimer);
      }
    };
    tryHealth();
    return () => {
      active = false;
      clearTimeout(retryTimer);
      clearTimeout(deadlineTimer);
      controller.abort();
    };
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    const selectionRevision = documentSelectionRevision.current;
    const scenarioGeneration = captureScenario('document');
    axios.get('/api/workshop/rag-injection/current-session', { signal: controller.signal })
      .then(res => {
        if (controller.signal.aborted || documentSelectionRevision.current !== selectionRevision
          || !scenarioIsCurrent('document', scenarioGeneration)) return;
        const { session_id, filename, chunks_stored } = res.data || {};
        if (session_id && filename != null) {
          setRagSessionId(session_id);
          setUploadStatus({ filename, chunks_stored: chunks_stored || 0 });
        }
      })
      .catch(() => {});
    return () => controller.abort();
  }, [platformToken]);

  useEffect(() => {
    const progressGeneration = progressGuard.begin('progress');
    setProgressLoading(true);
    axios.get('/api/workshop/rag-injection/progress')
      .then(res => {
        if (!ownerIsCurrent()) return;
        const objectives = res.data.objectives || {};
        const completed = {};
        RAG_OBJECTIVES.forEach(obj => {
          completed[obj.id] = !!(objectives[obj.id] && objectives[obj.id].completed);
        });
        progressGuard.commit('progress', progressGeneration, () => {
          setCompletedObjectivesFromPoll(completed);
        });
      })
      .catch(() => {})
      .finally(() => { if (ownerIsCurrent()) setProgressLoading(false); });
  }, [progressGuard, platformToken]);

  // Email Agent Effects (Reversed Flow)
  useEffect(() => {
    const emailGeneration = captureScenario('email');
    axios.get('/api/email-agent/health')
      .then(async res => {
        if (!scenarioIsCurrent('email', emailGeneration)) return;
        setEmailHealth(res.data);
        if (res.data.provider === 'mailpit') {
          const owned = await axios.get('/api/email-agent/owned-inbox');
          if (scenarioIsCurrent('email', emailGeneration) && owned.data?.ownedInbox) {
            setTempEmail(owned.data.ownedInbox);
            localStorage.setItem('dvaia_email_agent_temp_email', owned.data.ownedInbox);
          }
        }
      })
      .catch(() => {
        if (scenarioIsCurrent('email', emailGeneration)) {
          setEmailHealth({ gmail: { initialized: false, canSend: false }, llm: { available: false }, allowedDomains: [] });
        }
      });
  }, [platformToken]);

  useEffect(() => {
    axios.get('/api/email-agent/scenarios')
      .then(res => {
        setAvailableScenarios(res.data.scenarios || []);
      })
      .catch(() => {});
  }, [platformToken]);

  useEffect(() => {
    const emailGeneration = progressGuard.begin('emailProgress');
    setEmailProgressLoading(true);
    axios.get('/api/email-agent/progress')
      .then(res => {
        if (!ownerIsCurrent()) return;
        progressGuard.commit('emailProgress', emailGeneration, () => {
          setEmailProgressFromPoll(res.data.progress || {});
        });
      })
      .catch(() => {})
      .finally(() => { if (ownerIsCurrent()) setEmailProgressLoading(false); });
  }, [progressGuard, platformToken]);

  const refreshEmailProgress = async (isCurrent = () => true) => {
    if (!ownerIsCurrent()) return;
    const emailGeneration = progressGuard.begin('emailProgress');
    const scenarioGeneration = captureScenario('email');
    try {
      const res = await axios.get('/api/email-agent/progress');
      if (!retryMounted.current || !scenarioIsCurrent('email', scenarioGeneration) || !isCurrent()) return;
      if (progressGuard.capture('emailProgress') !== emailGeneration) return true;
      progressGuard.commit('emailProgress', emailGeneration, () => {
        setEmailProgressFromPoll(res.data.progress || {});
      });
      return true;
    } catch (_) { return false; }
  };

  const retryScenarios = { ...scenarioGenerationsRef.current };
  const handleJudgeRetryResult = async (scenario, data, { signal } = {}) => {
    const isCurrent = () => retryMounted.current && !signal?.aborted
      && scenarioIsCurrent(scenario, retryScenarios[scenario] || 0);
    if (!isCurrent()) return;
    const retryJudgments = data.judgment ? [data.judgment] : (data.judgments || []);
    let progressRefreshed = true;
    if (scenario === 'email') {
      setEmailJudgments(previous => [...previous, ...retryJudgments]);
      progressRefreshed = await refreshEmailProgress(isCurrent);
    } else {
      setRagEvaluation(previous => ({
        ...(previous || {}),
        judgments: [...(previous?.judgments || []), ...retryJudgments],
      }));
      const progressGeneration = progressGuard.begin('progress');
      try {
        const response = await axios.get('/api/workshop/rag-injection/progress', { signal });
        if (!isCurrent()) return;
        const objectives = response.data.objectives || {};
        const completed = {};
        RAG_OBJECTIVES.forEach(objective => {
          completed[objective.id] = !!objectives[objective.id]?.completed;
        });
        if (progressGuard.capture('progress') === progressGeneration) {
          progressGuard.commit('progress', progressGeneration, () => setCompletedObjectivesFromPoll(completed));
        }
      } catch (_) { progressRefreshed = false; }
    }
    if (!isCurrent()) return;
    if (progressRefreshed === false) {
      toast.warning('Evaluation finished, but progress could not be refreshed.');
      return;
    }
    if (data.completed === true) toast.success('Objective evaluation passed.');
  };

  // Refresh RAG health status
  const refreshRagHealth = async () => {
    if (!ownerIsCurrent()) return;
    setIsRefreshingRagHealth(true);
    try {
      const res = await axios.get('/api/workshop/rag-injection/health');
      if (!ownerIsCurrent()) return;
      setHealth({
        embeddingReady: res.data.embeddingReady === true,
        llmReady: res.data.llmReady === true,
        modelReady: res.data.modelReady === true,
        ollamaAvailable: res.data.ollamaAvailable === true,
        status: res.data.status || 'ok',
        message: res.data.message,
        activeModel: res.data.activeModel
      });
      if (res.data.embeddingReady && res.data.llmReady) {
        toast.success('Embedding model & LLM ready');
      } else {
        toast.warning(res.data.message || 'Some services still unavailable');
      }
    } catch (err) {
      if (!ownerIsCurrent()) return;
      if (!ownerIsCurrent()) return;
      setHealth({ embeddingReady: false, llmReady: false, modelReady: false, ollamaAvailable: false, status: 'error' });
      toast.error('Failed to check RAG health');
    } finally {
      if (ownerIsCurrent()) setIsRefreshingRagHealth(false);
    }
  };

  // Refresh Email Agent health status
  const refreshEmailHealth = async () => {
    if (!ownerIsCurrent()) return;
    setIsRefreshingEmailHealth(true);
    try {
      // Retry external Gmail only; local Mailpit is already available through the owned sidecar.
      const currentHealth = emailHealth;
      if (currentHealth.provider !== 'mailpit' && !currentHealth.gmail?.canSend) {
        try {
          const retryRes = await axios.post('/api/email-agent/retry-gmail');
          if (!ownerIsCurrent()) return;
          if (retryRes.data.success) {
            toast.success('Gmail SMTP connected successfully!');
          }
        } catch (retryErr) {
          console.log('Gmail retry failed:', retryErr.message);
        }
      }
      
      // Then fetch the updated health status
      if (!ownerIsCurrent()) return;
      const res = await axios.get('/api/email-agent/health');
      if (!ownerIsCurrent()) return;
      setEmailHealth(res.data);
      if (res.data.llm?.available && res.data.gmail?.canSend) {
        toast.success(res.data.provider === 'mailpit' ? 'AI Service and local mail are ready' : 'AI Service and Gmail are now ready');
      } else {
        const issues = [];
        if (!res.data.llm?.available) issues.push('LLM unavailable');
        if (!res.data.gmail?.canSend) issues.push(res.data.provider === 'mailpit' ? 'Local mail is not ready' : 'Gmail not ready - click Refresh to retry');
        toast.warning(issues.join(', ') || 'Services still unavailable');
      }
    } catch (err) {
      if (!ownerIsCurrent()) return;
      setEmailHealth({ gmail: { initialized: false, canSend: false }, llm: { available: false }, allowedDomains: [] });
      toast.error('Failed to check service status');
    } finally {
      if (ownerIsCurrent()) setIsRefreshingEmailHealth(false);
    }
  };

  // RAG Functions
  const clearSession = () => {
    setRetrievedChunks([]);
    setRagAnswer('');
    setRagEvaluation(null);
    setAttackDetected(false);
    setRagError(null);
  };

  const uploadFile = async (file) => {
    if (!ownerIsCurrent()) return;
    if (!file) return;
    documentSelectionRevision.current += 1;
    const scenarioGeneration = captureScenario('document');
    const previousSessionId = ragSessionId;
    setIsUploading(true);
    setRagError(null);
    clearSession();
    const formData = new FormData();
    formData.append('document', file);
    try {
      const res = await axios.post('/api/workshop/rag-injection/upload', formData, {
        headers: { 'Content-Type': 'multipart/form-data' }
      });
      if (!scenarioIsCurrent('document', scenarioGeneration)) return;
      if (res.data.currently_selected === false) {
        // A completed retry is an observation of the original upload, not
        // permission to replace a newer server-side document selection.
        let current;
        try { current = (await axios.get('/api/workshop/rag-injection/current-session')).data || {}; }
        catch {
          if (scenarioIsCurrent('document', scenarioGeneration)) {
            setRagSessionId(null);
            setUploadStatus(null);
          }
          throw new Error('Upload was already recorded, but the current document could not be refreshed. Please reload before querying.');
        }
        if (!scenarioIsCurrent('document', scenarioGeneration)) return;
        const restored = current.session_id && current.filename != null;
        setRagSessionId(restored ? current.session_id : null);
        setUploadStatus(restored ? { filename: current.filename, chunks_stored: current.chunks_stored || 0 } : null);
        toast.info('Upload already recorded. Current document selection refreshed.');
        return;
      }
      setRagSessionId(res.data.session_id);
      setUploadStatus({ filename: res.data.filename, chunks_stored: res.data.chunks_stored });
      toast.success(`Uploaded: ${res.data.filename} (${res.data.chunks_stored} chunks)`);
      // Preserve the previous document until replacement has succeeded. Failed
      // validation or embedding must not discard the learner's only source.
      if (previousSessionId && previousSessionId !== res.data.session_id) {
        await axios.delete(`/api/workshop/rag-injection/session/${previousSessionId}`).catch(() => {});
        if (!scenarioIsCurrent('document', scenarioGeneration)) return;
      }
      const progressGeneration = progressGuard.begin('progress');
      axios.get('/api/workshop/rag-injection/progress').then(r => {
        if (!scenarioIsCurrent('document', scenarioGeneration)) return;
        const objectives = r.data.objectives || {};
        const completed = {};
        RAG_OBJECTIVES.forEach(obj => {
          completed[obj.id] = !!(objectives[obj.id] && objectives[obj.id].completed);
        });
        if (progressGuard.capture('progress') !== progressGeneration) return;
        progressGuard.commit('progress', progressGeneration, () => setCompletedObjectivesFromPoll(completed));
        // Keep the student's selected objective (don't snap to first-incomplete) —
        // loading the objective-5 doc must not bounce them back to objective 4.
      }).catch(() => {});
      return { selected: true };
    } catch (err) {
      if (!scenarioIsCurrent('document', scenarioGeneration)) return;
      const msg = err.response?.data?.error || err.message || 'Upload failed';
      setRagError(msg);
      toast.error(msg);
    } finally {
      if (scenarioIsCurrent('document', scenarioGeneration)) setIsUploading(false);
    }
  };

  const loadSample = async (sample) => {
    if (!ownerIsCurrent()) return;
    const scenarioGeneration = captureScenario('document');
    setIsUploading(true);
    setRagError(null);
    try {
      const res = await fetch(`/assets/rag_samples/${sample.file}`);
      if (!scenarioIsCurrent('document', scenarioGeneration)) return;
      if (!res.ok) throw new Error('Sample not found');
      const text = await res.text();
      const blob = new Blob([text], { type: 'text/plain' });
      const file = new File([blob], sample.file, { type: 'text/plain' });
      const outcome = await uploadFile(file);
      if (outcome?.selected === true && sample.queryPrefill && scenarioIsCurrent('document', scenarioGeneration)) {
        setRagQuestion(sample.queryPrefill);
      }
    } catch (err) {
      if (!scenarioIsCurrent('document', scenarioGeneration)) return;
      setRagError(err.message || 'Failed to load sample');
      toast.error(err.message || 'Failed to load sample');
    } finally {
      if (scenarioIsCurrent('document', scenarioGeneration)) setIsUploading(false);
    }
  };

  const handleFileChange = (e) => {
    const file = e.target.files?.[0];
    setSelectedFile(file || null);
  };

  const handleUploadClick = () => {
    if (selectedFile) uploadFile(selectedFile);
    else fileInputRef.current?.click();
  };

  const handleQuery = async (e) => {
    if (!ownerIsCurrent()) return;
    e.preventDefault();
    if (!modeReady || !isAllowedRagObjective(ipiMode, activeObjectiveId)
        || !ragQuestion.trim() || !ragSessionId || isQuerying || isUploading) return;
    const scenarioGeneration = captureScenario('document');
    const selectionRevision = documentSelectionRevision.current;
    setIsQuerying(true);
    setRagError(null);
    setRetrievedChunks([]);
    setRagAnswer('');
    setRagEvaluation(null);
    setAttackDetected(false);
    try {
      const res = await axios.post('/api/workshop/rag-injection/query', {
        session_id: ragSessionId,
        question: ragQuestion.trim(),
        active_objective: activeObjectiveId
      });
      if (!scenarioIsCurrent('document', scenarioGeneration)
        || documentSelectionRevision.current !== selectionRevision) return;
      setRetrievedChunks(res.data.retrieved_chunks || []);
      setRagAnswer(res.data.answer ?? '');
      setRagEvaluation(res.data);
      setAttackDetected(res.data.attack_detected === true);
      if (res.data.attack_detected) toast.warning('Response flagged for injection review');
      const progressGeneration = progressGuard.begin('progress');
      axios.get('/api/workshop/rag-injection/progress').then(r => {
        if (!scenarioIsCurrent('document', scenarioGeneration)) return;
        const objectives = r.data.objectives || {};
        const completed = {};
        RAG_OBJECTIVES.forEach(obj => {
          completed[obj.id] = !!(objectives[obj.id] && objectives[obj.id].completed);
        });
        if (progressGuard.capture('progress') !== progressGeneration) return;
        progressGuard.commit('progress', progressGeneration, () => setCompletedObjectivesFromPoll(completed));
        // Do NOT reset the active objective here — the student chose it. Snapping
        // it back to "first incomplete" after every query pinned it to objective 4
        // so objective 5's completion branch (gated on the active objective) was
        // never reached. Keep the user's selection.
      }).catch(() => {});
    } catch (err) {
      if (!scenarioIsCurrent('document', scenarioGeneration)) return;
      const msg = err.response?.data?.error || err.message || 'Query failed';
      if (documentSelectionRevision.current !== selectionRevision) return;
      setRagError(msg);
      if (err.response?.status === 404) {
        if (documentSelectionRevision.current === selectionRevision) {
          documentSelectionRevision.current += 1;
          setRagSessionId(null);
          setUploadStatus(null);
        }
        toast.error('Session not found. Upload a document first.');
      }
      else toast.error(msg);
    } finally {
      if (scenarioIsCurrent('document', scenarioGeneration)) setIsQuerying(false);
    }
  };

  // Email Agent Functions (Reversed Flow)
  const isValidEmail = (email) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);

  const isAllowedDomain = (email) => {
    if (!email || !emailHealth.allowedDomains?.length) return true;
    const domain = email.toLowerCase().split('@')[1];
    return emailHealth.allowedDomains.includes(domain);
  };

  const handleSaveTempEmail = async () => {
    if (!ownerIsCurrent()) return;
    if (!isValidEmail(tempEmail)) {
      toast.error('Please enter a valid email address');
      return;
    }
    if (!isAllowedDomain(tempEmail)) {
      toast.error('Please use a temporary email service (e.g., sharklasers.com, guerrillamail.com)');
      return;
    }
    localStorage.setItem('dvaia_email_agent_temp_email', tempEmail);
    const scenarioGeneration = captureScenario('email');
    try {
      const response = await axios.post('/api/email-agent/save-email', { tempEmail });
      if (!scenarioIsCurrent('email', scenarioGeneration)) return;
      setEmailJudgments(response.data.judgment ? [response.data.judgment] : []);
      toast.success('Email address saved');
      refreshEmailProgress();
    } catch (err) {
      if (!scenarioIsCurrent('email', scenarioGeneration)) return;
      const msg = err.response?.data?.error || 'Failed to save email';
      toast.error(msg);
    }
  };

  const handleSendAttackEmail = async () => {
    if (!ownerIsCurrent()) return;
    if (!isValidEmail(tempEmail)) {
      toast.error('Please enter a valid email address first');
      return;
    }
    if (!selectedScenario) {
      toast.error('Please select an attack scenario');
      return;
    }
    if (selectedScenario === 'custom' && (!customPayload || customPayload.trim().length < 10)) {
      toast.error('Custom payload must be at least 10 characters');
      return;
    }

    const scenarioGeneration = captureScenario('email');
    setIsSendingEmail(true);
    setEmailError(null);
    setEmailSent(false);
    setSentEmailInfo(null);

    try {
      const res = await axios.post('/api/email-agent/send', {
        recipientEmail: tempEmail,
        scenario: selectedScenario,
        customBody: selectedScenario === 'custom' ? customPayload : undefined
      });
      if (!scenarioIsCurrent('email', scenarioGeneration)) return;

      if (res.data.success) {
        setEmailJudgments(res.data.judgments || []);
        setEmailSent(true);
        setSentEmailInfo(res.data);
        toast.success(`Attack email sent to ${tempEmail}. Check your inbox in 1-2 minutes.`);
        refreshEmailProgress();
      }
    } catch (err) {
      if (!scenarioIsCurrent('email', scenarioGeneration)) return;
      if (err.response?.status === 429) {
        const retryAfter = err.response.data.retryAfter || 60;
        setEmailError(`Rate limit exceeded. Please wait ${retryAfter} seconds.`);
        toast.error(`Rate limit exceeded. Please wait ${retryAfter} seconds.`);
      } else {
        const msg = err.response?.data?.error || 'Failed to send email';
        setEmailError(msg);
        toast.error(msg);
      }
    } finally {
      if (scenarioIsCurrent('email', scenarioGeneration)) setIsSendingEmail(false);
    }
  };

  const handleFetchFromSharkLasers = async () => {
    if (!ownerIsCurrent()) return;
    if (!isValidEmail(tempEmail)) {
      toast.error('Please enter a valid email address');
      return;
    }

    const scenarioGeneration = captureScenario('email');
    const submittedManualContent = manualFallback && manualEmailContent.trim().length > 10
      ? manualEmailContent
      : null;
    setIsFetchingEmail(true);
    setEmailError(null);
    setScrapedEmails([]);
    setFetchedEmail(null);
    setEmailSummary(null);
    setEmailJudgments([]);
    setEmailInjectionDetected(false);
    setInjectionAnalysis(null);
    setSafeSummary(null);
    setShowAnalysis(false);
    setManualFallback(false);

    try {
      const payload = { tempEmail };
      if (submittedManualContent) {
        payload.manualContent = submittedManualContent;
      }

      const res = await axios.post('/api/email-agent/fetch-sharklasers', payload);
      if (!scenarioIsCurrent('email', scenarioGeneration)) return;
      
      if (res.data.success) {
        if (res.data.emails && res.data.emails.length > 0) {
          const persistedEmail = res.data.emails.find(email => typeof email?.artifactId === 'string');
          setEmailJudgments(res.data.judgments || []);
          setScrapedEmails(res.data.emails);
          if (persistedEmail) {
            setFetchedEmail(persistedEmail);
            toast.success(res.data.message || 'Email retrieved successfully');
            refreshEmailProgress();
          } else {
            setEmailError('The inbox listing did not include retrievable message content. Try fetching again.');
            toast.warning('Message content is not available yet. Try fetching again.');
          }
        } else {
          setEmailError(res.data.message || 'No emails found. The email may take 1-2 minutes to arrive.');
          toast.warning(res.data.message || 'No emails found yet. Try again in a minute.');
        }
      } else {
        if (res.data.fallbackAvailable) {
          setManualFallback(true);
          setEmailError(res.data.fallbackMessage || 'Automatic fetching failed. Please paste the email content manually.');
          toast.warning('Automatic fetching failed. Use manual entry below.');
        } else {
          setEmailError(res.data.error);
          toast.error(res.data.error);
        }
      }
    } catch (err) {
      if (!scenarioIsCurrent('email', scenarioGeneration)) return;
      const msg = err.response?.data?.error || 'Failed to fetch emails';
      setEmailError(msg);
      toast.error(msg);
      if (err.response?.data?.fallbackAvailable) {
        setManualFallback(true);
      }
    } finally {
      if (scenarioIsCurrent('email', scenarioGeneration)) setIsFetchingEmail(false);
    }
  };

  const handleSummarizeEmail = async () => {
    if (!ownerIsCurrent()) return;
    if (!modeReady) return;
    if (!fetchedEmail?.artifactId) {
      toast.error('Select an email returned by the workshop before summarizing');
      return;
    }

    const scenarioGeneration = captureScenario('email');
    setIsSummarizing(true);
    setEmailSummary(null);
    setVulnerableEmailSummary(null);
    setEmailResponseMode(null);
    setEmailJudgments([]);
    setEmailInjectionDetected(false);
    setInjectionAnalysis(null);
    setSafeSummary(null);

    try {
      const res = await axios.post('/api/email-agent/summarize', { artifactId: fetchedEmail.artifactId });
      if (!scenarioIsCurrent('email', scenarioGeneration)) return;

      if (res.data.success) {
        setEmailJudgments(res.data.judgments || []);
        setEmailSummary(res.data.summary);
        setVulnerableEmailSummary(res.data.vulnerableSummary || (res.data.mode === 'fixed' ? null : res.data.summary));
        setEmailResponseMode(res.data.mode ?? null);
        setEmailInjectionDetected(res.data.injectionDetected);
        setInjectionAnalysis(res.data.injectionAnalysis);
        setSafeSummary(res.data.safeSummary);
        
        if (res.data.injectionDetected) {
          toast.warning('Injection indicators found; review the Judge result');
        } else {
          toast.success('Email summarized successfully');
        }
        refreshEmailProgress();
      }
    } catch (err) {
      if (!scenarioIsCurrent('email', scenarioGeneration)) return;
      const msg = err.response?.data?.error || 'Failed to summarize email';
      toast.error(msg);
    } finally {
      if (scenarioIsCurrent('email', scenarioGeneration)) setIsSummarizing(false);
    }
  };

  const handleViewAnalysis = () => {
    setShowAnalysis(true);
    refreshEmailProgress();
  };

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text).then(() => {
      toast.success('Copied to clipboard');
    }).catch(() => {
      toast.error('Failed to copy');
    });
  };

  const highlightSuspicious = (text, keywords) => {
    if (!keywords || keywords.length === 0) return text;
    
    let result = text;
    keywords.forEach(kw => {
      const regex = new RegExp(`(${kw.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')})`, 'gi');
      result = result.replace(regex, '<mark class="suspicious-highlight">$1</mark>');
    });
    return result;
  };

  const ragReset = useWorkshopResetController({
    operationStorageKey: user?.id ? `dvaia:reset:${user.id}:indirect:document` : undefined,
    owner: {
      attendeeId: `platform-session-${ownerRevision}`,
      workshopKey: indirectPromptInjectionExperience.workshopKey,
      scenarioId: 'document',
    },
    title: 'Reset the Document Upload scenario?',
    description: 'This clears RAG objective progress, the loaded document, current session, question, and retrieved results. Email Agent state and workshop time are preserved.',
    onBegin: () => {
      if (!ownerIsCurrent()) throw new Error('Session changed; reopen reset.');
      invalidateScenario('document');
      setIsUploading(false);
      setIsQuerying(false);
    },
    mutation: ({ operationId }) => axios.post('/api/workshop/rag-injection/progress/reset', undefined,
      operationId ? { headers: { 'x-reset-operation-id': operationId } } : undefined),
    onCommit: async () => {
      if (!ownerIsCurrent()) return;
      const generation = captureScenario('document');
      const [currentResponse, progressResponse] = await Promise.all([
        axios.get('/api/workshop/rag-injection/current-session'),
        axios.get('/api/workshop/rag-injection/progress'),
      ]);
      if (!scenarioIsCurrent('document', generation)) throw new Error('Reset reconciliation superseded; retry to refresh the current document.');
      const current = currentResponse.data || {};
      const progress = progressResponse.data?.objectives || {};
      setCompletedObjectives(Object.fromEntries(RAG_OBJECTIVES.map(objective => [objective.id, progress[objective.id]?.completed === true])));
      setRagEvaluation(null);
      setRagSessionId(current.session_id || null);
      setUploadStatus(current.session_id ? { filename: current.filename, chunks_stored: current.chunks_stored || 0 } : null);
      setSelectedFile(null);
      setRagQuestion('');
      if (fileInputRef.current) fileInputRef.current.value = '';
      clearSession();
      toast.success('Document Upload scenario reset.');
    },
    onError: (err) => {
      if (!ownerIsCurrent()) return;
      const msg = err.response?.status === 403
        ? (err.response?.data?.error || 'Only the account owner or an admin can reset progress.')
        : 'Failed to reset Document Upload scenario.';
      toast.error(msg);
      return msg;
    },
  });

  const emailReset = useWorkshopResetController({
    owner: {
      attendeeId: `platform-session-${ownerRevision}`,
      workshopKey: indirectPromptInjectionExperience.workshopKey,
      scenarioId: 'email',
    },
    title: 'Reset the Email Agent scenario?',
    description: emailHealth.provider === 'mailpit'
      ? 'This clears Email Agent objective progress and pipeline results. Your server-assigned local inbox rotates with the reset generation; the selected attack scenario, custom payload, Document Upload state, and workshop time are preserved.'
      : 'This clears Email Agent objective progress and pipeline results. Your temporary email, selected attack scenario, custom payload, Document Upload state, and workshop time are preserved.',
    onBegin: () => {
      if (!ownerIsCurrent()) throw new Error('Session changed; reopen reset.');
      invalidateScenario('email');
      setIsSendingEmail(false);
      setIsFetchingEmail(false);
      setIsSummarizing(false);
    },
    mutation: () => axios.post('/api/email-agent/progress/reset'),
    onCommit: async () => {
      if (!ownerIsCurrent()) return;
      setEmailProgress({});
      setEmailJudgments([]);
      setEmailSent(false);
      setSentEmailInfo(null);
      setScrapedEmails([]);
      setFetchedEmail(null);
      setEmailSummary(null);
      setVulnerableEmailSummary(null);
      setEmailResponseMode(null);
      setEmailInjectionDetected(false);
      setInjectionAnalysis(null);
      setSafeSummary(null);
      setShowAnalysis(false);
      setEmailError(null);
      setManualFallback(false);
      setManualEmailContent('');
      const emailGeneration = captureScenario('email');
      const owned = await axios.get('/api/email-agent/owned-inbox');
      if (scenarioIsCurrent('email', emailGeneration) && owned.data?.ownedInbox) {
        setTempEmail(owned.data.ownedInbox);
        localStorage.setItem('dvaia_email_agent_temp_email', owned.data.ownedInbox);
      }
      if (!scenarioIsCurrent('email', emailGeneration)) return;
      toast.success('Email Agent scenario reset.');
    },
    onError: () => {
      if (!ownerIsCurrent()) return;
      const msg = 'Failed to reset Email Agent scenario.';
      toast.error(msg);
      return msg;
    },
  });

  const ragCompletedCount = visibleRagObjectives.filter(o => completedObjectives[o.id]).length;
  const ragAllComplete = visibleRagObjectives.length > 0
    && ragCompletedCount === visibleRagObjectives.length;
  const ragProgressPercent = visibleRagObjectives.length > 0
    ? (ragCompletedCount / visibleRagObjectives.length) * 100
    : 0;
  const emailCompletedCount = visibleEmailObjectives.filter(o => emailProgress[o.id]?.completed).length;
  const emailAllComplete = visibleEmailObjectives.length > 0
    && emailCompletedCount === visibleEmailObjectives.length;
  const emailProgressPercent = visibleEmailObjectives.length > 0
    ? (emailCompletedCount / visibleEmailObjectives.length) * 100
    : 0;

  return (
    <VulnerabilityTemplate challengeId="indirect_prompt_injection" icon={FiFileText} hideSidePanel={true}>
      <MultiScenarioWorkshop definition={indirectPromptInjectionExperience} activeScenarioId={activeTab}>
        <IntroSection>
          <h3><FiMessageSquare /> Indirect Prompt Injection Workshop</h3>
          <p>
            This workshop demonstrates <strong>indirect prompt injection</strong> attacks where malicious instructions 
            are embedded in external content (documents, emails) that AI systems process. Learn how attackers can 
            hijack AI behavior by poisoning the data the AI reads.
          </p>
        </IntroSection>

        <ScenarioNavigator
          definition={indirectPromptInjectionExperience}
          activeScenarioId={activeTab}
          onScenarioChange={nextTab => { if (nextTab !== activeTab) { setModeLoading(true); setActiveTab(nextTab); } }}
          renderLabel={(scenario) => (
            <>{scenario.id === 'document' ? <FiFileText /> : <FiMail />}{scenario.label}</>
          )}
        />

        <ModeControl aria-label="Indirect prompt injection agent mode">
          <p className="mode-description">
            {modeLoading || modeSaving ? 'Loading your shared workshop setting…'
              : ipiMode === 'fixed'
                ? 'Fixed mode treats retrieved documents and email as untrusted data. Defense credit requires the observed model response to pass the Judge.'
                : ipiMode === 'vuln'
                  ? 'Vulnerable mode exposes the teaching path so you can test whether source instructions redirect the model.'
                  : 'Existing lesson mode keeps the original mixed objectives. Choose a mode to apply one policy across the document and email agents.'}
          </p>
          <WorkshopModeControl mode={modeLoading || (modeError && ipiMode === null) ? undefined : ipiMode}
            allowedModes={['vuln', 'fixed']} unselectedModeLabel="Existing lesson mode"
            scopeLabel="Agent mode for documents and email" pending={modeLoading || modeSaving}
            disabled={!modeReady} onChange={chooseMode} />
          {modeError && <Button type="button" variant="secondary"
            onClick={() => setModeRefreshVersion(value => value + 1)}>Retry mode</Button>}
          {modeError && <div className="mode-error" role="alert">{modeError}</div>}
        </ModeControl>

        {/* Document Upload Tab */}
        <ScenarioWorkspace scenarioId="document" activeScenarioId={activeTab}>
          <TheoryBox>
            <h4>How RAG Injection Works</h4>
            <p>
              Retrieved document text enters the AI's context as external data. An attacker can embed instructions that try to
              redirect the assistant away from its task. Success depends on the model and its defenses; compare the actual
              response with the Judge result. Instructions placed directly in the user's question are direct prompt injection.
            </p>
          </TheoryBox>

          {health.embeddingReady && health.llmReady ? (
            <SuccessBanner initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
              <FiCheckCircle size={20} />
              <span style={{ flex: 1 }}>
                Embedding model & LLM ready
                {health.activeModel && <span style={{ opacity: 0.8 }}> (model: {health.activeModel})</span>}
              </span>
              <Button
                type="button"
                onClick={refreshRagHealth}
                disabled={isRefreshingRagHealth}
                style={{ padding: '0.4rem 0.8rem', fontSize: '0.8rem', background: 'rgba(255,255,255,0.2)' }}
                whileHover={{ scale: 1.02 }}
                whileTap={{ scale: 0.98 }}
              >
                <FiRefreshCw size={14} className={isRefreshingRagHealth ? 'spin' : ''} /> Refresh
              </Button>
            </SuccessBanner>
          ) : (
            <AttackBanner initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
              <FiAlertTriangle size={20} />
              <span style={{ flex: 1 }}>
                {!health.embeddingReady && !health.llmReady
                  ? 'Embedding model and LLM both unavailable. Check server startup logs for errors.'
                  : !health.embeddingReady
                    ? 'Embedding model not loaded. Check server logs for ONNX/initialization errors.'
                    : 'LLM service unavailable. Ensure the LLM provider is running.'}
                {health.message && <span style={{ display: 'block', fontSize: '0.85rem', marginTop: '0.25rem', opacity: 0.9 }}>{health.message}</span>}
              </span>
              <Button
                type="button"
                onClick={refreshRagHealth}
                disabled={isRefreshingRagHealth}
                style={{ padding: '0.4rem 0.8rem', fontSize: '0.8rem', background: 'rgba(255,255,255,0.2)' }}
                whileHover={{ scale: 1.02 }}
                whileTap={{ scale: 0.98 }}
              >
                <FiRefreshCw size={14} className={isRefreshingRagHealth ? 'spin' : ''} /> Retry
              </Button>
            </AttackBanner>
          )}

          <CurrentDocBar $isEmpty={!uploadStatus}>
            {uploadStatus ? (() => {
              const doc = resolveDocDisplay(uploadStatus.filename);
              return (
                <>
                  <FiFileText size={18} />
                  <span>
                    <strong>Document loaded in RAG:</strong>{' '}
                    {doc.icon} {doc.label}
                    {' '}
                    <span style={{
                      fontSize: '0.78rem', fontWeight: 600, padding: '0.1rem 0.5rem',
                      borderRadius: 10, marginLeft: '0.25rem',
                      background: doc.isCustom ? 'rgba(108,117,125,0.12)' : 'rgba(102,126,234,0.12)',
                      color: doc.isCustom ? '#555' : '#5568d3'
                    }}>
                      {doc.isCustom ? 'Custom Document' : 'Provided Document'}
                    </span>
                    {' '}— {uploadStatus.chunks_stored} chunks indexed
                  </span>
                </>
              );
            })() : (
              <>
                <FiAlertTriangle size={18} />
                <span><strong>No document loaded in RAG.</strong> Upload a .txt file or choose a sample below.</span>
              </>
            )}
          </CurrentDocBar>

          <TwoColumnLayout>
            <div>
              <Panel>
                <SectionTitle>Step 1: Upload a Document</SectionTitle>
                <UploadRow>
                  <input
                    ref={fileInputRef}
                    type="file"
                    accept=".txt,text/plain"
                    onChange={handleFileChange}
                    disabled={isUploading}
                    style={{ display: 'none' }}
                  />
                  <Button type="button" onClick={() => fileInputRef.current?.click()} disabled={isUploading} whileHover={{ scale: 1.02 }} whileTap={{ scale: 0.98 }}>
                    <FiUpload /> Choose .txt file (max 1MB)
                  </Button>
                  <Button type="button" onClick={handleUploadClick} disabled={isUploading} whileHover={{ scale: 1.02 }} whileTap={{ scale: 0.98 }}>
                    Upload
                  </Button>
                  {selectedFile && <span style={{ fontSize: '0.9rem', color: '#666' }}>{selectedFile.name}</span>}
                </UploadRow>
                <DownloadSection>
                  <div className="download-label">Download sample files:</div>
                  <div className="download-links">
                    <a href="/assets/rag_samples/random_document.txt" download="random_document.txt" className="download-link" title="ML intro document — use for objective 1 (load any document)">
                      <FiDownload size={16} /> Random Document (obj 1)
                    </a>
                    <a href="/assets/rag_samples/normal_policy.txt" download="normal_policy.txt" className="download-link" title="Clean HR policy — use for objectives 1–3">
                      <FiDownload size={16} /> Clean Policy (obj 1–3)
                    </a>
                    <a href="/assets/rag_samples/injected_document.txt" download="injected_document.txt" className="download-link" title="Policy with hidden SYSTEM OVERRIDE payload — use for objective 4">
                      <FiDownload size={16} /> Secure Poisoned RAG (obj 4)
                    </a>
                    <a href="/assets/rag_samples/query_injection_demo.txt" download="query_injection_demo.txt" className="download-link" title="Policy with embedded directive — use for objective 5, ask an off-topic question">
                      <FiDownload size={16} /> Poisoned RAG RolePlay (obj 5)
                    </a>
                  </div>
                </DownloadSection>
                <div style={{ fontSize: '0.9rem', fontWeight: 600, color: '#555', marginTop: '1.25rem', marginBottom: '0.75rem' }}>Or try a sample:</div>
                <SampleButtons>
                  {SAMPLE_FILES.map((s) => (
                    <Button
                      key={s.file + s.label}
                      type="button"
                      className="secondary"
                      onClick={() => loadSample(s)}
                      disabled={isUploading}
                      whileHover={{ scale: 1.02 }}
                      whileTap={{ scale: 0.98 }}
                    >
                      {s.label === 'Random Document' && '🎲 Random Document'}
                      {s.label === 'Clean Document' && '✅ Clean Document'}
                      {s.label === 'Secure Poisoned RAG' && '🛡️ Secure Poisoned RAG'}
                      {s.label === 'Poisoned RAG RolePlay' && '🎭 Poisoned RAG RolePlay'}
                    </Button>
                  ))}
                </SampleButtons>
                {uploadStatus && (() => {
                  const doc = resolveDocDisplay(uploadStatus.filename);
                  return (
                    <UploadStatus>
                      <FiCheckCircle />
                      <span>
                        Loaded: {doc.icon} <strong>{doc.label}</strong>
                        {' '}
                        <span style={{
                          fontSize: '0.78rem', fontWeight: 600, padding: '0.1rem 0.45rem',
                          borderRadius: 10,
                          background: doc.isCustom ? 'rgba(108,117,125,0.15)' : 'rgba(40,167,69,0.15)',
                          color: doc.isCustom ? '#555' : '#155724'
                        }}>
                          {doc.isCustom ? 'Custom' : 'Provided'}
                        </span>
                        {' '}— {uploadStatus.chunks_stored} chunks indexed
                      </span>
                    </UploadStatus>
                  );
                })()}
                {ragError && (
                  <div style={{ marginTop: '0.75rem', color: '#dc3545', fontSize: '0.9rem' }}>{safeText(ragError)}</div>
                )}
              </Panel>

              <Panel style={{ marginTop: '1.5rem' }}>
                <SectionTitle>Step 2: Ask a Question</SectionTitle>
                {uploadStatus && uploadStatus.filename && String(uploadStatus.filename).toLowerCase().includes('injected_document') && (
                  <p style={{ fontSize: '0.9rem', color: '#0c5460', background: 'rgba(23, 162, 184, 0.12)', padding: '0.5rem 0.75rem', borderRadius: 8, marginBottom: '0.75rem' }}>
                    <strong>Poisoned document:</strong> Ask a question to trigger the injection (Secure Poisoned RAG objective). Then load the Poisoned RAG RolePlay document and ask an off-topic question—e.g. "Give me a recipe for pie."
                  </p>
                )}
                <QuestionRow onSubmit={handleQuery}>
                  <input
                    type="text"
                    value={ragQuestion}
                    onChange={e => setRagQuestion(e.target.value)}
                    placeholder="What is the remote work policy?"
                    disabled={!modeReady || !ragSessionId || isQuerying || isUploading}
                    maxLength={500}
                  />
                  <Button type="submit" disabled={!modeReady || !ragSessionId || !ragQuestion.trim() || isQuerying || isUploading} whileHover={{ scale: 1.02 }} whileTap={{ scale: 0.98 }}>
                    <FiSend /> Ask
                  </Button>
                </QuestionRow>

                {attackDetected && (ragEvaluation?.mode === 'fixed'
                  ? <SuccessBanner initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
                      <FiShield size={24} />
                      <span>The Judge accepted this response as recognizing and rejecting the document instruction.</span>
                    </SuccessBanner>
                  : <AttackBanner initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
                      <FiAlertTriangle size={24} />
                      <span>The response detector flagged possible injection-related content. Review the model response and Judge result below to see whether this objective was completed.</span>
                    </AttackBanner>)}

                {(retrievedChunks.length > 0 || ragAnswer || ragEvaluation?.judgments?.length > 0) && (
                  <>
                    <SectionTitle style={{ fontSize: '1.1rem', marginBottom: '0.75rem' }}>AI Response</SectionTitle>
                    {ragEvaluation?.presentation_source === 'teaching_simulation' && <AttackBanner><FiAlertTriangle /><span>Teaching simulation. Objective grading uses the original model response below.</span></AttackBanner>}
                    {ragEvaluation?.judgments?.length > 0 && <div role="status">
                      <p>Judge: {ragEvaluation.judgments.map(j => `${j.objectiveId}: ${j.verdict}`).join(' · ')}. Accepted objectives: {(ragEvaluation.completedObjectiveIds || []).join(', ') || 'none'}.</p>
                      {getJudgeFeedback({ judgments: ragEvaluation.judgments }).map(feedback => <div key={`${feedback.objectiveId}-${feedback.evaluationId || feedback.verdict}`}>
                        <span style={{ whiteSpace: 'pre-wrap' }}>{feedback.content}</span>
                        <JudgeRetryButton evaluationId={feedback.evaluationId} canRetry={feedback.canRetry} onResult={(data, options) => handleJudgeRetryResult('document', data, options)} />
                      </div>)}
                    </div>}
                    <AnswerBox>
                      {ragAnswer
                        ? <SafeChatBody content={safeText(ragAnswer)} />
                        : '(No response received.)'}
                    </AnswerBox>
                    {ragEvaluation?.presentation_source === 'teaching_simulation' && <details><summary>Original model response</summary><pre style={{whiteSpace:'pre-wrap',overflowWrap:'anywhere'}}>{ragEvaluation.raw_model_answer || '(No model response)'}</pre></details>}
                  </>
                )}
              </Panel>
            </div>

            <Panel>
              <SectionTitle style={{ marginBottom: '1rem' }}><FiTarget /> Exercise Objectives</SectionTitle>
              {progressLoading && <div style={{ fontSize: '0.85rem', color: '#666', marginBottom: '0.5rem' }}>Loading progress...</div>}
              <ObjectivesListWrapper>
                <div className="objectives-list">
                  {visibleRagObjectives.map((obj, idx) => (
                    <ObjectiveItem
                      key={obj.id}
                      $completed={completedObjectives[obj.id]}
                      onClick={() => { if (isAllowedRagObjective(ipiMode, obj.id)) setActiveObjectiveId(obj.id); }}
                      aria-disabled={!isAllowedRagObjective(ipiMode, obj.id)}
                      style={{ cursor: isAllowedRagObjective(ipiMode, obj.id) ? 'pointer' : 'not-allowed', opacity: isAllowedRagObjective(ipiMode, obj.id) ? 1 : 0.58 }}
                      initial={{ opacity: 0, x: -10 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ delay: idx * 0.05 }}
                    >
                      {activeObjectiveId === obj.id && <div className="status-badge" style={{ background: '#667eea', right: completedObjectives[obj.id] ? '80px' : '0' }}>ACTIVE</div>}
                      {completedObjectives[obj.id] && <div className="status-badge">COMPLETED</div>}
                      <div className="obj-icon">
                        {completedObjectives[obj.id] ? <FiCheckCircle /> : <FiTarget />}
                      </div>
                      <div className="obj-content">
                        <div className="obj-name">{obj.name}</div>
                        <div className="obj-desc">{obj.description}</div>
                        {!isAllowedRagObjective(ipiMode, obj.id) && <div className="obj-desc">Switch to {ipiMode === 'fixed' ? 'Vulnerable' : 'Fixed'} mode for this objective.</div>}
                        {renderObjectiveHelp(obj, obj.id)}
                      </div>
                    </ObjectiveItem>
                  ))}
                </div>
              </ObjectivesListWrapper>
              <ProgressBlock>
                <div className="progress-title"><FiZap /> Progress</div>
                <div className="progress-text">
                  {ragCompletedCount} of {visibleRagObjectives.length} objectives completed
                </div>
                <div className="progress-bar-track">
                  <motion.div
                    className="progress-bar-fill"
                    initial={{ width: 0 }}
                    animate={{ width: `${ragProgressPercent}%` }}
                    transition={{ duration: 0.5, ease: 'easeOut' }}
                    style={{ minWidth: 0 }}
                  />
                </div>
                {ragAllComplete && (
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
                  <Button
                    type="button"
                    className="secondary"
                    onClick={ragReset.requestReset}
                    disabled={ragReset.resetting || isUploading || isQuerying}
                    style={{ padding: '0.5rem 1rem', fontSize: '0.85rem' }}
                  >
                    Reset Progress
                  </Button>
                </div>
              </ProgressBlock>

            </Panel>

              {retrievedChunks.length > 0 && (
                <Panel style={{ marginTop: '1.5rem' }}>
                  <SectionTitle style={{ fontSize: '1.1rem', marginBottom: '0.75rem' }}><FiFileText /> Retrieved Context Chunks</SectionTitle>
                  <ChunkList>
                    {retrievedChunks.map((c, i) => (
                      <ChunkCard key={i} className={isInjected(c.text) ? 'injected' : ''}>
                        <div className="chunk-meta">
                          {isInjected(c.text) && '⚠ '}Chunk {c.chunkIndex + 1} (score: {typeof c.score === 'number' ? c.score.toFixed(2) : c.score})
                        </div>
                        <span className="chunk-body">{safeText(c.text)}</span>
                      </ChunkCard>
                    ))}
                  </ChunkList>
                </Panel>
              )}
          </TwoColumnLayout>
        </ScenarioWorkspace>

        {/* Email Agent Tab (Reversed Flow) */}
        <ScenarioWorkspace scenarioId="email" activeScenarioId={activeTab}>
          <TheoryBox>
            <h4>How Email Agent Injection Works</h4>
            <p>
              AI email assistants that summarize or respond to emails can be compromised when attackers embed hidden 
              instructions in email content. In this workshop, compare the assistants' actual summaries of a poisoned email
              to determine whether they follow or ignore its embedded instructions.
            </p>
          </TheoryBox>

          {emailHealth.llm?.available && emailHealth.gmail?.canSend ? (
            <SuccessBanner initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
              <FiCheckCircle size={20} />
              <span style={{ flex: 1 }}>
                AI Service and Gmail ready
                {emailHealth.llm?.activeModel && (
                  <span style={{ opacity: 0.8 }}>
                    {' '}({emailHealth.llm.providerName || 'AI'}: {emailHealth.llm.activeModel}
                    {emailHealth.llm.region ? `, ${emailHealth.llm.region}` : ''})
                  </span>
                )}
              </span>
              <Button
                type="button"
                onClick={refreshEmailHealth}
                disabled={isRefreshingEmailHealth}
                style={{ padding: '0.4rem 0.8rem', fontSize: '0.8rem', background: 'rgba(255,255,255,0.2)' }}
                whileHover={{ scale: 1.02 }}
                whileTap={{ scale: 0.98 }}
              >
                <FiRefreshCw size={14} className={isRefreshingEmailHealth ? 'spin' : ''} /> Refresh
              </Button>
            </SuccessBanner>
          ) : (
            <AttackBanner initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
              <FiAlertTriangle size={20} />
              <span style={{ flex: 1 }}>
                {!emailHealth.llm?.available && (
                  emailHealth.llm?.provider === 'ollama'
                    ? 'AI service unavailable. Start Ollama (ollama serve). '
                    : `AI service unavailable${emailHealth.llm?.providerName ? ` (${emailHealth.llm.providerName})` : ''}. ${emailHealth.llm?.message || ''} `
                )}
                {!emailHealth.gmail?.canSend && (
                  <>
                    Gmail send service not configured.
                    {emailHealth.gmail?.error && (
                      <span style={{ display: 'block', marginTop: '0.25rem', fontSize: '0.85rem', opacity: 0.9 }}>
                        Error: {emailHealth.gmail.error}
                      </span>
                    )}
                    {emailHealth.gmail?.setupHint && (
                      <span style={{ display: 'block', marginTop: '0.25rem', fontSize: '0.85rem', opacity: 0.9 }}>
                        {emailHealth.gmail.setupHint}
                      </span>
                    )}
                  </>
                )}
                {emailHealth.llm?.ollamaBaseURL && !emailHealth.llm?.available && emailHealth.llm?.provider === 'ollama' && (
                  <span style={{ display: 'block', fontSize: '0.85rem', marginTop: '0.25rem', opacity: 0.9 }}>
                    Ollama server: {emailHealth.llm.ollamaBaseURL}
                  </span>
                )}
              </span>
              <Button
                type="button"
                onClick={refreshEmailHealth}
                disabled={isRefreshingEmailHealth}
                style={{ padding: '0.4rem 0.8rem', fontSize: '0.8rem', background: 'rgba(255,255,255,0.2)' }}
                whileHover={{ scale: 1.02 }}
                whileTap={{ scale: 0.98 }}
              >
                <FiRefreshCw size={14} className={isRefreshingEmailHealth ? 'spin' : ''} /> Retry
              </Button>
            </AttackBanner>
          )}

          <TwoColumnLayout>
            <div>
              <InstructionPanel>
                <h4><FiMail /> How This Workshop Works</h4>
                <div className="step">
                  <div className="step-number">1</div>
                  <div className="step-content">
                    {emailHealth.provider === 'mailpit'
                      ? 'Use the server-assigned local inbox. It is private to this learner and reset generation.'
                      : 'Get a free temporary email address from SharkLasers or GuerrillaMail (no signup required).'}
                  </div>
                </div>
                {emailHealth.provider !== 'mailpit' && <ExternalLinks>
                  <a href="https://www.guerrillamail.com" target="_blank" rel="noopener noreferrer" className="primary">
                    <FiExternalLink /> GuerrillaMail.com (Recommended)
                  </a>
                  <a href="https://www.sharklasers.com" target="_blank" rel="noopener noreferrer" className="secondary">
                    <FiExternalLink /> SharkLasers.com
                  </a>
                </ExternalLinks>}
                <div className="step">
                  <div className="step-number">2</div>
                  <div className="step-content">
                    {emailHealth.provider === 'mailpit'
                      ? 'Your assigned local inbox is ready. Select an attack scenario to send a poisoned email.'
                      : "Enter your temporary email below and select an attack scenario. We'll send you a poisoned email."}
                  </div>
                </div>
                <div className="step">
                  <div className="step-number">3</div>
                  <div className="step-content">
                    Fetch the email from your inbox, then compare whether the AI summarizes it or follows the hidden instructions.
                  </div>
                </div>
              </InstructionPanel>

              <TargetEmailBox>
                <div>
                  <div style={{ fontSize: '0.85rem', color: '#666', marginBottom: '0.25rem' }}>Attack emails sent FROM:</div>
                  <div className="email-display">{emailHealth.gmail?.targetEmail || TARGET_EMAIL}</div>
                </div>
                <div style={{ fontSize: '0.8rem', color: '#666', maxWidth: '200px' }}>
                  {emailHealth.provider === 'mailpit'
                    ? 'Messages are captured by the owned local inbox.'
                    : "Check your spam folder if you don't see the email."}
                </div>
              </TargetEmailBox>

              <Panel>
                <SectionTitle>Step 1: Enter Your Temporary Email</SectionTitle>
                <p style={{ fontSize: '0.9rem', color: '#666', marginBottom: '0.75rem' }}>
                  {emailHealth.provider === 'mailpit'
                    ? 'Use the assigned local inbox shown below. It is scoped to your current reset generation.'
                    : 'Use a temporary email service like GuerrillaMail or SharkLasers.'}
                </p>
                <QuestionRow onSubmit={(e) => { e.preventDefault(); handleSaveTempEmail(); }}>
                  <input
                    type="email"
                    value={tempEmail}
                    onChange={e => setTempEmail(e.target.value)}
                    placeholder={emailHealth.provider === 'mailpit' ? 'Assigned local inbox' : 'youremail@sharklasers.com'}
                  />
                  <Button
                    type="button"
                    onClick={handleSaveTempEmail}
                    disabled={!isValidEmail(tempEmail)}
                    whileHover={{ scale: 1.02 }}
                    whileTap={{ scale: 0.98 }}
                  >
                    Save
                  </Button>
                </QuestionRow>
                {emailHealth.allowedDomains?.length > 0 && (
                  <div style={{ fontSize: '0.8rem', color: '#666', marginTop: '0.5rem' }}>
                    Allowed domains: {emailHealth.allowedDomains.slice(0, 5).join(', ')}{emailHealth.allowedDomains.length > 5 ? '...' : ''}
                  </div>
                )}

                <SectionTitle style={{ marginTop: '1.5rem' }}>Step 2: Select Attack Scenario & Send</SectionTitle>
                <p style={{ fontSize: '0.9rem', color: '#666', marginBottom: '0.75rem' }}>
                  Choose an attack scenario. We'll send you an email with hidden malicious instructions.
                </p>
                <div style={{ marginBottom: '1rem' }}>
                  <select
                    value={selectedScenario}
                    onChange={e => setSelectedScenario(e.target.value)}
                    style={{
                      width: '100%',
                      padding: '0.75rem 1rem',
                      border: '2px solid #e9ecef',
                      borderRadius: '8px',
                      fontSize: '0.95rem',
                      background: 'white',
                      cursor: 'pointer'
                    }}
                  >
                    {availableScenarios.map(scenario => (
                      <option key={scenario.id} value={scenario.id}>
                        {scenario.name}
                      </option>
                    ))}
                  </select>
                </div>

                {selectedScenario === 'custom' && (
                  <div style={{ marginBottom: '1rem' }}>
                    <textarea
                      value={customPayload}
                      onChange={e => setCustomPayload(e.target.value)}
                      placeholder="Enter your custom attack payload here (min 10 characters)..."
                      style={{
                        width: '100%',
                        minHeight: '120px',
                        padding: '0.75rem 1rem',
                        border: '2px solid #e9ecef',
                        borderRadius: '8px',
                        fontSize: '0.9rem',
                        fontFamily: 'monospace',
                        resize: 'vertical'
                      }}
                    />
                  </div>
                )}

                <Button
                  type="button"
                  onClick={handleSendAttackEmail}
                  disabled={!isValidEmail(tempEmail) || isSendingEmail || !emailHealth.gmail?.canSend}
                  whileHover={{ scale: 1.02 }}
                  whileTap={{ scale: 0.98 }}
                  className="danger"
                >
                  {isSendingEmail ? 'Sending...' : <><FiSend /> Send Attack Email to Me</>}
                </Button>

                {emailSent && sentEmailInfo && (
                  <SuccessBanner initial={{ opacity: 0 }} animate={{ opacity: 1 }} style={{ marginTop: '1rem' }}>
                    <FiCheckCircle size={20} />
                    <div>
                      <strong>Email Sent!</strong>
                      <div style={{ fontWeight: 400, fontSize: '0.85rem', marginTop: '0.25rem' }}>
                        Attack email sent to {sentEmailInfo.sentTo}. Check your inbox in 1-2 minutes.
                      </div>
                    </div>
                  </SuccessBanner>
                )}

                <SectionTitle style={{ marginTop: '1.5rem' }}>Step 3: Load Email Content</SectionTitle>
                <p style={{ fontSize: '0.9rem', color: '#666', marginBottom: '1rem' }}>
                  Fetch from your temporary inbox. If the provider fetch fails, the labeled manual fallback loads pasted workshop content but does not prove provider delivery.
                </p>
                <Button
                  type="button"
                  onClick={handleFetchFromSharkLasers}
                  disabled={!isValidEmail(tempEmail) || isFetchingEmail}
                  whileHover={{ scale: 1.02 }}
                  whileTap={{ scale: 0.98 }}
                >
                  {isFetchingEmail ? 'Fetching...' : <><FiMail /> Fetch My Emails</>}
                </Button>

                {manualFallback && (
                  <div style={{ marginTop: '1rem', padding: '1rem', background: 'rgba(255, 193, 7, 0.1)', border: '1px solid #ffc107', borderRadius: '8px' }}>
                    <div style={{ fontWeight: 600, color: '#856404', marginBottom: '0.5rem' }}>
                      <FiAlertTriangle size={14} style={{ marginRight: '0.5rem' }} />
                      Manual Entry Mode
                    </div>
                    <p style={{ fontSize: '0.85rem', color: '#666', marginBottom: '0.75rem' }}>
                      Automatic fetching failed. Paste the email body below. This source is recorded as manual workshop input and does not prove provider delivery:
                    </p>
                    <textarea
                      value={manualEmailContent}
                      onChange={e => setManualEmailContent(e.target.value)}
                      placeholder="Paste the email content here..."
                      style={{
                        width: '100%',
                        minHeight: '100px',
                        padding: '0.75rem',
                        border: '1px solid #e9ecef',
                        borderRadius: '8px',
                        fontSize: '0.9rem',
                        marginBottom: '0.75rem'
                      }}
                    />
                    <Button
                      type="button"
                      onClick={handleFetchFromSharkLasers}
                      disabled={manualEmailContent.trim().length < 10}
                      whileHover={{ scale: 1.02 }}
                      whileTap={{ scale: 0.98 }}
                      className="secondary"
                    >
                      Submit Manual Content
                    </Button>
                  </div>
                )}

                {emailError && !manualFallback && (
                  <div style={{ marginTop: '1rem', padding: '0.75rem 1rem', background: 'rgba(220, 53, 69, 0.1)', border: '1px solid #dc3545', borderRadius: '8px', color: '#721c24', fontSize: '0.9rem' }}>
                    {emailError}
                  </div>
                )}

                {fetchedEmail && (
                  <EmailCard>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1rem' }}>
                      <FiMail size={20} color="#667eea" />
                      <strong style={{ color: '#667eea' }}>Email Retrieved</strong>
                      {fetchedEmail.containsSuspiciousContent && (
                        <span style={{ background: '#ffc107', color: '#856404', padding: '0.2rem 0.5rem', borderRadius: '4px', fontSize: '0.75rem', fontWeight: 700, marginLeft: 'auto' }}>
                          <FiAlertTriangle size={12} style={{ marginRight: '0.25rem' }} />
                          SUSPICIOUS CONTENT
                        </span>
                      )}
                    </div>
                    <div className="email-header">
                      <div className="email-field">
                        <span className="label">From:</span>
                        <span className="value">{fetchedEmail.from}</span>
                      </div>
                      <div className="email-field">
                        <span className="label">Subject:</span>
                        <span className="value">{fetchedEmail.subject || '(No subject)'}</span>
                      </div>
                      {fetchedEmail.time && (
                        <div className="email-field">
                          <span className="label">Time:</span>
                          <span className="value">{fetchedEmail.time}</span>
                        </div>
                      )}
                    </div>
                    <div 
                      className="email-body"
                      dangerouslySetInnerHTML={{ 
                        __html: highlightSuspicious(
                          safeText(fetchedEmail.body).replace(/</g, '&lt;').replace(/>/g, '&gt;'), 
                          fetchedEmail.suspiciousKeywords
                        ) 
                      }}
                    />
                  </EmailCard>
                )}

                {fetchedEmail && (
                  <>
                    <SectionTitle style={{ marginTop: '1.5rem' }}>Step 4: Summarize Email</SectionTitle>
                    <p style={{ fontSize: '0.9rem', color: '#666', marginBottom: '1rem' }}>
                      Ask the AI to summarize this email, then check whether it follows or ignores the embedded instructions.
                    </p>
                    <Button
                      type="button"
                      onClick={handleSummarizeEmail}
                      disabled={!modeReady || isSummarizing || !emailHealth.llm?.available}
                      whileHover={{ scale: 1.02 }}
                      whileTap={{ scale: 0.98 }}
                    >
                      {isSummarizing ? 'Summarizing...' : <><FiSend /> Summarize Email</>}
                    </Button>
                  </>
                )}

                {emailJudgments.length > 0 && <div role="status">
                  <p>Judge: {emailJudgments.map(j => `${j.objectiveId}: ${j.verdict}`).join(' · ')}. Accepted completions appear in objective progress.</p>
                  {getJudgeFeedback({ judgments: emailJudgments }).map(feedback => <div key={`${feedback.objectiveId}-${feedback.evaluationId || feedback.verdict}`}>
                    <span style={{ whiteSpace: 'pre-wrap' }}>{feedback.content}</span>
                    <JudgeRetryButton evaluationId={feedback.evaluationId} canRetry={feedback.canRetry} onResult={(data, options) => handleJudgeRetryResult('email', data, options)} />
                  </div>)}
                </div>}
                {emailSummary && (
                  <>
                    <SectionTitle style={{ marginTop: '1.5rem', fontSize: '1.1rem' }}>
                      <FiZap /> {emailResponseMode === 'fixed' ? 'Fixed agent response' : 'Agent response'}
                    </SectionTitle>
                    <AnswerBox><SafeChatBody content={safeText(emailSummary)} /></AnswerBox>
                    <SectionTitle style={{ marginTop: '1.5rem', fontSize: '1.1rem' }}>Observed response comparison</SectionTitle>
                    
                    <SideBySideComparison>
                      <ComparisonPanel
                        className="vulnerable"
                        initial={{ opacity: 0, x: -20 }}
                        animate={{ opacity: 1, x: 0 }}
                        transition={{ duration: 0.3 }}
                      >
                        <div className="panel-header">
                          <FiAlertTriangle className="panel-icon" />
                          Vulnerable AI Output
                          <span className="panel-subtitle">Observed teaching response</span>
                        </div>
                        <div className="panel-content">{safeText(vulnerableEmailSummary || 'No vulnerable response available')}</div>
                      </ComparisonPanel>
                      
                      <ComparisonPanel
                        className="secure"
                        initial={{ opacity: 0, x: 20 }}
                        animate={{ opacity: 1, x: 0 }}
                        transition={{ duration: 0.3, delay: 0.1 }}
                      >
                        <div className="panel-header">
                          <FiShield className="panel-icon" />
                          Secure AI Output
                          <span className="panel-subtitle">Observed defense response</span>
                        </div>
                        <div className="panel-content">{safeText(safeSummary || 'No secure summary available')}</div>
                      </ComparisonPanel>
                    </SideBySideComparison>

                    {emailInjectionDetected && (
                      <>
                        <AttackBanner initial={{ opacity: 0 }} animate={{ opacity: 1 }} style={{ marginTop: '1rem' }}>
                          <FiAlertTriangle size={24} />
                          <div>
                            <strong>Injection indicators found</strong>
                            <div style={{ fontWeight: 400, fontSize: '0.9rem', marginTop: '0.25rem' }}>
                              The email or response contains possible injection indicators.
                              Compare the actual outputs and objective Judge results to determine whether the attack succeeded.
                            </div>
                          </div>
                        </AttackBanner>

                        {!showAnalysis && (
                          <Button
                            type="button"
                            className="danger"
                            onClick={handleViewAnalysis}
                            whileHover={{ scale: 1.02 }}
                            whileTap={{ scale: 0.98 }}
                            style={{ marginTop: '0.5rem' }}
                          >
                            <FiEye /> Show Attack Analysis
                          </Button>
                        )}

                        {showAnalysis && injectionAnalysis && (
                          <AttackAnalysisPanel
                            initial={{ opacity: 0, y: 10 }}
                            animate={{ opacity: 1, y: 0 }}
                          >
                            <h4><FiShield /> Attack Analysis</h4>
                            <div className="analysis-row">
                              <span className="label">Attack Type:</span>
                              <span className="value">{injectionAnalysis.attackType}</span>
                            </div>
                            <div className="analysis-row">
                              <span className="label">Severity:</span>
                              <span className="value">{injectionAnalysis.severity}</span>
                            </div>
                            <div className="analysis-row">
                              <span className="label">Injected Instructions:</span>
                              <span className="value" style={{ fontFamily: 'monospace', fontSize: '0.85rem' }}>
                                {injectionAnalysis.injectedInstructions}
                              </span>
                            </div>
                            <div className="analysis-row">
                              <span className="label">Expected Behavior:</span>
                              <span className="value">{injectionAnalysis.expectedBehavior}</span>
                            </div>
                            <div className="analysis-row">
                              <span className="label">Actual Behavior:</span>
                              <span className="value">{injectionAnalysis.actualBehavior}</span>
                            </div>
                          </AttackAnalysisPanel>
                        )}
                      </>
                    )}
                  </>
                )}

                <PrivacyNotice>
                  <FiShield size={16} />
                  Emails are sent to temporary addresses only. Your privacy is protected.
                </PrivacyNotice>
              </Panel>
            </div>

            <Panel>
              <SectionTitle style={{ marginBottom: '1rem' }}><FiTarget /> Email Agent Objectives</SectionTitle>
              {emailProgressLoading && <div style={{ fontSize: '0.85rem', color: '#666', marginBottom: '0.5rem' }}>Loading progress...</div>}
              <ObjectivesListWrapper>
                <div className="objectives-list">
                  {visibleEmailObjectives.map((obj, idx) => (
                    <ObjectiveItem
                      key={obj.id}
                      $completed={emailProgress[obj.id]?.completed}
                      aria-disabled={!isAllowedEmailObjective(ipiMode, obj.id)}
                      style={{ opacity: isAllowedEmailObjective(ipiMode, obj.id) ? 1 : 0.58 }}
                      initial={{ opacity: 0, x: -10 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ delay: idx * 0.05 }}
                    >
                      {emailProgress[obj.id]?.completed && <div className="status-badge">COMPLETED</div>}
                      <div className="obj-icon">
                        {emailProgress[obj.id]?.completed ? <FiCheckCircle /> : <FiTarget />}
                      </div>
                      <div className="obj-content">
                        <div className="obj-name">{obj.name}</div>
                        <div className="obj-desc">{obj.description}</div>
                        {!isAllowedEmailObjective(ipiMode, obj.id) && <div className="obj-desc">Switch to {ipiMode === 'fixed' ? 'Vulnerable' : 'Fixed'} mode for this objective.</div>}
                        {renderObjectiveHelp(obj, obj.configId)}
                      </div>
                    </ObjectiveItem>
                  ))}
                </div>
              </ObjectivesListWrapper>
              <ProgressBlock>
                <div className="progress-title"><FiZap /> Progress</div>
                <div className="progress-text">
                  {emailCompletedCount} of {visibleEmailObjectives.length} objectives completed
                </div>
                <div className="progress-bar-track">
                  <motion.div
                    className="progress-bar-fill"
                    initial={{ width: 0 }}
                    animate={{ width: `${emailProgressPercent}%` }}
                    transition={{ duration: 0.5, ease: 'easeOut' }}
                    style={{ minWidth: 0 }}
                  />
                </div>
                {emailAllComplete && (
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
                  <Button
                    type="button"
                    className="secondary"
                    onClick={emailReset.requestReset}
                    disabled={emailReset.resetting || isSendingEmail || isFetchingEmail || isSummarizing}
                    style={{ padding: '0.5rem 1rem', fontSize: '0.85rem' }}
                  >
                    Reset Progress
                  </Button>
                </div>
              </ProgressBlock>
            </Panel>
          </TwoColumnLayout>
        </ScenarioWorkspace>
        <ResetConfirmation {...ragReset.confirmation} />
        <ResetConfirmation {...emailReset.confirmation} />
      </MultiScenarioWorkshop>
    {viewingIpiSolution && (
      <ObjectiveHelpModal
        kind="solution"
        appearance="legacy-light"
        objective={{ name: viewingIpiSolution.title || viewingIpiSolution.id }}
        content={ipiSolutionContent(viewingIpiSolution)}
        onClose={closeIpiSolution}
      />
    )}
    </VulnerabilityTemplate>
  );
};

export default IndirectPromptInjectionChallenge;
