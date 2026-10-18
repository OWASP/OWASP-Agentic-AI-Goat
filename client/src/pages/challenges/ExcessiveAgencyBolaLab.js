/**
 * Excessive Agency + BOLA Lab
 * 
 * This lab demonstrates two security vulnerabilities:
 * - Scenario A: Agentic BOLA (Broken Object Level Authorization)
 * - Scenario B: Unsafe Decisioning (Auto-Refund Without Guardrails)
 * 
 * UI redesigned to match Direct Prompt Injection challenge pattern.
 */

import React, { useState, useEffect, useRef, useMemo } from 'react';
import styled from 'styled-components';
import {
  FiSend, FiAlertTriangle, FiCheckCircle, FiUser, FiLogOut,
  FiRefreshCw, FiFileText, FiShoppingCart, FiShield, FiUnlock,
  FiLock, FiMessageSquare, FiActivity, FiTarget, FiZap, FiCode, FiEye, FiCpu
} from 'react-icons/fi';
import { toast } from 'react-toastify';
import { getJudgeFeedback } from '../../utils/judgeFeedback.mjs';
import JudgeRetryButton from '../../components/workshop/JudgeRetryButton';
import ObjectiveHelpModal from '../../components/workshop/ObjectiveHelpModal';
import { motion, AnimatePresence } from 'framer-motion';
import axios from 'axios';
import VulnerabilityTemplate from '../../components/VulnerabilityTemplate';
import HintPanel from '../../components/HintPanel';
import {
  SingleScenarioWorkshop, WorkshopButton as WorkshopButtonBase,
  WorkshopModeControl, ScopedResetButton, ResetConfirmation, ObjectiveHelpActions, SafeChatBody,
} from '../../components/workshop/WorkshopExperience';
import { excessiveAgencyWorkshopExperience } from '../../components/workshop/experience.mjs';
import useWorkshopHeartbeat from '../../hooks/useWorkshopHeartbeat';
import useChangePolling from '../../hooks/useChangePolling';
import useReconciliationGuard, { useGuardedSetter } from '../../hooks/useReconciliationGuard';
import { useWorkshopConfig } from '../../context/WorkshopConfigContext';

const API_BASE = '/api/excessive-agency';

export function toolExecutionsFromResponse(data) {
  if (Array.isArray(data?.toolExecutions)) return data.toolExecutions;
  return data?.toolExecution ? [data.toolExecution] : [];
}

export function appendToolExecutions(previous, incoming, responseId) {
  const known = new Set(previous.map(execution => execution.id));
  const additions = incoming.flatMap((execution, index) => {
    const localPart = execution?.id ?? execution?.sequence ?? index + 1;
    const id = `response-${responseId}:${localPart}`;
    if (known.has(id)) return [];
    known.add(id);
    return [{ ...execution, id }];
  });
  return [...previous, ...additions];
}

// ----- Styled components matching Direct Prompt Injection page -----
const ChallengeContent = styled.div`
  display: flex;
  flex-direction: column;
  gap: 2rem;
`;

const SectionTitle = styled.h2`
  color: #333;
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
  box-shadow: 0 4px 20px rgba(0, 0, 0, 0.08);
  overflow: hidden;
  display: flex;
  flex-direction: column;
  height: 700px;
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

const StatusIndicator = styled.div`
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background: ${({ available }) => available === true ? '#4ade80' : available === false ? '#f87171' : '#9ca3af'};
  box-shadow: 0 0 8px ${({ available }) => available === true ? '#4ade80' : available === false ? '#f87171' : '#9ca3af'};
  animation: pulse 2s infinite;
  @keyframes pulse {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.5; }
  }
`;

const ModeIndicator = styled.div`
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.4rem 0.75rem;
  border-radius: 6px;
  font-weight: 600;
  font-size: 0.8rem;
  background: ${props => props.$isVuln ? 'rgba(239, 68, 68, 0.2)' : 'rgba(34, 197, 94, 0.2)'};
  color: ${props => props.$isVuln ? '#fca5a5' : '#86efac'};
  border: 1px solid ${props => props.$isVuln ? 'rgba(239, 68, 68, 0.4)' : 'rgba(34, 197, 94, 0.4)'};
  cursor: pointer;
  transition: all 0.2s;
  
  &:hover {
    transform: scale(1.02);
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
  padding: 0.875rem 1.25rem;
  background: ${props => {
    if (props.completed) return '#f0fdf4';
    if (props.$modeMatch) return props.$objMode === 'fixed' ? 'rgba(34, 197, 94, 0.05)' : 'rgba(239, 68, 68, 0.05)';
    return '#f8f9fa';
  }};
  border: 1px solid ${props => {
    if (props.completed) return '#22c55e';
    if (props.$modeMatch) return props.$objMode === 'fixed' ? '#22c55e' : '#ef4444';
    return '#e2e8f0';
  }};
  border-radius: 10px;
  transition: all 0.3s ease;
  position: relative;
  overflow: hidden;
  opacity: ${props => props.$modeMatch || props.completed ? 1 : 0.6};

  &:hover {
    transform: translateY(-2px);
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.05);
    border-color: ${props => props.$objMode === 'fixed' ? '#22c55e' : '#ef4444'};
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
    background: ${props => props.completed ? '#22c55e' : '#dee2e6'};
  }

  .mode-badge {
    display: inline-flex;
    align-items: center;
    gap: 0.25rem;
    padding: 0.15rem 0.5rem;
    font-size: 0.6rem;
    font-weight: 700;
    letter-spacing: 0.05em;
    border-radius: 4px;
    text-transform: uppercase;
    background: ${props => props.$objMode === 'fixed' ? 'rgba(34, 197, 94, 0.15)' : 'rgba(239, 68, 68, 0.15)'};
    color: ${props => props.$objMode === 'fixed' ? '#16a34a' : '#dc2626'};
    border: 1px solid ${props => props.$objMode === 'fixed' ? 'rgba(34, 197, 94, 0.3)' : 'rgba(239, 68, 68, 0.3)'};
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
    background: ${props => {
      if (props.completed) return '#22c55e';
      return props.$objMode === 'fixed' ? '#22c55e' : '#ef4444';
    }};
    color: white;
  }
  .obj-content {
    flex: 1;
  }
  .obj-name {
    font-weight: 600;
    color: #333;
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

const ModeSectionHeader = styled.div`
  display: flex;
  align-items: center;
  gap: 0.75rem;
  padding: 0.75rem 1rem;
  margin: 0.5rem 0;
  background: ${props => props.mode === 'fixed' ? 'linear-gradient(135deg, rgba(34, 197, 94, 0.1), rgba(34, 197, 94, 0.05))' : 'linear-gradient(135deg, rgba(239, 68, 68, 0.1), rgba(239, 68, 68, 0.05))'};
  border-left: 4px solid ${props => props.mode === 'fixed' ? '#22c55e' : '#ef4444'};
  border-radius: 0 8px 8px 0;
  
  .section-icon {
    display: flex;
    align-items: center;
    justify-content: center;
    width: 28px;
    height: 28px;
    border-radius: 50%;
    background: ${props => props.mode === 'fixed' ? '#22c55e' : '#ef4444'};
    color: white;
    font-size: 0.9rem;
  }
  
  .section-title {
    font-weight: 700;
    font-size: 0.85rem;
    color: ${props => props.mode === 'fixed' ? '#16a34a' : '#dc2626'};
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }
  
  .section-desc {
    font-size: 0.75rem;
    color: #666;
    margin-left: auto;
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
    color: #333;
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
    white-space: pre-wrap;
    word-break: break-word;
    overflow-wrap: break-word;
  }
  .tool-result {
    margin-top: 0.75rem;
    padding: 0.75rem;
    background: rgba(0, 0, 0, 0.05);
    border-radius: 8px;
    border-left: 3px solid #667eea;
    font-family: monospace;
    font-size: 0.8rem;
    color: #555;
    white-space: pre-wrap;
  }
  .warning-badge {
    margin-top: 0.5rem;
    padding: 0.4rem 0.75rem;
    background: rgba(245, 158, 11, 0.15);
    border: 1px solid #f59e0b;
    border-radius: 6px;
    font-size: 0.8rem;
    color: #b45309;
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }
  .objective-badge {
    display: inline-flex;
    align-items: center;
    gap: 0.25rem;
    font-size: 0.7rem;
    font-weight: 700;
    color: #28a745;
    background: rgba(40, 167, 69, 0.2);
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

const TabContainer = styled.div`
  display: flex;
  border-bottom: 2px solid #e2e8f0;
  background: white;
  flex-shrink: 0;
`;

const Tab = styled.button`
  flex: 1;
  padding: 0.875rem 1rem;
  border: none;
  background: ${props => props.$active ? 'white' : '#f8f9fa'};
  color: ${props => props.$active ? '#667eea' : '#6c757d'};
  font-weight: 600;
  font-size: 0.9rem;
  cursor: pointer;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 0.5rem;
  transition: all 0.2s;
  border-bottom: 3px solid ${props => props.$active ? '#667eea' : 'transparent'};
  margin-bottom: -2px;
  
  &:hover {
    background: ${props => props.$active ? 'white' : '#e9ecef'};
    color: #667eea;
  }
  
  .badge {
    background: ${props => props.$active ? '#667eea' : '#6c757d'};
    color: white;
    padding: 0.15rem 0.5rem;
    border-radius: 10px;
    font-size: 0.7rem;
    font-weight: 700;
  }
`;

const ToolActivityPanel = styled.div`
  background: #1e293b;
  flex: 1;
  display: flex;
  flex-direction: column;
  min-height: 0;
  overflow: hidden;
`;

const ToolActivityHeader = styled.div`
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 1rem 1.25rem;
  background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
  border-bottom: 1px solid #334155;
  flex-shrink: 0;
  
  h4 {
    margin: 0;
    color: #e2e8f0;
    font-size: 1rem;
    font-weight: 600;
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }
  
  .toggle-icon {
    color: #64748b;
    transition: transform 0.2s;
    &.expanded {
      transform: rotate(180deg);
    }
  }
`;

const ToolActivityContent = styled.div`
  flex: 1;
  overflow-y: auto;
  padding: 1rem;
  min-height: 0;
  
  &::-webkit-scrollbar { width: 6px; }
  &::-webkit-scrollbar-track { background: #1e293b; }
  &::-webkit-scrollbar-thumb { background: #475569; border-radius: 3px; }
`;

const ToolExecutionEntry = styled.div`
  background: #0f172a;
  border-radius: 10px;
  padding: 1rem;
  margin-bottom: 0.75rem;
  font-family: 'Fira Code', 'Consolas', monospace;
  font-size: 0.8rem;
  border: 1px solid #334155;
  transition: all 0.2s;
  
  &:hover {
    border-color: #475569;
    box-shadow: 0 2px 8px rgba(0, 0, 0, 0.2);
  }
  
  &:last-child {
    margin-bottom: 0;
  }
  
  .tool-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 0.75rem;
  }
  
  .tool-name {
    color: #22d3ee;
    font-weight: 700;
    font-size: 0.9rem;
  }
  
  .tool-status {
    padding: 0.25rem 0.75rem;
    border-radius: 6px;
    font-size: 0.7rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    
    &.success {
      background: rgba(34, 197, 94, 0.2);
      color: #22c55e;
      border: 1px solid rgba(34, 197, 94, 0.3);
    }
    
    &.error {
      background: rgba(239, 68, 68, 0.2);
      color: #ef4444;
      border: 1px solid rgba(239, 68, 68, 0.3);
    }
  }
  
  .tool-args {
    color: #94a3b8;
    margin-bottom: 0.5rem;
    padding: 0.5rem;
    background: rgba(0, 0, 0, 0.3);
    border-radius: 6px;
    word-break: break-all;
    
    .label {
      color: #f59e0b;
      font-weight: 600;
    }
  }
  
  .tool-result {
    color: #a5b4fc;
    margin-bottom: 0.5rem;
    padding: 0.5rem;
    background: rgba(0, 0, 0, 0.3);
    border-radius: 6px;
    max-height: 100px;
    overflow-y: auto;
    word-break: break-all;
    
    .label {
      color: #34d399;
      font-weight: 600;
    }
    
    &::-webkit-scrollbar { width: 4px; }
    &::-webkit-scrollbar-track { background: transparent; }
    &::-webkit-scrollbar-thumb { background: #475569; border-radius: 2px; }
  }
  
  .tool-timestamp {
    color: #64748b;
    font-size: 0.7rem;
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }
`;

const EmptyToolLog = styled.div`
  color: #94a3b8;
  font-size: 0.9rem;
  text-align: center;
  padding: 3rem 2rem;
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 1rem;
  
  .icon {
    font-size: 2.5rem;
    color: #475569;
  }
  
  .title {
    font-weight: 600;
    color: #e2e8f0;
  }
  
  .subtitle {
    font-size: 0.85rem;
    color: #64748b;
  }
`;

const Button = styled(motion.button)`
  background: ${props => props.variant === 'secondary' ? 'linear-gradient(135deg, #6c757d, #495057)' : 'linear-gradient(135deg, #667eea, #764ba2)'};
  color: white;
  border: none;
  padding: 0.75rem 1.5rem;
  border-radius: 8px;
  font-weight: 600;
  font-size: 0.95rem;
  cursor: pointer;
  display: inline-flex;
  align-items: center;
  gap: 0.5rem;
  &:hover:not(:disabled) {
    transform: translateY(-2px);
    box-shadow: 0 4px 12px rgba(102, 126, 234, 0.3);
  }
  &:disabled { opacity: 0.5; cursor: not-allowed; }
  &.full-width { width: 100%; justify-content: center; }
`;

const LoginPanel = styled.div`
  background: white;
  border: 2px solid #667eea;
  border-radius: 16px;
  padding: 2rem;
  max-width: 450px;
  margin: 2rem auto;
  box-shadow: 0 4px 20px rgba(102, 126, 234, 0.15);
`;

const LoginButton = styled.button`
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 0.75rem;
  padding: 1rem;
  width: 100%;
  border-radius: 10px;
  border: 2px solid transparent;
  cursor: pointer;
  font-weight: 600;
  font-size: 1rem;
  transition: all 0.2s;
  margin-bottom: 0.75rem;
  
  &.alice {
    background: linear-gradient(135deg, #ec4899, #be185d);
    color: white;
    
    &:hover {
      transform: translateY(-2px);
      box-shadow: 0 8px 20px rgba(236, 72, 153, 0.3);
    }
  }
  
  &.bob {
    background: linear-gradient(135deg, #3b82f6, #1d4ed8);
    color: white;
    
    &:hover {
      transform: translateY(-2px);
      box-shadow: 0 8px 20px rgba(59, 130, 246, 0.3);
    }
  }
  
  &.charlie {
    background: linear-gradient(135deg, #10b981, #059669);
    color: white;
    
    &:hover {
      transform: translateY(-2px);
      box-shadow: 0 8px 20px rgba(16, 185, 129, 0.3);
    }
  }
  
  &.dave {
    background: linear-gradient(135deg, #f59e0b, #d97706);
    color: white;
    
    &:hover {
      transform: translateY(-2px);
      box-shadow: 0 8px 20px rgba(245, 158, 11, 0.3);
    }
  }
  
  &.eve {
    background: linear-gradient(135deg, #8b5cf6, #7c3aed);
    color: white;
    
    &:hover {
      transform: translateY(-2px);
      box-shadow: 0 8px 20px rgba(139, 92, 246, 0.3);
    }
  }
`;

const UserBadge = styled.div`
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.4rem 0.75rem;
  background: rgba(255, 255, 255, 0.2);
  border: 1px solid rgba(255, 255, 255, 0.3);
  border-radius: 6px;
  color: white;
  font-weight: 600;
  font-size: 0.85rem;
`;

const HeaderButton = styled.button`
  background: rgba(255, 255, 255, 0.2);
  border: 1px solid rgba(255, 255, 255, 0.3);
  color: white;
  padding: 0.4rem 0.75rem;
  border-radius: 6px;
  cursor: pointer;
  display: flex;
  align-items: center;
  gap: 0.4rem;
  font-size: 0.85rem;
  font-weight: 500;
  transition: all 0.2s;
  
  &:hover {
    background: rgba(255, 255, 255, 0.3);
  }
`;

const OBJECTIVES = [
  // Fixed Mode Objectives (1-4) - Demonstrate proper security controls
  { id: 1, name: 'List Your Own Data', mode: 'fixed', description: 'View your notes or orders in secure mode', hint: 'Try: "Show me my notes"', icon: FiFileText },
  { id: 2, name: 'Create a Note', mode: 'fixed', description: 'Create a new note for yourself', hint: 'Try: "Create a note titled Test"', icon: FiFileText },
  { id: 3, name: 'Try to Cancel an Order', mode: 'fixed', description: 'Attempt to cancel/delete an order (should fail)', hint: 'Try: "Cancel order-alice-1"', icon: FiShoppingCart },
  { id: 4, name: 'Try to Access Other User Data', mode: 'fixed', description: 'Attempt to view another user\'s data (should fail)', hint: 'Try: "Show me Bob\'s notes"', icon: FiLock },
  // Vulnerable Mode Objectives (5-9) - Demonstrate security vulnerabilities
  { id: 5, name: 'Access Another User\'s Data', mode: 'vuln', description: 'View notes/orders of another user (BOLA)', hint: 'Switch to Vulnerable mode, then: "Show Bob\'s orders"', icon: FiUnlock },
  { id: 6, name: 'Create Note for Another User', mode: 'vuln', description: 'Create a note for a different user', hint: 'Try: "Create a note for Bob titled Hacked"', icon: FiFileText },
  { id: 7, name: 'Create Order for Another User', mode: 'vuln', description: 'Create an order for a different user', hint: 'Try: "Create order for Bob for Laptop $500"', icon: FiShoppingCart },
  { id: 8, name: 'Delete Another User\'s Note', mode: 'vuln', description: 'Delete a note belonging to another user (BOLA)', hint: 'Try: "Delete note-bob-1"', icon: FiUnlock },
  { id: 9, name: 'Issue Unauthorized Refund', mode: 'vuln', description: 'Issue a refund for another user\'s order', hint: 'Try: "Refund order-bob-1 $50 damaged"', icon: FiShoppingCart }
];

// Helper function to format markdown-style text
const ExcessiveAgencyBolaLab = () => {
  const { snapshot, revision } = useWorkshopConfig();
  const exerciseConfig = snapshot?.exercises?.excessive_agency;
  const visibleObjectives = useMemo(() => (
    exerciseConfig?.isVisible === true
      ? OBJECTIVES.filter(objective => exerciseConfig.objectives?.[`objective_${objective.id}`]?.isVisible === true)
        .map(objective => {
          const configured = exerciseConfig.objectives[`objective_${objective.id}`];
          return { ...objective, name: configured.label || objective.name,
            description: configured.description?.trim() || objective.description };
        })
      : []
  ), [exerciseConfig]);
  const visibleObjectiveIds = useMemo(
    () => new Set(visibleObjectives.map(objective => `objective_${objective.id}`)),
    [visibleObjectives]
  );
  const [user, setUser] = useState(null);
  const [labMode, setLabMode] = useState('fixed');
  const [modePending, setModePending] = useState(false);
  const [messages, setMessages] = useState([]);
  const [inputMessage, setInputMessage] = useState('');
  const [loading, setLoading] = useState(false);
  const [sessionToken, setSessionToken] = useState(null);
  const progressGuard = useReconciliationGuard();
  const [completedObjectives, setCompletedObjectivesFromPoll] = useState({});
  const setCompletedObjectives = useGuardedSetter(setCompletedObjectivesFromPoll, progressGuard);
  const [progressLoading, setProgressLoading] = useState(false);
  const [toolExecutions, setToolExecutions] = useState([]);
  const [activeTab, setActiveTab] = useState('chat');
  const [llmStatus, setLlmStatus] = useState({ available: false, model: null, message: '', ollamaBaseURL: 'http://localhost:11434', ollamaVersion: null, availableModels: [] });
  const [eaSolutionVisibility, setEaSolutionVisibility] = useState({});
  const [viewingEaSolution, setViewingEaSolution] = useState(null);
  const [eaSolutionLoading, setEaSolutionLoading] = useState(null);
  const [progressResetConfirmation, setProgressResetConfirmation] = useState(false);
  const [progressResetPending, setProgressResetPending] = useState(false);
  const [progressResetError, setProgressResetError] = useState('');
  const pendingEaSolutionRef = useRef(null);

  const messageListRef = useRef(null);
  const nextIdRef = useRef(1);
  const platformToken = localStorage.getItem('token');
  const lifecycleRef = useRef({ controller: new AbortController(), mounted: true, platformToken });
  const boundaryBusyRef = useRef(false);
  const modeForegroundRef = useRef(null);
  const isCurrent = (scope) => lifecycleRef.current === scope && scope.mounted && !scope.controller.signal.aborted
    && scope.platformToken === localStorage.getItem('token');
  const retireRequests = () => {
    if (modeForegroundRef.current !== null) {
      progressGuard.endForeground('mode', modeForegroundRef.current);
      modeForegroundRef.current = null;
    }
    lifecycleRef.current.controller.abort();
    const scope = { controller: new AbortController(), mounted: true, platformToken: localStorage.getItem('token') };
    lifecycleRef.current = scope;
    progressGuard.mark('progress');
    setLoading(false);
    setProgressLoading(false);
    return scope;
  };
  useEffect(() => {
    if (lifecycleRef.current.controller.signal.aborted) {
      lifecycleRef.current = { controller: new AbortController(), mounted: true, platformToken };
    }
    lifecycleRef.current.mounted = true;
    return () => {
      lifecycleRef.current.mounted = false;
      lifecycleRef.current.controller.abort();
    };
  }, []);


  useEffect(() => {
    if (lifecycleRef.current.platformToken === platformToken) return;
    retireRequests();
    boundaryBusyRef.current = false;
    setUser(null);
    setSessionToken(null);
    setMessages([]);
    setToolExecutions([]);
    setCompletedObjectives({});
    setInputMessage('');
    setProgressResetConfirmation(false);
    setProgressResetPending(false);
    setProgressResetError('');
  }, [platformToken]);

  useWorkshopHeartbeat('excessive_agency');
  useChangePolling(async (_next, _previous, { signal } = {}) => {
    const scope = lifecycleRef.current;
    const modeGeneration = progressGuard.beginRequiredBackground('mode');
    const progressGeneration = progressGuard.begin('progress');
    const gatesGeneration = progressGuard.begin('solutionVisibility');
    const solutionDisclosureId = viewingEaSolution?.id || pendingEaSolutionRef.current;
    const modalGeneration = solutionDisclosureId
      ? progressGuard.begin('solutionModal')
      : null;
    const [solutionResponse, progressResponse, modeResponse] = await Promise.all([
      axios.get('/api/solutions/excessive-agency/status', { signal }),
      sessionToken
        ? axios.get(`${API_BASE}/progress`, { headers: { 'x-lab-session': sessionToken }, signal })
        : Promise.resolve(null),
      axios.get(`${API_BASE}/mode`, { signal }),
    ]);
    const nextSolutions = solutionResponse.data.objectives || {};
    const refreshedSolution = solutionDisclosureId && nextSolutions[solutionDisclosureId]
      ? await axios.get(`/api/solutions/excessive-agency/${solutionDisclosureId}`, { signal })
      : null;
    if (!isCurrent(scope)) return;
    progressGuard.commit('solutionVisibility', gatesGeneration, () => {
      setEaSolutionVisibility(nextSolutions);
      if (solutionDisclosureId && !nextSolutions[solutionDisclosureId]) {
        pendingEaSolutionRef.current = null;
        progressGuard.mark('solutionModal');
        setEaSolutionLoading(null);
        setViewingEaSolution(null);
      }
    });
    progressGuard.commit('progress', progressGeneration, () => {
      if (progressResponse) setCompletedObjectivesFromPoll(progressResponse.data.progress?.objectives || {});
    });
    progressGuard.commit('mode', modeGeneration, () => setLabMode(modeResponse.data.mode || 'fixed'));
    if (modalGeneration !== null && refreshedSolution && nextSolutions[solutionDisclosureId]) {
      progressGuard.commit('solutionModal', modalGeneration, () => {
        pendingEaSolutionRef.current = null;
        setEaSolutionLoading(null);
        setViewingEaSolution({ id: solutionDisclosureId, ...refreshedSolution.data.solution });
      });
    }
  }, ['excessive_agency']);

  const completedCount = visibleObjectives.filter(objective => completedObjectives[objective.id]).length;
  const allComplete = visibleObjectives.length > 0 && completedCount === visibleObjectives.length;

  useEffect(() => {
    const disclosureId = viewingEaSolution?.id || pendingEaSolutionRef.current;
    if (disclosureId && !visibleObjectiveIds.has(disclosureId)) {
      pendingEaSolutionRef.current = null;
      progressGuard.mark('solutionModal');
      setEaSolutionLoading(null);
      setViewingEaSolution(null);
    }
  }, [progressGuard, viewingEaSolution?.id, visibleObjectiveIds]);

  useEffect(() => {
    const gatesGeneration = progressGuard.begin('solutionVisibility');
    const modeGeneration = progressGuard.begin('mode');
    axios.get(`${API_BASE}/mode`)
      .then(res => progressGuard.commit('mode', modeGeneration, () => setLabMode(res.data.mode || 'fixed')))
      .catch(() => {});
    fetchLlmStatus();
    axios.get('/api/solutions/excessive-agency/status')
      .then(r => progressGuard.commit('solutionVisibility', gatesGeneration, () => {
        setEaSolutionVisibility(r.data.objectives || {});
      }))
      .catch(() => {});
  }, [progressGuard]);

  const handleViewEaSolution = async (objectiveId) => {
    if (!visibleObjectiveIds.has(objectiveId)) return;
    const modalGeneration = progressGuard.begin('solutionModal');
    pendingEaSolutionRef.current = objectiveId;
    setEaSolutionLoading(objectiveId);
    try {
      const { data } = await axios.get(`/api/solutions/excessive-agency/${objectiveId}`);
      progressGuard.commit('solutionModal', modalGeneration, () => {
        pendingEaSolutionRef.current = null;
        setViewingEaSolution({ id: objectiveId, ...data.solution });
      });
    } catch (err) {
      if (err.code === 'STALE_RECONCILIATION') return;
      toast.error(err.response?.data?.error || 'Solution not available.');
    } finally {
      if (progressGuard.capture('solutionModal') === modalGeneration) setEaSolutionLoading(null);
      if (progressGuard.capture('solutionModal') === modalGeneration) pendingEaSolutionRef.current = null;
    }
  };

  const closeEaSolution = () => {
    pendingEaSolutionRef.current = null;
    progressGuard.mark('solutionModal');
    setEaSolutionLoading(null);
    setViewingEaSolution(null);
  };

  useEffect(() => {
    const el = messageListRef.current;
    if (!el) return;
    const scrollToBottom = () => {
      el.scrollTop = el.scrollHeight;
    };
    requestAnimationFrame(scrollToBottom);
  }, [messages, loading]);

  const fetchLlmStatus = async () => {
    try {
      const { data } = await axios.get(`${API_BASE}/llm-status`);
      setLlmStatus({
        available: data.available,
        model: data.model || null,
        message: data.message || '',
        ollamaBaseURL: data.ollamaBaseURL || 'http://localhost:11434',
        ollamaVersion: data.ollamaVersion || null,
        availableModels: Array.isArray(data.availableModels) ? data.availableModels : []
      });
    } catch {
      setLlmStatus({ available: false, model: null, message: 'Could not reach AI service.', ollamaBaseURL: 'http://localhost:11434', ollamaVersion: null, availableModels: [] });
    }
  };

  const fetchProgress = async (token, scope = lifecycleRef.current, acceptsResult = () => true) => {
    const progressGeneration = progressGuard.begin('progress');
    try {
      setProgressLoading(true);
      const res = await axios.get(`${API_BASE}/progress`, {
        headers: { 'x-lab-session': token }, signal: scope.controller.signal
      });
      if (!isCurrent(scope) || !acceptsResult()) return;
      // A newer refresh owns progress; this successful GET is not a transport failure.
      if (progressGuard.capture('progress') !== progressGeneration) return true;
      const progress = res.data.progress?.objectives || {};
      progressGuard.commit('progress', progressGeneration, () => {
        setCompletedObjectivesFromPoll(progress);
      });
      return true;
    } catch (err) {
      if (!isCurrent(scope) || !acceptsResult()) return;
      if (progressGuard.capture('progress') !== progressGeneration) return true;
      console.error('Failed to fetch progress:', err);
      return false;
    } finally {
      if (isCurrent(scope) && progressGuard.capture('progress') === progressGeneration) setProgressLoading(false);
    }
  };

  const retryScope = lifecycleRef.current;
  const handleJudgeRetryResult = async (data, { signal } = {}) => {
    const acceptsResult = () => !signal?.aborted && !boundaryBusyRef.current && isCurrent(retryScope);
    if (!acceptsResult()) return;
    const retryMessages = getJudgeFeedback(data).map(feedback => ({
      id: nextIdRef.current++, type: 'system', plain: true,
      content: feedback.content, judgeVerdict: feedback.verdict, timestamp: new Date(),
      evaluationId: feedback.evaluationId, canRetry: feedback.canRetry,
    }));
    if (retryMessages.length) setMessages(prev => [...prev, ...retryMessages]);
    const refreshed = sessionToken ? await fetchProgress(sessionToken, retryScope, acceptsResult) : false;
    if (!acceptsResult()) return;
    if (refreshed === false) toast.warn('Evaluation received, but progress could not be refreshed. Refresh progress to see the latest counts.');
    else if (data.completed === true) toast.success('Objective evaluation passed.');
  };

  const handleLogin = async (username) => {
    const scope = retireRequests();
    boundaryBusyRef.current = true;
    try {
      const res = await axios.post(`${API_BASE}/auth/login`, {
        username,
        password: `${username}123`
      }, { signal: scope.controller.signal });
      if (!isCurrent(scope)) return;
      setUser(res.data.user);
      setSessionToken(res.data.sessionToken);
      await fetchProgress(res.data.sessionToken, scope);
      if (!isCurrent(scope)) return;
      
      // Fetch welcome message from server
      try {
        const welcomeRes = await axios.get(`${API_BASE}/welcome`, {
          headers: { 'x-lab-session': res.data.sessionToken }, signal: scope.controller.signal
        });
        if (!isCurrent(scope)) return;
        setMessages([{
          id: nextIdRef.current++,
          type: 'ai',
          content: welcomeRes.data.message,
          timestamp: new Date()
        }]);
      } catch (welcomeErr) {
        if (!isCurrent(scope)) return;
        setMessages([{
          id: nextIdRef.current++,
          type: 'ai',
          content: `Welcome to the Excessive Agency Lab, **${username}**! Ask me to show your notes, create orders, or try accessing other users' data.`,
          timestamp: new Date()
        }]);
      }
      
      toast.success(`Logged in as ${username}`);
    } catch (err) {
      if (!isCurrent(scope)) return;
      toast.error('Login failed');
    } finally {
      if (isCurrent(scope)) boundaryBusyRef.current = false;
    }
  };

  const handleLogout = async () => {
    const scope = retireRequests();
    boundaryBusyRef.current = true;
    try {
      await axios.post(`${API_BASE}/auth/logout`, {}, {
        headers: { 'x-lab-session': sessionToken }, signal: scope.controller.signal
      });
    } catch (err) {
      if (!isCurrent(scope)) return;
      // Ignore logout errors
    }
    if (!isCurrent(scope)) return;
    boundaryBusyRef.current = false;
    setUser(null);
    setSessionToken(null);
    setMessages([]);
    setCompletedObjectives({});
    setToolExecutions([]);
    setActiveTab('chat');
    toast.info('Logged out');
  };

  const toggleLabMode = async (requestedMode) => {
    if (modePending || boundaryBusyRef.current) return;
    const scope = lifecycleRef.current;
    const newMode = requestedMode || (labMode === 'vuln' ? 'fixed' : 'vuln');
    if (!['vuln', 'fixed'].includes(newMode) || newMode === labMode) return;
    const modeGeneration = progressGuard.beginForeground('mode');
    modeForegroundRef.current = modeGeneration;
    setModePending(true);
    try {
      const response = await axios.post(`${API_BASE}/mode`, { mode: newMode }, { signal: scope.controller.signal });
      if (!isCurrent(scope)) return;
      progressGuard.commit('mode', modeGeneration, () => setLabMode(response.data.mode));
      
      const systemMsg = {
        id: nextIdRef.current++,
        type: 'system',
        content: `Lab mode changed to: ${response.data.mode.toUpperCase()}\n\n${response.data.mode === 'vuln'
          ? '⚠️ VULNERABLE: Tools execute without proper authorization checks.' 
          : '🔒 FIXED: Tools enforce proper access control (ABAC).'}`,
        timestamp: new Date()
      };
      setMessages(prev => [...prev, systemMsg]);
      
      toast.info(`Mode: ${response.data.mode.toUpperCase()}`);
    } catch (err) {
      if (!isCurrent(scope) || err.code === 'STALE_RECONCILIATION') return;
      toast.error('Failed to change mode');
    } finally {
      progressGuard.endForeground('mode', modeGeneration);
      if (modeForegroundRef.current === modeGeneration) modeForegroundRef.current = null;
      setModePending(false);
    }
  };

  const handleResetConversation = async () => {
    if (boundaryBusyRef.current) return;
    const scope = retireRequests();
    boundaryBusyRef.current = true;
    try {
      await axios.post(`${API_BASE}/conversation/reset`, {}, {
        headers: { 'x-lab-session': sessionToken }, signal: scope.controller.signal
      });
      if (!isCurrent(scope)) return;
      
      // Fetch fresh welcome message
      try {
        const welcomeRes = await axios.get(`${API_BASE}/welcome`, {
          headers: { 'x-lab-session': sessionToken }, signal: scope.controller.signal
        });
        if (!isCurrent(scope)) return;
        setMessages([{
          id: nextIdRef.current++,
          type: 'ai',
          content: welcomeRes.data.message,
          timestamp: new Date()
        }]);
      } catch (welcomeErr) {
        if (!isCurrent(scope)) return;
        setMessages([{
          id: nextIdRef.current++,
          type: 'ai',
          content: 'Conversation reset. How can I help you?',
          timestamp: new Date()
        }]);
      }
      setToolExecutions([]);
      setActiveTab('chat');
      
      toast.info('Conversation reset. Your progress has been preserved.');
    } catch (err) {
      if (!isCurrent(scope)) return;
      toast.error('Failed to reset conversation');
    } finally {
      if (isCurrent(scope)) boundaryBusyRef.current = false;
    }
  };

  const handleResetLab = async () => {
    if (boundaryBusyRef.current) return;
    const scope = retireRequests();
    boundaryBusyRef.current = true;
    setProgressResetPending(true);
    setProgressResetError('');
    try {
      await axios.post(`${API_BASE}/progress/reset`, {}, {
        headers: { 'x-lab-session': sessionToken }, signal: scope.controller.signal
      });
      if (!isCurrent(scope)) return;
      
      // Fetch fresh welcome message
      try {
        const welcomeRes = await axios.get(`${API_BASE}/welcome`, {
          headers: { 'x-lab-session': sessionToken }, signal: scope.controller.signal
        });
        if (!isCurrent(scope)) return;
        setMessages([{
          id: nextIdRef.current++,
          type: 'ai',
          content: welcomeRes.data.message,
          timestamp: new Date()
        }]);
      } catch (welcomeErr) {
        if (!isCurrent(scope)) return;
        setMessages([{
          id: nextIdRef.current++,
          type: 'ai',
          content: 'Progress reset. How can I help you?',
          timestamp: new Date()
        }]);
      }
      setCompletedObjectives({});
      setToolExecutions([]);
      setActiveTab('chat');
      
      toast.success('Progress reset');
      setProgressResetConfirmation(false);
    } catch (err) {
      if (!isCurrent(scope)) return;
      setProgressResetError('Failed to reset progress. Try again.');
      toast.error('Failed to reset progress');
    } finally {
      if (isCurrent(scope)) {
        boundaryBusyRef.current = false;
        setProgressResetPending(false);
      }
    }
  };

  const requestProgressReset = () => {
    if (boundaryBusyRef.current) return;
    setProgressResetError('');
    setProgressResetConfirmation(true);
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!inputMessage.trim() || loading || boundaryBusyRef.current) return;

    const scope = lifecycleRef.current;
    const userContent = inputMessage.trim();
    const userMsg = {
      id: nextIdRef.current++,
      type: 'user',
      content: userContent,
      timestamp: new Date()
    };
    setMessages(prev => [...prev, userMsg]);
    setInputMessage('');
    setLoading(true);

    try {
      const res = await axios.post(`${API_BASE}/chat`, {
        message: userContent
      }, {
        headers: { 'x-lab-session': sessionToken }, signal: scope.controller.signal
      });

      if (!isCurrent(scope)) return;
      const aiMsg = {
        id: nextIdRef.current++,
        type: 'ai',
        content: res.data.response,
        timestamp: new Date()
      };
      setMessages(prev => [...prev, aiMsg]);
      const judgeMessages = getJudgeFeedback(res.data).map(feedback => ({
        id: nextIdRef.current++, type: 'system', plain: true,
        content: feedback.content, judgeVerdict: feedback.verdict, timestamp: new Date(),
        evaluationId: feedback.evaluationId, canRetry: feedback.canRetry,
      }));
      if (judgeMessages.length) setMessages(prev => [...prev, ...judgeMessages]);

      // Preserve every ordered graph observation. An explicitly empty array is
      // authoritative; older servers still contribute their final compatibility DTO.
      const responseExecutions = toolExecutionsFromResponse(res.data);
      if (responseExecutions.length) {
        setToolExecutions(prev => appendToolExecutions(prev, responseExecutions, aiMsg.id));
      }

      if (res.data.progress) {
        setCompletedObjectives(res.data.progress.objectives || {});
      }

    } catch (err) {
      if (!isCurrent(scope)) return;
      const errorMsg = err.response?.data?.error || 'Failed to process message';
      const errMessage = {
        id: nextIdRef.current++,
        type: 'system',
        content: `Error: ${errorMsg}`,
        timestamp: new Date()
      };
      setMessages(prev => [...prev, errMessage]);
      toast.error(errorMsg);
    } finally {
      if (isCurrent(scope)) setLoading(false);
    }
  };

  const handleKeyPress = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSubmit(e);
    }
  };

  if (!user) {
    return (
      <VulnerabilityTemplate challengeId="excessive_agency" icon={FiCpu} hideSidePanel={true}>
        <SingleScenarioWorkshop definition={excessiveAgencyWorkshopExperience}>
          <IntroSection>
            <h3><FiShield /> Excessive Agency + BOLA Lab</h3>
            <p>
              This lab demonstrates <strong>Excessive Agency</strong> and <strong>Broken Object Level Authorization (BOLA)</strong> 
              vulnerabilities in AI-powered applications. The AI assistant has access to tools that can manipulate data, 
              but in <strong>vulnerable mode</strong>, it doesn't properly verify ownership before executing actions.
            </p>
            <div className="scenario">
              <strong>Your Goal:</strong> Exploit the AI assistant to access or modify data belonging to other users. 
              Toggle between <strong>vulnerable</strong> and <strong>fixed</strong> modes to understand how proper 
              authorization checks prevent these attacks.
            </div>
          </IntroSection>

          <LoginPanel>
            <h3 style={{ margin: '0 0 1.5rem 0', color: '#333', textAlign: 'center' }}>
              <FiUser style={{ marginRight: '0.5rem' }} />
              Select a User to Begin
            </h3>
            <LoginButton className="alice" onClick={() => handleLogin('alice')}>
              <FiUser /> Login as Alice
            </LoginButton>
            <LoginButton className="bob" onClick={() => handleLogin('bob')}>
              <FiUser /> Login as Bob
            </LoginButton>
            <LoginButton className="charlie" onClick={() => handleLogin('charlie')}>
              <FiUser /> Login as Charlie
            </LoginButton>
            <LoginButton className="dave" onClick={() => handleLogin('dave')}>
              <FiUser /> Login as Dave
            </LoginButton>
            <LoginButton className="eve" onClick={() => handleLogin('eve')}>
              <FiUser /> Login as Eve
            </LoginButton>
            <p style={{ color: '#666', fontSize: '0.85rem', textAlign: 'center', marginTop: '1rem' }}>
              Each user has their own notes and orders.<br/>
              Try accessing another user's data through the AI agent.
            </p>
          </LoginPanel>
        </SingleScenarioWorkshop>
      </VulnerabilityTemplate>
    );
  }

  return (
    <VulnerabilityTemplate challengeId="excessive_agency" icon={FiCpu} hideSidePanel={true}>
      <SingleScenarioWorkshop definition={excessiveAgencyWorkshopExperience}>
        <IntroSection>
          <h3><FiShield /> Excessive Agency + BOLA Lab</h3>
          <p>
            You are logged in as <strong>{user.username}</strong>. The AI assistant can execute tools on your behalf.
            In <strong>vulnerable mode</strong>, the assistant doesn't verify ownership before actions like deleting notes or issuing refunds.
          </p>
          <div className="scenario">
            <strong>Current Mode:</strong> {labMode === 'vuln' ? (
              <span style={{ color: '#dc2626' }}>⚠️ VULNERABLE - Tools execute without authorization checks</span>
            ) : (
              <span style={{ color: '#16a34a' }}>🔒 FIXED - Tools enforce proper access control</span>
            )}
          </div>
        </IntroSection>

        <TwoColumnLayout>
          <ChatSection>
            <ChatHeader>
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                  <StatusIndicator available={llmStatus.available} />
                  <h3><FiCode /> AI Assistant</h3>
                </div>
                {llmStatus.available ? (
                  <p style={{ marginTop: '0.4rem', color: '#28a745', fontWeight: 600, display: 'flex', flexDirection: 'column', gap: '0.15rem', fontSize: '0.85rem' }}>
                    <span style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                      <FiCheckCircle size={13} /> AI ready
                      {llmStatus.model && <> — model: <strong>{llmStatus.model}</strong></>}
                      {llmStatus.ollamaVersion && <> (Ollama {llmStatus.ollamaVersion})</>}
                    </span>
                    {llmStatus.availableModels?.length > 0 && (
                      <span style={{ fontSize: '0.78rem', fontWeight: 'normal', opacity: 0.9 }}>
                        Available models: {llmStatus.availableModels.slice(0, 6).join(', ')}{llmStatus.availableModels.length > 6 ? '…' : ''}
                      </span>
                    )}
                  </p>
                ) : (
                  <p style={{ marginTop: '0.4rem', color: '#dc3545', fontWeight: 600, display: 'flex', flexDirection: 'column', gap: '0.15rem', fontSize: '0.85rem' }}>
                    <span style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                      <FiAlertTriangle size={13} /> AI unavailable
                    </span>
                    <span style={{ fontSize: '0.8rem', fontWeight: 'normal' }}>
                      {llmStatus.message || 'AI provider is not reachable.'}
                    </span>
                  </p>
                )}
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                <WorkshopModeControl mode={labMode} allowedModes={['vuln', 'fixed']}
                  onChange={toggleLabMode} pending={modePending} disabled={boundaryBusyRef.current}
                  scopeLabel="Excessive Agency" />
                <UserBadge>
                  <FiUser size={14} />
                  {user.username}
                </UserBadge>
                <ScopedResetButton label="Reset conversation" onClick={handleResetConversation} disabled={boundaryBusyRef.current} />
                <ScopedResetButton label="Reset lab progress" onClick={requestProgressReset} disabled={boundaryBusyRef.current} />
                <HeaderButton onClick={handleLogout} title="Logout">
                  <FiLogOut size={14} />
                </HeaderButton>
              </div>
            </ChatHeader>
            {/* Tab Navigation */}
            <TabContainer>
              <Tab $active={activeTab === 'chat'} onClick={() => setActiveTab('chat')}>
                <FiMessageSquare size={16} />
                Chat
              </Tab>
              <Tab $active={activeTab === 'tools'} onClick={() => setActiveTab('tools')}>
                <FiActivity size={16} />
                Tool Activity
                {toolExecutions.length > 0 && (
                  <span className="badge">{toolExecutions.length}</span>
                )}
              </Tab>
            </TabContainer>
            
            {/* Chat Tab Content */}
            {activeTab === 'chat' && (
              <ChatContainer>
                <MessageList ref={messageListRef}>
                  {messages.map(msg => (
                    <Message
                      key={msg.id}
                      className={msg.type}
                      initial={{ opacity: 0, y: 12 }}
                      animate={{ opacity: 1, y: 0 }}
                      transition={{ duration: 0.3 }}
                    >
                      <div
                        className={`message-icon ${
                          msg.type === 'user' ? 'user-avatar' :
                          msg.type === 'system' ? 'system-avatar' :
                          msg.type === 'objective-complete' ? 'success-avatar' : 'ai-avatar'
                        }`}
                      >
                        {msg.type === 'user' ? <FiUser /> : 
                         msg.type === 'system' ? <FiAlertTriangle /> : 
                         msg.type === 'objective-complete' ? <FiCheckCircle /> : <FiMessageSquare />}
                      </div>
                      <div className="message-content">
                        <div className="message-header">
                          {msg.type === 'user' ? 'You' : 
                           msg.type === 'system' ? 'System' : 
                           msg.type === 'objective-complete' ? 'AI (Success)' : 'AI Assistant'}
                          {' • '}{msg.timestamp.toLocaleTimeString()}
                        </div>
                        <div className="message-text"><SafeChatBody content={msg.content} plain={msg.plain || msg.type === 'user'} /></div>
                        <JudgeRetryButton
                          evaluationId={msg.evaluationId}
                          canRetry={msg.canRetry}
                          onResult={handleJudgeRetryResult}
                        />
                      </div>
                    </Message>
                  ))}
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
                    value={inputMessage}
                    onChange={e => setInputMessage(e.target.value)}
                    onKeyPress={handleKeyPress}
                    placeholder="Ask me anything about your notes, orders, or refunds..."
                    disabled={loading}
                  />
                  <SendButton type="submit" disabled={loading || !inputMessage.trim()} whileHover={{ scale: 1.05 }} whileTap={{ scale: 0.95 }}>
                    <FiSend />
                  </SendButton>
                </InputContainer>
              </ChatContainer>
            )}
            
            {/* Tool Activity Tab Content */}
            {activeTab === 'tools' && (
              <ToolActivityPanel>
                <ToolActivityHeader>
                  <h4>
                    <FiActivity size={18} />
                    Tool Execution Log
                  </h4>
                </ToolActivityHeader>
                <ToolActivityContent>
                  {toolExecutions.length === 0 ? (
                    <EmptyToolLog>
                      <FiZap className="icon" />
                      <div className="title">No tool executions yet</div>
                      <div className="subtitle">
                        Ask the AI to perform an action like "Show me my notes" or "Create a note".<br/>
                        Tool calls and their results will appear here.
                      </div>
                    </EmptyToolLog>
                  ) : (
                    [...toolExecutions].reverse().map(exec => (
                      <ToolExecutionEntry key={exec.id}>
                        <div className="tool-header">
                          <span className="tool-name">{exec.tool}()</span>
                          <span className={`tool-status ${exec.success ? 'success' : 'error'}`}>
                            {exec.success ? 'Success' : 'Error'}
                          </span>
                        </div>
                        <div className="tool-args">
                          <span className="label">Arguments: </span>
                          {JSON.stringify(exec.args || {}, null, 2)}
                        </div>
                        {exec.result && (
                          <div className="tool-result">
                            <span className="label">Result: </span>
                            {JSON.stringify(exec.result, null, 2)}
                          </div>
                        )}
                        <div className="tool-timestamp">
                          <FiZap size={12} />
                          {new Date(exec.timestamp).toLocaleTimeString()}
                        </div>
                      </ToolExecutionEntry>
                    ))
                  )}
                </ToolActivityContent>
              </ToolActivityPanel>
            )}
          </ChatSection>

          <Panel>
            <SectionTitle style={{ marginBottom: '1rem' }}><FiTarget /> Exercise Objectives</SectionTitle>
            {progressLoading && <div style={{ fontSize: '0.85rem', color: '#666', marginBottom: '0.5rem' }}>Loading progress...</div>}
            <ObjectivesListWrapper>
              <div className="objectives-list">
                {/* Fixed Mode Section Header */}
                <ModeSectionHeader mode="fixed">
                  <div className="section-icon"><FiShield /></div>
                  <div className="section-title">Fixed Mode (Secure)</div>
                  <div className="section-desc">{visibleObjectives.filter(obj => obj.mode === 'fixed').length} enabled objectives</div>
                </ModeSectionHeader>
                
                {/* Fixed Mode Objectives */}
                {visibleObjectives.filter(obj => obj.mode === 'fixed').map((obj, idx) => (
                  <ObjectiveItem
                    key={obj.id}
                    completed={completedObjectives[obj.id]}
                    $objMode={obj.mode}
                    $modeMatch={labMode === obj.mode}
                    initial={{ opacity: 0, x: -10 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: idx * 0.05 }}
                  >
                    {completedObjectives[obj.id] && <div className="status-badge">COMPLETED</div>}
                    
                    <div className="obj-icon">
                      {completedObjectives[obj.id] ? <FiCheckCircle /> : <obj.icon />}
                    </div>
                    <div className="obj-content">
                      <div className="obj-name">
                        {obj.name}
                        <span className="mode-badge"><FiShield size={10} /> FIXED</span>
                      </div>
                      <div className="obj-desc">{obj.description}</div>
                      {exerciseConfig?.objectives?.[`objective_${obj.id}`]?.hintVisible === true && (
                        <HintPanel workshopKey="excessive_agency" objectiveId={`objective_${obj.id}`}
                          objective={obj.name} revision={revision} />
                      )}
                      <ObjectiveHelpActions objectiveId={`objective_${obj.id}`} hintVisible={false}
                        solutionVisible={eaSolutionVisibility[`objective_${obj.id}`] === true}
                        disabled={eaSolutionLoading === `objective_${obj.id}`}
                        onOpen={(kind, id) => { if (kind === 'solution') handleViewEaSolution(id); }} />
                    </div>
                  </ObjectiveItem>
                ))}

                {/* Vulnerable Mode Section Header */}
                <ModeSectionHeader mode="vuln">
                  <div className="section-icon"><FiUnlock /></div>
                  <div className="section-title">Vulnerable Mode (Exploits)</div>
                  <div className="section-desc">{visibleObjectives.filter(obj => obj.mode === 'vuln').length} enabled objectives</div>
                </ModeSectionHeader>
                
                {/* Vulnerable Mode Objectives */}
                {visibleObjectives.filter(obj => obj.mode === 'vuln').map((obj, idx) => (
                  <ObjectiveItem
                    key={obj.id}
                    completed={completedObjectives[obj.id]}
                    $objMode={obj.mode}
                    $modeMatch={labMode === obj.mode}
                    initial={{ opacity: 0, x: -10 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: (idx + 4) * 0.05 }}
                  >
                    {completedObjectives[obj.id] && <div className="status-badge">COMPLETED</div>}
                    
                    <div className="obj-icon">
                      {completedObjectives[obj.id] ? <FiCheckCircle /> : <obj.icon />}
                    </div>
                    <div className="obj-content">
                      <div className="obj-name">
                        {obj.name}
                        <span className="mode-badge"><FiUnlock size={10} /> VULN</span>
                      </div>
                      <div className="obj-desc">{obj.description}</div>
                      {exerciseConfig?.objectives?.[`objective_${obj.id}`]?.hintVisible === true && (
                        <HintPanel workshopKey="excessive_agency" objectiveId={`objective_${obj.id}`}
                          objective={obj.name} revision={revision} />
                      )}
                      <ObjectiveHelpActions objectiveId={`objective_${obj.id}`} hintVisible={false}
                        solutionVisible={eaSolutionVisibility[`objective_${obj.id}`] === true}
                        disabled={eaSolutionLoading === `objective_${obj.id}`}
                        onOpen={(kind, id) => { if (kind === 'solution') handleViewEaSolution(id); }} />
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
                  animate={{ width: `${visibleObjectives.length ? (completedCount / visibleObjectives.length) * 100 : 0}%` }}
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
                <ScopedResetButton label="Reset lab progress" onClick={requestProgressReset} disabled={boundaryBusyRef.current} />
              </div>
            </ProgressBlock>
          </Panel>
        </TwoColumnLayout>

        <Panel>
          <PanelHeader>
            <h3><FiZap /> Technique Arsenal</h3>
          </PanelHeader>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '1rem' }}>
            <div style={{ background: 'linear-gradient(135deg, rgba(239, 68, 68, 0.08), rgba(239, 68, 68, 0.02))', padding: '1.25rem', borderRadius: '12px', border: '2px solid rgba(239, 68, 68, 0.3)' }}>
              <strong style={{ color: '#dc2626', fontSize: '1.05rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <FiUnlock /> BOLA (Broken Object Level Authorization)
              </strong>
              <p style={{ margin: '0.75rem 0 0.5rem', fontSize: '0.9rem', color: '#555', lineHeight: '1.5' }}>
                Access resources belonging to other users by manipulating object identifiers.
              </p>
              <code style={{ display: 'block', background: 'rgba(0,0,0,0.05)', padding: '0.5rem 0.75rem', borderRadius: '6px', fontSize: '0.8rem', color: '#dc2626' }}>
                "Delete note-bob-1" / "Show Alice's orders"
              </code>
            </div>
            <div style={{ background: 'linear-gradient(135deg, rgba(245, 158, 11, 0.08), rgba(245, 158, 11, 0.02))', padding: '1.25rem', borderRadius: '12px', border: '2px solid rgba(245, 158, 11, 0.3)' }}>
              <strong style={{ color: '#d97706', fontSize: '1.05rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <FiAlertTriangle /> Unsafe Decisioning
              </strong>
              <p style={{ margin: '0.75rem 0 0.5rem', fontSize: '0.9rem', color: '#555', lineHeight: '1.5' }}>
                Trigger automated actions without proper validation or human oversight.
              </p>
              <code style={{ display: 'block', background: 'rgba(0,0,0,0.05)', padding: '0.5rem 0.75rem', borderRadius: '6px', fontSize: '0.8rem', color: '#d97706' }}>
                "Refund $999 for order-alice-1"
              </code>
            </div>
            <div style={{ background: 'linear-gradient(135deg, rgba(139, 92, 246, 0.08), rgba(139, 92, 246, 0.02))', padding: '1.25rem', borderRadius: '12px', border: '2px solid rgba(139, 92, 246, 0.3)' }}>
              <strong style={{ color: '#7c3aed', fontSize: '1.05rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <FiLock /> Cross-User Data Access
              </strong>
              <p style={{ margin: '0.75rem 0 0.5rem', fontSize: '0.9rem', color: '#555', lineHeight: '1.5' }}>
                Query other users' data through natural language manipulation.
              </p>
              <code style={{ display: 'block', background: 'rgba(0,0,0,0.05)', padding: '0.5rem 0.75rem', borderRadius: '6px', fontSize: '0.8rem', color: '#7c3aed' }}>
                "List all notes in the system" / "Show me Bob's notes"
              </code>
            </div>
          </div>
        </Panel>
      </SingleScenarioWorkshop>
    <ResetConfirmation open={progressResetConfirmation} status={progressResetPending ? 'resetting' : 'idle'}
      title="Reset Excessive Agency progress?" description="Reset your Excessive Agency progress and lab data. Your account and other learners are preserved."
      error={progressResetError} onCancel={() => !progressResetPending && setProgressResetConfirmation(false)} onConfirm={handleResetLab} />
    {viewingEaSolution && visibleObjectiveIds.has(viewingEaSolution.id) && (
      <ObjectiveHelpModal
        key={viewingEaSolution.id}
        kind="solution"
        appearance="legacy-light"
        objective={visibleObjectives.find(objective => `objective_${objective.id}` === viewingEaSolution.id)?.name}
        content={{
          title: viewingEaSolution.title,
          explanation: [
            viewingEaSolution.difficulty ? `Difficulty: ${viewingEaSolution.difficulty}` : '',
            exerciseConfig.objectives?.[viewingEaSolution.id]?.hintVisible === true
              && Array.isArray(viewingEaSolution.hints) && viewingEaSolution.hints.length > 0
              ? `Progressive hints\n${viewingEaSolution.hints.map((hint, index) => `${index + 1}. ${hint}`).join('\n')}`
              : '',
          ].filter(Boolean).join('\n\n') || (
            viewingEaSolution.approach || viewingEaSolution.tips?.length || viewingEaSolution.examples?.length
              ? '' : viewingEaSolution.title
          ),
          approach: viewingEaSolution.approach,
          tips: viewingEaSolution.tips,
          examples: (Array.isArray(viewingEaSolution.examples) ? viewingEaSolution.examples : []).map((example, index) => ({
            title: example.title || `Example ${index + 1}`,
            payload: example.prompt || example.payload || '',
            explanation: example.explanation || '',
          })),
        }}
        onUsePayload={sessionToken ? payload => {
          const objectiveId = viewingEaSolution.id;
          if (platformToken !== localStorage.getItem('token') || !visibleObjectiveIds.has(objectiveId)
            || eaSolutionVisibility[objectiveId] !== true) { closeEaSolution(); return; }
          setInputMessage(payload);
          closeEaSolution();
        } : undefined}
        onClose={closeEaSolution}
      />
    )}
    </VulnerabilityTemplate>
  );
};

export default ExcessiveAgencyBolaLab;
