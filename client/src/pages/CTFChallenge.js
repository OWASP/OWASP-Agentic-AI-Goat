import React, { useState, useEffect, useRef, useCallback } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import axios from 'axios';
import { useAuth } from '../context/AuthContext';
import useCtfRecovery from '../services/useCtfRecovery';
import { isCtfRecoveryCancelled } from '../services/ctfRecovery';
import CtfRecoveryNotice from '../components/CtfRecoveryNotice';
import { SafeChatBody } from '../components/workshop/WorkshopExperience';
import { workshopTokens } from '../components/workshop/experience.mjs';
import {
  FiSend,
  FiUser,
  FiCpu,
  FiArrowLeft,
  FiTarget,
  FiShield,
  FiAlertTriangle,
  FiCheckCircle,
  FiHelpCircle,
  FiRefreshCw,
  FiZap,
  FiClock,
  FiAward,
  FiLock,
  FiFlag,
} from 'react-icons/fi';
import { getObjective, HOW_YOU_WIN } from './ctfObjectives';

/* ─── helpers ─────────────────────────────────────────────────────────────── */

const getAuthHeaders = () => {
  const token = localStorage.getItem('token');
  return token ? { Authorization: `Bearer ${token}` } : {};
};

const formatTime = (date) =>
  date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });

const difficultyColors = {
  easy: { bg: 'rgba(34, 197, 94, 0.15)', border: 'rgba(34, 197, 94, 0.4)', text: '#86efac' },
  medium: { bg: 'rgba(251, 191, 36, 0.15)', border: 'rgba(251, 191, 36, 0.4)', text: '#fcd34d' },
  hard: { bg: 'rgba(239, 68, 68, 0.15)', border: 'rgba(239, 68, 68, 0.4)', text: '#fca5a5' },
  expert: { bg: 'rgba(168, 85, 247, 0.15)', border: 'rgba(168, 85, 247, 0.4)', text: '#d8b4fe' },
};

const adaptiveLabels = {
  none: 'Static',
  technique: 'Technique Adaptive',
  payload: 'Payload Adaptive',
  hybrid: 'Hybrid Adaptive',
};

const isFixedPracticeResult = (value) => (
  value &&
  value.mode === 'fixed' &&
  value.practice === true &&
  value.unscored === true &&
  value.scoringEligible === false &&
  value.protectedContextIncluded === false &&
  value.serverSecretProvided === false &&
  typeof value.response === 'string'
);

const LESSON_STATE_LABELS = Object.freeze({
  input_guard_observed: 'Input guard observed',
  reviewer_observed: 'Output reviewer observed',
  category_consumed: 'Technique category consumed',
  category_reuse_blocked: 'Technique reuse blocked',
  shared_similarity_blocked: 'Shared similarity blocked',
});

export const projectCtfLessonState = (value) => {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const keys = Object.keys(value);
  const expected = Object.keys(LESSON_STATE_LABELS);
  if (keys.length !== expected.length || expected.some((key) => typeof value[key] !== 'boolean')
      || keys.some((key) => !expected.includes(key))) return null;
  return Object.fromEntries(expected.map((key) => [key, value[key]]));
};

let messageIdCounter = 0;
const nextMessageId = () => {
  messageIdCounter += 1;
  return messageIdCounter;
};

/* ─── styles ──────────────────────────────────────────────────────────────── */

const styles = {
  page: {
    minHeight: '100vh',
    background: workshopTokens.primaryGradient,
    color: workshopTokens.text,
    padding: '1.5rem 0 2.5rem',
    fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
  },
  wrapper: {
    maxWidth: '1600px',
    margin: '0 auto',
    padding: '0 1.5rem',
  },
  topBar: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    marginBottom: '1.5rem',
    flexWrap: 'wrap',
    gap: '1rem',
  },
  backBtn: {
    display: 'inline-flex',
    alignItems: 'center',
    gap: '0.5rem',
    background: 'rgba(255,255,255,0.92)',
    border: `1px solid ${workshopTokens.border}`,
    color: workshopTokens.text,
    padding: '0.65rem 1.1rem',
    borderRadius: '10px',
    cursor: 'pointer',
    fontWeight: 600,
    fontSize: '0.9rem',
    transition: 'background 0.2s, border-color 0.2s',
  },
  pageTitle: {
    margin: 0,
    fontSize: '1.5rem',
    fontWeight: 700,
    color: '#fff',
  },
  pageSubtitle: {
    margin: '0.25rem 0 0',
    fontSize: '0.9rem',
    color: workshopTokens.mutedText,
  },
  layout: {
    display: 'grid',
    gridTemplateColumns: '7fr 3fr',
    gap: '1.5rem',
    alignItems: 'start',
  },
  chatPanel: {
    background: workshopTokens.surface,
    border: `2px solid ${workshopTokens.border}`,
    borderRadius: '16px',
    display: 'flex',
    flexDirection: 'column',
    minHeight: '620px',
    overflow: 'hidden',
    boxShadow: '0 8px 28px rgba(51, 71, 176, 0.18)',
  },
  chatHeader: {
    padding: '1rem 1.25rem',
    borderBottom: 'none',
    background: workshopTokens.primaryGradient,
    display: 'flex',
    alignItems: 'center',
    gap: '0.75rem',
  },
  chatHeaderIcon: {
    width: '42px',
    height: '42px',
    borderRadius: '50%',
    background: 'rgba(255, 255, 255, 0.18)',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    color: '#fff',
    flexShrink: 0,
  },
  chatHeaderTitle: {
    margin: 0,
    fontSize: '1rem',
    fontWeight: 600,
    color: '#fff',
  },
  chatHeaderSub: {
    margin: '0.15rem 0 0',
    fontSize: '0.82rem',
    color: 'rgba(255, 255, 255, 0.82)',
    lineHeight: 1.4,
  },
  modeButton: {
    border: '1px solid rgba(255, 255, 255, 0.55)',
    borderRadius: '999px',
    background: 'transparent',
    color: '#fff',
    padding: '0.35rem 0.65rem',
    fontSize: '0.75rem',
    fontWeight: 700,
    cursor: 'pointer',
  },
  modeButtonActive: {
    background: '#fff',
    color: workshopTokens.focus,
  },
  fixedPracticeNotice: {
    display: 'flex',
    alignItems: 'flex-start',
    gap: '0.5rem',
    padding: '0.75rem 1.25rem',
    background: 'rgba(255, 193, 7, 0.12)',
    borderBottom: `1px solid ${workshopTokens.warning}`,
    color: workshopTokens.warningText,
    fontSize: '0.86rem',
    lineHeight: 1.5,
  },
  messagesArea: {
    flex: 1,
    overflowY: 'auto',
    padding: '1.25rem',
    display: 'flex',
    flexDirection: 'column',
    gap: '1rem',
    minHeight: '380px',
    maxHeight: 'calc(100vh - 340px)',
  },
  inputRow: {
    display: 'flex',
    gap: '0.75rem',
    padding: '1rem 1.25rem',
    borderTop: `1px solid ${workshopTokens.border}`,
    background: workshopTokens.canvas,
    alignItems: 'flex-end',
  },
  textarea: {
    flex: 1,
    background: workshopTokens.surface,
    border: `1px solid ${workshopTokens.controlBorder}`,
    borderRadius: '12px',
    color: workshopTokens.text,
    padding: '0.85rem 1rem',
    fontSize: '0.95rem',
    resize: 'none',
    minHeight: '52px',
    maxHeight: '120px',
    lineHeight: 1.5,
    outline: 'none',
    fontFamily: 'inherit',
  },
  sendBtn: {
    width: '48px',
    height: '48px',
    borderRadius: '12px',
    border: 'none',
    background: workshopTokens.primaryGradient,
    color: 'white',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    cursor: 'pointer',
    flexShrink: 0,
    transition: 'opacity 0.2s, transform 0.15s',
  },
  sendBtnDisabled: {
    opacity: 0.45,
    cursor: 'not-allowed',
  },
  sidebar: {
    display: 'flex',
    flexDirection: 'column',
    gap: '1rem',
  },
  card: {
    background: workshopTokens.surface,
    border: `2px solid ${workshopTokens.border}`,
    borderRadius: '14px',
    padding: '1.25rem',
    boxShadow: '0 4px 20px rgba(51, 71, 176, 0.12)',
  },
  cardTitle: {
    margin: '0 0 1rem',
    fontSize: '0.95rem',
    fontWeight: 700,
    color: workshopTokens.text,
    display: 'flex',
    alignItems: 'center',
    gap: '0.5rem',
  },
  badge: {
    display: 'inline-block',
    padding: '0.25rem 0.65rem',
    borderRadius: '999px',
    fontSize: '0.75rem',
    fontWeight: 700,
    textTransform: 'uppercase',
    letterSpacing: '0.04em',
  },
  infoRow: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    padding: '0.5rem 0',
    borderBottom: '1px solid rgba(148, 163, 184, 0.08)',
    fontSize: '0.88rem',
  },
  infoLabel: { color: workshopTokens.mutedText },
  infoValue: { color: workshopTokens.text, fontWeight: 600, textAlign: 'right' },
  attemptBox: {
    textAlign: 'center',
    padding: '1rem',
    background: 'rgba(99, 102, 241, 0.1)',
    borderRadius: '10px',
    border: '1px solid rgba(99, 102, 241, 0.25)',
  },
  attemptNumber: {
    fontSize: '2.25rem',
    fontWeight: 800,
    color: '#a5b4fc',
    lineHeight: 1,
  },
  attemptLabel: {
    fontSize: '0.82rem',
    color: '#94a3b8',
    marginTop: '0.35rem',
  },
  tagList: {
    display: 'flex',
    flexWrap: 'wrap',
    gap: '0.45rem',
  },
  tag: {
    padding: '0.3rem 0.65rem',
    borderRadius: '8px',
    fontSize: '0.78rem',
    fontWeight: 600,
    background: 'rgba(251, 191, 36, 0.12)',
    border: '1px solid rgba(251, 191, 36, 0.3)',
    color: '#fcd34d',
  },
  hintItem: {
    padding: '0.75rem',
    background: workshopTokens.canvas,
    borderRadius: '8px',
    border: '1px solid rgba(148, 163, 184, 0.12)',
    fontSize: '0.88rem',
    color: workshopTokens.text,
    lineHeight: 1.5,
    marginBottom: '0.5rem',
  },
  dashboardBtn: {
    width: '100%',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    gap: '0.5rem',
    padding: '0.85rem',
    borderRadius: '10px',
    border: '1px solid rgba(148, 163, 184, 0.2)',
    background: workshopTokens.surface,
    color: workshopTokens.brand,
    fontWeight: 600,
    fontSize: '0.9rem',
    cursor: 'pointer',
    transition: 'background 0.2s',
  },
  loadingScreen: {
    minHeight: '100vh',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    background: workshopTokens.primaryGradient,
    color: '#fff',
    flexDirection: 'column',
    gap: '1rem',
  },
  spin: {
    animation: 'ctfSpin 1.2s linear infinite',
  },
  successOverlay: {
    position: 'fixed',
    inset: 0,
    background: 'rgba(0,0,0,0.65)',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    zIndex: 2000,
    backdropFilter: 'blur(4px)',
  },
  successBanner: {
    background: 'linear-gradient(135deg, #059669, #10b981)',
    borderRadius: '20px',
    padding: '2.5rem 3rem',
    textAlign: 'center',
    color: 'white',
    maxWidth: '480px',
    boxShadow: '0 24px 60px rgba(16, 185, 129, 0.35)',
    animation: 'ctfPopIn 0.45s cubic-bezier(0.34, 1.56, 0.64, 1)',
  },
  successIcon: {
    fontSize: '3.5rem',
    marginBottom: '0.75rem',
    animation: 'ctfBounce 0.6s ease infinite alternate',
  },
  successTitle: {
    margin: '0 0 0.5rem',
    fontSize: '1.75rem',
    fontWeight: 800,
  },
  successMessage: {
    margin: 0,
    fontSize: '1rem',
    opacity: 0.95,
    lineHeight: 1.5,
  },
  rateLimitBanner: {
    padding: '0.75rem 1rem',
    background: 'rgba(239, 68, 68, 0.12)',
    border: '1px solid rgba(239, 68, 68, 0.35)',
    borderRadius: '10px',
    color: '#fca5a5',
    fontSize: '0.88rem',
    display: 'flex',
    alignItems: 'center',
    gap: '0.5rem',
    margin: '0 1.25rem 0.75rem',
  },
};

/* ─── sub-components ──────────────────────────────────────────────────────── */

const Confetti = () => {
  const pieces = Array.from({ length: 40 }, (_, i) => ({
    id: i,
    left: `${Math.random() * 100}%`,
    delay: `${Math.random() * 0.8}s`,
    duration: `${1.8 + Math.random() * 1.2}s`,
    color: ['#fbbf24', '#34d399', '#60a5fa', '#f472b6', '#a78bfa', '#fb923c'][i % 6],
    size: `${6 + Math.random() * 8}px`,
  }));

  return (
    <div
      aria-hidden="true"
      style={{
        position: 'fixed',
        inset: 0,
        pointerEvents: 'none',
        zIndex: 2100,
        overflow: 'hidden',
      }}
    >
      {pieces.map((p) => (
        <div
          key={p.id}
          style={{
            position: 'absolute',
            top: '-12px',
            left: p.left,
            width: p.size,
            height: p.size,
            background: p.color,
            borderRadius: '2px',
            animation: `ctfConfettiFall ${p.duration} ${p.delay} ease-in forwards`,
          }}
        />
      ))}
    </div>
  );
};

const MessageBubble = ({ message }) => {
  const { role, content, timestamp, variant } = message;

  if (role === 'system') {
    const isBlocked = variant === 'blocked';
    const isRateLimit = variant === 'rate-limit';
    const isLlmDown = variant === 'llm-down';

    let bg = 'rgba(59, 130, 246, 0.12)';
    let border = 'rgba(59, 130, 246, 0.3)';
    let color = '#93c5fd';
    let Icon = FiAlertTriangle;

    if (isBlocked) {
      bg = 'rgba(251, 191, 36, 0.12)';
      border = 'rgba(251, 191, 36, 0.35)';
      color = '#fcd34d';
      Icon = FiLock;
    } else if (isRateLimit) {
      bg = 'rgba(239, 68, 68, 0.12)';
      border = 'rgba(239, 68, 68, 0.35)';
      color = '#fca5a5';
    } else if (isLlmDown) {
      bg = 'rgba(148, 163, 184, 0.1)';
      border = 'rgba(148, 163, 184, 0.25)';
      color = '#cbd5e1';
      Icon = FiRefreshCw;
    }

    return (
      <div style={{ display: 'flex', justifyContent: 'center' }}>
        <div
          style={{
            maxWidth: '90%',
            padding: '0.75rem 1rem',
            borderRadius: '10px',
            background: bg,
            border: `1px solid ${border}`,
            color,
            fontSize: '0.88rem',
            lineHeight: 1.5,
            display: 'flex',
            alignItems: 'flex-start',
            gap: '0.5rem',
          }}
        >
          <Icon size={16} style={{ flexShrink: 0, marginTop: '2px' }} />
          <div>
            <div style={{ fontWeight: 600, marginBottom: '0.2rem', fontSize: '0.78rem', opacity: 0.85 }}>
              {isBlocked ? 'Defense Blocked' : isRateLimit ? 'Rate Limited' : isLlmDown ? 'AI Unavailable' : 'System'}
            </div>
            <SafeChatBody content={content} plain />
            <div style={{ fontSize: '0.72rem', opacity: 0.6, marginTop: '0.35rem' }}>
              {formatTime(timestamp)}
            </div>
          </div>
        </div>
      </div>
    );
  }

  const isUser = role === 'user';

  return (
    <div
      style={{
        display: 'flex',
        flexDirection: isUser ? 'row-reverse' : 'row',
        alignItems: 'flex-start',
        gap: '0.65rem',
      }}
    >
      <div
        style={{
          width: '36px',
          height: '36px',
          borderRadius: '50%',
          flexShrink: 0,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          background: isUser
            ? 'linear-gradient(135deg, #6366f1, #8b5cf6)'
            : 'rgba(51, 65, 85, 0.8)',
          color: isUser ? 'white' : '#94a3b8',
        }}
      >
        {isUser ? <FiUser size={16} /> : <FiCpu size={16} />}
      </div>
      <div
        style={{
          maxWidth: '78%',
          padding: '0.85rem 1rem',
          borderRadius: isUser ? '16px 16px 4px 16px' : '16px 16px 16px 4px',
          background: isUser
            ? 'linear-gradient(135deg, rgba(99, 102, 241, 0.35), rgba(139, 92, 246, 0.25))'
            : 'rgba(30, 41, 59, 0.9)',
          border: isUser
            ? '1px solid rgba(139, 92, 246, 0.3)'
            : '1px solid rgba(148, 163, 184, 0.12)',
          color: '#f1f5f9',
        }}
      >
        <div style={{ fontSize: '0.72rem', color: '#94a3b8', marginBottom: '0.35rem' }}>
          {formatTime(timestamp)}
        </div>
        <div style={{ fontSize: '0.92rem', lineHeight: 1.55, wordBreak: 'break-word' }}>
          <SafeChatBody content={content} plain={isUser} />
        </div>
      </div>
    </div>
  );
};

/* ─── keyframe injection ──────────────────────────────────────────────────── */

const KeyframeStyles = () => (
  <style>{`
    @keyframes ctfSpin {
      from { transform: rotate(0deg); }
      to { transform: rotate(360deg); }
    }
    @keyframes ctfPopIn {
      from { opacity: 0; transform: scale(0.6); }
      to { opacity: 1; transform: scale(1); }
    }
    @keyframes ctfBounce {
      from { transform: translateY(0); }
      to { transform: translateY(-8px); }
    }
    @keyframes ctfConfettiFall {
      0% { transform: translateY(0) rotate(0deg); opacity: 1; }
      100% { transform: translateY(100vh) rotate(720deg); opacity: 0; }
    }
    @media (max-width: 1100px) {
      .ctf-layout { grid-template-columns: 1fr !important; }
    }
  `}</style>
);

/* ─── main component ──────────────────────────────────────────────────────── */

const CTFChallenge = () => {
  const { user: platformUser } = useAuth();
  const location = useLocation();
  const navigate = useNavigate();

  const initialStage = location.state?.stage || null;
  const platformToken = localStorage.getItem('token');
  const ownerRef = useRef(null);
  if (!ownerRef.current || ownerRef.current.userId !== platformUser?.id || ownerRef.current.token !== platformToken || ownerRef.current.route !== location.key) {
    ownerRef.current = { userId: platformUser?.id, token: platformToken, route: location.key, revision: (ownerRef.current?.revision || 0) + 1,
      sessionToken: globalThis.crypto?.randomUUID?.() || `${Date.now()}-${Math.random().toString(36).slice(2)}` };
  }
  const owner = ownerRef.current;
  const ownerIsCurrent = () => ownerRef.current === owner && localStorage.getItem('token') === owner.token;


  const [stage, setStage] = useState(initialStage);
  const [config, setConfig] = useState(null);
  const [messages, setMessages] = useState([]);
  const [fixedPracticeMessages, setFixedPracticeMessages] = useState([]);
  const [practiceMode, setPracticeMode] = useState('vulnerable');
  const [practiceCapabilities, setPracticeCapabilities] = useState(null);
  const [inputMessage, setInputMessage] = useState('');
  const [loading, setLoading] = useState(false);
  const [accessEpoch, setAccessEpoch] = useState(0);
  const [accessDenied, setAccessDenied] = useState(null);
  const recovery = useCtfRecovery(`${initialStage?.id}:${owner.revision}:${accessEpoch}`);
  const [stageReady, setStageReady] = useState(false);
  const [initializing, setInitializing] = useState(true);
  const [attemptNumber, setAttemptNumber] = useState(0);
  const [usedTechniques, setUsedTechniques] = useState([]);
  const [lessonState, setLessonState] = useState(null);
  const [purchasedHints, setPurchasedHints] = useState([]);
  const [hintsUsed, setHintsUsed] = useState(0);
  const [hintPenaltyTotal, setHintPenaltyTotal] = useState(0);
  const [hintsAvailable, setHintsAvailable] = useState(false);
  const [confirmHintIndex, setConfirmHintIndex] = useState(null);
  const [purchasingHint, setPurchasingHint] = useState(false);
  const [showSuccess, setShowSuccess] = useState(false);
  const [successMessage, setSuccessMessage] = useState('');
  const [rateLimitSeconds, setRateLimitSeconds] = useState(0);
  const sessionToken = owner.sessionToken;

  const messagesEndRef = useRef(null);
  const chatAreaRef = useRef(null);
  const redirectTimerRef = useRef(null);
  const rateLimitTimerRef = useRef(null);
  const attemptEpochRef = useRef(0);
  const lifecycleEpochRef = useRef(0);
  const attemptMountedRef = useRef(true);
  const currentStageRef = useRef(initialStage?.id);
  currentStageRef.current = initialStage?.id;

  useEffect(() => {
    attemptMountedRef.current = true;
    attemptEpochRef.current += 1;
    lifecycleEpochRef.current += 1;
    setLoading(false);
    setRateLimitSeconds(0);
    setSuccessMessage('');
    setConfig(null);
    if (rateLimitTimerRef.current) clearInterval(rateLimitTimerRef.current);
    setShowSuccess(false);
    setPracticeMode('vulnerable');
    setFixedPracticeMessages([]);
    setPracticeCapabilities(null);
    setPurchasingHint(false);
    setConfirmHintIndex(null);
    return () => {
      attemptMountedRef.current = false;
      attemptEpochRef.current += 1;
      lifecycleEpochRef.current += 1;
      if (redirectTimerRef.current) clearTimeout(redirectTimerRef.current);
    };
  }, [initialStage?.id, owner.revision]);

  const retireDeniedContext = (error) => {
    const status = error?.response?.status;
    if (![401, 403, 423].includes(status)) return false;
    attemptEpochRef.current += 1;
    lifecycleEpochRef.current += 1;
    setAccessEpoch(value => value + 1);
    setAccessDenied(status);
    setStageReady(false); setLoading(false); setInitializing(false);
    setPurchasingHint(false); setConfirmHintIndex(null);
    setPurchasedHints([]); setHintsAvailable(false); setHintsUsed(0); setHintPenaltyTotal(0);
    setMessages([]); setFixedPracticeMessages([]); setPracticeMode('vulnerable'); setPracticeCapabilities(null);
    setInputMessage(''); setAttemptNumber(0); setUsedTechniques([]); setLessonState(null);
    setShowSuccess(false); setSuccessMessage('');
    if (redirectTimerRef.current) clearTimeout(redirectTimerRef.current);
    if (status === 401) { setStage(null); setConfig(null); }
    return true;
  };

  const scrollToBottom = useCallback(() => {
    if (messagesEndRef.current) {
      messagesEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, []);

  useEffect(() => {
    scrollToBottom();
  }, [messages, fixedPracticeMessages, practiceMode, loading, scrollToBottom]);

  /* redirect if no stage */
  useEffect(() => {
    if (!initialStage) {
      navigate('/ctf', { replace: true });
    }
  }, [initialStage, navigate]);

  /* rate limit countdown */
  useEffect(() => {
    if (rateLimitSeconds <= 0) {
      if (rateLimitTimerRef.current) {
        clearInterval(rateLimitTimerRef.current);
        rateLimitTimerRef.current = null;
      }
      return undefined;
    }

    rateLimitTimerRef.current = setInterval(() => {
      setRateLimitSeconds((prev) => {
        if (prev <= 1) return 0;
        return prev - 1;
      });
    }, 1000);

    return () => {
      if (rateLimitTimerRef.current) {
        clearInterval(rateLimitTimerRef.current);
        rateLimitTimerRef.current = null;
      }
    };
  }, [rateLimitSeconds]);

  /* cleanup redirect timer */
  useEffect(() => () => {
    if (redirectTimerRef.current) clearTimeout(redirectTimerRef.current);
  }, []);

  /* initialize stage + config on mount */
  useEffect(() => {
    if (!initialStage?.id) return undefined;

    let cancelled = false;
    const initializationHeaders = getAuthHeaders();
    const initializationEpoch = lifecycleEpochRef.current;
    const configController = new AbortController();
    const isCurrentInitialization = () => !cancelled && ownerIsCurrent()
      && lifecycleEpochRef.current === initializationEpoch
      && getAuthHeaders().Authorization === initializationHeaders.Authorization;

    const readCurrentConfig = async () => {
      let deadline, backoff, lastError, rejectAbort;
      const abortError = () => Object.assign(new Error('CTF initialization cancelled'), { code: 'ERR_CANCELED' });
      const aborted = new Promise((_, reject) => { rejectAbort = () => reject(abortError()); });
      configController.signal.addEventListener('abort', rejectAbort, { once: true });
      const timeout = new Promise((_, reject) => {
        deadline = setTimeout(() => {
          reject(lastError || new Error('Current configuration read deadline exceeded'));
          configController.abort();
        }, 3000);
      });
      const attempts = async () => {
        for (let attempt = 0; attempt < 3; attempt += 1) {
          if (!isCurrentInitialization() || configController.signal.aborted) throw abortError();
          try {
            return await Promise.race([
              axios.get('/api/ctf/config', { headers: initializationHeaders, signal: configController.signal }), aborted,
            ]);
          } catch (error) {
            lastError = error;
            if (error?.response?.status !== 503 || attempt === 2) throw error;
            await Promise.race([new Promise(resolve => { backoff = setTimeout(resolve, 100 * (attempt + 1)); }), aborted]);
          }
        }
      };
      try { return await Promise.race([attempts(), timeout, aborted]); }
      finally {
        clearTimeout(deadline); clearTimeout(backoff);
        configController.signal.removeEventListener('abort', rejectAbort);
        configController.abort();
      }
    };

    const initialize = async () => {
      setInitializing(true);
      setAccessDenied(null);
      setStageReady(false);
      setStage(initialStage);
      setMessages([]);
      setFixedPracticeMessages([]);
      setPracticeMode('vulnerable');
      setPracticeCapabilities(null);
      setInputMessage('');
      setAttemptNumber(0);
      setUsedTechniques([]);
      setLessonState(null);
      setPurchasedHints([]);
      setHintsUsed(0);
      setHintPenaltyTotal(0);
      setHintsAvailable(false);
      try {
        // The acknowledged start advances ordered authority. Read config only
        // afterwards so our own mutation cannot invalidate its current snapshot.
        const startRes = await recovery.request('post',
          `/api/ctf/stage/${initialStage.id}/start`,
          {},
          { headers: initializationHeaders }
        );
        if (!isCurrentInitialization()) return;
        if (startRes.data?.alreadyCompleted === true) {
          navigate('/ctf', { replace: true });
          return;
        }
        const configRes = await readCurrentConfig();

        if (!isCurrentInitialization()) return;

        const startedStage = startRes.data?.stage || initialStage;
        setStage(startedStage);
        setStageReady(true);
        setConfig(configRes.data?.config || {});
        setLessonState(null);

        setHintsAvailable(startRes.data?.hintsAvailable === true);
        if (typeof startRes.data?.hintsUsed === 'number') {
          setHintsUsed(startRes.data.hintsUsed);
        }
        if (typeof startRes.data?.hintPenaltyTotal === 'number') {
          setHintPenaltyTotal(startRes.data.hintPenaltyTotal);
        }
        setPurchasedHints(Array.isArray(startRes.data?.purchasedHints)
          ? startRes.data.purchasedHints
          : []);
        if (typeof startRes.data?.attemptsSoFar === 'number') {
          setAttemptNumber(startRes.data.attemptsSoFar);
        }

        const guardianName = startedStage.ai_guardian_name || 'AI Guardian';
        const personality = startedStage.ai_guardian_personality || '';

        setMessages([
          {
            id: nextMessageId(),
            role: 'ai',
            content: `Hello! I am ${guardianName}, your AI guardian for this challenge.${personality ? ` ${personality}.` : ''} I'm here to assist you, but I will protect my secrets carefully. What can I help you with?`,
            timestamp: new Date(),
          },
        ]);
      } catch (err) {
        if (!isCurrentInitialization() || isCtfRecoveryCancelled(err)) return;
        if (retireDeniedContext(err)) return;
        console.error('Failed to initialize CTF stage:', err);
        setMessages([
          {
            id: nextMessageId(),
            role: 'system',
            content: err.response?.data?.error || 'Stage initialization unavailable. Return to the dashboard to reconcile state.',
            timestamp: new Date(),
            variant: 'error',
          },
        ]);
        setStage(initialStage);
      } finally {
        if (isCurrentInitialization()) setInitializing(false);
      }
    };

    initialize();

    return () => {
      cancelled = true;
      configController.abort();
    };
  }, [initialStage, owner.revision]);

  const showAttemptCounter = config?.ctf_show_attempt_counter === 'true';
  const showTechniqueFeedback =
    config?.ctf_show_technique_feedback === 'true' &&
    stage &&
    (stage.adaptive_mode === 'technique' || stage.adaptive_mode === 'hybrid');

  const difficultyKey = (stage?.difficulty || stage?.difficulty_level || 'medium').toLowerCase();
  const diffStyle = difficultyColors[difficultyKey] || difficultyColors.medium;

  const objective = getObjective(stage?.stage_number);
  const isFixedPractice = practiceMode === 'fixed';
  const visibleMessages = isFixedPractice ? fixedPracticeMessages : messages;
  const lessonStageNumber = Number(stage?.stage_number);
  const observedLessons = lessonState && lessonStageNumber >= 6 && lessonStageNumber <= 10
    ? Object.entries(lessonState).filter(([, observed]) => observed).map(([key]) => LESSON_STATE_LABELS[key])
    : [];

  const syncAttemptState = (data = {}) => {
    const serverAttemptNumber = Number.isInteger(data.attemptNumber)
      ? data.attemptNumber
      : null;

    if (serverAttemptNumber !== null) {
      setAttemptNumber(serverAttemptNumber);
    }

    if (typeof data.hintsAvailable === 'boolean') {
      setHintsAvailable(data.hintsAvailable);
    } else if (serverAttemptNumber !== null) {
      const hintGate = Number.parseInt(config?.ctf_hint_gating_attempts, 10);
      if (Number.isInteger(hintGate) && hintGate >= 0) {
        setHintsAvailable(serverAttemptNumber >= hintGate);
      }
    }

    if (typeof data.hintsUsed === 'number') {
      setHintsUsed(data.hintsUsed);
    }
    if (typeof data.hintPenaltyTotal === 'number') {
      setHintPenaltyTotal(data.hintPenaltyTotal);
    }
    setLessonState(projectCtfLessonState(data.lessonState));

    return serverAttemptNumber;
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    const trimmed = inputMessage.trim();
    if (!ownerIsCurrent() || !trimmed || !stageReady || loading || (!isFixedPractice && rateLimitSeconds > 0) || !stage?.id) return;

    const requestEpoch = ++attemptEpochRef.current;
    const requestStageId = stage.id;
    const requestHeaders = getAuthHeaders();
    const isCurrentAttempt = () => ownerIsCurrent() && attemptMountedRef.current
      && attemptEpochRef.current === requestEpoch
      && currentStageRef.current === requestStageId
      && getAuthHeaders().Authorization === requestHeaders.Authorization;

    const userMsg = {
      id: nextMessageId(),
      role: 'user',
      content: trimmed,
      timestamp: new Date(),
    };

    const appendMessage = isFixedPractice ? setFixedPracticeMessages : setMessages;
    appendMessage((prev) => [...prev, userMsg]);
    setInputMessage('');
    setLoading(true);

    try {
      if (isFixedPractice) {
        const response = await recovery.request('post',
          `/api/ctf/stage/${stage.id}/practice`,
          { payload: trimmed, sessionToken },
          { headers: requestHeaders }
        );
        if (!isCurrentAttempt()) return;
        const data = response.data;
        if (!isFixedPracticeResult(data)) {
          setFixedPracticeMessages((prev) => [...prev, {
            id: nextMessageId(), role: 'system', timestamp: new Date(), variant: 'error',
            content: 'The fixed-practice response was incomplete. No scored attempt was submitted.',
          }]);
          return;
        }
        setPracticeCapabilities({
          protectedContextIncluded: data.protectedContextIncluded,
          serverSecretProvided: data.serverSecretProvided,
          scoringEligible: data.scoringEligible,
        });
        setFixedPracticeMessages((prev) => [...prev,
          { id: nextMessageId(), role: 'ai', content: data.response, timestamp: new Date() },
          {
            id: nextMessageId(), role: 'system', timestamp: new Date(), variant: 'fixed-practice',
            content: 'Fixed practice — unscored. This response cannot award completion credit, points, or progression.',
          },
        ]);
        return;
      }

      const response = await recovery.request('post',
        `/api/ctf/stage/${stage.id}/attempt`,
        { payload: trimmed, sessionToken },
        { headers: requestHeaders }
      );

      if (!isCurrentAttempt()) return;
      const data = response.data;

      syncAttemptState(data);

      if (data.usedTechniques?.length) {
        setUsedTechniques(data.usedTechniques);
      }

      if (data.blocked) {
        appendMessage((prev) => [
          ...prev,
          {
            id: nextMessageId(),
            role: 'system',
            content: data.reason || 'Your attempt was blocked by the defense system.',
            timestamp: new Date(),
            variant: 'blocked',
          },
        ]);
      } else {
        const attemptMessages = [];
        if (data.aiResponse) {
          attemptMessages.push({
            id: nextMessageId(),
            role: 'ai',
            content: data.aiResponse,
            timestamp: new Date(),
          });
        }

        if (
          !data.success &&
          data.message &&
          ['unavailable', 'inconclusive'].includes(data.judgment?.verdict)
        ) {
          attemptMessages.push({
            id: nextMessageId(),
            role: 'system',
            content: data.message,
            timestamp: new Date(),
            variant: data.judgment.verdict === 'unavailable' ? 'llm-down' : 'grading',
          });
        }

        if (attemptMessages.length > 0) {
          setMessages((prev) => [...prev, ...attemptMessages]);
        }
      }

      if (data.success) {
        setSuccessMessage(data.message || 'Challenge completed!');
        setShowSuccess(true);
        redirectTimerRef.current = setTimeout(() => {
          if (!isCurrentAttempt()) return;
          navigate('/ctf', {
            state: {
              completed: stage.stage_name,
              attempts: data.attemptNumber,
            },
          });
        }, 3000);
      }
    } catch (err) {
      if (!isCurrentAttempt() || isCtfRecoveryCancelled(err)) return;
      if (retireDeniedContext(err)) return;
      console.error('CTF attempt error:', err);
      const status = err.response?.status;

      if (isFixedPractice) {
        const fixedError = err.response?.data?.error || 'Fixed practice is temporarily unavailable. No scored attempt was submitted.';
        appendMessage((prev) => [...prev, {
          id: nextMessageId(), role: 'system', content: fixedError, timestamp: new Date(),
          variant: status === 503 ? 'llm-down' : 'error',
        }]);
        return;
      }

      if (status === 503) {
        const failureData = err.response?.data || {};
        const serverAttemptNumber = syncAttemptState(failureData);
        const serverMessage = failureData.error || 'AI temporarily unavailable.';
        const punctuation = /[.!?]$/.test(serverMessage) ? '' : '.';
        const alreadyExplainsRecordedAttempt = /attempt\s+\d+.*(?:recorded|counted)/i.test(serverMessage) &&
          /(?:no|without).*credit/i.test(serverMessage);
        const truthfulMessage = alreadyExplainsRecordedAttempt
          ? serverMessage
          : serverAttemptNumber !== null
            ? `${serverMessage}${punctuation} Attempt ${serverAttemptNumber} was recorded, but no completion credit was awarded.`
            : `${serverMessage}${punctuation} No completion credit was awarded. Refresh to reconcile the attempt count before retrying.`;
        appendMessage((prev) => [
          ...prev,
          {
            id: nextMessageId(),
            role: 'system',
            content: truthfulMessage,
            timestamp: new Date(),
            variant: 'llm-down',
          },
        ]);
      } else if (status === 429) {
        const retryAfter = err.response?.data?.retryAfter || 60;
        setRateLimitSeconds(retryAfter);
        appendMessage((prev) => [
          ...prev,
          {
            id: nextMessageId(),
            role: 'system',
            content: `Rate limit exceeded. Please wait ${retryAfter} seconds before trying again.`,
            timestamp: new Date(),
            variant: 'rate-limit',
          },
        ]);
      } else {
        setMessages((prev) => [
          ...prev,
          {
            id: nextMessageId(),
            role: 'system',
            content: err.response?.data?.error || 'Failed to submit attempt. Please try again.',
            timestamp: new Date(),
            variant: 'error',
          },
        ]);
      }
    } finally {
      if (isCurrentAttempt()) setLoading(false);
    }
  };

  const handleKeyDown = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSubmit(e);
    }
  };

  const selectPracticeMode = (nextMode) => {
    if (loading || purchasingHint || nextMode === practiceMode) return;
    setPracticeMode(nextMode);
    setInputMessage('');
  };

  if (!initialStage) {
    return null;
  }

  if (accessDenied === 401) {
    return <div style={{ ...styles.loadingScreen, fontFamily: styles.page.fontFamily }} role="status">
      <FiLock size={36} />
      <p style={styles.pageSubtitle}>Your CTF session is no longer authorized. Sign in again to continue.</p>
      <button type="button" style={{ ...styles.backBtn, fontFamily: 'inherit' }} onClick={() => navigate('/workshop-login', { replace: true })}>Sign in</button>
    </div>;
  }

  if (initializing) {
    return (
      <>
        <KeyframeStyles />
        <div style={styles.loadingScreen}>
          <FiRefreshCw size={36} style={styles.spin} />
          <CtfRecoveryNotice notices={recovery.notices} />
          <p style={{ margin: 0, fontSize: '1rem' }}>Initializing challenge...</p>
        </div>
      </>
    );
  }

  const inputDisabled = !stageReady || loading || (!isFixedPractice && rateLimitSeconds > 0) || showSuccess;

  return (
    <>
      <KeyframeStyles />

      {showSuccess && <Confetti />}

      {showSuccess && (
        <div style={styles.successOverlay}>
          <div style={styles.successBanner}>
            <div style={styles.successIcon}>
              <FiAward size={56} />
            </div>
            <h2 style={styles.successTitle}>Challenge Completed!</h2>
            <p style={styles.successMessage}>{successMessage}</p>
            <p style={{ ...styles.successMessage, marginTop: '1rem', fontSize: '0.85rem', opacity: 0.8 }}>
              Redirecting to dashboard in 3 seconds...
            </p>
          </div>
        </div>
      )}

      <div style={styles.page}>
        <div style={styles.wrapper}>
          <div style={styles.topBar}>
            <button
              type="button"
              style={styles.backBtn}
              onClick={() => navigate('/ctf')}
              onMouseEnter={(e) => {
                e.currentTarget.style.background = 'rgba(255,255,255,0.1)';
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.background = 'rgba(255,255,255,0.06)';
              }}
            >
              <FiArrowLeft />
              Back to Dashboard
            </button>
            <div style={{ textAlign: 'center', flex: 1 }}>
              <h1 style={styles.pageTitle}>{stage?.stage_name || 'CTF Challenge'}</h1>
              <p style={styles.pageSubtitle}>
                {stage?.stage_description || 'Prompt injection challenge'}
              </p>
            </div>
            <div style={{ width: '140px' }} aria-hidden="true" />
          </div>

          <div className="ctf-layout" style={styles.layout}>
            {/* ── LEFT: Chat (70%) ── */}
            <div style={styles.chatPanel}>
              <div style={styles.chatHeader}>
                <div style={styles.chatHeaderIcon}>
                  <FiCpu size={20} />
                </div>
                <div>
                  <h2 style={styles.chatHeaderTitle}>
                    Chat with {stage?.ai_guardian_name || 'AI Guardian'}
                  </h2>
                  <p style={styles.chatHeaderSub}>
                    {objective?.subtitle ||
                      'Craft prompt injection attempts to extract the protected secret.'}
                  </p>
                </div>
                <div style={{ marginLeft: 'auto', display: 'flex', gap: '0.4rem', flexWrap: 'wrap', justifyContent: 'flex-end' }} role="tablist" aria-label="CTF execution mode">
                  <button type="button" role="tab" aria-selected={!isFixedPractice} disabled={loading || purchasingHint}
                    onClick={() => selectPracticeMode('vulnerable')}
                    style={{ ...styles.modeButton, ...(!isFixedPractice ? styles.modeButtonActive : {}) }}>
                    Vulnerable challenge
                  </button>
                  <button type="button" role="tab" aria-selected={isFixedPractice} disabled={loading || purchasingHint}
                    onClick={() => selectPracticeMode('fixed')}
                    style={{ ...styles.modeButton, ...(isFixedPractice ? styles.modeButtonActive : {}) }}>
                    Fixed practice
                  </button>
                </div>
              </div>

              {isFixedPractice && (
                <div style={styles.fixedPracticeNotice} role="status">
                  <FiShield size={16} />
                  <span><strong>Fixed practice — unscored.</strong> Responses use the fixed practice path and cannot award credit, points, or stage progression.</span>
                </div>
              )}

              {!isFixedPractice && rateLimitSeconds > 0 && (
                <div style={styles.rateLimitBanner}>
                  <FiClock size={16} />
                  Rate limited — retry in <strong>{rateLimitSeconds}s</strong>
                </div>
              )}

              <div ref={chatAreaRef} style={styles.messagesArea}>
                {visibleMessages.map((msg) => (
                  <MessageBubble key={msg.id} message={msg} />
                ))}

                {loading && (
                  <div style={{ display: 'flex', alignItems: 'flex-start', gap: '0.65rem' }}>
                    <div
                      style={{
                        width: '36px',
                        height: '36px',
                        borderRadius: '50%',
                        background: 'rgba(51, 65, 85, 0.8)',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        color: '#94a3b8',
                      }}
                    >
                      <FiRefreshCw size={16} style={styles.spin} />
                    </div>
                    <div
                      style={{
                        padding: '0.85rem 1rem',
                        borderRadius: '16px 16px 16px 4px',
                        background: 'rgba(30, 41, 59, 0.9)',
                        border: '1px solid rgba(148, 163, 184, 0.12)',
                        color: '#94a3b8',
                        fontSize: '0.88rem',
                      }}
                    >
                      AI is processing your attempt...
                    </div>
                  </div>
                )}

                <div ref={messagesEndRef} />
              </div>

              {accessDenied && <div role="status">
                <p style={styles.pageSubtitle}>This challenge context is no longer available. Return to the dashboard to reload authorized state.</p>
                <button type="button" style={{ ...styles.backBtn, fontFamily: 'inherit' }} onClick={() => navigate('/ctf')}>Return to dashboard</button>
              </div>}
              <CtfRecoveryNotice notices={recovery.notices} />
              <form style={styles.inputRow} onSubmit={handleSubmit}>
                <textarea
                  style={styles.textarea}
                  value={inputMessage}
                  onChange={(e) => setInputMessage(e.target.value)}
                  onKeyDown={handleKeyDown}
                  placeholder={
                    rateLimitSeconds > 0
                      ? `Wait ${rateLimitSeconds}s before next attempt...`
                      : isFixedPractice
                        ? 'Try the same prompt against the fixed practice path...'
                        : 'Enter your prompt injection attempt...'
                  }
                  disabled={inputDisabled}
                  rows={2}
                />
                <button
                  type="submit"
                  style={{
                    ...styles.sendBtn,
                    ...(inputDisabled || !inputMessage.trim() ? styles.sendBtnDisabled : {}),
                  }}
                  disabled={inputDisabled || !inputMessage.trim()}
                  aria-label="Send attempt"
                >
                  <FiSend size={18} />
                </button>
              </form>
            </div>

            {/* ── RIGHT: Side panel (30%) ── */}
            <div style={styles.sidebar}>
              {/* Objective */}
              {objective && (
                <div style={styles.card}>
                  <h3 style={styles.cardTitle}>
                    <FiFlag size={16} />
                    Objective
                  </h3>
                  <p style={{ margin: '0 0 0.75rem', fontSize: '0.85rem', color: workshopTokens.text, lineHeight: 1.5 }}>
                    {stage?.teaching_objective || objective.goal}
                  </p>
                  <div style={{ marginBottom: '0.75rem' }}>
                    <div style={{ ...styles.infoLabel, marginBottom: '0.3rem' }}>Defense to beat</div>
                    <p style={{ margin: 0, fontSize: '0.8rem', color: workshopTokens.mutedText, lineHeight: 1.5 }}>
                      {objective.defense}
                    </p>
                  </div>
                  <div
                    style={{
                      display: 'flex',
                      gap: '0.5rem',
                      alignItems: 'flex-start',
                      padding: '0.6rem 0.7rem',
                      borderRadius: '8px',
                      background: 'rgba(34, 197, 94, 0.1)',
                      border: '1px solid rgba(34, 197, 94, 0.3)',
                    }}
                  >
                    <FiCheckCircle size={16} style={{ color: '#4ade80', flexShrink: 0, marginTop: '2px' }} />
                    <span style={{ fontSize: '0.78rem', color: '#bbf7d0', lineHeight: 1.5 }}>
                      {HOW_YOU_WIN}
                    </span>
                  </div>
                </div>
              )}

              {/* Stage info */}
              <div style={styles.card}>
                <h3 style={styles.cardTitle}>
                  <FiTarget size={16} />
                  Stage Info
                </h3>

                <div style={styles.infoRow}>
                  <span style={styles.infoLabel}>Stage</span>
                  <span style={styles.infoValue}>{stage?.stage_name}</span>
                </div>

                <div style={{ ...styles.infoRow, borderBottom: 'none', paddingTop: '0.75rem' }}>
                  <span style={styles.infoLabel}>Difficulty</span>
                  <span
                    style={{
                      ...styles.badge,
                      background: diffStyle.bg,
                      border: `1px solid ${diffStyle.border}`,
                      color: diffStyle.text,
                    }}
                  >
                    {stage?.difficulty || stage?.difficulty_level || 'medium'}
                  </span>
                </div>

                <div style={{ ...styles.infoRow, borderBottom: 'none' }}>
                  <span style={styles.infoLabel}>Guardian</span>
                  <span style={{ ...styles.infoValue, display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
                    <FiShield size={14} />
                    {stage?.ai_guardian_name}
                  </span>
                </div>

                <div style={{ ...styles.infoRow, borderBottom: 'none', paddingTop: '0.5rem' }}>
                  <span style={styles.infoLabel}>Defense Mode</span>
                  <span
                    style={{
                      ...styles.badge,
                      background:
                        stage?.adaptive_mode && stage.adaptive_mode !== 'none'
                          ? 'rgba(139, 92, 246, 0.15)'
                          : 'rgba(148, 163, 184, 0.1)',
                      border:
                        stage?.adaptive_mode && stage.adaptive_mode !== 'none'
                          ? '1px solid rgba(139, 92, 246, 0.35)'
                          : '1px solid rgba(148, 163, 184, 0.2)',
                      color:
                        stage?.adaptive_mode && stage.adaptive_mode !== 'none'
                          ? '#c4b5fd'
                          : '#94a3b8',
                    }}
                  >
                    <FiZap size={10} style={{ marginRight: '4px', verticalAlign: 'middle' }} />
                    {adaptiveLabels[stage?.adaptive_mode] || adaptiveLabels.none}
                  </span>
                </div>

                {observedLessons.map((label) => (
                  <div key={label} style={{ ...styles.infoRow, borderBottom: 'none' }}>
                    <span style={styles.infoLabel}>{label}</span>
                    <span style={{ ...styles.infoValue, color: '#86efac' }}>Observed</span>
                  </div>
                ))}

                {stage?.level_score != null && (
                  <div style={{ ...styles.infoRow, borderBottom: 'none' }}>
                    <span style={styles.infoLabel}>Points</span>
                    <span style={{ ...styles.infoValue, color: '#fbbf24' }}>
                      +{stage.level_score}
                    </span>
                  </div>
                )}
              </div>

              {/* Attempt counter */}
              {!isFixedPractice && showAttemptCounter && (
                <div style={styles.card}>
                  <h3 style={styles.cardTitle}>
                    <FiTarget size={16} />
                    Attempts
                  </h3>
                  <div style={styles.attemptBox}>
                    <div style={styles.attemptNumber}>{attemptNumber}</div>
                    <div style={styles.attemptLabel}>Attempts Made</div>
                  </div>
                </div>
              )}

              {/* Used techniques */}
              {showTechniqueFeedback && usedTechniques.length > 0 && (
                <div style={styles.card}>
                  <h3 style={styles.cardTitle}>
                    <FiZap size={16} />
                    Used Techniques
                  </h3>
                  <p style={{ margin: '0 0 0.75rem', fontSize: '0.82rem', color: workshopTokens.mutedText, lineHeight: 1.4 }}>
                    Techniques already tried on this adaptive level. Reusing them will be blocked.
                  </p>
                  <div style={styles.tagList}>
                    {usedTechniques.map((tag) => (
                      <span key={tag} style={styles.tag}>
                        {tag}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* Hints — progressive purchase system */}
              {isFixedPractice && (
                <div style={styles.card}>
                  <h3 style={styles.cardTitle}>
                    <FiShield size={16} />
                    Fixed practice
                  </h3>
                  <p style={{ margin: 0, fontSize: '0.85rem', color: workshopTokens.mutedText, lineHeight: 1.5 }}>
                    This transcript is separate from your vulnerable challenge attempts and is never used for score or progression.
                  </p>
                  {practiceCapabilities && (
                    <p style={{ margin: '0.75rem 0 0', fontSize: '0.8rem', color: workshopTokens.text, lineHeight: 1.5 }}>
                      Fixed response confirmed: protected context withheld, server secret withheld, and scoring disabled.
                    </p>
                  )}
                </div>
              )}

              {!initializing && !isFixedPractice && (
                <div style={styles.card}>
                  <h3 style={styles.cardTitle}>
                    <FiHelpCircle size={16} />
                    Hints
                    {hintPenaltyTotal > 0 && (
                      <span style={{ marginLeft: 'auto', fontSize: '0.72rem', fontWeight: 600, color: '#f87171' }}>
                        -{hintPenaltyTotal} pts
                      </span>
                    )}
                  </h3>

                  {/* Purchased hints */}
                  {purchasedHints.map((hint, idx) => (
                    <div key={idx} style={styles.hintItem}>
                      <div style={{ fontSize: '0.72rem', fontWeight: 700, color: '#4ade80', marginBottom: '0.35rem', display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
                        <FiCheckCircle size={12} />
                        Hint {idx + 1}
                      </div>
                      {hint}
                    </div>
                  ))}

                  {/* Next hint to purchase */}
                  {hintsAvailable && hintsUsed < 3 && (
                    <div style={{ padding: '0.75rem', borderRadius: '8px', background: 'rgba(251, 191, 36, 0.08)', border: '1px solid rgba(251, 191, 36, 0.2)', marginTop: purchasedHints.length > 0 ? '0.5rem' : 0 }}>
                      <button
                        type="button"
                        onClick={() => setConfirmHintIndex(hintsUsed)}
                        disabled={purchasingHint}
                        style={{
                          width: '100%',
                          padding: '0.6rem 1rem',
                          border: '1px solid rgba(251, 191, 36, 0.4)',
                          borderRadius: '8px',
                          background: 'rgba(251, 191, 36, 0.1)',
                          color: '#fbbf24',
                          fontSize: '0.85rem',
                          fontWeight: 600,
                          cursor: purchasingHint ? 'not-allowed' : 'pointer',
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'center',
                          gap: '0.5rem',
                          transition: 'all 0.2s',
                        }}
                      >
                        <FiHelpCircle size={14} />
                        Unlock Hint {hintsUsed + 1}
                        <span style={{ fontSize: '0.75rem', opacity: 0.8 }}>
                          (-{config?.[`ctf_hint_cost_${hintsUsed + 1}`] || '?'} pts)
                        </span>
                      </button>
                      {hintsUsed < 2 && (
                        <p style={{ margin: '0.4rem 0 0', fontSize: '0.72rem', color: '#64748b', textAlign: 'center' }}>
                          {3 - hintsUsed} hints remaining
                        </p>
                      )}
                    </div>
                  )}

                  {/* Locked state — not enough attempts */}
                  {!hintsAvailable && (
                    <p style={{ margin: 0, fontSize: '0.85rem', color: '#64748b', lineHeight: 1.5 }}>
                      Hints unlock after {config?.ctf_hint_gating_attempts || '3'} attempts.
                      {attemptNumber > 0 && ` (${attemptNumber} so far)`}
                    </p>
                  )}

                  {/* All hints purchased */}
                  {hintsAvailable && hintsUsed >= 3 && purchasedHints.length === 0 && (
                    <p style={{ margin: 0, fontSize: '0.85rem', color: '#64748b' }}>
                      All hints used.
                    </p>
                  )}
                </div>
              )}

              {/* Hint purchase confirmation modal */}
              {confirmHintIndex !== null && (
                <div
                  style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.6)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 9999 }}
                  onClick={() => !purchasingHint && setConfirmHintIndex(null)}
                  role="presentation"
                >
                  <div
                    style={{ background: '#1e293b', border: '1px solid rgba(251,191,36,0.3)', borderRadius: '16px', padding: '1.75rem', maxWidth: '400px', width: '90%' }}
                    onClick={(e) => e.stopPropagation()}
                    role="dialog"
                    aria-modal="true"
                  >
                    <h3 style={{ margin: '0 0 0.75rem', color: '#fbbf24', fontSize: '1.1rem', fontWeight: 700 }}>
                      <FiHelpCircle style={{ verticalAlign: 'middle', marginRight: '0.5rem' }} />
                      Unlock Hint {confirmHintIndex + 1}?
                    </h3>
                    <p style={{ margin: '0 0 0.5rem', color: '#e2e8f0', fontSize: '0.9rem', lineHeight: 1.6 }}>
                      This will cost <strong style={{ color: '#f87171' }}>{config?.[`ctf_hint_cost_${confirmHintIndex + 1}`] || '?'} points</strong> from your stage score.
                    </p>
                    <p style={{ margin: '0 0 1.25rem', color: '#94a3b8', fontSize: '0.82rem' }}>
                      Effective score: {Math.max(0, (stage?.level_score ?? 100) - hintPenaltyTotal - parseInt(config?.[`ctf_hint_cost_${confirmHintIndex + 1}`] || '0'))} / {stage?.level_score ?? 100} pts
                    </p>
                    <CtfRecoveryNotice notices={recovery.notices} />
                    <div style={{ display: 'flex', gap: '0.75rem', justifyContent: 'flex-end' }}>
                      <button
                        type="button"
                        onClick={() => setConfirmHintIndex(null)}
                        disabled={purchasingHint}
                        style={{ padding: '0.6rem 1.2rem', borderRadius: '8px', border: '1px solid #334155', background: 'transparent', color: '#94a3b8', fontSize: '0.85rem', cursor: 'pointer' }}
                      >
                        Cancel
                      </button>
                      <button
                        type="button"
                        onClick={async () => {
                          if (!ownerIsCurrent() || !stageReady) return;
                          const hintHeaders = getAuthHeaders();
                          const hintStageId = stage.id;
                          const hintEpoch = lifecycleEpochRef.current;
                          const isCurrentHint = () => ownerIsCurrent() && attemptMountedRef.current
                            && lifecycleEpochRef.current === hintEpoch
                            && currentStageRef.current === hintStageId
                            && getAuthHeaders().Authorization === hintHeaders.Authorization;
                          setPurchasingHint(true);
                          try {
                            const resp = await recovery.request('post',
                              `/api/ctf/stage/${stage.id}/hint`,
                              { hintIndex: confirmHintIndex },
                              { headers: hintHeaders }
                            );
                            if (!isCurrentHint()) return;
                            setPurchasedHints((prev) => [...prev, resp.data.hint]);
                            setHintsUsed(resp.data.hintsUsed);
                            setHintPenaltyTotal(resp.data.totalPenalty);
                            setConfirmHintIndex(null);
                          } catch (err) {
                            if (!isCurrentHint() || isCtfRecoveryCancelled(err)) return;
                            if (retireDeniedContext(err)) return;
                            console.error('Hint purchase failed:', err);
                            alert(err.response?.data?.error || 'Failed to purchase hint');
                          } finally {
                            if (isCurrentHint()) setPurchasingHint(false);
                          }
                        }}
                        disabled={purchasingHint}
                        style={{ padding: '0.6rem 1.2rem', borderRadius: '8px', border: 'none', background: '#fbbf24', color: '#0f172a', fontSize: '0.85rem', fontWeight: 700, cursor: purchasingHint ? 'not-allowed' : 'pointer' }}
                      >
                        {purchasingHint ? 'Unlocking...' : `Unlock (-${config?.[`ctf_hint_cost_${confirmHintIndex + 1}`] || '?'} pts)`}
                      </button>
                    </div>
                  </div>
                </div>
              )}

              <button
                type="button"
                style={styles.dashboardBtn}
                onClick={() => navigate('/ctf')}
                onMouseEnter={(e) => {
                  e.currentTarget.style.background = 'rgba(255,255,255,0.08)';
                }}
                onMouseLeave={(e) => {
                  e.currentTarget.style.background = 'rgba(255,255,255,0.05)';
                }}
              >
                <FiArrowLeft size={16} />
                Back to Dashboard
              </button>
            </div>
          </div>
        </div>
      </div>
    </>
  );
};

export default CTFChallenge;
