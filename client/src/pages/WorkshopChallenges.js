import React, { useState, useEffect, useCallback, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  FiCheckCircle, FiLock, FiUnlock, FiTarget, FiDatabase, FiCode,
  FiShield, FiCpu, FiZap, FiAlertTriangle, FiCircle,
  FiTerminal, FiPlay, FiPackage, FiFileText, FiClock
} from 'react-icons/fi';
import styled from 'styled-components';
import { motion } from 'framer-motion';
import axios from 'axios';
import HintPanel from '../components/HintPanel';
import SolutionPanel from '../components/SolutionPanel';
import { useWorkshopConfig } from '../context/WorkshopConfigContext';
import { workshopTokens } from '../components/workshop/experience.mjs';
import { formatWorkshopTime } from '../utils/formatWorkshopTime';
// The shared configuration snapshot gates hint/solution visibility. The
// challenges endpoint still supplies user progress and solution content paths.

const ChallengesContainer = styled.div`
  min-height: 100vh;
  background: ${workshopTokens.primaryGradient};
  padding: 2rem 0 3rem;
  overflow-x: hidden;
`;

const ChallengesContent = styled.div`
  max-width: 1400px;
  margin: 0 auto;
  padding: 0 clamp(1rem, 3vw, 2rem);
`;

// Presentation follows the original student dashboard at reference ba8b389.
// Keep this page's canonical library/configuration data flow independent of styling.
const Header = styled(motion.div)`
  background: rgba(255, 255, 255, 0.95);
  backdrop-filter: blur(20px);
  border: 1px solid rgba(255, 255, 255, 0.2);
  border-radius: 24px;
  padding: clamp(1.25rem, 4vw, 2.5rem);
  margin-bottom: 2rem;
  box-shadow: 0 25px 50px rgba(0, 0, 0, 0.1);
`;

const Title = styled.h1`
  margin: 0 0 0.5rem;
  font-size: clamp(1.75rem, 4vw, 2.5rem);
  font-weight: 700;
  color: ${workshopTokens.brand};
  span {
    background: ${workshopTokens.primaryGradient};
    -webkit-background-clip: text;
    background-clip: text;
    -webkit-text-fill-color: transparent;
  }
  display: flex;
  align-items: center;
  gap: 0.75rem;
  svg { flex-shrink: 0; }
`;

const Subtitle = styled.p`
  color: #666;
  font-size: clamp(1rem, 2vw, 1.2rem);
  line-height: 1.6;
  margin: 0;
  max-width: 80ch;
`;

const SummaryGrid = styled.div`
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  background: #fff;
  border: 1px solid #edf0f5;
  border-radius: 16px;
  overflow: hidden;
  margin-top: 2rem;
  @media (max-width: 640px) { grid-template-columns: repeat(2, minmax(0, 1fr)); }
`;

const SummaryStat = styled.div`
  min-width: 0;
  padding: clamp(0.85rem, 2vw, 1.5rem) clamp(0.75rem, 2vw, 1.25rem);
  border-right: 1px solid #edf0f5;
  display: flex;
  flex-direction: column;
  gap: 0.35rem;
  strong { display: block; color: #1a202c; font-size: clamp(1.4rem, 3vw, 1.9rem); line-height: 1.1; }
  span { display: block; color: #626d80; font-size: 0.72rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.06em; }
  &:last-child { border-right: none; }
  @media (max-width: 640px) {
    &:nth-child(2n) { border-right: none; }
    &:nth-child(-n+2) { border-bottom: 1px solid #edf0f5; }
  }
`;

const ProgressBar = styled.div`
  background: ${workshopTokens.border};
  height: 12px;
  border-radius: 8px;
  margin: 1.25rem 0 0.5rem;
  overflow: hidden;
`;

const ProgressFill = styled.div`
  background: ${workshopTokens.primaryGradient};
  height: 100%;
  width: ${props => props.progress}%;
  border-radius: 8px;
  transition: width 0.3s ease;
  @media (prefers-reduced-motion: reduce) { transition: none; }
`;

const ProgressText = styled.p`
  color: ${workshopTokens.mutedText};
  font-size: 0.9rem;
  font-weight: 600;
  margin: 0;
`;

/* ── Section ── */
const Section = styled(motion.div)`
  background: rgba(255, 255, 255, 0.95);
  backdrop-filter: blur(20px);
  border: 1px solid rgba(255, 255, 255, 0.2);
  border-radius: 24px;
  padding: clamp(1.25rem, 3vw, 2rem);
  margin-bottom: 2rem;
  box-shadow: 0 25px 50px rgba(0, 0, 0, 0.1);
`;

const SectionTitle = styled.h2`
  color: ${workshopTokens.text};
  margin: 0 0 1.25rem;
  font-size: clamp(1.4rem, 3vw, 1.8rem);
  font-weight: 700;
  display: flex;
  align-items: center;
  gap: 0.75rem;
`;

/* ── Grid ── */
const ChallengeGrid = styled.div`
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(min(100%, 300px), 1fr));
  gap: 1.25rem;
`;

/* ── Card ── */
const CARD_COLORS = {
  accent: workshopTokens.brand,
  bg: 'rgba(102,126,234,0.08)',
  border: 'rgba(102,126,234,0.28)',
};

const ChallengeCard = styled.div`
  background: ${workshopTokens.surface};
  border-radius: 14px;
  padding: 1.25rem;
  box-shadow: 0 1px 3px rgba(0,0,0,0.06);
  border: 1px solid #edf0f5;
  position: relative;
  transition: transform 0.3s ease, box-shadow 0.3s ease;
  overflow: hidden;
  display: flex;
  flex-direction: column; /* uniform structure; action row pinned to bottom */

  @media (prefers-reduced-motion: reduce) {
    transition: none;
    &:hover { transform: none; }
  }

  &::before {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 4px;
    background: ${props =>
      props.status === 'completed'
        ? workshopTokens.successGradient
        : props.status === 'in_progress'
        ? `linear-gradient(90deg, ${workshopTokens.warning}, #d69e2e)`
        : props.status === 'locked' ? workshopTokens.controlBorder : workshopTokens.primaryGradient};
  }

  &:hover {
    transform: translateY(-3px);
    box-shadow: 0 10px 24px rgba(0,0,0,0.1);
  }
`;

const CardTop = styled.div`
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: 1rem;
  margin-bottom: 0.75rem;
`;

const CardIconWrap = styled.div`
  width: 44px;
  height: 44px;
  border-radius: 12px;
  background: ${props => props.bg};
  display: flex;
  align-items: center;
  justify-content: center;
  color: ${props => props.color};
  font-size: 1.3rem;
  flex-shrink: 0;
`;

const CardTitleWrap = styled.div`
  flex: 1;
`;

const CardTitle = styled.h3`
  color: ${workshopTokens.text};
  margin: 0 0 0.5rem 0;
  font-size: 1.15rem;
  font-weight: 700;
  line-height: 1.3;
`;

const BadgeRow = styled.div`
  display: flex;
  align-items: center;
  gap: 0.5rem;
  flex-wrap: wrap;
`;

const Badge = styled.span`
  background: ${props => props.bg || CARD_COLORS.bg};
  color: ${props => props.color || workshopTokens.focus};
  border: 1px solid ${props => props.border || CARD_COLORS.border};
  padding: 0.2rem 0.65rem;
  border-radius: 20px;
  font-size: 0.72rem;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.4px;
`;

const StatusBadge = styled.div`
  display: flex;
  align-items: center;
  gap: 0.35rem;
  font-size: 0.85rem;
  font-weight: 600;
  white-space: nowrap;
  color: ${props =>
    props.status === 'completed'   ? '#22863a' :
    props.status === 'in_progress' ? '#d69e2e' :
    props.status === 'unlocked'    ? workshopTokens.focus : '#4a5568'};
`;

const Description = styled.p`
  color: ${workshopTokens.mutedText};
  font-size: 0.9rem;
  line-height: 1.55;
  margin: 0.75rem 0 1rem;
  /* clamp to 3 lines so collapsed cards keep a consistent header height */
  display: -webkit-box;
  -webkit-line-clamp: 3;
  -webkit-box-orient: vertical;
  overflow: hidden;
`;

const TechTags = styled.div`
  display: flex;
  flex-wrap: wrap;
  gap: 0.4rem;
  margin-bottom: 1.1rem;
`;

const TechTag = styled.span`
  background: ${props => props.bg};
  color: ${props => props.color};
  border-radius: 6px;
  padding: 0.2rem 0.55rem;
  font-size: 0.75rem;
  font-weight: 500;
`;

const ObjectivesHeader = styled.div`
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 0.65rem;
`;

const ObjectivesLabel = styled.span`
  font-size: 0.85rem;
  font-weight: 600;
  color: #4a5568;
  display: flex;
  align-items: center;
  gap: 0.4rem;
`;

const ObjCount = styled.span`
  font-size: 0.8rem;
  font-weight: 600;
  color: ${props => props.$done === props.total ? '#22863a' : '#667eea'};
  background: ${props => props.$done === props.total ? 'rgba(34,134,58,0.1)' : 'rgba(102,126,234,0.1)'};
  padding: 0.15rem 0.55rem;
  border-radius: 10px;
`;

const ObjectivesList = styled.div`
  display: flex;
  flex-direction: column;
  gap: 0.3rem;
  margin-bottom: 1.25rem;
  max-height: ${props => props.$expanded ? '1000px' : '110px'};
  overflow: hidden;
  transition: max-height 0.4s ease;
`;

const ObjRow = styled.div`
  display: flex;
  align-items: flex-start;
  gap: 0.55rem;
  padding: 0.3rem 0;
  font-size: 0.85rem;
  color: ${props => props.$done ? '#2d6a4f' : '#4a5568'};

  svg {
    margin-top: 1px;
    flex-shrink: 0;
    color: ${props => props.$done ? '#28a745' : '#a0aec0'};
  }
`;

const ShowMoreBtn = styled.button`
  background: none;
  border: none;
  color: ${workshopTokens.focus};
  font: inherit;
  font-size: 0.82rem;
  font-weight: 600;
  cursor: pointer;
  min-height: 44px;
  padding: 0.5rem 0;
  margin-bottom: 1rem;

  &:hover { text-decoration: underline; }
  &:focus-visible { outline: 3px solid ${workshopTokens.focus}; outline-offset: 2px; }
`;

const StartBtn = styled.button`
  width: 100%;
  background: ${props => props.disabled ? workshopTokens.controlBorder : workshopTokens.primaryGradient};
  color: ${props => props.disabled ? '#4a5568' : 'white'};
  border: none;
  min-height: 44px;
  padding: 0.75rem 1.5rem;
  border-radius: ${workshopTokens.controlRadius};
  font: inherit;
  font-weight: 700;
  font-size: 0.95rem;
  cursor: ${props => props.disabled ? 'not-allowed' : 'pointer'};
  transition: all 0.25s ease;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 0.5rem;

  &:hover:not(:disabled) {
    transform: translateY(-2px);
    box-shadow: 0 6px 20px rgba(0,0,0,0.18);
  }
  &:focus-visible { outline: 3px solid ${workshopTokens.focus}; outline-offset: 2px; }
  @media (prefers-reduced-motion: reduce) { transition: none; &:hover:not(:disabled) { transform: none; } }
`;

const RefreshBtn = styled(StartBtn)`
  width: auto;
`;

/* ── Challenge metadata ── */
const CHALLENGE_META = {
  reflected_xss_llm: {
    icon: <FiCode />,
    categoryLabel: 'AI Security',
    techniques: ['Reflected XSS', 'LLM Output Injection', 'Script Injection', 'SVG Payloads'],
  },
  direct_prompt_injection: {
    icon: <FiShield />,
    categoryLabel: 'AI Security',
    techniques: ['Jailbreak', 'Prompt Leakage', 'Role Playing', 'Obfuscation', 'Multi-Language'],
  },
  indirect_prompt_injection: {
    icon: <FiFileText />,
    categoryLabel: 'AI Security',
    techniques: ['RAG Poisoning', 'Email Agent Attack', 'Document Injection', 'Data Exfiltration'],
  },
  csrf_prompt_injection: {
    icon: <FiShield />,
    categoryLabel: 'AI Security',
    techniques: ['CSRF', 'Prompt Injection', 'Excessive Agency', 'GET State Change', 'Unsafe HTML'],
  },
  sensitive_info_disclosure: {
    icon: <FiAlertTriangle />,
    categoryLabel: 'Web Security',
    techniques: ['Tool Enumeration', 'Path Traversal', 'SSRF', 'Error Leakage', 'Admin Tool Abuse'],
  },
  mcp_server_rce: {
    icon: <FiTerminal />,
    categoryLabel: 'AI Security',
    techniques: ['MCP Tool Abuse', 'Command Injection', 'Env Var Leakage', 'Allowlist Bypass'],
  },
  excessive_agency: {
    icon: <FiCpu />,
    categoryLabel: 'AI Security',
    techniques: ['Permission Escalation', 'Dangerous AI Actions', 'Agent Exploitation'],
  },
  ctf_prompt_injection_challenge: {
    icon: <FiZap />,
    categoryLabel: 'CTF',
    techniques: ['Adaptive Defenses', 'AI Guardians', 'Prompt Injection Mastery'],
  },
  sql_injection_workshop: {
    icon: <FiDatabase />,
    categoryLabel: 'SQL Injection',
    techniques: ['UNION-Based', 'Error-Based', 'Boolean Bypass', 'Schema Extraction'],
  },
  nosql_injection_workshop: {
    icon: <FiDatabase />,
    categoryLabel: 'NoSQL Injection',
    techniques: ['Simulated Operator Injection', 'Wildcard Search Bypass', 'Simulated $where Bypass', 'Restricted Record Disclosure'],
  },
  supply_chain_rce: {
    icon: <FiPackage />,
    categoryLabel: 'Supply Chain',
    techniques: ['Fictional Dependency Exploit', 'Isolated JavaScript Execution', 'Synthetic Config Disclosure', 'Synthetic SSH Key Disclosure'],
  },
};

const DIFFICULTY_STYLE = {
  beginner:     { bg: 'rgba(40,167,69,0.12)',  color: '#276749', border: 'rgba(40,167,69,0.3)' },
  intermediate: { bg: 'rgba(255,193,7,0.12)',  color: '#744210', border: 'rgba(255,193,7,0.4)' },
  advanced:     { bg: 'rgba(220,53,69,0.1)',   color: '#9b2335', border: 'rgba(220,53,69,0.3)' },
  expert:       { bg: 'rgba(128,90,213,0.1)',  color: '#553c9a', border: 'rgba(128,90,213,0.3)' },
};

/* ═══════════════════════════════════════════ Component ═══════════════════════════════════════════ */

const WorkshopChallenges = () => {
  const navigate = useNavigate();
  const { snapshot, revision, registerReconciler } = useWorkshopConfig();
  const [challenges, setChallenges] = useState([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState(null);
  const [expandedObjectives, setExpandedObjectives] = useState({});
  const mountedRef = useRef(false);
  const requestSequenceRef = useRef(0);

  const fetchChallenges = useCallback(async (options = {}) => {
    const background = options === true || options?.background === true;
    const signal = options?.signal;
    const requestId = ++requestSequenceRef.current;
    setLoading(true);
    if (!background) setLoadError(null);
    try {
      const response = await axios.get('/api/workshop/challenges', { signal });
      const visible = (response.data.challenges || []).filter(
        c => c.id !== 'ctf_prompt_injection_challenge' && c.challenge_key !== 'ctf_prompt_injection_challenge'
      );
      if (!mountedRef.current || signal?.aborted || requestId !== requestSequenceRef.current) return null;
      setChallenges(visible);
      setLoadError(null);
      return visible;
    } catch (err) {
      if (!mountedRef.current || requestId !== requestSequenceRef.current) return null;
      setLoadError('Unable to load exercises. Please try again.');
      if (background) throw err;
      console.error('Error fetching challenges:', err);
      return null;
    } finally {
      if (mountedRef.current && requestId === requestSequenceRef.current) setLoading(false);
    }
  }, []);

  useEffect(() => {
    mountedRef.current = true;
    void fetchChallenges();
    return () => {
      mountedRef.current = false;
      requestSequenceRef.current += 1;
    };
  }, [fetchChallenges]);

  useEffect(() => registerReconciler(
    (_revision, { signal } = {}) => fetchChallenges({ background: true, signal })
  ), [fetchChallenges, registerReconciler]);

  const toggleObjectives = (id) =>
    setExpandedObjectives(prev => ({ ...prev, [id]: !prev[id] }));

  const renderEmptyState = () => (
    <Section initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}>
      <div style={{ textAlign: 'center', padding: '4rem 2rem' }}>
        <FiShield size={60} style={{ color: workshopTokens.brand, marginBottom: '1.5rem' }} />
        <h3 style={{ color: workshopTokens.text, fontSize: '1.6rem', marginBottom: '0.75rem' }}>
          No Exercises Available
        </h3>
        <p style={{ color: workshopTokens.mutedText, fontSize: '1.05rem', lineHeight: 1.65, maxWidth: '480px', margin: '0 auto 2rem' }}>
          Your instructor hasn't enabled any exercises yet. Contact them to enable tasks for this workshop session.
        </p>
        <RefreshBtn type="button" onClick={() => fetchChallenges()}>
          Refresh
        </RefreshBtn>
      </div>
    </Section>
  );

  const renderCard = (challenge, index) => {
    const colors = CARD_COLORS;
    const meta = CHALLENGE_META[challenge.id] || { icon: <FiShield />, categoryLabel: 'Security', techniques: [] };
    const diffKey = (challenge.difficulty || '').toLowerCase();
    const diffStyle = DIFFICULTY_STYLE[diffKey] || DIFFICULTY_STYLE.intermediate;
    const objectives = challenge.objectives || [];
    const doneCount = objectives.filter(o => o.completed).length;
    const PREVIEW_COUNT = 3;
    const expanded = !!expandedObjectives[challenge.id];

    return (
      <ChallengeCard key={challenge.id} status={challenge.status}
        data-testid={challenge.id === 'direct_prompt_injection' ? 'workshop-card-direct_prompt_injection' : undefined}
        as={motion.div}
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.08 * index }}
      >
        <CardTop>
          <CardIconWrap bg={colors.bg} color={colors.accent}>
            {meta.icon}
          </CardIconWrap>

          <CardTitleWrap>
            <CardTitle>{challenge.title}</CardTitle>
            <BadgeRow>
              <Badge bg={diffStyle.bg} color={diffStyle.color} border={diffStyle.border}>
                {challenge.difficulty}
              </Badge>
              <Badge bg={colors.bg} color={colors.accent} border={colors.border}>
                {meta.categoryLabel}
              </Badge>
            </BadgeRow>
          </CardTitleWrap>

          <StatusBadge status={challenge.status}>
            {challenge.status === 'completed'   && <><FiCheckCircle /> Done</>}
            {challenge.status === 'in_progress' && <><FiPlay /> In Progress</>}
            {challenge.status === 'unlocked'    && <><FiUnlock /> Open</>}
            {challenge.status === 'locked'      && <><FiLock /> Locked</>}
          </StatusBadge>
        </CardTop>

        <Description>{challenge.description}</Description>

        {meta.techniques.length > 0 && (
          <TechTags>
            {meta.techniques.map(t => (
              <TechTag key={t} bg={colors.bg} color={colors.accent}>{t}</TechTag>
            ))}
          </TechTags>
        )}

        {objectives.length > 0 && (
          <>
            <ObjectivesHeader>
              <ObjectivesLabel><FiTarget size={13} /> Objectives</ObjectivesLabel>
              <ObjCount
                $done={doneCount}
                total={objectives.length}
                data-testid={challenge.id === 'direct_prompt_injection' ? 'objective-count' : undefined}
              >
                {doneCount}/{objectives.length} completed
              </ObjCount>
            </ObjectivesHeader>

            <ObjectivesList $expanded={expanded || objectives.length <= PREVIEW_COUNT}>
              {objectives.map(obj => (
                <ObjRow key={obj.id} $done={obj.completed}>
                  {obj.completed ? <FiCheckCircle size={14} /> : <FiCircle size={14} />}
                  <div style={{ flex: 1 }}>
                    <span>{obj.text}</span>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.25rem', marginTop: '0.3rem' }}>
                      {snapshot?.exercises?.[obj.sourceWorkshopKey || challenge.workshopKey]?.objectives?.[obj.id]?.hintVisible && (
                        <HintPanel
                          key={`hint-${obj.id}-${revision}`}
                          workshopKey={obj.sourceChallengeKey || challenge.id}
                          objectiveId={obj.id}
                          accentColor={colors.accent}
                        />
                      )}
                      {snapshot?.exercises?.[obj.sourceWorkshopKey || challenge.workshopKey]?.objectives?.[obj.id]?.solutionVisible && obj.solutionEndpoint && (
                        <SolutionPanel
                          key={`solution-${obj.id}-${revision}`}
                          solutionEndpoint={obj.solutionEndpoint}
                          accentColor={colors.accent}
                        />
                      )}
                    </div>
                  </div>
                </ObjRow>
              ))}
            </ObjectivesList>

            {objectives.length > PREVIEW_COUNT && (
              <ShowMoreBtn onClick={() => toggleObjectives(challenge.id)}>
                {expanded ? '▲ Show less' : `▼ Show all ${objectives.length} objectives`}
              </ShowMoreBtn>
            )}

            <div style={{ margin: '0.5rem 0 1rem' }}>
              <div style={{
                  background: workshopTokens.border, height: '6px', borderRadius: '4px', overflow: 'hidden'
              }}>
                <div style={{
                  background: doneCount === objectives.length
                    ? workshopTokens.successGradient
                    : workshopTokens.primaryGradient,
                  height: '100%',
                  width: `${objectives.length ? (doneCount / objectives.length) * 100 : 0}%`,
                  borderRadius: '4px',
                  transition: 'width 0.6s ease',
                }} />
              </div>
            </div>
          </>
        )}

        {(challenge.timeSpentSeconds || 0) > 0 && (
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.3rem', fontSize: '0.8rem', color: workshopTokens.mutedText, marginBottom: '0.75rem' }}>
            <FiClock size={12} />
            {formatWorkshopTime(challenge.timeSpentSeconds)}
          </div>
        )}

        <StartBtn
          disabled={challenge.status === 'locked'}
          onClick={() => {
            if (challenge.status !== 'locked') navigate(challenge.route);
          }}
        >
          {challenge.status === 'locked'      && <><FiLock size={15} /> Locked</>}
          {challenge.status === 'completed'   && <><FiCheckCircle size={15} /> Review Exercise</>}
          {challenge.status === 'in_progress' && <><FiPlay size={15} /> Continue Exercise</>}
          {challenge.status === 'unlocked'    && <><FiZap size={15} /> Start Exercise</>}
        </StartBtn>
      </ChallengeCard>
    );
  };

  const totalObjectives = challenges.reduce((s, c) => s + (c.objectiveCount ?? c.objectives?.length ?? 0), 0);
  const completedObjectives = challenges.reduce((s, c) => s + (c.completedObjectiveCount ?? c.objectives?.filter(o => o.completed).length ?? 0), 0);
  const objectivePct = totalObjectives > 0 ? Math.round((completedObjectives / totalObjectives) * 100) : 0;
  const readyExerciseCount = challenges.filter((challenge) => challenge.status !== 'locked').length;
  const lockedExerciseCount = challenges.length - readyExerciseCount;
  const trackedTimeSeconds = challenges.reduce((s, c) => s + (c.timeSpentSeconds || 0), 0);

  return (
    <ChallengesContainer>
      <ChallengesContent>

        <Header initial={{ opacity: 0, y: -24 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.5 }}>
          <Title><FiShield aria-hidden="true" /><span>Student Dashboard</span></Title>
          <Subtitle>
            {challenges.length > 0
              ? `Browse ${challenges.length} instructor-visible exercises: ${readyExerciseCount} ready to open, ${lockedExerciseCount} locked until objectives are enabled.`
              : loading ? 'Loading your exercise library.'
              : loadError ? 'The exercise library could not be loaded.'
              : 'Waiting for your instructor to enable exercises for this session.'}
          </Subtitle>

          {challenges.length > 0 && (
            <>
              <SummaryGrid aria-label="Workshop progress summary">
                <SummaryStat><strong>{readyExerciseCount}</strong><span>Ready to open</span></SummaryStat>
                <SummaryStat><strong>{lockedExerciseCount}</strong><span>Locked exercises</span></SummaryStat>
                <SummaryStat><strong>{completedObjectives}/{totalObjectives}</strong><span>Objectives completed</span></SummaryStat>
                <SummaryStat><strong>{formatWorkshopTime(trackedTimeSeconds)}</strong><span>Time tracked</span></SummaryStat>
              </SummaryGrid>
              <ProgressBar role="progressbar" aria-label="Objective completion progress" aria-valuenow={objectivePct} aria-valuemin={0} aria-valuemax={100}>
                <ProgressFill progress={objectivePct} />
              </ProgressBar>
              <ProgressText>
                {objectivePct}% complete — {completedObjectives}/{totalObjectives} objectives done
              </ProgressText>
            </>
          )}
        </Header>

        {loading && (
          <Section role="status" aria-live="polite">
            {challenges.length ? 'Refreshing exercises…' : 'Loading exercises…'}
          </Section>
        )}
        {loadError && (
          <Section role="alert">
            <p>{loadError}</p>
            <RefreshBtn type="button" disabled={loading} onClick={() => fetchChallenges()}>
              Retry loading exercises
            </RefreshBtn>
          </Section>
        )}
        {challenges.length === 0 ? (!loading && !loadError ? renderEmptyState() : null) : (
          <Section initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.15 }}>
            <SectionTitle>
              <FiTarget /> Exercise Library ({challenges.length} visible)
            </SectionTitle>
            <ChallengeGrid>
              {challenges.map((c, i) => renderCard(c, i))}
            </ChallengeGrid>
          </Section>
        )}

      </ChallengesContent>
    </ChallengesContainer>
  );
};

export default WorkshopChallenges;
