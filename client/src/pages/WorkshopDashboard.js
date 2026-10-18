import React, { useState, useEffect, useCallback, useRef } from 'react';
import { Link } from 'react-router-dom';
import {
  FiShield, FiLock, FiUnlock,
  FiCheckCircle, FiTarget,
  FiDatabase, FiCpu, FiCode, FiAlertTriangle,
  FiPlay, FiClock, FiBarChart, FiRefreshCw,
  FiPackage, FiFileText, FiTerminal
} from 'react-icons/fi';
import styled from 'styled-components';
import { motion } from 'framer-motion';
import { useAuth } from '../context/AuthContext';
import { useWorkshopConfig } from '../context/WorkshopConfigContext';
import { formatWorkshopTime } from '../utils/formatWorkshopTime';
import axios from 'axios';

const DashboardContainer = styled.div`
  min-height: 100vh;
  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
  padding: 2rem 0;
`;

const DashboardContent = styled.div`
  max-width: 1400px;
  margin: 0 auto;
  padding: 0 2rem;
`;

const Header = styled(motion.div)`
  background: rgba(255, 255, 255, 0.95);
  backdrop-filter: blur(20px);
  border-radius: 24px;
  padding: 2.5rem;
  margin-bottom: 2rem;
  box-shadow: 0 25px 50px rgba(0, 0, 0, 0.1);
  border: 1px solid rgba(255, 255, 255, 0.2);
`;

const HeaderTop = styled.div`
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: 2rem;

  @media (max-width: 768px) {
    flex-direction: column;
    gap: 1rem;
  }
`;

const WelcomeSection = styled.div`
  flex: 1;
`;

const WelcomeTitle = styled.h1`
  color: #333;
  margin: 0 0 0.5rem 0;
  font-size: 2.5rem;
  font-weight: 700;
  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  background-clip: text;
`;

const WelcomeSubtitle = styled.p`
  color: #666;
  font-size: 1.2rem;
  margin: 0;
`;

/* Cohesive hero stat band — one row of 4 stats separated by hairline dividers,
   not 6 disconnected floating cards. Functionalist: every stat earns its place. */
const StatBand = styled(motion.div)`
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  background: #ffffff;
  border: 1px solid #edf0f5;
  border-radius: 16px;
  overflow: hidden;

  @media (max-width: 640px) {
    grid-template-columns: repeat(2, 1fr);
  }
`;

const StatItem = styled.div`
  padding: 1.5rem 1.25rem;
  border-right: 1px solid #edf0f5;
  display: flex;
  flex-direction: column;
  gap: 0.35rem;

  &:last-child { border-right: none; }

  @media (max-width: 640px) {
    &:nth-child(2n) { border-right: none; }
    &:nth-child(-n+2) { border-bottom: 1px solid #edf0f5; }
  }
`;

const StatLabel = styled.div`
  color: #8a93a6;
  font-size: 0.72rem;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.06em;
  display: flex;
  align-items: center;
  gap: 0.4rem;
`;

const StatValue = styled.div`
  font-size: 1.9rem;
  font-weight: 700;
  color: #1a202c;
  line-height: 1.1;
`;

const StatSub = styled.div`
  font-size: 0.78rem;
  color: #a0aec0;
  font-weight: 500;
`;

const ProgressSection = styled(motion.div)`
  background: rgba(255, 255, 255, 0.95);
  backdrop-filter: blur(20px);
  border-radius: 24px;
  padding: 2rem;
  margin-bottom: 2rem;
  box-shadow: 0 25px 50px rgba(0, 0, 0, 0.1);
  border: 1px solid rgba(255, 255, 255, 0.2);
`;

const SectionTitle = styled.h2`
  color: #333;
  margin: 0 0 1.5rem 0;
  font-size: 1.8rem;
  font-weight: 700;
  display: flex;
  align-items: center;
  gap: 0.75rem;
`;

const ExerciseGrid = styled.div`
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
  gap: 1.25rem;
  margin-top: 1rem;
  align-items: stretch; /* uniform card heights across the row */
`;

/* Uniform card: flex column so every card is the same height regardless of
   description length; the action row is pinned to the bottom via margin-top:auto. */
const ExerciseCard = styled(motion.div)`
  background: white;
  border-radius: 14px;
  padding: 1.25rem;
  box-shadow: 0 1px 3px rgba(0, 0, 0, 0.06);
  border: 1px solid #edf0f5;
  transition: transform 0.2s ease, box-shadow 0.2s ease;
  display: flex;
  flex-direction: column;

  &:hover {
    transform: translateY(-3px);
    box-shadow: 0 10px 24px rgba(0, 0, 0, 0.1);
  }

  @media (prefers-reduced-motion: reduce) {
    transition: none;
    &:hover { transform: none; }
  }
`;

const ExerciseHeader = styled.div`
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: 1rem;
`;

const ExerciseInfo = styled.div`
  flex: 1;
`;

const ExerciseTitle = styled.h3`
  color: #333;
  margin: 0 0 0.5rem 0;
  font-size: 1.2rem;
  font-weight: 600;
  line-height: 1.3;
`;

const ExerciseDifficulty = styled.span`
  background: ${props =>
    props.level === 'Beginner' ? 'linear-gradient(135deg, #28a745, #20c997)' :
    props.level === 'Intermediate' ? 'linear-gradient(135deg, #ffc107, #fd7e14)' :
    'linear-gradient(135deg, #dc3545, #fd7e14)'
  };
  color: white;
  padding: 0.3rem 0.8rem;
  border-radius: 12px;
  font-size: 0.75rem;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.5px;
`;

const ExerciseStatus = styled.div`
  display: flex;
  align-items: center;
  gap: 0.5rem;
  font-size: 0.9rem;
  font-weight: 600;
  color: ${props =>
    props.status === 'completed' ? '#28a745' :
    props.status === 'in_progress' ? '#fd7e14' :
    props.status === 'unlocked' ? '#667eea' : '#6c757d'
  };
`;

const ExerciseDescription = styled.p`
  color: #666;
  font-size: 0.875rem;
  line-height: 1.5;
  margin: 0 0 1rem 0;
  /* clamp to 2 lines so every card header block is the same height */
  display: -webkit-box;
  -webkit-line-clamp: 2;
  -webkit-box-orient: vertical;
  overflow: hidden;
  min-height: 2.6em;
`;

const ExerciseAction = styled(Link)`
  display: inline-flex;
  align-items: center;
  gap: 0.5rem;
  background: ${props =>
    props.status === 'completed' ? 'linear-gradient(135deg, #28a745, #20c997)' :
    props.status === 'in_progress' ? 'linear-gradient(135deg, #fd7e14, #e65100)' :
    'linear-gradient(135deg, #667eea, #764ba2)'
  };
  color: white;
  padding: 0.75rem 1.5rem;
  border-radius: 10px;
  text-decoration: none;
  font-weight: 600;
  font-size: 0.9rem;
  transition: all 0.3s ease;

  &:hover {
    transform: translateY(-1px);
    box-shadow: 0 6px 20px rgba(0, 0, 0, 0.15);
  }
`;

const LockedExerciseAction = styled.div`
  display: inline-flex;
  align-items: center;
  gap: 0.5rem;
  background: #6c757d;
  color: white;
  padding: 0.75rem 1.5rem;
  border-radius: 10px;
  font-weight: 600;
  font-size: 0.9rem;
  cursor: not-allowed;
`;

const WorkshopDashboard = () => {
  const { user } = useAuth();
  const { registerReconciler } = useWorkshopConfig();
  const [exercises, setExercises] = useState([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState(null);
  const [stats, setStats] = useState({
    completedExercises: 0,
    totalExercises: 0,
    completedObjectives: 0,
    totalObjectives: 0,
    totalTimeSeconds: 0
  });
  const mountedRef = useRef(false);
  const requestSequenceRef = useRef(0);

  const fetchExercises = useCallback(async (options = {}) => {
    const background = options === true || options?.background === true;
    const signal = options?.signal;
    const requestId = ++requestSequenceRef.current;
    setLoading(true);
    if (!background) setLoadError(null);
    try {
      const [challengeRes, timeRes] = await Promise.all([
        axios.get('/api/workshop/challenges', { signal }),
        axios.get('/api/workshop/time/summary', { signal }).catch(() => ({ data: { summary: {} } }))
      ]);
      const timeSummary = timeRes.data.summary || {};
      const visibleExercises = (challengeRes.data.challenges || []).filter(
        c => c.id !== 'ctf_prompt_injection_challenge' && c.challenge_key !== 'ctf_prompt_injection_challenge'
      ).map(c => {
        const summaryTime = timeSummary[c.workshopKey || c.id] ?? timeSummary[c.id];
        return {
          ...c,
          // /challenges is canonical. The legacy summary remains a compatibility
          // fallback and must never erase valid canonical time when it fails/returns 0.
          timeSpentSeconds: c.timeSpentSeconds ?? summaryTime ?? 0
        };
      });
      if (!mountedRef.current || signal?.aborted || requestId !== requestSequenceRef.current) return null;
      setExercises(visibleExercises);
      setLoadError(null);

      if (!background) {
        console.log(`[Dashboard] Loaded ${visibleExercises.length} visible exercises from admin settings`);
      }

      const completedExercises = visibleExercises.filter(c => c.status === 'completed').length;
      const totalObjectives = visibleExercises.reduce((sum, e) => sum + (e.objectiveCount || 0), 0);
      const completedObjectives = visibleExercises.reduce((sum, e) => sum + (e.completedObjectiveCount || 0), 0);
      const totalTimeSeconds = visibleExercises.reduce((sum, e) => sum + (e.timeSpentSeconds || 0), 0);
      setStats({
        completedExercises,
        totalExercises: visibleExercises.length,
        totalObjectives,
        completedObjectives,
        totalTimeSeconds
      });
      return visibleExercises;
    } catch (error) {
      if (!mountedRef.current || requestId !== requestSequenceRef.current) return null;
      setLoadError('Unable to load your dashboard. Please try again.');
      if (background) throw error;
      console.error('Failed to fetch visible exercises:', error);
      return null;
    } finally {
      if (mountedRef.current && requestId === requestSequenceRef.current) setLoading(false);
    }
  }, []);

  useEffect(() => {
    mountedRef.current = true;
    void fetchExercises();
    return () => {
      mountedRef.current = false;
      requestSequenceRef.current += 1;
    };
  }, [fetchExercises]);

  useEffect(() => registerReconciler(
    (_revision, { signal } = {}) => fetchExercises({ background: true, signal })
  ), [fetchExercises, registerReconciler]);

  // Handle empty state when no exercises are enabled by admin
  const renderEmptyState = () => (
    <ProgressSection
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
    >
      <div style={{ textAlign: 'center', padding: '4rem 2rem' }}>
        <FiShield size={64} style={{ color: '#667eea', marginBottom: '2rem' }} />
        <h3 style={{ color: '#333', fontSize: '1.8rem', marginBottom: '1rem' }}>
          Welcome to the Security Workshop
        </h3>
        <p style={{ color: '#666', fontSize: '1.2rem', lineHeight: 1.6, maxWidth: '600px', margin: '0 auto 2rem' }}>
          Your instructor hasn't enabled any exercises yet. Contact your instructor to enable tasks for this workshop session.
        </p>
        <button
          onClick={fetchExercises}
          style={{
            background: 'linear-gradient(135deg, #667eea, #764ba2)',
            color: 'white',
            padding: '1rem 2.5rem',
            border: 'none',
            borderRadius: '12px',
            fontSize: '1rem',
            fontWeight: '600',
            cursor: 'pointer',
            transition: 'all 0.3s ease'
          }}
        >
          Refresh Dashboard
        </button>
      </div>
    </ProgressSection>
  );

  // Get exercise icon
  const getExerciseIcon = (exerciseId) => {
    const iconMap = {
      'reflected_xss_llm': FiCode,
      'csrf_prompt_injection': FiRefreshCw,
      'direct_prompt_injection': FiShield,
      'indirect_prompt_injection': FiFileText,
      'ctf_prompt_injection_challenge': FiTarget,
      'sql_injection_workshop': FiDatabase,
      'nosql_injection_workshop': FiDatabase,
      'sensitive_info_disclosure': FiAlertTriangle,
      'excessive_agency': FiCpu,
      'mcp_server_rce': FiTerminal,
      'supply_chain_rce': FiPackage,
    };

    const IconComponent = iconMap[exerciseId] || FiShield;
    return <IconComponent size={24} />;
  };

  // The Overview intentionally offers one next step. The Exercise Library remains
  // the complete, instructor-controlled catalog and does not get a second source
  // of progress data from this selection.
  const recommendedExercise = exercises.find((exercise) => exercise.status === 'in_progress')
    || exercises.find((exercise) => exercise.status === 'unlocked')
    || exercises.find((exercise) => exercise.status === 'completed')
    || exercises[0];
  const readyExerciseCount = exercises.filter((exercise) => exercise.status !== 'locked').length;
  const lockedExerciseCount = exercises.length - readyExerciseCount;

  return (
    <DashboardContainer>
      <DashboardContent>
        <Header
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6 }}
        >
          <HeaderTop>
            <WelcomeSection>
              <WelcomeTitle>Student Dashboard</WelcomeTitle>
              <WelcomeSubtitle>
                {exercises.length > 0
                  ? `Welcome back, ${user?.username || 'Student'}. ${exercises.length} instructor-visible exercises are in your library: ${readyExerciseCount} ready to open, ${lockedExerciseCount} locked until objectives are enabled.`
                  : loading
                    ? 'Loading your workshop dashboard…'
                    : loadError
                      ? 'Your workshop dashboard could not be loaded.'
                      : 'Waiting for your instructor to enable exercises for this session.'
                }
              </WelcomeSubtitle>
            </WelcomeSection>
          </HeaderTop>

          {exercises.length > 0 && (() => {
            const pct = stats.totalObjectives > 0
              ? Math.round((stats.completedObjectives / stats.totalObjectives) * 100) : 0;
            return (
            <StatBand
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.15 }}
            >
              <StatItem>
                <StatLabel><FiCheckCircle size={13} color="#28a745" /> Visible Exercises</StatLabel>
                <StatValue>{stats.completedExercises}<span style={{ fontSize: '1rem', color: '#a0aec0', fontWeight: 500 }}> / {stats.totalExercises}</span></StatValue>
                <StatSub>completed</StatSub>
              </StatItem>

              <StatItem>
                <StatLabel><FiTarget size={13} color="#667eea" /> Objectives</StatLabel>
                <StatValue>{stats.completedObjectives}<span style={{ fontSize: '1rem', color: '#a0aec0', fontWeight: 500 }}> / {stats.totalObjectives}</span></StatValue>
                <StatSub>{stats.totalObjectives - stats.completedObjectives} remaining</StatSub>
              </StatItem>

              <StatItem>
                <StatLabel><FiBarChart size={13} color="#17a2b8" /> Completion</StatLabel>
                <StatValue>{pct}%</StatValue>
                <div style={{ background: '#edf0f5', borderRadius: '3px', height: '5px', overflow: 'hidden', marginTop: '0.15rem' }}>
                  <div style={{ width: `${pct}%`, height: '100%', background: pct === 100 ? 'linear-gradient(135deg, #28a745, #20c997)' : 'linear-gradient(135deg, #667eea, #764ba2)', transition: 'width 0.4s ease' }} />
                </div>
              </StatItem>

              <StatItem>
                <StatLabel><FiClock size={13} color="#e91e63" /> Time</StatLabel>
                <StatValue>{formatWorkshopTime(stats.totalTimeSeconds)}</StatValue>
                <StatSub>invested</StatSub>
              </StatItem>
            </StatBand>
            );
          })()}

        </Header>

        {loading && (
          <ProgressSection role="status" aria-live="polite">
            {exercises.length ? 'Refreshing dashboard…' : 'Loading your dashboard…'}
          </ProgressSection>
        )}
        {loadError && (
          <ProgressSection role="alert">
            <p>{loadError}</p>
            <button type="button" disabled={loading} onClick={() => fetchExercises()}>
              Retry loading dashboard
            </button>
          </ProgressSection>
        )}
        {exercises.length === 0 ? (!loading && !loadError ? renderEmptyState() : null) : (
          <ProgressSection
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.3 }}
          >
            <SectionTitle><FiPlay /> Continue learning</SectionTitle>

            <ExerciseGrid>
              {recommendedExercise && (
                <ExerciseCard
                  key={recommendedExercise.id}
                  data-testid="dashboard-continue-learning"
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: 0.1 }}
                >
                  <ExerciseHeader>
                    <ExerciseInfo>
                      <ExerciseTitle>{recommendedExercise.title}</ExerciseTitle>
                      <ExerciseDifficulty level={recommendedExercise.difficulty}>
                        {recommendedExercise.difficulty}
                      </ExerciseDifficulty>
                    </ExerciseInfo>
                    <ExerciseStatus status={recommendedExercise.status}>
                      {recommendedExercise.status === 'completed' && <FiCheckCircle />}
                      {recommendedExercise.status === 'in_progress' && <FiPlay />}
                      {recommendedExercise.status === 'unlocked' && <FiUnlock />}
                      {recommendedExercise.status === 'locked' && <FiLock />}
                      {recommendedExercise.status === 'completed' ? `Completed ${recommendedExercise.completedObjectiveCount}/${recommendedExercise.objectiveCount}` :
                       recommendedExercise.status === 'in_progress' ? `In Progress ${recommendedExercise.completedObjectiveCount}/${recommendedExercise.objectiveCount}` :
                       recommendedExercise.status === 'unlocked' ? `Not Started 0/${recommendedExercise.objectiveCount}` : 'Locked'}
                    </ExerciseStatus>
                  </ExerciseHeader>

                  <ExerciseDescription>
                    {recommendedExercise.description}
                  </ExerciseDescription>

                  <div style={{ margin: '0.5rem 0 0.75rem' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '0.78rem', color: '#666', marginBottom: '0.35rem' }}>
                      <span style={{ display: 'flex', alignItems: 'center', gap: '0.3rem' }}>
                        Objectives
                        {recommendedExercise.timeSpentSeconds > 0 && (
                          <span style={{ display: 'inline-flex', alignItems: 'center', gap: '0.2rem', color: '#a0aec0', marginLeft: '0.4rem' }}>
                            <FiClock size={11} /> {formatWorkshopTime(recommendedExercise.timeSpentSeconds)}
                          </span>
                        )}
                      </span>
                      <span
                        style={{ fontWeight: 600, color: recommendedExercise.objectiveCount > 0 && recommendedExercise.completedObjectiveCount === recommendedExercise.objectiveCount ? '#28a745' : '#667eea' }}
                      >
                        {recommendedExercise.completedObjectiveCount || 0}/{recommendedExercise.objectiveCount || 0}
                      </span>
                    </div>
                    <div style={{ background: '#edf0f5', borderRadius: '4px', height: '6px', overflow: 'hidden' }}>
                      <div style={{
                        width: `${recommendedExercise.objectiveCount > 0 ? Math.round((recommendedExercise.completedObjectiveCount / recommendedExercise.objectiveCount) * 100) : 0}%`,
                        height: '100%',
                        background: recommendedExercise.objectiveCount > 0 && recommendedExercise.completedObjectiveCount === recommendedExercise.objectiveCount
                          ? 'linear-gradient(135deg, #28a745, #20c997)'
                          : 'linear-gradient(135deg, #667eea, #764ba2)',
                        transition: 'width 0.4s ease',
                        borderRadius: '4px'
                      }} />
                    </div>
                  </div>

                  <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center', flexWrap: 'wrap', marginTop: 'auto' }}>
                    {recommendedExercise.status === 'locked' ? (
                      <LockedExerciseAction aria-disabled="true">
                        {getExerciseIcon(recommendedExercise.id)} Locked
                      </LockedExerciseAction>
                    ) : <ExerciseAction
                      to={recommendedExercise.route}
                      status={recommendedExercise.status}
                      onClick={() => {
                        setTimeout(() => {
                          window.scrollTo({ top: 0, behavior: 'smooth' });
                        }, 100);
                      }}
                    >
                      {getExerciseIcon(recommendedExercise.id)}
                      {recommendedExercise.status === 'completed' ? 'Review Exercise' :
                       recommendedExercise.status === 'in_progress' ? 'Continue Exercise' : 'Start Exercise'}
                    </ExerciseAction>}
                  </div>
                </ExerciseCard>
              )}
            </ExerciseGrid>

            <div style={{
              display: 'flex',
              justifyContent: 'center',
              gap: '1rem',
              marginTop: '2rem',
              flexWrap: 'wrap'
            }}>
              <Link
                to="/workshop/challenges"
                onClick={() => {
                  setTimeout(() => {
                    window.scrollTo({ top: 0, behavior: 'smooth' });
                  }, 100);
                }}
                style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '0.5rem',
                  background: 'linear-gradient(135deg, #28a745, #20c997)',
                  color: 'white',
                  padding: '1rem 2rem',
                  borderRadius: '12px',
                  textDecoration: 'none',
                  fontWeight: '600',
                  transition: 'all 0.3s ease'
                }}
              >
                <FiTarget />
                Browse Exercise Library
              </Link>
            </div>
          </ProgressSection>
        )}
      </DashboardContent>
    </DashboardContainer>
  );
};

export default WorkshopDashboard;
