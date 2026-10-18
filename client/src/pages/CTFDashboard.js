import React, { useState, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';
import useCtfRecovery from '../services/useCtfRecovery';
import { isCtfRecoveryCancelled } from '../services/ctfRecovery';
import CtfRecoveryNotice from '../components/CtfRecoveryNotice';
import { useAuth } from '../context/AuthContext';
import {
  FiAward,
  FiTarget,
  FiClock,
  FiPlay,
  FiStar,
  FiShield,
  FiZap,
  FiActivity,
  FiBarChart2,
  FiChevronRight,
  FiLock,
  FiUnlock,
  FiAlertTriangle,
  FiRefreshCw,
  FiUsers,
  FiTrendingUp,
  FiCheckCircle,
  FiFlag,
  FiMessageSquare,
} from 'react-icons/fi';
import { getObjective, HOW_YOU_WIN } from './ctfObjectives';
import { workshopTokens } from '../components/workshop/experience.mjs';

const DIFFICULTY_COLORS = {
  trivial: { bg: 'rgba(34, 197, 94, 0.15)', color: '#22c55e', border: 'rgba(34, 197, 94, 0.35)' },
  beginner: { bg: 'rgba(34, 197, 94, 0.15)', color: '#22c55e', border: 'rgba(34, 197, 94, 0.35)' },
  easy: { bg: 'rgba(59, 130, 246, 0.15)', color: '#3b82f6', border: 'rgba(59, 130, 246, 0.35)' },
  medium: { bg: 'rgba(234, 179, 8, 0.15)', color: '#eab308', border: 'rgba(234, 179, 8, 0.35)' },
  hard: { bg: 'rgba(249, 115, 22, 0.15)', color: '#f97316', border: 'rgba(249, 115, 22, 0.35)' },
  expert: { bg: 'rgba(239, 68, 68, 0.15)', color: '#ef4444', border: 'rgba(239, 68, 68, 0.35)' },
  legendary: { bg: 'rgba(168, 85, 247, 0.15)', color: '#a855f7', border: 'rgba(168, 85, 247, 0.35)' },
};

const DEFAULT_DESCRIPTION =
  'Master prompt injection through progressively challenging AI guardians. Extract hidden secrets, adapt to defense layers, and climb the leaderboard.';

const getAuthHeaders = () => {
  const token = localStorage.getItem('token');
  return token ? { Authorization: `Bearer ${token}` } : {};
};

const formatDuration = (ms) => {
  if (!ms || ms <= 0) return '—';
  const totalSeconds = Math.floor(ms / 1000);
  const minutes = Math.floor(totalSeconds / 60);
  const seconds = totalSeconds % 60;
  if (minutes >= 60) {
    const hours = Math.floor(minutes / 60);
    const mins = minutes % 60;
    return `${hours}h ${mins}m`;
  }
  if (minutes > 0) return `${minutes}m ${seconds}s`;
  return `${seconds}s`;
};

const getDifficultyStyle = (level) => {
  const key = (level || 'medium').toLowerCase();
  return DIFFICULTY_COLORS[key] || DIFFICULTY_COLORS.medium;
};

const CTFDashboard = () => {
  const navigate = useNavigate();
  const { user } = useAuth();
  const token = localStorage.getItem('token');
  const ownerRef = useRef(null);
  if (!ownerRef.current || ownerRef.current.token !== token || ownerRef.current.userId !== user?.id) {
    ownerRef.current = { token, userId: user?.id, revision: Symbol('ctf-session') };
  }
  const owner = ownerRef.current;
  const mounted = useRef(false);
  const current = () => mounted.current && ownerRef.current === owner && localStorage.getItem('token') === owner.token;
  const recovery = useCtfRecovery(owner.revision);

  const [ctfConfig, setCtfConfig] = useState({});
  const [stages, setStages] = useState([]);
  const [userStatus, setUserStatus] = useState({ registered: false });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [registering, setRegistering] = useState(false);
  const [registerError, setRegisterError] = useState(null);
  const [displayName, setDisplayName] = useState(user?.username || '');
  const [startingStageId, setStartingStageId] = useState(null);

  const loadCTFData = async () => {
    if (!current()) return;
    setError(null);
    try {
      setLoading(true);
      const headers = getAuthHeaders();

      const [configResponse, stagesResponse, statusResponse] = await Promise.all([
        axios.get('/api/ctf/config', { headers }),
        axios.get('/api/ctf/stages', { headers }),
        axios.get('/api/ctf/status', { headers }).catch((err) => {
          if (err.response?.status === 401) {
            return { data: { registered: false } };
          }
          throw err;
        }),
      ]);

      if (!current()) return;
      setCtfConfig(configResponse.data.config || {});
      setStages(stagesResponse.data.stages || []);
      setUserStatus(statusResponse.data || { registered: false });
    } catch (err) {
      if (!current()) return;
      console.error('Error loading CTF data:', err);
      const message =
        err.response?.data?.error ||
        (err.response?.status === 403
          ? 'CTF is not available at this time'
          : 'Failed to load CTF data. Please try again.');
      setError(message);
    } finally {
      if (current()) setLoading(false);
    }
  };

  useEffect(() => {
    mounted.current = true;
    setCtfConfig({}); setStages([]); setUserStatus({ registered: false });
    setDisplayName(user?.username || ''); setError(null); setRegisterError(null);
    setRegistering(false); setStartingStageId(null); setLoading(true);
    loadCTFData();
    return () => { mounted.current = false; };
  }, [owner]);

  const handleRegister = async (e) => {
    e.preventDefault();
    if (!current()) return;
    setRegisterError(null);

    try {
      setRegistering(true);
      await recovery.request('post',
        '/api/ctf/register',
        { displayName: displayName.trim() || user?.username || null },
        { headers: getAuthHeaders() }
      );
      if (!current()) return;
      await loadCTFData();
    } catch (err) {
      if (!current() || isCtfRecoveryCancelled(err)) return;
      console.error('Error registering for CTF:', err);
      setRegisterError(err.response?.data?.error || 'Failed to register for CTF');
    } finally {
      if (current()) setRegistering(false);
    }
  };

  const getStageProgress = (stageId) => {
    if (!userStatus.progress) return null;
    return userStatus.progress.find((p) => p.stage_id === stageId) || null;
  };

  const getStageStatus = (stage) => {
    const progress = getStageProgress(stage.id);
    return progress?.status || 'not_started';
  };

  const isStageUnlocked = (stage, index) => {
    if (!userStatus.registered) return false;
    if (index === 0) return true;

    const prevStage = stages[index - 1];
    if (!prevStage) return false;

    const prevProgress = getStageProgress(prevStage.id);
    return prevProgress?.status === 'completed';
  };

  const getProgressStats = () => {
    const total = stages.length;
    if (!userStatus.progress || total === 0) {
      return { completed: 0, total, percentage: 0 };
    }
    const completed = userStatus.progress.filter((p) => p.status === 'completed').length;
    return {
      completed,
      total,
      percentage: Math.round((completed / total) * 100),
    };
  };

  const getBestTime = () => {
    if (!userStatus.progress) return null;
    const completedTimes = userStatus.progress
      .filter((p) => p.status === 'completed' && p.completion_time > 0)
      .map((p) => p.completion_time);
    if (completedTimes.length === 0) return null;
    return Math.min(...completedTimes);
  };

  const getPlayerStats = () => {
    const entry = userStatus.leaderboardEntry;
    const totalAttempts =
      entry?.total_attempts ??
      (userStatus.progress || []).reduce((sum, p) => sum + (p.attempts_count || 0), 0);
    const successRate = entry?.success_rate ?? 0;
    const bestTime = getBestTime();
    const rank = entry?.rank_position ?? null;
    const totalScore = entry?.total_score ?? 0;

    return { totalAttempts, successRate, bestTime, rank, totalScore };
  };

  const handleStageClick = (stage, index) => {
    if (!current() || !isStageUnlocked(stage, index)) return;
    setStartingStageId(stage.id);
    // Challenge initialization owns the authenticated start and current config read.
    if (!current()) return;
    navigate('/ctf/challenge', {
      state: { stage, participantId: userStatus.participant?.id },
    });
  };

  const progressStats = getProgressStats();
  const playerStats = getPlayerStats();
  const registrationOpen = ctfConfig.ctf_registration_open === 'true';
  const registrationAvailable = ctfConfig.registration_available !== false;
  const leaderboardVisible = ctfConfig.student_leaderboard_visible === 'true';

  if (loading) {
    return (
      <div style={styles.page}>
        <div style={styles.wrapper}>
          <CtfRecoveryNotice notices={recovery.notices} />
          <div style={styles.loadingContainer}>
            <div style={styles.loadingSpinner}>
              <FiAward size={40} />
            </div>
            <p style={styles.loadingText}>Loading CTF dashboard…</p>
          </div>
        </div>
      </div>
    );
  }

  if (error && !userStatus.registered && stages.length === 0) {
    return (
      <div style={styles.page}>
        <div style={styles.wrapper}>
          <CtfRecoveryNotice notices={recovery.notices} />
          <div style={styles.errorCard}>
            <FiAlertTriangle size={32} style={{ color: '#f87171', marginBottom: '1rem' }} />
            <h2 style={styles.errorTitle}>Unable to Load CTF</h2>
            <p style={styles.errorMessage}>{error}</p>
            <button type="button" style={styles.retryButton} onClick={loadCTFData}>
              <FiRefreshCw size={16} />
              Try Again
            </button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div style={styles.page}>
      <div style={styles.wrapper}>
          <CtfRecoveryNotice notices={recovery.notices} />
        {/* Header */}
        <header style={styles.header}>
          <div style={styles.headerTop}>
            <div style={styles.headerBadge}>
              <FiShield size={18} />
              <span>Capture The Flag</span>
            </div>
            {userStatus.registered && leaderboardVisible && (
              <div style={styles.headerMeta}>
                <span style={styles.metaPill}>
                  <FiAward size={14} />
                  Rank #{playerStats.rank ?? '—'}
                </span>
                <span style={styles.metaPillGold}>
                  <FiStar size={14} />
                  {playerStats.totalScore} pts
                </span>
              </div>
            )}
          </div>

          <h1 style={styles.title}>Prompt Injection CTF</h1>
          <p style={styles.subtitle}>{DEFAULT_DESCRIPTION}</p>

          <div style={styles.howToPlay}>
            <div style={styles.howToPlayTitle}>
              <FiFlag size={15} />
              How to play
            </div>
            <div style={styles.howToPlaySteps}>
              <span style={styles.howToPlayStep}>
                <FiMessageSquare size={13} style={{ color: '#818cf8' }} />
                Each level is a chat with an AI guardian hiding a secret passphrase.
              </span>
              <span style={styles.howToPlayStep}>
                <FiTarget size={13} style={{ color: '#818cf8' }} />
                Use prompt-injection to make it reveal that secret in a reply.
              </span>
              <span style={styles.howToPlayStep}>
                <FiCheckCircle size={13} style={{ color: '#4ade80' }} />
                {HOW_YOU_WIN}
              </span>
              <span style={styles.howToPlayStep}>
                <FiAlertTriangle size={13} style={{ color: '#fbbf24' }} />
                Hints are optional and cost points. Later levels add defenses you must work around.
              </span>
            </div>
          </div>

          {userStatus.registered && (
            <div style={styles.progressSection}>
              <div style={styles.progressLabels}>
                <span style={styles.progressLabel}>
                  Overall Progress — {progressStats.completed} / {progressStats.total} stages
                </span>
                <span style={styles.progressPercent}>{progressStats.percentage}%</span>
              </div>
              <div style={styles.progressTrack}>
                <div
                  style={{
                    ...styles.progressFill,
                    width: `${progressStats.percentage}%`,
                  }}
                />
              </div>
            </div>
          )}
        </header>

        {error && (
          <div style={styles.inlineError}>
            <FiAlertTriangle size={16} />
            <span>{error}</span>
            <button type="button" style={styles.inlineErrorDismiss} onClick={() => setError(null)}>
              Dismiss
            </button>
          </div>
        )}

        {/* Registration */}
        {!userStatus.registered ? (
          <div style={styles.registrationCard}>
            <div style={styles.registrationIcon}>
              <FiUsers size={28} />
            </div>
            <h2 style={styles.registrationTitle}>Join the CTF</h2>
            <p style={styles.registrationDesc}>
              Register to unlock the stage grid and compete on the leaderboard.
              {!registrationOpen && ' Registration is currently closed by the administrator.'}
            </p>

            {registerError && (
              <div style={styles.registerError}>
                <FiAlertTriangle size={14} />
                {registerError}
              </div>
            )}

            <form onSubmit={handleRegister} style={styles.registrationForm}>
              <label style={styles.inputLabel} htmlFor="displayName">
                Your CTF Name
              </label>
              <input
                id="displayName"
                type="text"
                value={displayName}
                onChange={(e) => setDisplayName(e.target.value)}
                placeholder="Enter your CTF display name…"
                maxLength={50}
                style={styles.input}
                disabled={!registrationOpen || !registrationAvailable}
              />

              <button
                type="submit"
                style={{
                  ...styles.primaryButton,
                  ...((!registrationOpen || !registrationAvailable || registering) && styles.buttonDisabled),
                }}
                disabled={!registrationOpen || !registrationAvailable || registering}
              >
                {registering ? (
                  <>
                    <FiClock size={18} />
                    Registering…
                  </>
                ) : (
                  <>
                    <FiPlay size={18} />
                    Join CTF
                  </>
                )}
              </button>
            </form>

            <p style={styles.participantCount}>
              {ctfConfig.current_participants ?? 0} active participants
            </p>
          </div>
        ) : (
          <>
            {/* Stats Row */}
            <div style={styles.statsRow}>
              <div style={styles.statCard}>
                <div style={{ ...styles.statIcon, background: 'rgba(59, 130, 246, 0.15)', color: '#60a5fa' }}>
                  <FiActivity size={20} />
                </div>
                <div style={styles.statValue}>{playerStats.totalAttempts}</div>
                <div style={styles.statLabel}>Total Attempts</div>
              </div>

              <div style={styles.statCard}>
                <div style={{ ...styles.statIcon, background: 'rgba(34, 197, 94, 0.15)', color: '#4ade80' }}>
                  <FiTrendingUp size={20} />
                </div>
                <div style={styles.statValue}>
                  {typeof playerStats.successRate === 'number'
                    ? `${Math.round(playerStats.successRate)}%`
                    : '—'}
                </div>
                <div style={styles.statLabel}>Success Rate</div>
              </div>

              {leaderboardVisible && (
                <div style={styles.statCard}>
                  <div style={{ ...styles.statIcon, background: 'rgba(234, 179, 8, 0.15)', color: '#facc15' }}>
                    <FiClock size={20} />
                  </div>
                  <div style={styles.statValue}>{formatDuration(playerStats.bestTime)}</div>
                  <div style={styles.statLabel}>Best Time</div>
                </div>
              )}

              {leaderboardVisible && (
                <div style={styles.statCard}>
                  <div style={{ ...styles.statIcon, background: 'rgba(168, 85, 247, 0.15)', color: '#c084fc' }}>
                    <FiBarChart2 size={20} />
                  </div>
                  <div style={styles.statValue}>#{playerStats.rank ?? '—'}</div>
                  <div style={styles.statLabel}>Current Rank</div>
                </div>
              )}
            </div>

            {/* Level Grid */}
            <section style={styles.levelSection}>
              <div style={styles.sectionHeader}>
                <h2 style={styles.sectionTitle}>
                  <FiTarget size={22} />
                  Challenge Stages
                </h2>
                <span style={styles.sectionCount}>{stages.length} levels</span>
              </div>

              <div style={styles.levelGrid}>
                {stages.map((stage, index) => {
                  const status = getStageStatus(stage);
                  const unlocked = isStageUnlocked(stage, index);
                  const diffStyle = getDifficultyStyle(stage.difficulty_level);
                  const isStarting = startingStageId === stage.id;
                  const hasAdaptive = stage.adaptive_mode && stage.adaptive_mode !== 'none';
                  const objective = getObjective(stage.stage_number);

                  return (
                    <div
                      key={stage.id}
                      role="button"
                      tabIndex={unlocked ? 0 : -1}
                      style={{
                        ...styles.levelCard,
                        ...(status === 'completed' && styles.levelCardCompleted),
                        ...(status === 'in_progress' && styles.levelCardInProgress),
                        ...(!unlocked && styles.levelCardLocked),
                        ...(unlocked && styles.levelCardClickable),
                      }}
                      onClick={() => unlocked && !isStarting && handleStageClick(stage, index)}
                      onKeyDown={(e) => {
                        if (unlocked && (e.key === 'Enter' || e.key === ' ')) {
                          e.preventDefault();
                          if (!isStarting) handleStageClick(stage, index);
                        }
                      }}
                    >
                      <div style={styles.levelCardTop}>
                        <div
                          style={{
                            ...styles.stageNumber,
                            ...(status === 'completed' && { background: '#22c55e' }),
                            ...(status === 'in_progress' && { background: '#f59e0b' }),
                            ...(!unlocked && { background: '#64748b' }),
                          }}
                        >
                          {status === 'completed' ? <FiStar size={14} /> : stage.stage_number}
                        </div>

                        <div style={styles.levelCardBadges}>
                          {hasAdaptive && (
                            <span style={styles.adaptiveBadge} title={`Adaptive: ${stage.adaptive_mode}`}>
                              <FiZap size={12} />
                              {stage.adaptive_mode}
                            </span>
                          )}
                          {unlocked ? (
                            <FiUnlock size={16} style={{ color: '#4ade80' }} />
                          ) : (
                            <FiLock size={16} style={{ color: '#94a3b8' }} />
                          )}
                        </div>
                      </div>

                      <h3 style={styles.levelName}>{stage.stage_name}</h3>

                      <div style={styles.levelMeta}>
                        <span
                          style={{
                            ...styles.difficultyBadge,
                            background: diffStyle.bg,
                            color: diffStyle.color,
                            border: `1px solid ${diffStyle.border}`,
                          }}
                        >
                          {stage.difficulty_level}
                        </span>
                        <span style={styles.completionCount}>
                          <FiUsers size={12} />
                          {stage.completion_count ?? 0} completed
                        </span>
                      </div>

                      {stage.stage_description && (
                        <p style={styles.levelDescription}>{stage.stage_description}</p>
                      )}

                      {objective?.goal && (
                        <p style={styles.levelGoal}>
                          <FiFlag size={12} style={{ color: '#818cf8', flexShrink: 0, marginTop: '2px' }} />
                          <span><strong style={{ color: '#c7d2fe' }}>Goal:</strong> {objective.goal}</span>
                        </p>
                      )}

                      <div style={styles.levelFooter}>
                        {isStarting ? (
                          <span style={styles.levelAction}>Starting…</span>
                        ) : !unlocked ? (
                          <span style={styles.levelActionLocked}>
                            <FiLock size={14} />
                            Complete previous stage
                          </span>
                        ) : status === 'completed' ? (
                          <span style={styles.levelActionCompleted}>
                            <FiCheckCircle size={14} />
                            Completed — replay
                          </span>
                        ) : status === 'in_progress' ? (
                          <span style={styles.levelActionContinue}>
                            <FiPlay size={14} />
                            Continue challenge
                          </span>
                        ) : (
                          <span style={styles.levelActionStart}>
                            <FiPlay size={14} />
                            Start challenge
                          </span>
                        )}
                        {unlocked && <FiChevronRight size={16} style={{ color: '#64748b' }} />}
                      </div>
                    </div>
                  );
                })}
              </div>

              {stages.length === 0 && (
                <div style={styles.emptyState}>
                  <FiTarget size={32} style={{ color: '#64748b', marginBottom: '0.75rem' }} />
                  <p>No stages are available yet.</p>
                </div>
              )}
            </section>

            {/* Leaderboard Link */}
            {leaderboardVisible && (
            <div style={styles.leaderboardLinkWrapper}>
              <button
                type="button"
                style={styles.leaderboardLink}
                onClick={() => navigate('/ctf/leaderboard')}
              >
                <div style={styles.leaderboardLinkContent}>
                  <FiAward size={22} style={{ color: '#fbbf24' }} />
                  <div>
                    <div style={styles.leaderboardLinkTitle}>View Leaderboard</div>
                    <div style={styles.leaderboardLinkDesc}>
                      See rankings, completion times, and top performers
                    </div>
                  </div>
                </div>
                <FiChevronRight size={20} />
              </button>
            </div>
            )}
          </>
        )}
      </div>
    </div>
  );
};

const styles = {
  page: {
    minHeight: '100vh',
    background: workshopTokens.primaryGradient,
    padding: '2rem 0 4rem',
    color: workshopTokens.text,
    fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
  },
  wrapper: {
    maxWidth: '1200px',
    margin: '0 auto',
    padding: '0 1.5rem',
  },
  loadingContainer: {
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'center',
    justifyContent: 'center',
    minHeight: '60vh',
    gap: '1rem',
  },
  loadingSpinner: {
    width: '72px',
    height: '72px',
    borderRadius: '50%',
    background: 'rgba(251, 191, 36, 0.12)',
    border: '2px solid rgba(251, 191, 36, 0.3)',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    color: '#fbbf24',
    animation: 'none',
  },
  loadingText: {
    fontSize: '1.1rem',
    color: '#94a3b8',
    margin: 0,
  },
  errorCard: {
    background: workshopTokens.surface,
    border: `2px solid ${workshopTokens.danger}`,
    borderRadius: '16px',
    padding: '2.5rem',
    textAlign: 'center',
    maxWidth: '480px',
    margin: '4rem auto',
  },
  errorTitle: {
    fontSize: '1.5rem',
    fontWeight: 700,
    margin: '0 0 0.75rem',
    color: workshopTokens.text,
  },
  errorMessage: {
    color: workshopTokens.mutedText,
    margin: '0 0 1.5rem',
    lineHeight: 1.6,
  },
  retryButton: {
    display: 'inline-flex',
    alignItems: 'center',
    gap: '0.5rem',
    background: 'rgba(59, 130, 246, 0.15)',
    border: '1px solid rgba(59, 130, 246, 0.4)',
    color: '#60a5fa',
    padding: '0.65rem 1.25rem',
    borderRadius: '10px',
    fontWeight: 600,
    cursor: 'pointer',
    fontSize: '0.95rem',
  },
  header: {
    marginBottom: '2rem',
  },
  headerTop: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    flexWrap: 'wrap',
    gap: '1rem',
    marginBottom: '1.25rem',
  },
  headerBadge: {
    display: 'inline-flex',
    alignItems: 'center',
    gap: '0.5rem',
    background: 'rgba(99, 102, 241, 0.15)',
    border: '1px solid rgba(99, 102, 241, 0.35)',
    color: '#a5b4fc',
    padding: '0.4rem 0.9rem',
    borderRadius: '999px',
    fontSize: '0.85rem',
    fontWeight: 600,
  },
  headerMeta: {
    display: 'flex',
    gap: '0.75rem',
    flexWrap: 'wrap',
  },
  metaPill: {
    display: 'inline-flex',
    alignItems: 'center',
    gap: '0.4rem',
    background: 'rgba(30, 41, 59, 0.7)',
    border: '1px solid rgba(148, 163, 184, 0.2)',
    padding: '0.4rem 0.85rem',
    borderRadius: '999px',
    fontSize: '0.85rem',
    fontWeight: 600,
    color: '#cbd5e1',
  },
  metaPillGold: {
    display: 'inline-flex',
    alignItems: 'center',
    gap: '0.4rem',
    background: 'rgba(251, 191, 36, 0.12)',
    border: '1px solid rgba(251, 191, 36, 0.35)',
    padding: '0.4rem 0.85rem',
    borderRadius: '999px',
    fontSize: '0.85rem',
    fontWeight: 600,
    color: '#fbbf24',
  },
  title: {
    fontSize: 'clamp(2rem, 5vw, 2.75rem)',
    fontWeight: 800,
    margin: '0 0 0.75rem',
    color: '#fff',
    letterSpacing: '-0.02em',
  },
  subtitle: {
    fontSize: '1.05rem',
    color: '#94a3b8',
    lineHeight: 1.7,
    margin: '0 0 1.25rem',
    maxWidth: '720px',
  },
  howToPlay: {
    background: 'rgba(99, 102, 241, 0.08)',
    border: '1px solid rgba(99, 102, 241, 0.25)',
    borderRadius: '12px',
    padding: '1rem 1.25rem',
    margin: '0 0 1.5rem',
    maxWidth: '760px',
  },
  howToPlayTitle: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.5rem',
    fontSize: '0.85rem',
    fontWeight: 700,
    color: '#c7d2fe',
    textTransform: 'uppercase',
    letterSpacing: '0.04em',
    marginBottom: '0.75rem',
  },
  howToPlaySteps: {
    display: 'flex',
    flexDirection: 'column',
    gap: '0.5rem',
  },
  howToPlayStep: {
    display: 'flex',
    alignItems: 'flex-start',
    gap: '0.5rem',
    fontSize: '0.86rem',
    color: '#cbd5e1',
    lineHeight: 1.5,
  },
  progressSection: {
    background: workshopTokens.surface,
    border: `2px solid ${workshopTokens.border}`,
    borderRadius: '14px',
    padding: '1.25rem 1.5rem',
  },
  progressLabels: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: '0.65rem',
    gap: '1rem',
    flexWrap: 'wrap',
  },
  progressLabel: {
    fontSize: '0.9rem',
    color: workshopTokens.text,
    fontWeight: 500,
  },
  progressPercent: {
    fontSize: '0.9rem',
    fontWeight: 700,
    color: '#fbbf24',
  },
  progressTrack: {
    height: '8px',
    background: workshopTokens.border,
    borderRadius: '999px',
    overflow: 'hidden',
  },
  progressFill: {
    height: '100%',
    background: workshopTokens.primaryGradient,
    borderRadius: '999px',
    transition: 'width 0.4s ease',
  },
  inlineError: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.75rem',
    background: 'rgba(239, 68, 68, 0.1)',
    border: '1px solid rgba(239, 68, 68, 0.3)',
    borderRadius: '10px',
    padding: '0.75rem 1rem',
    marginBottom: '1.5rem',
    color: '#fca5a5',
    fontSize: '0.9rem',
  },
  inlineErrorDismiss: {
    marginLeft: 'auto',
    background: 'transparent',
    border: 'none',
    color: '#fca5a5',
    cursor: 'pointer',
    fontSize: '0.85rem',
    fontWeight: 600,
    padding: '0.25rem 0.5rem',
  },
  registrationCard: {
    background: workshopTokens.surface,
    border: `2px solid ${workshopTokens.border}`,
    borderRadius: '20px',
    padding: '2.5rem',
    maxWidth: '520px',
    margin: '0 auto',
    textAlign: 'center',
    backdropFilter: 'blur(12px)',
  },
  registrationIcon: {
    width: '64px',
    height: '64px',
    borderRadius: '50%',
    background: 'rgba(99, 102, 241, 0.15)',
    border: '1px solid rgba(99, 102, 241, 0.3)',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    margin: '0 auto 1.25rem',
    color: '#818cf8',
  },
  registrationTitle: {
    fontSize: '1.75rem',
    fontWeight: 700,
    margin: '0 0 0.75rem',
    color: workshopTokens.text,
  },
  registrationDesc: {
    color: '#94a3b8',
    lineHeight: 1.6,
    margin: '0 0 1.5rem',
    fontSize: '0.95rem',
  },
  registerError: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    gap: '0.5rem',
    background: 'rgba(239, 68, 68, 0.1)',
    border: '1px solid rgba(239, 68, 68, 0.25)',
    borderRadius: '8px',
    padding: '0.65rem 1rem',
    marginBottom: '1rem',
    color: '#fca5a5',
    fontSize: '0.875rem',
  },
  registrationForm: {
    textAlign: 'left',
  },
  inputLabel: {
    display: 'block',
    fontSize: '0.875rem',
    fontWeight: 600,
    color: workshopTokens.text,
    marginBottom: '0.5rem',
  },
  optional: {
    fontWeight: 400,
    color: '#64748b',
  },
  input: {
    width: '100%',
    padding: '0.75rem 1rem',
    background: workshopTokens.surface,
    border: `1px solid ${workshopTokens.controlBorder}`,
    borderRadius: workshopTokens.controlRadius,
    color: workshopTokens.text,
    fontSize: '1rem',
    marginBottom: '1.25rem',
    boxSizing: 'border-box',
    outline: 'none',
  },
  primaryButton: {
    width: '100%',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    gap: '0.5rem',
    background: workshopTokens.primaryGradient,
    border: 'none',
    borderRadius: '12px',
    padding: '0.9rem 1.5rem',
    color: '#fff',
    fontSize: '1rem',
    fontWeight: 600,
    cursor: 'pointer',
  },
  buttonDisabled: {
    opacity: 0.55,
    cursor: 'not-allowed',
  },
  participantCount: {
    marginTop: '1.25rem',
    fontSize: '0.85rem',
    color: '#64748b',
  },
  statsRow: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))',
    gap: '1rem',
    marginBottom: '2rem',
  },
  statCard: {
    background: workshopTokens.surface,
    border: `2px solid ${workshopTokens.border}`,
    borderRadius: '14px',
    padding: '1.25rem',
    textAlign: 'center',
  },
  statIcon: {
    width: '44px',
    height: '44px',
    borderRadius: '12px',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    margin: '0 auto 0.75rem',
  },
  statValue: {
    fontSize: '1.75rem',
    fontWeight: 700,
    color: workshopTokens.text,
    marginBottom: '0.25rem',
  },
  statLabel: {
    fontSize: '0.8rem',
    color: '#64748b',
    fontWeight: 500,
    textTransform: 'uppercase',
    letterSpacing: '0.04em',
  },
  levelSection: {
    marginBottom: '2rem',
  },
  sectionHeader: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    marginBottom: '1.25rem',
    flexWrap: 'wrap',
    gap: '0.75rem',
  },
  sectionTitle: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.6rem',
    fontSize: '1.35rem',
    fontWeight: 700,
    margin: 0,
    color: workshopTokens.text,
  },
  sectionCount: {
    fontSize: '0.85rem',
    color: '#64748b',
    fontWeight: 500,
  },
  levelGrid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))',
    gap: '1.25rem',
  },
  levelCard: {
    background: workshopTokens.surface,
    border: `2px solid ${workshopTokens.border}`,
    borderRadius: '16px',
    padding: '1.35rem',
    transition: 'transform 0.2s ease, box-shadow 0.2s ease, border-color 0.2s ease',
    outline: 'none',
  },
  levelCardClickable: {
    cursor: 'pointer',
  },
  levelCardCompleted: {
    borderColor: 'rgba(34, 197, 94, 0.35)',
  },
  levelCardInProgress: {
    borderColor: 'rgba(245, 158, 11, 0.4)',
  },
  levelCardLocked: {
    opacity: 0.65,
    cursor: 'not-allowed',
  },
  levelCardTop: {
    display: 'flex',
    alignItems: 'flex-start',
    justifyContent: 'space-between',
    marginBottom: '0.85rem',
  },
  stageNumber: {
    width: '32px',
    height: '32px',
    borderRadius: '50%',
    background: '#6366f1',
    color: '#fff',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    fontWeight: 700,
    fontSize: '0.85rem',
    flexShrink: 0,
  },
  levelCardBadges: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.5rem',
  },
  adaptiveBadge: {
    display: 'inline-flex',
    alignItems: 'center',
    gap: '0.3rem',
    background: 'rgba(168, 85, 247, 0.15)',
    border: '1px solid rgba(168, 85, 247, 0.3)',
    color: '#c084fc',
    padding: '0.2rem 0.55rem',
    borderRadius: '999px',
    fontSize: '0.7rem',
    fontWeight: 600,
    textTransform: 'capitalize',
  },
  levelName: {
    fontSize: '1.05rem',
    fontWeight: 700,
    color: workshopTokens.text,
    margin: '0 0 0.65rem',
    lineHeight: 1.3,
  },
  levelMeta: {
    display: 'flex',
    alignItems: 'center',
    flexWrap: 'wrap',
    gap: '0.6rem',
    marginBottom: '0.65rem',
  },
  difficultyBadge: {
    display: 'inline-block',
    padding: '0.2rem 0.65rem',
    borderRadius: '999px',
    fontSize: '0.72rem',
    fontWeight: 700,
    textTransform: 'uppercase',
    letterSpacing: '0.03em',
  },
  completionCount: {
    display: 'inline-flex',
    alignItems: 'center',
    gap: '0.35rem',
    fontSize: '0.78rem',
    color: '#64748b',
  },
  levelDescription: {
    fontSize: '0.85rem',
    color: '#94a3b8',
    lineHeight: 1.55,
    margin: '0 0 0.7rem',
    display: '-webkit-box',
    WebkitLineClamp: 2,
    WebkitBoxOrient: 'vertical',
    overflow: 'hidden',
  },
  levelGoal: {
    display: 'flex',
    alignItems: 'flex-start',
    gap: '0.4rem',
    fontSize: '0.82rem',
    color: workshopTokens.text,
    lineHeight: 1.5,
    margin: '0 0 1rem',
  },
  levelFooter: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    paddingTop: '0.75rem',
    borderTop: '1px solid rgba(148, 163, 184, 0.1)',
  },
  levelAction: {
    fontSize: '0.85rem',
    color: '#94a3b8',
    fontWeight: 500,
  },
  levelActionLocked: {
    display: 'inline-flex',
    alignItems: 'center',
    gap: '0.4rem',
    fontSize: '0.85rem',
    color: '#64748b',
    fontWeight: 500,
  },
  levelActionCompleted: {
    display: 'inline-flex',
    alignItems: 'center',
    gap: '0.4rem',
    fontSize: '0.85rem',
    color: '#4ade80',
    fontWeight: 600,
  },
  levelActionContinue: {
    display: 'inline-flex',
    alignItems: 'center',
    gap: '0.4rem',
    fontSize: '0.85rem',
    color: '#fbbf24',
    fontWeight: 600,
  },
  levelActionStart: {
    display: 'inline-flex',
    alignItems: 'center',
    gap: '0.4rem',
    fontSize: '0.85rem',
    color: '#818cf8',
    fontWeight: 600,
  },
  emptyState: {
    textAlign: 'center',
    padding: '3rem',
    color: '#64748b',
  },
  leaderboardLinkWrapper: {
    marginTop: '1rem',
  },
  leaderboardLink: {
    width: '100%',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    background: workshopTokens.surface,
    border: `2px solid ${workshopTokens.border}`,
    borderRadius: '16px',
    padding: '1.25rem 1.5rem',
    cursor: 'pointer',
    color: workshopTokens.text,
    textAlign: 'left',
    transition: 'border-color 0.2s ease, background 0.2s ease',
  },
  leaderboardLinkContent: {
    display: 'flex',
    alignItems: 'center',
    gap: '1rem',
  },
  leaderboardLinkTitle: {
    fontSize: '1.05rem',
    fontWeight: 700,
    color: workshopTokens.text,
    marginBottom: '0.2rem',
  },
  leaderboardLinkDesc: {
    fontSize: '0.85rem',
    color: '#64748b',
  },
};

export default CTFDashboard;
