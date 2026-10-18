import React, { useState, useEffect, useCallback, useRef } from 'react';
import { Link } from 'react-router-dom';
import axios from 'axios';
import { createReconciliationGuard, createRevisionPoller } from '../services/revisionPoller';
import {
  FiAward,
  FiArrowLeft,
  FiClock,
  FiTarget,
  FiUsers,
  FiRefreshCw,
  FiCheckCircle,
  FiBarChart2,
  FiZap,
  FiFilter,
} from 'react-icons/fi';
import { workshopTokens } from '../components/workshop/experience.mjs';

const TOTAL_STAGES = 10;
const POLL_INTERVAL_MS = 12000;
const MAX_POLL_INTERVAL_MS = 15000;
const UNAVAILABLE_MESSAGE = 'Leaderboard is not available at this time.';

async function loadLeaderboardSnapshot({ signal } = {}) {
  const token = localStorage.getItem('token');
  try {
    const response = await axios.get('/api/ctf/leaderboard', {
      params: { limit: 50 },
      headers: token ? { Authorization: `Bearer ${token}` } : {},
      signal,
      timeout: 10000,
    });
    return { available: true, leaderboard: response.data.leaderboard || [] };
  } catch (error) {
    if (error.response?.status === 403) {
      return { available: false, leaderboard: [] };
    }
    throw error;
  }
}

const styles = {
  page: {
    minHeight: '100vh',
    background: workshopTokens.primaryGradient,
    padding: '2rem 0 3rem',
    color: workshopTokens.text,
  },
  wrapper: {
    maxWidth: '1400px',
    margin: '0 auto',
    padding: '0 1.5rem',
  },
  header: {
    marginBottom: '2.5rem',
  },
  backLink: {
    display: 'inline-flex',
    alignItems: 'center',
    gap: '0.5rem',
    color: workshopTokens.text,
    textDecoration: 'none',
    fontSize: '0.95rem',
    fontWeight: 600,
    marginBottom: '1.5rem',
    padding: '0.5rem 1rem',
    borderRadius: '10px',
    border: `1px solid ${workshopTokens.border}`,
    background: 'rgba(255, 255, 255, 0.92)',
    transition: 'color 0.2s, border-color 0.2s',
  },
  title: {
    fontSize: '2.75rem',
    fontWeight: 800,
    margin: '0 0 0.75rem',
    color: '#fff',
  },
  subtitle: {
    margin: 0,
    fontSize: '1.1rem',
    color: workshopTokens.mutedText,
    maxWidth: '640px',
    lineHeight: 1.6,
  },
  filterRow: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    flexWrap: 'wrap',
    gap: '1rem',
    marginBottom: '2rem',
    padding: '1rem 1.25rem',
    borderRadius: '14px',
    background: workshopTokens.surface,
    border: `2px solid ${workshopTokens.border}`,
  },
  toggleLabel: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.75rem',
    cursor: 'pointer',
    fontSize: '0.95rem',
    fontWeight: 600,
    color: workshopTokens.text,
    userSelect: 'none',
  },
  toggleTrack: (active) => ({
    width: '44px',
    height: '24px',
    borderRadius: '12px',
    background: active ? '#f59e0b' : '#334155',
    position: 'relative',
    transition: 'background 0.2s',
    flexShrink: 0,
  }),
  toggleThumb: (active) => ({
    position: 'absolute',
    top: '3px',
    left: active ? '23px' : '3px',
    width: '18px',
    height: '18px',
    borderRadius: '50%',
    background: '#fff',
    transition: 'left 0.2s',
    boxShadow: '0 1px 3px rgba(0,0,0,0.3)',
  }),
  refreshBtn: (disabled) => ({
    display: 'inline-flex',
    alignItems: 'center',
    gap: '0.5rem',
    padding: '0.6rem 1.1rem',
    borderRadius: '10px',
    border: '1px solid rgba(148, 163, 184, 0.25)',
    background: workshopTokens.surface,
    color: workshopTokens.text,
    fontWeight: 600,
    fontSize: '0.9rem',
    cursor: disabled ? 'not-allowed' : 'pointer',
    opacity: disabled ? 0.6 : 1,
  }),
  podiumSection: {
    marginBottom: '2.5rem',
  },
  podiumGrid: {
    display: 'grid',
    gridTemplateColumns: '1fr 1.15fr 1fr',
    gap: '1.25rem',
    alignItems: 'end',
  },
  podiumCard: (rank) => {
    const palettes = {
      1: {
        border: '1px solid rgba(251, 191, 36, 0.45)',
        background: 'linear-gradient(180deg, rgba(251, 191, 36, 0.18) 0%, #ffffff 100%)',
        accent: '#fbbf24',
        shadow: '0 12px 40px rgba(251, 191, 36, 0.15)',
      },
      2: {
        border: '1px solid rgba(203, 213, 225, 0.35)',
        background: 'linear-gradient(180deg, rgba(203, 213, 225, 0.2) 0%, #ffffff 100%)',
        accent: '#cbd5e1',
        shadow: '0 10px 32px rgba(148, 163, 184, 0.1)',
      },
      3: {
        border: '1px solid rgba(205, 127, 50, 0.4)',
        background: 'linear-gradient(180deg, rgba(205, 127, 50, 0.15) 0%, #ffffff 100%)',
        accent: '#cd7f32',
        shadow: '0 10px 32px rgba(205, 127, 50, 0.12)',
      },
    };
    const p = palettes[rank] || palettes[3];
    return {
      textAlign: 'center',
      padding: rank === 1 ? '2rem 1.5rem 1.75rem' : '1.5rem 1.25rem 1.5rem',
      borderRadius: '18px',
      border: p.border,
      background: p.background,
      boxShadow: p.shadow,
      order: rank === 1 ? 2 : rank === 2 ? 1 : 3,
    };
  },
  podiumRank: (rank) => ({
    fontSize: rank === 1 ? '2.5rem' : '2rem',
    fontWeight: 800,
    color: rank === 1 ? '#fbbf24' : rank === 2 ? '#cbd5e1' : '#cd7f32',
    marginBottom: '0.5rem',
  }),
  podiumUsername: {
    fontSize: '1.25rem',
    fontWeight: 700,
    color: workshopTokens.text,
    marginBottom: '0.35rem',
    wordBreak: 'break-word',
  },
  podiumTeam: {
    fontSize: '0.85rem',
    color: '#94a3b8',
    marginBottom: '1rem',
  },
  podiumStats: {
    display: 'grid',
    gridTemplateColumns: '1fr 1fr',
    gap: '0.75rem',
    textAlign: 'left',
  },
  podiumStat: {
    padding: '0.65rem 0.75rem',
    borderRadius: '10px',
    background: 'rgba(0, 0, 0, 0.25)',
    border: '1px solid rgba(148, 163, 184, 0.1)',
  },
  podiumStatLabel: {
    fontSize: '0.7rem',
    textTransform: 'uppercase',
    letterSpacing: '0.05em',
    color: '#64748b',
    marginBottom: '0.25rem',
  },
  podiumStatValue: {
    fontSize: '0.95rem',
    fontWeight: 700,
    color: workshopTokens.text,
  },
  tableCard: {
    borderRadius: '18px',
    border: `2px solid ${workshopTokens.border}`,
    background: workshopTokens.surface,
    overflow: 'hidden',
    boxShadow: '0 20px 50px rgba(0, 0, 0, 0.25)',
  },
  tableHeaderBar: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.75rem',
    padding: '1.25rem 1.5rem',
    borderBottom: '1px solid rgba(148, 163, 184, 0.12)',
    fontSize: '1.25rem',
    fontWeight: 700,
    color: workshopTokens.text,
  },
  tableScroll: {
    overflowX: 'auto',
  },
  table: {
    width: '100%',
    borderCollapse: 'collapse',
    minWidth: '960px',
  },
  th: {
    padding: '0.9rem 1rem',
    textAlign: 'left',
    fontSize: '0.75rem',
    fontWeight: 700,
    textTransform: 'uppercase',
    letterSpacing: '0.06em',
    color: '#64748b',
    background: workshopTokens.canvas,
    borderBottom: `1px solid ${workshopTokens.border}`,
    whiteSpace: 'nowrap',
  },
  td: {
    padding: '1rem',
    fontSize: '0.92rem',
    color: workshopTokens.text,
    borderBottom: `1px solid ${workshopTokens.border}`,
    verticalAlign: 'middle',
  },
  rankCell: (rank) => ({
    fontWeight: 800,
    fontSize: '1rem',
    color: rank === 1 ? '#fbbf24' : rank === 2 ? '#cbd5e1' : rank === 3 ? '#cd7f32' : '#64748b',
  }),
  playerCell: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.75rem',
  },
  avatar: {
    width: '36px',
    height: '36px',
    borderRadius: '50%',
    background: 'linear-gradient(135deg, #6366f1, #8b5cf6)',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    fontWeight: 700,
    fontSize: '0.85rem',
    color: '#fff',
    flexShrink: 0,
  },
  playerName: {
    fontWeight: 600,
    color: workshopTokens.text,
  },
  completedBadge: {
    display: 'inline-flex',
    alignItems: 'center',
    gap: '0.35rem',
    padding: '0.3rem 0.65rem',
    borderRadius: '999px',
    background: 'rgba(34, 197, 94, 0.15)',
    border: '1px solid rgba(34, 197, 94, 0.35)',
    color: '#4ade80',
    fontSize: '0.78rem',
    fontWeight: 700,
    whiteSpace: 'nowrap',
  },
  inProgressBadge: {
    display: 'inline-flex',
    alignItems: 'center',
    gap: '0.35rem',
    padding: '0.3rem 0.65rem',
    borderRadius: '999px',
    background: 'rgba(100, 116, 139, 0.15)',
    border: '1px solid rgba(100, 116, 139, 0.3)',
    color: '#94a3b8',
    fontSize: '0.78rem',
    fontWeight: 600,
    whiteSpace: 'nowrap',
  },
  loadingContainer: {
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'center',
    justifyContent: 'center',
    minHeight: '50vh',
    gap: '1rem',
    color: '#94a3b8',
  },
  emptyState: {
    textAlign: 'center',
    padding: '4rem 2rem',
    color: '#64748b',
  },
  emptyIcon: {
    fontSize: '3.5rem',
    marginBottom: '1rem',
    opacity: 0.5,
  },
  wsIndicator: (connected) => ({
    display: 'inline-flex',
    alignItems: 'center',
    gap: '0.4rem',
    fontSize: '0.8rem',
    color: connected ? '#4ade80' : '#64748b',
    fontWeight: 600,
  }),
  wsDot: (connected) => ({
    width: '8px',
    height: '8px',
    borderRadius: '50%',
    background: connected ? '#4ade80' : '#64748b',
    boxShadow: connected ? '0 0 8px rgba(74, 222, 128, 0.6)' : 'none',
  }),
};

function formatTime(ms) {
  if (ms == null || ms <= 0) return '--:--';
  const totalSeconds = Math.floor(ms / 1000);
  const hours = Math.floor(totalSeconds / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);
  const seconds = totalSeconds % 60;
  const pad = (n) => String(n).padStart(2, '0');
  if (hours > 0) {
    return `${pad(hours)}:${pad(minutes)}:${pad(seconds)}`;
  }
  return `${pad(minutes)}:${pad(seconds)}`;
}

function formatSuccessRate(rate) {
  if (rate == null || Number.isNaN(rate)) return '--';
  return `${Math.round(rate)}%`;
}

function isBossComplete(entry) {
  return (entry.total_stages_completed || 0) >= TOTAL_STAGES;
}

function PodiumCard({ entry, rank }) {
  if (!entry) return null;
  const medals = { 1: '🥇', 2: '🥈', 3: '🥉' };

  return (
    <div style={styles.podiumCard(rank)}>
      <div style={styles.podiumRank(rank)}>
        {medals[rank]} #{entry.rank_position || rank}
      </div>
      <div style={styles.podiumUsername}>{entry.username}</div>
      <div style={styles.podiumTeam}>
        {entry.team_name ? `Team: ${entry.team_name}` : 'No team'}
      </div>
      <div style={styles.podiumStats}>
        <div style={styles.podiumStat}>
          <div style={styles.podiumStatLabel}>Stages</div>
          <div style={styles.podiumStatValue}>
            {entry.total_stages_completed || 0}/{TOTAL_STAGES}
          </div>
        </div>
        <div style={styles.podiumStat}>
          <div style={styles.podiumStatLabel}>Total Time</div>
          <div style={styles.podiumStatValue}>
            {formatTime(entry.total_completion_time)}
          </div>
        </div>
        <div style={styles.podiumStat}>
          <div style={styles.podiumStatLabel}>Score</div>
          <div style={styles.podiumStatValue}>{entry.total_score || 0}</div>
        </div>
        <div style={styles.podiumStat}>
          <div style={styles.podiumStatLabel}>Status</div>
          <div style={styles.podiumStatValue}>
            {isBossComplete(entry) ? 'Complete' : 'In Progress'}
          </div>
        </div>
      </div>
    </div>
  );
}

const CTFLeaderboard = ({ pollerOptions } = {}) => {
  const [leaderboard, setLeaderboard] = useState([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [bossOnly, setBossOnly] = useState(false);
  const [error, setError] = useState(null);
  const mountedRef = useRef(false);
  const hasCanonicalRef = useRef(false);
  const manualAbortRef = useRef(null);
  const guardRef = useRef(createReconciliationGuard());
  const pollerOptionsRef = useRef(pollerOptions);
  pollerOptionsRef.current = pollerOptions;

  const applySnapshot = useCallback((snapshot, token) => {
    if (!mountedRef.current) return;
    guardRef.current.commit('leaderboard', token, () => {
      hasCanonicalRef.current = true;
      setLeaderboard(snapshot.leaderboard);
      setError(snapshot.available ? null : UNAVAILABLE_MESSAGE);
      setLoading(false);
    });
  }, []);

  const refreshLeaderboard = useCallback(async () => {
    const guard = guardRef.current;
    const requestToken = guard.beginForeground('leaderboard');
    manualAbortRef.current?.abort();
    const controller = new AbortController();
    manualAbortRef.current = controller;

    if (mountedRef.current) {
      setRefreshing(true);
      setError(null);
    }
    try {
      const snapshot = await loadLeaderboardSnapshot({ signal: controller.signal });
      applySnapshot(snapshot, requestToken);
    } catch (requestError) {
      if (!controller.signal.aborted && requestError?.code !== 'STALE_RECONCILIATION' && mountedRef.current) {
        guard.commit('leaderboard', requestToken, () => {
          setError('Failed to load leaderboard data.');
          setLoading(false);
        });
      }
    } finally {
      guard.endForeground('leaderboard', requestToken);
      if (manualAbortRef.current === controller) {
        manualAbortRef.current = null;
        if (mountedRef.current) setRefreshing(false);
      }
    }
  }, [applySnapshot]);

  useEffect(() => {
    mountedRef.current = true;
    const options = pollerOptionsRef.current || {};
    const poller = createRevisionPoller({
      ...options,
      intervalMs: POLL_INTERVAL_MS,
      maxIntervalMs: MAX_POLL_INTERVAL_MS,
      async fetchSnapshot({ signal } = {}) {
        const token = guardRef.current.beginRequiredBackground('leaderboard');
        const snapshot = await loadLeaderboardSnapshot({ signal });
        applySnapshot(snapshot, token);
        return snapshot;
      },
      onChange: async () => {},
      onError(requestError) {
        options.onError?.(requestError);
        if (
          mountedRef.current &&
          !hasCanonicalRef.current &&
          requestError?.code !== 'STALE_RECONCILIATION'
        ) {
          setError('Failed to load leaderboard data.');
          setLoading(false);
        }
      },
    });
    void poller.start();

    return () => {
      mountedRef.current = false;
      poller.stop();
      manualAbortRef.current?.abort();
      manualAbortRef.current = null;
    };
  }, [applySnapshot]);

  const filteredLeaderboard = bossOnly
    ? leaderboard.filter(isBossComplete)
    : leaderboard;

  const hasAnyProgress = filteredLeaderboard.some(e => (e.total_stages_completed || 0) > 0);
  const allSameRank = filteredLeaderboard.length > 1 && filteredLeaderboard.every(e => e.rank_position === filteredLeaderboard[0].rank_position);
  const topThree = hasAnyProgress ? filteredLeaderboard.slice(0, 3) : [];

  if (loading && leaderboard.length === 0) {
    return (
      <div style={styles.page}>
        <div style={styles.wrapper}>
          <Link to="/ctf" style={styles.backLink}>
            <FiArrowLeft /> Back to CTF
          </Link>
          <div style={styles.loadingContainer}>
            <FiAward size={48} color="#fbbf24" />
            <h2 style={{ margin: 0, fontWeight: 700, color: '#e2e8f0' }}>Loading Leaderboard...</h2>
            <p style={{ margin: 0, fontSize: '0.95rem' }}>Fetching live rankings</p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div style={styles.page}>
      <div style={styles.wrapper}>
        <header style={styles.header}>
          <Link
            to="/ctf"
            style={styles.backLink}
            onMouseEnter={(e) => { e.currentTarget.style.color = '#fbbf24'; }}
            onMouseLeave={(e) => { e.currentTarget.style.color = '#94a3b8'; }}
          >
            <FiArrowLeft /> Back to CTF
          </Link>
          <h1 style={styles.title}>CTF Leaderboard</h1>
          <p style={styles.subtitle}>
            Live rankings for the AI Prompt Injection CTF. Compete through 10 progressive stages
            including the final Boss (L10) guardian — fastest completions with the highest scores rise to the top.
          </p>
        </header>

        <div style={styles.filterRow}>
          <label style={styles.toggleLabel}>
            <input
              type="checkbox"
              checked={bossOnly}
              onChange={(e) => setBossOnly(e.target.checked)}
              style={{ position: 'absolute', opacity: 0, width: 0, height: 0 }}
            />
            <span style={styles.toggleTrack(bossOnly)}>
              <span style={styles.toggleThumb(bossOnly)} />
            </span>
            <FiFilter size={16} />
            Show only Boss (L10) completions
          </label>

          <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', flexWrap: 'wrap' }}>
            <span style={styles.wsIndicator(true)}>
              <span style={styles.wsDot(true)} />
              Auto-refresh · 15s
            </span>
            <button
              type="button"
              style={styles.refreshBtn(refreshing)}
              onClick={refreshLeaderboard}
              disabled={refreshing}
            >
              <FiRefreshCw
                size={16}
                style={{
                  animation: refreshing ? 'spin 1s linear infinite' : 'none',
                }}
              />
              Refresh
            </button>
          </div>
        </div>

        {error && (
          <div
            style={{
              padding: '1rem 1.25rem',
              marginBottom: '1.5rem',
              borderRadius: '12px',
              background: 'rgba(239, 68, 68, 0.12)',
              border: '1px solid rgba(239, 68, 68, 0.3)',
              color: '#fca5a5',
              fontSize: '0.95rem',
            }}
          >
            {error}
          </div>
        )}

        {filteredLeaderboard.length === 0 ? (
          <div style={styles.emptyState}>
            <div style={styles.emptyIcon}>
              <FiAward />
            </div>
            <h3 style={{ margin: '0 0 0.5rem', color: '#94a3b8', fontSize: '1.35rem' }}>
              {bossOnly ? 'No Boss (L10) completions yet' : 'No participants yet'}
            </h3>
            <p style={{ margin: 0, fontSize: '0.95rem' }}>
              {bossOnly
                ? 'Be the first to defeat the final Boss stage and claim the top spot!'
                : 'Register for the CTF and complete stages to appear on the leaderboard.'}
            </p>
          </div>
        ) : (
          <>
            {topThree.length > 0 && (
              <section style={styles.podiumSection}>
                <div style={styles.podiumGrid} className="podium-grid-responsive">
                  <PodiumCard entry={topThree[1]} rank={2} />
                  <PodiumCard entry={topThree[0]} rank={1} />
                  <PodiumCard entry={topThree[2]} rank={3} />
                </div>
              </section>
            )}

            {!hasAnyProgress && (
              <div style={{
                padding: '1.5rem 1.75rem',
                marginBottom: '2rem',
                borderRadius: '14px',
                background: 'rgba(251, 191, 36, 0.08)',
                border: '1px solid rgba(251, 191, 36, 0.25)',
                textAlign: 'center',
              }}>
                <p style={{ margin: 0, fontSize: '1rem', color: '#fbbf24', fontWeight: 600, marginBottom: '0.35rem' }}>
                  No stages completed yet
                </p>
                <p style={{ margin: 0, fontSize: '0.9rem', color: '#94a3b8' }}>
                  Rankings will appear once participants start completing levels. Below are registered players.
                </p>
              </div>
            )}

            <div style={styles.tableCard}>
              <div style={styles.tableHeaderBar}>
                <FiBarChart2 size={22} color="#fbbf24" />
                {hasAnyProgress ? 'Full Rankings' : 'Registered Participants'}
                <span style={{ fontSize: '0.85rem', fontWeight: 500, color: '#64748b', marginLeft: '0.5rem' }}>
                  ({filteredLeaderboard.length} {filteredLeaderboard.length === 1 ? 'player' : 'players'})
                </span>
              </div>
              <div style={styles.tableScroll}>
                <table style={styles.table}>
                  <thead>
                    <tr>
                      <th style={styles.th}>Rank</th>
                      <th style={styles.th}>Player</th>
                      <th style={styles.th}>Team</th>
                      <th style={styles.th}>Stages Completed</th>
                      <th style={styles.th}>Total Time</th>
                      <th style={styles.th}>Total Attempts</th>
                      <th style={styles.th}>Success Rate</th>
                      <th style={styles.th}>Score</th>
                      <th style={styles.th}>Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredLeaderboard.map((entry, idx) => {
                      const rank = allSameRank ? idx + 1 : (entry.rank_position || idx + 1);
                      const completed = isBossComplete(entry);
                      return (
                        <tr
                          key={entry.participant_id || `${entry.username}-${rank}`}
                          style={{
                            background: (hasAnyProgress && rank <= 3) ? 'rgba(251, 191, 36, 0.04)' : 'transparent',
                          }}
                        >
                          <td style={{ ...styles.td, ...styles.rankCell(hasAnyProgress ? rank : 0) }}>
                            #{rank || '—'}
                          </td>
                          <td style={styles.td}>
                            <div style={styles.playerCell}>
                              <div style={styles.avatar}>
                                {(entry.username || '?').charAt(0).toUpperCase()}
                              </div>
                              <span style={styles.playerName}>{entry.username}</span>
                            </div>
                          </td>
                          <td style={styles.td}>{entry.team_name || '—'}</td>
                          <td style={styles.td}>
                            <span style={{ display: 'inline-flex', alignItems: 'center', gap: '0.35rem' }}>
                              <FiTarget size={14} color="#64748b" />
                              {entry.total_stages_completed || 0}/{TOTAL_STAGES}
                            </span>
                          </td>
                          <td style={styles.td}>
                            <span style={{ display: 'inline-flex', alignItems: 'center', gap: '0.35rem' }}>
                              <FiClock size={14} color="#64748b" />
                              {formatTime(entry.total_completion_time)}
                            </span>
                          </td>
                          <td style={styles.td}>{entry.total_attempts ?? 0}</td>
                          <td style={styles.td}>{formatSuccessRate(entry.success_rate)}</td>
                          <td style={styles.td}>
                            <span style={{ display: 'inline-flex', alignItems: 'center', gap: '0.35rem', fontWeight: 700, color: '#fbbf24' }}>
                              <FiZap size={14} />
                              {entry.total_score ?? 0}
                            </span>
                          </td>
                          <td style={styles.td}>
                            {completed ? (
                              <span style={styles.completedBadge}>
                                <FiCheckCircle size={13} />
                                Completed
                              </span>
                            ) : (
                              <span style={styles.inProgressBadge}>
                                <FiUsers size={13} />
                                In Progress
                              </span>
                            )}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>
          </>
        )}
      </div>

      <style>{`
        @keyframes spin {
          from { transform: rotate(0deg); }
          to { transform: rotate(360deg); }
        }
        @media (max-width: 900px) {
          .podium-grid-responsive {
            grid-template-columns: 1fr !important;
          }
        }
      `}</style>
    </div>
  );
};

export default CTFLeaderboard;
