import React, { useState, useEffect, useCallback, useMemo, useRef } from 'react';
import axios from 'axios';
import useCtfRecovery from '../../services/useCtfRecovery';
import { isCtfRecoveryCancelled } from '../../services/ctfRecovery';
import CtfRecoveryNotice from '../../components/CtfRecoveryNotice';
import { ResetConfirmation } from '../../components/workshop/WorkshopExperience';
import { toast } from 'react-toastify';
import {
  FiActivity,
  FiAlertTriangle,
  FiBarChart2,
  FiCheck,
  FiChevronDown,
  FiChevronLeft,
  FiChevronRight,
  FiChevronUp,
  FiCopy,
  FiEye,
  FiFilter,
  FiKey,
  FiLayers,
  FiList,
  FiRefreshCw,
  FiSave,
  FiSettings,
  FiShield,
  FiTrash2,
  FiUserX,
  FiUsers,
  FiX,
  FiZap,
} from 'react-icons/fi';

// Matched to ComprehensiveAdminDashboard's light theme:
//   background page: #f8fafc, cards white, borders #e2e8f0,
//   primary accent #667eea (purple), text slate #2d3748, muted #718096,
//   danger #e53e3e, success #48bb78, table header #f7fafc.
const COLORS = {
  bg: '#f8fafc',
  card: '#ffffff',
  cardBorder: '#e2e8f0',
  text: '#2d3748',
  textMuted: '#718096',
  accent: '#667eea',
  accentDim: 'rgba(102, 126, 234, 0.12)',
  danger: '#e53e3e',
  dangerDim: 'rgba(229, 62, 62, 0.08)',
  success: '#48bb78',
  warning: '#dd6b20',
  inputBg: '#f7fafc',
  tableHeader: '#f7fafc',
  rowHover: 'rgba(102, 126, 234, 0.05)',
};

const TECHNIQUE_TAGS = [
  'direct_extraction',
  'role_play',
  'virtualization',
  'obfuscation_base64',
  'obfuscation_hex',
  'obfuscation_unicode',
  'multi_language',
  'jailbreak_override',
  'side_stepping',
  'context_injection',
  'authority_appeal',
  'emotional_manipulation',
  'other',
];

const ADAPTIVE_MODES = ['none', 'technique', 'payload', 'hybrid'];
const FEEDBACK_MODES = ['full', 'reason', 'silent'];

const CONFIG_LABELS = {
  ctf_enabled: 'CTF Enabled',
  ctf_visible_to_students: 'Visible to Students',
  student_leaderboard_visible: 'Student Leaderboard Visible',
  public_leaderboard_visible: 'Public Leaderboard Visible',
  ctf_registration_open: 'Registration Open',
  ctf_max_participants: 'Max Participants (-1 = unlimited)',
  ctf_time_limit: 'Time Limit (ms, -1 = none)',
  leaderboard_update_interval: 'Leaderboard Update Interval (ms)',
  ctf_nav_visible: 'CTF Nav Visible',
  ctf_show_technique_feedback: 'Show Technique Feedback',
  ctf_show_attempt_counter: 'Show Attempt Counter',
  ctf_hint_gating_attempts: 'Hint Gating (attempts before hints)',
  ctf_hint_cost_1: 'Hint 1 Cost (points)',
  ctf_hint_cost_2: 'Hint 2 Cost (points)',
  ctf_hint_cost_3: 'Hint 3 Cost (points)',
};

const BOOLEAN_CONFIG_KEYS = new Set([
  'ctf_enabled',
  'ctf_visible_to_students',
  'student_leaderboard_visible',
  'public_leaderboard_visible',
  'ctf_registration_open',
  'ctf_nav_visible',
  'ctf_show_technique_feedback',
  'ctf_show_attempt_counter',
]);

const READONLY_CONFIG_KEYS = new Set(['current_participants', 'registration_available']);

const TABS = [
  { id: 'overview', label: 'Overview', icon: FiBarChart2 },
  { id: 'levels', label: 'Levels', icon: FiLayers },
  { id: 'solutions', label: 'Solutions', icon: FiKey },
  { id: 'attempts', label: 'Attempts', icon: FiList },
  { id: 'leaderboard', label: 'Leaderboard', icon: FiUsers },
  { id: 'config', label: 'Config', icon: FiSettings },
  { id: 'danger', label: 'Danger Zone', icon: FiAlertTriangle },
];

function getAuthHeaders() {
  const token = localStorage.getItem('token');
  return token ? { Authorization: `Bearer ${token}` } : {};
}

function formatTimestamp(ts) {
  if (!ts) return '—';
  try {
    return new Date(ts).toLocaleString();
  } catch {
    return ts;
  }
}

function formatDuration(ms) {
  if (ms == null || ms === '') return '—';
  const n = Number(ms);
  if (Number.isNaN(n)) return '—';
  if (n < 1000) return `${n}ms`;
  const sec = Math.floor(n / 1000);
  const min = Math.floor(sec / 60);
  const remSec = sec % 60;
  if (min === 0) return `${sec}s`;
  return `${min}m ${remSec}s`;
}

function truncate(str, len = 80) {
  if (!str) return '—';
  return str.length > len ? `${str.slice(0, len)}…` : str;
}

function parseHintsForEdit(hints) {
  if (!hints) return '[]';
  if (typeof hints === 'string') {
    try {
      return JSON.stringify(JSON.parse(hints), null, 2);
    } catch {
      return hints;
    }
  }
  return JSON.stringify(hints, null, 2);
}

function stylesForTheme() {
  return {
    container: {
      background: COLORS.bg,
      color: COLORS.text,
      borderRadius: '12px',
      padding: '1.5rem',
      minHeight: '400px',
      // Subtle shadow so the panel reads as a card on the admin page's
      // light background — matches ComprehensiveAdminDashboard section chrome.
      boxShadow: '0 1px 3px rgba(0,0,0,0.04), 0 1px 2px rgba(0,0,0,0.06)',
      border: `1px solid ${COLORS.cardBorder}`,
    },
    tabBar: {
      display: 'flex',
      flexWrap: 'wrap',
      gap: '0.5rem',
      marginBottom: '1.5rem',
      borderBottom: `1px solid ${COLORS.cardBorder}`,
      paddingBottom: '1rem',
    },
    tab: (active) => ({
      display: 'inline-flex',
      alignItems: 'center',
      gap: '0.5rem',
      padding: '0.6rem 1rem',
      borderRadius: '8px',
      border: 'none',
      cursor: 'pointer',
      fontWeight: 600,
      fontSize: '0.875rem',
      background: active ? COLORS.accentDim : 'transparent',
      color: active ? COLORS.accent : COLORS.textMuted,
      borderBottom: active ? `2px solid ${COLORS.accent}` : '2px solid transparent',
      transition: 'all 0.2s',
    }),
    card: {
      background: COLORS.card,
      border: `1px solid ${COLORS.cardBorder}`,
      borderRadius: '10px',
      padding: '1.25rem',
      marginBottom: '1rem',
    },
    cardTitle: {
      margin: '0 0 1rem',
      fontSize: '1rem',
      fontWeight: 700,
      color: COLORS.accent,
      display: 'flex',
      alignItems: 'center',
      gap: '0.5rem',
    },
    statGrid: {
      display: 'grid',
      gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
      gap: '1rem',
      marginBottom: '1.5rem',
    },
    statBox: {
      background: COLORS.card,
      border: `1px solid ${COLORS.cardBorder}`,
      borderRadius: '10px',
      padding: '1.25rem',
      textAlign: 'center',
    },
    statValue: {
      fontSize: '2rem',
      fontWeight: 800,
      color: COLORS.accent,
      margin: '0.25rem 0',
    },
    statLabel: {
      fontSize: '0.85rem',
      color: COLORS.textMuted,
      margin: 0,
    },
    table: {
      width: '100%',
      borderCollapse: 'collapse',
      fontSize: '0.875rem',
    },
    th: {
      textAlign: 'left',
      padding: '0.75rem',
      background: COLORS.tableHeader,
      color: COLORS.text,
      fontWeight: 600,
      borderBottom: `1px solid ${COLORS.cardBorder}`,
    },
    td: {
      padding: '0.75rem',
      borderBottom: `1px solid ${COLORS.cardBorder}`,
      verticalAlign: 'middle',
    },
    input: {
      width: '100%',
      padding: '0.5rem 0.75rem',
      background: COLORS.inputBg,
      border: `1px solid ${COLORS.cardBorder}`,
      borderRadius: '6px',
      color: COLORS.text,
      fontSize: '0.875rem',
      boxSizing: 'border-box',
    },
    select: {
      padding: '0.5rem 0.75rem',
      background: COLORS.inputBg,
      border: `1px solid ${COLORS.cardBorder}`,
      borderRadius: '6px',
      color: COLORS.text,
      fontSize: '0.875rem',
    },
    textarea: {
      width: '100%',
      padding: '0.5rem 0.75rem',
      background: COLORS.inputBg,
      border: `1px solid ${COLORS.cardBorder}`,
      borderRadius: '6px',
      color: COLORS.text,
      fontSize: '0.875rem',
      fontFamily: 'Monaco, Menlo, monospace',
      minHeight: '80px',
      resize: 'vertical',
      boxSizing: 'border-box',
    },
    btn: (variant = 'primary') => {
      const base = {
        display: 'inline-flex',
        alignItems: 'center',
        gap: '0.4rem',
        padding: '0.5rem 1rem',
        borderRadius: '6px',
        border: 'none',
        cursor: 'pointer',
        fontWeight: 600,
        fontSize: '0.8125rem',
        transition: 'opacity 0.2s',
      };
      if (variant === 'primary') {
        return { ...base, background: COLORS.accent, color: '#fff' };
      }
      if (variant === 'danger') {
        return { ...base, background: COLORS.danger, color: '#fff' };
      }
      if (variant === 'ghost') {
        return {
          ...base,
          background: 'transparent',
          color: COLORS.textMuted,
          border: `1px solid ${COLORS.cardBorder}`,
        };
      }
      if (variant === 'success') {
        return { ...base, background: COLORS.success, color: '#fff' };
      }
      return { ...base, background: COLORS.cardBorder, color: COLORS.text };
    },
    label: {
      display: 'block',
      marginBottom: '0.35rem',
      fontSize: '0.8125rem',
      color: COLORS.textMuted,
      fontWeight: 500,
    },
    formGroup: {
      marginBottom: '1rem',
    },
    formGrid: {
      display: 'grid',
      gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
      gap: '1rem',
    },
    barTrack: {
      height: '8px',
      background: COLORS.inputBg,
      borderRadius: '4px',
      overflow: 'hidden',
      flex: 1,
    },
    barFill: (pct, color = COLORS.accent) => ({
      height: '100%',
      width: `${Math.min(100, Math.max(0, pct))}%`,
      background: color,
      borderRadius: '4px',
      transition: 'width 0.3s',
    }),
    activityItem: {
      padding: '0.75rem',
      borderBottom: `1px solid ${COLORS.cardBorder}`,
      fontSize: '0.8125rem',
    },
    modalOverlay: {
      position: 'fixed',
      inset: 0,
      background: 'rgba(0, 0, 0, 0.7)',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      zIndex: 9999,
      padding: '1rem',
    },
    modal: {
      background: COLORS.card,
      border: `1px solid ${COLORS.cardBorder}`,
      borderRadius: '12px',
      padding: '1.5rem',
      maxWidth: '640px',
      width: '100%',
      maxHeight: '90vh',
      overflow: 'auto',
      color: COLORS.text,
    },
    toggle: (on) => ({
      width: '44px',
      height: '24px',
      borderRadius: '12px',
      background: on ? COLORS.accent : COLORS.cardBorder,
      position: 'relative',
      cursor: 'pointer',
      border: 'none',
      padding: 0,
      flexShrink: 0,
    }),
    toggleKnob: (on) => ({
      position: 'absolute',
      top: '2px',
      left: on ? '22px' : '2px',
      width: '20px',
      height: '20px',
      borderRadius: '50%',
      background: '#fff',
      transition: 'left 0.2s',
    }),
    loading: {
      textAlign: 'center',
      padding: '3rem',
      color: COLORS.textMuted,
    },
    dangerZone: {
      border: `2px solid ${COLORS.danger}`,
      borderRadius: '10px',
      padding: '1.5rem',
      background: COLORS.dangerDim,
    },
    pagination: {
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'space-between',
      marginTop: '1rem',
      flexWrap: 'wrap',
      gap: '0.75rem',
    },
    badge: (color) => ({
      display: 'inline-block',
      padding: '0.2rem 0.5rem',
      borderRadius: '4px',
      fontSize: '0.75rem',
      fontWeight: 600,
      background: `${color}22`,
      color,
    }),
    expandableRow: {
      background: COLORS.inputBg,
    },
  };
}

function ToggleSwitch({ checked, onChange, disabled }) {
  const s = stylesForTheme();
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      disabled={disabled}
      style={{ ...s.toggle(checked), opacity: disabled ? 0.5 : 1 }}
      onClick={() => !disabled && onChange(!checked)}
    >
      <span style={s.toggleKnob(checked)} />
    </button>
  );
}

function OverviewTab({ analytics, loading, onRefresh }) {
  const s = stylesForTheme();

  if (loading) {
    return <div style={s.loading}><FiRefreshCw /> Loading analytics…</div>;
  }

  if (!analytics) {
    return (
      <div style={s.card}>
        <p style={{ color: COLORS.textMuted, margin: 0 }}>No analytics data available.</p>
        <button type="button" style={{ ...s.btn('ghost'), marginTop: '1rem' }} onClick={onRefresh}>
          <FiRefreshCw /> Retry
        </button>
      </div>
    );
  }

  const participantCount = analytics.participants?.total ?? 0;
  const totalCompletions = (analytics.stages || []).reduce(
    (sum, st) => sum + (Number(st.completions) || 0),
    0
  );
  const topTechniques = analytics.topTechniques || [];
  const maxTechniqueCount = Math.max(...topTechniques.map((t) => t.count), 1);
  const blockRates = analytics.blockRates || [];
  const recentActivity = (analytics.recent_activity || []).slice(0, 10);

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: '1rem' }}>
        <button type="button" style={s.btn('ghost')} onClick={onRefresh}>
          <FiRefreshCw /> Refresh
        </button>
      </div>

      <div style={s.statGrid}>
        <div style={s.statBox}>
          <FiUsers size={24} color={COLORS.accent} />
          <div style={s.statValue}>{participantCount}</div>
          <p style={s.statLabel}>Participants</p>
        </div>
        <div style={s.statBox}>
          <FiCheck size={24} color={COLORS.success} />
          <div style={s.statValue}>{totalCompletions}</div>
          <p style={s.statLabel}>Total Stage Completions</p>
        </div>
        <div style={s.statBox}>
          <FiZap size={24} color={COLORS.warning} />
          <div style={s.statValue}>{analytics.participants?.completed ?? 0}</div>
          <p style={s.statLabel}>Fully Completed</p>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '1rem' }}>
        <div style={s.card}>
          <h3 style={s.cardTitle}><FiBarChart2 /> Top Techniques Used</h3>
          {topTechniques.length === 0 ? (
            <p style={{ color: COLORS.textMuted, margin: 0, fontSize: '0.875rem' }}>No technique data yet.</p>
          ) : (
            topTechniques.map((t) => (
              <div key={t.technique_tag} style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '0.75rem' }}>
                <span style={{ width: '140px', fontSize: '0.75rem', color: COLORS.textMuted, flexShrink: 0 }}>
                  {t.technique_tag}
                </span>
                <div style={s.barTrack}>
                  <div style={s.barFill((t.count / maxTechniqueCount) * 100)} />
                </div>
                <span style={{ width: '32px', textAlign: 'right', fontSize: '0.8125rem', fontWeight: 600 }}>
                  {t.count}
                </span>
              </div>
            ))
          )}
        </div>

        <div style={s.card}>
          <h3 style={s.cardTitle}><FiShield /> Block Rates per Level</h3>
          {blockRates.length === 0 ? (
            <p style={{ color: COLORS.textMuted, margin: 0, fontSize: '0.875rem' }}>No attempt data yet.</p>
          ) : (
            blockRates.map((b) => {
              const total = Number(b.total_attempts) || 0;
              const blocked = Number(b.blocked_count) || 0;
              const pct = total > 0 ? (blocked / total) * 100 : 0;
              return (
                <div key={b.stage_name} style={{ marginBottom: '0.75rem' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.25rem', fontSize: '0.8125rem' }}>
                    <span>{b.stage_name}</span>
                    <span style={{ color: COLORS.textMuted }}>
                      {blocked}/{total} ({pct.toFixed(1)}%)
                    </span>
                  </div>
                  <div style={s.barTrack}>
                    <div style={s.barFill(pct, COLORS.danger)} />
                  </div>
                </div>
              );
            })
          )}
        </div>
      </div>

      <div style={s.card}>
        <h3 style={s.cardTitle}><FiActivity /> Recent Activity</h3>
        {recentActivity.length === 0 ? (
          <p style={{ color: COLORS.textMuted, margin: 0, fontSize: '0.875rem' }}>No recent events.</p>
        ) : (
          recentActivity.map((ev) => (
            <div key={ev.id} style={s.activityItem}>
              <div style={{ display: 'flex', justifyContent: 'space-between', gap: '1rem' }}>
                <span>
                  <strong style={{ color: COLORS.accent }}>{ev.event_type}</strong>
                  {ev.username && <> — {ev.username}</>}
                  {ev.stage_name && <> on {ev.stage_name}</>}
                </span>
                <span style={{ color: COLORS.textMuted, flexShrink: 0 }}>{formatTimestamp(ev.timestamp)}</span>
              </div>
              {ev.event_data && (
                <div style={{ marginTop: '0.35rem', color: COLORS.textMuted, fontSize: '0.75rem', fontFamily: 'monospace' }}>
                  {typeof ev.event_data === 'string' ? truncate(ev.event_data, 120) : truncate(JSON.stringify(ev.event_data), 120)}
                </div>
              )}
            </div>
          ))
        )}
      </div>
    </div>
  );
}

function TeachingContentForm({ stage, onSave, saving }) {
  const s = stylesForTheme();
  const [form, setForm] = useState({
    stage_name: stage.stage_name || '',
    stage_description: stage.stage_description || '',
    hints: parseHintsForEdit(stage.hints),
    teaching_objective: stage.teaching_objective || '',
    solution_content: stage.solution_content || '',
  });

  useEffect(() => {
    setForm({
      stage_name: stage.stage_name || '',
      stage_description: stage.stage_description || '',
      hints: parseHintsForEdit(stage.hints),
      teaching_objective: stage.teaching_objective || '',
      solution_content: stage.solution_content || '',
    });
  }, [stage]);

  const update = (key, value) => setForm((prev) => ({ ...prev, [key]: value }));
  const save = () => {
    let hints;
    try {
      hints = JSON.parse(form.hints);
    } catch {
      toast.error('Hints must be valid JSON (array of strings)');
      return;
    }
    if (!Array.isArray(hints) || hints.length > 3 || hints.some((hint) => typeof hint !== 'string')) {
      toast.error('Hints must be an ordered array of up to three strings');
      return;
    }
    onSave(stage.id, { ...form, hints: JSON.stringify(hints) });
  };

  return (
    <section aria-label="Teaching content editor" style={{ ...s.card, marginBottom: '1.25rem', borderLeft: `4px solid ${COLORS.accent}` }}>
      <h3 style={{ ...s.cardTitle, marginBottom: '0.35rem' }}>Teaching content</h3>
      <p style={{ color: COLORS.textMuted, fontSize: '0.8125rem', lineHeight: 1.5, marginTop: 0 }}>
        Learners receive the title, description, objective, and purchased hints. Instructor solution text remains in the admin-only solutions view.
      </p>
      <div style={s.formGrid}>
        <div style={s.formGroup}>
          <label style={s.label}>Stage Name</label>
          <input style={s.input} value={form.stage_name} onChange={(e) => update('stage_name', e.target.value)} />
        </div>
        <div style={s.formGroup}>
          <label style={s.label}>Learner Objective</label>
          <input style={s.input} value={form.teaching_objective} onChange={(e) => update('teaching_objective', e.target.value)} />
        </div>
      </div>
      <div style={s.formGroup}>
        <label style={s.label}>Learner Description</label>
        <textarea style={s.textarea} rows={2} value={form.stage_description} onChange={(e) => update('stage_description', e.target.value)} />
      </div>
      <div style={s.formGroup}>
        <label style={s.label}>Hints (ordered JSON array)</label>
        <textarea style={s.textarea} rows={4} value={form.hints} onChange={(e) => update('hints', e.target.value)} />
      </div>
      <div style={s.formGroup}>
        <label style={s.label}>Instructor Solution (admin only)</label>
        <textarea style={{ ...s.textarea, minHeight: '100px' }} value={form.solution_content} onChange={(e) => update('solution_content', e.target.value)} />
      </div>
      <button type="button" style={s.btn('primary')} onClick={save} disabled={saving}>
        <FiSave /> {saving ? 'Saving…' : 'Save teaching content'}
      </button>
    </section>
  );
}

function StageEditForm({ stage, onSave, onSaveTeaching, onDelete, onPreview, saving }) {
  const s = stylesForTheme();
  const [form, setForm] = useState({
    stage_name: stage.stage_name || '',
    stage_description: stage.stage_description || '',
    system_prompt: stage.system_prompt || '',
    success_criteria: stage.success_criteria || '',
    hints: parseHintsForEdit(stage.hints),
    defense_style: stage.defense_style || '[]',
    adaptive_mode: stage.adaptive_mode || 'none',
    level_score: stage.level_score ?? 100,
    feedback_mode: stage.feedback_mode || 'reason',
  });

  useEffect(() => {
    setForm({
      stage_name: stage.stage_name || '',
      stage_description: stage.stage_description || '',
      system_prompt: stage.system_prompt || '',
      success_criteria: stage.success_criteria || '',
      hints: parseHintsForEdit(stage.hints),
      defense_style: stage.defense_style || '[]',
      adaptive_mode: stage.adaptive_mode || 'none',
      level_score: stage.level_score ?? 100,
      feedback_mode: stage.feedback_mode || 'reason',
    });
  }, [stage]);

  const update = (key, value) => setForm((prev) => ({ ...prev, [key]: value }));

  const handleSave = () => {
    let hintsPayload = form.hints;
    try {
      hintsPayload = JSON.stringify(JSON.parse(form.hints));
    } catch {
      toast.error('Hints must be valid JSON (array of strings)');
      return;
    }
    try {
      JSON.parse(form.defense_style || '[]');
    } catch {
      toast.error('Defense style must be valid JSON');
      return;
    }
    onSave(stage.id, { ...form, hints: hintsPayload });
  };

  return (
    <tr>
      <td colSpan={7} style={{ ...s.td, ...s.expandableRow, padding: '1.25rem' }}>
        <TeachingContentForm stage={stage} onSave={onSaveTeaching} saving={saving} />
        <h3 style={{ ...s.cardTitle, marginTop: 0 }}>Advanced stage controls</h3>
        <div style={s.formGrid}>
          <div style={s.formGroup}>
            <label style={s.label}>Stage Name</label>
            <input style={s.input} value={form.stage_name} onChange={(e) => update('stage_name', e.target.value)} />
          </div>
          <div style={s.formGroup}>
            <label style={s.label}>Adaptive Mode</label>
            <select style={s.select} value={form.adaptive_mode} onChange={(e) => update('adaptive_mode', e.target.value)}>
              {ADAPTIVE_MODES.map((m) => (
                <option key={m} value={m}>{m}</option>
              ))}
            </select>
          </div>
          <div style={s.formGroup}>
            <label style={s.label}>Level Score</label>
            <input style={s.input} type="number" value={form.level_score} onChange={(e) => update('level_score', parseInt(e.target.value, 10) || 0)} />
          </div>
          <div style={s.formGroup}>
            <label style={s.label}>Time Bonus (seconds) — legacy, inactive</label>
            <input aria-label="Legacy inactive time bonus" style={s.input} type="number" value={stage.time_bonus_seconds ?? 300} disabled readOnly />
            <small>Points equal the level score minus hint costs, floored at zero. Rankings compare completed stages, then points, then elapsed time. This legacy value does not affect scoring.</small>
          </div>
          <div style={s.formGroup}>
            <label style={s.label}>Feedback Mode</label>
            <select style={s.select} value={form.feedback_mode} onChange={(e) => update('feedback_mode', e.target.value)}>
              {FEEDBACK_MODES.map((m) => (
                <option key={m} value={m}>{m}</option>
              ))}
            </select>
          </div>
          <div style={s.formGroup}>
            <label style={s.label}>Defense Style (JSON)</label>
            <input style={s.input} value={form.defense_style} onChange={(e) => update('defense_style', e.target.value)} />
          </div>
        </div>
        <div style={s.formGroup}>
          <label style={s.label}>Description</label>
          <textarea style={s.textarea} rows={2} value={form.stage_description} onChange={(e) => update('stage_description', e.target.value)} />
        </div>
        <div style={s.formGroup}>
          <label style={s.label}>System Prompt</label>
          <textarea style={{ ...s.textarea, minHeight: '120px' }} value={form.system_prompt} onChange={(e) => update('system_prompt', e.target.value)} />
        </div>
        <div style={s.formGroup}>
          <label style={s.label}>Success Criteria</label>
          <input style={s.input} value={form.success_criteria} onChange={(e) => update('success_criteria', e.target.value)} />
        </div>
        <div style={s.formGroup}>
          <label style={s.label}>Hints (JSON array)</label>
          <textarea style={s.textarea} rows={4} value={form.hints} onChange={(e) => update('hints', e.target.value)} />
        </div>
        <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap', marginTop: '1rem' }}>
          <button type="button" style={s.btn('primary')} onClick={handleSave} disabled={saving}>
            <FiSave /> {saving ? 'Saving…' : 'Save'}
          </button>
          <button type="button" style={s.btn('ghost')} onClick={() => onPreview(stage)}>
            <FiEye /> Preview
          </button>
          <button
            type="button"
            style={s.btn('danger')}
            onClick={() => {
              if (window.confirm(`Delete stage "${stage.stage_name}"? This cannot be undone.`)) {
                onDelete(stage.id);
              }
            }}
          >
            <FiTrash2 /> Delete
          </button>
        </div>
      </td>
    </tr>
  );
}

function PreviewModal({ stage, onClose }) {
  const s = stylesForTheme();
  const [payload, setPayload] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);

  const runPreview = async () => {
    if (!payload.trim()) {
      toast.error('Enter a payload to preview');
      return;
    }
    setLoading(true);
    setResult(null);
    try {
      const res = await axios.post(
        `/api/ctf/admin/stages/${stage.id}/preview`,
        { payload },
        { headers: getAuthHeaders() }
      );
      setResult(res.data);
    } catch (err) {
      toast.error(err.response?.data?.error || 'Preview failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={s.modalOverlay} onClick={onClose} role="presentation">
      <div style={s.modal} onClick={(e) => e.stopPropagation()} role="dialog" aria-labelledby="preview-title">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
          <h3 id="preview-title" style={{ margin: 0, color: COLORS.accent }}>
            Disclosure Preview: {stage.stage_name}
          </h3>
          <button type="button" style={{ ...s.btn('ghost'), padding: '0.35rem' }} onClick={onClose} aria-label="Close">
            <FiX />
          </button>
        </div>
        <div style={s.formGroup}>
          <label style={s.label}>Test Payload</label>
          <textarea
            style={{ ...s.textarea, minHeight: '100px' }}
            value={payload}
            onChange={(e) => setPayload(e.target.value)}
            placeholder="Enter a prompt injection payload to test…"
          />
        </div>
        <button type="button" style={s.btn('primary')} onClick={runPreview} disabled={loading}>
          {loading ? <FiRefreshCw /> : <FiZap />} {loading ? 'Running…' : 'Run Preview'}
        </button>
        <p style={{ margin: '0.75rem 0 0', fontSize: '0.75rem', color: COLORS.textMuted, lineHeight: 1.5 }}>
          This checks the configured input/output defenses and guardian response. It does not run learner admission,
          adaptive memory, the Objective Judge, progress, or scoring.
        </p>
        {result && (
          <div style={{ marginTop: '1.25rem' }}>
            <div style={s.card}>
              <h4 style={{ margin: '0 0 0.75rem', fontSize: '0.875rem', color: COLORS.accent }}>Classification</h4>
              <p style={{ margin: 0, fontSize: '0.8125rem' }}>
                Tag: <strong>{result.classification?.tag}</strong>
                {' '}({((result.classification?.confidence || 0) * 100).toFixed(0)}% confidence)
              </p>
            </div>
            <div style={s.card}>
              <h4 style={{ margin: '0 0 0.75rem', fontSize: '0.875rem', color: COLORS.accent }}>Defense Result</h4>
              {result.defenseBlocked ? (
                <p style={{ margin: 0, color: COLORS.danger, fontSize: '0.8125rem' }}>
                  Blocked{result.defenseLayer ? ` (layer: ${result.defenseLayer})` : ''}: {result.defenseReason || 'Input blocked'}
                </p>
              ) : (
                <p style={{ margin: 0, color: COLORS.success, fontSize: '0.8125rem' }}>Passed defense layers</p>
              )}
            </div>
            <div style={s.card}>
              <h4 style={{ margin: '0 0 0.35rem', fontSize: '0.875rem', color: COLORS.accent }}>Guardian Draft</h4>
              <p style={{ margin: '0 0 0.75rem', fontSize: '0.75rem', color: COLORS.textMuted }}>
                The disclosure signal below is computed from the post-defense learner-visible response, which may differ from this draft.
              </p>
              <pre style={{
                margin: 0,
                padding: '0.75rem',
                background: COLORS.inputBg,
                borderRadius: '6px',
                fontSize: '0.75rem',
                whiteSpace: 'pre-wrap',
                wordBreak: 'break-word',
                maxHeight: '200px',
                overflow: 'auto',
              }}>
                {result.rawResponse || result.processedResponse || '(no response — blocked or AI unavailable)'}
              </pre>
            </div>
            <div style={{
              padding: '0.75rem',
              borderRadius: '6px',
              background: result.wouldSucceed ? 'rgba(72, 187, 120, 0.2)' : 'rgba(255, 68, 68, 0.2)',
              border: `1px solid ${result.wouldSucceed ? COLORS.success : COLORS.danger}`,
              fontSize: '0.875rem',
              fontWeight: 600,
            }}>
              Learner-visible secret detected: {result.wouldSucceed ? 'yes' : 'no'}
              {result.secretCriteria && (
                <span style={{ display: 'block', marginTop: '0.35rem', fontWeight: 400, color: COLORS.textMuted, fontSize: '0.75rem' }}>
                  Criteria: {result.secretCriteria}
                </span>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

function ConfirmDialog({ open, title, message, confirmLabel = 'Confirm', cancelLabel = 'Cancel', loading: busy, onConfirm, onCancel }) {
  const s = stylesForTheme();
  if (!open) return null;
  return (
    <div style={s.modalOverlay} onClick={onCancel} role="presentation">
      <div style={{ ...s.modal, maxWidth: '440px' }} onClick={(e) => e.stopPropagation()} role="dialog" aria-modal="true" aria-labelledby="confirm-dialog-title">
        <h3 id="confirm-dialog-title" style={{ margin: '0 0 0.75rem', color: COLORS.danger, fontSize: '1.1rem' }}>
          <FiAlertTriangle style={{ verticalAlign: 'middle', marginRight: '0.5rem' }} />
          {title}
        </h3>
        <p style={{ margin: '0 0 1.5rem', color: COLORS.textMuted, fontSize: '0.875rem', lineHeight: 1.5 }}>
          {message}
        </p>
        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.75rem' }}>
          <button type="button" style={s.btn('ghost')} onClick={onCancel} disabled={busy}>
            {cancelLabel}
          </button>
          <button type="button" style={s.btn('danger')} onClick={onConfirm} disabled={busy}>
            {busy ? <><FiRefreshCw style={{ animation: 'spin 1s linear infinite' }} /> Resetting…</> : confirmLabel}
          </button>
        </div>
      </div>
    </div>
  );
}

function CopyablePayload({ text, index }) {
  const s = stylesForTheme();
  const [copied, setCopied] = useState(false);

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      toast.error('Clipboard unavailable — select and copy manually');
    }
  };

  return (
    <div
      style={{
        display: 'flex',
        alignItems: 'flex-start',
        gap: '0.6rem',
        padding: '0.6rem 0.75rem',
        borderBottom: `1px solid ${COLORS.cardBorder}`,
      }}
    >
      <span style={{ ...s.badge(COLORS.accent), flexShrink: 0, marginTop: '0.1rem' }}>{index + 1}</span>
      <code
        style={{
          flex: 1,
          fontSize: '0.8125rem',
          fontFamily: 'Monaco, Menlo, monospace',
          color: COLORS.text,
          whiteSpace: 'pre-wrap',
          wordBreak: 'break-word',
          lineHeight: 1.5,
        }}
      >
        {text}
      </code>
      <button
        type="button"
        title="Copy payload"
        aria-label="Copy payload"
        style={{
          ...s.btn(copied ? 'success' : 'ghost'),
          padding: '0.3rem 0.5rem',
          fontSize: '0.75rem',
          flexShrink: 0,
        }}
        onClick={copy}
      >
        {copied ? <FiCheck /> : <FiCopy />} {copied ? 'Copied' : 'Copy'}
      </button>
    </div>
  );
}

const SOLUTION_APPLICABILITY_COPY = {
  matches_default: {
    label: 'Candidate applies to default; current configuration matches',
    color: COLORS.success,
  },
  differs_from_default: {
    label: 'Candidate applies to default; current configuration differs',
    color: COLORS.warning,
  },
  stage_missing: {
    label: 'Candidate applies to default; current stage missing',
    color: COLORS.danger,
  },
  canonical_default_missing: {
    label: 'Canonical default configuration missing',
    color: COLORS.danger,
  },
  canonical_default_invalid: {
    label: 'Canonical default configuration invalid',
    color: COLORS.danger,
  },
};

const SOLUTION_FIELD_LABELS = {
  system_prompt: 'guardian prompt',
  success_criteria: 'stage secret',
  defense_style: 'defense stack',
  adaptive_mode: 'adaptive mode',
};

function SolutionLevelCard({ level }) {
  const s = stylesForTheme();
  const [open, setOpen] = useState(false);
  const applicability = level.configurationApplicability;
  const applicabilityCopy = applicability
    ? SOLUTION_APPLICABILITY_COPY[applicability.currentConfiguration]
    : null;
  const changedLabels = (applicability?.differingFields || [])
    .map((field) => SOLUTION_FIELD_LABELS[field] || field)
    .join(', ');

  return (
    <div style={{ ...s.card, padding: 0, overflow: 'hidden' }}>
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        style={{
          width: '100%',
          display: 'flex',
          alignItems: 'center',
          gap: '0.75rem',
          padding: '1rem 1.25rem',
          background: 'transparent',
          border: 'none',
          cursor: 'pointer',
          textAlign: 'left',
        }}
      >
        <span style={{ ...s.badge(COLORS.accent), fontSize: '0.8125rem' }}>L{level.level}</span>
        <div style={{ flex: 1 }}>
          <div style={{ fontWeight: 700, fontSize: '0.95rem', color: COLORS.text }}>
            {level.stageName} <span style={{ color: COLORS.textMuted, fontWeight: 500 }}>— {level.guardian}</span>
          </div>
          <div style={{ fontSize: '0.75rem', color: COLORS.textMuted, marginTop: '0.15rem' }}>
            Defenses: {level.defenses}
          </div>
          {applicabilityCopy && (
            <div style={{ marginTop: '0.4rem' }}>
              <span style={{ ...s.badge(applicabilityCopy.color), fontSize: '0.6875rem' }}>
                {applicabilityCopy.label}
              </span>
              {changedLabels && (
                <span style={{ marginLeft: '0.45rem', fontSize: '0.6875rem', color: COLORS.textMuted }}>
                  Changed: {changedLabels}
                </span>
              )}
            </div>
          )}
        </div>
        <code
          style={{
            ...s.badge(COLORS.success),
            fontFamily: 'Monaco, Menlo, monospace',
            fontSize: '0.75rem',
          }}
        >
          {level.secret}
        </code>
        {open ? <FiChevronUp color={COLORS.accent} /> : <FiChevronDown color={COLORS.textMuted} />}
      </button>
      {open && (
        <div style={{ borderTop: `1px solid ${COLORS.cardBorder}` }}>
          {level.note && (
            <p
              style={{
                margin: 0,
                padding: '0.75rem 1.25rem',
                fontSize: '0.8125rem',
                color: COLORS.warning,
                background: 'rgba(221, 107, 32, 0.06)',
                borderBottom: `1px solid ${COLORS.cardBorder}`,
              }}
            >
              {level.note}
            </p>
          )}
          <div>
            {level.payloads.map((p, i) => (
              <CopyablePayload key={i} text={p} index={i} />
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function SolutionsTab() {
  const s = stylesForTheme();
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);

  const fetchSolutions = useCallback(async () => {
    setLoading(true);
    try {
      const res = await axios.get('/api/ctf/admin/solutions', { headers: getAuthHeaders() });
      setData(res.data || null);
    } catch (err) {
      toast.error(err.response?.data?.error || 'Failed to load solutions');
      setData(null);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchSolutions();
  }, [fetchSolutions]);

  if (loading) {
    return <div style={s.loading}><FiRefreshCw /> Loading solutions…</div>;
  }

  if (!data) {
    return (
      <div style={s.card}>
        <p style={{ color: COLORS.textMuted, margin: 0 }}>No solution data available.</p>
        <button type="button" style={{ ...s.btn('ghost'), marginTop: '1rem' }} onClick={fetchSolutions}>
          <FiRefreshCw /> Retry
        </button>
      </div>
    );
  }

  return (
    <div>
      <div
        style={{
          ...s.card,
          borderLeft: `4px solid ${COLORS.danger}`,
          background: COLORS.dangerDim,
          display: 'flex',
          alignItems: 'flex-start',
          justifyContent: 'space-between',
          gap: '1rem',
          flexWrap: 'wrap',
        }}
      >
        <div>
          <h3 style={{ margin: '0 0 0.35rem', color: COLORS.danger, fontSize: '0.95rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <FiKey /> Instructor Payload Candidates — Spoilers
          </h3>
          <p style={{ margin: 0, fontSize: '0.8125rem', color: COLORS.textMuted }}>
            Model-dependent payload candidates for all 10 levels. Verify enabled levels before a workshop; candidates are not guaranteed wins.
          </p>
          {data.comparisonPolicy?.description && (
            <p style={{ margin: '0.35rem 0 0', fontSize: '0.75rem', color: COLORS.textMuted }}>
              Configuration status: {data.comparisonPolicy.description}
            </p>
          )}
        </div>
        <button type="button" style={s.btn('ghost')} onClick={fetchSolutions}>
          <FiRefreshCw /> Refresh
        </button>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '1rem', marginBottom: '1rem' }}>
        <div style={s.card}>
          <h3 style={s.cardTitle}><FiCheck /> How winning works</h3>
          <ul style={{ margin: 0, paddingLeft: '1.1rem', fontSize: '0.8125rem', color: COLORS.text, lineHeight: 1.6 }}>
            {(data.howWinningWorks || []).map((line, i) => (
              <li key={i} style={{ marginBottom: '0.4rem' }}>{line}</li>
            ))}
          </ul>
        </div>
        <div style={s.card}>
          <h3 style={s.cardTitle}><FiZap /> Five payload families and where they stop working</h3>
          {(data.payloadFamilies || []).map((f, i) => (
            <div key={i} style={{ marginBottom: '0.6rem' }}>
              <div style={{ fontWeight: 600, fontSize: '0.8125rem', color: COLORS.accent }}>{f.name}</div>
              <div style={{ fontSize: '0.75rem', color: COLORS.textMuted }}>{f.detail}</div>
            </div>
          ))}
        </div>
      </div>

      {(data.levels || []).map((level) => (
        <React.Fragment key={level.level}>
          <SolutionLevelCard level={level} />
          <div style={{ ...s.card, marginTop: '-0.5rem', marginBottom: '1rem', borderLeft: `4px solid ${COLORS.accent}` }}>
            <h4 style={{ margin: '0 0 0.35rem', fontSize: '0.8125rem', color: COLORS.accent }}>Saved instructor solution</h4>
            <p style={{ margin: 0, fontSize: '0.8125rem', whiteSpace: 'pre-wrap', lineHeight: 1.5 }}>
              {level.instructorSolution || 'No instructor-authored solution saved for this level.'}
            </p>
          </div>
        </React.Fragment>
      ))}

      {(data.instructorNotes || []).length > 0 && (
        <div style={s.card}>
          <h3 style={s.cardTitle}><FiAlertTriangle /> Instructor notes</h3>
          <ul style={{ margin: 0, paddingLeft: '1.1rem', fontSize: '0.8125rem', color: COLORS.text, lineHeight: 1.6 }}>
            {data.instructorNotes.map((note, i) => (
              <li key={i} style={{ marginBottom: '0.4rem' }}>{note}</li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

function LevelsTab() {
  const s = stylesForTheme();
  const recovery = useCtfRecovery();
  const [stages, setStages] = useState([]);
  const [loading, setLoading] = useState(true);
  const [expandedId, setExpandedId] = useState(null);
  const [previewStage, setPreviewStage] = useState(null);
  const [saving, setSaving] = useState(false);
  const [togglingId, setTogglingId] = useState(null);

  const fetchStages = useCallback(async () => {
    setLoading(true);
    try {
      const res = await axios.get('/api/ctf/admin/stages', { headers: getAuthHeaders() });
      setStages(res.data.stages || []);
    } catch (err) {
      if (isCtfRecoveryCancelled(err)) return;
      toast.error(err.response?.data?.error || 'Failed to load stages');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchStages();
  }, [fetchStages]);

  const toggleActive = async (stage) => {
    setTogglingId(stage.id);
    const newActive = stage.is_active ? 0 : 1;
    try {
      await recovery.request('put',
        `/api/ctf/admin/stages/${stage.id}`,
        { is_active: newActive },
        { headers: getAuthHeaders() }
      );
      setStages((prev) => prev.map((st) => (st.id === stage.id ? { ...st, is_active: newActive } : st)));
      toast.success(`Stage ${newActive ? 'activated' : 'deactivated'}`);
    } catch (err) {
      if (isCtfRecoveryCancelled(err)) return;
      toast.error(err.response?.data?.error || 'Failed to toggle stage');
    } finally {
      setTogglingId(null);
    }
  };

  const handleSave = async (id, data) => {
    setSaving(true);
    try {
      await recovery.request('put',`/api/ctf/admin/stages/${id}`, data, { headers: getAuthHeaders() });
      toast.success('Stage saved');
      setExpandedId(null);
      fetchStages();
    } catch (err) {
      if (isCtfRecoveryCancelled(err)) return;
      toast.error(err.response?.data?.error || 'Failed to save stage');
    } finally {
      setSaving(false);
    }
  };

  const handleSaveTeaching = async (id, data) => {
    setSaving(true);
    try {
      await recovery.request('put',`/api/ctf/admin/stages/${id}/content`, data, { headers: getAuthHeaders() });
      toast.success('Teaching content saved');
      fetchStages();
    } catch (err) {
      if (isCtfRecoveryCancelled(err)) return;
      toast.error(err.response?.data?.error || 'Failed to save teaching content');
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = async (id) => {
    try {
      await recovery.request('delete',`/api/ctf/admin/stages/${id}`, undefined, { headers: getAuthHeaders() });
      toast.success('Stage deleted');
      setExpandedId(null);
      fetchStages();
    } catch (err) {
      if (isCtfRecoveryCancelled(err)) return;
      toast.error(err.response?.data?.error || 'Failed to delete stage');
    }
  };

  if (loading) {
    return <div style={s.loading}><FiRefreshCw /> Loading stages…</div>;
  }

  return (
    <div>
      <CtfRecoveryNotice notices={recovery.notices} />
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '1rem' }}>
        <p style={{ margin: 0, color: COLORS.textMuted, fontSize: '0.875rem' }}>
          {stages.length} stage(s) — click a row to edit
        </p>
        <button type="button" style={s.btn('ghost')} onClick={fetchStages}>
          <FiRefreshCw /> Refresh
        </button>
      </div>
      <div style={{ overflowX: 'auto' }}>
        <table style={s.table}>
          <thead>
            <tr>
              <th style={s.th}>#</th>
              <th style={s.th}>Name</th>
              <th style={s.th}>Difficulty</th>
              <th style={s.th}>Adaptive</th>
              <th style={s.th}>Score</th>
              <th style={s.th}>Active</th>
              <th style={s.th} />
            </tr>
          </thead>
          <tbody>
            {stages.map((stage) => (
              <React.Fragment key={stage.id}>
                <tr
                  style={{ cursor: 'pointer' }}
                  onClick={() => setExpandedId(expandedId === stage.id ? null : stage.id)}
                >
                  <td style={s.td}>{stage.stage_number}</td>
                  <td style={s.td}>{stage.stage_name}</td>
                  <td style={s.td}>{stage.difficulty || stage.difficulty_level || '—'}</td>
                  <td style={s.td}>
                    <span style={s.badge(COLORS.accent)}>{stage.adaptive_mode || 'none'}</span>
                  </td>
                  <td style={s.td}>{stage.level_score ?? '—'}</td>
                  <td style={s.td} onClick={(e) => e.stopPropagation()}>
                    <ToggleSwitch
                      checked={!!stage.is_active}
                      disabled={togglingId === stage.id}
                      onChange={() => toggleActive(stage)}
                    />
                  </td>
                  <td style={s.td}>
                    {expandedId === stage.id ? <FiChevronUp color={COLORS.accent} /> : <FiChevronDown color={COLORS.textMuted} />}
                  </td>
                </tr>
                {expandedId === stage.id && (
                  <StageEditForm
                    stage={stage}
                    onSave={handleSave}
                    onSaveTeaching={handleSaveTeaching}
                    onDelete={handleDelete}
                    onPreview={setPreviewStage}
                    saving={saving}
                  />
                )}
              </React.Fragment>
            ))}
          </tbody>
        </table>
      </div>
      {previewStage && (
        <PreviewModal stage={previewStage} onClose={() => setPreviewStage(null)} />
      )}
    </div>
  );
}

function AttemptsTab() {
  const s = stylesForTheme();
  const [attempts, setAttempts] = useState([]);
  const [stages, setStages] = useState([]);
  const [participants, setParticipants] = useState([]);
  const [loading, setLoading] = useState(true);
  const [draftFilters, setDraftFilters] = useState({
    stageId: '',
    blocked: '',
    techniqueTag: '',
    username: '',
  });
  const [appliedFilters, setAppliedFilters] = useState({
    stageId: '',
    blocked: '',
    techniqueTag: '',
    username: '',
  });
  const [limit] = useState(50);
  const [offset, setOffset] = useState(0);
  const [hasMore, setHasMore] = useState(false);

  useEffect(() => {
    const loadMeta = async () => {
      try {
        const [stagesRes, partsRes] = await Promise.all([
          axios.get('/api/ctf/admin/stages', { headers: getAuthHeaders() }),
          axios.get('/api/ctf/admin/participants', { headers: getAuthHeaders() }),
        ]);
        setStages(stagesRes.data.stages || []);
        setParticipants(partsRes.data.participants || []);
      } catch {
        /* optional meta */
      }
    };
    loadMeta();
  }, []);

  const fetchAttempts = useCallback(async () => {
    setLoading(true);
    try {
      const params = { limit, offset };
      if (appliedFilters.stageId) params.stageId = appliedFilters.stageId;
      if (appliedFilters.blocked !== '') params.blocked = appliedFilters.blocked;
      if (appliedFilters.techniqueTag) params.techniqueTag = appliedFilters.techniqueTag;

      if (appliedFilters.username.trim()) {
        const match = participants.find(
          (p) => p.username.toLowerCase().includes(appliedFilters.username.trim().toLowerCase())
        );
        if (match) {
          params.participantId = match.id;
        } else {
          setAttempts([]);
          setHasMore(false);
          setLoading(false);
          return;
        }
      }

      const res = await axios.get('/api/ctf/admin/attempts', {
        headers: getAuthHeaders(),
        params,
      });
      const rows = res.data.attempts || [];
      setAttempts(rows);
      setHasMore(rows.length === limit);
    } catch (err) {
      toast.error(err.response?.data?.error || 'Failed to load attempts');
    } finally {
      setLoading(false);
    }
  }, [appliedFilters, limit, offset, participants]);

  useEffect(() => {
    fetchAttempts();
  }, [fetchAttempts]);

  const applyFilters = () => {
    setOffset(0);
    setAppliedFilters({ ...draftFilters });
  };

  return (
    <div>
      <div style={{ ...s.card, marginBottom: '1rem' }}>
        <h3 style={{ ...s.cardTitle, marginBottom: '0.75rem' }}><FiFilter /> Filters</h3>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '1rem', alignItems: 'flex-end' }}>
          <div>
            <label style={s.label}>Stage</label>
            <select
              style={s.select}
              value={draftFilters.stageId}
              onChange={(e) => setDraftFilters((f) => ({ ...f, stageId: e.target.value }))}
            >
              <option value="">All stages</option>
              {stages.map((st) => (
                <option key={st.id} value={st.id}>{st.stage_number}. {st.stage_name}</option>
              ))}
            </select>
          </div>
          <div>
            <label style={s.label}>Blocked</label>
            <select
              style={s.select}
              value={draftFilters.blocked}
              onChange={(e) => setDraftFilters((f) => ({ ...f, blocked: e.target.value }))}
            >
              <option value="">All</option>
              <option value="true">Blocked only</option>
              <option value="false">Not blocked</option>
            </select>
          </div>
          <div>
            <label style={s.label}>Technique</label>
            <select
              style={s.select}
              value={draftFilters.techniqueTag}
              onChange={(e) => setDraftFilters((f) => ({ ...f, techniqueTag: e.target.value }))}
            >
              <option value="">All techniques</option>
              {TECHNIQUE_TAGS.map((t) => (
                <option key={t} value={t}>{t}</option>
              ))}
            </select>
          </div>
          <div>
            <label style={s.label}>Username</label>
            <input
              style={{ ...s.input, width: '180px' }}
              value={draftFilters.username}
              onChange={(e) => setDraftFilters((f) => ({ ...f, username: e.target.value }))}
              placeholder="Search username…"
            />
          </div>
          <button type="button" style={s.btn('primary')} onClick={applyFilters}>
            <FiFilter /> Apply
          </button>
        </div>
      </div>

      {loading ? (
        <div style={s.loading}><FiRefreshCw /> Loading attempts…</div>
      ) : (
        <>
          <div style={{ overflowX: 'auto' }}>
            <table style={s.table}>
              <thead>
                <tr>
                  <th style={s.th}>Timestamp</th>
                  <th style={s.th}>Username</th>
                  <th style={s.th}>Stage</th>
                  <th style={s.th}>Payload</th>
                  <th style={s.th}>Technique</th>
                  <th style={s.th}>Blocked</th>
                  <th style={s.th}>Success</th>
                </tr>
              </thead>
              <tbody>
                {attempts.length === 0 ? (
                  <tr>
                    <td colSpan={7} style={{ ...s.td, textAlign: 'center', color: COLORS.textMuted }}>
                      No attempts found
                    </td>
                  </tr>
                ) : (
                  attempts.map((a) => (
                    <tr key={a.id}>
                      <td style={s.td}>{formatTimestamp(a.attempt_timestamp)}</td>
                      <td style={s.td}>{a.username}</td>
                      <td style={s.td}>{a.stage_number ? `#${a.stage_number}` : ''} {a.stage_name}</td>
                      <td style={{ ...s.td, fontFamily: 'monospace', fontSize: '0.75rem' }} title={a.payload}>
                        {truncate(a.payload, 60)}
                      </td>
                      <td style={s.td}>
                        {a.technique_tag ? (
                          <span style={s.badge(COLORS.warning)}>{a.technique_tag}</span>
                        ) : '—'}
                      </td>
                      <td style={s.td}>
                        {a.blocked ? (
                          <span style={s.badge(COLORS.danger)}>Yes</span>
                        ) : (
                          <span style={s.badge(COLORS.success)}>No</span>
                        )}
                      </td>
                      <td style={s.td}>
                        {a.was_successful ? (
                          <FiCheck color={COLORS.success} />
                        ) : (
                          <FiX color={COLORS.textMuted} />
                        )}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
          <div style={s.pagination}>
            <span style={{ color: COLORS.textMuted, fontSize: '0.8125rem' }}>
              Showing {attempts.length} result(s) — offset {offset}
            </span>
            <div style={{ display: 'flex', gap: '0.5rem' }}>
              <button
                type="button"
                style={s.btn('ghost')}
                disabled={offset === 0}
                onClick={() => setOffset((o) => Math.max(0, o - limit))}
              >
                <FiChevronLeft /> Previous
              </button>
              <button
                type="button"
                style={s.btn('ghost')}
                disabled={!hasMore}
                onClick={() => setOffset((o) => o + limit)}
              >
                Next <FiChevronRight />
              </button>
            </div>
          </div>
        </>
      )}
    </div>
  );
}

function LeaderboardTab() {
  const s = stylesForTheme();
  const recovery = useCtfRecovery();
  const [leaderboard, setLeaderboard] = useState([]);
  const [participants, setParticipants] = useState([]);
  const [bannedUserIds, setBannedUserIds] = useState(new Set());
  const [loading, setLoading] = useState(true);
  const [actionUserId, setActionUserId] = useState(null);
  const [resetTarget, setResetTarget] = useState(null);
  const [resetting, setResetting] = useState(false);
  const participantResetRef = useRef(false);
  const [removeTarget, setRemoveTarget] = useState(null);
  const [removing, setRemoving] = useState(false);

  const participantByLeaderId = useMemo(() => {
    const map = {};
    participants.forEach((p) => {
      map[p.id] = p;
    });
    return map;
  }, [participants]);

  const fetchData = useCallback(async () => {
    setLoading(true);
    try {
      const [lbRes, partsRes] = await Promise.all([
        axios.get('/api/ctf/leaderboard', { headers: getAuthHeaders(), params: { limit: 50 } }),
        axios.get('/api/ctf/admin/participants', { headers: getAuthHeaders() }),
      ]);
      setLeaderboard(lbRes.data.leaderboard || []);
      setParticipants(partsRes.data.participants || []);
    } catch (err) {
      if (isCtfRecoveryCancelled(err)) return;
      toast.error(err.response?.data?.error || 'Failed to load leaderboard');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  const getUserId = (entry) => {
    const p = participantByLeaderId[entry.participant_id];
    return p?.user_id;
  };

  const confirmReset = async () => {
    if (!resetTarget || participantResetRef.current) return;
    const userId = getUserId(resetTarget);
    if (!userId) {
      toast.error('Could not resolve user ID for this participant');
      setResetTarget(null);
      return;
    }
    participantResetRef.current = true;
    setResetting(true);
    setActionUserId(userId);
    try {
      await recovery.request('post',`/api/ctf/admin/participants/${userId}/reset`, {}, { headers: getAuthHeaders() });
      toast.success(`${resetTarget.username} reset successfully`);
      fetchData();
    } catch (err) {
      if (isCtfRecoveryCancelled(err)) return;
      toast.error(err.response?.data?.error || 'Reset failed');
    } finally {
      participantResetRef.current = false;
      setActionUserId(null);
      setResetting(false);
      setResetTarget(null);
    }
  };

  const confirmRemove = async () => {
    if (!removeTarget) return;
    const userId = getUserId(removeTarget);
    if (!userId) {
      toast.error('Could not resolve user ID for this participant');
      setRemoveTarget(null);
      return;
    }
    setRemoving(true);
    setActionUserId(userId);
    try {
      await recovery.request('post',`/api/ctf/admin/participants/${userId}/remove`, {}, { headers: getAuthHeaders() });
      toast.success(`${removeTarget.username} removed from CTF`);
      fetchData();
    } catch (err) {
      if (isCtfRecoveryCancelled(err)) return;
      toast.error(err.response?.data?.error || 'Remove failed');
    } finally {
      setActionUserId(null);
      setRemoving(false);
      setRemoveTarget(null);
    }
  };

  const handleBan = async (entry) => {
    const userId = getUserId(entry);
    if (!userId) {
      toast.error('Could not resolve user ID');
      return;
    }
    const reason = window.prompt(`Ban reason for ${entry.username}:`, 'Banned by admin');
    if (reason === null) return;
    setActionUserId(userId);
    try {
      await recovery.request('post',
        `/api/ctf/admin/participants/${userId}/ban`,
        { reason },
        { headers: getAuthHeaders() }
      );
      toast.success(`${entry.username} banned`);
      setBannedUserIds((prev) => new Set([...prev, userId]));
    } catch (err) {
      if (isCtfRecoveryCancelled(err)) return;
      toast.error(err.response?.data?.error || 'Ban failed');
    } finally {
      setActionUserId(null);
    }
  };

  const handleUnban = async (entry) => {
    const userId = getUserId(entry);
    if (!userId) return;
    setActionUserId(userId);
    try {
      await recovery.request('post',`/api/ctf/admin/participants/${userId}/unban`, {}, { headers: getAuthHeaders() });
      toast.success(`${entry.username} unbanned`);
      setBannedUserIds((prev) => {
        const next = new Set(prev);
        next.delete(userId);
        return next;
      });
    } catch (err) {
      if (isCtfRecoveryCancelled(err)) return;
      toast.error(err.response?.data?.error || 'Unban failed');
    } finally {
      setActionUserId(null);
    }
  };

  if (loading) {
    return <div style={s.loading}><FiRefreshCw /> Loading leaderboard…</div>;
  }

  return (
    <div>
      <CtfRecoveryNotice notices={recovery.notices} />
      <div style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: '1rem' }}>
        <button type="button" style={s.btn('ghost')} onClick={fetchData}>
          <FiRefreshCw /> Refresh
        </button>
      </div>
      <div style={{ overflowX: 'auto' }}>
        <table style={s.table}>
          <thead>
            <tr>
              <th style={s.th}>Rank</th>
              <th style={s.th}>Username</th>
              <th style={s.th}>Team</th>
              <th style={s.th}>Stages</th>
              <th style={s.th}>Total Time</th>
              <th style={s.th}>Attempts</th>
              <th style={s.th}>Success Rate</th>
              <th style={s.th}>Score</th>
              <th style={s.th}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {leaderboard.length === 0 ? (
              <tr>
                <td colSpan={9} style={{ ...s.td, textAlign: 'center', color: COLORS.textMuted }}>
                  No leaderboard entries yet
                </td>
              </tr>
            ) : (
              leaderboard.map((entry) => {
                const userId = getUserId(entry);
                const isBanned = userId && bannedUserIds.has(userId);
                const busy = actionUserId === userId;
                return (
                  <tr key={entry.participant_id}>
                    <td style={s.td}>#{entry.rank_position ?? '—'}</td>
                    <td style={s.td}>
                      {entry.username}
                      {isBanned && (
                        <span style={{ ...s.badge(COLORS.danger), marginLeft: '0.5rem' }}>banned</span>
                      )}
                    </td>
                    <td style={s.td}>{entry.team_name || '—'}</td>
                    <td style={s.td}>{entry.total_stages_completed ?? 0}</td>
                    <td style={s.td}>{formatDuration(entry.total_completion_time)}</td>
                    <td style={s.td}>{entry.total_attempts ?? 0}</td>
                    <td style={s.td}>
                      {entry.success_rate != null ? `${Number(entry.success_rate).toFixed(1)}%` : '—'}
                    </td>
                    <td style={s.td}>{entry.total_score ?? 0}</td>
                    <td style={s.td}>
                      <div style={{ display: 'flex', gap: '0.35rem', flexWrap: 'wrap' }}>
                        <button
                          type="button"
                          style={{ ...s.btn('ghost'), padding: '0.35rem 0.5rem', fontSize: '0.75rem' }}
                          disabled={busy}
                          onClick={() => setResetTarget(entry)}
                        >
                          Reset
                        </button>
                        {isBanned ? (
                          <button
                            type="button"
                            style={{ ...s.btn('success'), padding: '0.35rem 0.5rem', fontSize: '0.75rem' }}
                            disabled={busy}
                            onClick={() => handleUnban(entry)}
                          >
                            Unban
                          </button>
                        ) : (
                          <button
                            type="button"
                            style={{ ...s.btn('danger'), padding: '0.35rem 0.5rem', fontSize: '0.75rem' }}
                            disabled={busy}
                            onClick={() => handleBan(entry)}
                          >
                            <FiUserX /> Ban
                          </button>
                        )}
                        <button
                          type="button"
                          style={{ ...s.btn('ghost'), padding: '0.35rem 0.5rem', fontSize: '0.75rem', color: COLORS.warning }}
                          disabled={busy}
                          onClick={() => setRemoveTarget(entry)}
                        >
                          <FiTrash2 /> Remove
                        </button>
                      </div>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>
      <ConfirmDialog
        open={!!resetTarget}
        title="Reset participant progress"
        message={resetTarget ? `Progress, attempts, and per-player technique blocks for "${resetTarget.username}" will be permanently deleted. The participant will remain registered and start from Level 1 again. Shared winning-payload fingerprints remain active for everyone.` : ''}
        confirmLabel="Reset Progress"
        loading={resetting}
        onConfirm={confirmReset}
        onCancel={() => setResetTarget(null)}
      />
      <ConfirmDialog
        open={!!removeTarget}
        title="Remove participant from CTF"
        message={removeTarget ? `"${removeTarget.username}" will be completely removed from the CTF. All their progress, attempts, and leaderboard data will be deleted. They will be able to re-register and start the CTF from scratch.` : ''}
        confirmLabel="Remove from CTF"
        loading={removing}
        onConfirm={confirmRemove}
        onCancel={() => setRemoveTarget(null)}
      />
    </div>
  );
}

function ConfigTab() {
  const s = stylesForTheme();
  const recovery = useCtfRecovery();
  const [config, setConfig] = useState({});
  const [loading, setLoading] = useState(true);
  const [savingKey, setSavingKey] = useState(null);

  const fetchConfig = useCallback(async () => {
    setLoading(true);
    try {
      const res = await axios.get('/api/ctf/config', { headers: getAuthHeaders() });
      setConfig(res.data.config || {});
    } catch (err) {
      if (isCtfRecoveryCancelled(err)) return;
      toast.error(err.response?.data?.error || 'Failed to load config (is CTF enabled?)');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchConfig();
  }, [fetchConfig]);

  const saveConfig = async (key, value) => {
    setSavingKey(key);
    try {
      await recovery.request('post','/api/ctf/admin/config', { key, value: String(value) }, { headers: getAuthHeaders() });
      setConfig((prev) => ({ ...prev, [key]: String(value) }));
      toast.success(`${CONFIG_LABELS[key] || key} updated`);
    } catch (err) {
      if (isCtfRecoveryCancelled(err)) return;
      toast.error(err.response?.data?.error || 'Failed to save config');
    } finally {
      setSavingKey(null);
    }
  };

  const editableKeys = Object.keys(CONFIG_LABELS);

  if (loading) {
    return <div style={s.loading}><FiRefreshCw /> Loading configuration…</div>;
  }

  return (
    <div>
      <CtfRecoveryNotice notices={recovery.notices} />
      <div style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: '1rem' }}>
        <button type="button" style={s.btn('ghost')} onClick={fetchConfig}>
          <FiRefreshCw /> Refresh
        </button>
      </div>
      <div style={s.card}>
        {editableKeys.map((key) => {
          const value = config[key] ?? '';
          const isBool = BOOLEAN_CONFIG_KEYS.has(key);
          const isSaving = savingKey === key;

          return (
            <div
              key={key}
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                padding: '0.875rem 0',
                borderBottom: `1px solid ${COLORS.cardBorder}`,
                gap: '1rem',
                flexWrap: 'wrap',
              }}
            >
              <div>
                <div style={{ fontWeight: 600, fontSize: '0.875rem' }}>{CONFIG_LABELS[key]}</div>
                <div style={{ fontSize: '0.75rem', color: COLORS.textMuted, fontFamily: 'monospace' }}>{key}</div>
              </div>
              {isBool ? (
                <ToggleSwitch
                  checked={value === 'true'}
                  disabled={isSaving}
                  onChange={(on) => saveConfig(key, on ? 'true' : 'false')}
                />
              ) : (
                <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
                  <input
                    style={{ ...s.input, width: '160px' }}
                    value={value}
                    onChange={(e) => setConfig((prev) => ({ ...prev, [key]: e.target.value }))}
                  />
                  <button
                    type="button"
                    style={s.btn('primary')}
                    disabled={isSaving}
                    onClick={() => saveConfig(key, config[key])}
                  >
                    <FiSave /> {isSaving ? '…' : 'Save'}
                  </button>
                </div>
              )}
            </div>
          );
        })}
        {READONLY_CONFIG_KEYS.has('current_participants') && config.current_participants != null && (
          <div style={{ marginTop: '1rem', fontSize: '0.8125rem', color: COLORS.textMuted }}>
            Current participants: {config.current_participants}
            {config.registration_available != null && (
              <> — Registration {config.registration_available ? 'open' : 'closed'}</>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

function DangerZoneTab() {
  const s = stylesForTheme();
  const recovery = useCtfRecovery();
  const [resetConfirm, setResetConfirm] = useState('');
  const [resetDialogOpen, setResetDialogOpen] = useState(false);
  const [loading, setLoading] = useState(null);
  const destructiveActionRef = useRef(null);

  const clearBlocklist = async (type) => {
    const label = type === 'technique' ? 'technique' : 'payload';
    if (destructiveActionRef.current) return;
    if (!window.confirm(`Clear the entire ${label} blocklist?`)) return;
    if (destructiveActionRef.current) return;
    destructiveActionRef.current = type;
    setLoading(type);
    try {
      const res = await recovery.request('post',
        `/api/ctf/admin/blocklists/${type}/clear`,
        {},
        { headers: getAuthHeaders() }
      );
      toast.success(res.data.message || `${label} blocklist cleared`);
    } catch (err) {
      if (isCtfRecoveryCancelled(err)) return;
      toast.error(err.response?.data?.error || `Failed to clear ${label} blocklist`);
    } finally {
      destructiveActionRef.current = null;
      setLoading(null);
    }
  };

  const fullReset = async () => {
    if (resetConfirm !== 'RESET_CTF_CONFIRM' || destructiveActionRef.current) return;
    destructiveActionRef.current = 'reset';
    setResetDialogOpen(false);
    setLoading('reset');
    try {
      const res = await recovery.request('post',
        '/api/ctf/admin/reset',
        { confirm: 'RESET_CTF_CONFIRM' },
        { headers: getAuthHeaders() }
      );
      toast.success(res.data.message || 'CTF reset successfully');
      setResetConfirm('');
    } catch (err) {
      if (isCtfRecoveryCancelled(err)) return;
      toast.error(err.response?.data?.error || 'CTF reset failed');
    } finally {
      destructiveActionRef.current = null;
      setLoading(null);
    }
  };

  const requestFullReset = () => {
    if (resetConfirm !== 'RESET_CTF_CONFIRM' || destructiveActionRef.current) return;
    setResetDialogOpen(true);
  };

  const destructiveBusy = Boolean(loading);

  return (
    <div style={s.dangerZone}>
      <CtfRecoveryNotice notices={recovery.notices} />
      <h3 style={{ margin: '0 0 0.5rem', color: COLORS.danger, display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
        <FiAlertTriangle /> Danger Zone
      </h3>
      <p style={{ color: COLORS.textMuted, fontSize: '0.875rem', marginBottom: '1.5rem' }}>
        Destructive actions — use with caution. These cannot be undone.
      </p>

      <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
        <div style={s.card}>
          <h4 style={{ margin: '0 0 0.5rem', fontSize: '0.9375rem' }}>Clear Technique Blocklist</h4>
          <p style={{ margin: '0 0 1rem', fontSize: '0.8125rem', color: COLORS.textMuted }}>
            Removes all per-user technique blocks across all stages.
          </p>
          <button
            type="button"
            style={s.btn('danger')}
            disabled={destructiveBusy}
            onClick={() => clearBlocklist('technique')}
          >
            {loading === 'technique' ? <FiRefreshCw /> : <FiTrash2 />}
            {loading === 'technique' ? ' Clearing…' : ' Clear Technique Blocklist'}
          </button>
        </div>

        <div style={s.card}>
          <h4 style={{ margin: '0 0 0.5rem', fontSize: '0.9375rem' }}>Clear Payload Blocklist</h4>
          <p style={{ margin: '0 0 1rem', fontSize: '0.8125rem', color: COLORS.textMuted }}>
            Removes all community payload blocks across all stages.
          </p>
          <button
            type="button"
            style={s.btn('danger')}
            disabled={destructiveBusy}
            onClick={() => clearBlocklist('payload')}
          >
            {loading === 'payload' ? <FiRefreshCw /> : <FiTrash2 />}
            {loading === 'payload' ? ' Clearing…' : ' Clear Payload Blocklist'}
          </button>
        </div>

        <div style={s.card}>
          <h4 style={{ margin: '0 0 0.5rem', fontSize: '0.9375rem', color: COLORS.danger }}>Full CTF Reset</h4>
          <p style={{ margin: '0 0 1rem', fontSize: '0.8125rem', color: COLORS.textMuted }}>
            Wipes all participants, progress, attempts, events, sessions, blocklists, and leaderboard data.
          </p>
          <label style={s.label}>
            Type <code style={{ color: COLORS.danger }}>RESET_CTF_CONFIRM</code> to enable reset
          </label>
          <input
            style={{ ...s.input, maxWidth: '320px', marginBottom: '1rem' }}
            value={resetConfirm}
            onChange={(e) => setResetConfirm(e.target.value)}
            placeholder="RESET_CTF_CONFIRM"
          />
          <br />
          <button
            type="button"
            style={{
              ...s.btn('danger'),
              opacity: resetConfirm === 'RESET_CTF_CONFIRM' ? 1 : 0.4,
              cursor: resetConfirm === 'RESET_CTF_CONFIRM' ? 'pointer' : 'not-allowed',
            }}
            disabled={resetConfirm !== 'RESET_CTF_CONFIRM' || destructiveBusy || resetDialogOpen}
            onClick={requestFullReset}
          >
            {loading === 'reset' ? <FiRefreshCw /> : <FiAlertTriangle />}
            {loading === 'reset' ? ' Resetting…' : ' Full CTF Reset'}
          </button>
        </div>
      </div>
      <ResetConfirmation
        open={resetDialogOpen}
        status={loading === 'reset' ? 'resetting' : 'confirming'}
        title="Reset the entire CTF?"
        description="This deletes all CTF participants, progress, attempts, events, sessions, blocklists, and leaderboard data."
        onCancel={() => { if (!destructiveActionRef.current) setResetDialogOpen(false); }}
        onConfirm={fullReset}
      />
    </div>
  );
}

function CTFAdminPanel() {
  const [activeTab, setActiveTab] = useState('overview');
  const [analytics, setAnalytics] = useState(null);
  const [analyticsLoading, setAnalyticsLoading] = useState(false);
  const s = stylesForTheme();

  const fetchAnalytics = useCallback(async () => {
    setAnalyticsLoading(true);
    try {
      const res = await axios.get('/api/ctf/admin/analytics', { headers: getAuthHeaders() });
      setAnalytics(res.data.analytics || null);
    } catch (err) {
      toast.error(err.response?.data?.error || 'Failed to load analytics');
      setAnalytics(null);
    } finally {
      setAnalyticsLoading(false);
    }
  }, []);

  useEffect(() => {
    if (activeTab === 'overview') {
      fetchAnalytics();
    }
  }, [activeTab, fetchAnalytics]);

  const renderTabContent = () => {
    switch (activeTab) {
      case 'overview':
        return (
          <OverviewTab
            analytics={analytics}
            loading={analyticsLoading}
            onRefresh={fetchAnalytics}
          />
        );
      case 'levels':
        return <LevelsTab />;
      case 'solutions':
        return <SolutionsTab />;
      case 'attempts':
        return <AttemptsTab />;
      case 'leaderboard':
        return <LeaderboardTab />;
      case 'config':
        return <ConfigTab />;
      case 'danger':
        return <DangerZoneTab />;
      default:
        return null;
    }
  };

  return (
    <div style={s.container}>
      <div style={{ marginBottom: '1.25rem' }}>
        <h2 style={{
          margin: 0,
          fontSize: '1.5rem',
          fontWeight: 800,
          color: COLORS.accent,
          display: 'flex',
          alignItems: 'center',
          gap: '0.5rem',
        }}>
          <FiShield /> CTF Management
        </h2>
        <p style={{ margin: '0.35rem 0 0', color: COLORS.textMuted, fontSize: '0.875rem' }}>
          Configure stages, monitor attempts, manage leaderboard, and control CTF settings
        </p>
      </div>

      <nav style={s.tabBar} aria-label="CTF admin sections">
        {TABS.map(({ id, label, icon: Icon }) => (
          <button
            key={id}
            type="button"
            style={s.tab(activeTab === id)}
            onClick={() => setActiveTab(id)}
            aria-selected={activeTab === id}
          >
            <Icon size={16} />
            {label}
          </button>
        ))}
      </nav>

      <div>{renderTabContent()}</div>
    </div>
  );
}

export default CTFAdminPanel;
