import React, { useState, useEffect, useCallback, useMemo, useRef } from 'react';
import styled from 'styled-components';
import { motion } from 'framer-motion';
import { toast } from 'react-toastify';
import { useNavigate } from 'react-router-dom';
import {
  FiUsers, FiTarget, FiClock, FiTrendingUp, FiRefreshCw,
  FiDownload, FiAward, FiActivity, FiChevronUp, FiChevronDown, FiSearch
} from 'react-icons/fi';
import axios from 'axios';
import useChangePolling from '../../hooks/useChangePolling';

// ── styled components ────────────────────────────────────────────────────────

const SectionHeader = styled.div`
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 1.5rem;

  h2 {
    font-size: 1.5rem;
    font-weight: 700;
    color: #1a202c;
    margin: 0;
  }
`;

const Actions = styled.div`
  display: flex;
  gap: 0.75rem;
`;

const Btn = styled.button`
  display: flex;
  align-items: center;
  gap: 0.4rem;
  padding: 0.5rem 1rem;
  border: 1px solid #e2e8f0;
  border-radius: 8px;
  background: ${p => p.$primary ? '#667eea' : 'white'};
  color: ${p => p.$primary ? 'white' : '#4a5568'};
  font-weight: 600;
  font-size: 0.85rem;
  cursor: pointer;
  transition: all 0.15s;
  &:hover { opacity: 0.85; }
  &:disabled { opacity: 0.5; cursor: default; }
`;

const KPIGrid = styled.div`
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
  gap: 1.25rem;
  margin-bottom: 2rem;
`;

const KPICard = styled(motion.div)`
  background: white;
  border-radius: 14px;
  padding: 1.5rem;
  box-shadow: 0 2px 8px rgba(0,0,0,0.06);
  border: 1px solid #e2e8f0;
  display: flex;
  align-items: center;
  gap: 1.25rem;

  .icon-wrap {
    width: 52px; height: 52px;
    border-radius: 14px;
    display: flex; align-items: center; justify-content: center;
    font-size: 1.3rem;
    background: ${p => p.$bg || '#667eea20'};
    color: ${p => p.$fg || '#667eea'};
  }
  .kpi-body { flex: 1; }
  .kpi-value { font-size: 1.75rem; font-weight: 800; color: #1a202c; }
  .kpi-label { color: #718096; font-size: 0.85rem; font-weight: 500; margin-top: 2px; }
  .kpi-delta { font-size: 0.78rem; color: #10b981; margin-top: 4px; display: flex; align-items: center; gap: 3px; }
`;

const Card = styled(motion.div)`
  background: white;
  border-radius: 14px;
  padding: 1.5rem;
  box-shadow: 0 2px 8px rgba(0,0,0,0.06);
  border: 1px solid #e2e8f0;
  margin-bottom: 1.5rem;

  h3 {
    font-size: 1.15rem;
    font-weight: 700;
    color: #1a202c;
    margin: 0 0 1.25rem 0;
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }
`;

const Grid2 = styled.div`
  display: grid;
  grid-template-columns: 2fr 1fr;
  gap: 1.5rem;
  margin-bottom: 1.5rem;
  @media (max-width: 1024px) { grid-template-columns: 1fr; }
`;

const Table = styled.table`
  width: 100%;
  border-collapse: collapse;
  th, td { padding: 0.75rem 1rem; text-align: left; border-bottom: 1px solid #edf2f7; }
  th { background: #f8fafc; font-weight: 700; color: #1a202c; font-size: 0.82rem; text-transform: uppercase; letter-spacing: 0.04em; white-space: nowrap; cursor: pointer; user-select: none; }
  th:hover { color: #667eea; }
  tbody tr { transition: background 0.15s; }
  tbody tr:hover { background: #f7fafc; }
`;

const SortIcon = styled.span`
  margin-left: 4px;
  font-size: 0.7rem;
  vertical-align: middle;
`;

const ProgressBar = styled.div`
  height: 8px;
  background: #edf2f7;
  border-radius: 99px;
  overflow: hidden;
  min-width: 80px;
  .fill {
    height: 100%;
    border-radius: 99px;
    transition: width 0.4s ease;
    background: ${p => {
      const pct = p.$pct || 0;
      if (pct >= 75) return '#48bb78';
      if (pct >= 50) return '#ed8936';
      if (pct >= 25) return '#ecc94b';
      return '#f56565';
    }};
    width: ${p => p.$pct || 0}%;
  }
`;

const DiffBadge = styled.span`
  display: inline-block;
  padding: 0.2rem 0.5rem;
  border-radius: 4px;
  font-size: 0.75rem;
  font-weight: 600;
  background: ${p => {
    switch (p.$d) {
      case 'beginner': case 'easy': return '#f0fff4';
      case 'intermediate': return '#e6fffa';
      case 'advanced': return '#feebc8';
      case 'expert': return '#fed7d7';
      default: return '#edf2f7';
    }
  }};
  color: ${p => {
    switch (p.$d) {
      case 'beginner': case 'easy': return '#22543d';
      case 'intermediate': return '#234e52';
      case 'advanced': return '#c05621';
      case 'expert': return '#c53030';
      default: return '#4a5568';
    }
  }};
  text-transform: capitalize;
`;

const BarChart = styled.div`
  display: flex;
  align-items: flex-end;
  gap: 6px;
  height: 180px;
  padding: 0 0 1.5rem 0;
  position: relative;
`;

const Bar = styled(motion.div)`
  flex: 1;
  border-radius: 4px 4px 0 0;
  background: linear-gradient(180deg, #667eea, #764ba2);
  position: relative;
  min-height: 4px;

  .bar-label {
    position: absolute;
    bottom: -1.4rem;
    left: 50%;
    transform: translateX(-50%);
    font-size: 0.65rem;
    color: #718096;
    white-space: nowrap;
  }
  .bar-val {
    position: absolute;
    top: -1.4rem;
    left: 50%;
    transform: translateX(-50%);
    font-size: 0.7rem;
    font-weight: 600;
    color: #1a202c;
  }
`;

const RankBadge = styled.div`
  width: 28px; height: 28px;
  border-radius: 50%;
  background: ${p => p.$i < 3 ? '#f59e0b' : '#e2e8f0'};
  color: ${p => p.$i < 3 ? 'white' : '#4a5568'};
  display: flex; align-items: center; justify-content: center;
  font-weight: 700;
  font-size: 0.8rem;
  flex-shrink: 0;
`;

const Spinner = styled.div`
  display: flex; justify-content: center; align-items: center; height: 240px;
  font-size: 1.6rem; color: #667eea;
  svg { animation: spin 1s linear infinite; }
  @keyframes spin { to { transform: rotate(360deg); } }
`;

const Empty = styled.div`
  display: flex; flex-direction: column; align-items: center; justify-content: center;
  height: 200px; color: #718096; text-align: center;
  h4 { margin: 0.5rem 0 0.25rem; }
  p { margin: 0; font-size: 0.9rem; }
`;

const TableToolbar = styled.div`
  display: flex;
  flex-wrap: wrap;
  justify-content: space-between;
  align-items: center;
  gap: 0.75rem;
  margin-bottom: 1rem;
`;

const SearchBox = styled.div`
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.5rem 0.75rem;
  border: 1px solid #e2e8f0;
  border-radius: 8px;
  background: #f8fafc;
  min-width: 240px;
  flex: 1;
  max-width: 360px;

  svg { color: #a0aec0; flex-shrink: 0; }
  input {
    border: none;
    background: transparent;
    outline: none;
    width: 100%;
    font-size: 0.9rem;
    color: #1a202c;
    &::placeholder { color: #a0aec0; }
  }
`;

const TableMeta = styled.div`
  font-size: 0.85rem;
  color: #718096;
`;

const Pagination = styled.div`
  display: flex;
  align-items: center;
  justify-content: space-between;
  flex-wrap: wrap;
  gap: 0.75rem;
  margin-top: 1rem;
  padding-top: 1rem;
  border-top: 1px solid #edf2f7;
`;

const PageButtons = styled.div`
  display: flex;
  align-items: center;
  gap: 0.35rem;
`;

const PageBtn = styled.button`
  min-width: 36px;
  height: 36px;
  padding: 0 0.5rem;
  border: 1px solid ${p => p.$active ? '#667eea' : '#e2e8f0'};
  border-radius: 8px;
  background: ${p => p.$active ? '#667eea' : 'white'};
  color: ${p => p.$active ? 'white' : '#4a5568'};
  font-weight: ${p => p.$active ? 700 : 500};
  font-size: 0.85rem;
  cursor: ${p => p.disabled ? 'default' : 'pointer'};
  opacity: ${p => p.disabled ? 0.45 : 1};
  transition: all 0.15s;
  &:hover:not(:disabled) { border-color: #667eea; color: ${p => p.$active ? 'white' : '#667eea'}; }
`;

const PAGE_SIZE = 10;

// ── helpers ──────────────────────────────────────────────────────────────────

function parseTs(ts) {
  if (!ts) return null;
  if (typeof ts === 'string' && /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/.test(ts))
    return new Date(ts.replace(' ', 'T') + 'Z');
  return new Date(ts);
}

function fmtTime(minutes) {
  if (!minutes || minutes <= 0) return '0m';
  if (minutes < 60) return `${Math.round(minutes)}m`;
  const h = Math.floor(minutes / 60);
  const m = Math.round(minutes % 60);
  return m > 0 ? `${h}h ${m}m` : `${h}h`;
}

function fmtRelative(ts) {
  const d = parseTs(ts);
  if (!d || Number.isNaN(d.getTime())) return 'Never';
  const diff = Date.now() - d.getTime();
  if (diff < 0) return d.toLocaleString();
  if (diff < 60_000) return 'Just now';
  if (diff < 3600_000) return `${Math.floor(diff / 60_000)}m ago`;
  if (diff < 86400_000) return `${Math.floor(diff / 3600_000)}h ago`;
  return d.toLocaleDateString();
}

// ── component ────────────────────────────────────────────────────────────────

export default function ProgressAnalyticsPanel() {
  const navigate = useNavigate();
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [sortKey, setSortKey] = useState('objectivesCompleted');
  const [sortDir, setSortDir] = useState('desc');
  const [searchQuery, setSearchQuery] = useState('');
  const [currentPage, setCurrentPage] = useState(1);
  const mountedRef = useRef(false);
  const requestSequenceRef = useRef(0);
  const foregroundInFlightRef = useRef(null);

  const fetchData = useCallback(({ background = false, signal } = {}) => {
    const run = async () => {
      if (background && foregroundInFlightRef.current) {
        await foregroundInFlightRef.current.catch(() => {});
      }
      const requestId = ++requestSequenceRef.current;
      try {
        if (!background && mountedRef.current) setLoading(true);
        const token = localStorage.getItem('token');
        const res = await axios.get('/api/admin/analytics/progress', {
          headers: { Authorization: `Bearer ${token}` },
          timeout: 30000,
          signal,
        });
        if (!mountedRef.current || signal?.aborted || requestId !== requestSequenceRef.current) return null;
        setData(res.data);
        return res.data;
      } catch (err) {
        if ((err.response?.status === 401 || err.response?.status === 403)
          && mountedRef.current && requestId === requestSequenceRef.current) {
          setData(null);
        }
        if (background) throw err;
        if (mountedRef.current && requestId === requestSequenceRef.current) {
          console.error('Failed to load analytics:', err);
          toast.error('Failed to load analytics: ' + (err.response?.data?.error || err.message));
        }
        return null;
      } finally {
        if (!background && mountedRef.current) setLoading(false);
      }
    };

    const request = run();
    if (!background) {
      foregroundInFlightRef.current = request;
      void request.finally(() => {
        if (foregroundInFlightRef.current === request) foregroundInFlightRef.current = null;
      });
    }
    return request;
  }, []);

  useEffect(() => {
    mountedRef.current = true;
    void fetchData();
    return () => {
      mountedRef.current = false;
      requestSequenceRef.current += 1;
      foregroundInFlightRef.current = null;
    };
  }, [fetchData]);

  useChangePolling((_next, _previous, { signal } = {}) => fetchData({ background: true, signal }));

  const exportCsv = useCallback(() => {
    if (!data?.studentProgress?.length) { toast.error('No data to export'); return; }
    const header = 'Username,Objectives Completed,Total Objectives,Completion %,Workshops In Progress,Last Activity,Time Spent';
    const rows = data.studentProgress.map(s =>
      [s.username, s.objectivesCompleted, s.totalEnabledObjectives, s.completionPercentage,
       s.workshopsInProgress, s.lastActivity || '', fmtTime(s.totalTimeMinutes)].join(',')
    );
    const blob = new Blob([header + '\n' + rows.join('\n')], { type: 'text/csv' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `student_progress_${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    URL.revokeObjectURL(a.href);
    toast.success('CSV exported');
  }, [data]);

  const toggleSort = useCallback((key) => {
    setSortKey(prev => {
      if (prev === key) { setSortDir(d => d === 'asc' ? 'desc' : 'asc'); return key; }
      setSortDir('desc');
      return key;
    });
  }, []);

  const sortedStudents = useMemo(() => {
    if (!data?.studentProgress) return [];
    const arr = [...data.studentProgress];
    arr.sort((a, b) => {
      let av = a[sortKey], bv = b[sortKey];
      if (typeof av === 'string') { av = av.toLowerCase(); bv = (bv || '').toLowerCase(); }
      if (av == null) av = sortDir === 'asc' ? Infinity : -Infinity;
      if (bv == null) bv = sortDir === 'asc' ? Infinity : -Infinity;
      return sortDir === 'asc' ? (av > bv ? 1 : -1) : (av < bv ? 1 : -1);
    });
    return arr;
  }, [data, sortKey, sortDir]);

  const filteredStudents = useMemo(() => {
    const q = searchQuery.trim().toLowerCase();
    if (!q) return sortedStudents;
    return sortedStudents.filter(s => (s.username || '').toLowerCase().includes(q));
  }, [sortedStudents, searchQuery]);

  const totalPages = Math.max(1, Math.ceil(filteredStudents.length / PAGE_SIZE));

  const paginatedStudents = useMemo(() => {
    const start = (currentPage - 1) * PAGE_SIZE;
    return filteredStudents.slice(start, start + PAGE_SIZE);
  }, [filteredStudents, currentPage]);

  useEffect(() => {
    setCurrentPage(1);
  }, [searchQuery, sortKey, sortDir]);

  useEffect(() => {
    if (currentPage > totalPages) setCurrentPage(totalPages);
  }, [currentPage, totalPages]);

  const pageNumbers = useMemo(() => {
    const pages = [];
    const maxVisible = 5;
    let start = Math.max(1, currentPage - Math.floor(maxVisible / 2));
    let end = Math.min(totalPages, start + maxVisible - 1);
    start = Math.max(1, end - maxVisible + 1);
    for (let i = start; i <= end; i++) pages.push(i);
    return pages;
  }, [currentPage, totalPages]);

  if (loading && !data) {
    return <Spinner><FiRefreshCw /></Spinner>;
  }
  if (!data) {
    return (
      <Empty>
        <FiActivity size={48} style={{ marginBottom: '1rem', opacity: 0.5 }} />
        <h4>No Analytics Data</h4>
        <p>Could not load analytics. <Btn onClick={fetchData}><FiRefreshCw /> Retry</Btn></p>
      </Empty>
    );
  }

  const ov = data.overview || {};
  const timeline = data.progressOverTime || [];
  const maxComp = Math.max(1, ...timeline.map(d => d.completions));

  const SortArrow = ({ col }) => {
    if (sortKey !== col) return null;
    return <SortIcon>{sortDir === 'asc' ? <FiChevronUp /> : <FiChevronDown />}</SortIcon>;
  };

  return (
    <div>
      <SectionHeader>
        <h2>Student Progress Analytics</h2>
        <Actions>
          <Btn onClick={fetchData} disabled={loading}><FiRefreshCw /> Refresh</Btn>
          <Btn $primary onClick={exportCsv}><FiDownload /> Export CSV</Btn>
        </Actions>
      </SectionHeader>

      {/* ── KPI cards ─────────────────────────────────────────── */}
      <KPIGrid>
        <KPICard $bg="#10b98120" $fg="#10b981" initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.05 }}>
          <div className="icon-wrap"><FiUsers /></div>
          <div className="kpi-body">
            <div className="kpi-value">{ov.activeStudents || 0}<span style={{ fontSize: '0.9rem', color: '#718096', fontWeight: 500 }}> / {ov.totalStudents || 0}</span></div>
            <div className="kpi-label">Active Students (30d)</div>
          </div>
        </KPICard>
        <KPICard $bg="#667eea20" $fg="#667eea" initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }}>
          <div className="icon-wrap"><FiTarget /></div>
          <div className="kpi-body">
            <div className="kpi-value">{ov.totalObjectiveCompletions || 0}</div>
            <div className="kpi-label">Objective Completions</div>
            {ov.completionsThisWeek > 0 && <div className="kpi-delta"><FiTrendingUp /> +{ov.completionsThisWeek} this week</div>}
          </div>
        </KPICard>
        <KPICard $bg="#f59e0b20" $fg="#f59e0b" initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.15 }}>
          <div className="icon-wrap"><FiClock /></div>
          <div className="kpi-body">
            <div className="kpi-value">{fmtTime(ov.avgSessionMinutes)}</div>
            <div className="kpi-label">Avg Time per Student</div>
          </div>
        </KPICard>
        <KPICard $bg="#ef444420" $fg="#ef4444" initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.2 }}>
          <div className="icon-wrap"><FiAward /></div>
          <div className="kpi-body">
            <div className="kpi-value">{ov.platformCompletionRate || 0}%</div>
            <div className="kpi-label">Platform Completion Rate</div>
          </div>
        </KPICard>
      </KPIGrid>

      {/* ── Exercise breakdown + Top Performers ───────────────── */}
      <Grid2>
        <Card initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.25 }}>
          <h3><FiActivity /> Exercise Breakdown</h3>
          <div style={{ overflowX: 'auto' }}>
            <Table>
              <thead>
                <tr>
                  <th>Exercise</th>
                  <th>Difficulty</th>
                  <th>Objectives</th>
                  <th>Started</th>
                  <th>Completed</th>
                  <th>Rate</th>
                  <th>Avg Time</th>
                </tr>
              </thead>
              <tbody>
                {(data.challengeStats || []).map(c => (
                  <tr key={c.challengeKey}>
                    <td style={{ fontWeight: 500 }}>{c.challengeName}</td>
                    <td><DiffBadge $d={c.difficulty}>{c.difficulty}</DiffBadge></td>
                    <td>{c.enabledObjectives}</td>
                    <td>{c.studentsStarted}</td>
                    <td>{c.studentsCompleted}</td>
                    <td>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                        <ProgressBar $pct={c.completionRate}><div className="fill" /></ProgressBar>
                        <span style={{ fontSize: '0.8rem', color: '#4a5568', minWidth: 32 }}>{c.completionRate}%</span>
                      </div>
                    </td>
                    <td style={{ color: '#718096', fontSize: '0.85rem' }}>{fmtTime(c.avgTimeMinutes)}</td>
                  </tr>
                ))}
                {(!data.challengeStats || data.challengeStats.length === 0) && (
                  <tr><td colSpan={7} style={{ textAlign: 'center', color: '#a0aec0', padding: '2rem' }}>No exercises found</td></tr>
                )}
              </tbody>
            </Table>
          </div>
        </Card>

        <Card initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.3 }}>
          <h3><FiAward /> Top Performers</h3>
          {(data.topStudents || []).length === 0 ? (
            <Empty style={{ height: 140 }}><p>No student completions yet</p></Empty>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
              {data.topStudents.map((s, i) => (
                <div key={s.id} style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', cursor: 'pointer' }}
                     onClick={() => navigate(`/admin/student-workshop-view?studentId=${s.id}`)}>
                  <RankBadge $i={i}>{i + 1}</RankBadge>
                  <div style={{ flex: 1 }}>
                    <div style={{ fontWeight: 600, color: '#1a202c', marginBottom: 4 }}>{s.username}</div>
                    <ProgressBar $pct={s.completionPercentage}><div className="fill" /></ProgressBar>
                    <div style={{ fontSize: '0.75rem', color: '#718096', marginTop: 3 }}>
                      {s.objectivesCompleted}/{s.totalEnabledObjectives} objectives &middot; {fmtTime(s.totalTimeMinutes)}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </Card>
      </Grid2>

      {/* ── Timeline bar chart ────────────────────────────────── */}
      {timeline.length > 0 && (
        <Card initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.35 }}>
          <h3><FiTrendingUp /> Completions (Last 30 Days)</h3>
          <BarChart>
            {timeline.slice().reverse().map((d, i) => (
              <Bar key={d.date}
                   style={{ height: `${Math.max(4, (d.completions / maxComp) * 100)}%` }}
                   initial={{ height: 0 }}
                   animate={{ height: `${Math.max(4, (d.completions / maxComp) * 100)}%` }}
                   transition={{ delay: 0.4 + i * 0.03, duration: 0.5 }}>
                <div className="bar-val">{d.completions}</div>
                <div className="bar-label">{d.date.slice(5)}</div>
              </Bar>
            ))}
          </BarChart>
        </Card>
      )}

      {/* ── Student progress table ────────────────────────────── */}
      <Card initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.4 }}>
        <h3><FiUsers /> Student Progress</h3>
        <TableToolbar>
          <SearchBox>
            <FiSearch size={16} />
            <input
              type="text"
              placeholder="Search students by username..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              aria-label="Search students"
            />
          </SearchBox>
          <TableMeta>
            {filteredStudents.length === 0
              ? 'No students match your search'
              : `Showing ${(currentPage - 1) * PAGE_SIZE + 1}–${Math.min(currentPage * PAGE_SIZE, filteredStudents.length)} of ${filteredStudents.length} student${filteredStudents.length === 1 ? '' : 's'}`}
          </TableMeta>
        </TableToolbar>
        <div style={{ overflowX: 'auto' }}>
          <Table>
            <thead>
              <tr>
                <th onClick={() => toggleSort('username')}>Student<SortArrow col="username" /></th>
                <th onClick={() => toggleSort('objectivesCompleted')}>Completed<SortArrow col="objectivesCompleted" /></th>
                <th onClick={() => toggleSort('completionPercentage')}>Progress<SortArrow col="completionPercentage" /></th>
                <th onClick={() => toggleSort('workshopsInProgress')}>Workshops<SortArrow col="workshopsInProgress" /></th>
                <th onClick={() => toggleSort('totalTimeMinutes')}>Time<SortArrow col="totalTimeMinutes" /></th>
                <th onClick={() => toggleSort('lastActivity')}>Last Activity<SortArrow col="lastActivity" /></th>
              </tr>
            </thead>
            <tbody>
              {paginatedStudents.map(s => (
                <tr key={s.id} style={{ cursor: 'pointer' }}
                    onClick={() => navigate(`/admin/student-workshop-view?studentId=${s.id}`)}>
                  <td style={{ fontWeight: 600 }}>{s.username}</td>
                  <td>{s.objectivesCompleted} / {s.totalEnabledObjectives}</td>
                  <td>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                      <ProgressBar $pct={s.completionPercentage}><div className="fill" /></ProgressBar>
                      <span style={{ fontSize: '0.8rem', color: '#4a5568', minWidth: 32 }}>{s.completionPercentage}%</span>
                    </div>
                  </td>
                  <td>{s.workshopsInProgress}</td>
                  <td style={{ color: '#718096', fontSize: '0.85rem' }}>{fmtTime(s.totalTimeMinutes)}</td>
                  <td style={{ color: '#718096', fontSize: '0.85rem' }}>{fmtRelative(s.lastActivity)}</td>
                </tr>
              ))}
              {filteredStudents.length === 0 && (
                <tr><td colSpan={6} style={{ textAlign: 'center', color: '#a0aec0', padding: '2rem' }}>
                  {searchQuery.trim() ? `No students found matching "${searchQuery.trim()}"` : 'No student data yet'}
                </td></tr>
              )}
            </tbody>
          </Table>
        </div>
        {filteredStudents.length > PAGE_SIZE && (
          <Pagination>
            <TableMeta>Page {currentPage} of {totalPages}</TableMeta>
            <PageButtons>
              <PageBtn disabled={currentPage === 1} onClick={() => setCurrentPage(p => Math.max(1, p - 1))}>
                Prev
              </PageBtn>
              {pageNumbers[0] > 1 && (
                <>
                  <PageBtn onClick={() => setCurrentPage(1)}>1</PageBtn>
                  {pageNumbers[0] > 2 && <span style={{ color: '#a0aec0', padding: '0 0.25rem' }}>…</span>}
                </>
              )}
              {pageNumbers.map(page => (
                <PageBtn key={page} $active={page === currentPage} onClick={() => setCurrentPage(page)}>
                  {page}
                </PageBtn>
              ))}
              {pageNumbers[pageNumbers.length - 1] < totalPages && (
                <>
                  {pageNumbers[pageNumbers.length - 1] < totalPages - 1 && <span style={{ color: '#a0aec0', padding: '0 0.25rem' }}>…</span>}
                  <PageBtn onClick={() => setCurrentPage(totalPages)}>{totalPages}</PageBtn>
                </>
              )}
              <PageBtn disabled={currentPage === totalPages} onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))}>
                Next
              </PageBtn>
            </PageButtons>
          </Pagination>
        )}
      </Card>

      {/* ── Difficulty breakdown ──────────────────────────────── */}
      {data.difficultyBreakdown && Object.keys(data.difficultyBreakdown).length > 0 && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '1.25rem' }}>
          {Object.entries(data.difficultyBreakdown).map(([diff, d]) => (
            <Card key={diff} initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }}>
              <h3 style={{ textTransform: 'capitalize' }}>{diff} Exercises</h3>
              <div style={{ display: 'grid', gap: '0.5rem', fontSize: '0.9rem', color: '#4a5568' }}>
                <div>Exercises: <strong>{d.totalChallenges}</strong></div>
                <div>Objectives: <strong>{d.totalObjectives}</strong></div>
                <div>Completions: <strong>{d.completed}</strong></div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  Rate: <ProgressBar $pct={d.completionRate} style={{ flex: 1 }}><div className="fill" /></ProgressBar>
                  <strong>{d.completionRate}%</strong>
                </div>
              </div>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}
