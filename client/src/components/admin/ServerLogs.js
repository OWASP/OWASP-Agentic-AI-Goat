import React, { useState, useEffect, useCallback, useRef } from 'react';
import {
  FiRefreshCw, FiDownload, FiSearch, FiActivity, FiCpu,
  FiAlertTriangle, FiChevronDown, FiChevronUp, FiCheckCircle, FiXCircle, FiUser
} from 'react-icons/fi';
import styled from 'styled-components';
import { toast } from 'react-toastify';

// ─── Styled Components ────────────────────────────────────────────────────────

const Container = styled.div`
  display: flex;
  flex-direction: column;
  height: 100%;
`;

const PageHeader = styled.div`
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 2rem;
  flex-wrap: wrap;
  gap: 1rem;

  h2 {
    margin: 0;
    color: #1a202c;
    font-size: 1.5rem;
  }

  .header-actions {
    display: flex;
    gap: 0.75rem;
  }
`;

const InnerTabBar = styled.div`
  display: flex;
  border-bottom: 2px solid #e2e8f0;
  margin-bottom: 1.5rem;
  gap: 0;
`;

const InnerTab = styled.button`
  padding: 0.75rem 1.5rem;
  border: none;
  background: none;
  cursor: pointer;
  font-size: 0.9rem;
  font-weight: 500;
  color: ${({ active }) => (active ? '#667eea' : '#718096')};
  border-bottom: 3px solid ${({ active }) => (active ? '#667eea' : 'transparent')};
  margin-bottom: -2px;
  transition: all 0.2s ease;
  display: flex;
  align-items: center;
  gap: 0.5rem;

  &:hover {
    color: #667eea;
  }
`;

const FiltersBar = styled.div`
  display: flex;
  gap: 1rem;
  margin-bottom: 1.5rem;
  flex-wrap: wrap;
  align-items: center;

  @media (max-width: 768px) {
    flex-direction: column;
    align-items: stretch;
  }
`;

const LevelButton = styled.button`
  padding: 0.5rem 1rem;
  border-radius: 6px;
  border: 2px solid ${({ active, color }) => (active ? color || '#667eea' : '#e2e8f0')};
  background: ${({ active, bg }) => (active ? bg || '#eef2ff' : 'white')};
  color: ${({ active, color }) => (active ? color || '#667eea' : '#718096')};
  font-weight: 500;
  cursor: pointer;
  font-size: 0.8rem;
  transition: all 0.2s ease;

  &:hover {
    border-color: ${({ color }) => color || '#667eea'};
  }
`;

const SearchBox = styled.div`
  position: relative;
  flex: 1;
  max-width: 320px;

  input {
    width: 100%;
    padding: 0.6rem 1rem 0.6rem 2.4rem;
    border: 2px solid #e2e8f0;
    border-radius: 8px;
    font-size: 0.875rem;
    transition: all 0.2s ease;
    box-sizing: border-box;

    &:focus {
      outline: none;
      border-color: #667eea;
      box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
    }
  }

  .search-icon {
    position: absolute;
    left: 0.75rem;
    top: 50%;
    transform: translateY(-50%);
    color: #9ca3af;
  }
`;

const MiniSearchBox = styled.div`
  position: relative;

  input {
    padding: 0.5rem 0.75rem 0.5rem 2rem;
    border: 2px solid #e2e8f0;
    border-radius: 8px;
    font-size: 0.8rem;
    width: 140px;
    transition: all 0.2s ease;
    box-sizing: border-box;

    &:focus {
      outline: none;
      border-color: #667eea;
      box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
      width: 180px;
    }
  }

  .icon {
    position: absolute;
    left: 0.5rem;
    top: 50%;
    transform: translateY(-50%);
    color: #9ca3af;
  }
`;

const FilterSelect = styled.select`
  padding: 0.6rem 1rem;
  border: 2px solid #e2e8f0;
  border-radius: 8px;
  background: white;
  min-width: 140px;
  cursor: pointer;
  font-size: 0.875rem;

  &:focus {
    outline: none;
    border-color: #667eea;
  }
`;

const ActionButton = styled.button`
  padding: 0.6rem 1.25rem;
  border: none;
  border-radius: 8px;
  font-weight: 500;
  cursor: pointer;
  display: flex;
  align-items: center;
  gap: 0.5rem;
  transition: all 0.2s ease;
  font-size: 0.875rem;
  background: ${({ variant }) => (variant === 'primary' ? '#667eea' : variant === 'danger' ? '#fc8181' : '#f7fafc')};
  color: ${({ variant }) => (variant === 'primary' || variant === 'danger' ? 'white' : '#4a5568')};
  border: ${({ variant }) => (variant === 'primary' || variant === 'danger' ? 'none' : '1px solid #e2e8f0')};

  &:hover {
    opacity: 0.85;
  }

  &:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }
`;

const ToggleButton = styled.button`
  padding: 0.6rem 1.25rem;
  border-radius: 8px;
  border: 1px solid #e2e8f0;
  background: ${({ active }) => (active ? '#e0e7ff' : '#f7fafc')};
  color: ${({ active }) => (active ? '#4f46e5' : '#4a5568')};
  font-size: 0.875rem;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s ease;
`;

const LogTable = styled.div`
  background: white;
  border-radius: 12px;
  overflow: hidden;
  border: 1px solid #e2e8f0;
`;

const LogEntry = styled.div`
  border-bottom: 1px solid #f1f5f9;
  cursor: pointer;
  transition: background 0.15s ease;

  &:hover {
    background: #fafbfc;
  }

  &:last-child {
    border-bottom: none;
  }
`;

const LogEntryRow = styled.div`
  display: flex;
  align-items: center;
  gap: 0.75rem;
  padding: 0.75rem 1rem;
`;

const Timestamp = styled.span`
  font-family: 'Courier New', monospace;
  font-size: 0.75rem;
  color: #718096;
  min-width: 165px;
  white-space: nowrap;
`;

const LEVEL_STYLES = {
  error: { bg: '#fee2e2', color: '#991b1b' },
  warn:  { bg: '#fef3c7', color: '#92400e' },
  info:  { bg: '#dbeafe', color: '#1e40af' },
  debug: { bg: '#f3f4f6', color: '#374151' }
};

const LevelBadge = styled.span`
  display: inline-block;
  padding: 0.2rem 0.6rem;
  border-radius: 4px;
  font-size: 0.7rem;
  font-weight: 700;
  letter-spacing: 0.05em;
  background: ${({ level }) => (LEVEL_STYLES[level] || LEVEL_STYLES.info).bg};
  color: ${({ level }) => (LEVEL_STYLES[level] || LEVEL_STYLES.info).color};
  min-width: 46px;
  text-align: center;
`;

const UserBadge = styled.span`
  display: inline-flex;
  align-items: center;
  gap: 0.25rem;
  padding: 0.15rem 0.5rem;
  border-radius: 4px;
  font-size: 0.72rem;
  font-weight: 500;
  background: #f0fdf4;
  color: #166534;
  white-space: nowrap;
  max-width: 120px;
  overflow: hidden;
  text-overflow: ellipsis;
`;

const IpBadge = styled.span`
  font-family: 'Courier New', monospace;
  font-size: 0.72rem;
  color: #6b7280;
  white-space: nowrap;
`;

const LogMessage = styled.span`
  flex: 1;
  font-size: 0.875rem;
  color: #374151;
  word-break: break-word;
`;

const MetaBlock = styled.pre`
  margin: 0 1rem 0.75rem 1rem;
  padding: 0.75rem;
  background: #f8fafc;
  border: 1px solid #e2e8f0;
  border-radius: 6px;
  font-size: 0.75rem;
  font-family: 'Courier New', monospace;
  overflow-x: auto;
  color: #4a5568;
  white-space: pre-wrap;
  word-break: break-all;
`;

const EmptyState = styled.div`
  padding: 3rem;
  text-align: center;
  color: #718096;
  font-size: 0.9rem;
`;

const LoadMoreButton = styled.button`
  width: 100%;
  padding: 0.75rem;
  background: #f8fafc;
  border: none;
  border-top: 1px solid #e2e8f0;
  color: #4a5568;
  cursor: pointer;
  font-size: 0.875rem;
  font-weight: 500;
  transition: background 0.2s ease;

  &:hover {
    background: #edf2f7;
  }
`;

// LLM table — added User + IP columns
const LlmTableHeader = styled.div`
  display: grid;
  grid-template-columns: 150px minmax(90px,1fr) 100px 90px 120px 70px 60px auto;
  background: #f8fafc;
  border-bottom: 1px solid #e2e8f0;
  font-weight: 600;
  color: #374151;
  font-size: 0.8rem;
`;

const LlmHeaderCell = styled.div`
  padding: 0.75rem 0.75rem;
`;

const LlmRow = styled.div`
  display: grid;
  grid-template-columns: 150px minmax(90px,1fr) 100px 90px 120px 70px 60px auto;
  border-bottom: 1px solid #f1f5f9;
  font-size: 0.82rem;
  cursor: pointer;
  transition: background 0.15s ease;

  &:hover { background: #fafbfc; }
  &:last-child { border-bottom: none; }
`;

const LlmCell = styled.div`
  padding: 0.65rem 0.75rem;
  color: #4a5568;
  display: flex;
  align-items: center;
  overflow: hidden;
  white-space: nowrap;
  text-overflow: ellipsis;
`;

// Stats cards
const StatsGrid = styled.div`
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 1.5rem;
  margin-bottom: 2rem;
`;

const StatCard = styled.div`
  background: white;
  border-radius: 12px;
  padding: 1.5rem;
  border: 1px solid #e2e8f0;
  box-shadow: 0 1px 3px rgba(0,0,0,0.05);

  .label {
    font-size: 0.8rem;
    color: #718096;
    margin-bottom: 0.5rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }

  .value {
    font-size: 2rem;
    font-weight: 700;
    color: ${({ color }) => color || '#1a202c'};
  }

  .sub {
    font-size: 0.75rem;
    color: #a0aec0;
    margin-top: 0.25rem;
  }
`;

const TopErrorsCard = styled.div`
  background: white;
  border-radius: 12px;
  padding: 1.5rem;
  border: 1px solid #e2e8f0;
  box-shadow: 0 1px 3px rgba(0,0,0,0.05);

  h3 {
    margin: 0 0 1rem;
    font-size: 1rem;
    color: #1a202c;
  }
`;

const ErrorItem = styled.div`
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0.6rem 0;
  border-bottom: 1px solid #f1f5f9;
  font-size: 0.85rem;

  &:last-child { border-bottom: none; }

  .msg { color: #4a5568; flex: 1; font-family: monospace; }
  .count {
    background: #fee2e2;
    color: #991b1b;
    font-weight: 700;
    padding: 0.2rem 0.6rem;
    border-radius: 999px;
    font-size: 0.75rem;
    min-width: 32px;
    text-align: center;
  }
`;

// ─── Helpers ──────────────────────────────────────────────────────────────────

const formatUser = (username, userId) => {
  if (username && userId) return `${username} (#${userId})`;
  if (username) return username;
  if (userId) return `#${userId}`;
  return null;
};

// ─── Component ────────────────────────────────────────────────────────────────

export default function ServerLogs() {
  const [activeTab, setActiveTab] = useState('app');

  // ── App Logs state ──
  const [appLogs,        setAppLogs]        = useState([]);
  const [appLoading,     setAppLoading]     = useState(false);
  const [appLevel,       setAppLevel]       = useState('all');
  const [appSearch,      setAppSearch]      = useState('');
  const [appLines,       setAppLines]       = useState(100);
  const [appAutoRefresh, setAppAutoRefresh] = useState(false);
  const [expandedApp,    setExpandedApp]    = useState(null);
  const [hideHttp,       setHideHttp]       = useState(true);

  // ── LLM Logs state ──
  const [llmLogs,      setLlmLogs]      = useState([]);
  const [llmLoading,   setLlmLoading]   = useState(false);
  const [llmProvider,  setLlmProvider]  = useState('');
  const [llmSuccess,   setLlmSuccess]   = useState('');
  const [llmLines,     setLlmLines]     = useState(100);
  const [expandedLlm,  setExpandedLlm]  = useState(null);
  const [llmUserSearch, setLlmUserSearch] = useState('');
  const [llmIpSearch,   setLlmIpSearch]   = useState('');

  // ── Stats state ──
  const [stats,        setStats]        = useState(null);
  const [statsLoading, setStatsLoading] = useState(false);

  const autoRefreshTimer = useRef(null);
  const searchTimer      = useRef(null);
  const llmSearchTimer   = useRef(null);

  const getToken = () => localStorage.getItem('adminToken') || localStorage.getItem('token') || '';

  // ── Fetch functions ──
  const fetchAppLogs = useCallback(async (lines) => {
    const n = lines || appLines;
    setAppLoading(true);
    try {
      const params = new URLSearchParams({ lines: n });
      if (appLevel && appLevel !== 'all') params.append('level', appLevel);
      if (appSearch) params.append('search', appSearch);
      params.append('hideHttp', hideHttp ? 'true' : 'false');
      const res = await fetch(`/api/admin/logs/app?${params}`, {
        headers: { Authorization: `Bearer ${getToken()}` }
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      setAppLogs(data.logs || []);
    } catch (err) {
      toast.error('Failed to load app logs');
    } finally {
      setAppLoading(false);
    }
  }, [appLevel, appSearch, appLines, hideHttp]);

  const fetchLlmLogs = useCallback(async (lines) => {
    const n = lines || llmLines;
    setLlmLoading(true);
    try {
      const params = new URLSearchParams({ lines: n });
      if (llmProvider)   params.append('provider', llmProvider);
      if (llmSuccess)    params.append('success',  llmSuccess);
      if (llmUserSearch) params.append('username', llmUserSearch);
      if (llmIpSearch)   params.append('ip',       llmIpSearch);
      const res = await fetch(`/api/admin/logs/llm?${params}`, {
        headers: { Authorization: `Bearer ${getToken()}` }
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      setLlmLogs(data.logs || []);
    } catch (err) {
      toast.error('Failed to load LLM logs');
    } finally {
      setLlmLoading(false);
    }
  }, [llmProvider, llmSuccess, llmLines, llmUserSearch, llmIpSearch]);

  const fetchStats = useCallback(async () => {
    setStatsLoading(true);
    try {
      const res = await fetch('/api/admin/logs/stats', {
        headers: { Authorization: `Bearer ${getToken()}` }
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      setStats(data);
    } catch (err) {
      toast.error('Failed to load log stats');
    } finally {
      setStatsLoading(false);
    }
  }, []);

  // Load on tab change or filter change
  useEffect(() => {
    if (activeTab === 'app')   fetchAppLogs();
    if (activeTab === 'llm')   fetchLlmLogs();
    if (activeTab === 'stats') fetchStats();
  }, [activeTab, appLevel, llmProvider, llmSuccess, hideHttp]); // eslint-disable-line react-hooks/exhaustive-deps

  // Auto-refresh for app logs
  useEffect(() => {
    clearInterval(autoRefreshTimer.current);
    if (appAutoRefresh && activeTab === 'app') {
      autoRefreshTimer.current = setInterval(() => fetchAppLogs(), 30000);
    }
    return () => clearInterval(autoRefreshTimer.current);
  }, [appAutoRefresh, activeTab, fetchAppLogs]);

  // Stats auto-refresh (60s)
  useEffect(() => {
    if (activeTab !== 'stats') return;
    const t = setInterval(fetchStats, 60000);
    return () => clearInterval(t);
  }, [activeTab, fetchStats]);

  // Debounced search
  const handleSearchChange = (val) => {
    setAppSearch(val);
    clearTimeout(searchTimer.current);
    searchTimer.current = setTimeout(() => fetchAppLogs(), 400);
  };

  const handleLlmUserSearchChange = (val) => {
    setLlmUserSearch(val);
    clearTimeout(llmSearchTimer.current);
    llmSearchTimer.current = setTimeout(() => fetchLlmLogs(), 500);
  };

  const handleLlmIpSearchChange = (val) => {
    setLlmIpSearch(val);
    clearTimeout(llmSearchTimer.current);
    llmSearchTimer.current = setTimeout(() => fetchLlmLogs(), 500);
  };

  const downloadAppLogs = () => {
    const blob = new Blob(
      [appLogs.map(l => JSON.stringify(l)).join('\n')],
      { type: 'application/json' }
    );
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `app-logs-${new Date().toISOString().split('T')[0]}.jsonl`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const formatTs = (ts) => {
    if (!ts) return '\u2014';
    try { return new Date(ts).toLocaleString(); } catch (_) { return ts; }
  };

  const formatLatency = (ms) => {
    if (ms == null) return '\u2014';
    return ms >= 1000 ? `${(ms / 1000).toFixed(1)}s` : `${ms}ms`;
  };

  // ── Render: App Logs ──────────────────────────────────────────────────────
  const renderAppLogs = () => (
    <>
      <FiltersBar>
        {['all', 'error', 'warn', 'info'].map(lvl => (
          <LevelButton
            key={lvl}
            active={appLevel === lvl}
            color={lvl === 'error' ? '#991b1b' : lvl === 'warn' ? '#92400e' : lvl === 'info' ? '#1e40af' : '#667eea'}
            bg={lvl === 'error' ? '#fee2e2' : lvl === 'warn' ? '#fef3c7' : lvl === 'info' ? '#dbeafe' : '#eef2ff'}
            onClick={() => setAppLevel(lvl)}
          >
            {lvl.toUpperCase()}
          </LevelButton>
        ))}
        <SearchBox>
          <FiSearch className="search-icon" size={14} />
          <input
            placeholder="Search logs..."
            value={appSearch}
            onChange={e => handleSearchChange(e.target.value)}
          />
        </SearchBox>
        <ToggleButton active={!hideHttp} onClick={() => setHideHttp(v => !v)}>
          {hideHttp ? 'Show HTTP' : 'Hide HTTP'}
        </ToggleButton>
        <ToggleButton active={appAutoRefresh} onClick={() => setAppAutoRefresh(v => !v)}>
          {appAutoRefresh ? 'Auto-refresh ON' : 'Auto-refresh'}
        </ToggleButton>
        <ActionButton onClick={downloadAppLogs}>
          <FiDownload size={14} /> Download
        </ActionButton>
        <ActionButton variant="primary" onClick={() => fetchAppLogs()} disabled={appLoading}>
          <FiRefreshCw size={14} style={{ animation: appLoading ? 'spin 1s linear infinite' : 'none' }} />
          {appLoading ? 'Loading...' : 'Refresh'}
        </ActionButton>
      </FiltersBar>

      <LogTable>
        {appLoading && appLogs.length === 0 ? (
          <EmptyState>Loading logs...</EmptyState>
        ) : appLogs.length === 0 ? (
          <EmptyState>
            No logs found.{hideHttp ? ' HTTP access entries are hidden \u2014 click "Show HTTP" to include them.' : ''}
            {' '}Workshop events (errors, tool calls, completions) appear here automatically.
          </EmptyState>
        ) : (
          [...appLogs].reverse().map((log, i) => (
            <LogEntry key={i} onClick={() => setExpandedApp(expandedApp === i ? null : i)}>
              <LogEntryRow>
                <Timestamp>{formatTs(log.timestamp)}</Timestamp>
                <LevelBadge level={(log.level || 'info').toLowerCase()}>
                  {(log.level || 'INFO').toUpperCase()}
                </LevelBadge>
                {(log.username || log.userId) && (
                  <UserBadge title={formatUser(log.username, log.userId)}>
                    <FiUser size={10} /> {log.username || `#${log.userId}`}
                  </UserBadge>
                )}
                {log.ip && <IpBadge title={log.ip}>{log.ip}</IpBadge>}
                <LogMessage>{log.message}</LogMessage>
                {expandedApp === i ? <FiChevronUp size={14} color="#718096" /> : <FiChevronDown size={14} color="#718096" />}
              </LogEntryRow>
              {expandedApp === i && log.meta && Object.keys(log.meta).length > 0 && (
                <MetaBlock>{JSON.stringify(log.meta, null, 2)}</MetaBlock>
              )}
            </LogEntry>
          ))
        )}
        {appLogs.length >= appLines && (
          <LoadMoreButton onClick={() => { const n = appLines + 100; setAppLines(n); fetchAppLogs(n); }}>
            Load 100 more
          </LoadMoreButton>
        )}
      </LogTable>
    </>
  );

  // ── Render: LLM Logs ──────────────────────────────────────────────────────
  const renderLlmLogs = () => (
    <>
      <FiltersBar>
        <FilterSelect value={llmProvider} onChange={e => setLlmProvider(e.target.value)}>
          <option value="">All Providers</option>
          <option value="ollama">Ollama</option>
          <option value="bedrock">Bedrock</option>
          <option value="openai">OpenAI</option>
          <option value="claude">Claude</option>
        </FilterSelect>
        <FilterSelect value={llmSuccess} onChange={e => setLlmSuccess(e.target.value)}>
          <option value="">All Results</option>
          <option value="true">Success</option>
          <option value="false">Failed</option>
        </FilterSelect>
        <MiniSearchBox>
          <FiUser className="icon" size={12} />
          <input
            placeholder="User..."
            value={llmUserSearch}
            onChange={e => handleLlmUserSearchChange(e.target.value)}
          />
        </MiniSearchBox>
        <MiniSearchBox>
          <FiSearch className="icon" size={12} />
          <input
            placeholder="IP..."
            value={llmIpSearch}
            onChange={e => handleLlmIpSearchChange(e.target.value)}
          />
        </MiniSearchBox>
        <ActionButton variant="primary" onClick={() => fetchLlmLogs()} disabled={llmLoading}>
          <FiRefreshCw size={14} style={{ animation: llmLoading ? 'spin 1s linear infinite' : 'none' }} />
          {llmLoading ? 'Loading...' : 'Refresh'}
        </ActionButton>
      </FiltersBar>

      <LogTable>
        <LlmTableHeader>
          <LlmHeaderCell>Time</LlmHeaderCell>
          <LlmHeaderCell>User</LlmHeaderCell>
          <LlmHeaderCell>IP</LlmHeaderCell>
          <LlmHeaderCell>Provider</LlmHeaderCell>
          <LlmHeaderCell>Model</LlmHeaderCell>
          <LlmHeaderCell>Latency</LlmHeaderCell>
          <LlmHeaderCell>Status</LlmHeaderCell>
          <LlmHeaderCell>Message Preview</LlmHeaderCell>
        </LlmTableHeader>

        {llmLoading && llmLogs.length === 0 ? (
          <EmptyState>Loading LLM logs...</EmptyState>
        ) : llmLogs.length === 0 ? (
          <EmptyState>No LLM call logs yet. LLM calls are logged automatically after AI interactions in any workshop.</EmptyState>
        ) : (
          [...llmLogs].reverse().map((log, i) => (
            <div key={i}>
              <LlmRow onClick={() => setExpandedLlm(expandedLlm === i ? null : i)}>
                <LlmCell title={log.timestamp}>{formatTs(log.timestamp)}</LlmCell>
                <LlmCell title={formatUser(log.username, log.userId)}>
                  {log.username || log.userId
                    ? <UserBadge><FiUser size={10} /> {log.username || `#${log.userId}`}</UserBadge>
                    : <span style={{ color: '#a0aec0', fontSize: '0.75rem' }}>system</span>
                  }
                </LlmCell>
                <LlmCell><IpBadge>{log.ip || '\u2014'}</IpBadge></LlmCell>
                <LlmCell>{log.provider || '\u2014'}</LlmCell>
                <LlmCell title={log.model}>{log.model ? log.model.split(':')[0] : '\u2014'}</LlmCell>
                <LlmCell>{formatLatency(log.latencyMs)}</LlmCell>
                <LlmCell>
                  {log.success === true  ? <FiCheckCircle color="#38a169" size={16} title="Success" /> :
                   log.success === false ? <FiXCircle color="#e53e3e" size={16} title="Failed" /> :
                   '\u2014'}
                </LlmCell>
                <LlmCell title={log.messageSummary}>
                  {log.messageSummary ? log.messageSummary.substring(0, 60) + (log.messageSummary.length > 60 ? '\u2026' : '') : '\u2014'}
                </LlmCell>
              </LlmRow>
              {expandedLlm === i && (
                <MetaBlock style={{ margin: '0 0 0 0', borderRadius: 0, borderLeft: 'none', borderRight: 'none' }}>
                  {JSON.stringify(log, null, 2)}
                </MetaBlock>
              )}
            </div>
          ))
        )}
        {llmLogs.length >= llmLines && (
          <LoadMoreButton onClick={() => { const n = llmLines + 100; setLlmLines(n); fetchLlmLogs(n); }}>
            Load 100 more
          </LoadMoreButton>
        )}
      </LogTable>
    </>
  );

  // ── Render: Error Summary ─────────────────────────────────────────────────
  const renderStats = () => (
    <>
      <div style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: '1rem' }}>
        <ActionButton variant="primary" onClick={fetchStats} disabled={statsLoading}>
          <FiRefreshCw size={14} style={{ animation: statsLoading ? 'spin 1s linear infinite' : 'none' }} />
          {statsLoading ? 'Loading...' : 'Refresh'}
        </ActionButton>
      </div>

      {statsLoading && !stats ? (
        <EmptyState>Loading statistics...</EmptyState>
      ) : stats ? (
        <>
          <StatsGrid>
            <StatCard color="#991b1b">
              <div className="label"><FiAlertTriangle size={12} /> Errors (24h)</div>
              <div className="value">{stats.errorCount ?? '\u2014'}</div>
              <div className="sub">From app.log</div>
            </StatCard>
            <StatCard color="#92400e">
              <div className="label">Warnings (24h)</div>
              <div className="value" style={{ color: '#92400e' }}>{stats.warnCount ?? '\u2014'}</div>
              <div className="sub">From app.log</div>
            </StatCard>
            <StatCard color="#1e40af">
              <div className="label"><FiCpu size={12} /> LLM Success Rate</div>
              <div className="value" style={{ color: stats.llmSuccessRate >= 90 ? '#38a169' : stats.llmSuccessRate >= 70 ? '#d69e2e' : '#e53e3e' }}>
                {stats.llmSuccessRate != null ? `${stats.llmSuccessRate}%` : '\u2014'}
              </div>
              <div className="sub">{stats.llmCallCount} total calls</div>
            </StatCard>
            <StatCard>
              <div className="label">Avg LLM Latency</div>
              <div className="value" style={{ color: '#1a202c', fontSize: '1.6rem' }}>
                {stats.avgLatencyMs != null ? formatLatency(stats.avgLatencyMs) : '\u2014'}
              </div>
              <div className="sub">Per LLM call</div>
            </StatCard>
          </StatsGrid>

          <TopErrorsCard>
            <h3><FiAlertTriangle size={16} style={{ verticalAlign: 'middle', marginRight: 6 }} />Top Error Messages</h3>
            {stats.topErrors && stats.topErrors.length > 0 ? (
              stats.topErrors.map((e, i) => (
                <ErrorItem key={i}>
                  <span className="msg">{i + 1}. {e.message}</span>
                  <span className="count">{e.count}</span>
                </ErrorItem>
              ))
            ) : (
              <p style={{ color: '#718096', fontSize: '0.875rem', margin: 0 }}>No errors recorded in last 1000 log entries.</p>
            )}
          </TopErrorsCard>
        </>
      ) : (
        <EmptyState>No statistics available</EmptyState>
      )}
    </>
  );

  // ── Main render ───────────────────────────────────────────────────────────
  return (
    <Container>
      <style>{`@keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }`}</style>
      <PageHeader>
        <h2>Server Logs</h2>
      </PageHeader>

      <InnerTabBar>
        <InnerTab active={activeTab === 'app'} onClick={() => setActiveTab('app')}>
          <FiActivity size={14} /> Application Logs
        </InnerTab>
        <InnerTab active={activeTab === 'llm'} onClick={() => setActiveTab('llm')}>
          <FiCpu size={14} /> LLM Logs
        </InnerTab>
        <InnerTab active={activeTab === 'stats'} onClick={() => setActiveTab('stats')}>
          <FiAlertTriangle size={14} /> Error Summary
        </InnerTab>
      </InnerTabBar>

      {activeTab === 'app'   && renderAppLogs()}
      {activeTab === 'llm'   && renderLlmLogs()}
      {activeTab === 'stats' && renderStats()}
    </Container>
  );
}
