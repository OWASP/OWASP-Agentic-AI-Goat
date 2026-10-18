import React, { useState, useEffect, useCallback, useRef } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import axios from 'axios';
import { runAdminStudentReset } from '../../utils/adminStudentReset';
import styled, { keyframes } from 'styled-components';
import { motion } from 'framer-motion';
import { 
  FiUser, FiCheckCircle, FiClock, FiTrendingUp, FiTarget,
  FiBookOpen, FiAward, FiActivity, FiRefreshCw, FiZap, FiEye,
  FiDatabase, FiRotateCcw, FiAlertTriangle
} from 'react-icons/fi';
import { toast } from 'react-toastify';
import { useWorkshopConfig } from '../../context/WorkshopConfigContext';
import { formatWorkshopTime } from '../../utils/formatWorkshopTime';

const spin = keyframes`
  from { transform: rotate(0deg); }
  to { transform: rotate(360deg); }
`;

const Container = styled.div`
  padding: 2rem;
  background: #f8fafc;
  min-height: 100vh;
`;

const Header = styled.div`
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 2rem;
  
  h2 {
    font-size: 1.75rem;
    color: #1a202c;
    display: flex;
    align-items: center;
    gap: 0.75rem;
  }
`;

const RefreshButton = styled(motion.button)`
  padding: 0.75rem 1.5rem;
  background: #667eea;
  color: white;
  border: none;
  border-radius: 8px;
  cursor: pointer;
  display: flex;
  align-items: center;
  gap: 0.5rem;
  font-weight: 500;
  
  &:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }

  svg.spinning {
    animation: ${spin} 1s linear infinite;
  }
`;

const StudentSelector = styled.div`
  background: white;
  padding: 1.5rem;
  border-radius: 12px;
  margin-bottom: 2rem;
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.08);
  
  label {
    display: block;
    font-weight: 600;
    color: #1a202c;
    margin-bottom: 0.75rem;
  }
  
  select {
    width: 100%;
    padding: 0.75rem;
    border: 2px solid #e2e8f0;
    border-radius: 8px;
    font-size: 1rem;
    cursor: pointer;
    
    &:focus {
      outline: none;
      border-color: #667eea;
    }
  }
`;

const StatsGrid = styled.div`
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 1.5rem;
  margin-bottom: 2rem;
`;

const StatCard = styled(motion.div)`
  background: ${props => props.bgColor || 'white'};
  padding: 1.5rem;
  border-radius: 12px;
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.08);
  
  .icon {
    font-size: 2rem;
    color: ${props => props.$iconColor || '#667eea'};
    margin-bottom: 0.75rem;
  }
  
  .label {
    font-size: 0.875rem;
    color: #64748b;
    margin-bottom: 0.25rem;
  }
  
  .value {
    font-size: 2rem;
    font-weight: 700;
    color: #1a202c;
  }
`;

const ExercisesSection = styled.div`
  background: white;
  padding: 1.5rem;
  border-radius: 12px;
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.08);
  
  h3 {
    font-size: 1.25rem;
    color: #1a202c;
    margin-bottom: 1.5rem;
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }
`;

const ExercisesList = styled.div`
  display: grid;
  gap: 1rem;
`;

const ExerciseCard = styled(motion.div)`
  border: 2px solid ${props => 
    props.status === 'completed' ? '#48bb78' :
    props.status === 'in_progress' ? '#ed8936' : '#e2e8f0'
  };
  border-radius: 12px;
  padding: 1.5rem;
  background: ${props => 
    props.status === 'completed' ? '#f0fff4' :
    props.status === 'in_progress' ? '#fffaf0' : 'white'
  };
  position: relative;
  transition: all 0.4s cubic-bezier(0.4, 0, 0.2, 1);
  overflow: hidden;
  
  .header {
    display: flex;
    justify-content: space-between;
    align-items: start;
    margin-bottom: 0.75rem;
  }
  
  .title {
    font-size: 1.1rem;
    font-weight: 600;
    color: #1a202c;
    margin-bottom: 0.25rem;
  }
  
  .description {
    font-size: 0.875rem;
    color: #64748b;
    line-height: 1.5;
    margin-bottom: 0.75rem;
  }
  
  .meta {
    display: flex;
    gap: 1rem;
    flex-wrap: wrap;
    align-items: center;
    font-size: 0.875rem;
  }
  
  .badge {
    padding: 0.25rem 0.75rem;
    border-radius: 9999px;
    font-size: 0.75rem;
    font-weight: 600;
    display: inline-flex;
    align-items: center;
    gap: 0.25rem;
  }
  
  .status-badge {
    background: ${props => 
      props.status === 'completed' ? '#48bb78' :
      props.status === 'in_progress' ? '#ed8936' : '#94a3b8'
    };
    color: white;
  }
  
  .difficulty-badge {
    background: ${props =>
      props.difficulty === 'Beginner' ? '#d1fae5' :
      props.difficulty === 'Intermediate' ? '#fef3c7' :
      props.difficulty === 'Advanced' ? '#fecaca' : '#e0e7ff'
    };
    color: ${props =>
      props.difficulty === 'Beginner' ? '#065f46' :
      props.difficulty === 'Intermediate' ? '#92400e' :
      props.difficulty === 'Advanced' ? '#991b1b' : '#3730a3'
    };
  }
  
  .category-badge {
    background: #e0e7ff;
    color: #3730a3;
  }
`;

const StartButton = styled.button`
  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
  color: white;
  border: none;
  padding: 0.5rem 1.25rem;
  border-radius: 8px;
  font-size: 0.875rem;
  font-weight: 600;
  cursor: pointer;
  display: flex;
  align-items: center;
  gap: 0.5rem;
  transition: all 0.3s ease;
  margin-left: auto;

  &:hover {
    transform: translateY(-2px);
    box-shadow: 0 4px 12px rgba(102, 126, 234, 0.3);
    filter: brightness(1.1);
  }

  &:active {
    transform: translateY(0);
  }
`;

const LoadingState = styled.div`
  display: flex;
  justify-content: center;
  align-items: center;
  height: 400px;
  color: #64748b;

  .spinning-icon {
    animation: ${spin} 1s linear infinite;
  }
`;

const ResetButton = styled(motion.button)`
  padding: 0.75rem 1.5rem;
  background: transparent;
  color: #e53e3e;
  border: 2px solid #e53e3e;
  border-radius: 8px;
  cursor: pointer;
  display: flex;
  align-items: center;
  gap: 0.5rem;
  font-weight: 600;
  font-size: 0.875rem;
  transition: background 0.2s ease;

  &:hover:not(:disabled) {
    background: rgba(229, 62, 62, 0.08);
  }

  &:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }
`;

const WorkshopSection = styled.div`
  background: white;
  padding: 1.5rem;
  border-radius: 12px;
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.08);
  margin-top: 2rem;

  .section-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 1.25rem;
  }

  h3 {
    font-size: 1.25rem;
    color: #1a202c;
    display: flex;
    align-items: center;
    gap: 0.5rem;
    margin: 0;
  }
`;

const LevelGrid = styled.div`
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(260px, 1fr));
  gap: 0.75rem;
`;

const LevelItem = styled.div`
  border: 1.5px solid ${props =>
    props.status === 'completed' ? '#48bb78' :
    props.status === 'in_progress' ? '#ed8936' :
    props.status === 'unlocked' ? '#667eea' : '#e2e8f0'
  };
  border-radius: 10px;
  padding: 0.875rem 1rem;
  background: ${props =>
    props.status === 'completed' ? '#f0fff4' :
    props.status === 'in_progress' ? '#fffaf0' :
    props.status === 'unlocked' ? '#eef2ff' : '#f8fafc'
  };

  .level-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 0.35rem;
  }

  .level-name {
    font-weight: 600;
    font-size: 0.875rem;
    color: #1a202c;
  }

  .level-badge {
    font-size: 0.7rem;
    font-weight: 700;
    padding: 2px 8px;
    border-radius: 9999px;
    background: ${props =>
      props.status === 'completed' ? '#48bb78' :
      props.status === 'in_progress' ? '#ed8936' :
      props.status === 'unlocked' ? '#667eea' : '#94a3b8'
    };
    color: white;
    display: flex;
    align-items: center;
    gap: 3px;
  }

  .level-objective {
    font-size: 0.75rem;
    color: #64748b;
    line-height: 1.4;
  }
`;

const NoProgressNote = styled.div`
  color: #64748b;
  font-size: 0.9rem;
  text-align: center;
  padding: 1.5rem;
  background: #f8fafc;
  border-radius: 8px;
  border: 1px dashed #e2e8f0;
`;

function StudentWorkshopView() {
  const navigate = useNavigate();
  const location = useLocation();
  const { registerReconciler } = useWorkshopConfig();
  const [students, setStudents] = useState([]);
  const [selectedStudentId, setSelectedStudentId] = useState(null);
  const [studentView, setStudentView] = useState(null);
  const [loadError, setLoadError] = useState('');
  const [loading, setLoading] = useState(false);
  const [resettingProgress, setResettingProgress] = useState(false);
  const mountedRef = useRef(false);
  const requestSequenceRef = useRef(0);
  const foregroundInFlightRef = useRef(null);
  const selectedStudentIdRef = useRef(null);
  const resetSelectionGenerationRef = useRef(0);
  const selectStudent = useCallback((studentId) => {
    resetSelectionGenerationRef.current += 1;
    selectedStudentIdRef.current = studentId;
    setResettingProgress(false);
    setStudentView(null);
    setLoadError('');
    setSelectedStudentId(studentId);
  }, []);

  useEffect(() => {
    mountedRef.current = true;
    const controller = new AbortController();
    void fetchStudents(controller.signal);
    return () => {
      controller.abort();
      mountedRef.current = false;
      requestSequenceRef.current += 1;
      resetSelectionGenerationRef.current += 1;
      foregroundInFlightRef.current = null;
    };
  }, []);

  // Handle studentId from query params
  useEffect(() => {
    const params = new URLSearchParams(location.search);
    const studentId = params.get('studentId');
    if (studentId) {
      selectStudent(studentId);
    }
  }, [location.search, selectStudent]);

  useEffect(() => {
    if (selectedStudentId) {
      void fetchStudentWorkshopView(selectedStudentId);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedStudentId]);

  const fetchStudents = async (signal) => {
    try {
      const token = localStorage.getItem('token');
      const response = await axios.get('/api/admin/students', {
        headers: { 'Authorization': `Bearer ${token}` }, signal
      });
      
      if (signal.aborted || !mountedRef.current) return;
      if (response.data.success && response.data.students.length > 0) {
        setStudents(response.data.students);
        
        // Query and manual selections are authoritative over the bootstrap default.
        if (selectedStudentIdRef.current === null) {
          selectStudent(response.data.students[0].id);
        }
      }
    } catch (error) {
      if (signal.aborted || !mountedRef.current) return;
      console.error('Error fetching students:', error);
      toast.error('Failed to load students');
    }
  };

  const fetchStudentWorkshopView = useCallback((studentId, { background = false, signal } = {}) => {
    const run = async () => {
      const isSelectedStudent = () => String(selectedStudentIdRef.current) === String(studentId);
      if (background && (!isSelectedStudent() || signal?.aborted)) return null;
      while (background && foregroundInFlightRef.current) {
        await foregroundInFlightRef.current.catch(() => {});
        if (!mountedRef.current || signal?.aborted || !isSelectedStudent()) return null;
      }
      if (!mountedRef.current || signal?.aborted || !isSelectedStudent()) return null;

      const requestId = ++requestSequenceRef.current;
      try {
        if (!background) {
          setLoading(true);
          setLoadError('');
        }
        const token = localStorage.getItem('token');
        const workshopRes = await axios.get(`/api/admin/student-workshop-view/${studentId}`, {
          headers: { 'Authorization': `Bearer ${token}` }, signal
        });

        if (!workshopRes.data.success) throw new Error('Invalid student workshop response');
        if (!mountedRef.current || signal?.aborted || !isSelectedStudent() || requestId !== requestSequenceRef.current) return null;
        setStudentView({ ownerId: String(studentId), data: workshopRes.data });
        return workshopRes.data;
      } catch (error) {
        if (!mountedRef.current || !isSelectedStudent()) return null;
        if (background) {
          if (!signal?.aborted && requestId === requestSequenceRef.current
              && [401, 403, 404].includes(error.response?.status)) {
            setStudentView(null);
            setLoadError('Student workshop data is no longer accessible. Restore access and refresh.');
          }
          throw error;
        }
        if (requestId !== requestSequenceRef.current) return null;
        console.error('Error fetching student workshop view:', error);
        setStudentView(null);
        setLoadError(error.response?.data?.error || 'Failed to load student workshop data. Refresh to try again.');
        toast.error('Failed to load student workshop data');
        return null;
      } finally {
        if (!background && mountedRef.current && isSelectedStudent()
          && requestId === requestSequenceRef.current) {
          setLoading(false);
        }
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

  useEffect(() => registerReconciler(async (_revision, { signal } = {}) => {
    if (selectedStudentId) {
      await fetchStudentWorkshopView(selectedStudentId, { background: true, signal });
    }
  }), [fetchStudentWorkshopView, registerReconciler, selectedStudentId]);

  const handleRefresh = () => {
    if (selectedStudentId) {
      fetchStudentWorkshopView(selectedStudentId);
    }
  };

  const handleResetSensitiveInfoProgress = async () => {
    if (!selectedStudentId) return;
    const studentId = selectedStudentId;
    const token = localStorage.getItem('token');
    const resetGeneration = ++resetSelectionGenerationRef.current;
    const isCurrentReset = () => (
      mountedRef.current && resetSelectionGenerationRef.current === resetGeneration
      && localStorage.getItem('token') === token
    );
    const selectedStudent = students.find(s => s.id === parseInt(studentId));
    const name = selectedStudent?.username || `Student #${studentId}`;
    const confirmed = window.confirm(
      `Reset Sensitive Info Workshop Progress for ${name}?\n\nThis will erase this student's canonical objective completions and recorded workshop time for the Sensitive Information Disclosure workshop.\n\nAre you sure?`
    );
    if (!confirmed) return;
    try {
      setResettingProgress(true);
      const response = await runAdminStudentReset({ api: axios, studentId, token, isCurrent: isCurrentReset });
      if (response.data.success) {
        if (!isCurrentReset()) return;
        toast.success(`Sensitive Info progress reset for ${name}`);
        fetchStudentWorkshopView(studentId);
      } else if (isCurrentReset()) {
        toast.error(response.data.error || 'Failed to reset progress');
      }
    } catch (error) {
      if (!isCurrentReset()) return;
      console.error('Error resetting Sensitive Info progress:', error);
      toast.error('Reset completion is uncertain. Retry this same student to recover the original request.');
    } finally {
      if (isCurrentReset()) setResettingProgress(false);
    }
  };

  const handleStartExercise = (route) => {
    if (route) {
      // Save current admin page to return later
      sessionStorage.setItem('adminReturnPath', location.pathname + location.search);
      // Navigate in the same window to maintain auth context
      navigate(route);
    } else {
      toast.error('Exercise route not found');
    }
  };

  const selectedStudent = students.find(s => s.id === parseInt(selectedStudentId));
  const studentData = studentView && String(studentView.ownerId) === String(selectedStudentId)
    ? studentView.data
    : null;
  const sensitiveInfoWorkshop = studentData?.challenges?.find(
    challenge => challenge.workshopKey === 'sensitive_info_disclosure'
      || challenge.id === 'sensitive_info_disclosure'
  );
  const sensitiveInfoObjectives = Array.isArray(sensitiveInfoWorkshop?.objectives)
    ? sensitiveInfoWorkshop.objectives
    : [];
  return (
    <Container>
      <Header>
        <h2>
          <FiUser />
          Student Workshop View
        </h2>
        <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'center' }}>
          <RefreshButton
            onClick={handleRefresh}
            disabled={loading}
            whileHover={{ scale: 1.02 }}
            whileTap={{ scale: 0.98 }}
          >
            <FiRefreshCw className={loading ? 'spinning' : ''} />
            Refresh
          </RefreshButton>
        </div>
      </Header>

      <StudentSelector>
        <label>Select Student</label>
        <select 
          value={selectedStudentId || ''} 
          onChange={(e) => selectStudent(e.target.value)}
        >
          {students.map(student => (
            <option key={student.id} value={student.id}>
              {student.username} ({student.email})
            </option>
          ))}
        </select>
      </StudentSelector>

      {loading ? (
        <LoadingState>
          <FiRefreshCw size={32} className="spinning-icon" />
        </LoadingState>
      ) : loadError ? (
        <NoProgressNote role="alert">
          <FiAlertTriangle style={{ marginBottom: '0.5rem', opacity: 0.5 }} size={20} />
          <div>{loadError}</div>
        </NoProgressNote>
      ) : studentData ? (
        <>
          <StatsGrid>
            <StatCard
              $iconColor="#667eea"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
            >
              <div className="icon"><FiCheckCircle /></div>
              <div className="label">Completed</div>
              <div className="value">{studentData.overview.completedChallenges}</div>
            </StatCard>

            <StatCard
              $iconColor="#48bb78"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.1 }}
            >
              <div className="icon"><FiEye /></div>
              <div className="label">Visible to Students</div>
              <div className="value">{studentData.overview.totalChallenges}</div>
            </StatCard>

            <StatCard
              $iconColor="#ed8936"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.2 }}
            >
              <div className="icon"><FiAward /></div>
              <div className="label">Points</div>
              <div className="value" title={studentData.overview.pointsAvailable === false ? 'Workshop points are not configured' : undefined}>{studentData.overview.totalPoints ?? '—'}</div>
            </StatCard>

            <StatCard
              $iconColor="#f56565"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.3 }}
            >
              <div className="icon"><FiActivity /></div>
              <div className="label">Streak</div>
              <div className="value">{studentData.overview.streak} 🔥</div>
            </StatCard>

            <StatCard
              $iconColor="#9333ea"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.4 }}
            >
              <div className="icon"><FiTrendingUp /></div>
              <div className="label">Progress</div>
              <div className="value">{studentData.overview.completionPercentage}%</div>
            </StatCard>

            <StatCard
              $iconColor="#06b6d4"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.5 }}
            >
              <div className="icon"><FiTarget /></div>
              <div className="label">Total Exercises</div>
              <div className="value">{studentData.overview.totalSystemChallenges}</div>
            </StatCard>
          </StatsGrid>

          <ExercisesSection>
            <h3>
              <FiBookOpen />
              Available Exercises ({studentData.challenges.length})
            </h3>
            
            <ExercisesList>
              {studentData.challenges.map((exercise, index) => (
                <ExerciseCard
                  key={exercise.id}
                  status={exercise.status}
                  difficulty={exercise.difficulty}
                  initial={{ opacity: 0, x: -20 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: index * 0.05 }}
                >
                  <div className="header">
                    <div>
                      <div className="title">{exercise.name}</div>
                    </div>
                    <div className="badge status-badge">
                      {exercise.status === 'completed' && <FiCheckCircle />}
                      {exercise.status === 'in_progress' && <FiClock />}
                      {exercise.status.replace(/_/g, ' ')}
                    </div>
                  </div>
                  
                  <div className="description">{exercise.description}</div>

                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.75rem', color: '#64748b', fontSize: '0.8rem' }}>
                    <span>
                      <strong>{exercise.completedObjectiveCount}</strong>/{exercise.objectiveCount} objectives
                    </span>
                    <span style={{ display: 'inline-flex', alignItems: 'center', gap: '0.25rem' }}>
                      <FiClock /> {formatWorkshopTime(exercise.timeSpentSeconds)}
                    </span>
                    <span>
                      Hints: <strong>{exercise.objectives?.filter(objective => objective.hintVisible).length || 0}</strong>
                    </span>
                    <span>
                      Solutions: <strong>{exercise.objectives?.filter(objective => objective.solutionVisible).length || 0}</strong>
                    </span>
                  </div>
                  
                  <details aria-label={`Objective progress: ${exercise.name}`} style={{ marginTop: '0.75rem' }}>
                    <summary style={{ cursor: 'pointer', color: '#64748b', fontSize: '0.875rem' }}>Objective progress</summary>
                    <LevelGrid style={{ marginTop: '0.75rem' }}>
                      {Array.isArray(exercise.objectives) && exercise.objectives.length > 0 ? exercise.objectives.map(objective => (
                        <LevelItem key={objective.id} data-objective-id={objective.id} status={objective.completed ? 'completed' : 'not_completed'}>
                          <div className="level-header">
                            <span className="level-name">{objective.label || objective.text || objective.id}</span>
                            <span className="level-badge">
                              {objective.completed && <FiCheckCircle size={10} />}
                              {objective.completed ? 'Completed' : 'Not completed'}
                            </span>
                          </div>
                          <div className="level-objective">Objective ID: {objective.id}</div>
                          <div className="level-objective">Hints: {objective.hintVisible === true ? 'Available' : 'Unavailable'}</div>
                          <div className="level-objective">Solutions: {objective.solutionVisible === true ? 'Available' : 'Unavailable'}</div>
                        </LevelItem>
                      )) : <div className="level-objective">No objectives are currently available.</div>}
                    </LevelGrid>
                  </details>

                  <div className="meta">
                    <span className="badge difficulty-badge">{exercise.difficulty}</span>
                    {exercise.category && (
                      <span className="badge category-badge">{exercise.category}</span>
                    )}
                    {exercise.completed_at && (
                      <span style={{ color: '#48bb78', fontSize: '0.875rem' }}>
                        ✓ Completed: {new Date(exercise.completed_at).toLocaleDateString()}
                      </span>
                    )}
                    
                    <StartButton onClick={() => handleStartExercise(exercise.route)}>
                      <FiZap />
                      Try Exercise
                    </StartButton>
                  </div>
                </ExerciseCard>
              ))}
            </ExercisesList>
          </ExercisesSection>

          {/* Sensitive Information Disclosure Workshop canonical objective progress */}
          <WorkshopSection>
            <div className="section-header">
              <h3>
                <FiDatabase />
                Sensitive Info Disclosure Workshop — Objective Progress
              </h3>
              <ResetButton
                onClick={handleResetSensitiveInfoProgress}
                disabled={resettingProgress || loading}
                whileHover={{ scale: 1.02 }}
                whileTap={{ scale: 0.98 }}
                title="Erase all Sensitive Info workshop progress for this student"
                style={{ padding: '0.5rem 1rem', fontSize: '0.8rem' }}
              >
                <FiRotateCcw size={14} />
                Reset Progress
              </ResetButton>
            </div>

            {sensitiveInfoWorkshop && sensitiveInfoObjectives.length > 0 ? (
              <>
                <div style={{ display: 'flex', gap: '1.5rem', marginBottom: '1rem', fontSize: '0.85rem', color: '#64748b' }}>
                  <span>
                    <strong style={{ color: '#48bb78' }}>
                      {sensitiveInfoWorkshop.completedObjectiveCount}
                    </strong> / {sensitiveInfoWorkshop.objectiveCount} objectives completed
                  </span>
                </div>
                <LevelGrid>
                  {sensitiveInfoObjectives.map((objective, index) => {
                    const status = objective.completed ? 'completed' : 'not_completed';
                    return (
                      <LevelItem key={objective.id} status={status}>
                        <div className="level-header">
                          <span className="level-name">{index + 1}. {objective.label || objective.text || objective.id}</span>
                          <span className="level-badge">
                            {status === 'completed' && <FiCheckCircle size={10} />}
                            {status === 'completed' ? 'COMPLETED' : 'NOT COMPLETED'}
                          </span>
                        </div>
                        <div className="level-objective">Objective ID: {objective.id}</div>
                        {objective.completedAt && (
                          <div style={{ fontSize: '0.7rem', color: '#48bb78', marginTop: '4px' }}>
                            ✓ {new Date(objective.completedAt).toLocaleDateString()}
                          </div>
                        )}
                      </LevelItem>
                    );
                  })}
                </LevelGrid>
              </>
            ) : (
              <NoProgressNote>
                <FiAlertTriangle style={{ marginBottom: '0.5rem', opacity: 0.5 }} size={20} />
                <div>
                  {sensitiveInfoWorkshop
                    ? 'No Sensitive Info objectives are currently enabled for students.'
                    : `Sensitive Info progress is unavailable for ${selectedStudent?.username || 'this student'} in the current admin projection.`}
                </div>
              </NoProgressNote>
            )}
          </WorkshopSection>
        </>
      ) : (
        <LoadingState>No data available</LoadingState>
      )}
    </Container>
  );
}

export default StudentWorkshopView;
