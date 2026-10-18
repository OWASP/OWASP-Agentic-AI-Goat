import React, { useState, useEffect, useCallback, useRef } from 'react';
import { useAuth } from '../context/AuthContext';
import useChangePolling from '../hooks/useChangePolling';
import { FiActivity, FiClock, FiUser, FiTarget, FiShield, FiEye, FiFilter } from 'react-icons/fi';
import styled, { keyframes } from 'styled-components';
import { motion } from 'framer-motion';
import axios from 'axios';

const fadeInUp = keyframes`
  from {
    opacity: 0;
    transform: translateY(30px);
  }
  to {
    opacity: 1;
    transform: translateY(0);
  }
`;

const PageContainer = styled.div`
  min-height: 100vh;
  background: linear-gradient(135deg, #667eea 0%, #764ba2 50%, #f093fb 100%);
  padding: 2rem 0;
  position: relative;
  overflow-x: hidden;
  
  &::before {
    content: '';
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    background: radial-gradient(circle at 20% 80%, rgba(120, 119, 198, 0.3) 0%, transparent 50%),
                radial-gradient(circle at 80% 20%, rgba(255, 119, 198, 0.3) 0%, transparent 50%);
    pointer-events: none;
  }
`;

const ContentWrapper = styled.div`
  max-width: 1200px;
  margin: 0 auto;
  padding: 0 2rem;
  position: relative;
  z-index: 1;
`;

const Header = styled(motion.div)`
  background: rgba(255, 255, 255, 0.95);
  backdrop-filter: blur(20px);
  border-radius: 24px;
  padding: 2.5rem;
  margin-bottom: 2rem;
  text-align: center;
  
  h1 {
    font-size: 2.5rem;
    font-weight: 700;
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
    margin-bottom: 1rem;
  }

  .subtitle {
    color: #666;
    font-size: 1.1rem;
    line-height: 1.6;
  }
`;

const StatsGrid = styled(motion.div)`
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
  gap: 1.5rem;
  margin-bottom: 2rem;
`;

const StatCard = styled.div`
  background: rgba(255, 255, 255, 0.95);
  backdrop-filter: blur(20px);
  border-radius: 16px;
  padding: 1.5rem;
  text-align: center;
  border: 1px solid rgba(255, 255, 255, 0.3);
  
  .stat-icon {
    font-size: 2rem;
    color: #667eea;
    margin-bottom: 0.5rem;
  }
  
  .stat-number {
    font-size: 2rem;
    font-weight: 700;
    color: #333;
    margin-bottom: 0.25rem;
  }
  
  .stat-label {
    color: #666;
    font-size: 0.9rem;
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }
`;

const ActivityContainer = styled(motion.div)`
  background: rgba(255, 255, 255, 0.95);
  backdrop-filter: blur(20px);
  border-radius: 24px;
  padding: 2rem;
  box-shadow: 0 25px 50px rgba(0, 0, 0, 0.15);
  border: 1px solid rgba(255, 255, 255, 0.3);
`;

const FilterBar = styled.div`
  display: flex;
  align-items: center;
  gap: 1rem;
  margin-bottom: 2rem;
  flex-wrap: wrap;
`;

const FilterButton = styled.button`
  padding: 0.5rem 1rem;
  border-radius: 8px;
  border: 2px solid #dee2e6;
  background: ${props => props.active ? 'linear-gradient(135deg, #667eea, #764ba2)' : 'transparent'};
  color: ${props => props.active ? 'white' : '#666'};
  font-weight: 600;
  font-size: 0.9rem;
  cursor: pointer;
  transition: all 0.3s ease;
  
  &:hover {
    border-color: #667eea;
    color: ${props => props.active ? 'white' : '#667eea'};
  }
`;

const ActivityList = styled.div`
  max-height: 600px;
  overflow-y: auto;
`;

const ActivityItem = styled.div`
  display: flex;
  align-items: center;
  padding: 1rem;
  border-bottom: 1px solid #f0f0f0;
  transition: all 0.3s ease;
  
  &:hover {
    background: rgba(102, 126, 234, 0.05);
  }
  
  &:last-child {
    border-bottom: none;
  }
`;

const ActivityIcon = styled.div`
  width: 48px;
  height: 48px;
  border-radius: 12px;
  background: ${props => {
    switch (props.type) {
      case 'challenge': return 'linear-gradient(135deg, #28a745, #20c997)';
      case 'login': return 'linear-gradient(135deg, #667eea, #764ba2)';
      case 'profile': return 'linear-gradient(135deg, #ffc107, #fd7e14)';
      default: return 'linear-gradient(135deg, #6c757d, #495057)';
    }
  }};
  display: flex;
  align-items: center;
  justify-content: center;
  color: white;
  margin-right: 1rem;
  flex-shrink: 0;
`;

const ActivityContent = styled.div`
  flex: 1;
  
  .activity-title {
    font-weight: 600;
    color: #333;
    margin-bottom: 0.25rem;
  }
  
  .activity-description {
    color: #666;
    font-size: 0.9rem;
    line-height: 1.4;
  }
`;

const ActivityTime = styled.div`
  color: #999;
  font-size: 0.8rem;
  text-align: right;
  flex-shrink: 0;
  margin-left: 1rem;
`;

const EmptyState = styled.div`
  text-align: center;
  padding: 3rem;
  color: #666;
  
  .empty-icon {
    font-size: 3rem;
    margin-bottom: 1rem;
    opacity: 0.5;
  }
`;

const UserActivity = () => {
  const { user } = useAuth();
  const [activities, setActivities] = useState([]);
  const [stats, setStats] = useState({
    totalChallenges: 0,
    completedChallenges: 0,
    totalSessions: 0,
    lastLogin: null
  });
  const [filter, setFilter] = useState('all');
  const [loading, setLoading] = useState(true);
  const mountedRef = useRef(false);
  const requestSequenceRef = useRef(0);
  const foregroundInFlightRef = useRef(null);

  const fetchActivityData = useCallback(({ background = false, signal } = {}) => {
    const run = async () => {
      if (background && foregroundInFlightRef.current) {
        await foregroundInFlightRef.current.catch(() => {});
      }
      const requestId = ++requestSequenceRef.current;
      try {
        if (!background && mountedRef.current) setLoading(true);

        const requests = [
          axios.get('/api/workshop/user-activity', { signal }),
          axios.get('/api/workshop/progress', { signal }),
        ];
        const [activityRes, progressRes] = background
          ? (await Promise.all(requests)).map((value) => ({ status: 'fulfilled', value }))
          : await Promise.allSettled(requests);

      const rawActivity = activityRes.status === 'fulfilled'
        ? (activityRes.value.data.activity || [])
        : [];
      const apiLastLogin = activityRes.status === 'fulfilled'
        ? activityRes.value.data.lastLogin
        : null;

      const challenges = progressRes.status === 'fulfilled'
        ? (progressRes.value.data.challenges || [])
        : [];

      const objectiveActivities = rawActivity.map((row, idx) => ({
        id: row.id || `activity_${idx}`,
        type: row.type || 'challenge',
        title: row.title || `Completed: ${row.objective_label || row.objective_id}`,
        description: row.description || `in ${row.workshop_name || row.workshop_key || 'workshop'}`,
        timestamp: row.timestamp || row.completed_at || new Date().toISOString()
      }));

        if (!mountedRef.current || signal?.aborted || requestId !== requestSequenceRef.current) return null;
        setActivities(objectiveActivities);

      const completedCount = challenges.filter(c => c.status === 'completed').length;
      const completedObjectives = challenges.reduce((s, c) => s + (c.completedObjectiveCount || 0), 0);
        setStats({
          totalChallenges: challenges.length,
          completedChallenges: completedCount,
          totalSessions: completedObjectives,
          lastLogin: apiLastLogin || user?.lastLogin || user?.last_login || null
        });
        return { activities: objectiveActivities, challenges };
      } catch (error) {
        if (background) throw error;
        if (mountedRef.current && requestId === requestSequenceRef.current) {
          console.error('Error fetching activity data:', error);
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
  }, [user?.lastLogin, user?.last_login]);

  useEffect(() => {
    mountedRef.current = true;
    void fetchActivityData();
    return () => {
      mountedRef.current = false;
      requestSequenceRef.current += 1;
      foregroundInFlightRef.current = null;
    };
  }, [fetchActivityData]);

  useChangePolling((_next, _previous, { signal } = {}) => fetchActivityData({ background: true, signal }));

  const getActivityIcon = (type) => {
    switch (type) {
      case 'challenge': return <FiTarget />;
      case 'login': return <FiUser />;
      case 'profile': return <FiUser />;
      default: return <FiActivity />;
    }
  };

  const parseTimestamp = (timestamp) => {
    if (!timestamp) return null;
    if (typeof timestamp === 'string' && /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/.test(timestamp)) {
      return new Date(timestamp.replace(' ', 'T') + 'Z');
    }
    return new Date(timestamp);
  };

  const formatTime = (timestamp) => {
    const date = parseTimestamp(timestamp);
    if (!date || Number.isNaN(date.getTime())) return 'Unknown';
    const now = new Date();
    const diff = now - date;
    
    if (diff < 0) return date.toLocaleString();
    if (diff < 60 * 1000) return 'Just now';
    if (diff < 60 * 60 * 1000) return `${Math.floor(diff / (60 * 1000))}m ago`;
    if (diff < 24 * 60 * 60 * 1000) return `${Math.floor(diff / (60 * 60 * 1000))}h ago`;
    return date.toLocaleDateString();
  };

  const filteredActivities = activities.filter(activity => {
    if (filter === 'all') return true;
    return activity.type === filter;
  });

  if (loading) {
    return (
      <PageContainer>
        <ContentWrapper>
          <Header>
            <h1>Loading...</h1>
          </Header>
        </ContentWrapper>
      </PageContainer>
    );
  }

  return (
    <PageContainer>
      <ContentWrapper>
        <Header
          initial={{ y: -50, opacity: 0 }}
          animate={{ y: 0, opacity: 1 }}
          transition={{ duration: 0.8 }}
        >
          <h1>
            <FiActivity />
            User Activity
          </h1>
          <div className="subtitle">
            Track your workshop progress and activity history
          </div>
        </Header>

        <StatsGrid
          initial={{ y: 50, opacity: 0 }}
          animate={{ y: 0, opacity: 1 }}
          transition={{ duration: 0.8, delay: 0.1 }}
        >
          <StatCard>
            <div className="stat-icon"><FiTarget /></div>
            <div className="stat-number">{stats.completedChallenges}</div>
            <div className="stat-label">Completed Challenges</div>
          </StatCard>
          <StatCard>
            <div className="stat-icon"><FiShield /></div>
            <div className="stat-number">{stats.totalChallenges}</div>
            <div className="stat-label">Total Challenges</div>
          </StatCard>
          <StatCard>
            <div className="stat-icon"><FiClock /></div>
            <div className="stat-number">{stats.totalSessions}</div>
            <div className="stat-label">Objectives Done</div>
          </StatCard>
          <StatCard>
            <div className="stat-icon"><FiUser /></div>
            <div className="stat-number">{stats.lastLogin ? formatTime(stats.lastLogin) : 'Never'}</div>
            <div className="stat-label">Last Login</div>
          </StatCard>
        </StatsGrid>

        <ActivityContainer
          initial={{ y: 50, opacity: 0 }}
          animate={{ y: 0, opacity: 1 }}
          transition={{ duration: 0.8, delay: 0.2 }}
        >
          <FilterBar>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <FiFilter />
              <span style={{ fontWeight: '600', color: '#333' }}>Filter:</span>
            </div>
            <FilterButton 
              active={filter === 'all'} 
              onClick={() => setFilter('all')}
            >
              All Activity
            </FilterButton>
            <FilterButton 
              active={filter === 'challenge'} 
              onClick={() => setFilter('challenge')}
            >
              Challenges
            </FilterButton>
            <FilterButton 
              active={filter === 'login'} 
              onClick={() => setFilter('login')}
            >
              Login Sessions
            </FilterButton>
            <FilterButton 
              active={filter === 'profile'} 
              onClick={() => setFilter('profile')}
            >
              Profile Updates
            </FilterButton>
          </FilterBar>

          <ActivityList>
            {filteredActivities.length > 0 ? (
              filteredActivities.map((activity) => (
                <ActivityItem key={activity.id}>
                  <ActivityIcon type={activity.type}>
                    {getActivityIcon(activity.type)}
                  </ActivityIcon>
                  <ActivityContent>
                    <div className="activity-title">{activity.title}</div>
                    <div className="activity-description">{activity.description}</div>
                  </ActivityContent>
                  <ActivityTime>
                    {formatTime(activity.timestamp)}
                  </ActivityTime>
                </ActivityItem>
              ))
            ) : (
              <EmptyState>
                <div className="empty-icon">
                  <FiActivity />
                </div>
                <h3>No activity found</h3>
                <p>No activities match the selected filter.</p>
              </EmptyState>
            )}
          </ActivityList>
        </ActivityContainer>
      </ContentWrapper>
    </PageContainer>
  );
};

export default UserActivity;
