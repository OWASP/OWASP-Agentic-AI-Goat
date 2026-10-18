import React, { useState, useEffect, useRef } from 'react';
import { useAuth } from '../context/AuthContext';
import { FiUser, FiMail, FiPhone, FiMapPin, FiEdit, FiActivity, FiSave, FiCheckCircle, FiCalendar, FiTarget, FiSettings } from 'react-icons/fi';
import styled from 'styled-components';
import { motion } from 'framer-motion';
import { toast } from 'react-toastify';
import axios from 'axios';

const ProfileContainer = styled.div`
  min-height: 100vh;
  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
  padding: 2rem 0;
`;

const ProfileWrapper = styled.div`
  max-width: 1200px;
  margin: 0 auto;
  padding: 2rem;
`;

const ProfileHeader = styled(motion.div)`
  background: rgba(255, 255, 255, 0.95);
  backdrop-filter: blur(20px);
  border-radius: 24px;
  padding: 2rem;
  margin-bottom: 2rem;
  box-shadow: 0 25px 50px rgba(0, 0, 0, 0.1);
  border: 1px solid rgba(255, 255, 255, 0.2);
`;

const HeaderTop = styled.div`
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: 2rem;
`;

const PageTitle = styled.h1`
  font-size: 1.8rem;
  font-weight: 700;
  color: #333;
  margin: 0;
  display: flex;
  align-items: center;
  gap: 0.75rem;
`;

const EditButton = styled.button`
  display: flex;
  align-items: center;
  gap: 0.5rem;
  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
  color: white;
  border: none;
  padding: 0.75rem 1.5rem;
  border-radius: 12px;
  cursor: pointer;
  font-weight: 600;
  transition: all 0.3s ease;

  &:hover {
    transform: translateY(-2px);
    box-shadow: 0 10px 25px rgba(102, 126, 234, 0.4);
  }
`;

const UserBanner = styled.div`
  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
  border-radius: 16px;
  padding: 2rem;
  color: white;
  display: flex;
  align-items: center;
  gap: 2rem;
  margin-bottom: 2rem;
`;

const UserAvatar = styled.div`
  width: 80px;
  height: 80px;
  border-radius: 16px;
  background: rgba(255, 255, 255, 0.2);
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 2rem;
  font-weight: 700;
  color: white;
  border: 3px solid rgba(255, 255, 255, 0.3);
`;

const UserInfo = styled.div`
  flex: 1;
`;

const UserName = styled.h2`
  font-size: 2rem;
  font-weight: 700;
  margin: 0 0 0.5rem 0;
`;

const UserRole = styled.span`
  display: inline-block;
  padding: 0.5rem 1rem;
  background: rgba(255, 255, 255, 0.2);
  border-radius: 20px;
  font-size: 0.9rem;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.5px;
`;

const UserStats = styled.div`
  display: flex;
  gap: 3rem;
  margin-top: 1rem;

  @media (max-width: 768px) {
    gap: 1.5rem;
    flex-wrap: wrap;
  }
`;

const StatItem = styled.div`
  text-align: center;
`;

const StatValue = styled.div`
  font-size: 1.8rem;
  font-weight: 700;
  margin-bottom: 0.25rem;
`;

const StatLabel = styled.div`
  font-size: 0.9rem;
  opacity: 0.9;
  font-weight: 500;
`;

const TabsContainer = styled.div`
  display: flex;
  gap: 1rem;
  margin-bottom: 2rem;
`;

const Tab = styled.button`
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.75rem 1.5rem;
  border: none;
  border-radius: 12px;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.3s ease;
  background: ${props => props.$active ? 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)' : 'rgba(255, 255, 255, 0.8)'};
  color: ${props => props.$active ? 'white' : '#666'};

  &:hover {
    transform: translateY(-2px);
    box-shadow: 0 8px 20px rgba(0, 0, 0, 0.15);
  }
`;

const ContentSection = styled(motion.div)`
  background: rgba(255, 255, 255, 0.95);
  backdrop-filter: blur(20px);
  border-radius: 24px;
  padding: 2rem;
  box-shadow: 0 25px 50px rgba(0, 0, 0, 0.1);
  border: 1px solid rgba(255, 255, 255, 0.2);
`;

const SectionGrid = styled.div`
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 3rem;

  @media (max-width: 968px) {
    grid-template-columns: 1fr;
    gap: 2rem;
  }
`;

const InfoSection = styled.div``;

const SectionTitle = styled.h3`
  font-size: 1.2rem;
  font-weight: 600;
  color: #333;
  margin-bottom: 1.5rem;
  display: flex;
  align-items: center;
  gap: 0.75rem;
`;

const InfoItem = styled.div`
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 1rem 0;
  border-bottom: 1px solid rgba(0, 0, 0, 0.05);

  &:last-child {
    border-bottom: none;
  }
`;

const InfoLabel = styled.span`
  font-weight: 500;
  color: #666;
`;

const InfoValue = styled.span`
  font-weight: 600;
  color: #333;
`;

const Badge = styled.span`
  display: inline-block;
  padding: 0.25rem 0.75rem;
  background: ${props => props.variant === 'success' ? 'rgba(16, 185, 129, 0.1)' : 'rgba(102, 126, 234, 0.1)'};
  color: ${props => props.variant === 'success' ? '#10b981' : '#667eea'};
  border-radius: 20px;
  font-size: 0.75rem;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.5px;
`;

const FormGroup = styled.div`
  margin-bottom: 1.5rem;
`;

const FormLabel = styled.label`
  display: block;
  color: #333;
  font-weight: 500;
  margin-bottom: 0.5rem;
`;

const FormInput = styled.input`
  width: 100%;
  padding: 0.75rem 1rem;
  border: 1px solid rgba(0, 0, 0, 0.1);
  border-radius: 8px;
  font-size: 1rem;
  transition: all 0.3s ease;

  &:focus {
    outline: none;
    border-color: #667eea;
    box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
  }
`;

const SaveButton = styled.button`
  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
  color: white;
  border: none;
  padding: 0.75rem 1.5rem;
  border-radius: 8px;
  cursor: pointer;
  font-weight: 500;
  display: flex;
  align-items: center;
  gap: 0.5rem;
  transition: all 0.3s ease;

  &:hover {
    transform: translateY(-1px);
    box-shadow: 0 4px 15px rgba(0, 0, 0, 0.1);
  }
`;

const ActivityList = styled.div`
  display: flex;
  flex-direction: column;
  gap: 1rem;
`;

const ActivityItem = styled.div`
  display: flex;
  align-items: center;
  gap: 1rem;
  padding: 1rem;
  background: rgba(248, 250, 252, 0.5);
  border-radius: 12px;
  border: 1px solid rgba(226, 232, 240, 0.5);
  transition: all 0.3s ease;
  
  &:hover {
    transform: translateX(4px);
    box-shadow: 0 4px 15px rgba(0, 0, 0, 0.08);
  }
`;

const ActivityIcon = styled.div`
  width: 40px;
  height: 40px;
  border-radius: 12px;
  background: ${props => props.color || '#667eea'};
  display: flex;
  align-items: center;
  justify-content: center;
  color: white;
  font-size: 1rem;
  flex-shrink: 0;
`;

const ActivityContent = styled.div`
  flex: 1;
  min-width: 0;
`;

const ActivityText = styled.p`
  color: #334155;
  margin: 0 0 0.25rem 0;
  font-size: 0.9rem;
  font-weight: 500;
`;

const ActivityTime = styled.p`
  color: #64748b;
  margin: 0;
  font-size: 0.8rem;
`;

const ActivityStatus = styled.p`
  color: #64748b;
  margin: 0;
  padding: 1rem;
  text-align: center;
`;

const FieldHelp = styled.p`
  color: #64748b;
  font-size: 0.8rem;
  margin: 0.35rem 0 0;
`;

const UserProfileContent = ({ user, updateUser }) => {
  const [activeTab, setActiveTab] = useState('overview');
  const [profileData, setProfileData] = useState({
    email: user?.email || '',
    fullName: user?.fullName ?? user?.full_name ?? ''
  });
  const [recentActivity, setRecentActivity] = useState([]);
  const [activityStatus, setActivityStatus] = useState(user?.id ? 'loading' : 'unavailable');
  const [lastLogin, setLastLogin] = useState(null);
  const [saving, setSaving] = useState(false);
  const saveAuthorityRef = useRef(null);

  useEffect(() => {
    const authority = { current: true, ownerId: user?.id || null, controller: null };
    const previous = saveAuthorityRef.current;
    if (previous) {
      previous.current = false;
      previous.controller?.abort();
    }
    saveAuthorityRef.current = authority;
    return () => {
      authority.current = false;
      authority.controller?.abort();
      if (saveAuthorityRef.current === authority) saveAuthorityRef.current = null;
    };
  }, [user?.id]);

  useEffect(() => {
    if (!user?.id) {
      setRecentActivity([]);
      setLastLogin(null);
      setActivityStatus('unavailable');
      return undefined;
    }
    const controller = new AbortController();
    let current = true;
    const loadActivity = async () => {
      try {
        const response = await axios.get('/api/workshop/user-activity', { signal: controller.signal });
        if (!current || controller.signal.aborted) return;
        if (!response.data || !Array.isArray(response.data.activity)) {
          throw new TypeError('Invalid account activity response');
        }
        const rows = response.data.activity;
        setRecentActivity(rows.map((row, index) => {
          const type = row.type || 'challenge';
          const timestamp = row.timestamp || row.completed_at || null;
          return {
            id: row.id || `activity_${index}`,
            text: row.title || `Completed: ${row.objective_label || row.objective_id || 'workshop objective'}`,
            time: formatActivityTime(timestamp),
            icon: type === 'challenge' ? FiCheckCircle : FiUser,
            color: type === 'challenge' ? '#10b981' : '#3b82f6'
          };
        }));
        setLastLogin(response.data?.lastLogin || null);
        setActivityStatus('loaded');
      } catch (error) {
        if (!current || controller.signal.aborted || error?.name === 'CanceledError') return;
        setRecentActivity([]);
        setLastLogin(null);
        setActivityStatus('unavailable');
      }
    };
    void loadActivity();
    return () => {
      current = false;
      controller.abort();
    };
  }, [user?.id]);

  const handleProfileUpdate = async () => {
    const authority = saveAuthorityRef.current;
    if (!user?.id || !authority?.current || authority.ownerId !== user.id || authority.controller) return;
    const controller = new AbortController();
    authority.controller = controller;
    const ownerId = user.id;
    setSaving(true);
    try {
      const response = await axios.put('/api/auth/profile', {
        email: profileData.email,
        fullName: profileData.fullName
      }, { signal: controller.signal });
      if (!authority.current || authority.ownerId !== ownerId || authority.controller !== controller || controller.signal.aborted) return;
      const returnedUser = response.data?.user;
      if (response.data?.success !== true || !returnedUser || typeof returnedUser !== 'object') {
        throw new TypeError('Invalid profile update response');
      }
      if (String(returnedUser.id) !== String(ownerId) || typeof updateUser !== 'function') {
        throw new TypeError('Profile update owner mismatch');
      }
      if (typeof returnedUser.email !== 'string'
        || (typeof returnedUser.fullName !== 'string' && typeof returnedUser.full_name !== 'string')) {
        throw new TypeError('Invalid profile update user fields');
      }
      const returnedEmail = returnedUser.email;
      const returnedFullName = typeof returnedUser.fullName === 'string' ? returnedUser.fullName : returnedUser.full_name;
      const normalizedUser = { ...returnedUser, email: returnedEmail, fullName: returnedFullName, full_name: returnedFullName };
      setProfileData({ email: returnedEmail, fullName: returnedFullName });
      updateUser(normalizedUser);
      toast.success('Profile updated successfully!');
    } catch (error) {
      if (!authority.current || authority.ownerId !== ownerId || controller.signal.aborted || error?.name === 'CanceledError') return;
      const serverError = typeof error?.response?.data?.error === 'string'
        ? error.response.data.error.replace(/[\u0000-\u001F\u007F]/g, ' ').trim().slice(0, 160)
        : '';
      toast.error(serverError || 'Failed to update profile');
    } finally {
      if (authority.current && authority.ownerId === ownerId && authority.controller === controller) {
        authority.controller = null;
        setSaving(false);
      }
    }
  };

  const formatDate = (date) => {
    const parsed = new Date(date);
    if (Number.isNaN(parsed.getTime())) return 'Unavailable';
    return parsed.toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: '2-digit'
    });
  };

  function formatActivityTime(value) {
    if (!value) return 'Time unavailable';
    const normalized = typeof value === 'string' && /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/.test(value)
      ? `${value.replace(' ', 'T')}Z`
      : value;
    const parsed = new Date(normalized);
    return Number.isNaN(parsed.getTime()) ? 'Time unavailable' : parsed.toLocaleString();
  }

  const memberSince = user?.created_at ? formatDate(user.created_at) : 'Unavailable';
  const lastLoginLabel = activityStatus === 'loading'
    ? 'Loading…'
    : activityStatus === 'unavailable'
      ? 'Unavailable'
      : lastLogin
        ? formatDate(lastLogin)
        : 'Never';

  return (
    <ProfileContainer>
      <ProfileWrapper>
        <ProfileHeader
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6 }}
        >
          <HeaderTop>
            <PageTitle>
              <FiUser />
              Player Profile
            </PageTitle>
            <EditButton onClick={() => setActiveTab('edit')}>
              <FiEdit size={16} />
              Edit Profile
            </EditButton>
          </HeaderTop>

          <UserBanner>
            <UserAvatar>
              {user?.username?.charAt(0).toUpperCase() || 'U'}
            </UserAvatar>
            <UserInfo>
              <UserName>{user?.username || 'User'}</UserName>
              <UserRole>
                {user?.workshop_admin ? 'Administrator' : 'Security Student'}
              </UserRole>
              <UserStats>
                <StatItem>
                  <StatLabel>Role</StatLabel>
                  <StatValue>{user?.workshop_admin ? 'Admin' : 'Student'}</StatValue>
                </StatItem>
                <StatItem>
                  <StatLabel>Member Since</StatLabel>
                  <StatValue>{memberSince}</StatValue>
                </StatItem>
                <StatItem>
                  <StatLabel>Last Login</StatLabel>
                  <StatValue>{lastLoginLabel}</StatValue>
                </StatItem>
              </UserStats>
            </UserInfo>
          </UserBanner>

          <TabsContainer>
            <Tab
              $active={activeTab === 'overview'}
              onClick={() => setActiveTab('overview')}
            >
              <FiUser size={16} />
              Overview
            </Tab>
            <Tab
              $active={activeTab === 'edit'}
              onClick={() => setActiveTab('edit')}
            >
              <FiEdit size={16} />
              Edit Profile
            </Tab>
            <Tab
              $active={activeTab === 'activity'}
              onClick={() => setActiveTab('activity')}
            >
              <FiActivity size={16} />
              User Activity
            </Tab>
          </TabsContainer>
        </ProfileHeader>

        <ContentSection
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, delay: 0.2 }}
        >
          {activeTab === 'overview' && (
            <SectionGrid>
              <InfoSection>
                <SectionTitle>
                  <FiUser />
                  Personal Information
                </SectionTitle>
                <InfoItem>
                  <InfoLabel>Full Name</InfoLabel>
                  <InfoValue>{user?.fullName ?? user?.full_name ?? 'Not provided'}</InfoValue>
                </InfoItem>
                <InfoItem>
                  <InfoLabel>Email</InfoLabel>
                  <InfoValue>{user?.email || 'Not provided'}</InfoValue>
                </InfoItem>
                <InfoItem>
                  <InfoLabel>Phone</InfoLabel>
                  <InfoValue>{user?.phone || 'Not available in this session'}</InfoValue>
                </InfoItem>
                <InfoItem>
                  <InfoLabel>Role</InfoLabel>
                  <InfoValue>
                    <Badge variant={user?.workshop_admin ? 'primary' : 'success'}>
                      {user?.workshop_admin ? 'Admin' : 'Student'}
                    </Badge>
                  </InfoValue>
                </InfoItem>
              </InfoSection>
            </SectionGrid>
          )}

          {activeTab === 'edit' && (
            <div>
              <SectionTitle>
                <FiEdit />
                Edit Profile Information
              </SectionTitle>
              <SectionGrid>
                <div>
                  <FormGroup>
                    <FormLabel>Username</FormLabel>
                    <FormInput
                      type="text"
                      value={user?.username || ''}
                      readOnly
                    />
                    <FieldHelp>Usernames are fixed when the account is created.</FieldHelp>
                  </FormGroup>
                  <FormGroup>
                    <FormLabel>Full Name</FormLabel>
                    <FormInput
                      type="text"
                      value={profileData.fullName}
                      onChange={(e) => setProfileData(prev => ({ ...prev, fullName: e.target.value }))}
                    />
                  </FormGroup>
                </div>
                <div>
                  <FormGroup>
                    <FormLabel>Email</FormLabel>
                    <FormInput
                      type="email"
                      value={profileData.email}
                      onChange={(e) => setProfileData(prev => ({ ...prev, email: e.target.value }))}
                    />
                  </FormGroup>
                  <FormGroup>
                    <FormLabel>Phone</FormLabel>
                    <FormInput
                      type="tel"
                      value={user?.phone || ''}
                      placeholder="Not available in this session"
                      readOnly
                    />
                    <FieldHelp>Phone numbers cannot be changed from this profile form.</FieldHelp>
                  </FormGroup>
                </div>
              </SectionGrid>
              <SaveButton onClick={handleProfileUpdate} disabled={saving || !user?.id}>
                <FiSave />
                {saving ? 'Updating Profile…' : 'Update Profile'}
              </SaveButton>
            </div>
          )}

          {activeTab === 'activity' && (
            <div>
              <SectionTitle>
                <FiActivity />
                Recent Account Activity
              </SectionTitle>
              <ActivityList>
                {activityStatus === 'loading' && <ActivityStatus>Loading account activity…</ActivityStatus>}
                {activityStatus === 'unavailable' && <ActivityStatus>Account activity is temporarily unavailable.</ActivityStatus>}
                {activityStatus === 'loaded' && recentActivity.length === 0 && <ActivityStatus>No account activity recorded.</ActivityStatus>}
                {activityStatus === 'loaded' && recentActivity.map(activity => (
                  <ActivityItem key={activity.id}>
                    <ActivityIcon color={activity.color}>
                      <activity.icon />
                    </ActivityIcon>
                    <ActivityContent>
                      <ActivityText>{activity.text}</ActivityText>
                      <ActivityTime>{activity.time}</ActivityTime>
                    </ActivityContent>
                  </ActivityItem>
                ))}
              </ActivityList>
            </div>
          )}
        </ContentSection>
      </ProfileWrapper>
    </ProfileContainer>
  );
};

const UserProfile = () => {
  const { user, updateUser } = useAuth();
  return <UserProfileContent key={user?.id || 'no-owner'} user={user} updateUser={updateUser} />;
};

export default UserProfile;
