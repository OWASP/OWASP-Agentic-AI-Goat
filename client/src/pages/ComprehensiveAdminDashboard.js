import React, { useState, useEffect, useCallback, useRef } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { 
  FiHome, FiUsers, FiBookOpen, FiSettings, FiActivity, FiShield,
  FiLogOut, FiMenu, FiX, FiToggleLeft, FiToggleRight, FiEye, 
  FiTrendingUp, FiClock, FiCheck, FiAlertTriangle, FiEdit, FiSave, FiLock,
  FiTarget, FiMonitor, FiSliders, FiTrash2, FiPlus, FiRefreshCw, FiCpu, FiUser,
  FiChevronUp, FiChevronDown, FiCode, FiShoppingCart, FiServer, FiCloud, FiZap
} from 'react-icons/fi';
import styled from 'styled-components';
import { motion, AnimatePresence } from 'framer-motion';
import { useAuth } from '../context/AuthContext';
import { loadAdminActivityUsers } from '../utils/loadAdminActivityUsers';
import { runAdminBulkReset } from '../utils/adminBulkReset';
import useAdminActiveUserCount from '../hooks/useAdminActiveUserCount';
import CTFAdminPanel from './admin/CTFAdminPanel';
import { toast } from 'react-toastify';
import axios from 'axios';
import { useWorkshopConfig } from '../context/WorkshopConfigContext';
import AIProviderManagement from '../components/admin/AIProviderManagement';
import StudentWorkshopView from '../components/admin/StudentWorkshopView';
import ServerLogs from '../components/admin/ServerLogs';
import ProgressAnalyticsPanel from './admin/ProgressAnalyticsPanel';
import TypedObjectiveSolutionEditor, { isEditableSolution } from '../components/admin/TypedObjectiveSolutionEditor';
import PromptInjectionHintEditorModal from '../components/admin/PromptInjectionHintEditorModal';
import WorkshopObjectiveEditor from '../components/admin/WorkshopObjectiveEditor';
import WorkshopSolutionEditor from '../components/admin/WorkshopSolutionEditor';
import AgentRunInspector from '../components/observability/AgentRunInspector';
import { readAdminExerciseState } from '../utils/adminExerciseLoading';
import { runAfterTrackedLoad } from '../utils/serializedReconciliation';

const {
  PROMPT_INJECTION_EXERCISES,
  mutatePromptInjectionMasterSolution,
  reconcilePromptInjectionExercise,
} = require('../utils/promptInjectionAdminCompatibility');

const AdminContainer = styled.div`
  display: flex;
  height: 100vh;
  overflow: hidden;
  background: #f8fafc;
`;

const Sidebar = styled(motion.div)`
  width: 270px;
  min-width: 270px;
  background: linear-gradient(180deg, #0f1523 0%, #1a202c 50%, #2d3748 100%);
  position: fixed;
  height: 100vh;
  left: 0;
  top: 0;
  z-index: 1000;
  overflow: hidden;
  display: flex;
  flex-direction: column;
  box-shadow: 4px 0 24px rgba(0, 0, 0, 0.35);
  transform: translateX(${props => props.isOpen ? '0' : '-100%'});
  transition: transform 0.3s ease;

  @media (min-width: 769px) {
    transform: translateX(0);
    position: fixed;
  }
`;

const MainContent = styled.div`
  flex: 1;
  height: 100vh;
  overflow-y: auto;
  padding: 2rem;
  margin-left: 270px;

  @media (max-width: 768px) {
    margin-left: 0;
    padding: 1rem;
  }
`;

const MobileToggle = styled.button`
  display: none;
  position: fixed;
  top: 1rem;
  left: 1rem;
  z-index: 1001;
  background: #667eea;
  color: white;
  border: none;
  padding: 0.5rem;
  border-radius: 8px;
  cursor: pointer;
  
  @media (max-width: 768px) {
    display: flex;
    align-items: center;
    justify-content: center;
  }
`;

const SidebarHeader = styled.div`
  padding: 1.5rem 1.25rem 1.25rem;
  border-bottom: 1px solid rgba(255, 255, 255, 0.08);
  flex-shrink: 0;

  .brand {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    margin-bottom: 1rem;
  }

  .brand-icon {
    width: 38px;
    height: 38px;
    background: linear-gradient(135deg, #667eea, #764ba2);
    border-radius: 10px;
    display: flex;
    align-items: center;
    justify-content: center;
    color: white;
    font-size: 1.1rem;
    flex-shrink: 0;
    box-shadow: 0 4px 12px rgba(102, 126, 234, 0.4);
  }

  .brand-text h1 {
    color: white;
    font-size: 1.05rem;
    font-weight: 700;
    margin: 0 0 0.1rem 0;
    letter-spacing: 0.01em;
  }

  .brand-text p {
    color: #718096;
    font-size: 0.72rem;
    margin: 0;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    font-weight: 500;
  }

  .user-pill {
    display: flex;
    align-items: center;
    gap: 0.6rem;
    background: rgba(255, 255, 255, 0.06);
    border: 1px solid rgba(255, 255, 255, 0.08);
    border-radius: 10px;
    padding: 0.5rem 0.75rem;
  }

  .user-avatar {
    width: 28px;
    height: 28px;
    background: linear-gradient(135deg, #48bb78, #38a169);
    border-radius: 8px;
    display: flex;
    align-items: center;
    justify-content: center;
    color: white;
    font-size: 0.75rem;
    font-weight: 700;
    flex-shrink: 0;
  }

  .user-info {
    flex: 1;
    min-width: 0;
  }

  .user-info .name {
    color: #e2e8f0;
    font-size: 0.8rem;
    font-weight: 600;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .user-info .role {
    color: #48bb78;
    font-size: 0.68rem;
    font-weight: 500;
    text-transform: uppercase;
    letter-spacing: 0.06em;
  }
`;

const NavSection = styled.div`
  flex: 1;
  padding: 0.75rem 0.75rem 0;
  display: flex;
  flex-direction: column;
  overflow-y: auto;
  scrollbar-width: none;
  &::-webkit-scrollbar { display: none; }
`;

const NavGroupLabel = styled.div`
  color: #4a5568;
  font-size: 0.65rem;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.1em;
  padding: 0.6rem 1rem 0.3rem;
  margin-top: 0.25rem;
`;

const NavItem = styled(motion.div)`
  display: flex;
  align-items: center;
  gap: 0.75rem;
  padding: 0.6rem 1rem;
  margin-bottom: 0.1rem;
  border-radius: 8px;
  cursor: pointer;
  color: ${props => props.active ? '#fff' : '#718096'};
  background: ${props => props.active ? 'rgba(102, 126, 234, 0.18)' : 'transparent'};
  border-left: 3px solid ${props => props.active ? '#667eea' : 'transparent'};
  transition: all 0.15s ease;
  font-size: 0.855rem;

  &:hover {
    background: rgba(102, 126, 234, 0.1);
    color: #cbd5e0;
    border-left-color: rgba(102, 126, 234, 0.5);
  }

  svg {
    font-size: ${props => props.active ? '1.05rem' : '0.95rem'};
    flex-shrink: 0;
    color: ${props => props.active ? '#818cf8' : 'inherit'};
    transition: font-size 0.15s ease;
  }

  span {
    font-weight: ${props => props.active ? '600' : '500'};
  }
`;

const SidebarFooter = styled.div`
  flex-shrink: 0;
  padding: 0.75rem;
  border-top: 1px solid rgba(255, 255, 255, 0.07);
  background: rgba(0, 0, 0, 0.15);
`;

const Header = styled.div`
  background: white;
  padding: 2rem;
  border-radius: 16px;
  margin-bottom: 2rem;
  box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
  display: flex;
  justify-content: space-between;
  align-items: center;
  
  @media (max-width: 768px) {
    padding: 1rem;
    flex-direction: column;
    gap: 1rem;
  }
`;

const HeaderTitle = styled.div`
  h1 {
    color: #1a202c;
    font-size: 2rem;
    font-weight: 700;
    margin: 0 0 0.5rem 0;
  }
  
  p {
    color: #718096;
    margin: 0;
  }
`;

const UserInfo = styled.div`
  display: flex;
  align-items: center;
  gap: 1rem;
  
  .avatar {
    width: 48px;
    height: 48px;
    border-radius: 50%;
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    display: flex;
    align-items: center;
    justify-content: center;
    color: white;
    font-weight: bold;
    font-size: 1.2rem;
  }
  
  .details {
    h3 {
      color: #1a202c;
      margin: 0;
      font-size: 1.1rem;
    }
    
    p {
      color: #718096;
      margin: 0;
      font-size: 0.875rem;
    }
  }
`;

const StatsGrid = styled.div`
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
  gap: 1.5rem;
  margin-bottom: 2rem;
`;

const StatCard = styled(motion.div)`
  background: white;
  padding: 2rem;
  border-radius: 16px;
  box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
  display: flex;
  align-items: center;
  gap: 1.5rem;
  
  .icon {
    width: 60px;
    height: 60px;
    border-radius: 12px;
    background: ${props => props.bgColor || 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)'};
    display: flex;
    align-items: center;
    justify-content: center;
    color: white;
    font-size: 1.5rem;
  }
  
  .content {
    flex: 1;
    
    h3 {
      color: #1a202c;
      font-size: 2rem;
      font-weight: 700;
      margin: 0 0 0.5rem 0;
    }
    
    p {
      color: #718096;
      margin: 0;
    }
  }
`;

const TableCard = styled.div`
  background: white;
  padding: 1.5rem;
  border-radius: 12px;
  box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
  
  h3 {
    color: #1a202c;
    font-size: 1.25rem;
    font-weight: 600;
    margin: 0 0 1rem 0;
  }
  
  table {
    width: 100%;
    border-collapse: collapse;
    
    th {
      text-align: left;
      padding: 0.75rem;
      background: #f7fafc;
      color: #4a5568;
      font-weight: 600;
      font-size: 0.875rem;
      border-bottom: 2px solid #e2e8f0;
    }
    
    td {
      padding: 0.75rem;
      border-bottom: 1px solid #e2e8f0;
      color: #2d3748;
      font-size: 0.875rem;
    }
    
    tbody tr:hover {
      background: #f7fafc;
    }
    
    tbody tr:last-child td {
      border-bottom: none;
    }
  }
`;

const ContentSection = styled(motion.div)`
  background: white;
  border-radius: 16px;
  padding: 2rem;
  margin-bottom: 2rem;
  box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
  
  h2 {
    color: #1a202c;
    font-size: 1.5rem;
    font-weight: 700;
    margin: 0 0 1.5rem 0;
    display: flex;
    align-items: center;
    gap: 0.75rem;
  }
`;

const ChallengeGrid = styled.div`
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
  gap: 1.5rem;
`;

const ChallengeCard = styled.div`
  border: 2px solid ${props => props.enabled ? '#48bb78' : '#e2e8f0'};
  border-radius: 12px;
  padding: 1.5rem;
  transition: all 0.3s ease;
  background: ${props => props.enabled ? '#f0fff4' : '#f7fafc'};
  
  &:hover {
    transform: translateY(-2px);
    box-shadow: 0 8px 25px rgba(0, 0, 0, 0.1);
  }
  
  .header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 1rem;
    
    h3 {
      color: #1a202c;
      font-size: 1.1rem;
      font-weight: 600;
      margin: 0;
    }
  }
  
  .description {
    color: #718096;
    font-size: 0.875rem;
    margin-bottom: 1rem;
    line-height: 1.5;
  }
  
  .stats {
    display: flex;
    justify-content: space-between;
    font-size: 0.875rem;
    color: #4a5568;
  }
`;

const ToggleSwitch = styled.div`
  width: 50px;
  height: 26px;
  background: ${props => props.enabled ? '#48bb78' : '#cbd5e0'};
  border-radius: 13px;
  position: relative;
  cursor: pointer;
  transition: all 0.3s ease;
  
  &:before {
    content: '';
    position: absolute;
    width: 22px;
    height: 22px;
    border-radius: 50%;
    background: white;
    top: 2px;
    left: ${props => props.enabled ? '26px' : '2px'};
    transition: all 0.3s ease;
    box-shadow: 0 2px 4px rgba(0, 0, 0, 0.2);
  }
`;

const SectionHeader = styled.div`
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 1.5rem;
  
  h2 {
    margin: 0;
    color: #1a202c;
    font-size: 1.5rem;
    font-weight: 600;
    display: flex;
    align-items: center;
    gap: 0.5rem;
    
    svg {
      color: #4f46e5;
    }
  }
`;

const StudentTable = styled.div`
  overflow-x: auto;
  
  table {
    width: 100%;
    border-collapse: collapse;
    
    th, td {
      text-align: left;
      padding: 1rem;
      border-bottom: 1px solid #e2e8f0;
    }
    
    th {
      background: #f7fafc;
      color: #4a5568;
      font-weight: 600;
      font-size: 0.875rem;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }
    
    td {
      color: #1a202c;
    }
    
    tr:hover {
      background: #f7fafc;
    }
  }
`;

const ActionButton = styled.button`
  background: ${props => props.variant === 'danger' ? '#e53e3e' : '#667eea'};
  color: white;
  border: none;
  padding: 0.5rem 1rem;
  border-radius: 8px;
  cursor: pointer;
  font-size: 0.875rem;
  font-weight: 500;
  transition: all 0.3s ease;
  display: inline-flex;
  align-items: center;
  gap: 0.5rem;
  
  &:hover {
    background: ${props => props.variant === 'danger' ? '#c53030' : '#5a6fd8'};
    transform: translateY(-1px);
  }
  
  &:disabled {
    opacity: 0.6;
    cursor: not-allowed;
    transform: none;
  }
`;

const ModalOverlay = styled(motion.div)`
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background: rgba(0, 0, 0, 0.5);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 2000;
  padding: 2rem;
`;

const ModalContent = styled(motion.div)`
  background: white;
  border-radius: 16px;
  width: 100%;
  max-width: 800px;
  max-height: 90vh;
  overflow-y: auto;
  position: relative;
`;

const ModalHeader = styled.div`
  padding: 2rem 2rem 1rem 2rem;
  border-bottom: 1px solid #e2e8f0;
  display: flex;
  justify-content: space-between;
  align-items: center;
  
  h2 {
    margin: 0;
    color: #1a202c;
    font-size: 1.5rem;
  }
  
  button {
    background: none;
    border: none;
    font-size: 1.5rem;
    color: #718096;
    cursor: pointer;
    padding: 0.5rem;
    border-radius: 8px;
    
    &:hover {
      background: #f7fafc;
      color: #1a202c;
    }
  }
`;

const ModalBody = styled.div`
  padding: 2rem;
`;

const ModalFooter = styled.div`
  padding: 1.5rem 2rem;
  border-top: 1px solid #e2e8f0;
  display: flex;
  justify-content: flex-end;
  gap: 1rem;
  background: #f8fafc;
  border-bottom-left-radius: 16px;
  border-bottom-right-radius: 16px;
`;

const FormGroup = styled.div`
  margin-bottom: 1.5rem;
  
  label {
    display: block;
    margin-bottom: 0.5rem;
    color: #4a5568;
    font-weight: 600;
    font-size: 0.875rem;
  }
  
  input, select, textarea {
    width: 100%;
    padding: 0.75rem;
    border: 2px solid #e2e8f0;
    border-radius: 8px;
    font-size: 1rem;
    transition: all 0.3s ease;
    
    &:focus {
      outline: none;
      border-color: #667eea;
      box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
    }
  }
`;

const FormGrid = styled.div`
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 1.5rem;
  margin-bottom: 1.5rem;
`;

const SecondaryButton = styled.button`
  background: #edf2f7;
  color: #4a5568;
  border: none;
  padding: 0.6rem 1.2rem;
  border-radius: 8px;
  cursor: pointer;
  font-size: 0.875rem;
  font-weight: 600;
  transition: all 0.3s ease;
  
  &:hover {
    background: #e2e8f0;
    color: #2d3748;
  }
`;

const AdministratorForm = styled.form`
  margin-top: 1rem;
  padding: 1.25rem;
  border: 1px solid #e2e8f0;
  border-radius: 12px;
  background: #f8fafc;

  h4 { margin: 0 0 1rem; color: #1a202c; }
`;

const AdministratorFields = styled.div`
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 1rem;

  @media (max-width: 600px) { grid-template-columns: minmax(0, 1fr); }
`;

const AdministratorField = styled.div`
  min-width: 0;

  label { display: block; margin-bottom: 0.4rem; color: #334155; font-size: 0.875rem; font-weight: 600; }
  input, select {
    box-sizing: border-box;
    display: block;
    width: 100%;
    min-height: 2.7rem;
    padding: 0.65rem 0.75rem;
    border: 1px solid #cbd5e1;
    border-radius: 8px;
    background: #fff;
    color: #1a202c;
    font: inherit;
  }
  input:focus-visible, select:focus-visible { outline: 2px solid #667eea; outline-offset: 2px; }
`;

const AdministratorPermissions = styled.fieldset`
  margin: 1.25rem 0;
  padding: 0;
  border: 0;
  min-width: 0;

  legend { margin-bottom: 0.6rem; color: #334155; font-size: 0.875rem; font-weight: 700; }
  > div { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 0.6rem; }
  @media (max-width: 600px) { > div { grid-template-columns: minmax(0, 1fr); } }
`;

const AdministratorChoice = styled.label`
  display: flex;
  align-items: center;
  gap: 0.65rem;
  min-height: 2.5rem;
  padding: 0.6rem 0.75rem;
  border: 1px solid #e2e8f0;
  border-radius: 8px;
  background: #fff;
  color: #334155;
  font-size: 0.875rem;
  cursor: pointer;

  input { flex: none; width: 1rem; height: 1rem; margin: 0; accent-color: #667eea; }
  &:focus-within { outline: 2px solid #667eea; outline-offset: 2px; }
`;

const AdministratorActions = styled.div`
  display: flex;
  justify-content: flex-end;
  flex-wrap: wrap;
  gap: 0.6rem;
  margin-top: 1rem;
`;

const UserManagementTabs = styled.div`
  display: flex;
  gap: 0.4rem;
  border-bottom: 1px solid #e2e8f0;
  margin-bottom: 1.5rem;
`;

const UserManagementTab = styled.button`
  padding: 0.7rem 1rem;
  border: 0;
  border-bottom: 3px solid ${props => props.$active ? '#667eea' : 'transparent'};
  background: transparent;
  color: ${props => props.$active ? '#4f46e5' : '#64748b'};
  font: inherit;
  font-weight: 700;
  cursor: pointer;
  &:focus-visible { outline: 2px solid #667eea; outline-offset: 2px; }
`;

const UserManagementOverlay = styled(ModalOverlay)`
  @media (max-width: 600px) { padding: 0.5rem; }
`;

const UserManagementContent = styled(ModalContent)`
  max-width: 760px;
  @media (max-width: 600px) { max-height: calc(100dvh - 1rem); }
`;

const UserManagementBody = styled(ModalBody)`
  @media (max-width: 600px) { padding: 1rem; }
`;

const StudentInfoGrid = styled.div`
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 1.5rem;
  margin-bottom: 2rem;
`;

const InfoCard = styled.div`
  background: #f7fafc;
  padding: 1.5rem;
  border-radius: 12px;
  border: 2px solid #e2e8f0;
  
  .label {
    font-size: 0.875rem;
    color: #718096;
    margin-bottom: 0.5rem;
    font-weight: 500;
  }
  
  .value {
    font-size: 1.25rem;
    color: #1a202c;
    font-weight: 600;
  }
`;

const ProgressSection = styled.div`
  margin-top: 2rem;
  
  h3 {
    color: #1a202c;
    margin-bottom: 1rem;
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }
`;

const ProgressList = styled.div`
  display: flex;
  flex-direction: column;
  gap: 1rem;
`;

const ProgressItem = styled.div`
  background: white;
  border: 2px solid ${props => {
    if (props.status === 'completed') return '#48bb78';
    if (props.status === 'in_progress') return '#ed8936';
    return '#e2e8f0';
  }};
  border-radius: 12px;
  padding: 1.5rem;
  
  .header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 0.5rem;
    
    h4 {
      margin: 0;
      color: #1a202c;
      font-size: 1.1rem;
    }
    
    .status {
      padding: 0.25rem 0.75rem;
      border-radius: 20px;
      font-size: 0.875rem;
      font-weight: 500;
      background: ${props => {
        if (props.status === 'completed') return '#c6f6d5';
        if (props.status === 'in_progress') return '#fed7aa';
        return '#f7fafc';
      }};
      color: ${props => {
        if (props.status === 'completed') return '#276749';
        if (props.status === 'in_progress') return '#9c4221';
        return '#4a5568';
      }};
    }
  }
  
  .details {
    display: flex;
    justify-content: space-between;
    font-size: 0.875rem;
    color: #718096;
  }
`;

const emptyAdministratorDraft = () => ({ username: '', email: '', fullName: '', password: '',
  confirmPassword: '', adminLevel: 1,
  permissions: ['challenge_management', 'view_analytics', 'manage_progress'] });
const emptyStudentDraft = () => ({ username: '', email: '', password: '', confirmPassword: '',
  full_name: '', role: 'student' });
const emptySelfPasswordDraft = () => ({ currentPassword: '', newPassword: '', confirmPassword: '' });

const ComprehensiveAdminDashboard = () => {
  const { user, logout, getAuthRevision } = useAuth();
  const resetActorRef = useRef(user?.id);
  resetActorRef.current = user?.id;
  useEffect(() => {
    resetActorRef.current = user?.id;
    return () => { resetActorRef.current = null; };
  }, [user?.id]);
  const { registerReconciler, refreshAfterMutation, retireSnapshotReads, snapshotReadSequence, snapshot: canonicalConfig } = useWorkshopConfig();
  const navigate = useNavigate();
  const location = useLocation();
  
  // Determine active section from URL
  const getActiveSectionFromPath = () => {
    const path = location.pathname;
    if (path.includes('/admin/student-workshop-view')) return 'student-workshop-view';
    if (path.includes('/admin/students')) return 'students';
    if (path.includes('/admin/locked-users')) return 'locked-users';
    if (path.includes('/admin/exercises')) return 'exercises';
    // Legacy paths merged into Exercises Management (routes redirect, but keep resilient):
    if (path.includes('/admin/challenges')) return 'exercises';
    if (path.includes('/admin/solutions')) return 'exercises';
    if (path.includes('/admin/ctf-management')) return 'ctf-management';
    if (path.includes('/admin/progress-analytics')) return 'progress-analytics';
    if (path.includes('/admin/llm-health')) return 'llm-health';
    if (path.includes('/admin/ai-providers')) return 'ai-providers';
    if (path.includes('/admin/server-logs')) return 'server-logs';
    if (path.includes('/admin/agent-runs')) return 'agent-runs';
    if (path.includes('/admin/activity')) return 'activity';
    if (path.includes('/admin/settings')) return 'settings';
    return 'dashboard'; // default
  };
  
  const [activeSection, setActiveSection] = useState(getActiveSectionFromPath());
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [loading, setLoading] = useState(false);
  const [challenges, setChallenges] = useState([]);
  const toWorkshopKey = (key) => challenges.find(challenge =>
    challenge.key === key || challenge.id === key || challenge.workshopKey === key)?.workshopKey || (key === 'mcp_server_rce' ? 'mcp_workshop' : key);
  const workshopKeyRef = useRef(toWorkshopKey);
  workshopKeyRef.current = toWorkshopKey;
  const canViewAgentRuns = Array.isArray(user?.permissions) && user.permissions.includes('view_analytics');
  const hasUserManagementPermission = Array.isArray(user?.permissions)
    && user.permissions.includes('user_management');
  const accountAccessPermissionRef = useRef(Number(user?.adminLevel) >= 1 && hasUserManagementPermission);
  accountAccessPermissionRef.current = Number(user?.adminLevel) >= 1 && hasUserManagementPermission;
  const canManageProgress = Array.isArray(user?.permissions)
    && user.permissions.includes('manage_progress');
  const resetPermissionRef = useRef(canManageProgress);
  resetPermissionRef.current = canManageProgress;
  const canManageChallenges = Array.isArray(user?.permissions) && user.permissions.includes('challenge_management');
  const challengePermissionRef = useRef(canManageChallenges);
  challengePermissionRef.current = canManageChallenges;
  const objectiveBulkRef = useRef(false);
  const [objectiveBulkPending, setObjectiveBulkPending] = useState(false);
  const canViewActiveUsers = hasUserManagementPermission;
  const activeUserCount = useAdminActiveUserCount({ownerId: user?.id,
    enabled: canViewActiveUsers && activeSection === 'dashboard'});
  const canDeleteStudents = Number(user?.adminLevel) >= 2 && hasUserManagementPermission;
  const canCreateAdministrators = Number(user?.adminLevel) >= 2 && hasUserManagementPermission;
  const deactivationPermissionRef = useRef(canCreateAdministrators);
  deactivationPermissionRef.current = canCreateAdministrators;
  const adminRosterPermissionRef = useRef(hasUserManagementPermission);
  adminRosterPermissionRef.current = hasUserManagementPermission;
  const deleteStudentPermissionTitle = Number(user?.adminLevel) < 2
    ? 'Student deletion requires administrator level 2.'
    : !hasUserManagementPermission
      ? 'Student deletion requires user management permission.'
      : 'Delete student';
  const [piSolutionChallenges, setPiSolutionChallenges] = useState([]);
  const [piSolutionLoading, setPiSolutionLoading] = useState(false);
  const [finflowSolutions, setFinflowSolutions] = useState([]);
  const [finflowSolutionLoading, setFinflowSolutionLoading] = useState(false);
  const [scSolutions, setScSolutions] = useState([]);
  const [scSolutionLoading, setScSolutionLoading] = useState(false);
  const [selectedScObjective, setSelectedScObjective] = useState(null);
  const [scViewModalOpen, setScViewModalOpen] = useState(false);
  const [scEditModalOpen, setScEditModalOpen] = useState(false);
  const [scEditFormData, setScEditFormData] = useState({});
  const [solutionPreview, setSolutionPreview] = useState(null);
  // EA / SQL-NoSQL / IPI / RCE solution state
  const [eaSolutions, setEaSolutions] = useState([]);
  const [eaSolutionLoading, setEaSolutionLoading] = useState(false);

  const [ipiSolutions, setIpiSolutions] = useState([]);
  const [ipiSolutionLoading, setIpiSolutionLoading] = useState(false);
  const [mcpSolutions, setMcpSolutions] = useState([]);
  const [mcpSolutionLoading, setMcpSolutionLoading] = useState(false);
  const [xssLoading, setXssLoading] = useState(false);
  const [xssObjectives, setXssObjectives] = useState([]);
  const [xssObjEditId, setXssObjEditId] = useState(null);
  const [xssObjEditFormData, setXssObjEditFormData] = useState({});
  const [csrfLoading, setCsrfLoading] = useState(false);
  const [csrfObjectives, setCsrfObjectives] = useState([]);
  const [csrfObjEditId, setCsrfObjEditId] = useState(null);
  const [csrfObjEditFormData, setCsrfObjEditFormData] = useState({});
  // SQL Injection Workshop solution toggles
  const [sqliObjectives, setSqliObjectives] = useState([]);
  const [sqliLoading, setSqliLoading] = useState(false);
  // NoSQL Injection Workshop solution toggles
  const [nosqliObjectives, setNosqliObjectives] = useState([]);
  const [nosqliLoading, setNosqliLoading] = useState(false);
  const [students, setStudents] = useState([]);
  const [selectedStudent, setSelectedStudent] = useState(null);
  const [studentModalOpen, setStudentModalOpen] = useState(false);
  const [loadingStudent, setLoadingStudent] = useState(false);
  const [securitySettingsModalOpen, setSecuritySettingsModalOpen] = useState(false);
  const [userManagementModalOpen, setUserManagementModalOpen] = useState(false);
  const [accountAccessConfirm, setAccountAccessConfirm] = useState(null);
  const [accountAccessStatus, setAccountAccessStatus] = useState(null);
  const stagedAccountAccessRef = useRef(null);
  const pendingAccountAccessRef = useRef(null);
  const lockedUsersLoadGenerationRef = useRef(0);
  const [userManagementTab, setUserManagementTab] = useState('administrators');
  const userManagementModalOpenRef = useRef(userManagementModalOpen);
  userManagementModalOpenRef.current = userManagementModalOpen;
  const userManagementTabRef = useRef(userManagementTab);
  userManagementTabRef.current = userManagementTab;
  const [adminAccounts, setAdminAccounts] = useState([]);
  const adminRosterGenerationRef = useRef(0);
  const [adminAccountsLoading, setAdminAccountsLoading] = useState(false);
  const [adminAccountsError, setAdminAccountsError] = useState('');
  const [managementStudentsLoading, setManagementStudentsLoading] = useState(false);
  const [managementStudentsError, setManagementStudentsError] = useState('');
  const [editingAdministrator, setEditingAdministrator] = useState(null);
  const editingAdministratorRef = useRef(editingAdministrator);
  editingAdministratorRef.current = editingAdministrator;
  const [administratorEditStage, setAdministratorEditStage] = useState(null);
  const [administratorEditOutcome, setAdministratorEditOutcome] = useState(null);
  const stagedAdministratorEditRef = useRef(null);
  const pendingAdministratorEditRef = useRef(null);
  const [deactivatingAdministrator, setDeactivatingAdministrator] = useState(null);
  const [deactivationOutcome, setDeactivationOutcome] = useState(null);
  const stagedDeactivationRef = useRef(null);
  const pendingDeactivationRef = useRef(null);
  const [administratorMutationPending, setAdministratorMutationPending] = useState(false);
  const [createAdministratorOpen, setCreateAdministratorOpen] = useState(false);
  const [creatingAdministrator, setCreatingAdministrator] = useState(false);
  const [newAdministrator, setNewAdministrator] = useState(emptyAdministratorDraft);
  const newAdministratorRef = useRef(newAdministrator);
  newAdministratorRef.current = newAdministrator;
  const [administratorCreateStage, setAdministratorCreateStage] = useState(null);
  const [administratorCreateOutcome, setAdministratorCreateOutcome] = useState(null);
  const stagedAdministratorCreateRef = useRef(null);
  const pendingAdministratorCreateRef = useRef(null);
  const [systemLogsModalOpen, setSystemLogsModalOpen] = useState(false);
  const [changePasswordModalOpen, setChangePasswordModalOpen] = useState(false);
  const [selfPasswordStage, setSelfPasswordStage] = useState(null);
  const [selfPasswordOutcome, setSelfPasswordOutcome] = useState(null);
  const [selfPasswordPending, setSelfPasswordPending] = useState(false);
  const stagedSelfPasswordRef = useRef(null);
  const pendingSelfPasswordRef = useRef(null);
  const selfPasswordPermissionRef = useRef(Number(user?.adminLevel) >= 1);
  selfPasswordPermissionRef.current = Number(user?.adminLevel) >= 1;
  const [securitySettings, setSecuritySettings] = useState({});
  const [systemLogs, setSystemLogs] = useState([]);
  const [loadingLogs, setLoadingLogs] = useState(false);
  const [solutions, setSolutions] = useState([]);
  const [selectedSolution, setSelectedSolution] = useState(null);
  const [solutionModalOpen, setSolutionModalOpen] = useState(false);
  const [loadingSolutions, setLoadingSolutions] = useState(false);
  const [editingSolution, setEditingSolution] = useState(null);
  const [solutionEditModalOpen, setSolutionEditModalOpen] = useState(false);
  
  // Prompt Injection Solution Management (Objective-level)
  const [selectedPiObjective, setSelectedPiObjective] = useState(null);
  const [piViewModalOpen, setPiViewModalOpen] = useState(false);
  const [piEditModalOpen, setPiEditModalOpen] = useState(false);
  const [piAllSolutionsViewModalOpen, setPiAllSolutionsViewModalOpen] = useState(false);
  const [piAllSolutions, setPiAllSolutions] = useState([]);
  const [piEditFormData, setPiEditFormData] = useState({
    title: '',
    difficulty: 'Medium',
    examples: [{ prompt: '', explanation: '' }],
    approach: '',
    tips: ['']
  });
  
  const [editStudentModalOpen, setEditStudentModalOpen] = useState(false);
  const [studentEditStage, setStudentEditStage] = useState(null);
  const [studentEditOutcome, setStudentEditOutcome] = useState(null);
  const stagedStudentEditRef = useRef(null);
  const [deleteStudentModalOpen, setDeleteStudentModalOpen] = useState(false);
  const [changeStudentPasswordModalOpen, setChangeStudentPasswordModalOpen] = useState(false);
  const [studentPasswordStage, setStudentPasswordStage] = useState(null);
  const [studentPasswordOutcome, setStudentPasswordOutcome] = useState(null);
  const [studentPasswordPending, setStudentPasswordPending] = useState(false);
  const stagedStudentPasswordRef = useRef(null);
  const pendingStudentPasswordRef = useRef(null);
  const [createStudentModalOpen, setCreateStudentModalOpen] = useState(false);
  const [studentCreateStage, setStudentCreateStage] = useState(null);
  const [studentCreateOutcome, setStudentCreateOutcome] = useState(null);
  const stagedStudentCreateRef = useRef(null);
  const pendingStudentAccountMutationRef = useRef(null);
  const [studentAccountMutationPending, setStudentAccountMutationPending] = useState(false);
  const [studentToEdit, setStudentToEdit] = useState(null);
  const [studentToDelete, setStudentToDelete] = useState(null);
  const [studentDeletionPending, setStudentDeletionPending] = useState(false);
  const stagedStudentDeletionRef = useRef(null);
  const studentDeletionPendingRef = useRef(false);
  const studentDeletionMountedRef = useRef(true);
  const studentDeletionEpochRef = useRef(0);
  const authorityStorageEpochRef = useRef(0);
  const getAuthRevisionRef = useRef(getAuthRevision);
  getAuthRevisionRef.current = getAuthRevision;
  const captureAdminAuthority = () => {
    try {
      const token = localStorage.getItem('token');
      return token && resetActorRef.current != null ? {
        token, actorId: resetActorRef.current,
        revision: getAuthRevisionRef.current ? getAuthRevisionRef.current() : null,
        storageEpoch: authorityStorageEpochRef.current,
      } : null;
    } catch { return null; }
  };
  const isCurrentAdminAuthority = authority => {
    try {
      return !!authority && authority.token === localStorage.getItem('token')
        && authority.actorId === resetActorRef.current
        && authority.storageEpoch === authorityStorageEpochRef.current
        && (authority.revision === null || (getAuthRevisionRef.current
          && authority.revision === getAuthRevisionRef.current()));
    } catch { return false; }
  };
  useEffect(() => {
    studentDeletionMountedRef.current = true;
    const onStorage = event => {
      if (event.storageArea !== localStorage || (event.key !== 'token' && event.key !== null)) return;
      authorityStorageEpochRef.current += 1;
      studentDeletionEpochRef.current += 1;
      stagedStudentDeletionRef.current = null;
      setStudentToDelete(null);
      setDeleteStudentModalOpen(false);
      stagedStudentPasswordRef.current = null;
      setStudentPasswordStage(null);
      setStudentPasswordOutcome(null);
      setStudentForPasswordChange(null);
      setChangeStudentPasswordModalOpen(false);
      setPasswordChangeData({ newPassword: '', confirmPassword: '' });
      stagedSelfPasswordRef.current = null;
      setSelfPasswordStage(null);
      setSelfPasswordOutcome(null);
      setChangePasswordModalOpen(false);
      setPasswords(emptySelfPasswordDraft());
      stagedStudentCreateRef.current = null;
      stagedStudentEditRef.current = null;
      setStudentCreateStage(null);
      setStudentEditStage(null);
      setStudentCreateOutcome(null);
      setStudentEditOutcome(null);
      setCreateStudentModalOpen(false);
      setEditStudentModalOpen(false);
      setStudentToEdit(null);
      setNewStudent(emptyStudentDraft());
      bulkResetEpochRef.current += 1;
      stagedBulkResetRef.current = null;
      setResetConfirm(null);
      setResettingWorkshop({});
      stagedAccountAccessRef.current = null;
      setAccountAccessConfirm(null);
      setAccountAccessStatus(null);
      stagedBulkVisibilityRef.current = null;
      setBulkVisibilityConfirm(null);
      setBulkVisibilityOutcome(null);
      stagedBulkContentRef.current = null;
      setBulkContentConfirm(null);
      setBulkContentOutcome(null);
      lockedUsersLoadGenerationRef.current += 1;
      setLockedUsers([]);
      if (activeSectionRef.current === 'locked-users') void fetchLockedUsers();
      stagedDeactivationRef.current = null;
      setDeactivatingAdministrator(null);
      setDeactivationOutcome(null);
      stagedAdministratorEditRef.current = null;
      setAdministratorEditStage(null);
      setEditingAdministrator(null);
      setAdministratorEditOutcome(null);
      stagedAdministratorCreateRef.current = null;
      setAdministratorCreateStage(null);
      setAdministratorCreateOutcome(null);
      setCreateAdministratorOpen(false);
      setNewAdministrator(emptyAdministratorDraft());
      adminRosterGenerationRef.current += 1;
      setAdminAccounts([]);
      if (userManagementModalOpenRef.current && userManagementTabRef.current === 'administrators')
        void loadAdminAccounts();
    };
    window.addEventListener('storage', onStorage);
    return () => {
      window.removeEventListener('storage', onStorage);
      studentDeletionMountedRef.current = false;
      studentDeletionEpochRef.current += 1;
      stagedStudentDeletionRef.current = null;
      stagedStudentPasswordRef.current = null;
      stagedSelfPasswordRef.current = null;
      stagedStudentCreateRef.current = null;
      stagedStudentEditRef.current = null;
      bulkResetEpochRef.current += 1;
      stagedBulkResetRef.current = null;
      stagedAccountAccessRef.current = null;
      stagedBulkVisibilityRef.current = null;
      stagedBulkContentRef.current = null;
      lockedUsersLoadGenerationRef.current += 1;
      stagedDeactivationRef.current = null;
      stagedAdministratorEditRef.current = null;
      stagedAdministratorCreateRef.current = null;
      adminRosterGenerationRef.current += 1;
    };
  }, []);
  const [editFormData, setEditFormData] = useState({
    username: '',
    email: '',
    full_name: '',
    role: 'student',
    is_active: true,
    department: '',
    phone: ''
  });
  const editFormDataRef = useRef(editFormData);
  editFormDataRef.current = editFormData;
  const [newStudent, setNewStudent] = useState(emptyStudentDraft);
  const newStudentRef = useRef(newStudent);
  newStudentRef.current = newStudent;
  const [studentForPasswordChange, setStudentForPasswordChange] = useState(null);
  const [passwordChangeData, setPasswordChangeData] = useState({
    newPassword: '',
    confirmPassword: ''
  });
  const passwordChangeDataRef = useRef(passwordChangeData);
  passwordChangeDataRef.current = passwordChangeData;
  const [passwords, setPasswords] = useState(emptySelfPasswordDraft);
  const passwordsRef = useRef(passwords);
  passwordsRef.current = passwords;
  const [solutionData, setSolutionData] = useState({
    solution_title: '',
    solution_description: '',
    solution_steps: '',
    solution_code: '',
    explanation: '',
    reference_links: '',
    difficulty_level: 'medium',
    estimated_time: '',
    prerequisites: '',
    tags: '',
    is_public: false
  });
  const [stats, setStats] = useState({
    totalStudents: null,
    activeUsers: null,
    completedChallenges: 0,
    totalChallenges: 8
  });
  const dashboardRequestRef = useRef(0);
  useEffect(() => {
    if (!canManageProgress) {
      dashboardRequestRef.current += 1;
      setStudents([]);
      setStats(current => ({ ...current, totalStudents: null, activeUsers: null }));
    }
  }, [canManageProgress]);

  // Activity Logs state (moved from renderActivityLogs to fix React hooks error)
  const [activityStats, setActivityStats] = useState({
    successful_logins: 0,
    failed_logins: 0,
    challenge_completions: 0
  });
  const [recentActivity, setRecentActivity] = useState([]);
  const [loadingActivity, setLoadingActivity] = useState(true);
  const [activityLoadError, setActivityLoadError] = useState(null);
  const activityRequestRef = useRef(0);
  const [activeUsers, setActiveUsers] = useState([]);
  const [loadingActiveUsers, setLoadingActiveUsers] = useState(false);
  const [activeUsersLoadError, setActiveUsersLoadError] = useState(null);
  const activeUsersRequestRef = useRef(0);
  const activeUsersRef = useRef([]);
  const [activityPage, setActivityPage] = useState(1);
  const [activityTotalPages, setActivityTotalPages] = useState(1);
  const [activityTotalCount, setActivityTotalCount] = useState(0);
  const [activityPageJump, setActivityPageJump] = useState('');
  const activityPerPage = 100;

  // LLM Health state (moved from renderLLMHealth to fix React hooks error)
  const [llmHealthData, setLlmHealthData] = useState(null);
  const [llmStatsData, setLlmStatsData] = useState(null);
  const [llmHealthLoading, setLlmHealthLoading] = useState(true);
  const [llmAutoRefresh, setLlmAutoRefresh] = useState(false);

  // Locked Users state (for user unlock functionality)
  const [lockedUsers, setLockedUsers] = useState([]);
  const [loadingLockedUsers, setLoadingLockedUsers] = useState(false);

  // Bulk challenge toggle state
  const [bulkTogglingChallenges, setBulkTogglingChallenges] = useState(false);
  const [bulkContentPending, setBulkContentPending] = useState(false);
  const bulkContentRef = useRef(false);
  const [bulkContentConfirm, setBulkContentConfirm] = useState(null);
  const [bulkContentOutcome, setBulkContentOutcome] = useState(null);
  const stagedBulkContentRef = useRef(null);
  const pendingBulkContentRef = useRef(null);
  const [bulkVisibilityConfirm, setBulkVisibilityConfirm] = useState(null);
  const [bulkVisibilityOutcome, setBulkVisibilityOutcome] = useState(null);
  const stagedBulkVisibilityRef = useRef(null);
  const pendingBulkVisibilityRef = useRef(null);

  // Per-workshop objective visibility toggles
  const [workshopObjectives, setWorkshopObjectives] = useState({}); // { workshopKey: [{objective_id, is_enabled}] }
  const [workshopHints, setWorkshopHints] = useState({}); // { workshopKey: { objectiveId: is_enabled } }
  const [mcpSolutionEditor, setMcpSolutionEditor] = useState(null);
  const hintSavePending = useRef(false);
  const [hintEditor, setHintEditor] = useState(null); // { workshopKey, objectiveId, objectiveLabel, hint }
  const [hintEditorSaving, setHintEditorSaving] = useState(false);
  const [objectiveEditor, setObjectiveEditor] = useState(null);
  const [solutionEditor, setSolutionEditor] = useState(null);
  const [objPanelOpen, setObjPanelOpen] = useState({}); // { workshopKey: bool }
  const [objModalKey, setObjModalKey] = useState(null);  // challenge_key whose objectives modal is open
  const exerciseLoadRef = useRef({ sequence: 0, controller: null, key: null, mounted: false });
  const exerciseIdentity = JSON.stringify([user?.id, user?.isAdmin, user?.role, user?.adminLevel, user?.permissions, localStorage.getItem('token')]);
  const exerciseIdentityRef = useRef(exerciseIdentity);
  exerciseIdentityRef.current = exerciseIdentity;
  const activeSectionRef = useRef(activeSection);
  activeSectionRef.current = activeSection;

  const masterMutationsRef = useRef(new Map());
  const masterEpochRef = useRef(0);
  const staleMastersRef = useRef(new Map());
  const [staleMasters, setStaleMasters] = useState({});
  const [pendingMasters, setPendingMasters] = useState({});
  useEffect(() => {
    masterEpochRef.current++;
    setPendingMasters({});
    return () => {
      masterEpochRef.current++;
      for (const operation of masterMutationsRef.current.values()) operation.abort();
      masterMutationsRef.current.clear();
    };
  }, [activeSection, exerciseIdentity]);

  useEffect(() => {
    staleMastersRef.current.clear(); setStaleMasters({});
  }, [exerciseIdentity]);

  useEffect(() => {
    for (const [key, prior] of staleMastersRef.current) {
      if (snapshotReadSequence > prior.barrier
          && canonicalConfig?.exercises?.[key]?.[prior.field] === prior.enabled) staleMastersRef.current.delete(key);
    }
    setStaleMasters(Object.fromEntries([...staleMastersRef.current.keys()].map(key => [key, true])));
  }, [canonicalConfig, snapshotReadSequence]);

  const [resettingWorkshop, setResettingWorkshop] = useState({}); // { workshopKey: bool }
  const [resetConfirm, setResetConfirm] = useState(null); // Staged workshop and administrator authority
  const stagedBulkResetRef = useRef(null);
  const bulkResetEpochRef = useRef(0);
  const bulkResetPendingRef = useRef(null);
  const resetAuthRevision = getAuthRevisionRef.current ? getAuthRevisionRef.current() : null;
  useEffect(() => {
    const staged = stagedBulkResetRef.current;
    if (staged && (!isCurrentAdminAuthority(staged.authority) || !resetPermissionRef.current)) {
      bulkResetEpochRef.current += 1;
      stagedBulkResetRef.current = null;
      setResetConfirm(null);
    }
  }, [exerciseIdentity, resetAuthRevision]);
  useEffect(() => {
    const staged = stagedAccountAccessRef.current;
    if (staged && (!isCurrentAdminAuthority(staged.authority) || !accountAccessPermissionRef.current)) {
      stagedAccountAccessRef.current = null;
      setAccountAccessConfirm(null);
      setAccountAccessStatus(null);
    }
  }, [exerciseIdentity, resetAuthRevision]);
  useEffect(() => {
    const staged = stagedBulkVisibilityRef.current;
    if (staged && (!isCurrentAdminAuthority(staged.authority) || !challengePermissionRef.current
      || activeSection !== 'exercises')) {
      stagedBulkVisibilityRef.current = null;
      setBulkVisibilityConfirm(null);
      setBulkVisibilityOutcome(null);
    }
  }, [exerciseIdentity, resetAuthRevision, activeSection]);
  useEffect(() => {
    const staged = stagedBulkContentRef.current;
    if (staged && (!isCurrentAdminAuthority(staged.authority) || !challengePermissionRef.current
      || activeSection !== 'exercises')) {
      stagedBulkContentRef.current = null;
      setBulkContentConfirm(null);
      setBulkContentOutcome(null);
    }
  }, [exerciseIdentity, resetAuthRevision, activeSection]);
  useEffect(() => {
    const selfPassword = stagedSelfPasswordRef.current;
    if (selfPassword && (!isCurrentAdminAuthority(selfPassword.authority)
      || !selfPasswordPermissionRef.current || activeSection !== 'settings')) {
      stagedSelfPasswordRef.current = null;
      setSelfPasswordStage(null);
      setSelfPasswordOutcome(null);
      setChangePasswordModalOpen(false);
      setPasswords(emptySelfPasswordDraft());
    }
    const createStage = stagedStudentCreateRef.current;
    if (createStage && (!isCurrentAdminAuthority(createStage.authority)
      || !accountAccessPermissionRef.current || activeSection !== 'students')) {
      stagedStudentCreateRef.current = null;
      setStudentCreateStage(null);
      setStudentCreateOutcome(null);
      setCreateStudentModalOpen(false);
      setNewStudent(emptyStudentDraft());
    }
    const editStage = stagedStudentEditRef.current;
    if (editStage && (!isCurrentAdminAuthority(editStage.authority)
      || !accountAccessPermissionRef.current || activeSection !== 'students')) {
      stagedStudentEditRef.current = null;
      setStudentEditStage(null);
      setStudentEditOutcome(null);
      setStudentToEdit(null);
      setEditStudentModalOpen(false);
    }
    const passwordStage = stagedStudentPasswordRef.current;
    if (passwordStage && (!isCurrentAdminAuthority(passwordStage.authority)
      || !accountAccessPermissionRef.current || activeSection !== 'students')) {
      stagedStudentPasswordRef.current = null;
      setStudentPasswordStage(null);
      setStudentPasswordOutcome(null);
      setStudentForPasswordChange(null);
      setChangeStudentPasswordModalOpen(false);
      setPasswordChangeData({ newPassword: '', confirmPassword: '' });
    }
    const staged = stagedDeactivationRef.current;
    if (staged && (!isCurrentAdminAuthority(staged.authority) || !deactivationPermissionRef.current
      || !userManagementModalOpen || userManagementTab !== 'administrators' || activeSection !== 'settings')) {
      stagedDeactivationRef.current = null;
      setDeactivatingAdministrator(null);
      setDeactivationOutcome(null);
    }
    const edit = stagedAdministratorEditRef.current;
    if (edit && (!isCurrentAdminAuthority(edit.authority) || !deactivationPermissionRef.current
      || !userManagementModalOpen || userManagementTab !== 'administrators' || activeSection !== 'settings')) {
      stagedAdministratorEditRef.current = null;
      setAdministratorEditStage(null);
      setEditingAdministrator(null);
      setAdministratorEditOutcome(null);
    }
    const create = stagedAdministratorCreateRef.current;
    if (create && (!isCurrentAdminAuthority(create.authority) || !deactivationPermissionRef.current
      || !userManagementModalOpen || userManagementTab !== 'administrators' || activeSection !== 'settings')) {
      stagedAdministratorCreateRef.current = null;
      setAdministratorCreateStage(null);
      setAdministratorCreateOutcome(null);
      setCreateAdministratorOpen(false);
      setNewAdministrator(emptyAdministratorDraft());
    }
  }, [exerciseIdentity, resetAuthRevision, userManagementModalOpen, userManagementTab, activeSection]);

  // Workshop signup random email toggle state
  const [randomEmailEnabled, setRandomEmailEnabled] = useState(false);
  const [randomEmailLoading, setRandomEmailLoading] = useState(false);
  const [rateLimitEnabled, setRateLimitEnabled] = useState(false);
  const [rateLimitLoading, setRateLimitLoading] = useState(false);
  const [secureshopVisible, setSecureshopVisible] = useState(false);
  const [secureshopLoading, setSecureshopLoading] = useState(false);
  const [allowRegistration, setAllowRegistration] = useState(true);
  const [allowRegistrationLoading, setAllowRegistrationLoading] = useState(false);
  const configReconcileGenerationRef = useRef(0);
  const initialConfigLoadRef = useRef(null);

  // Load locked users data
  const fetchLockedUsers = async (authority = captureAdminAuthority(), reportError = true) => {
    const generation = ++lockedUsersLoadGenerationRef.current;
    const current = () => studentDeletionMountedRef.current && generation === lockedUsersLoadGenerationRef.current
      && isCurrentAdminAuthority(authority);
    if (!authority) {
      setLockedUsers([]);
      setLoadingLockedUsers(false);
      return;
    }
    try {
      setLoadingLockedUsers(true);
      const response = await axios.get('/api/admin/users/locked', {
        headers: { 'Authorization': `Bearer ${authority.token}` }
      });

      if (current() && response.data.success && Array.isArray(response.data.lockedUsers)) {
        setLockedUsers(response.data.lockedUsers || []);
      }
    } catch (error) {
      if (current()) {
        console.error('Failed to fetch locked users:', error);
        if (reportError) toast.error('Failed to fetch locked users: ' + (error.response?.data?.error || error.message));
      }
    } finally {
      if (current()) setLoadingLockedUsers(false);
    }
  };

  const closeAccountAccessConfirm = staged => {
    if (stagedAccountAccessRef.current !== staged || pendingAccountAccessRef.current === staged) return;
    stagedAccountAccessRef.current = null;
    setAccountAccessConfirm(null);
    setAccountAccessStatus(null);
  };
  const stageAccountAccess = (action, target) => {
    if (!accountAccessPermissionRef.current || stagedAccountAccessRef.current || pendingAccountAccessRef.current) return;
    const authority = captureAdminAuthority();
    if (!authority) return;
    const staged = { action, target: { id: target.id, username: target.username || `User ${target.id}` }, authority, consumed: false };
    stagedAccountAccessRef.current = staged;
    setAccountAccessStatus(null);
    setAccountAccessConfirm(staged);
  };
  const lockUser = (userId, username) => stageAccountAccess('lock', { id: userId, username });
  const unlockUser = (userId, username) => stageAccountAccess('unlock', { id: userId, username });
  const confirmAccountAccess = async staged => {
    if (stagedAccountAccessRef.current !== staged || staged.consumed || pendingAccountAccessRef.current
      || !accountAccessPermissionRef.current || !isCurrentAdminAuthority(staged.authority)) return;
    staged.consumed = true;
    pendingAccountAccessRef.current = staged;
    setAccountAccessStatus({ kind: 'pending' });
    const current = () => studentDeletionMountedRef.current && stagedAccountAccessRef.current === staged
      && isCurrentAdminAuthority(staged.authority) && accountAccessPermissionRef.current;
    const headers = { Authorization: `Bearer ${staged.authority.token}` };
    try {
      const response = await axios.post(`/api/admin/users/${staged.target.id}/${staged.action}`, {}, { headers });
      if (!current()) return;
      if (response.data?.success !== true) throw new Error('The server did not acknowledge the account change.');
      toast.success(`${staged.target.username} ${staged.action === 'lock' ? 'locked' : 'unlocked'}`);
      stagedAccountAccessRef.current = null;
      setAccountAccessConfirm(null);
      setAccountAccessStatus(null);
      // A self-lock can revoke this very session; the acknowledged result remains valid even if this read fails.
      await fetchLockedUsers(staged.authority, false);
    } catch (error) {
      if (!current()) return;
      if (error.response?.status >= 400 && error.response.status < 500 && error.response.status !== 408) {
        setAccountAccessStatus({ kind: 'rejected', message: error.response.data?.error || 'The server rejected this account change.' });
        return;
      }
      // A failed or lost acknowledgement does not establish whether the mutation committed.
      try {
        const detail = await axios.get(`/api/admin/users/${staged.target.id}`, { headers });
        if (!current()) return;
        const account = detail.data?.user;
        if (!detail.data?.success || !account || String(account.id) !== String(staged.target.id))
          throw new Error('Target account details were unavailable.');
        const lockUntil = account.account_locked_until;
        if (lockUntil !== null && (typeof lockUntil !== 'string' || !lockUntil.trim()
          || !Number.isFinite(Date.parse(lockUntil)))) throw new Error('Invalid account lock timestamp.');
        const locked = lockUntil !== null && Date.parse(lockUntil) > Date.now();
        setAccountAccessStatus({ kind: 'unknown', observed: locked ? 'locked' : 'unlocked' });
      } catch (readError) {
        if (current()) setAccountAccessStatus({ kind: 'unknown', observed: null });
      }
    } finally {
      if (pendingAccountAccessRef.current === staged) pendingAccountAccessRef.current = null;
    }
  };

  // Capture authority at render time so a retained button callback cannot stage B's session.
  const bulkVisibilityRenderAuthority = captureAdminAuthority();
  const stageBulkVisibility = enabled => {
    if (!studentDeletionMountedRef.current || !challengePermissionRef.current
      || activeSectionRef.current !== 'exercises' || !isCurrentAdminAuthority(bulkVisibilityRenderAuthority)
      || stagedBulkVisibilityRef.current || pendingBulkVisibilityRef.current) return;
    const staged = { enabled, authority: bulkVisibilityRenderAuthority, consumed: false };
    stagedBulkVisibilityRef.current = staged;
    setBulkVisibilityConfirm(staged);
    setBulkVisibilityOutcome(null);
  };
  const closeBulkVisibility = staged => {
    if (stagedBulkVisibilityRef.current !== staged || pendingBulkVisibilityRef.current === staged) return;
    stagedBulkVisibilityRef.current = null;
    setBulkVisibilityConfirm(null);
    setBulkVisibilityOutcome(null);
  };
  const confirmBulkVisibility = async staged => {
    if (!studentDeletionMountedRef.current || stagedBulkVisibilityRef.current !== staged
      || staged.consumed || pendingBulkVisibilityRef.current || !challengePermissionRef.current
      || activeSectionRef.current !== 'exercises' || !isCurrentAdminAuthority(staged.authority)) return;
    staged.consumed = true;
    pendingBulkVisibilityRef.current = staged;
    setBulkTogglingChallenges(true);
    setBulkVisibilityOutcome({ kind: 'pending' });
    const current = () => studentDeletionMountedRef.current && stagedBulkVisibilityRef.current === staged
      && challengePermissionRef.current && activeSectionRef.current === 'exercises'
      && isCurrentAdminAuthority(staged.authority);
    try {
      const response = await axios.post('/api/admin/challenges/bulk-toggle', { enabled: staged.enabled },
        { headers: { Authorization: `Bearer ${staged.authority.token}` } });
      if (!current()) return;
      const data = response.data;
      const validRevision = (typeof data?.revision === 'string' && /^\d+$/.test(data.revision))
        || (typeof data?.revision === 'number' && Number.isSafeInteger(data.revision) && data.revision >= 0);
      const unavailableWorkshops = Array.isArray(data?.unavailableWorkshops)
        && data.unavailableWorkshops.every(key => typeof key === 'string') ? data.unavailableWorkshops : [];
      const validSnapshot = data?.exercises && typeof data.exercises === 'object' && !Array.isArray(data.exercises)
        && Object.entries(data.exercises).every(([key, item]) => item && typeof item === 'object'
          && !Array.isArray(item) && item.workshopKey === key
          && typeof item.isVisible === 'boolean' && (item.isVisible === staged.enabled
            || (staged.enabled && unavailableWorkshops.includes(key) && item.isVisible === false)));
      const validAck = response.status === 200 && data?.success === true && data.enabled === staged.enabled
        && typeof data.changed === 'boolean' && Number.isSafeInteger(data.affectedCount)
        && data.affectedCount >= 0 && data.affectedCount <= Object.keys(data.exercises || {}).length
        && data.changed === (data.affectedCount > 0)
        && validRevision && validSnapshot;
      if (!validAck) throw new Error('The server response did not confirm the visibility change.');
      stagedBulkVisibilityRef.current = null;
      setBulkVisibilityConfirm(null);
      setBulkVisibilityOutcome(null);
      const skipped = staged.enabled && unavailableWorkshops.length;
      toast.success(skipped
        ? `All ready exercises enabled. ${unavailableWorkshops.join(', ')} remains hidden until its runtime is ready.`
        : `All catalog-active exercises ${staged.enabled ? 'enabled' : 'disabled'}${data.changed ? '' : ' (already in this state)'}.`);
      void loadDashboardData(true, () => studentDeletionMountedRef.current
        && challengePermissionRef.current && activeSectionRef.current === 'exercises'
        && isCurrentAdminAuthority(staged.authority));
    } catch (error) {
      if (!current()) return;
      setBulkVisibilityOutcome({ kind: error.response?.status >= 400 && error.response.status < 500
        && error.response.status !== 408 ? 'rejected' : 'unknown' });
    } finally {
      if (pendingBulkVisibilityRef.current === staged) {
        pendingBulkVisibilityRef.current = null;
        if (studentDeletionMountedRef.current) setBulkTogglingChallenges(false);
      }
    }
  };

  const stageBulkContentVisibility = enabled => {
    if (bulkContentRef.current || !challengePermissionRef.current || activeSectionRef.current !== 'exercises'
      || stagedBulkContentRef.current || pendingBulkContentRef.current) return;
    const authority = captureAdminAuthority();
    if (!authority) return;
    const staged = { enabled, authority, consumed: false };
    stagedBulkContentRef.current = staged;
    setBulkContentConfirm(staged);
    setBulkContentOutcome(null);
  };
  const closeBulkContentVisibility = staged => {
    if (stagedBulkContentRef.current !== staged || pendingBulkContentRef.current === staged) return;
    stagedBulkContentRef.current = null;
    setBulkContentConfirm(null);
    setBulkContentOutcome(null);
  };
  const confirmBulkContentVisibility = async staged => {
    if (bulkContentRef.current || stagedBulkContentRef.current !== staged || staged.consumed
      || pendingBulkContentRef.current || !challengePermissionRef.current
      || activeSectionRef.current !== 'exercises' || !isCurrentAdminAuthority(staged.authority)) return;
    staged.consumed = true;
    pendingBulkContentRef.current = staged;
    bulkContentRef.current = true;
    setBulkContentPending(true);
    setBulkContentOutcome({ kind: 'pending' });
    const current = () => stagedBulkContentRef.current === staged && challengePermissionRef.current
      && activeSectionRef.current === 'exercises' && isCurrentAdminAuthority(staged.authority);
    try {
      const response = await axios.patch('/api/admin/exercises/content-visibility', { enabled: staged.enabled }, {
        headers: { Authorization: `Bearer ${staged.authority.token}` }, timeout: 10000,
      });
      if (!current()) return;
      const data = response.data;
      const validRevision = (typeof data?.revision === 'string' && /^\d+$/.test(data.revision))
        || (typeof data?.revision === 'number' && Number.isSafeInteger(data.revision) && data.revision >= 0);
      const exercises = data?.exercises;
      const validExercises = exercises && typeof exercises === 'object' && !Array.isArray(exercises)
        && Object.values(exercises).every(exercise => exercise && typeof exercise === 'object'
          && exercise.showHints === staged.enabled && exercise.showSolutions === staged.enabled);
      if (response.status !== 200 || data?.success !== true || typeof data.changed !== 'boolean'
        || !validRevision || !validExercises) {
        throw new Error('The server response did not confirm the content visibility change.');
      }
      stagedBulkContentRef.current = null;
      setBulkContentConfirm(null);
      setBulkContentOutcome(null);
      setChallenges(previous => previous.map(challenge => {
        const exercise = exercises[toWorkshopKey(challenge.key || challenge.id || challenge.workshopKey)];
        return exercise ? { ...challenge, enabled: exercise.isVisible, showHints: exercise.showHints,
          showSolutions: exercise.showSolutions } : challenge;
      }));
      // The mutation response is authoritative. Refresh the shared projection afterwards,
      // but do not report a committed update as failed if that independent read is delayed.
      void refreshAfterMutation();
      toast.success(`All available hints and solutions ${staged.enabled ? 'enabled' : 'disabled'}${data.changed ? '' : ' (already in this state)'}.`);
    } catch (error) {
      if (!current()) return;
      setBulkContentOutcome({ kind: error.response?.status >= 400 && error.response.status < 500
        && error.response.status !== 408 ? 'rejected' : 'unknown' });
    } finally {
      if (pendingBulkContentRef.current === staged) {
        pendingBulkContentRef.current = null;
        bulkContentRef.current = false;
        setBulkContentPending(false);
      }
    }
  };

  // CTF visibility is now managed entirely in CTF Management → Config tab

  // Load settings when their panel is entered.
  useEffect(() => {
    if (activeSection !== 'settings') return;
    const loadRandomEmailSetting = async () => {
      try {
        const response = await axios.get('/api/auth/signup-config');
        setRandomEmailEnabled(response.data.randomEmailEnabled === true);
      } catch (error) {
        console.error('Failed to load random email setting:', error);
      }
    };
    loadRandomEmailSetting();
  }, [activeSection]);

  // Load rate limiting settings only for their panel.
  useEffect(() => {
    if (activeSection !== 'settings') return;
    const loadRateLimitSetting = async () => {
      try {
        const token = localStorage.getItem('token');
        const response = await axios.get('/api/admin/config', {
          headers: { 'Authorization': `Bearer ${token}` }
        });
        const cfg = response.data.config || {};
        setRateLimitEnabled(cfg.enable_rate_limiting?.value === 'true');
        setSecureshopVisible(cfg.secureshop_visible?.value === 'true');
        setAllowRegistration(cfg.allow_registration?.value !== 'false');
      } catch (error) {
        console.error('Failed to load rate limit setting:', error);
      }
    };
    loadRateLimitSetting();
  }, [activeSection]);

  // Toggle rate limiting
  const toggleRateLimit = async () => {
    try {
      setRateLimitLoading(true);
      const token = localStorage.getItem('token');
      const newValue = !rateLimitEnabled;

      await axios.put('/api/admin/config/enable_rate_limiting',
        { value: newValue ? 'true' : 'false', type: 'boolean', description: 'Enable API rate limiting on authentication endpoints' },
        { headers: { 'Authorization': `Bearer ${token}` } }
      );

      setRateLimitEnabled(newValue);
      toast.success(`Rate limiting ${newValue ? 'enabled' : 'disabled'}`);
    } catch (error) {
      console.error('Failed to toggle rate limiting:', error);
      toast.error('Failed to toggle rate limiting: ' + (error.response?.data?.error || error.message));
    } finally {
      setRateLimitLoading(false);
    }
  };

  const toggleSecureshop = async () => {
    try {
      setSecureshopLoading(true);
      const token = localStorage.getItem('token');
      const newValue = !secureshopVisible;
      await axios.put('/api/admin/config/secureshop_visible',
        { value: newValue ? 'true' : 'false', type: 'boolean', description: 'Show SecureShop Playground card on landing and workshop pages', isPublic: true },
        { headers: { 'Authorization': `Bearer ${token}` } }
      );
      setSecureshopVisible(newValue);
      toast.success(`SecureShop Playground ${newValue ? 'shown' : 'hidden'}`);
    } catch (error) {
      console.error('Failed to toggle SecureShop:', error);
      toast.error('Failed to toggle SecureShop: ' + (error.response?.data?.error || error.message));
    } finally {
      setSecureshopLoading(false);
    }
  };

  // Toggle allow user registration
  const toggleAllowRegistration = async () => {
    try {
      setAllowRegistrationLoading(true);
      const token = localStorage.getItem('token');
      const newValue = !allowRegistration;
      await axios.put('/api/admin/config/allow_registration',
        { value: newValue ? 'true' : 'false', type: 'boolean', description: 'Allow new users to register accounts' },
        { headers: { 'Authorization': `Bearer ${token}` } }
      );
      setAllowRegistration(newValue);
      toast.success(`User registration ${newValue ? 'enabled' : 'disabled'}`);
    } catch (error) {
      console.error('Failed to toggle allow_registration:', error);
      toast.error('Failed to update registration setting');
    } finally {
      setAllowRegistrationLoading(false);
    }
  };

  // Toggle random email on signup
  const toggleRandomEmail = async () => {
    try {
      setRandomEmailLoading(true);
      const token = localStorage.getItem('token');
      const newValue = !randomEmailEnabled;
      
      await axios.put('/api/admin/config/workshop_signup_random_email_enabled', 
        { value: newValue ? 'true' : 'false', type: 'boolean', description: 'Show "Generate random email" button on workshop signup page' },
        { headers: { 'Authorization': `Bearer ${token}` } }
      );
      
      setRandomEmailEnabled(newValue);
      toast.success(`Random email button ${newValue ? 'enabled' : 'disabled'} on signup page`);
    } catch (error) {
      console.error('Failed to toggle random email setting:', error);
      toast.error('Failed to toggle random email setting: ' + (error.response?.data?.error || error.message));
    } finally {
      setRandomEmailLoading(false);
    }
  };

  // Load activity data (moved from renderActivityLogs to fix hooks error)
  const loadActivityData = async (page = activityPage) => {
    const requestId = ++activityRequestRef.current;
    setLoadingActivity(true);
    setActivityLoadError(null);
    try {
      const [statsResponse, activityResponse] = await Promise.all([
        axios.get('/api/admin/activity-stats'),
        axios.get(`/api/admin/activity-logs?limit=${activityPerPage}&page=${page}`),
      ]);
      if (requestId !== activityRequestRef.current) return;
      setActivityStats(statsResponse.data.stats || {});
      setRecentActivity(activityResponse.data.logs || []);
      setActivityTotalPages(activityResponse.data.pagination?.pages || 1);
      setActivityTotalCount(activityResponse.data.pagination?.total || 0);
    } catch (error) {
      if (requestId !== activityRequestRef.current) return;
      console.error('Error loading activity data:', error);
      setActivityStats({});
      setRecentActivity([]);
      setActivityTotalPages(1);
      setActivityTotalCount(0);
      setActivityLoadError('Unable to load activity logs. Refresh to try again.');
      toast.error('Failed to load activity data');
    } finally {
      if (requestId === activityRequestRef.current) setLoadingActivity(false);
    }
  };

  useEffect(() => () => { activityRequestRef.current += 1; }, []);

  // Load active users with their activity
  const loadActiveUsersData = async () => {
    if (!canViewActiveUsers) return;
    const requestId = ++activeUsersRequestRef.current;
    try {
      setLoadingActiveUsers(true);
      setActiveUsersLoadError(null);
      
      const users = await loadAdminActivityUsers(
        (...args) => axios.get(...args),
        () => requestId === activeUsersRequestRef.current
      );
      if (users !== null) {
        activeUsersRef.current = users;
        setActiveUsers(users);
      }
    } catch (error) {
      if (requestId !== activeUsersRequestRef.current) return;
      console.error('Error loading active users:', error);
      if ([401, 403].includes(error.response?.status)) {
        activeUsersRef.current = [];
        setActiveUsers([]);
        setActiveUsersLoadError('Active user data is no longer accessible. Restore access and refresh.');
      } else {
        setActiveUsersLoadError(activeUsersRef.current.length > 0
          ? 'Unable to refresh active users. Showing previously loaded data.'
          : 'Active user data is unavailable. Refresh to try again.');
      }
      toast.error('Failed to load active users data');
    } finally {
      if (requestId === activeUsersRequestRef.current) setLoadingActiveUsers(false);
    }
  };

  useEffect(() => {
    activeUsersRequestRef.current += 1;
    activeUsersRef.current = [];
    setActiveUsers([]);
    setLoadingActiveUsers(false);
    setActiveUsersLoadError(null);
    if (canViewActiveUsers && ['dashboard','activity'].includes(activeSection)) loadActiveUsersData();
    return () => { activeUsersRequestRef.current += 1; };
    // Permission changes must immediately retire in-flight privileged data.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [user?.id, canViewActiveUsers, activeSection]);

  // Load LLM health data (moved from renderLLMHealth to fix React hooks error)
  // deep=false (default): fast reachability/config probe — opens instantly.
  // deep=true: live generation test per provider (slower; triggered by the button).
  const fetchLlmHealthData = async (deep = false) => {
    try {
      setLlmHealthLoading(true);
      const [healthRes, statsRes] = await Promise.all([
        axios.get(`/api/admin/llm/health${deep ? '?deep=1' : ''}`),
        axios.get('/api/admin/llm/stats')
      ]);
      
      setLlmHealthData(healthRes.data.health);
      setLlmStatsData(statsRes.data.stats);
    } catch (error) {
      console.error('Failed to fetch LLM data:', error);
      toast.error('Failed to fetch LLM health data');
    } finally {
      setLlmHealthLoading(false);
    }
  };

  // Update active section when location changes
  useEffect(() => {
    setActiveSection(getActiveSectionFromPath());
  }, [location.pathname]);
  
  const retireExerciseContent = useCallback(() => {
    setPiSolutionChallenges([]); setXssObjectives([]); setCsrfObjectives([]); setFinflowSolutions([]);
    setScSolutions([]); setEaSolutions([]); setIpiSolutions([]); setMcpSolutions([]);
    setSqliObjectives([]); setNosqliObjectives([]); setSolutions([]);
    setWorkshopObjectives({}); setWorkshopHints({});
    setHintEditor(null); setObjectiveEditor(null); setSolutionEditor(null);
    setObjModalKey(null); setSelectedSolution(null); setSolutionModalOpen(false);
  }, []);
  const loadExerciseState = useCallback(async (key, { signal } = {}) => {
    const state = exerciseLoadRef.current;
    state.controller?.abort();
    const controller = new AbortController(), sequence = ++state.sequence;
    state.controller = controller;
    const identity = exerciseIdentityRef.current, token = localStorage.getItem('token');
    const abort = () => controller.abort();
    if (signal?.aborted) abort(); else signal?.addEventListener('abort', abort, { once: true });
    const current = () => state.mounted && !controller.signal.aborted && state.sequence === sequence
      && identity === exerciseIdentityRef.current && token === localStorage.getItem('token')
      && activeSectionRef.current === 'exercises' && state.key === key;
    try {
      if (initialConfigLoadRef.current) await initialConfigLoadRef.current;
      if (!current()) return false;
      const result = await readAdminExerciseState({ get: axios.get, key, workshopKey: key && workshopKeyRef.current(key),
        config: { headers: { Authorization: `Bearer ${token}` }, signal: controller.signal, timeout: 10000 } });
      if (!current()) return false;
      setChallenges(result.challenges.filter(row => row.key !== 'ctf_prompt_injection_challenge'));
      if (key) {
        setWorkshopObjectives({ [key]: result.objectives });
        const enabled = {};
        result.objectives.forEach(row => { enabled[row.objective_id] = !!row.hint_enabled; });
        // The hints endpoint is effective visibility; editable toggles retain stored objective flags.
        setWorkshopHints({ [key]: enabled });
        const setters = { pi: setPiSolutionChallenges, xss: setXssObjectives, csrf: setCsrfObjectives,
          finflow: setFinflowSolutions, supplyChain: setScSolutions, ea: setEaSolutions, ipi: setIpiSolutions,
          mcp: setMcpSolutions, sql: setSqliObjectives, nosql: setNosqliObjectives, generic: setSolutions };
        if (result.target) setters[result.target](result.content);
        setObjModalKey(key);
      }
      setLoading(false);
      return true;
    } catch (error) {
      if (current()) { setLoading(false); retireExerciseContent(); toast.error('Unable to load current exercise controls.'); throw error; }
      return false;
    } finally { signal?.removeEventListener('abort', abort); }
  }, [retireExerciseContent]);
  useEffect(() => {
    const state = exerciseLoadRef.current;
    state.mounted = true; state.key = null; dashboardRequestRef.current++;
    retireExerciseContent();
    if (activeSection === 'exercises') { setChallenges([]); setLoading(true); void loadExerciseState(null).catch(() => {}); }
    return () => { state.mounted = false; state.sequence++; state.controller?.abort(); };
  }, [activeSection, exerciseIdentity, loadExerciseState, retireExerciseContent]);

  // Initialize data on first mount only - AGGRESSIVE PRE-LOADING for instant tab switching
  useEffect(() => {
    if (activeSection === 'exercises') return;
    // Other panels retain their existing initial data contracts.
    const loadAllData = async () => {
      try {
        // Track every initial writer that overlaps the canonical configuration snapshot.
        const configLoad = Promise.allSettled([
          loadDashboardData(),
          loadPiSolutionChallenges(),
          loadXssObjectives(),
          loadCsrfObjectives(),
          loadFinflowSolutions(),
          loadScSolutions(),
          loadEaSolutions(),
          loadIpiSolutions(),
          loadMcpSolutions(),
          fetchSqliObjectives(),
          fetchNosqliObjectives(),
          loadSolutions(),
        ]);
        initialConfigLoadRef.current = configLoad;
        void configLoad.finally(() => {
          if (initialConfigLoadRef.current === configLoad) initialConfigLoadRef.current = null;
        });

        // Pre-load commonly accessed tab data in parallel (non-blocking)
        // Note: Progress analytics now self-loads in ProgressAnalyticsPanel
        Promise.all([
          loadActivityData(),           // Activity tab
        ]).catch(error => {
          console.error('Pre-loading failed for some tabs:', error);
          // Don't toast error - this is background loading
        });
        
        // LLM health and AI providers load on-demand (less critical)
      } catch (error) {
        console.error('Initial data load error:', error);
      }
    };
    
    loadAllData();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeSection, exerciseIdentity]); // Refresh on panel/identity entry

  const loadConfigStateInBackground = useCallback(async (_revision, { signal } = {}) => {
    if (activeSectionRef.current === 'exercises') return runAfterTrackedLoad(initialConfigLoadRef, () => loadExerciseState(exerciseLoadRef.current.key, { signal }));
    const generation = configReconcileGenerationRef.current, identity = exerciseIdentityRef.current, credential = localStorage.getItem('token');
    return runAfterTrackedLoad(initialConfigLoadRef, async () => {
      if (signal?.aborted || generation !== configReconcileGenerationRef.current || identity !== exerciseIdentityRef.current || credential !== localStorage.getItem('token')) return;
      const token = localStorage.getItem('token');
      const config = { headers: { Authorization: `Bearer ${token}` }, signal };
      const [
        challengesResponse,
        studentsResponse,
        piResponse,
        xssResponse,
        csrfResponse,
        finflowResponse,
        supplyChainResponse,
        eaResponse,
        ipiResponse,
        mcpResponse,
        sqlResponse,
        nosqlResponse,
      ] = await Promise.all([
        axios.get('/api/admin/challenges', config),
        canManageProgress ? axios.get('/api/admin/students', config) : Promise.resolve(null),
        axios.get('/api/admin/pi-workshop/solutions', config),
        axios.get('/api/admin/xss-workshop/objective-solutions', config),
        axios.get('/api/admin/csrf-workshop/objective-solutions', config),
        axios.get('/api/admin/finflow-workshop/solutions', config),
        axios.get('/api/admin/supply-chain-workshop/solutions', config),
        axios.get('/api/admin/ea-workshop/solutions', config),
        axios.get('/api/admin/ipi-workshop/solutions', config),
        axios.get('/api/admin/mcp-workshop/solutions', config),
        axios.get('/api/admin/sql-injection-workshop/solutions', config),
        axios.get('/api/admin/nosql-injection-workshop/solutions', config),
      ]);

      const requireList = (value, label) => {
        if (!Array.isArray(value)) throw new Error(`Invalid ${label} response`);
        return value;
      };
      if (!challengesResponse.data?.success || (canManageProgress && !studentsResponse.data?.success)) {
        throw new Error('Invalid admin dashboard response');
      }

      const challengeRows = requireList(challengesResponse.data.challenges, 'challenges');
      const studentRows = canManageProgress ? requireList(studentsResponse.data.students, 'students') : [];
      const nextState = {
        challenges: challengeRows.filter((challenge) => challenge.key !== 'ctf_prompt_injection_challenge'),
        pi: requireList(piResponse.data?.challenges, 'prompt injection solutions'),
        xss: requireList(xssResponse.data?.objectives, 'XSS objectives'),
        csrf: requireList(csrfResponse.data?.objectives, 'CSRF objectives'),
        finflow: requireList(finflowResponse.data?.objectives, 'FinFlow solutions'),
        supplyChain: requireList(supplyChainResponse.data?.solutions, 'supply chain solutions'),
        ea: requireList(eaResponse.data?.objectives, 'excessive agency solutions'),
        ipi: requireList(ipiResponse.data?.objectives, 'indirect prompt injection solutions'),
        mcp: requireList(mcpResponse.data?.objectives, 'MCP solutions'),
        sql: requireList(sqlResponse.data?.objectives, 'SQL injection objectives'),
        nosql: requireList(nosqlResponse.data?.objectives, 'NoSQL injection objectives'),
      };
      if (signal?.aborted || generation !== configReconcileGenerationRef.current || identity !== exerciseIdentityRef.current || credential !== localStorage.getItem('token')) return;

      setChallenges(nextState.challenges);
      setStudents(studentRows);
      setStats({
        totalStudents: studentRows.length,
        activeUsers: studentRows.filter((student) => student.enabled || student.is_active).length,
        completedChallenges: challengeRows.reduce((sum, challenge) => sum + (challenge.completions || 0), 0),
        totalChallenges: challengeRows.length,
        visibleChallenges: challengeRows.filter((challenge) => challenge.enabled).length,
      });
      setPiSolutionChallenges(nextState.pi);
      setXssObjectives(nextState.xss);
      setCsrfObjectives(nextState.csrf);
      setFinflowSolutions(nextState.finflow);
      setScSolutions(nextState.supplyChain);
      setEaSolutions(nextState.ea);
      setIpiSolutions(nextState.ipi);
      setMcpSolutions(nextState.mcp);
      setSqliObjectives(nextState.sql);
      setNosqliObjectives(nextState.nosql);
    });
  }, [canManageProgress, loadExerciseState]);

  useEffect(() => {
    const unregister = registerReconciler(loadConfigStateInBackground);
    return () => {
      configReconcileGenerationRef.current += 1;
      unregister();
    };
  }, [loadConfigStateInBackground, registerReconciler, activeSection, exerciseIdentity]);
  
  // Refresh tab-specific data when switching tabs (if already loaded, refresh silently)
  useEffect(() => {
    // Refresh activity data when switching to activity tab
    if (activeSection === 'activity') {
      if (recentActivity.length > 0) {
        // Already loaded, refresh silently
        loadActivityData();
        if (canViewActiveUsers) loadActiveUsersData();
      }
    }
    
    // Note: Progress analytics panel manages its own data loading
    
    // Load LLM health data on-demand (first visit only)
    if (activeSection === 'llm-health' && !llmHealthData) {
      fetchLlmHealthData();
    }
    
    // Refresh dashboard/students data if needed
    if (activeSection === 'students' || activeSection === 'dashboard') {
      if (!initialConfigLoadRef.current && (students.length === 0 || challenges.length === 0)) {
        loadDashboardData(true);
      }
    }

    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeSection]); // Only run when activeSection changes

  useEffect(() => {
    if (activeSection === 'locked-users') {
      setLockedUsers([]);
      void fetchLockedUsers();
    }
    else {
      lockedUsersLoadGenerationRef.current += 1;
      setLoadingLockedUsers(false);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeSection, exerciseIdentity, resetAuthRevision]);
  
  // Set up auto-refresh for real-time data
  useEffect(() => {
    const refreshInterval = setInterval(() => {
      if (activeSection === 'students' || activeSection === 'dashboard') {
        if (!initialConfigLoadRef.current) loadDashboardData(true); // Silent refresh
      }
      if (activeSection === 'activity') {
        loadActivityData();
        if (canViewActiveUsers) loadActiveUsersData();
      }
      if (activeSection === 'llm-health' && llmAutoRefresh) {
        fetchLlmHealthData();
      }
    }, 30000); // Refresh every 30 seconds
    
    return () => clearInterval(refreshInterval);
  }, [activeSection, llmAutoRefresh, activityPage, canViewActiveUsers, canManageProgress]); // eslint-disable-line react-hooks/exhaustive-deps

  // Reload activity data when page changes
  useEffect(() => {
    if (activeSection === 'activity') {
      loadActivityData(activityPage);
    }
  }, [activityPage]);

  // Update solutionData when editingSolution changes
  useEffect(() => {
    if (editingSolution) {
      setSolutionData({
        solution_title: editingSolution.title || '',
        solution_description: editingSolution.description || '',
        solution_steps: Array.isArray(editingSolution.steps) ? editingSolution.steps.join('\n') : '',
        solution_code: editingSolution.code || '',
        explanation: editingSolution.explanation || '',
        reference_links: Array.isArray(editingSolution.references) ? editingSolution.references.join('\n') : '',
        difficulty_level: editingSolution.difficultyLevel || 'medium',
        estimated_time: editingSolution.estimatedTime || '',
        prerequisites: Array.isArray(editingSolution.prerequisites) ? editingSolution.prerequisites.join(', ') : '',
        tags: Array.isArray(editingSolution.tags) ? editingSolution.tags.join(', ') : '',
        is_public: editingSolution.isPublic || false
      });
    }
  }, [editingSolution]);

  const loadDashboardData = async (silent = false, isCurrent = () => true) => {
    const requestId = ++dashboardRequestRef.current;
    if (!silent) {
      setLoading(true);
    }
    
    try {
      const token = localStorage.getItem('token');
      
      // Load challenges and students data in parallel for better performance
      const [challengesResponse, studentsResponse] = await Promise.all([
        axios.get('/api/admin/challenges', { 
          headers: { 'Authorization': `Bearer ${token}` },
          timeout: 30000 
        }),
        canManageProgress ? axios.get('/api/admin/students', {
          headers: { 'Authorization': `Bearer ${token}` },
          timeout: 30000 
        }) : Promise.resolve(null)
      ]);
      if (requestId !== dashboardRequestRef.current || !isCurrent()) return;
      
      // Validate and set challenges data (CTF is managed separately in CTF Management)
      if (challengesResponse.data && challengesResponse.data.success) {
        const challengesData = (challengesResponse.data.challenges || []).filter(
          c => c.key !== 'ctf_prompt_injection_challenge'
        );
        setChallenges(challengesData);
        console.log('[Admin] Loaded challenges:', challengesData.length);
      } else {
        console.warn('[Admin] Invalid challenges response:', challengesResponse.data);
        setChallenges([]);
      }
      
      // Validate and set students data  
      if (canManageProgress && studentsResponse.data && studentsResponse.data.success) {
        const studentsData = studentsResponse.data.students || [];
        setStudents(studentsData);
        console.log('[Admin] Loaded students:', studentsData.length);
      } else if (canManageProgress) {
        console.warn('[Admin] Invalid students response:', studentsResponse.data);
        setStudents([]);
      }
      
      // Update stats with real-time visibility information
      const challengesData = challengesResponse.data.challenges || [];
      const studentsData = canManageProgress ? studentsResponse.data.students || [] : [];
      
      setStats({
        totalStudents: studentsData.length,
        activeUsers: studentsData.filter(s => s.enabled || s.is_active).length,
        completedChallenges: challengesData.reduce((sum, c) => sum + (c.completions || 0), 0),
        totalChallenges: challengesData.length,
        visibleChallenges: challengesData.filter(c => c.enabled).length
      });
      
      if (!silent) {
        toast.success('Dashboard data refreshed', {
          toastId: 'dashboard-refresh'
        });
      }
    } catch (error) {
      if (requestId !== dashboardRequestRef.current || !isCurrent()) return;
      console.error('Error loading dashboard data:', error);
      console.error('Error details:', error.response?.data);
      
      if (!silent) {
        const errorMessage = error.response?.data?.error || error.message || 'Failed to load dashboard data';
        toast.error(errorMessage);
      }
      
      // Set empty arrays if API fails
      if (challenges.length === 0) {
        console.warn('[Admin] Using empty challenges array due to API error');
        setChallenges([]);
      }
      
      if (canManageProgress && students.length === 0) {
        console.warn('[Admin] Using empty students array due to API error');
        setStudents([]);
      }
    } finally {
      if (requestId === dashboardRequestRef.current && isCurrent() && !silent) {
        setLoading(false);
      }
    }
  };

  const toggleChallenge = async (challengeKey, enabled) => {
    const challenge = challenges.find(c => c.key === challengeKey || c.id === challengeKey);
    if (!challenge) return;
    return runMasterMutation(challengeKey, 'active', enabled, post =>
      post('/api/admin/challenges/toggle', { challengeKey, enabled }));
  };

  const openHintEditor = async (workshopKey, objectiveId, objectiveLabel) => {
    const identity = exerciseIdentityRef.current;
    const token = localStorage.getItem('token');
    try {
      const apiKey = toWorkshopKey(workshopKey);
      const response = await axios.get(
        `/api/admin/exercises/${apiKey}/objectives/${objectiveId}/hint`,
        { headers: { Authorization: `Bearer ${token}` } },
      );
      if (identity !== exerciseIdentityRef.current || token !== localStorage.getItem('token') || exerciseLoadRef.current.key !== workshopKey) return;
      if (!response.data.hint || typeof response.data.hint !== 'object') throw new Error('Hint content unavailable');
      setHintEditor({
        workshopKey,
        objectiveId,
        objectiveLabel,
        hint: { title: '', hints: [], ...response.data.hint },
      });
    } catch (error) {
      console.error('Failed to load hint content', error);
      toast.error('Failed to load hint content');
    }
  };

  const saveHintEditor = async (content) => {
    if (!hintEditor || hintSavePending.current) return;
    hintSavePending.current = true;
    setHintEditorSaving(true);
    try {
      const token = localStorage.getItem('token');
      const apiKey = toWorkshopKey(hintEditor.workshopKey);
      await axios.put(
        `/api/admin/exercises/${apiKey}/objectives/${hintEditor.objectiveId}/hint`,
        content,
        { headers: { Authorization: `Bearer ${token}` } },
      );
      await loadExerciseState(hintEditor.workshopKey);
      await refreshAfterMutation();
      setHintEditor(null);
      toast.success('Hint updated successfully');
    } catch (error) {
      console.error('Failed to save hint content', error);
      toast.error(error.response?.data?.error || 'Failed to save hint content');
    } finally {
      hintSavePending.current = false;
      setHintEditorSaving(false);
    }
  };

  const openObjectiveEditor = async (workshopKey, objectiveId) => {
    const identity = exerciseIdentityRef.current, token = localStorage.getItem('token');
    try {
      const { data } = await axios.get(`/api/admin/exercises/${toWorkshopKey(workshopKey)}/objectives/${objectiveId}`,
        { headers: { Authorization: `Bearer ${token}` } });
      if (identity !== exerciseIdentityRef.current || token !== localStorage.getItem('token') || exerciseLoadRef.current.key !== workshopKey) return;
      if (!data.objective || data.objective.objectiveId !== objectiveId) throw new Error('Objective unavailable');
      setObjectiveEditor({ workshopKey, ...data.objective });
    } catch (error) { toast.error(error.response?.data?.error || 'Failed to load objective'); }
  };

  const saveObjectiveEditor = async patch => {
    if (!objectiveEditor) return;
    const { workshopKey, objectiveId } = objectiveEditor, token = localStorage.getItem('token');
    await axios.put(`/api/admin/exercises/${toWorkshopKey(workshopKey)}/objectives/${objectiveId}`, patch,
      { headers: { Authorization: `Bearer ${token}` } });
    await loadExerciseState(workshopKey);
    await refreshAfterMutation();
    setObjectiveEditor(null);
    toast.success('Objective updated');
  };

  const openUniversalSolutionEditor = async (workshopKey, objectiveId) => {
    const identity = exerciseIdentityRef.current, token = localStorage.getItem('token');
    try {
      const { data } = await axios.get(`/api/admin/exercises/${toWorkshopKey(workshopKey)}/objectives/${objectiveId}/solution`,
        { headers: { Authorization: `Bearer ${token}` } });
      if (identity !== exerciseIdentityRef.current || token !== localStorage.getItem('token') || exerciseLoadRef.current.key !== workshopKey) return;
      if (!data.solution || typeof data.solution !== 'object') throw new Error('Solution content unavailable');
      setSolutionEditor({ workshopKey, objectiveId, solution: data.solution });
    } catch (error) { toast.error(error.response?.data?.error || 'Failed to load solution'); }
  };

  const saveUniversalSolutionEditor = async patch => {
    if (!solutionEditor) return;
    const { workshopKey, objectiveId } = solutionEditor, token = localStorage.getItem('token');
    await axios.put(`/api/admin/exercises/${toWorkshopKey(workshopKey)}/objectives/${objectiveId}/solution`, patch,
      { headers: { Authorization: `Bearer ${token}` } });
    await loadExerciseState(workshopKey);
    await refreshAfterMutation();
    setSolutionEditor(null);
    toast.success('Solution updated');
  };

  const toggleHint = async (workshopKey, objectiveId, currentEnabled) => {
    const identity = exerciseIdentityRef.current;
    const token = localStorage.getItem('token');
    const current = () => identity === exerciseIdentityRef.current
      && token === localStorage.getItem('token') && exerciseLoadRef.current.mounted
      && exerciseLoadRef.current.key === workshopKey && activeSectionRef.current === 'exercises';
    try {
      const apiKey = toWorkshopKey(workshopKey);
      const { data } = await axios.post(`/api/admin/workshops/${apiKey}/hints/${objectiveId}/toggle`,
        { enabled: !currentEnabled },
        { headers: { Authorization: `Bearer ${token}` } }
      );
      if (!current()) return;
      const enabled = data.exercise?.objectives?.[objectiveId]?.raw?.hintEnabled;
      if (typeof enabled !== 'boolean') throw new Error('Canonical hint gate unavailable');
      setWorkshopHints(prev => ({
        ...prev,
        [workshopKey]: { ...(prev[workshopKey] || {}), [objectiveId]: enabled }
      }));
      toast.success(`Hint ${enabled ? 'enabled' : 'disabled'} for ${objectiveId}`);
    } catch (err) {
      if (!current()) return;
      console.error('Failed to toggle hint', err);
      toast.error('Failed to update hint visibility');
    }
  };

  const toggleObjective = async (workshopKey, objectiveId, currentEnabled) => {
    const identity = exerciseIdentityRef.current;
    const token = localStorage.getItem('token');
    const current = () => identity === exerciseIdentityRef.current
      && token === localStorage.getItem('token') && exerciseLoadRef.current.mounted
      && exerciseLoadRef.current.key === workshopKey && activeSectionRef.current === 'exercises';
    try {
      const apiKey = toWorkshopKey(workshopKey);
      const { data } = await axios.post(`/api/admin/workshops/${apiKey}/objectives/${objectiveId}/toggle`,
        { enabled: !currentEnabled },
        { headers: { Authorization: `Bearer ${token}` } }
      );
      if (!current()) return;
      const enabled = data.exercise?.objectives?.[objectiveId]?.raw?.objectiveEnabled;
      if (typeof enabled !== 'boolean') throw new Error('Canonical objective gate unavailable');
      setWorkshopObjectives(prev => ({
        ...prev,
        [workshopKey]: (prev[workshopKey] || []).map(o =>
          o.objective_id === objectiveId ? { ...o, is_enabled: enabled } : o
        )
      }));
      toast.success(`Objective ${enabled ? 'enabled' : 'disabled'}`);
    } catch (err) {
      if (!current()) return;
      console.error('Failed to toggle objective', err);
      toast.error('Failed to update objective visibility');
    }
  };

  const toggleAllObjectives = async (workshopKey, enabled) => {
    if (!challengePermissionRef.current || objectiveBulkRef.current) return;
    const identity = exerciseIdentityRef.current, token = localStorage.getItem('token');
    const current = () => identity === exerciseIdentityRef.current && token === localStorage.getItem('token')
      && challengePermissionRef.current && exerciseLoadRef.current.mounted
      && exerciseLoadRef.current.key === workshopKey && activeSectionRef.current === 'exercises';
    if (!current()) return;
    objectiveBulkRef.current = true; setObjectiveBulkPending(true);
    try {
      const { data } = await axios.post(`/api/admin/workshops/${toWorkshopKey(workshopKey)}/objectives/bulk-toggle`,
        { enabled }, { headers: { Authorization: `Bearer ${token}` }, timeout: 10000 });
      if (!current()) return;
      const rows = workshopObjectives[workshopKey] || [];
      if (data.success !== true || !rows.length || rows.some(row =>
        typeof data.exercise?.objectives?.[row.objective_id]?.raw?.objectiveEnabled !== 'boolean')) {
        throw new Error('Canonical objective mutation readback unavailable');
      }
      setWorkshopObjectives(previous => ({ ...previous, [workshopKey]: (previous[workshopKey] || []).map(row => ({
        ...row, is_enabled: data.exercise.objectives[row.objective_id].raw.objectiveEnabled,
      })) }));
      await refreshAfterMutation();
      if (current()) toast.success(enabled ? 'Available objectives enabled; unavailable objectives remain disabled.' : 'All objectives disabled.');
    } catch (error) {
      if (current()) toast.error(error.response?.data?.error || 'Unable to confirm objective availability. Reload before trying again.');
    } finally {
      objectiveBulkRef.current = false;
      if (identity === exerciseIdentityRef.current && exerciseLoadRef.current.mounted) setObjectiveBulkPending(false);
    }
  };

  const toggleCanonicalSolution = async (workshopKey, objectiveId, currentEnabled) => {
    const identity = exerciseIdentityRef.current, token = localStorage.getItem('token');
    const current = () => identity === exerciseIdentityRef.current
      && token === localStorage.getItem('token') && exerciseLoadRef.current.mounted
      && exerciseLoadRef.current.key === workshopKey && activeSectionRef.current === 'exercises';
    try {
      const { data } = await axios.patch(`/api/admin/exercises/${toWorkshopKey(workshopKey)}/objectives/${objectiveId}/solution`,
        { enabled: !currentEnabled }, { headers: { Authorization: `Bearer ${token}` } });
      if (!current()) return;
      const enabled = data.exercise?.objectives?.[objectiveId]?.raw?.solutionEnabled;
      if (typeof enabled !== 'boolean') throw new Error('Canonical solution gate unavailable');
      setWorkshopObjectives(previous => ({ ...previous, [workshopKey]: (previous[workshopKey] || []).map(row =>
        row.objective_id === objectiveId ? { ...row, solutions_enabled: enabled } : row) }));
      await refreshAfterMutation();
      if (current()) toast.success(`Solution ${enabled ? 'enabled' : 'disabled'} for ${objectiveId}`);
    } catch (error) {
      if (current()) toast.error(error.response?.data?.error || 'Failed to update solution visibility');
    }
  };

  const refreshResetCounts = async (token, actorId, isCurrent = () => true) => {
    const requestId = ++dashboardRequestRef.current;
    const generation = ++configReconcileGenerationRef.current;
    const current = () => isCurrent() && resetActorRef.current === actorId
      && resetPermissionRef.current && localStorage.getItem('token') === token;
    if (!current()) throw new Error('Administrator session changed');
    const config = { headers: { Authorization: `Bearer ${token}` } };
    const [challengeResponse, studentResponse] = await Promise.all([
      axios.get('/api/admin/challenges', config), axios.get('/api/admin/students', config),
    ]);
    if (!current() || requestId !== dashboardRequestRef.current || generation !== configReconcileGenerationRef.current) throw new Error('Reset counts changed while refreshing; retry the original operation.');
    if (challengeResponse.data?.success !== true || !Array.isArray(challengeResponse.data.challenges)
      || studentResponse.data?.success !== true || !Array.isArray(studentResponse.data.students)) throw new Error('Reset count refresh failed; retry the original operation.');
    const rows = challengeResponse.data.challenges, students = studentResponse.data.students;
    setChallenges(rows.filter(challenge => challenge.key !== 'ctf_prompt_injection_challenge'));
    setStudents(students);
    setStats({totalStudents: students.length, activeUsers: students.filter(student => student.enabled || student.is_active).length,
      completedChallenges: rows.reduce((sum, challenge) => sum + (Number(challenge.completions) || 0), 0),
      totalChallenges: rows.length, visibleChallenges: rows.filter(challenge => challenge.enabled).length});
  };

  // Opens the in-app confirmation modal (replaces the native window.confirm alert)
  const resetAllStudentsForWorkshop = (workshopKey, workshopName) => {
    if (!resetPermissionRef.current || bulkResetPendingRef.current != null) return;
    const authority = captureAdminAuthority();
    if (!authority) return;
    const staged = { workshopKey, workshopName, authority };
    stagedBulkResetRef.current = staged;
    setResetConfirm(staged);
  };

  const closeBulkResetConfirm = staged => {
    if (stagedBulkResetRef.current !== staged) return;
    stagedBulkResetRef.current = null;
    bulkResetEpochRef.current += 1;
    setResetConfirm(null);
  };

  // Runs the actual bulk reset after the admin confirms in the in-app modal
  const confirmResetAllStudents = async staged => {
    if (!staged || stagedBulkResetRef.current !== staged || bulkResetPendingRef.current != null) return;
    if (!resetPermissionRef.current || !isCurrentAdminAuthority(staged.authority)) {
      closeBulkResetConfirm(staged);
      return;
    }
    const { workshopKey, workshopName, authority } = staged;
    stagedBulkResetRef.current = null;
    setResetConfirm(null);
    const actionEpoch = ++bulkResetEpochRef.current;
    bulkResetPendingRef.current = actionEpoch;
    const current = () => actionEpoch === bulkResetEpochRef.current
      && isCurrentAdminAuthority(authority) && resetPermissionRef.current;
    setResettingWorkshop(prev => ({ ...prev, [workshopKey]: true }));
    try {
      const apiKey = toWorkshopKey(workshopKey);
      await runAdminBulkReset({ api: axios, actorId: authority.actorId, token: authority.token, workshopKey: apiKey,
        isCurrent: current,
        onCommit: () => refreshResetCounts(authority.token, authority.actorId, current) });
      if (current()) toast.success(`Student progress reset completed for "${workshopName}"`);
    } catch (err) {
      if (current()) {
        console.error('Bulk reset failed', err);
        toast.error(err.response?.data?.error || err.message || 'Failed to reset all student progress');
      }
    } finally {
      if (bulkResetPendingRef.current === actionEpoch) {
        bulkResetPendingRef.current = null;
        if (studentDeletionMountedRef.current) setResettingWorkshop(prev => ({ ...prev, [workshopKey]: false }));
      }
    }
  };

  const runMasterMutation = async (challengeKey, dimension, enabled, mutate) => {
    const key = toWorkshopKey(challengeKey);
    if (masterMutationsRef.current.has(key) || staleMastersRef.current.has(key)) return;
    const controller = new AbortController(), epoch = masterEpochRef.current;
    const identity = exerciseIdentityRef.current, token = localStorage.getItem('token');
    const current = () => !controller.signal.aborted && epoch === masterEpochRef.current
      && identity === exerciseIdentityRef.current && token === localStorage.getItem('token')
      && exerciseLoadRef.current.mounted && activeSectionRef.current === 'exercises';
    if (!current()) return;
    const field = dimension === 'hints' ? 'showHints'
      : dimension === 'solutions' ? 'showSolutions' : 'isVisible';
    const barrier = retireSnapshotReads();
    // Preserve uncertainty even if navigation retires the caller before its catch runs.
    staleMastersRef.current.set(key, { barrier, field, enabled });
    setStaleMasters(previous => ({ ...previous, [key]: true }));
    masterMutationsRef.current.set(key, controller);
    setPendingMasters(previous => ({ ...previous, [key]: true }));
    let onAbort;
    const cancelled = new Promise((_, reject) => {
      onAbort = () => reject(new Error('Exercise mutation deadline or cancellation'));
      controller.signal.addEventListener('abort', onAbort, { once: true });
    });
    const deadline = setTimeout(() => controller.abort(), 20000);
    const check = () => { if (!current()) throw new Error('Exercise mutation context retired'); };
    const request = async (method, url, body, config = {}) => {
      check();
      const response = await axios[method](url, body, { ...config,
        headers: { ...config.headers, Authorization: `Bearer ${token}` }, signal: controller.signal, timeout: 10000 });
      check(); return response;
    };
    const post = (...args) => request('post', ...args);
    post.patch = (...args) => request('patch', ...args);
    try {
      await Promise.race([(async () => {
      await mutate(post);
      check();
      const snapshot = await refreshAfterMutation({ signal: controller.signal });
      check();
      if (snapshot?.exercises?.[key]?.[field] !== enabled) {
        throw new Error('Canonical exercise mutation readback unavailable');
      }
      })(), cancelled]);
      check();
      staleMastersRef.current.delete(key);
      setStaleMasters(previous => { const next = { ...previous }; delete next[key]; return next; });
      toast.success(dimension === 'active'
        ? `Challenge ${enabled ? 'enabled' : 'disabled'} successfully! Students will ${enabled ? 'now see' : 'no longer see'} this challenge.`
        : `Challenge ${dimension} ${enabled ? 'enabled' : 'disabled'} successfully!`);
    } catch (error) {
      if (epoch === masterEpochRef.current && identity === exerciseIdentityRef.current
          && token === localStorage.getItem('token') && exerciseLoadRef.current.mounted) {
        staleMastersRef.current.set(key, { barrier: retireSnapshotReads(), field, enabled });
        setStaleMasters(previous => ({ ...previous, [key]: true }));
        toast.error('Unable to confirm current exercise controls. Reload before trying again.');
      }
    } finally {
      clearTimeout(deadline);
      controller.signal.removeEventListener('abort', onAbort);
      if (masterMutationsRef.current.get(key) === controller) {
        masterMutationsRef.current.delete(key);
        setPendingMasters(previous => { const next = { ...previous }; delete next[key]; return next; });
      }
    }
  };

  const handleToggleChallengeSolution = (challengeKey, showSolutions) => runMasterMutation(challengeKey, 'solutions', showSolutions, async post => {
      const token = localStorage.getItem('token');
      if (PROMPT_INJECTION_EXERCISES.has(challengeKey)) {
        const result = await mutatePromptInjectionMasterSolution(
          { patch: post.patch },
          challengeKey,
          showSolutions,
          { headers: { Authorization: `Bearer ${token}` } }
        );
        const reconcile = (state) => reconcilePromptInjectionExercise({
          challengeKey,
          exercise: result.exercise,
          challenges: state.challenges || [],
          solutionRows: state.solutionRows || [],
          objectiveRows: state.objectiveRows || [],
          hintMap: state.hintMap || {},
        });
        setChallenges(prev => reconcile({ challenges: prev }).challenges);
        if (challengeKey === 'direct_prompt_injection') {
          setPiSolutionChallenges(prev => reconcile({ solutionRows: prev }).solutionRows);
        } else {
          setIpiSolutions(prev => reconcile({ solutionRows: prev }).solutionRows);
        }
        setWorkshopObjectives(prev => {
          if (!prev[challengeKey]) return prev;
          return {
            ...prev,
            [challengeKey]: reconcile({ objectiveRows: prev[challengeKey] }).objectiveRows,
          };
        });
        setWorkshopHints(prev => {
          if (!prev[challengeKey]) return prev;
          return {
            ...prev,
            [challengeKey]: reconcile({ hintMap: prev[challengeKey] }).hintMap,
          };
        });
        return;
      }

      const { data: result } = await post('/api/admin/challenges/solutions/toggle', {
        challengeKey,
        showSolutions
      });

      setChallenges(prev => prev.map(challenge =>
        challenge.key === challengeKey
          ? { ...challenge, showSolutions }
          : challenge
      ));

      // The mutation response is the committed PostgreSQL projection. Keep an
      // already-open objectives panel in sync without issuing a second write.
      const objectiveState = result.exercise?.objectives || {};
      const reconcileRows = rows => rows.map(row => {
        if ((row.workshopKey || row.challengeKey)
            && ![challengeKey, toWorkshopKey(challengeKey)].includes(row.workshopKey || row.challengeKey)) return row;
        const id = row.objective_id || row.objectiveId || row.challengeId;
        const gate = objectiveState[id]?.raw?.solutionEnabled;
        if (gate === undefined) return row;
        if (Object.prototype.hasOwnProperty.call(row, 'solutionsEnabled')) return { ...row, solutionsEnabled: gate };
        if (Object.prototype.hasOwnProperty.call(row, 'isPublic')) return { ...row, isPublic: gate, is_public: gate };
        return { ...row, solutions_enabled: Number(gate) };
      });
      const rowSetters = {
        reflected_xss_llm: setXssObjectives, csrf_prompt_injection: setCsrfObjectives,
        sensitive_info_disclosure: setFinflowSolutions, supply_chain_rce: setScSolutions,
        excessive_agency: setEaSolutions, mcp_server_rce: setMcpSolutions,
        sql_injection_workshop: setSqliObjectives, nosql_injection_workshop: setNosqliObjectives,
      };
      const setRows = rowSetters[challengeKey] || setSolutions;
      setRows(reconcileRows);
  });

  const handleToggleChallengeHints = (challengeKey, showHints) => runMasterMutation(challengeKey, 'hints', showHints, async post => {
      const { data: result } = await post('/api/admin/challenges/hints/toggle', {
        challengeKey,
        showHints
      });
      
      setChallenges(prev => prev.map(challenge => 
        challenge.key === challengeKey 
          ? { ...challenge, showHints }
          : challenge
      ));

      setWorkshopHints(prev => {
        const existing = prev[challengeKey];
        if (!existing) return prev;
        const objectiveState = result.exercise?.objectives || {};
        const updated = Object.fromEntries(Object.entries(existing).map(([id, gate]) =>
          [id, objectiveState[id]?.raw?.hintEnabled ?? gate]));
        return { ...prev, [challengeKey]: updated };
      });
  });

  const handleLogout = async () => {
    try {
      await logout();
      navigate('/workshop-login');
    } catch (error) {
      navigate('/workshop-login');
    }
  };

  const handleViewStudent = async (studentId) => {
    try {
      setLoadingStudent(true);
      const token = localStorage.getItem('token');
      const response = await axios.get(`/api/admin/students/${studentId}/progress`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      setSelectedStudent(response.data);
      setStudentModalOpen(true);
    } catch (error) {
      console.error('Error loading student details:', error);
      toast.error('Failed to load student details');
    } finally {
      setLoadingStudent(false);
    }
  };

  const closeStudentModal = () => {
    setStudentModalOpen(false);
    setSelectedStudent(null);
  };

  const handleSecuritySettings = async () => {
    try {
      const response = await axios.get('/api/admin/security/settings');
      setSecuritySettings(response.data.settings || {});
      setSecuritySettingsModalOpen(true);
    } catch (error) {
      console.error('Error loading security settings:', error);
      toast.error('Failed to load security settings');
    }
  };

  const loadAdminAccounts = async (authority = captureAdminAuthority()) => {
    const generation = ++adminRosterGenerationRef.current;
    const current = () => studentDeletionMountedRef.current && generation === adminRosterGenerationRef.current
      && isCurrentAdminAuthority(authority) && adminRosterPermissionRef.current;
    if (!authority || !adminRosterPermissionRef.current) {
      setAdminAccounts([]);
      setAdminAccountsLoading(false);
      return;
    }
    setAdminAccountsLoading(true);
    setAdminAccountsError('');
    setAdminAccounts([]);
    try {
      const response = await axios.get('/api/admin/users?role=administrators&includeInactive=true&limit=200', {
        headers: { Authorization: `Bearer ${authority.token}` }
      });
      if (current() && Array.isArray(response.data?.users)) setAdminAccounts(response.data.users);
    } catch (error) {
      if (current()) setAdminAccountsError(error.response?.data?.error || 'Failed to load administrators. Try again.');
    } finally {
      if (current()) setAdminAccountsLoading(false);
    }
  };

  useEffect(() => {
    adminRosterGenerationRef.current += 1;
    setAdminAccounts([]);
    if (userManagementModalOpen && userManagementTab === 'administrators' && hasUserManagementPermission)
      void loadAdminAccounts();
    else setAdminAccountsLoading(false);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [userManagementModalOpen, userManagementTab, exerciseIdentity, resetAuthRevision]);

  const handleUserManagement = () => {
    if (!hasUserManagementPermission) return;
    setUserManagementTab('administrators');
    setUserManagementModalOpen(true);
  };

  const openManagementStudents = async () => {
    if (!canManageProgress) return;
    if (pendingDeactivationRef.current || pendingAdministratorEditRef.current || pendingAdministratorCreateRef.current) return;
    if (stagedDeactivationRef.current) {
      stagedDeactivationRef.current = null;
      setDeactivatingAdministrator(null);
      setDeactivationOutcome(null);
    }
    stagedAdministratorEditRef.current = null;
    setAdministratorEditStage(null);
    setEditingAdministrator(null);
    setAdministratorEditOutcome(null);
    closeAdministratorCreate(stagedAdministratorCreateRef.current);
    setUserManagementTab('students');
    setManagementStudentsLoading(true);
    setManagementStudentsError('');
    try {
      const token = localStorage.getItem('token');
      const response = await axios.get('/api/admin/students', {
        headers: { Authorization: `Bearer ${token}` }
      });
      setStudents(response.data.students || []);
    } catch (error) {
      setManagementStudentsError(error.response?.data?.error || 'Failed to load students. Try again.');
    } finally {
      setManagementStudentsLoading(false);
    }
  };

  const handleManagementTabKeyDown = (event) => {
    const tabs = canManageProgress ? ['administrators', 'students'] : ['administrators'];
    const index = tabs.indexOf(userManagementTab);
    let next;
    if (event.key === 'ArrowRight') next = tabs[(index + 1) % tabs.length];
    else if (event.key === 'ArrowLeft') next = tabs[(index + tabs.length - 1) % tabs.length];
    else if (event.key === 'Home') next = tabs[0];
    else if (event.key === 'End') next = tabs[tabs.length - 1];
    else return;
    event.preventDefault();
    if (next === 'students') openManagementStudents();
    else setUserManagementTab('administrators');
    document.getElementById(`user-management-${next}-tab`)?.focus();
  };

  const closeAdministratorCreate = stage => {
    if (stagedAdministratorCreateRef.current !== stage || pendingAdministratorCreateRef.current === stage) return;
    stagedAdministratorCreateRef.current = null;
    setAdministratorCreateStage(null);
    setAdministratorCreateOutcome(null);
    setCreateAdministratorOpen(false);
    setNewAdministrator(emptyAdministratorDraft());
  };
  const stageAdministratorCreate = () => {
    if (stagedAdministratorCreateRef.current) {
      closeAdministratorCreate(stagedAdministratorCreateRef.current);
      return;
    }
    if (!deactivationPermissionRef.current || pendingAdministratorCreateRef.current
      || pendingAdministratorEditRef.current || pendingDeactivationRef.current) return;
    const authority = captureAdminAuthority();
    if (!authority) return;
    closeAdministratorEdit(stagedAdministratorEditRef.current);
    closeAdministratorDeactivation(stagedDeactivationRef.current);
    const stage = { authority, consumed: false };
    stagedAdministratorCreateRef.current = stage;
    setAdministratorCreateStage(stage);
    setAdministratorCreateOutcome(null);
    setNewAdministrator(emptyAdministratorDraft());
    setCreateAdministratorOpen(true);
  };
  const updateAdministratorCreate = (stage, change) => {
    const permitted = () => studentDeletionMountedRef.current && stagedAdministratorCreateRef.current === stage
      && !stage?.consumed && !pendingAdministratorCreateRef.current && !pendingAdministratorEditRef.current
      && !pendingDeactivationRef.current && deactivationPermissionRef.current
      && isCurrentAdminAuthority(stage.authority) && userManagementModalOpenRef.current
      && userManagementTabRef.current === 'administrators';
    if (!permitted()) return;
    setNewAdministrator(current => permitted() ? { ...current, ...change(current) } : current);
  };
  const handleCreateAdministrator = async (event, stage) => {
    event.preventDefault();
    if (!studentDeletionMountedRef.current || stagedAdministratorCreateRef.current !== stage || stage.consumed || pendingAdministratorCreateRef.current
      || pendingAdministratorEditRef.current || pendingDeactivationRef.current
      || !deactivationPermissionRef.current || !isCurrentAdminAuthority(stage.authority)
      || !userManagementModalOpenRef.current || userManagementTabRef.current !== 'administrators') return;
    const draft = newAdministratorRef.current;
    if (draft.password !== draft.confirmPassword) {
      toast.error('Passwords do not match');
      return;
    }
    if (draft.password.length < 8 || !draft.permissions.length) {
      toast.error('Enter a password of at least 8 characters and select a permission');
      return;
    }
    const submitted = { username: draft.username, email: draft.email, fullName: draft.fullName,
      password: draft.password, adminLevel: Number(draft.adminLevel), permissions: [...draft.permissions] };
    stage.consumed = true;
    pendingAdministratorCreateRef.current = stage;
    setCreatingAdministrator(true);
    setAdministratorCreateOutcome({ kind: 'pending' });
    const current = () => studentDeletionMountedRef.current && stagedAdministratorCreateRef.current === stage
      && isCurrentAdminAuthority(stage.authority) && deactivationPermissionRef.current
      && userManagementModalOpenRef.current && userManagementTabRef.current === 'administrators';
    try {
      const response = await axios.post('/api/admin/administrators', submitted,
        { headers: { Authorization: `Bearer ${stage.authority.token}` } });
      if (!current()) return;
      const created = response.data?.user, grants = response.data?.permissions;
      const expectedFullName = submitted.fullName === '' ? null : submitted.fullName.trim();
      if (response.status !== 201 || response.data?.success !== true
        || !Number.isSafeInteger(created?.id) || created.id <= 0
        || created?.username !== submitted.username.trim() || created?.email !== submitted.email.trim()
        || created?.full_name !== expectedFullName || Number(created?.admin_level) !== submitted.adminLevel
        || created?.role !== 'admin' || (created?.is_active !== 1 && created?.is_active !== true)
        || !Array.isArray(grants) || grants.length !== submitted.permissions.length
        || !submitted.permissions.every(permission => grants.includes(permission)))
        throw new Error('The server did not acknowledge this administrator creation.');
      toast.success('Administrator created successfully');
      stagedAdministratorCreateRef.current = null;
      setAdministratorCreateStage(null);
      setAdministratorCreateOutcome(null);
      setCreateAdministratorOpen(false);
      setNewAdministrator(emptyAdministratorDraft());
      await loadAdminAccounts(stage.authority);
    } catch (error) {
      if (!current()) return;
      const status = error.response?.status;
      if (status >= 400 && status < 500 && status !== 408 && status !== 409) {
        setAdministratorCreateOutcome({ kind: 'rejected' });
        toast.error('Administrator creation was rejected.');
      } else {
        setAdministratorCreateOutcome({ kind: 'unknown' });
      }
    } finally {
      if (pendingAdministratorCreateRef.current === stage) {
        pendingAdministratorCreateRef.current = null;
        if (studentDeletionMountedRef.current) {
          if (stagedAdministratorCreateRef.current === stage)
            setNewAdministrator(currentDraft => ({ ...currentDraft, password: '', confirmPassword: '' }));
          setCreatingAdministrator(false);
        }
      }
    }
  };

  const beginAdministratorEdit = (account) => {
    if (!deactivationPermissionRef.current || pendingDeactivationRef.current || pendingAdministratorEditRef.current
      || pendingAdministratorCreateRef.current) return;
    const authority = captureAdminAuthority();
    if (!authority) return;
    stagedDeactivationRef.current = null;
    setDeactivatingAdministrator(null);
    setDeactivationOutcome(null);
    closeAdministratorCreate(stagedAdministratorCreateRef.current);
    const stage = { id: account.id, authority, consumed: false };
    stagedAdministratorEditRef.current = stage;
    setAdministratorEditStage(stage);
    setAdministratorEditOutcome(null);
    setEditingAdministrator({
      id: account.id, username: account.username || '', email: account.email || '',
      fullName: account.full_name || '', adminLevel: Number(account.admin_level),
      permissions: Array.isArray(account.permissions) ? [...account.permissions] : [],
      isActive: Boolean(account.is_active)
    });
  };

  const closeAdministratorEdit = stage => {
    if (stagedAdministratorEditRef.current !== stage || pendingAdministratorEditRef.current === stage) return;
    stagedAdministratorEditRef.current = null;
    setAdministratorEditStage(null);
    setEditingAdministrator(null);
    setAdministratorEditOutcome(null);
  };
  const updateAdministratorEdit = (stage, change) => {
    const permitted = () => studentDeletionMountedRef.current && stagedAdministratorEditRef.current === stage
      && !stage?.consumed && !pendingAdministratorEditRef.current && !pendingDeactivationRef.current
      && !pendingAdministratorCreateRef.current
      && deactivationPermissionRef.current && isCurrentAdminAuthority(stage.authority)
      && userManagementModalOpenRef.current && userManagementTabRef.current === 'administrators';
    if (!permitted()) return;
    setEditingAdministrator(current => {
      if (!permitted() || !current || String(current.id) !== String(stage.id)) return current;
      return { ...current, ...change(current) };
    });
  };
  const handleUpdateAdministrator = async (event, stage) => {
    event.preventDefault();
    if (stagedAdministratorEditRef.current !== stage || stage.consumed || pendingAdministratorEditRef.current
      || pendingDeactivationRef.current || pendingAdministratorCreateRef.current || !deactivationPermissionRef.current
      || !isCurrentAdminAuthority(stage.authority) || !userManagementModalOpenRef.current
      || userManagementTabRef.current !== 'administrators') return;
    const form = editingAdministratorRef.current;
    if (!form || String(form.id) !== String(stage.id)) return;
    if (!form.permissions.length) {
      toast.error('Select at least one permission');
      return;
    }
    const changes = { username: form.username, email: form.email, fullName: form.fullName,
      adminLevel: form.adminLevel, permissions: [...form.permissions], isActive: form.isActive };
    stage.consumed = true;
    pendingAdministratorEditRef.current = stage;
    setAdministratorMutationPending(true);
    setAdministratorEditOutcome({ kind: 'pending' });
    const current = () => studentDeletionMountedRef.current && stagedAdministratorEditRef.current === stage
      && isCurrentAdminAuthority(stage.authority) && deactivationPermissionRef.current
      && userManagementModalOpenRef.current && userManagementTabRef.current === 'administrators';
    const headers = { Authorization: `Bearer ${stage.authority.token}` };
    try {
      const response = await axios.put(`/api/admin/administrators/${stage.id}`, changes, { headers });
      if (!current()) return;
      const updated = response.data?.user;
      const expectedName = changes.fullName === '' ? null : changes.fullName.trim();
      const returnedPermissions = response.data?.permissions;
      if (response.data?.success !== true || String(updated?.id) !== String(stage.id)
        || updated?.username !== changes.username.trim() || updated?.email !== changes.email.trim()
        || updated?.full_name !== expectedName || Number(updated?.admin_level) !== Number(changes.adminLevel)
        || ![0, 1, false, true].includes(updated?.is_active)
        || (updated?.is_active === 1 || updated?.is_active === true) !== changes.isActive
        || !Array.isArray(returnedPermissions) || returnedPermissions.length !== changes.permissions.length
        || !changes.permissions.every(permission => returnedPermissions.includes(permission)))
        throw new Error('The server did not acknowledge this administrator update.');
      toast.success('Administrator updated');
      stagedAdministratorEditRef.current = null;
      setAdministratorEditStage(null);
      setEditingAdministrator(null);
      setAdministratorEditOutcome(null);
      if (String(stage.id) === String(stage.authority.actorId)) {
        setUserManagementModalOpen(false);
        try { Promise.resolve(logout()).catch(() => {}); } catch (logoutError) { /* local sign-out still navigates */ }
        navigate('/workshop-login');
      } else {
        await loadAdminAccounts(stage.authority);
      }
    } catch (error) {
      if (!current()) return;
      const code = error.response?.data?.code;
      if (code === 'LAST_ADMIN' || (error.response?.status >= 400 && error.response.status < 500
        && error.response.status !== 408)) {
        const message = code === 'LAST_ADMIN'
          ? 'At least one active level 2 administrator with user management permission must remain.'
          : error.response?.data?.error || 'Failed to update administrator';
        setAdministratorEditOutcome({ kind: 'rejected', message });
        toast.error(message);
        return;
      }
      try {
        const detail = await axios.get(`/api/admin/users/${stage.id}`, { headers });
        if (!current()) return;
        const observed = detail.data?.user;
        if (!detail.data?.success || !observed || String(observed.id) !== String(stage.id)
          || typeof observed.username !== 'string' || !observed.username.trim()
          || ![0, 1, false, true].includes(observed.is_active))
          throw new Error('Target account state unavailable.');
        setAdministratorEditOutcome({ kind: 'unknown', observed: {
          username: observed.username, active: observed.is_active === 1 || observed.is_active === true,
        } });
      } catch (readError) {
        if (current()) setAdministratorEditOutcome({ kind: 'unknown', observed: null });
      }
    } finally {
      if (pendingAdministratorEditRef.current === stage) {
        pendingAdministratorEditRef.current = null;
        if (studentDeletionMountedRef.current) setAdministratorMutationPending(false);
      }
    }
  };

  const closeAdministratorDeactivation = staged => {
    if (stagedDeactivationRef.current !== staged || pendingDeactivationRef.current === staged) return;
    stagedDeactivationRef.current = null;
    setDeactivatingAdministrator(null);
    setDeactivationOutcome(null);
  };
  const closeUserManagementModal = () => {
    if (pendingDeactivationRef.current || pendingAdministratorEditRef.current || pendingAdministratorCreateRef.current) return;
    closeAdministratorDeactivation(stagedDeactivationRef.current);
    closeAdministratorEdit(stagedAdministratorEditRef.current);
    closeAdministratorCreate(stagedAdministratorCreateRef.current);
    setUserManagementModalOpen(false);
  };
  const stageAdministratorDeactivation = account => {
    if (!deactivationPermissionRef.current || administratorMutationPending || pendingDeactivationRef.current
      || pendingAdministratorEditRef.current || pendingAdministratorCreateRef.current) return;
    const authority = captureAdminAuthority();
    if (!authority) return;
    const staged = { id: account.id, username: account.username, authority, consumed: false };
    stagedDeactivationRef.current = staged;
    closeAdministratorEdit(stagedAdministratorEditRef.current);
    closeAdministratorCreate(stagedAdministratorCreateRef.current);
    setEditingAdministrator(null);
    setDeactivationOutcome(null);
    setDeactivatingAdministrator(staged);
  };
  const handleDeactivateAdministrator = async staged => {
    if (stagedDeactivationRef.current !== staged || staged.consumed || pendingDeactivationRef.current
      || pendingAdministratorEditRef.current || pendingAdministratorCreateRef.current
      || !deactivationPermissionRef.current || !isCurrentAdminAuthority(staged.authority)
      || !userManagementModalOpenRef.current || userManagementTabRef.current !== 'administrators') return;
    staged.consumed = true;
    pendingDeactivationRef.current = staged;
    setAdministratorMutationPending(true);
    setDeactivationOutcome({ kind: 'pending' });
    const current = () => studentDeletionMountedRef.current && stagedDeactivationRef.current === staged
      && isCurrentAdminAuthority(staged.authority) && deactivationPermissionRef.current
      && userManagementModalOpenRef.current && userManagementTabRef.current === 'administrators';
    const headers = { Authorization: `Bearer ${staged.authority.token}` };
    try {
      const response = await axios.delete(`/api/admin/administrators/${staged.id}`, { headers });
      if (!current()) return;
      const acknowledged = response.data?.success === true && String(response.data?.user?.id) === String(staged.id)
        && (response.data.user.is_active === 0 || response.data.user.is_active === false);
      if (!acknowledged) throw new Error('The server did not acknowledge deactivation of this administrator.');
      toast.success('Administrator deactivated');
      stagedDeactivationRef.current = null;
      setDeactivatingAdministrator(null);
      setDeactivationOutcome(null);
      if (String(staged.id) === String(staged.authority.actorId)) {
        setUserManagementModalOpen(false);
        // Local logout begins synchronously; its later network completion must not navigate a replacement session.
        try { Promise.resolve(logout()).catch(() => {}); } catch (logoutError) { /* local sign-out still navigates */ }
        navigate('/workshop-login');
      } else {
        await loadAdminAccounts(staged.authority);
      }
    } catch (error) {
      if (!current()) return;
      const code = error.response?.data?.code;
      if (code === 'LAST_ADMIN' || (error.response?.status >= 400 && error.response.status < 500
        && error.response.status !== 408)) {
        const message = code === 'LAST_ADMIN'
          ? 'At least one active level 2 administrator with user management permission must remain.'
          : error.response?.data?.error || 'Failed to deactivate administrator';
        setDeactivationOutcome({ kind: 'rejected', message });
        toast.error(message);
        return;
      }
      try {
        const detail = await axios.get(`/api/admin/users/${staged.id}`, { headers });
        if (!current()) return;
        const observed = detail.data?.user;
        if (!detail.data?.success || !observed || String(observed.id) !== String(staged.id)
          || ![0, 1, false, true].includes(observed.is_active))
          throw new Error('Target account state unavailable.');
        setDeactivationOutcome({ kind: 'unknown', observed: observed.is_active === 0 || observed.is_active === false
          ? 'inactive' : 'active' });
      } catch (readError) {
        if (current()) setDeactivationOutcome({ kind: 'unknown', observed: null });
      }
    } finally {
      if (pendingDeactivationRef.current === staged) {
        pendingDeactivationRef.current = null;
        if (studentDeletionMountedRef.current) setAdministratorMutationPending(false);
      }
    }
  };

  const handleViewLogs = async () => {
    try {
      setLoadingLogs(true);
      const response = await axios.get('/api/admin/activity-logs?limit=100');
      setSystemLogs(response.data.logs || []);
      setSystemLogsModalOpen(true);
    } catch (error) {
      console.error('Error loading system logs:', error);
      toast.error('Failed to load system logs');
    } finally {
      setLoadingLogs(false);
    }
  };

  const handleChangePassword = () => {
    if (!studentDeletionMountedRef.current || !selfPasswordPermissionRef.current
      || activeSectionRef.current !== 'settings' || stagedSelfPasswordRef.current
      || pendingSelfPasswordRef.current) return;
    const authority = captureAdminAuthority();
    if (!authority) return;
    const stage = { authority, consumed: false };
    stagedSelfPasswordRef.current = stage;
    setSelfPasswordStage(stage);
    setSelfPasswordOutcome(null);
    setPasswords(emptySelfPasswordDraft());
    setChangePasswordModalOpen(true);
  };

  const closeSelfPassword = stage => {
    if (stagedSelfPasswordRef.current !== stage || pendingSelfPasswordRef.current === stage) return;
    stagedSelfPasswordRef.current = null;
    setSelfPasswordStage(null);
    setSelfPasswordOutcome(null);
    setChangePasswordModalOpen(false);
    setPasswords(emptySelfPasswordDraft());
  };
  const updateSelfPassword = (stage, change) => {
    const permitted = () => studentDeletionMountedRef.current && stagedSelfPasswordRef.current === stage
      && !stage?.consumed && !pendingSelfPasswordRef.current && selfPasswordPermissionRef.current
      && activeSectionRef.current === 'settings' && isCurrentAdminAuthority(stage.authority);
    if (!permitted()) return;
    setPasswords(current => permitted() ? { ...current, ...change } : current);
  };
  const handlePasswordSubmit = async (e, stage) => {
    e.preventDefault();
    if (!studentDeletionMountedRef.current || stagedSelfPasswordRef.current !== stage || stage.consumed
      || pendingSelfPasswordRef.current || !selfPasswordPermissionRef.current
      || activeSectionRef.current !== 'settings' || !isCurrentAdminAuthority(stage.authority)) return;
    const draft = passwordsRef.current;
    if (draft.newPassword !== draft.confirmPassword) {
      toast.error('New password and confirmation do not match');
      return;
    }

    if (draft.newPassword.length < 8) {
      toast.error('New password must be at least 8 characters long');
      return;
    }
    const submitted = { currentPassword: draft.currentPassword, newPassword: draft.newPassword,
      confirmPassword: draft.confirmPassword };
    stage.consumed = true;
    pendingSelfPasswordRef.current = stage;
    setSelfPasswordPending(true);
    setSelfPasswordOutcome({ kind: 'pending' });
    setPasswords(emptySelfPasswordDraft());
    const current = () => studentDeletionMountedRef.current && stagedSelfPasswordRef.current === stage
      && selfPasswordPermissionRef.current && activeSectionRef.current === 'settings'
      && isCurrentAdminAuthority(stage.authority);
    try {
      const response = await axios.post('/api/admin/account/change-password', submitted,
        { headers: { Authorization: `Bearer ${stage.authority.token}` } });
      if (!current()) return;
      if (response.status !== 200 || response.data?.success !== true
        || !Number.isSafeInteger(response.data?.sessionsRevoked) || response.data.sessionsRevoked < 0)
        throw new Error('Password change was not acknowledged.');
      stagedSelfPasswordRef.current = null;
      setSelfPasswordStage(null);
      setSelfPasswordOutcome(null);
      setChangePasswordModalOpen(false);
      toast.success('Password changed. Your sessions were revoked; sign in again.');
      // logout clears local authority synchronously. Navigate now so a newer login cannot be redirected later.
      try {
        const pendingLogout = logout();
        navigate('/workshop-login');
        void Promise.resolve(pendingLogout).catch(() => {});
      } catch { navigate('/workshop-login'); }
    } catch (error) {
      if (!current()) return;
      const status = error.response?.status;
      setSelfPasswordOutcome({ kind: status >= 400 && status < 500 && status !== 408 && status !== 409
        ? 'rejected' : 'unknown' });
    } finally {
      if (pendingSelfPasswordRef.current === stage) {
        pendingSelfPasswordRef.current = null;
        if (studentDeletionMountedRef.current) setSelfPasswordPending(false);
      }
    }
  };

  const handleDatabaseReset = async (resetType) => {
    if (resetType === 'challenges' && !resetPermissionRef.current) return;
    const resetMessages = {
      challenges: 'This resets canonical workshop data and progress for all learners. User accounts, CTF and SecureShop data are preserved.',
      logs: 'This clears activity logs older than 7 days. Workshop progress and audit receipts are preserved.',
      full: 'Full database reset is not available through this page.'
    };

    const confirmMessage = `${resetMessages[resetType]}\n\nNo automatic backup is created. This action cannot be undone.\n\nA pending retry resumes the original learner cohort.\n\nEnter your admin password to confirm:`;
    
    const password = prompt(confirmMessage);
    if (!password) return;

    try {
      const token = localStorage.getItem('token');
      const response = resetType === 'challenges'
        ? await runAdminBulkReset({ api: axios, actorId: user.id, token, confirmPassword: password,
          isCurrent: () => resetActorRef.current === user.id && resetPermissionRef.current && localStorage.getItem('token') === token,
          onCommit: () => refreshResetCounts(token, user.id) })
        : await axios.post('/api/admin/database/reset', { resetType, confirmPassword: password });

      toast.success(response.data.message || 'Administrative reset completed.');
      
      if (response.data.results?.errors?.length > 0) {
        toast.warning(`Some warnings occurred: ${response.data.results.errors.join(', ')}`);
      }
    } catch (error) {
      console.error('Database reset error:', error);
      toast.error(error.response?.data?.error || error.message || 'Failed to reset database');
    }
  };

  const saveSecuritySettings = async (newSettings) => {
    try {
      await axios.put('/api/admin/security/settings', { settings: newSettings });
      setSecuritySettings(newSettings);
      toast.success('Security settings updated successfully');
    } catch (error) {
      console.error('Error saving security settings:', error);
      toast.error('Failed to save security settings');
    }
  };

  const loadSolutions = async () => {
    const identity = exerciseIdentityRef.current, section = activeSectionRef.current, viewEpoch = exerciseLoadRef.current.sequence, credential = localStorage.getItem('token');
    try {
      setLoadingSolutions(true);
      const response = await axios.get('/api/admin/solutions');
      if (identity !== exerciseIdentityRef.current || section !== activeSectionRef.current || viewEpoch !== exerciseLoadRef.current.sequence || credential !== localStorage.getItem('token') || !exerciseLoadRef.current.mounted) return;
      setSolutions(response.data.solutions || []);
    } catch (error) {
      console.error('Error loading solutions:', error);
      toast.error('Failed to load exercise solutions');
    } finally {
      setLoadingSolutions(false);
    }
  };

  const loadPiSolutionChallenges = async () => {
    const identity = exerciseIdentityRef.current, section = activeSectionRef.current, viewEpoch = exerciseLoadRef.current.sequence, credential = localStorage.getItem('token');
    try {
      setPiSolutionLoading(true);
      const token = localStorage.getItem('token');
      const response = await axios.get('/api/admin/pi-workshop/solutions', {
        headers: { Authorization: `Bearer ${token}` }
      });
      if (identity !== exerciseIdentityRef.current || section !== activeSectionRef.current || viewEpoch !== exerciseLoadRef.current.sequence || credential !== localStorage.getItem('token') || !exerciseLoadRef.current.mounted) return;
      setPiSolutionChallenges(response.data.challenges || []);
    } catch (error) {
      console.error('Error loading PI solution visibility:', error);
    } finally {
      setPiSolutionLoading(false);
    }
  };

  const loadFinflowSolutions = async () => {
    const identity = exerciseIdentityRef.current, section = activeSectionRef.current, viewEpoch = exerciseLoadRef.current.sequence, credential = localStorage.getItem('token');
    try {
      setFinflowSolutionLoading(true);
      const token = localStorage.getItem('token');
      const response = await axios.get('/api/admin/finflow-workshop/solutions', {
        headers: { Authorization: `Bearer ${token}` }
      });
      if (identity !== exerciseIdentityRef.current || section !== activeSectionRef.current || viewEpoch !== exerciseLoadRef.current.sequence || credential !== localStorage.getItem('token') || !exerciseLoadRef.current.mounted) return;
      setFinflowSolutions(response.data.objectives || []);
    } catch (error) {
      console.error('Error loading FinFlow solution visibility:', error);
    } finally {
      setFinflowSolutionLoading(false);
    }
  };

  const toggleFinflowSolution = async (objectiveId, enabled) => {
    try {
      const token = localStorage.getItem('token');
      await axios.post('/api/admin/finflow-workshop/solutions/toggle',
        { objectiveId, enabled },
        { headers: { Authorization: `Bearer ${token}` } }
      );
      setFinflowSolutions(prev => prev.map(o => o.objectiveId === objectiveId ? { ...o, solutionsEnabled: enabled } : o));
      const FINFLOW_LABELS = {
        tool_enum: 'Tool Enumeration', llm_identify: 'LLM Identity Leak', tool_version: 'Version Disclosure',
        traversal_secrets: 'Read secrets.env', traversal_passwd: 'Read /etc/passwd', traversal_llm: 'Read llm_config.yml',
        ssrf_oob: 'Out-of-Band SSRF', ssrf_internal: 'Internal App SSRF', ssrf_ollama: 'Ollama Enumeration SSRF',
        error_leak: 'Verbose Error Leak', jailbreak: 'Jailbreak ARIA', admin_enum: 'Admin Tool Enumeration',
        admin_backup: 'Create DB Backup', admin_dl_backup: 'Download DB Backup', admin_read_logs: 'Read App Logs',
        admin_llm_logs: 'Read LLM Logs', admin_modify_logs: 'Tamper with Logs', admin_secrets: 'Exfiltrate Secrets',
        admin_dirlist: 'Directory + System Enum'
      };
      toast.success(`Solutions ${enabled ? 'enabled' : 'disabled'} for ${FINFLOW_LABELS[objectiveId] || objectiveId}`);
    } catch (error) {
      console.error('[Admin] Toggle FinFlow solution failed:', error);
      toast.error('Failed to update solution visibility');
    }
  };

  const loadScSolutions = async () => {
    const identity = exerciseIdentityRef.current, section = activeSectionRef.current, viewEpoch = exerciseLoadRef.current.sequence, credential = localStorage.getItem('token');
    try {
      setScSolutionLoading(true);
      const token = localStorage.getItem('token');
      const response = await axios.get('/api/admin/supply-chain-workshop/solutions', {
        headers: { Authorization: `Bearer ${token}` }
      });
      if (identity !== exerciseIdentityRef.current || section !== activeSectionRef.current || viewEpoch !== exerciseLoadRef.current.sequence || credential !== localStorage.getItem('token') || !exerciseLoadRef.current.mounted) return;
      setScSolutions(response.data.solutions || []);
    } catch (error) {
      console.error('Error loading Supply Chain solution visibility:', error);
    } finally {
      setScSolutionLoading(false);
    }
  };

  const toggleScSolution = async (objectiveId, enabled) => {
    try {
      const token = localStorage.getItem('token');
      await axios.post('/api/admin/supply-chain-workshop/solutions/toggle',
        { objectiveId, enabled },
        { headers: { Authorization: `Bearer ${token}` } }
      );
      setScSolutions(prev => prev.map(o => o.objective_id === objectiveId ? { ...o, solutions_enabled: enabled ? 1 : 0 } : o));
      const SC_LABELS = { tool_list: 'Enumerate Tools', pkg_discover: 'Identify Vulnerable Package', clean_request: 'Normal Check', rce_env: 'Read .env Secrets', rce_ssh: 'Steal SSH Key', rce_cmd: 'Execute System Commands' };
      toast.success(`Solutions ${enabled ? 'enabled' : 'disabled'} for ${SC_LABELS[objectiveId] || objectiveId}`);
    } catch (error) {
      console.error('[Admin] Toggle SC solution failed:', error);
      toast.error('Failed to update solution visibility');
    }
  };

  const handleViewScObjective = async (objectiveId) => {
    try {
      const token = localStorage.getItem('token');
      const r = await axios.get(`/api/admin/supply-chain-workshop/solutions/preview/${objectiveId}`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      setSelectedScObjective(r.data.solution);
      setScViewModalOpen(true);
    } catch (error) {
      console.error('Error fetching SC solution preview:', error);
      toast.error('Failed to load solution preview');
    }
  };

  const handleEditScObjective = async (objectiveId) => {
    try {
      const token = localStorage.getItem('token');
      const r = await axios.get(`/api/admin/supply-chain-workshop/solutions/preview/${objectiveId}`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      const sol = r.data.solution;
      setScEditFormData({
        objectiveId,
        title: sol.title || '',
        difficulty: sol.difficulty || 'Easy',
        approach: sol.approach || '',
        hints: Array.isArray(sol.hints) ? sol.hints : [],
        examples: Array.isArray(sol.examples) && sol.examples.length > 0 ? sol.examples : [{ prompt: '', explanation: '' }],
        tips: Array.isArray(sol.tips) ? sol.tips : [],
      });
      setScEditModalOpen(true);
    } catch (error) {
      console.error('Error fetching SC solution for edit:', error);
      toast.error('Failed to load solution for editing');
    }
  };

  const handleSaveScObjective = async () => {
    try {
      const token = localStorage.getItem('token');
      const { objectiveId, ...contentPatch } = scEditFormData;
      await axios.post(`/api/admin/supply-chain-workshop/solutions/${objectiveId}`,
        contentPatch,
        { headers: { Authorization: `Bearer ${token}` } }
      );
      toast.success('Solution updated successfully');
      setScEditModalOpen(false);
    } catch (error) {
      console.error('Error saving SC solution:', error);
      toast.error('Failed to save solution');
    }
  };

  // ── EA solutions ──────────────────────────────────────────────
  const loadEaSolutions = async () => {
    const identity = exerciseIdentityRef.current, section = activeSectionRef.current, viewEpoch = exerciseLoadRef.current.sequence, credential = localStorage.getItem('token');
    try {
      setEaSolutionLoading(true);
      const token = localStorage.getItem('token');
      const r = await axios.get('/api/admin/ea-workshop/solutions', { headers: { Authorization: `Bearer ${token}` } });
      if (identity !== exerciseIdentityRef.current || section !== activeSectionRef.current || viewEpoch !== exerciseLoadRef.current.sequence || credential !== localStorage.getItem('token') || !exerciseLoadRef.current.mounted) return;
      setEaSolutions(r.data.objectives || []);
    } catch (e) { console.error('Error loading EA solutions:', e); }
    finally { setEaSolutionLoading(false); }
  };
  const toggleEaSolution = async (objectiveId, enabled) => {
    try {
      const token = localStorage.getItem('token');
      await axios.post('/api/admin/ea-workshop/solutions/toggle', { objectiveId, enabled }, { headers: { Authorization: `Bearer ${token}` } });
      setEaSolutions(prev => prev.map(o => o.objective_id === objectiveId ? { ...o, solutions_enabled: enabled ? 1 : 0 } : o));
      toast.success(`Solutions ${enabled ? 'enabled' : 'disabled'} for ${objectiveId}`);
    } catch (e) { toast.error('Failed to update solution visibility'); }
  };

  // ── IPI solutions ──────────────────────────────────────────────
  const loadIpiSolutions = async () => {
    const identity = exerciseIdentityRef.current, section = activeSectionRef.current, viewEpoch = exerciseLoadRef.current.sequence, credential = localStorage.getItem('token');
    try {
      setIpiSolutionLoading(true);
      const token = localStorage.getItem('token');
      const r = await axios.get('/api/admin/ipi-workshop/solutions', { headers: { Authorization: `Bearer ${token}` } });
      if (identity !== exerciseIdentityRef.current || section !== activeSectionRef.current || viewEpoch !== exerciseLoadRef.current.sequence || credential !== localStorage.getItem('token') || !exerciseLoadRef.current.mounted) return;
      setIpiSolutions(r.data.objectives || []);
    } catch (e) { console.error('Error loading IPI solutions:', e); }
    finally { setIpiSolutionLoading(false); }
  };
  const toggleIpiSolution = async (objectiveId, enabled) => {
    try {
      const token = localStorage.getItem('token');
      await axios.post('/api/admin/ipi-workshop/solutions/toggle', { objectiveId, enabled }, { headers: { Authorization: `Bearer ${token}` } });
      setIpiSolutions(prev => prev.map(o => o.objective_id === objectiveId ? { ...o, solutions_enabled: enabled ? 1 : 0 } : o));
      const labels = { rag_upload: 'Upload Document', rag_query: 'Query the Agent', rag_clean_doc: 'Clean Document', rag_injected_doc: 'Injected Document', rag_query_injection: 'Query with Injection' };
      toast.success(`Solutions ${enabled ? 'enabled' : 'disabled'} for ${labels[objectiveId] || objectiveId}`);
    } catch (e) { toast.error('Failed to update solution visibility'); }
  };

  // ── MCP Workshop solutions ──────────────────────────────────────
  const loadMcpSolutions = async () => {
    const identity = exerciseIdentityRef.current, section = activeSectionRef.current, viewEpoch = exerciseLoadRef.current.sequence, credential = localStorage.getItem('token');
    try {
      setMcpSolutionLoading(true);
      const token = localStorage.getItem('token');
      const r = await axios.get('/api/admin/mcp-workshop/solutions', { headers: { Authorization: `Bearer ${token}` } });
      if (identity !== exerciseIdentityRef.current || section !== activeSectionRef.current || viewEpoch !== exerciseLoadRef.current.sequence || credential !== localStorage.getItem('token') || !exerciseLoadRef.current.mounted) return;
      setMcpSolutions(r.data.objectives || []);
    } catch (e) { console.error('Error loading MCP solutions:', e); }
    finally { setMcpSolutionLoading(false); }
  };
  const toggleMcpSolution = async (objectiveId, enabled) => {
    try {
      const token = localStorage.getItem('token');
      await axios.post('/api/admin/mcp-workshop/solutions/toggle', { objectiveId, enabled }, { headers: { Authorization: `Bearer ${token}` } });
      setMcpSolutions(prev => prev.map(o => o.objective_id === objectiveId ? { ...o, solutions_enabled: enabled ? 1 : 0 } : o));
      const labels = { mcp_recon: 'Recon — Discover Tools', mcp_cmd_injection: 'Command Injection', mcp_ssrf: 'SSRF — Internal Access', mcp_tool_poisoning: 'Tool Poisoning', mcp_indirect_injection: 'Indirect Injection', mcp_confused_deputy: 'Confused Deputy', mcp_broken_authz: 'Broken Authorization', mcp_secret_exposure: 'Secret Exposure', mcp_supply_chain: 'Supply Chain', mcp_audit_gap: 'Target-Private Audit Gap', mcp_shadow_server: 'Shadow Server' };
      toast.success(`Solutions ${enabled ? 'enabled' : 'disabled'} for ${labels[objectiveId] || objectiveId}`);
    } catch (e) { toast.error('Failed to update solution visibility'); }
  };

  const openMcpSolutionEditor = async (objectiveId) => {
    try {
      const response = await axios.get(`/api/admin/mcp-workshop/solutions/preview/${objectiveId}`, { headers: { Authorization: `Bearer ${localStorage.getItem('token')}` } });
      if (!isEditableSolution(response.data.solution)) throw new Error('Authored solution content is unavailable or unsupported');
      setMcpSolutionEditor({ objectiveId, solution: response.data.solution });
    } catch (error) { toast.error(error.message || 'Failed to load solution'); }
  };
  const saveMcpSolutionEditor = async (content) => {
    const objectiveId = mcpSolutionEditor.objectiveId;
    const headers = { Authorization: `Bearer ${localStorage.getItem('token')}` };
    await axios.put(`/api/admin/exercises/mcp_workshop/objectives/${objectiveId}/solution`, content, { headers });
    const response = await axios.get(`/api/admin/mcp-workshop/solutions/preview/${objectiveId}`, { headers });
    await loadMcpSolutions();
    setSolutionPreview(response.data.solution);
    setMcpSolutionEditor(null);
    toast.success('Solution updated successfully');
  };

  const openSolutionPreview = async (previewPath) => {
    try {
      const token = localStorage.getItem('token');
      const r = await axios.get(previewPath, { headers: { Authorization: `Bearer ${token}` } });
      setSolutionPreview(r.data.solution);
    } catch (e) {
      console.error('Error loading solution preview:', e);
      toast.error('Failed to load solution preview');
    }
  };

  const toggleAllFinflowSolutions = async (enabled) => {
    try {
      const token = localStorage.getItem('token');
      await axios.post('/api/admin/finflow-workshop/solutions/bulk', { enabled }, { headers: { Authorization: `Bearer ${token}` } });
      setFinflowSolutions(prev => prev.map(o => ({ ...o, solutionsEnabled: enabled })));
      toast.success(`All Sensitive Info solutions ${enabled ? 'enabled' : 'disabled'}`);
    } catch (e) { toast.error('Failed to bulk toggle Sensitive Info solutions'); }
  };

  const toggleAllScSolutions = async (enabled) => {
    try {
      const token = localStorage.getItem('token');
      await axios.post('/api/admin/supply-chain-workshop/solutions/bulk', { enabled }, { headers: { Authorization: `Bearer ${token}` } });
      setScSolutions(prev => prev.map(o => ({ ...o, solutions_enabled: enabled ? 1 : 0 })));
      toast.success(`All Supply Chain solutions ${enabled ? 'enabled' : 'disabled'}`);
    } catch (e) { toast.error('Failed to bulk toggle Supply Chain solutions'); }
  };

  const toggleAllEaSolutions = async (enabled) => {
    try {
      const token = localStorage.getItem('token');
      await axios.post('/api/admin/ea-workshop/solutions/bulk', { enabled }, { headers: { Authorization: `Bearer ${token}` } });
      setEaSolutions(prev => prev.map(o => ({ ...o, solutions_enabled: enabled ? 1 : 0 })));
      toast.success(`All Excessive Agency solutions ${enabled ? 'enabled' : 'disabled'}`);
    } catch (e) { toast.error('Failed to bulk toggle Excessive Agency solutions'); }
  };

  const toggleAllIpiSolutions = async (enabled) => {
    try {
      const token = localStorage.getItem('token');
      await axios.post('/api/admin/ipi-workshop/solutions/bulk', { enabled }, { headers: { Authorization: `Bearer ${token}` } });
      setIpiSolutions(prev => prev.map(o => ({ ...o, solutions_enabled: enabled ? 1 : 0 })));
      toast.success(`All Indirect PI solutions ${enabled ? 'enabled' : 'disabled'}`);
    } catch (e) { toast.error('Failed to bulk toggle Indirect PI solutions'); }
  };

  const toggleAllMcpSolutions = async (enabled) => {
    try {
      const token = localStorage.getItem('token');
      await axios.post('/api/admin/mcp-workshop/solutions/bulk', { enabled }, { headers: { Authorization: `Bearer ${token}` } });
      setMcpSolutions(prev => prev.map(o => ({ ...o, solutions_enabled: enabled ? 1 : 0 })));
      toast.success(`All MCP solutions ${enabled ? 'enabled' : 'disabled'}`);
    } catch (e) { toast.error('Failed to bulk toggle MCP solutions'); }
  };

  const toggleAllPiSolutions = async (enabled) => {
    try {
      const token = localStorage.getItem('token');
      await axios.post('/api/admin/pi-workshop/solutions/bulk', { enabled }, { headers: { Authorization: `Bearer ${token}` } });
      setPiSolutionChallenges(prev => prev.map(c => ({ ...c, solutionsEnabled: enabled })));
      toast.success(`All Direct PI solutions ${enabled ? 'enabled' : 'disabled'}`);
    } catch (e) { toast.error('Failed to bulk toggle Direct PI solutions'); }
  };

  const togglePiSolution = async (challengeId, enabled) => {
    try {
      const token = localStorage.getItem('token');
      await axios.post('/api/admin/pi-workshop/solutions/toggle', 
        { challengeId, enabled },
        { headers: { Authorization: `Bearer ${token}` } }
      );
      setPiSolutionChallenges(prev => prev.map(c => c.challengeId === challengeId ? { ...c, solutionsEnabled: enabled } : c));
      const names = { system_prompt: 'Direct System Prompt', jailbreak: 'Jailbreak', multi_language: 'Multi-Language', virtualization: 'Virtualization', role_playing: 'Role Playing', side_stepping: 'Side Stepping', obfuscation: 'Obfuscation' };
      toast.success(`Solutions ${enabled ? 'enabled' : 'disabled'} for ${names[challengeId] || challengeId}`);
    } catch (error) {
      console.error('[Admin] Toggle PI solution failed:', error);
      toast.error('Failed to update solution visibility');
    }
  };

  const toggleSolutionVisibility = async (solutionId, isPublic) => {
    try {
      const token = localStorage.getItem('token');
      // Backend PATCH now handles syncing per-workshop tables + broadcasting WS event
      await axios.patch(`/api/admin/solutions/${solutionId}/visibility`,
        { isPublic },
        { headers: { Authorization: `Bearer ${token}` } }
      );
      setSolutions(prev => prev.map(sol =>
        sol.id === solutionId ? { ...sol, isPublic, is_public: isPublic } : sol
      ));
      toast.success(`Solutions ${isPublic ? 'enabled' : 'disabled'} successfully`);
    } catch (error) {
      console.error('Error toggling solution visibility:', error);
      toast.error('Failed to update solution visibility');
    }
  };

  const handleViewAllPiSolutions = async () => {
    try {
      setPiSolutionLoading(true);
      const token = localStorage.getItem('token');
      // We need to fetch each of the 7 solutions. 
      // Instead of 7 requests, let's just use the status endpoint and then preview for each.
      // Actually, a single endpoint for all solutions would be better, but we have preview.
      // Let's just fetch them in parallel.
      const ids = ['system_prompt', 'jailbreak', 'multi_language', 'virtualization', 'role_playing', 'side_stepping', 'obfuscation'];
      const promises = ids.map(id => 
        axios.get(`/api/admin/pi-workshop/solutions/preview/${id}`, {
          headers: { Authorization: `Bearer ${token}` }
        })
      );
      
      const results = await Promise.all(promises);
      const allSols = results.map(r => r.data.solution);
      setPiAllSolutions(allSols);
      setPiAllSolutionsViewModalOpen(true);
    } catch (error) {
      console.error('Error fetching all PI solutions:', error);
      toast.error('Failed to load comprehensive solutions view');
    } finally {
      setPiSolutionLoading(false);
    }
  };

  const handleViewSolution = (solution) => {
    setSelectedSolution(solution);
    setSolutionModalOpen(true);
  };

  const handleViewPiObjective = async (challengeId) => {
    try {
      const token = localStorage.getItem('token');
      const response = await axios.get(`/api/admin/pi-workshop/solutions/preview/${challengeId}`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      setSelectedPiObjective(response.data.solution);
      setPiViewModalOpen(true);
    } catch (error) {
      console.error('Error fetching PI solution preview:', error);
      toast.error('Failed to load solution preview');
    }
  };

  const handleEditPiObjective = async (challengeId) => {
    try {
      const token = localStorage.getItem('token');
      const response = await axios.get(`/api/admin/pi-workshop/solutions/preview/${challengeId}`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      const sol = response.data.solution;
      setPiEditFormData({
        challengeId: challengeId,
        title: sol.title || '',
        difficulty: sol.difficulty || 'Medium',
        examples: sol.examples && sol.examples.length > 0 ? sol.examples : [{ prompt: '', explanation: '' }],
        approach: sol.approach || '',
        tips: sol.tips && sol.tips.length > 0 ? sol.tips : ['']
      });
      setPiEditModalOpen(true);
    } catch (error) {
      console.error('Error fetching PI solution for edit:', error);
      toast.error('Failed to load solution for editing');
    }
  };

  const handleSavePiObjective = async () => {
    try {
      const token = localStorage.getItem('token');
      const { challengeId, ...contentPatch } = piEditFormData;
      await axios.post(`/api/admin/pi-workshop/solutions/${challengeId}`,
        contentPatch,
        { headers: { Authorization: `Bearer ${token}` } }
      );
      toast.success('Solution updated successfully');
      setPiEditModalOpen(false);
    } catch (error) {
      console.error('Error saving PI solution:', error);
      toast.error('Failed to save solution');
    }
  };

  // ─── XSS Workshop solution management ───────────────────────────────────────

  const toggleXssAllSolutions = async (enabled) => {
    try {
      const token = localStorage.getItem('token');
      // Toggle all 12 objectives
      const allObjectiveIds = ['xss_r1','xss_r2','xss_r3','xss_s1','xss_s2','xss_s3','xss_g1','xss_g2','xss_g3','xss_e1','xss_e2','xss_e3'];
      await Promise.all(allObjectiveIds.map(id =>
        axios.post(`/api/admin/xss-workshop/objective-solutions/${id}/toggle`, { enabled }, { headers: { Authorization: `Bearer ${token}` } })
      ));
      setXssObjectives(prev => prev.map(o => ({ ...o, solutions_enabled: enabled ? 1 : 0 })));
      toast.success(`All XSS workshop solutions ${enabled ? 'enabled' : 'disabled'}`);
    } catch (error) {
      console.error('[Admin] Bulk XSS toggle failed:', error);
      toast.error('Failed to update XSS solution visibility');
    }
  };

  // XSS per-objective solution management
  const loadXssObjectives = async () => {
    const identity = exerciseIdentityRef.current, section = activeSectionRef.current, viewEpoch = exerciseLoadRef.current.sequence, credential = localStorage.getItem('token');
    try {
      const token = localStorage.getItem('token');
      const res = await axios.get('/api/admin/xss-workshop/objective-solutions', {
        headers: { Authorization: `Bearer ${token}` }
      });
      if (identity !== exerciseIdentityRef.current || section !== activeSectionRef.current || viewEpoch !== exerciseLoadRef.current.sequence || credential !== localStorage.getItem('token') || !exerciseLoadRef.current.mounted) return;
      setXssObjectives(res.data.objectives || []);
    } catch (err) {
      console.error('Error loading XSS objective solutions:', err);
    }
  };

  const handleEditXssObjective = async (objectiveId) => {
    try {
      const token = localStorage.getItem('token');
      const res = await axios.get(`/api/admin/xss-workshop/objective-solutions/preview/${objectiveId}`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      const sol = res.data.solution;
      setXssObjEditId(objectiveId);
      setXssObjEditFormData({
        title: sol.title || '',
        hint: sol.hint || '',
        example: sol.example || '',
        explanation: sol.explanation || '',
      });
    } catch (err) {
      toast.error('Failed to load objective solution');
    }
  };

  const handleSaveXssObjective = async () => {
    try {
      const token = localStorage.getItem('token');
      await axios.post(`/api/admin/xss-workshop/objective-solutions/${xssObjEditId}`,
        xssObjEditFormData,
        { headers: { Authorization: `Bearer ${token}` } }
      );
      toast.success('Objective solution updated');
      setXssObjEditId(null);
      loadXssObjectives();
    } catch (err) {
      toast.error('Failed to save objective solution');
    }
  };

  const toggleXssObjective = async (objectiveId, enabled) => {
    try {
      const token = localStorage.getItem('token');
      await axios.post(`/api/admin/xss-workshop/objective-solutions/${objectiveId}/toggle`,
        { enabled },
        { headers: { Authorization: `Bearer ${token}` } }
      );
      setXssObjectives(prev => prev.map(o => o.objective_id === objectiveId ? { ...o, solutions_enabled: enabled ? 1 : 0 } : o));
      toast.success(`Solution ${enabled ? 'enabled' : 'disabled'} for ${objectiveId}`);
    } catch (err) {
      toast.error('Failed to toggle objective solution visibility');
    }
  };

  // ─── CSRF Workshop solution management ──────────────────────────────────────

  const toggleCsrfAllSolutions = async (enabled) => {
    try {
      const token = localStorage.getItem('token');
      const allObjectiveIds = ['csrf_g1','csrf_g2','csrf_g3','csrf_p1','csrf_p2','csrf_p3','csrf_x1','csrf_x2','csrf_x3','csrf_i1','csrf_i2','csrf_i3'];
      // Flip all 12 per-objective rows (csrf_workshop_objective_solutions).
      await Promise.all(
        allObjectiveIds.map(id =>
          axios.post(`/api/admin/csrf-workshop/objective-solutions/${id}/toggle`,
            { enabled }, { headers: { Authorization: `Bearer ${token}` } }))
      );
      setCsrfObjectives(prev => prev.map(o => ({ ...o, solutions_enabled: enabled ? 1 : 0 })));
      toast.success(`All CSRF workshop solutions ${enabled ? 'enabled' : 'disabled'}`);
    } catch (error) {
      console.error('[Admin] Bulk CSRF toggle failed:', error);
      toast.error('Failed to update CSRF solution visibility');
    }
  };

  const loadCsrfObjectives = async () => {
    const identity = exerciseIdentityRef.current, section = activeSectionRef.current, viewEpoch = exerciseLoadRef.current.sequence, credential = localStorage.getItem('token');
    try {
      const token = localStorage.getItem('token');
      const res = await axios.get('/api/admin/csrf-workshop/objective-solutions', {
        headers: { Authorization: `Bearer ${token}` }
      });
      if (identity !== exerciseIdentityRef.current || section !== activeSectionRef.current || viewEpoch !== exerciseLoadRef.current.sequence || credential !== localStorage.getItem('token') || !exerciseLoadRef.current.mounted) return;
      setCsrfObjectives(res.data.objectives || []);
    } catch (err) {
      console.error('Error loading CSRF objective solutions:', err);
    }
  };

  const handleEditCsrfObjective = async (objectiveId) => {
    try {
      const token = localStorage.getItem('token');
      const res = await axios.get(`/api/admin/csrf-workshop/objective-solutions/preview/${objectiveId}`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      const sol = res.data.solution;
      setCsrfObjEditId(objectiveId);
      setCsrfObjEditFormData({
        title: sol.title || '',
        hint: sol.hint || '',
        example: sol.example || '',
        explanation: sol.explanation || '',
      });
    } catch (err) {
      toast.error('Failed to load objective solution');
    }
  };

  const handleSaveCsrfObjective = async () => {
    try {
      const token = localStorage.getItem('token');
      await axios.post(`/api/admin/csrf-workshop/objective-solutions/${csrfObjEditId}`,
        csrfObjEditFormData,
        { headers: { Authorization: `Bearer ${token}` } }
      );
      toast.success('Objective solution updated');
      setCsrfObjEditId(null);
      loadCsrfObjectives();
    } catch (err) {
      toast.error('Failed to save objective solution');
    }
  };

  const toggleCsrfObjective = async (objectiveId, enabled) => {
    try {
      const token = localStorage.getItem('token');
      await axios.post(`/api/admin/csrf-workshop/objective-solutions/${objectiveId}/toggle`,
        { enabled },
        { headers: { Authorization: `Bearer ${token}` } }
      );
      setCsrfObjectives(prev => prev.map(o => o.objective_id === objectiveId ? { ...o, solutions_enabled: enabled ? 1 : 0 } : o));
      toast.success(`Solution ${enabled ? 'enabled' : 'disabled'} for ${objectiveId}`);
    } catch (err) {
      toast.error('Failed to toggle objective solution visibility');
    }
  };

  const fetchSqliObjectives = async () => {
    const identity = exerciseIdentityRef.current, section = activeSectionRef.current, viewEpoch = exerciseLoadRef.current.sequence, credential = localStorage.getItem('token');
    setSqliLoading(true);
    try {
      const token = localStorage.getItem('token');
      const res = await axios.get('/api/admin/sql-injection-workshop/solutions',
        { headers: { Authorization: `Bearer ${token}` } }
      );
      if (identity !== exerciseIdentityRef.current || section !== activeSectionRef.current || viewEpoch !== exerciseLoadRef.current.sequence || credential !== localStorage.getItem('token') || !exerciseLoadRef.current.mounted) return;
      setSqliObjectives(res.data?.objectives || []);
    } catch (err) {
      toast.error('Failed to load SQL injection objectives');
    } finally {
      setSqliLoading(false);
    }
  };

  const toggleSqliObjective = async (objectiveId, enabled) => {
    try {
      const token = localStorage.getItem('token');
      await axios.post('/api/admin/sql-injection-workshop/solutions/toggle',
        { objectiveId, enabled },
        { headers: { Authorization: `Bearer ${token}` } }
      );
      setSqliObjectives(prev => prev.map(o => o.objective_id === objectiveId ? { ...o, solutions_enabled: enabled ? 1 : 0 } : o));
      toast.success(`Solution ${enabled ? 'enabled' : 'disabled'} for ${objectiveId}`);
    } catch (err) {
      toast.error('Failed to toggle SQL injection solution visibility');
    }
  };

  const toggleAllSqliObjectives = async (enabled) => {
    try {
      const token = localStorage.getItem('token');
      await axios.post('/api/admin/sql-injection-workshop/solutions/bulk',
        { enabled },
        { headers: { Authorization: `Bearer ${token}` } }
      );
      setSqliObjectives(prev => prev.map(o => ({ ...o, solutions_enabled: enabled ? 1 : 0 })));
      toast.success(`All SQL injection solutions ${enabled ? 'enabled' : 'disabled'}`);
    } catch (err) {
      toast.error('Failed to bulk toggle SQL injection solutions');
    }
  };

  const fetchNosqliObjectives = async () => {
    const identity = exerciseIdentityRef.current, section = activeSectionRef.current, viewEpoch = exerciseLoadRef.current.sequence, credential = localStorage.getItem('token');
    setNosqliLoading(true);
    try {
      const token = localStorage.getItem('token');
      const res = await axios.get('/api/admin/nosql-injection-workshop/solutions',
        { headers: { Authorization: `Bearer ${token}` } }
      );
      if (identity !== exerciseIdentityRef.current || section !== activeSectionRef.current || viewEpoch !== exerciseLoadRef.current.sequence || credential !== localStorage.getItem('token') || !exerciseLoadRef.current.mounted) return;
      setNosqliObjectives(res.data?.objectives || []);
    } catch (err) {
      toast.error('Failed to load NoSQL injection objectives');
    } finally {
      setNosqliLoading(false);
    }
  };

  const toggleNosqliObjective = async (objectiveId, enabled) => {
    try {
      const token = localStorage.getItem('token');
      await axios.post('/api/admin/nosql-injection-workshop/solutions/toggle',
        { objectiveId, enabled },
        { headers: { Authorization: `Bearer ${token}` } }
      );
      setNosqliObjectives(prev => prev.map(o => o.objective_id === objectiveId ? { ...o, solutions_enabled: enabled ? 1 : 0 } : o));
      toast.success(`Solution ${enabled ? 'enabled' : 'disabled'} for ${objectiveId}`);
    } catch (err) {
      toast.error('Failed to toggle NoSQL injection solution visibility');
    }
  };

  const toggleAllNosqliObjectives = async (enabled) => {
    try {
      const token = localStorage.getItem('token');
      await axios.post('/api/admin/nosql-injection-workshop/solutions/bulk',
        { enabled },
        { headers: { Authorization: `Bearer ${token}` } }
      );
      setNosqliObjectives(prev => prev.map(o => ({ ...o, solutions_enabled: enabled ? 1 : 0 })));
      toast.success(`All NoSQL injection solutions ${enabled ? 'enabled' : 'disabled'}`);
    } catch (err) {
      toast.error('Failed to bulk toggle NoSQL injection solutions');
    }
  };

  // Student Management Functions
  const captureStudentDeletionAuthority = captureAdminAuthority;
  const isCurrentStudentDeletionAuthority = isCurrentAdminAuthority;
  const closeDeleteStudentModal = () => {
    studentDeletionEpochRef.current += 1;
    stagedStudentDeletionRef.current = null;
    setDeleteStudentModalOpen(false);
    setStudentToDelete(null);
  };
  useEffect(() => {
    const staged = stagedStudentDeletionRef.current;
    if (staged && !isCurrentStudentDeletionAuthority(staged.authority)) closeDeleteStudentModal();
  }, [exerciseIdentity]);
  const handleEditStudent = (student) => {
    if (!studentDeletionMountedRef.current || !accountAccessPermissionRef.current || activeSectionRef.current !== 'students'
      || pendingStudentAccountMutationRef.current || pendingStudentPasswordRef.current
      || stagedStudentCreateRef.current || stagedStudentEditRef.current || stagedStudentPasswordRef.current) return;
    const authority = captureAdminAuthority();
    if (!authority) return;
    const target = { id: student.id, username: student.username, email: student.email };
    const stage = { target, authority, consumed: false };
    stagedStudentEditRef.current = stage;
    setStudentEditStage(stage);
    setStudentEditOutcome(null);
    setStudentToEdit(target);
    setEditFormData({
      username: student.username || '',
      email: student.email || '',
      full_name: student.full_name || '',
      role: student.role || 'student',
      is_active: student.is_active !== undefined ? student.is_active : true,
      department: student.department || '',
      phone: student.phone || ''
    });
    setEditStudentModalOpen(true);
  };

  const closeStudentEdit = stage => {
    if (stagedStudentEditRef.current !== stage || pendingStudentAccountMutationRef.current === stage) return;
    stagedStudentEditRef.current = null;
    setStudentEditStage(null);
    setStudentEditOutcome(null);
    setStudentToEdit(null);
    setEditStudentModalOpen(false);
  };
  const updateStudentEdit = (stage, change) => {
    const permitted = () => studentDeletionMountedRef.current && stagedStudentEditRef.current === stage
      && !stage?.consumed && !pendingStudentAccountMutationRef.current && !pendingStudentPasswordRef.current
      && accountAccessPermissionRef.current && activeSectionRef.current === 'students'
      && isCurrentAdminAuthority(stage.authority);
    if (!permitted()) return;
    setEditFormData(current => permitted() ? { ...current, ...change } : current);
  };

  const handleDeleteStudent = (student) => {
    if (!canDeleteStudents) {
      toast.error(deleteStudentPermissionTitle);
      return;
    }
    if (studentDeletionPendingRef.current) return;
    const authority = captureStudentDeletionAuthority();
    if (!authority) return;
    const target = { id: student.id, username: student.username,
      email: student.email, full_name: student.full_name };
    stagedStudentDeletionRef.current = { target, authority };
    setStudentToDelete(target);
    setDeleteStudentModalOpen(true);
  };

  const handleChangeStudentPassword = (student) => {
    if (!studentDeletionMountedRef.current || !accountAccessPermissionRef.current || activeSectionRef.current !== 'students'
      || pendingStudentPasswordRef.current || pendingStudentAccountMutationRef.current
      || stagedStudentCreateRef.current || stagedStudentEditRef.current || stagedStudentPasswordRef.current) return;
    const authority = captureAdminAuthority();
    if (!authority || !Number.isSafeInteger(Number(student?.id)) || Number(student.id) <= 0) return;
    const target = { id: student.id, username: student.username, email: student.email };
    const stage = { target, authority, consumed: false };
    stagedStudentPasswordRef.current = stage;
    setStudentPasswordStage(stage);
    setStudentPasswordOutcome(null);
    setPasswordChangeData({ newPassword: '', confirmPassword: '' });
    setStudentForPasswordChange(target);
    setChangeStudentPasswordModalOpen(true);
  };

  const closeStudentPassword = stage => {
    if (stagedStudentPasswordRef.current !== stage || pendingStudentPasswordRef.current === stage) return;
    stagedStudentPasswordRef.current = null;
    setStudentPasswordStage(null);
    setStudentPasswordOutcome(null);
    setStudentForPasswordChange(null);
    setChangeStudentPasswordModalOpen(false);
    setPasswordChangeData({ newPassword: '', confirmPassword: '' });
  };

  const updateStudentPassword = (stage, change) => {
    const permitted = () => studentDeletionMountedRef.current && stagedStudentPasswordRef.current === stage
      && !stage?.consumed && !pendingStudentPasswordRef.current && accountAccessPermissionRef.current
      && activeSectionRef.current === 'students' && isCurrentAdminAuthority(stage.authority);
    if (!permitted()) return;
    setPasswordChangeData(current => permitted() ? { ...current, ...change } : current);
  };

  const updateStudent = async stage => {
    if (!studentDeletionMountedRef.current || stagedStudentEditRef.current !== stage || stage.consumed
      || pendingStudentAccountMutationRef.current || pendingStudentPasswordRef.current
      || !accountAccessPermissionRef.current || activeSectionRef.current !== 'students'
      || !isCurrentAdminAuthority(stage.authority)) return;
    const updatedData = { ...editFormDataRef.current };
    stage.consumed = true;
    pendingStudentAccountMutationRef.current = stage;
    setStudentAccountMutationPending(true);
    setStudentEditOutcome({ kind: 'pending' });
    const current = () => studentDeletionMountedRef.current && stagedStudentEditRef.current === stage
      && accountAccessPermissionRef.current && activeSectionRef.current === 'students'
      && isCurrentAdminAuthority(stage.authority);
    try {
      const response = await axios.put(`/api/admin/students/${stage.target.id}`, updatedData, {
        headers: { 'Authorization': `Bearer ${stage.authority.token}` }
      });
      if (!current()) return;
      const acknowledged = response.data?.user;
      if (response.status !== 200 || response.data?.success !== true || response.data?.changes !== 1
        || acknowledged?.id !== stage.target.id || acknowledged?.role !== 'student'
        || acknowledged?.admin_level !== 0 || acknowledged?.username !== updatedData.username
        || acknowledged?.email !== updatedData.email || acknowledged?.full_name !== updatedData.full_name
        || acknowledged?.department !== updatedData.department || acknowledged?.phone !== updatedData.phone
        || acknowledged?.is_active !== (updatedData.is_active ? 1 : 0))
        throw new Error('Student update was not acknowledged.');
      stagedStudentEditRef.current = null;
      setStudentEditStage(null);
      setStudentEditOutcome(null);
      setEditStudentModalOpen(false);
      setStudentToEdit(null);
      toast.success('Student updated successfully');
      void loadDashboardData(true, () => studentDeletionMountedRef.current
        && isCurrentAdminAuthority(stage.authority) && accountAccessPermissionRef.current
        && activeSectionRef.current === 'students');
    } catch (error) {
      if (!current()) return;
      const status = error.response?.status;
      setStudentEditOutcome({ kind: status >= 400 && status < 500 && status !== 408 && status !== 409
        ? 'rejected' : 'unknown' });
    } finally {
      if (pendingStudentAccountMutationRef.current === stage) {
        pendingStudentAccountMutationRef.current = null;
        if (studentDeletionMountedRef.current) setStudentAccountMutationPending(false);
      }
    }
  };

  const deleteStudent = async (stagedFromDialog) => {
    const staged = stagedStudentDeletionRef.current;
    if (!canDeleteStudents) {
      toast.error(deleteStudentPermissionTitle);
      return;
    }
    if (!staged || staged !== stagedFromDialog || studentDeletionPendingRef.current) return;
    if (!isCurrentStudentDeletionAuthority(staged.authority)
        || staged.target.id !== studentToDelete?.id) {
      closeDeleteStudentModal();
      toast.error('Session changed. Review the student deletion again.');
      return;
    }
    studentDeletionPendingRef.current = true;
    stagedStudentDeletionRef.current = null;
    setStudentDeletionPending(true);
    const actionEpoch = ++studentDeletionEpochRef.current;
    const current = () => actionEpoch === studentDeletionEpochRef.current
      && isCurrentStudentDeletionAuthority(staged.authority);
    const retireIfStale = () => {
      if (!current()) {
        // No new deletion can be staged while this request is pending.
        if (studentDeletionMountedRef.current) closeDeleteStudentModal();
        return true;
      }
      return false;
    };
    try {
      await axios.delete(`/api/admin/students/${staged.target.id}`, {
        headers: { 'Authorization': `Bearer ${staged.authority.token}` }
      });
      if (retireIfStale()) return;
      await loadDashboardData(true, current); // Reload only under the original authority
      if (retireIfStale()) return;
      closeDeleteStudentModal();
      toast.success('Student deleted successfully');
    } catch (error) {
      if (retireIfStale()) return;
      console.error('Error deleting student:', error);
      closeDeleteStudentModal();
      toast.error(error.response?.data?.error
        || 'Deletion result could not be confirmed. Refresh students before deciding whether to act again.');
    } finally {
      studentDeletionPendingRef.current = false;
      if (studentDeletionMountedRef.current) setStudentDeletionPending(false);
    }
  };

  const changeStudentPassword = async stage => {
    if (!studentDeletionMountedRef.current || stagedStudentPasswordRef.current !== stage || stage.consumed
      || pendingStudentPasswordRef.current || pendingStudentAccountMutationRef.current || !accountAccessPermissionRef.current
      || activeSectionRef.current !== 'students' || !isCurrentAdminAuthority(stage.authority)) return;
    const draft = passwordChangeDataRef.current;
    if (draft.newPassword !== draft.confirmPassword) {
      toast.error('Passwords do not match');
      return;
    }
    if (draft.newPassword.length < 8) {
      toast.error('Password must be at least 8 characters long');
      return;
    }
    const passwordData = { newPassword: draft.newPassword, confirmPassword: draft.confirmPassword };
    stage.consumed = true;
    pendingStudentPasswordRef.current = stage;
    setStudentPasswordPending(true);
    setStudentPasswordOutcome({ kind: 'pending' });
    setPasswordChangeData({ newPassword: '', confirmPassword: '' });
    const current = () => studentDeletionMountedRef.current && stagedStudentPasswordRef.current === stage
      && accountAccessPermissionRef.current && activeSectionRef.current === 'students'
      && isCurrentAdminAuthority(stage.authority);
    try {
      const response = await axios.post(`/api/admin/students/${stage.target.id}/change-password`, passwordData, {
        headers: { 'Authorization': `Bearer ${stage.authority.token}` }
      });
      if (!current()) return;
      if (response.status !== 200 || response.data?.success !== true
        || !Number.isSafeInteger(response.data?.sessionsRevoked) || response.data.sessionsRevoked < 0)
        throw new Error('Student password rotation was not acknowledged.');
      stagedStudentPasswordRef.current = null;
      setStudentPasswordStage(null);
      setStudentPasswordOutcome(null);
      setStudentForPasswordChange(null);
      setChangeStudentPasswordModalOpen(false);
      toast.success('Student password changed; existing student sessions were revoked');
    } catch (error) {
      if (!current()) return;
      const status = error.response?.status;
      setStudentPasswordOutcome({ kind: status >= 400 && status < 500 && status !== 408 && status !== 409
        ? 'rejected' : 'unknown' });
    } finally {
      if (pendingStudentPasswordRef.current === stage) {
        pendingStudentPasswordRef.current = null;
        if (studentDeletionMountedRef.current) setStudentPasswordPending(false);
      }
    }
  };

  // Solution Management Functions
  const updateSolution = async (solutionId, solutionData) => {
    try {
      await axios.put(`/api/admin/solutions/${solutionId}`, solutionData);
      await loadSolutions(); // Reload solutions
      setSolutionEditModalOpen(false);
      setEditingSolution(null);
      toast.success('Solution updated successfully');
    } catch (error) {
      console.error('Error updating solution:', error);
      toast.error(error.response?.data?.error || 'Failed to update solution');
    }
  };

  const handleEditSolution = (solution) => {
    setEditingSolution(solution);
    setSolutionEditModalOpen(true);
  };

  const closeStudentCreate = stage => {
    if (stagedStudentCreateRef.current !== stage || pendingStudentAccountMutationRef.current === stage) return;
    stagedStudentCreateRef.current = null;
    setStudentCreateStage(null);
    setStudentCreateOutcome(null);
    setCreateStudentModalOpen(false);
    setNewStudent(emptyStudentDraft());
  };
  const openStudentCreate = () => {
    if (!studentDeletionMountedRef.current || !accountAccessPermissionRef.current || activeSectionRef.current !== 'students'
      || pendingStudentAccountMutationRef.current || pendingStudentPasswordRef.current
      || stagedStudentCreateRef.current || stagedStudentEditRef.current || stagedStudentPasswordRef.current) return;
    const authority = captureAdminAuthority();
    if (!authority) return;
    const stage = { authority, consumed: false };
    stagedStudentCreateRef.current = stage;
    setStudentCreateStage(stage);
    setStudentCreateOutcome(null);
    setNewStudent(emptyStudentDraft());
    setCreateStudentModalOpen(true);
  };
  const updateStudentCreate = (stage, change) => {
    const permitted = () => studentDeletionMountedRef.current && stagedStudentCreateRef.current === stage
      && !stage?.consumed && !pendingStudentAccountMutationRef.current && !pendingStudentPasswordRef.current
      && accountAccessPermissionRef.current && activeSectionRef.current === 'students'
      && isCurrentAdminAuthority(stage.authority);
    if (!permitted()) return;
    setNewStudent(current => permitted() ? { ...current, ...change } : current);
  };
  const handleCreateStudent = async (e, stage) => {
    e.preventDefault();
    if (!studentDeletionMountedRef.current || stagedStudentCreateRef.current !== stage || stage.consumed
      || pendingStudentAccountMutationRef.current || pendingStudentPasswordRef.current
      || !accountAccessPermissionRef.current || activeSectionRef.current !== 'students'
      || !isCurrentAdminAuthority(stage.authority)) return;
    const draft = newStudentRef.current;
    if (draft.password !== draft.confirmPassword) {
      toast.error('Passwords do not match');
      return;
    }

    if (draft.password.length < 8) {
      toast.error('Password must be at least 8 characters long');
      return;
    }
    if (draft.role !== 'student') return;
    const submitted = { username: draft.username, email: draft.email, password: draft.password,
      full_name: draft.full_name, role: 'student' };
    stage.consumed = true;
    pendingStudentAccountMutationRef.current = stage;
    setStudentAccountMutationPending(true);
    setStudentCreateOutcome({ kind: 'pending' });
    setNewStudent(current => ({ ...current, password: '', confirmPassword: '' }));
    const current = () => studentDeletionMountedRef.current && stagedStudentCreateRef.current === stage
      && accountAccessPermissionRef.current && activeSectionRef.current === 'students'
      && isCurrentAdminAuthority(stage.authority);
    try {
      const response = await axios.post('/api/admin/students', submitted,
        { headers: { 'Authorization': `Bearer ${stage.authority.token}` } });
      if (!current()) return;
      const created = response.data?.user;
      if (response.status !== 201 || response.data?.success !== true
        || !Number.isSafeInteger(created?.id) || created.id <= 0
        || created.username !== submitted.username || created.email !== submitted.email
        || created.full_name !== submitted.full_name || created.role !== 'student'
        || created.admin_level !== 0 || created.is_active !== 1)
        throw new Error('Student creation was not acknowledged.');
      stagedStudentCreateRef.current = null;
      setStudentCreateStage(null);
      setStudentCreateOutcome(null);
      toast.success('Student created successfully');
      setCreateStudentModalOpen(false);
      setNewStudent(emptyStudentDraft());
      void loadDashboardData(true, () => studentDeletionMountedRef.current
        && isCurrentAdminAuthority(stage.authority) && accountAccessPermissionRef.current
        && activeSectionRef.current === 'students');
    } catch (error) {
      if (!current()) return;
      const status = error.response?.status;
      setStudentCreateOutcome({ kind: status >= 400 && status < 500 && status !== 408 && status !== 409
        ? 'rejected' : 'unknown' });
    } finally {
      if (pendingStudentAccountMutationRef.current === stage) {
        pendingStudentAccountMutationRef.current = null;
        if (studentDeletionMountedRef.current) setStudentAccountMutationPending(false);
      }
    }
  };

  const navItems = [
    { id: 'dashboard', icon: FiHome, label: 'Dashboard' },
    { id: 'students', icon: FiUsers, label: 'Students' },
    { id: 'locked-users', icon: FiLock, label: 'Locked Users' },
    { id: 'student-workshop-view', icon: FiUser, label: 'Student View' },
    { id: 'exercises', icon: FiBookOpen, label: 'Exercises Management' },
    { id: 'ctf-management', icon: FiShield, label: 'CTF Management' },
    { id: 'progress-analytics', icon: FiTrendingUp, label: 'Student Progress' },
    { id: 'llm-health', icon: FiMonitor, label: 'LLM Health' },
    { id: 'ai-providers', icon: FiCpu, label: 'AI Provider Management' },
    { id: 'activity', icon: FiActivity, label: 'Activity Logs' },
    { id: 'server-logs', icon: FiCode, label: 'Server Logs' },
    { id: 'agent-runs', icon: FiZap, label: 'Agent Runs' },
    { id: 'settings', icon: FiSettings, label: 'Settings' }
  ];

  const renderDashboard = () => (
    <>
      <StatsGrid>
        <StatCard
          bgColor="linear-gradient(135deg, #667eea 0%, #764ba2 100%)"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
          onClick={() => canManageProgress && setActiveSection('students')}
          style={{ cursor: canManageProgress ? 'pointer' : 'default' }}
        >
          <div className="icon"><FiUsers /></div>
          <div className="content">
            <h3>{canManageProgress ? stats.totalStudents : '—'}</h3>
            <p>Total Students</p>
          </div>
        </StatCard>
        
        <StatCard
          bgColor="linear-gradient(135deg, #48bb78 0%, #38a169 100%)"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
            onClick={() => canViewActiveUsers && setActiveSection('activity')}
          style={{ cursor: canViewActiveUsers ? 'pointer' : 'default' }}
        >
          <div className="icon"><FiTrendingUp /></div>
          <div className="content">
            <h3>{activeUserCount ?? '—'}</h3>
            <p title="Users with recorded activity in the last 24 hours">Active Users</p>
          </div>
        </StatCard>
        
        <StatCard
          bgColor="linear-gradient(135deg, #ed8936 0%, #dd6b20 100%)"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3 }}
          onClick={() => setActiveSection('exercises')}
          style={{ cursor: 'pointer' }}
        >
          <div className="icon"><FiCheck /></div>
          <div className="content">
            <h3>{stats.completedChallenges}</h3>
            <p>Completed Exercises</p>
          </div>
        </StatCard>
        
        <StatCard
          bgColor="linear-gradient(135deg, #9f7aea 0%, #805ad5 100%)"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.4 }}
          onClick={() => setActiveSection('exercises')}
          style={{ cursor: 'pointer' }}
        >
          <div className="icon"><FiBookOpen /></div>
          <div className="content">
            <h3>{stats.totalChallenges}</h3>
            <p>Total Exercises</p>
          </div>
        </StatCard>
        
        <StatCard
          bgColor="linear-gradient(135deg, #38b2ac 0%, #319795 100%)"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.5 }}
          onClick={() => setActiveSection('exercises')}
          style={{ cursor: 'pointer' }}
        >
          <div className="icon"><FiEye /></div>
          <div className="content">
            <h3>{stats.visibleChallenges || 0}</h3>
            <p>Visible to Students</p>
          </div>
        </StatCard>
      </StatsGrid>
    </>
  );

  // ── Merged "Exercises Management" (was renderChallenges + renderSolutions) ──
  // One card per exercise. Master row (Active / Solutions / Hints) + Completions +
  // Reset + ONE "Manage Objectives" panel that unifies per-objective Visible +
  // Hint (from workshopObjectives/workshopHints) with per-objective Solution
  // visibility + Preview + Edit (from getObjectivePanelConfig). Reuses every
  // existing handler/state/modal — no new API calls.

  // Map a challenge → the two objective key-spaces it needs.
  const resolveExerciseKeys = (challengeKey) => ({
    // Objective/hint handlers apply toWorkshopKey() internally, so pass raw key.
    objectivesKey: challengeKey,
    solutionPanel: getObjectivePanelConfig(challengeKey),
  });

  // Build a per-objective solution lookup {objId -> solutionRow} for a panel,
  // so the merged row can attach Sol-Visible/Preview/Edit next to the canonical
  // objective. Handles the id-field variance (objective_id / objectiveId / challengeId).
  const buildSolutionByObjId = (panel) => {
    const map = {};
    if (!panel) return map;
    (panel.objectives || []).forEach(o => {
      const id = o[panel.lookupKey || panel.idKey];
      if (id != null) map[String(id)] = o;
    });
    return map;
  };

  // One unified objective table row (rendered inside the Manage Objectives modal).
  // Shared 5-column grid — header + every row use this SAME constant so columns
  // can never drift. Objective | Visible | Hint | Solution | Actions.
  const OBJ_GRID_COLUMNS = '1fr 84px 84px 84px 132px';

  const renderObjectiveRow = (wKey, obj, panel, solRow, idx) => {
    const objId = obj.objective_id;
    const hintEnabled = !!(workshopHints[wKey] || {})[objId];
    const studentGate = canonicalConfig?.exercises?.[toWorkshopKey(wKey)]?.objectives?.[objId];
    const hasSol = !!(panel && solRow);
    const solEnabled = hasSol ? !!solRow[panel.enabledKey] : false;
    const label = obj.label
      || (solRow && panel && panel.titleKey && solRow[panel.titleKey])
      || (panel && panel.labels && panel.labels[objId])
      || objId;
    const cell = { display: 'flex', alignItems: 'center', justifyContent: 'center' };
    return (
      <div key={objId} data-objective-id={objId} style={{
        display: 'grid', gridTemplateColumns: OBJ_GRID_COLUMNS, gap: '0.75rem',
        alignItems: 'center', padding: '0.7rem 0.5rem',
        borderBottom: '1px solid #edf2f7',
        background: idx % 2 ? '#fafbfc' : 'white'
      }}>
        {/* Objective label + monospace id */}
        <div style={{ minWidth: 0 }}>
          <div style={{ fontSize: '0.85rem', color: '#2d3748', fontWeight: 500, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }} title={label}>{label}</div>
          <div style={{ fontSize: '0.68rem', color: '#a0aec0', fontFamily: 'monospace' }}>{objId}</div>
          {studentGate && <div style={{ fontSize: '0.68rem', color: '#64748b' }}>
            Student view: hint {studentGate.hintVisible ? 'shown' : 'hidden'} · solution {studentGate.solutionVisible ? 'shown' : 'hidden'}
          </div>}
          {!!studentGate?.description && <div style={{ fontSize: '0.72rem', color: '#64748b', overflow: 'hidden', textOverflow: 'ellipsis' }} title={studentGate.description}>{studentGate.description}</div>}
        </div>
        {/* Visible */}
        <div style={cell}>
          <ToggleSwitch data-control="visible" enabled={!!obj.is_enabled} onClick={() => toggleObjective(wKey, objId, !!obj.is_enabled)} />
        </div>
        {/* Hint */}
        <div style={cell}>
          <ToggleSwitch enabled={hintEnabled} onClick={() => toggleHint(wKey, objId, hintEnabled)} />
        </div>
        {/* Solution toggle — isolated in its own column */}
        <div style={cell}>
          {hasSol
            ? <ToggleSwitch enabled={solEnabled} onClick={() => panel.toggle(solRow[panel.idKey], !solEnabled)} />
            : <ToggleSwitch enabled={!!obj.solutions_enabled} title={studentGate?.hasSolutionContent === false ? 'Author solution content before enabling' : 'Toggle solution visibility'}
                onClick={() => studentGate?.hasSolutionContent === false && !obj.solutions_enabled
                  ? toast.error('Author solution content before enabling it')
                  : toggleCanonicalSolution(wKey, objId, !!obj.solutions_enabled)} />}
        </div>
        {/* Actions: teaching text and content editors leave identity and grading fixed. */}
        <div style={{ ...cell, gap: '0.5rem' }}>
          <>
              <button onClick={(e) => { e.stopPropagation(); openObjectiveEditor(wKey, objId); }}
                style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#4f46e5', display: 'flex', padding: '2px' }}
                aria-label={`Edit objective ${label}`} title="Edit Objective"><FiEdit size={15} /></button>
              <button onClick={(e) => { e.stopPropagation(); openHintEditor(wKey, objId, label); }}
                style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#d69e2e', display: 'flex', padding: '2px' }}
                aria-label={`Edit hint for ${label}`} title="Edit Hint"><FiEdit size={15} /></button>
              <button onClick={(e) => { e.stopPropagation(); openUniversalSolutionEditor(wKey, objId); }}
                style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#2b6cb0', display: 'flex', padding: '2px' }}
                aria-label={`Edit solution teaching content for ${label}`} title={hasSol && panel.editFn ? 'Edit Teaching Content' : 'Edit Solution'}><FiEdit size={15} /></button>
              {hasSol && panel.viewFn && (
                <button onClick={(e) => { e.stopPropagation(); panel.viewFn(solRow[panel.idKey]); }}
                  style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#667eea', display: 'flex', padding: '2px' }}
                  title="Preview Solution"><FiEye size={15} /></button>
              )}
              {hasSol && panel.editFn && (
                <button onClick={(e) => { e.stopPropagation(); panel.editFn(solRow[panel.idKey]); }}
                  style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#3b82f6', display: 'flex', padding: '2px' }}
                  title="Edit Solution"><FiEdit size={15} /></button>
              )}
          </>
        </div>
      </div>
    );
  };

  // Manage-Objectives MODAL — keeps exercise cards compact + gives the objective
  // table room. Reuses Modal* styled components + all existing per-objective handlers.
  const renderObjectivesModal = () => {
    if (!objModalKey) return null;
    const challenge = challenges.find(c => (c.key || c.id) === objModalKey);
    const { objectivesKey, solutionPanel } = resolveExerciseKeys(objModalKey);
    const objectives = workshopObjectives[objectivesKey] || [];
    const solByObj = buildSolutionByObjId(solutionPanel);
    const close = () => { exerciseLoadRef.current.key = null; exerciseLoadRef.current.sequence++; exerciseLoadRef.current.controller?.abort(); setObjModalKey(null); };
    return (
      <ModalOverlay initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} onClick={close}>
        <ModalContent
          initial={{ scale: 0.95, opacity: 0 }} animate={{ scale: 1, opacity: 1 }}
          onClick={(e) => e.stopPropagation()}
        >
          <ModalHeader>
            <h3 style={{ margin: 0, display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <FiTarget /> Objectives — {challenge?.name || objModalKey}
            </h3>
            <button onClick={close} style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#718096', display: 'flex' }}><FiX size={20} /></button>
          </ModalHeader>
          <ModalBody>
            {objectives.length === 0 ? (
              <div style={{ fontSize: '0.9rem', color: '#718096', textAlign: 'center', padding: '2rem' }}>
                {solutionPanel ? 'No objectives found for this exercise.' : 'This exercise has no per-objective controls.'}
              </div>
            ) : (
              <>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem', flexWrap: 'wrap', gap: '0.5rem' }}>
                  <p style={{ margin: 0, fontSize: '0.8rem', color: '#718096' }}>
                    Toggle each objective's <strong>visibility</strong>, <strong>hint</strong>, and <strong>solution</strong>. Preview / edit solution content with the icons.
                  </p>
                  {objModalKey === 'secureshop_agent_security' && <p style={{ margin: 0, fontSize: '0.8rem', color: '#718096' }}>Only qualified objectives can be enabled. The two pending pricing objectives remain disabled.</p>}
                  {canManageChallenges && (
                    <div style={{ display: 'flex', gap: '0.4rem' }}>
                      <button disabled={objectiveBulkPending} onClick={() => toggleAllObjectives(objectivesKey, true)} style={{ fontSize: '0.72rem', padding: '0.3rem 0.7rem', background: '#48bb78', color: '#fff', border: 'none', borderRadius: '6px', cursor: 'pointer', fontWeight: 600 }}>Enable Available Objectives</button>
                      <button disabled={objectiveBulkPending} onClick={() => toggleAllObjectives(objectivesKey, false)} style={{ fontSize: '0.72rem', padding: '0.3rem 0.7rem', background: '#fc8181', color: '#fff', border: 'none', borderRadius: '6px', cursor: 'pointer', fontWeight: 600 }}>Disable All Objectives</button>
                    </div>
                  )}
                  {solutionPanel && solutionPanel.bulkToggle && (
                    <div style={{ display: 'flex', gap: '0.4rem' }}>
                      <button onClick={() => solutionPanel.bulkToggle(true)} style={{ fontSize: '0.72rem', padding: '0.3rem 0.7rem', background: '#48bb78', color: '#fff', border: 'none', borderRadius: '6px', cursor: 'pointer', fontWeight: 600 }}>Solutions: All On</button>
                      <button onClick={() => solutionPanel.bulkToggle(false)} style={{ fontSize: '0.72rem', padding: '0.3rem 0.7rem', background: '#fc8181', color: '#fff', border: 'none', borderRadius: '6px', cursor: 'pointer', fontWeight: 600 }}>All Off</button>
                    </div>
                  )}
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: OBJ_GRID_COLUMNS, gap: '0.75rem', padding: '0.5rem 0.5rem', borderBottom: '2px solid #e2e8f0', position: 'sticky', top: 0, background: 'white', zIndex: 1 }}>
                  {[['Objective','flex-start'],['Visible','center'],['Hint','center'],['Solution','center'],['Actions','center']].map(([h,j]) => (
                    <span key={h} style={{ fontSize: '0.7rem', color: '#718096', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.05em', textAlign: j==='center'?'center':'left' }}>{h}</span>
                  ))}
                </div>
                {objectives.map((obj, i) => renderObjectiveRow(objectivesKey, obj, solutionPanel, solByObj[String(obj.objective_id)], i))}
              </>
            )}
          </ModalBody>
          <ModalFooter>
            <ActionButton onClick={close}>Done</ActionButton>
          </ModalFooter>
        </ModalContent>
      </ModalOverlay>
    );
  };

  // In-app reset confirmation — replaces the native window.confirm() alert box.
  const renderResetConfirmModal = () => {
    if (!resetConfirm) return null;
    const close = () => closeBulkResetConfirm(resetConfirm);
    return (
      <ModalOverlay initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} onClick={close}>
        <ModalContent
          initial={{ scale: 0.95, opacity: 0 }} animate={{ scale: 1, opacity: 1 }}
          onClick={(e) => e.stopPropagation()}
          style={{ maxWidth: '460px' }}
        >
          <ModalHeader>
            <h3 style={{ margin: 0, display: 'flex', alignItems: 'center', gap: '0.5rem', color: '#c53030' }}>
              <FiAlertTriangle /> Reset All Student Progress
            </h3>
            <button onClick={close} style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#718096', display: 'flex' }}><FiX size={20} /></button>
          </ModalHeader>
          <ModalBody>
            <p style={{ margin: 0, fontSize: '0.9rem', color: '#2d3748', lineHeight: 1.5 }}>
              Reset <strong>ALL</strong> student progress for{' '}
              <strong>"{resetConfirm.workshopName}"</strong>?
            </p>
            <p style={{ margin: '0.6rem 0 0 0', fontSize: '0.82rem', color: '#c53030', fontWeight: 600 }}>
              This cannot be undone. A pending retry resumes the original learner cohort.
            </p>
          </ModalBody>
          <ModalFooter>
            <button
              onClick={close}
              style={{ padding: '0.55rem 1.1rem', borderRadius: '8px', border: '1px solid #e2e8f0', background: 'white', color: '#4a5568', cursor: 'pointer', fontWeight: 600, fontSize: '0.85rem' }}
            >
              Cancel
            </button>
            <button
              onClick={() => confirmResetAllStudents(resetConfirm)}
              style={{ padding: '0.55rem 1.1rem', borderRadius: '8px', border: 'none', background: '#e53e3e', color: 'white', cursor: 'pointer', fontWeight: 600, fontSize: '0.85rem' }}
            >
              Reset Progress
            </button>
          </ModalFooter>
        </ModalContent>
      </ModalOverlay>
    );
  };

  const renderAccountAccessConfirmModal = () => {
    if (!accountAccessConfirm) return null;
    const staged = accountAccessConfirm;
    const close = () => closeAccountAccessConfirm(staged);
    const locking = staged.action === 'lock';
    return (
      <ModalOverlay initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} onClick={close}>
        <ModalContent role="dialog" aria-label="Confirm account access change"
          initial={{ scale: 0.95, opacity: 0 }} animate={{ scale: 1, opacity: 1 }}
          onClick={event => event.stopPropagation()} style={{ maxWidth: '480px' }}>
          <ModalHeader>
            <h2>{locking ? 'Lock account' : 'Unlock account'}</h2>
            <button type="button" aria-label="Close account access confirmation" disabled={accountAccessStatus?.kind === 'pending'} onClick={close}><FiX /></button>
          </ModalHeader>
          <ModalBody>
            <p>{locking ? 'Lock' : 'Unlock'} <strong>{staged.target.username}</strong>?</p>
            <p>{locking
              ? 'Locking blocks new login and revokes all active sessions, including yours if this is your account.'
              : 'Unlocking permits a new login and clears failed login attempts. It does not restore revoked sessions.'}</p>
            {accountAccessStatus?.kind === 'pending' && <p role="status">Changing account access…</p>}
            {accountAccessStatus?.kind === 'unknown' && <p role="alert">
              The request outcome could not be confirmed.
              {accountAccessStatus.observed
                ? ` A fresh account read shows this account is currently ${accountAccessStatus.observed}; this does not prove this request made the change.`
                : ' Current account status could not be read.'}
              {' '}Close this dialog and start a new confirmation before any further change.
            </p>}
            {accountAccessStatus?.kind === 'rejected' && <p role="alert">
              The server rejected this account change: {accountAccessStatus.message}
            </p>}
          </ModalBody>
          <ModalFooter>
            <SecondaryButton type="button" disabled={accountAccessStatus?.kind === 'pending'} onClick={close}>
              {accountAccessStatus?.kind === 'unknown' || accountAccessStatus?.kind === 'rejected' ? 'Close' : 'Cancel'}
            </SecondaryButton>
            {!staged.consumed && <ActionButton type="button" variant={locking ? 'danger' : undefined}
              onClick={() => confirmAccountAccess(staged)}>{locking ? 'Confirm Lock' : 'Confirm Unlock'}</ActionButton>}
          </ModalFooter>
        </ModalContent>
      </ModalOverlay>
    );
  };

  const renderBulkVisibilityConfirmModal = () => {
    if (!bulkVisibilityConfirm) return null;
    const staged = bulkVisibilityConfirm;
    const close = () => closeBulkVisibility(staged);
    const verb = staged.enabled ? 'Enable' : 'Disable';
    return (
      <ModalOverlay initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} onClick={close}>
        <ModalContent role="dialog" aria-label="Confirm all exercise visibility change"
          initial={{ scale: 0.95, opacity: 0 }} animate={{ scale: 1, opacity: 1 }}
          onClick={event => event.stopPropagation()} style={{ maxWidth: '500px' }}>
          <ModalHeader>
            <h2>{verb} all exercises?</h2>
            <button type="button" aria-label="Close all exercise visibility confirmation"
              disabled={bulkVisibilityOutcome?.kind === 'pending'} onClick={close}><FiX /></button>
          </ModalHeader>
          <ModalBody>
            <p>This {staged.enabled ? 'shows' : 'hides'} all catalog-active exercises to learners, including those outside the current filtered list.</p>
            <p>Effective access to objectives, hints, and solutions follows exercise visibility. This does not delete exercises, reset learner progress, or change their configured gates.</p>
            {staged.enabled && <p>Exercises whose required runtime is not ready remain hidden; the server reports them after confirmation.</p>}
            {bulkVisibilityOutcome?.kind === 'pending' && <p role="status">Changing exercise visibility…</p>}
            {bulkVisibilityOutcome?.kind === 'unknown' && <p role="alert">
              The request outcome could not be confirmed. This dialog cannot retry it; close and review current visibility before a new confirmation.
            </p>}
            {bulkVisibilityOutcome?.kind === 'rejected' && <p role="alert">
              The server rejected this visibility change. No automatic retry was sent.
            </p>}
          </ModalBody>
          <ModalFooter>
            <SecondaryButton type="button" disabled={bulkVisibilityOutcome?.kind === 'pending'} onClick={close}>
              {staged.consumed ? 'Close' : 'Cancel'}
            </SecondaryButton>
            {!staged.consumed && <ActionButton type="button" onClick={() => confirmBulkVisibility(staged)}>
              Confirm {verb} All
            </ActionButton>}
          </ModalFooter>
        </ModalContent>
      </ModalOverlay>
    );
  };

  const renderBulkContentVisibilityConfirmModal = () => {
    if (!bulkContentConfirm) return null;
    const staged = bulkContentConfirm;
    const close = () => closeBulkContentVisibility(staged);
    const verb = staged.enabled ? 'Enable' : 'Disable';
    return (
      <ModalOverlay initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} onClick={close}>
        <ModalContent role="dialog" aria-label="Confirm all hint and solution visibility change"
          initial={{ scale: 0.95, opacity: 0 }} animate={{ scale: 1, opacity: 1 }}
          onClick={event => event.stopPropagation()} style={{ maxWidth: '500px' }}>
          <ModalHeader>
            <h2>{verb} all hints and solutions?</h2>
            <button type="button" aria-label="Close all hint and solution visibility confirmation"
              disabled={bulkContentOutcome?.kind === 'pending'} onClick={close}><FiX /></button>
          </ModalHeader>
          <ModalBody>
            <p>This {staged.enabled ? 'makes available' : 'hides'} all configured hints and solutions for catalog-active exercises, including those outside the current filtered list.</p>
            <p>It does not change exercise or objective visibility, delete teaching content, or reset learner progress. Objectives without the relevant content remain unavailable.</p>
            {bulkContentOutcome?.kind === 'pending' && <p role="status">Changing hint and solution visibility…</p>}
            {bulkContentOutcome?.kind === 'unknown' && <p role="alert">
              The request outcome could not be confirmed. This dialog cannot retry it; close and review current visibility before a new confirmation.
            </p>}
            {bulkContentOutcome?.kind === 'rejected' && <p role="alert">
              The server rejected this hint and solution visibility change. No automatic retry was sent.
            </p>}
          </ModalBody>
          <ModalFooter>
            <SecondaryButton type="button" disabled={bulkContentOutcome?.kind === 'pending'} onClick={close}>
              {staged.consumed ? 'Close' : 'Cancel'}
            </SecondaryButton>
            {!staged.consumed && <ActionButton type="button" onClick={() => confirmBulkContentVisibility(staged)}>
              Confirm {verb} All
            </ActionButton>}
          </ModalFooter>
        </ModalContent>
      </ModalOverlay>
    );
  };

  const renderExercises = () => (
    <ContentSection
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
    >
      <SectionHeader>
        <h2><FiBookOpen /> Exercises Management</h2>
        <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'center' }}>
          <ActionButton
            onClick={() => stageBulkContentVisibility(true)}
            disabled={bulkContentPending || !!bulkContentConfirm || !canManageChallenges}
            style={{ background: '#3182ce', color: 'white', display: 'flex', alignItems: 'center', gap: '0.5rem' }}
          >
            <FiToggleRight /> Enable All Hints &amp; Solutions
          </ActionButton>
          <ActionButton
            onClick={() => stageBulkContentVisibility(false)}
            disabled={bulkContentPending || !!bulkContentConfirm || !canManageChallenges}
            style={{ background: '#dd6b20', color: 'white', display: 'flex', alignItems: 'center', gap: '0.5rem' }}
          >
            <FiToggleLeft /> Disable All Hints &amp; Solutions
          </ActionButton>
          <ActionButton
            onClick={() => stageBulkVisibility(true)}
            disabled={bulkTogglingChallenges || !!bulkVisibilityConfirm || !canManageChallenges}
            style={{ background: '#48bb78', color: 'white', display: 'flex', alignItems: 'center', gap: '0.5rem' }}
          >
            <FiToggleRight /> Enable All
          </ActionButton>
          <ActionButton
            onClick={() => stageBulkVisibility(false)}
            disabled={bulkTogglingChallenges || !!bulkVisibilityConfirm || !canManageChallenges}
            style={{ background: '#f56565', color: 'white', display: 'flex', alignItems: 'center', gap: '0.5rem' }}
          >
            <FiToggleLeft /> Disable All
          </ActionButton>
        </div>
      </SectionHeader>

      <div style={{ marginBottom: '2rem' }}>
        <p style={{ color: '#718096', marginBottom: '1.5rem' }}>
          Show or hide each exercise, control student visibility of solutions &amp; hints, and open
          <strong> Manage Objectives</strong> for per-objective control. Visible exercises with no enabled objectives remain locked for students. Use the bulk controls above to change exercise visibility or all available hints and solutions.
        </p>

        {loading && (
          <div style={{ textAlign: 'center', padding: '2rem' }}>
            <FiRefreshCw style={{ animation: 'spin 1s linear infinite', fontSize: '2rem', color: '#667eea' }} />
            <p style={{ marginTop: '1rem', color: '#64748b' }}>Loading exercises...</p>
          </div>
        )}

        {!loading && challenges.length === 0 && (
          <div style={{ textAlign: 'center', padding: '3rem', background: 'white', borderRadius: '12px' }}>
            <FiAlertTriangle style={{ fontSize: '3rem', color: '#f59e0b', marginBottom: '1rem' }} />
            <h3 style={{ color: '#1a202c', marginBottom: '0.5rem' }}>No Exercises Found</h3>
            <p style={{ color: '#64748b', marginBottom: '1.5rem' }}>No exercises are currently configured in the system.</p>
            <ActionButton onClick={() => loadDashboardData()}><FiRefreshCw /> Reload Exercises</ActionButton>
          </div>
        )}

        {!loading && challenges.length > 0 && (
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(340px, 1fr))', gap: '1.25rem', alignItems: 'start' }}>
            {challenges.map(storedChallenge => {
              const cKey = storedChallenge.key || storedChallenge.id;
              const canonical = canonicalConfig?.exercises?.[toWorkshopKey(cKey)];
              const challenge = canonical ? { ...storedChallenge, enabled: canonical.isVisible, showHints: canonical.showHints, showSolutions: canonical.showSolutions } : storedChallenge;
              const { solutionPanel } = resolveExerciseKeys(cKey);
              const active = challenge.enabled;
              const objectiveEntries = canonical ? Object.values(canonical.objectives || {}) : null;
              const availableObjectives = objectiveEntries?.filter(objective => objective.isVisible === true).length;
              return (
              <React.Fragment key={challenge.id || challenge.key}>
              {cKey === 'secureshop_agent_security' && <h3 style={{ gridColumn: '1 / -1', margin: '1rem 0 0' }}>Separate application configuration</h3>}
              <div data-exercise-key={cKey === 'secureshop_agent_security' ? undefined : cKey} data-application-key={cKey === 'secureshop_agent_security' ? cKey : undefined} style={{
                background: 'white',
                border: `1px solid ${active ? '#9ae6b4' : '#e2e8f0'}`,
                borderLeft: `4px solid ${active ? '#48bb78' : '#cbd5e0'}`,
                borderRadius: '12px', padding: '1.15rem 1.25rem',
                boxShadow: '0 1px 3px rgba(0,0,0,0.06)',
                transition: 'all 0.2s ease', display: 'flex', flexDirection: 'column', gap: '0.85rem',
                opacity: active ? 1 : 0.85
              }}>
                {/* Header: title + difficulty + HERO Active toggle */}
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: '0.75rem' }}>
                  <div style={{ minWidth: 0 }}>
                    <h3 style={{ margin: '0 0 0.3rem 0', color: '#1a202c', fontSize: '1.02rem', lineHeight: 1.25 }}>{challenge.name}</h3>
                    <span style={{ fontSize: '0.7rem', color: '#718096', textTransform: 'uppercase', letterSpacing: '0.03em', fontWeight: 600 }}>
                      {challenge.category || 'General'} · {challenge.difficulty || 'Medium'}
                    </span>
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '0.15rem', flexShrink: 0 }}>
                    <ToggleSwitch data-control="active" enabled={active} aria-disabled={!!(pendingMasters[toWorkshopKey(cKey)] || staleMasters[toWorkshopKey(cKey)])} onClick={pendingMasters[toWorkshopKey(cKey)] || staleMasters[toWorkshopKey(cKey)] ? undefined : () => toggleChallenge(cKey, !active)} />
                    <span style={{ fontSize: '0.6rem', fontWeight: 700, letterSpacing: '0.06em', color: active ? '#276749' : '#a0aec0' }}>
                      {active ? 'VISIBLE' : 'HIDDEN'}
                    </span>
                  </div>
                </div>

                {/* Description — clamped to 2 lines */}
                <p style={{
                  color: '#718096', fontSize: '0.8rem', margin: 0, lineHeight: 1.4,
                  display: '-webkit-box', WebkitLineClamp: 2, WebkitBoxOrient: 'vertical', overflow: 'hidden'
                }}>
                  {challenge.description || 'No description available'}
                </p>

                {active && objectiveEntries && (
                  <p data-exercise-availability={cKey} style={{ margin: 0, fontSize: '0.78rem', color: availableObjectives === 0 ? '#975a16' : '#4a5568' }}>
                    {availableObjectives} of {objectiveEntries.length} objectives available to students.
                    {availableObjectives === 0 && ' Locked for students: no enabled objectives. Review Manage Objectives; unavailable objectives remain disabled.'}
                  </p>
                )}

                {/* Secondary controls: Solutions + Hints (compact pair) */}
                <div style={{ display: 'flex', gap: '0.6rem' }}>
                  {[
                    { label: 'Solutions', on: challenge.showSolutions, fn: () => handleToggleChallengeSolution(cKey, !challenge.showSolutions) },
                    { label: 'Hints', on: challenge.showHints, fn: () => handleToggleChallengeHints(cKey, !challenge.showHints) },
                  ].map(ctl => (
                    <div key={ctl.label} style={{
                      flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                      padding: '0.45rem 0.65rem', background: ctl.on ? '#f0fff4' : '#f7fafc',
                      border: `1px solid ${ctl.on ? '#c6f6d5' : '#edf2f7'}`, borderRadius: '8px'
                    }}>
                      <span style={{ fontSize: '0.78rem', fontWeight: 500, color: '#4a5568' }}>{ctl.label}</span>
                      <ToggleSwitch data-control={ctl.label.toLowerCase()} enabled={ctl.on} aria-disabled={!!(pendingMasters[toWorkshopKey(cKey)] || staleMasters[toWorkshopKey(cKey)])} onClick={pendingMasters[toWorkshopKey(cKey)] || staleMasters[toWorkshopKey(cKey)] ? undefined : ctl.fn} />
                    </div>
                  ))}
                </div>

                {/* Manage Objectives — opens modal (keeps card compact) */}
                <button
                  onClick={async () => {
                    exerciseLoadRef.current.key = cKey; setObjModalKey(null);
                    await loadExerciseState(cKey).catch(() => {});
                  }}
                  style={{
                    display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '0.4rem',
                    width: '100%', padding: '0.5rem', background: '#eef2ff', color: '#4f46e5',
                    border: '1px solid #e0e7ff', borderRadius: '8px', cursor: 'pointer',
                    fontSize: '0.8rem', fontWeight: 600
                  }}
                >
                  <FiTarget size={14} /> Manage Objectives
                </button>

                {/* Footer: completions · reset · status pills */}
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', paddingTop: '0.75rem', borderTop: '1px solid #edf2f7', fontSize: '0.78rem' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
                    <span style={{ color: '#718096' }}>✓ {challenge.completions}</span>
                    {canManageProgress && <button
                      onClick={() => resetAllStudentsForWorkshop(cKey, challenge.name)}
                      disabled={!!resettingWorkshop[cKey]}
                      style={{ padding: '0.2rem 0.6rem', borderRadius: '6px', fontSize: '0.72rem', background: '#fff5f5', color: '#c53030', border: '1px solid #feb2b2', cursor: 'pointer', fontWeight: 600 }}
                    >
                      {resettingWorkshop[cKey] ? 'Resetting…' : 'Reset'}
                    </button>}
                  </div>
                  <div style={{ display: 'flex', gap: '0.35rem' }}>
                    {challenge.showSolutions && <span style={{ padding: '0.15rem 0.5rem', borderRadius: '20px', fontSize: '0.68rem', background: '#dbeafe', color: '#1e40af', fontWeight: 600 }}>SOL</span>}
                    {challenge.showHints && <span style={{ padding: '0.15rem 0.5rem', borderRadius: '20px', fontSize: '0.68rem', background: '#fef3c7', color: '#92400e', fontWeight: 600 }}>HINT</span>}
                    {solutionPanel == null && <span style={{ padding: '0.15rem 0.5rem', borderRadius: '20px', fontSize: '0.68rem', background: '#edf2f7', color: '#718096', fontWeight: 600 }}>NO OBJ</span>}
                  </div>
                </div>
              </div>
              </React.Fragment>
            );
            })}
          </div>
        )}
      </div>
      {renderObjectivesModal()}
      {renderResetConfirmModal()}
    </ContentSection>
  );

  const renderStudents = () => (
    <ContentSection
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
    >
      <SectionHeader>
        <h2><FiUsers /> Student Management</h2>
        <div style={{ display: 'flex', gap: '0.5rem' }}>
          <ActionButton 
            onClick={() => loadDashboardData()} 
            style={{ 
              background: 'transparent', 
              border: '2px solid #4f46e5', 
              color: '#4f46e5',
              padding: '0.5rem'
            }}
            title="Refresh student data"
          >
            <FiRefreshCw />
          </ActionButton>
          <ActionButton onClick={openStudentCreate}>
            <FiPlus /> Create New Student
          </ActionButton>
        </div>
      </SectionHeader>
      <StudentTable>
        <table>
          <thead>
            <tr>
              <th>Student</th>
              <th>Email</th>
              <th>Progress</th>
              <th>Objectives</th>
              <th>Last Active</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr>
                <td colSpan="6" style={{ textAlign: 'center', padding: '2rem', color: '#718096' }}>
                  <FiRefreshCw style={{
                    animation: 'spin 1s linear infinite',
                    marginRight: '0.5rem',
                    '@keyframes spin': {
                      '0%': { transform: 'rotate(0deg)' },
                      '100%': { transform: 'rotate(360deg)' }
                    }
                  }} />
                  Loading students...
                </td>
              </tr>
            ) : students.length > 0 ? students.map(student => (
              <tr key={student.id}>
                <td>{student.username}</td>
                <td>{student.email}</td>
                <td>{student.completed_challenges !== undefined ? `${student.completed_challenges}/${student.total_challenges}` : '0/8'}</td>
                <td title="Objectives completed across all workshops">{student.wop_completed_objectives || 0}</td>
                <td>{student.last_login || 'Never'}</td>
                <td>
                  <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
                    <ActionButton 
                      onClick={() => {
                        navigate(`/admin/student-workshop-view?studentId=${student.id}`);
                        setActiveSection('student-workshop-view');
                      }}
                      style={{ padding: '0.4rem 0.8rem', fontSize: '0.8rem' }}
                    >
                      <FiUser /> Workshop View
                    </ActionButton>
                    <ActionButton 
                      onClick={() => handleViewStudent(student.id)}
                      disabled={loadingStudent}
                      style={{ padding: '0.4rem 0.8rem', fontSize: '0.8rem', background: '#4a5568' }}
                    >
                      <FiEye /> Details
                    </ActionButton>
                    <ActionButton 
                      onClick={() => handleEditStudent(student)}
                      style={{ padding: '0.4rem 0.8rem', fontSize: '0.8rem', background: '#3b82f6' }}
                    >
                      <FiEdit /> Edit
                    </ActionButton>
                    <ActionButton 
                      onClick={() => handleChangeStudentPassword(student)}
                      style={{ padding: '0.4rem 0.8rem', fontSize: '0.8rem', background: '#f59e0b' }}
                    >
                      <FiLock /> Password
                    </ActionButton>
                    <ActionButton 
                      onClick={() => handleDeleteStudent(student)}
                      variant="danger"
                      disabled={!canDeleteStudents}
                      title={deleteStudentPermissionTitle}
                      style={{ padding: '0.4rem 0.8rem', fontSize: '0.8rem' }}
                    >
                      <FiTrash2 /> Delete
                    </ActionButton>
                  </div>
                </td>
              </tr>
            )) : (
              <tr>
                <td colSpan="5" style={{ textAlign: 'center', color: '#718096' }}>
                  No students found
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </StudentTable>
    </ContentSection>
  );

  const renderLockedUsers = () => (
    <ContentSection
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
    >
      <SectionHeader>
        <h2><FiLock /> Locked Users Management</h2>
        <ActionButton
          onClick={() => fetchLockedUsers()}
          disabled={loadingLockedUsers}
          style={{
            background: 'transparent',
            border: '2px solid #4f46e5',
            color: '#4f46e5',
            padding: '0.5rem'
          }}
          title="Refresh locked users list"
        >
          <FiRefreshCw />
        </ActionButton>
      </SectionHeader>

      <p style={{ color: '#718096', marginBottom: '1.5rem' }}>
        Review manually locked and rate-limited accounts. Unlocking clears the lock and failed attempts
        so an active account can sign in again; revoked sessions are not restored.
      </p>

      {loadingLockedUsers ? (
        <div style={{ textAlign: 'center', padding: '2rem' }}>
          <FiRefreshCw style={{ animation: 'spin 1s linear infinite', fontSize: '2rem', color: '#667eea' }} />
          <p style={{ marginTop: '1rem', color: '#64748b' }}>Loading locked users...</p>
        </div>
      ) : lockedUsers.length === 0 ? (
        <div style={{ textAlign: 'center', padding: '3rem', background: 'white', borderRadius: '12px' }}>
          <FiCheck style={{ fontSize: '3rem', color: '#48bb78', marginBottom: '1rem' }} />
          <h3 style={{ color: '#1a202c', marginBottom: '0.5rem' }}>No Locked Users</h3>
          <p style={{ color: '#64748b' }}>
            All users have full access. No accounts are currently locked.
          </p>
        </div>
      ) : (
        <StudentTable>
          <table>
            <thead>
              <tr>
                <th>Username</th>
                <th>Email</th>
                <th>Failed Attempts</th>
                <th>Lock Status</th>
                <th>Time Remaining</th>
                <th>Last Login IP</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {lockedUsers.map(user => (
                <tr key={user.id}>
                  <td>
                    <strong>{user.username}</strong>
                    {user.full_name && <div style={{ fontSize: '0.85rem', color: '#718096' }}>{user.full_name}</div>}
                  </td>
                  <td>{user.email}</td>
                  <td>
                    <div style={{
                      display: 'inline-block',
                      padding: '0.25rem 0.75rem',
                      borderRadius: '20px',
                      fontSize: '0.85rem',
                      background: user.login_attempts >= 5 ? '#fed7d7' : '#feebc8',
                      color: user.login_attempts >= 5 ? '#9b2c2c' : '#9c4221'
                    }}>
                      {user.login_attempts || 0} attempts
                    </div>
                  </td>
                  <td>
                    <div style={{
                      display: 'inline-block',
                      padding: '0.25rem 0.75rem',
                      borderRadius: '20px',
                      fontSize: '0.85rem',
                      background: user.lock_type === 'admin' ? '#e9d8fd' : user.isCurrentlyLocked ? '#fed7d7' : '#fef3c7',
                      color: user.lock_type === 'admin' ? '#553c9a' : user.isCurrentlyLocked ? '#9b2c2c' : '#78350f'
                    }}>
                      {user.lock_type === 'admin' ? 'LOCKED BY ADMIN' : user.isCurrentlyLocked ? 'LOCKED' : 'Rate Limited'}
                    </div>
                  </td>
                  <td>
                    {user.lock_type === 'admin' ? (
                      <span style={{ color: '#718096' }}>— (manual)</span>
                    ) : user.isCurrentlyLocked ? (
                      <span style={{ color: '#f56565', fontWeight: '500' }}>
                        {user.remainingMinutes} min
                      </span>
                    ) : (
                      <span style={{ color: '#718096' }}>-</span>
                    )}
                  </td>
                  <td style={{ fontSize: '0.85rem', color: '#718096' }}>
                    {user.last_login_ip || 'N/A'}
                  </td>
                  <td>
                    <ActionButton
                      onClick={() => unlockUser(user.id, user.username)}
                      disabled={!accountAccessPermissionRef.current}
                      style={{
                        padding: '0.4rem 0.8rem',
                        fontSize: '0.8rem',
                        background: '#48bb78',
                        color: 'white'
                      }}
                    >
                      <FiCheck /> Unlock
                    </ActionButton>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </StudentTable>
      )}
    </ContentSection>
  );

  const renderActivityLogs = () => {
    // Helper functions for activity logs
    // Updated: Full timestamp display with timezone v3.0 - Shows complete date/time with seconds and timezone
    const formatTimestamp = (timestamp, timezone) => {
      const date = new Date(timestamp);
      const now = new Date();
      const diffMinutes = Math.floor((now - date) / (1000 * 60));
      
      // Format the full timestamp with timezone
      const fullTimestamp = date.toLocaleString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        hour12: true
      });
      
      // Calculate relative time
      let relativeTime = '';
      if (diffMinutes < 1) relativeTime = 'Just now';
      else if (diffMinutes < 60) relativeTime = `${diffMinutes} min${diffMinutes === 1 ? '' : 's'} ago`;
      else if (diffMinutes < 1440) relativeTime = `${Math.floor(diffMinutes / 60)} hour${Math.floor(diffMinutes / 60) === 1 ? '' : 's'} ago`;
      else relativeTime = `${Math.floor(diffMinutes / 1440)} day${Math.floor(diffMinutes / 1440) === 1 ? '' : 's'} ago`;
      
      // Add timezone information if available
      const timezoneInfo = timezone ? ` ${timezone}` : '';
      return `${fullTimestamp}${timezoneInfo} (${relativeTime})`;
    };

    const getActivityTypeInfo = (actionType, success) => {
      if (actionType === 'login_success' || (actionType === 'login' && success)) {
        return { color: '#48bb78', type: 'success' };
      }
      if (actionType === 'login_failed' || (actionType === 'login' && !success)) {
        return { color: '#ffd93d', type: 'warning' };
      }
      if (actionType === 'challenge_complete' || actionType === 'challenge_start') {
        return { color: '#2196f3', type: 'info' };
      }
      if (actionType === 'admin_action') {
        return { color: '#9333ea', type: 'admin' };
      }
      return { color: '#6b7280', type: 'default' };
    };

    return (
      <ContentSection
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
      >
        <h2><FiActivity /> Activity Logs <span style={{ fontSize: '0.7rem', color: '#666', fontWeight: 'normal' }}>(v2.0 - Full Timestamps)</span></h2>
        
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '1.5rem', marginBottom: '2rem' }}>
          <div style={{ 
            background: '#e8f5e8', 
            padding: '1.5rem', 
            borderRadius: '12px', 
            border: '2px solid #48bb78' 
          }}>
            <h4 style={{ color: '#2d7738', marginBottom: '0.5rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <FiCheck /> Successful Logins
            </h4>
            <div style={{ fontSize: '2rem', fontWeight: '700', color: '#2d7738' }}>
              {loadingActivity ? '...' : activityLoadError ? '—' : activityStats.successful_logins || 0}
            </div>
            <div style={{ fontSize: '0.9rem', color: '#2d7738' }}>Last 24 hours</div>
          </div>
          
          <div style={{ 
            background: '#fff3cd', 
            padding: '1.5rem', 
            borderRadius: '12px', 
            border: '2px solid #ffd93d' 
          }}>
            <h4 style={{ color: '#856404', marginBottom: '0.5rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <FiAlertTriangle /> Failed Attempts
            </h4>
            <div style={{ fontSize: '2rem', fontWeight: '700', color: '#856404' }}>
              {loadingActivity ? '...' : activityLoadError ? '—' : activityStats.failed_logins || 0}
            </div>
            <div style={{ fontSize: '0.9rem', color: '#856404' }}>Last 24 hours</div>
          </div>
          
          <div style={{ 
            background: '#e3f2fd', 
            padding: '1.5rem', 
            borderRadius: '12px', 
            border: '2px solid #2196f3' 
          }}>
            <h4 style={{ color: '#1565c0', marginBottom: '0.5rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <FiTrendingUp /> Challenge Completions
            </h4>
            <div style={{ fontSize: '2rem', fontWeight: '700', color: '#1565c0' }}>
              {loadingActivity ? '...' : activityLoadError ? '—' : activityStats.challenge_completions || 0}
            </div>
            <div style={{ fontSize: '0.9rem', color: '#1565c0' }}>Today</div>
          </div>
        </div>
        
        <div style={{ background: '#f8f9fa', padding: '1.5rem', borderRadius: '12px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
            <h3 style={{ color: '#1a202c', margin: 0 }}>Recent Activity</h3>
            <ActionButton onClick={() => loadActivityData(activityPage)} disabled={loadingActivity}>
              <FiMonitor />
              Refresh
            </ActionButton>
          </div>
          
          {loadingActivity ? (
            <div style={{ textAlign: 'center', padding: '2rem', color: '#666' }}>
              Loading activity logs...
            </div>
          ) : activityLoadError ? (
            <div role="alert" style={{ textAlign: 'center', padding: '2rem', color: '#666' }}>
              {activityLoadError}
            </div>
          ) : recentActivity.length === 0 ? (
            <div style={{ textAlign: 'center', padding: '2rem', color: '#666' }}>
              No recent activity found
            </div>
          ) : (
            <>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                {recentActivity.map((log) => {
                  const typeInfo = getActivityTypeInfo(log.action_type, log.success);
                  return (
                    <div key={log.id} style={{ 
                      display: 'flex', 
                      justifyContent: 'space-between', 
                      alignItems: 'center',
                      padding: '1rem',
                      background: 'white',
                      borderRadius: '8px',
                      borderLeft: `4px solid ${typeInfo.color}`
                    }}>
                      <div>
                        <div style={{ fontWeight: '600', color: '#1a202c' }}>{log.action_description}</div>
                        <div style={{ fontSize: '0.9rem', color: '#666' }}>
                          by {log.username || 'System'} • {log.action_type}
                        </div>
                      </div>
                      <div style={{ fontSize: '0.9rem', color: '#666' }}>
                        {formatTimestamp(log.timestamp, log.timezone)}
                      </div>
                    </div>
                  );
                })}
              </div>
              
              {/* Pagination Controls */}
              <div style={{ 
                marginTop: '1.5rem', 
                padding: '1.5rem', 
                background: 'white', 
                borderRadius: '8px',
                display: 'flex',
                flexDirection: 'column',
                gap: '1rem'
              }}>
                {/* Page Info */}
                <div style={{ 
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  flexWrap: 'wrap',
                  gap: '1rem'
                }}>
                  <div style={{ fontSize: '0.9rem', color: '#666' }}>
                    Showing {activityTotalCount > 0 ? ((activityPage - 1) * activityPerPage) + 1 : 0} to {Math.min(activityPage * activityPerPage, activityTotalCount)} of {activityTotalCount.toLocaleString()} logs
                  </div>
                  <div style={{ fontSize: '0.875rem', color: '#667eea', fontWeight: '500' }}>
                    Page {activityPage} of {activityTotalPages.toLocaleString()}
                  </div>
                </div>
                
                {/* Pagination Buttons */}
                <div style={{ 
                  display: 'flex',
                  justifyContent: 'center',
                  alignItems: 'center',
                  gap: '0.5rem',
                  flexWrap: 'wrap'
                }}>
                  {/* First Page */}
                  <button
                    onClick={() => setActivityPage(1)}
                    disabled={activityPage === 1}
                    style={{
                      padding: '0.5rem 0.75rem',
                      border: '1px solid #d1d5db',
                      borderRadius: '6px',
                      background: activityPage === 1 ? '#f3f4f6' : 'white',
                      color: activityPage === 1 ? '#9ca3af' : '#374151',
                      cursor: activityPage === 1 ? 'not-allowed' : 'pointer',
                      fontSize: '0.875rem',
                      fontWeight: '500',
                      transition: 'all 0.2s'
                    }}
                    title="First Page"
                  >
                    ««
                  </button>
                  
                  {/* Previous Page */}
                  <button
                    onClick={() => setActivityPage(activityPage - 1)}
                    disabled={activityPage === 1}
                    style={{
                      padding: '0.5rem 0.75rem',
                      border: '1px solid #d1d5db',
                      borderRadius: '6px',
                      background: activityPage === 1 ? '#f3f4f6' : 'white',
                      color: activityPage === 1 ? '#9ca3af' : '#374151',
                      cursor: activityPage === 1 ? 'not-allowed' : 'pointer',
                      fontSize: '0.875rem',
                      fontWeight: '500',
                      transition: 'all 0.2s'
                    }}
                  >
                    ‹ Previous
                  </button>
                  
                  {/* Page Numbers */}
                  {Array.from({ length: Math.min(activityTotalPages, 5) }, (_, i) => {
                    let pageNum;
                    if (activityTotalPages <= 5) {
                      pageNum = i + 1;
                    } else if (activityPage <= 3) {
                      pageNum = i + 1;
                    } else if (activityPage >= activityTotalPages - 2) {
                      pageNum = activityTotalPages - 4 + i;
                    } else {
                      pageNum = activityPage - 2 + i;
                    }
                    
                    return (
                      <button
                        key={pageNum}
                        onClick={() => setActivityPage(pageNum)}
                        style={{
                          padding: '0.5rem 0.75rem',
                          border: '1px solid #d1d5db',
                          borderRadius: '6px',
                          background: activityPage === pageNum ? '#667eea' : 'white',
                          color: activityPage === pageNum ? 'white' : '#374151',
                          cursor: 'pointer',
                          fontSize: '0.875rem',
                          fontWeight: '500',
                          minWidth: '40px',
                          transition: 'all 0.2s'
                        }}
                      >
                        {pageNum}
                      </button>
                    );
                  })}
                  
                  {/* Next Page */}
                  <button
                    onClick={() => setActivityPage(activityPage + 1)}
                    disabled={activityPage === activityTotalPages}
                    style={{
                      padding: '0.5rem 0.75rem',
                      border: '1px solid #d1d5db',
                      borderRadius: '6px',
                      background: activityPage === activityTotalPages ? '#f3f4f6' : 'white',
                      color: activityPage === activityTotalPages ? '#9ca3af' : '#374151',
                      cursor: activityPage === activityTotalPages ? 'not-allowed' : 'pointer',
                      fontSize: '0.875rem',
                      fontWeight: '500',
                      transition: 'all 0.2s'
                    }}
                  >
                    Next ›
                  </button>
                  
                  {/* Last Page */}
                  <button
                    onClick={() => setActivityPage(activityTotalPages)}
                    disabled={activityPage === activityTotalPages}
                    style={{
                      padding: '0.5rem 0.75rem',
                      border: '1px solid #d1d5db',
                      borderRadius: '6px',
                      background: activityPage === activityTotalPages ? '#f3f4f6' : 'white',
                      color: activityPage === activityTotalPages ? '#9ca3af' : '#374151',
                      cursor: activityPage === activityTotalPages ? 'not-allowed' : 'pointer',
                      fontSize: '0.875rem',
                      fontWeight: '500',
                      transition: 'all 0.2s'
                    }}
                    title="Last Page"
                  >
                    »»
                  </button>
                </div>
                
                {/* Page Jump */}
                <div style={{ 
                  display: 'flex',
                  justifyContent: 'center',
                  alignItems: 'center',
                  gap: '0.5rem',
                  paddingTop: '0.5rem',
                  borderTop: '1px solid #e5e7eb'
                }}>
                  <span style={{ fontSize: '0.875rem', color: '#6b7280' }}>Jump to page:</span>
                  <input
                    type="number"
                    min="1"
                    max={activityTotalPages}
                    value={activityPageJump}
                    onChange={(e) => setActivityPageJump(e.target.value)}
                    onKeyPress={(e) => {
                      if (e.key === 'Enter') {
                        const page = parseInt(activityPageJump);
                        if (page >= 1 && page <= activityTotalPages) {
                          setActivityPage(page);
                          setActivityPageJump('');
                        } else {
                          toast.error(`Page must be between 1 and ${activityTotalPages.toLocaleString()}`);
                        }
                      }
                    }}
                    placeholder={`1-${activityTotalPages.toLocaleString()}`}
                    style={{
                      width: '100px',
                      padding: '0.5rem',
                      border: '1px solid #d1d5db',
                      borderRadius: '6px',
                      fontSize: '0.875rem'
                    }}
                  />
                  <button
                    onClick={() => {
                      const page = parseInt(activityPageJump);
                      if (page >= 1 && page <= activityTotalPages) {
                        setActivityPage(page);
                        setActivityPageJump('');
                      } else {
                        toast.error(`Page must be between 1 and ${activityTotalPages.toLocaleString()}`);
                      }
                    }}
                    disabled={!activityPageJump}
                    style={{
                      padding: '0.5rem 1rem',
                      border: '1px solid #667eea',
                      borderRadius: '6px',
                      background: activityPageJump ? '#667eea' : '#f3f4f6',
                      color: activityPageJump ? 'white' : '#9ca3af',
                      cursor: activityPageJump ? 'pointer' : 'not-allowed',
                      fontSize: '0.875rem',
                      fontWeight: '500',
                      transition: 'all 0.2s'
                    }}
                  >
                    Go
                  </button>
                </div>
              </div>
            </>
          )}
        </div>

        {/* Active Users Section: the roster has a stronger permission than audit logs. */}
        <div style={{ background: '#f8f9fa', padding: '1.5rem', borderRadius: '12px', marginTop: '2rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
            <h3 style={{ color: '#1a202c', margin: 0 }}>
              <FiUsers style={{ marginRight: '0.5rem', verticalAlign: 'middle' }} />
              Active Users & Their Activity
            </h3>
            {canViewActiveUsers && (
              <ActionButton onClick={loadActiveUsersData} disabled={loadingActiveUsers}>
                <FiMonitor />
                Refresh
              </ActionButton>
            )}
          </div>
          
          {!canViewActiveUsers ? (
            <div role="status" style={{ textAlign: 'center', padding: '2rem', color: '#666' }}>
              User activity details require user management permission.
            </div>
          ) : (
            <>
              {activeUsersLoadError && (
                <div role="alert" style={{ marginBottom: '1rem', padding: '0.75rem 1rem', borderRadius: '8px', background: '#fff3cd', color: '#856404' }}>
                  {activeUsersLoadError}
                </div>
              )}
              {loadingActiveUsers ? (
            <div style={{ textAlign: 'center', padding: '2rem', color: '#666' }}>
              Loading active users...
            </div>
              ) : activeUsers.length === 0 && !activeUsersLoadError ? (
            <div style={{ textAlign: 'center', padding: '2rem', color: '#666' }}>
              No active users found
            </div>
              ) : activeUsers.length > 0 ? (
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(350px, 1fr))', gap: '1rem' }}>
              {activeUsers.map((user) => {
                const activityColor = 
                  (user.recent_activity_count || 0) > 50 ? '#48bb78' : 
                  (user.recent_activity_count || 0) > 20 ? '#2196f3' : 
                  (user.recent_activity_count || 0) > 5 ? '#f59e0b' : '#6b7280';
                
                return (
                  <div key={user.id} style={{ 
                    background: 'white',
                    borderRadius: '8px',
                    padding: '1rem',
                    borderLeft: `4px solid ${activityColor}`,
                    boxShadow: '0 2px 4px rgba(0,0,0,0.1)'
                  }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                      <div style={{ flex: 1 }}>
                        <div style={{ fontWeight: '600', color: '#1a202c', fontSize: '1rem', marginBottom: '0.25rem' }}>
                          {user.username}
                        </div>
                        <div style={{ fontSize: '0.85rem', color: '#666', marginBottom: '0.5rem' }}>
                          {user.full_name || user.email}
                        </div>
                        <div style={{ 
                          display: 'inline-block',
                          padding: '0.25rem 0.5rem',
                          background: user.role === 'admin' || user.admin_level > 0 ? '#9333ea20' : '#667eea20',
                          color: user.role === 'admin' || user.admin_level > 0 ? '#9333ea' : '#667eea',
                          borderRadius: '4px',
                          fontSize: '0.75rem',
                          fontWeight: '600',
                          textTransform: 'uppercase'
                        }}>
                          {user.role}
                        </div>
                      </div>
                      <div style={{ 
                        background: `${activityColor}20`,
                        color: activityColor,
                        padding: '0.5rem 1rem',
                        borderRadius: '8px',
                        textAlign: 'center',
                        minWidth: '70px'
                      }}>
                        <div style={{ fontSize: '1.5rem', fontWeight: '700' }}>
                          {user.recent_activity_count || 0}
                        </div>
                        <div style={{ fontSize: '0.7rem', opacity: 0.8 }}>
                          Activities
                        </div>
                      </div>
                    </div>
                    
                    <div style={{ 
                      marginTop: '0.75rem',
                      paddingTop: '0.75rem',
                      borderTop: '1px solid #e2e8f0',
                      display: 'grid',
                      gridTemplateColumns: '1fr 1fr',
                      gap: '0.5rem',
                      fontSize: '0.8rem'
                    }}>
                      <div>
                        <div style={{ color: '#666' }}>Completed</div>
                        <div style={{ fontWeight: '600', color: '#1a202c' }}>
                          {user.completed_challenges || 0} / {user.total_challenges || 0}
                        </div>
                      </div>
                      <div>
                        <div style={{ color: '#666' }}>Progress</div>
                        <div style={{ fontWeight: '600', color: '#1a202c' }}>
                          {user.progress_percentage || 0}%
                        </div>
                      </div>
                      <div>
                        <div style={{ color: '#666' }}>Last Login</div>
                        <div style={{ fontWeight: '600', color: '#1a202c', fontSize: '0.75rem' }}>
                          {user.last_login ? new Date(user.last_login).toLocaleDateString() : 'Never'}
                        </div>
                      </div>
                      <div>
                        <div style={{ color: '#666' }}>Period</div>
                        <div style={{ fontWeight: '600', color: '#1a202c', fontSize: '0.75rem' }}>
                          30 days
                        </div>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
              ) : null}
            </>
          )}
        </div>
      </ContentSection>
    );
  };

  const renderSettings = () => (
    <ContentSection
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
    >
      <h2><FiSettings /> Admin Settings</h2>
      
      {/* Admin Profile Section */}
      <div style={{ 
        background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)', 
        color: 'white', 
        padding: '2rem', 
        borderRadius: '16px', 
        marginBottom: '2rem' 
      }}>
        <h3 style={{ margin: '0 0 1rem 0', display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          <FiShield /> Admin Profile
        </h3>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))', gap: '1.5rem' }}>
          <div>
            <div style={{ fontSize: '0.9rem', opacity: 0.8, marginBottom: '0.5rem' }}>Username</div>
            <div style={{ fontSize: '1.2rem', fontWeight: '600' }}>{user?.username}</div>
          </div>
          <div>
            <div style={{ fontSize: '0.9rem', opacity: 0.8, marginBottom: '0.5rem' }}>Email</div>
            <div style={{ fontSize: '1.2rem', fontWeight: '600' }}>{user?.email}</div>
          </div>
          <div>
            <div style={{ fontSize: '0.9rem', opacity: 0.8, marginBottom: '0.5rem' }}>Admin Level</div>
            <div style={{ fontSize: '1.2rem', fontWeight: '600' }}>Level {user?.adminLevel}</div>
          </div>
          <div>
            <div style={{ fontSize: '0.9rem', opacity: 0.8, marginBottom: '0.5rem' }}>Role</div>
            <div style={{ fontSize: '1.2rem', fontWeight: '600' }}>{user?.role}</div>
          </div>
        </div>
      </div>
      
      {/* Platform Configuration */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '1.5rem' }}>
        <div style={{ 
          background: '#f8f9fa', 
          padding: '1.5rem', 
          borderRadius: '12px', 
          border: '2px solid #e9ecef' 
        }}>
          <h4 style={{ color: '#1a202c', marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <FiShield /> Security Settings
          </h4>
          <div style={{ fontSize: '0.9rem', color: '#666', marginBottom: '1rem' }}>
            Configure platform security options and access controls.
          </div>
          <ActionButton onClick={handleSecuritySettings}>
            <FiEdit /> Configure Security
          </ActionButton>
        </div>
        
        <div style={{ 
          background: '#f8f9fa', 
          padding: '1.5rem', 
          borderRadius: '12px', 
          border: '2px solid #e9ecef' 
        }}>
          <h4 style={{ color: '#1a202c', marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <FiUsers /> User Management
          </h4>
          <div style={{ fontSize: '0.9rem', color: '#666', marginBottom: '1rem' }}>
            Manage user accounts, permissions, and access levels.
          </div>
          <ActionButton onClick={handleUserManagement} disabled={!hasUserManagementPermission}
            title={hasUserManagementPermission ? 'Manage users' : 'User management permission required'}>
            <FiSettings /> Manage Users
          </ActionButton>
        </div>
        
        <div style={{ 
          background: '#f8f9fa', 
          padding: '1.5rem', 
          borderRadius: '12px', 
          border: '2px solid #e9ecef' 
        }}>
          <h4 style={{ color: '#1a202c', marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <FiActivity /> System Monitoring
          </h4>
          <div style={{ fontSize: '0.9rem', color: '#666', marginBottom: '1rem' }}>
            Monitor system performance and user activities.
          </div>
          <ActionButton onClick={handleViewLogs} disabled={loadingLogs}>
            <FiEye /> {loadingLogs ? 'Loading...' : 'View Logs'}
          </ActionButton>
        </div>
      </div>

      {/* Workshop Settings Section */}
      <div style={{ 
        marginTop: '2rem',
        background: '#e8f5e9', 
        border: '2px solid #4caf50',
        padding: '1.5rem', 
        borderRadius: '12px'
      }}>
        <h4 style={{ color: '#2e7d32', marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <FiSettings /> Workshop Settings
        </h4>
        <div style={{ 
          display: 'flex', 
          justifyContent: 'space-between', 
          alignItems: 'center',
          padding: '1rem',
          background: 'white',
          borderRadius: '8px',
          border: '1px solid #c8e6c9'
        }}>
          <div>
            <div style={{ fontWeight: '600', color: '#1a202c', marginBottom: '0.25rem' }}>
              Allow random email on workshop signup
            </div>
            <div style={{ fontSize: '0.85rem', color: '#666' }}>
              Show a "Generate random email" button on the signup page for quick demo registrations
            </div>
          </div>
          <div
            onClick={randomEmailLoading ? undefined : toggleRandomEmail}
            style={{
              width: '52px',
              height: '28px',
              background: randomEmailEnabled ? '#4caf50' : '#ccc',
              borderRadius: '14px',
              position: 'relative',
              cursor: randomEmailLoading ? 'wait' : 'pointer',
              transition: 'background 0.3s ease',
              opacity: randomEmailLoading ? 0.6 : 1
            }}
          >
            <div style={{
              width: '24px',
              height: '24px',
              background: 'white',
              borderRadius: '50%',
              position: 'absolute',
              top: '2px',
              left: randomEmailEnabled ? '26px' : '2px',
              transition: 'left 0.3s ease',
              boxShadow: '0 2px 4px rgba(0,0,0,0.2)'
            }} />
          </div>
        </div>

        {/* Allow User Registration toggle */}
        <div style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          padding: '1rem',
          background: 'white',
          borderRadius: '8px',
          border: '1px solid #c8e6c9',
          marginTop: '0.75rem'
        }}>
          <div>
            <div style={{ fontWeight: '600', color: '#1a202c', marginBottom: '0.25rem' }}>
              Allow User Registration
            </div>
            <div style={{ fontSize: '0.85rem', color: '#666' }}>
              Allow new users to register accounts on the workshop login page.
              Currently: <strong style={{ color: allowRegistration ? '#22c55e' : '#ef4444' }}>
                {allowRegistration ? 'Enabled' : 'Disabled'}
              </strong>
            </div>
          </div>
          <div
            onClick={allowRegistrationLoading ? undefined : toggleAllowRegistration}
            style={{
              width: '52px', height: '28px',
              background: allowRegistration ? '#4caf50' : '#ccc',
              borderRadius: '14px', position: 'relative',
              cursor: allowRegistrationLoading ? 'wait' : 'pointer',
              transition: 'background 0.3s ease',
              opacity: allowRegistrationLoading ? 0.6 : 1,
              flexShrink: 0
            }}
          >
            <div style={{
              width: '24px', height: '24px', background: 'white',
              borderRadius: '50%', position: 'absolute', top: '2px',
              left: allowRegistration ? '26px' : '2px',
              transition: 'left 0.3s ease',
              boxShadow: '0 2px 4px rgba(0,0,0,0.2)'
            }} />
          </div>
        </div>
      </div>
      
      {/* Rate Limiting Section */}
      <div style={{
        marginTop: '2rem',
        background: '#e8f4fd',
        border: '2px solid #667eea',
        padding: '1.5rem',
        borderRadius: '12px'
      }}>
        <h4 style={{ color: '#4c51bf', marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <FiShield /> Rate Limiting
        </h4>
        <div style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          padding: '1rem',
          background: 'white',
          borderRadius: '8px',
          border: '1px solid #c3dafe'
        }}>
          <div>
            <div style={{ fontWeight: '600', color: '#1a202c', marginBottom: '0.25rem' }}>
              Enable Login Rate Limiting
            </div>
            <div style={{ fontSize: '0.85rem', color: '#666' }}>
              Limit login attempts to 20 per 15 minutes per IP. Disable during workshops to prevent student lockouts.
              Currently: <strong style={{ color: rateLimitEnabled ? '#22c55e' : '#ef4444' }}>{rateLimitEnabled ? 'Enabled' : 'Disabled'}</strong>
            </div>
          </div>
          <div
            onClick={rateLimitLoading ? undefined : toggleRateLimit}
            style={{
              width: '52px',
              height: '28px',
              background: rateLimitEnabled ? '#4caf50' : '#ccc',
              borderRadius: '14px',
              position: 'relative',
              cursor: rateLimitLoading ? 'wait' : 'pointer',
              transition: 'background 0.3s ease',
              opacity: rateLimitLoading ? 0.6 : 1,
              flexShrink: 0
            }}
          >
            <div style={{
              width: '24px',
              height: '24px',
              background: 'white',
              borderRadius: '50%',
              position: 'absolute',
              top: '2px',
              left: rateLimitEnabled ? '26px' : '2px',
              transition: 'left 0.3s ease',
              boxShadow: '0 2px 4px rgba(0,0,0,0.2)'
            }} />
          </div>
        </div>
      </div>

      <div style={{ marginTop: '1.5rem' }}>
        <h4 style={{ color: '#2d3748', marginBottom: '0.75rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <FiShoppingCart /> SecureShop Playground
        </h4>
        <div style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          padding: '1rem',
          background: 'white',
          borderRadius: '8px',
          border: '1px solid #c3dafe'
        }}>
          <div>
            <div style={{ fontWeight: '600', color: '#1a202c', marginBottom: '0.25rem' }}>
              Show SecureShop Playground
            </div>
            <div style={{ fontSize: '0.85rem', color: '#666' }}>
              Toggle visibility of the SecureShop e-commerce card on the landing page and workshop home.
              Currently: <strong style={{ color: secureshopVisible ? '#22c55e' : '#ef4444' }}>{secureshopVisible ? 'Visible' : 'Hidden'}</strong>
            </div>
          </div>
          <div
            onClick={secureshopLoading ? undefined : toggleSecureshop}
            style={{
              width: '52px',
              height: '28px',
              background: secureshopVisible ? '#4caf50' : '#ccc',
              borderRadius: '14px',
              position: 'relative',
              cursor: secureshopLoading ? 'wait' : 'pointer',
              transition: 'background 0.3s ease',
              opacity: secureshopLoading ? 0.6 : 1,
              flexShrink: 0
            }}
          >
            <div style={{
              width: '24px',
              height: '24px',
              background: 'white',
              borderRadius: '50%',
              position: 'absolute',
              top: '2px',
              left: secureshopVisible ? '26px' : '2px',
              transition: 'left 0.3s ease',
              boxShadow: '0 2px 4px rgba(0,0,0,0.2)'
            }} />
          </div>
        </div>
      </div>

      {/* Password Change Section */}
      <div style={{
        marginTop: '2rem',
        background: '#fff3cd',
        border: '2px solid #ffd93d',
        padding: '1.5rem',
        borderRadius: '12px'
      }}>
        <h4 style={{ color: '#856404', marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <FiLock /> Change Password
        </h4>
        <div style={{ fontSize: '0.9rem', color: '#856404', marginBottom: '1rem' }}>
          Update your admin account password for enhanced security.
        </div>
        <ActionButton style={{ background: '#fd7e14' }} onClick={handleChangePassword}>
          <FiEdit /> Change Password
        </ActionButton>
      </div>

      {/* Database Reset Section - Only for Super Admins */}
      {user?.adminLevel >= 2 && (
        <>
          <div style={{ 
            background: '#e8f4fd', 
            border: '2px solid #667eea', 
            padding: '1.5rem', 
            borderRadius: '12px',
            marginTop: '1.5rem'
          }}>
            <h4 style={{ color: '#4c51bf', marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <FiRefreshCw /> PostgreSQL Schema Migrations
            </h4>
            <div style={{ fontSize: '0.9rem', color: '#2d3436', marginBottom: '1rem' }}>
              Run <code style={{ background: '#fff', padding: '0.2rem 0.4rem', borderRadius: '4px' }}>npm run db:initialize-all</code> from the configured installation to apply pending PostgreSQL migrations and default-only seeds. This preserves existing data and uses the configured migration roles. Use the authenticated workshop and administrator reset controls for their documented scopes; schema migration does not reset learner progress.
            </div>
            <ActionButton 
              style={{ background: '#667eea', color: 'white' }} 
              disabled
              title="Run the migration command from the configured installation"
            >
              <FiRefreshCw /> Use migration command
            </ActionButton>
          </div>
          <div style={{ 
            background: '#ffeaa7', 
            border: '2px solid #fdcb6e', 
            padding: '1.5rem', 
            borderRadius: '12px',
            marginTop: '1.5rem'
          }}>
            <h4 style={{ color: '#d63031', marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <FiAlertTriangle /> Database Reset (Dangerous)
            </h4>
            <div style={{ fontSize: '0.9rem', color: '#2d3436', marginBottom: '1rem' }}>
              Reset canonical workshop data or remove old activity logs. User accounts are preserved. No automatic backup is created.
            </div>
            <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap' }}>
              {canManageProgress && <ActionButton
                style={{ background: '#fdcb6e', color: '#2d3436' }} 
                onClick={() => handleDatabaseReset('challenges')}
              >
                <FiTrash2 /> Reset Challenge Data
              </ActionButton>}
              <ActionButton 
                style={{ background: '#e17055', color: 'white' }} 
                onClick={() => handleDatabaseReset('logs')}
              >
                <FiTrash2 /> Clear Old Logs
              </ActionButton>
              {user?.adminLevel >= 3 && (
                <ActionButton 
                  style={{ background: '#d63031', color: 'white' }} 
                  onClick={() => handleDatabaseReset('full')}
                >
                  <FiTrash2 /> Full Reset
                </ActionButton>
              )}
            </div>
          </div>
        </>
      )}
    </ContentSection>
  );

  // Unified objective-panel config: maps challenge_key → { objectives array, toggle fn, bulkToggle fn, editFn, labels, loading state }
  const getObjectivePanelConfig = (challengeKey) => {
    const LABELS = {
      sensitive_info_disclosure: { tool_enum: 'Tool Enumeration', llm_identify: 'LLM Identity Leak', tool_version: 'Version Disclosure', traversal_secrets: 'Read secrets.env', traversal_passwd: 'Read /etc/passwd', traversal_llm: 'Read llm_config.yml', ssrf_oob: 'Out-of-Band SSRF', ssrf_internal: 'Internal App SSRF', ssrf_ollama: 'Ollama Enumeration SSRF', error_leak: 'Verbose Error Leak', jailbreak: 'Jailbreak ARIA', admin_enum: 'Admin Tool Enumeration', admin_backup: 'Create DB Backup', admin_dl_backup: 'Download DB Backup', admin_read_logs: 'Read App Logs', admin_llm_logs: 'Read LLM Logs', admin_modify_logs: 'Tamper with Logs', admin_secrets: 'Exfiltrate Secrets', admin_dirlist: 'Directory + System Enum' },
      supply_chain_rce: { tool_list: 'Enumerate Tools', pkg_discover: 'Identify Vulnerable Package', clean_request: 'Normal Check', rce_env: 'Read .env Secrets', rce_ssh: 'Steal SSH Key', rce_cmd: 'Execute System Commands' },
      indirect_prompt_injection: { rag_upload: 'Upload Document', rag_query: 'Query the Agent', rag_clean_doc: 'Clean Document', rag_injected_doc: 'Injected Document', rag_query_injection: 'Query with Injection' },
      mcp_server_rce: { mcp_recon: 'Recon — Discover Tools', mcp_cmd_injection: 'Command Injection', mcp_ssrf: 'SSRF — Internal Access', mcp_tool_poisoning: 'Tool Poisoning', mcp_indirect_injection: 'Indirect Injection', mcp_confused_deputy: 'Confused Deputy', mcp_broken_authz: 'Broken Authorization', mcp_secret_exposure: 'Secret Exposure', mcp_supply_chain: 'Supply Chain', mcp_audit_gap: 'Target-Private Audit Gap', mcp_shadow_server: 'Shadow Server' },
      direct_prompt_injection: { system_prompt: 'System Prompt', jailbreak: 'Jailbreak', multi_language: 'Multi-Language', virtualization: 'Virtualization', role_playing: 'Role Playing', side_stepping: 'Side Stepping', obfuscation: 'Obfuscation' },
    };
    const configs = {
      sensitive_info_disclosure: { objectives: finflowSolutions || [], idKey: 'objectiveId', enabledKey: 'solutionsEnabled', labels: LABELS.sensitive_info_disclosure, loading: finflowSolutionLoading, toggle: (id, v) => toggleFinflowSolution(id, v), bulkToggle: (v) => toggleAllFinflowSolutions(v), viewFn: (id) => openSolutionPreview(`/api/admin/finflow-workshop/solutions/preview/${id}`), titleKey: 'title' },
      supply_chain_rce: { objectives: scSolutions || [], idKey: 'objective_id', enabledKey: 'solutions_enabled', labels: LABELS.supply_chain_rce, loading: scSolutionLoading, toggle: (id, v) => toggleScSolution(id, v), bulkToggle: (v) => toggleAllScSolutions(v), editFn: (id) => handleEditScObjective(id), viewFn: (id) => handleViewScObjective(id), titleKey: 'title' },
      excessive_agency: { objectives: eaSolutions || [], idKey: 'objective_id', enabledKey: 'solutions_enabled', labels: {}, loading: eaSolutionLoading, toggle: (id, v) => toggleEaSolution(id, v), bulkToggle: (v) => toggleAllEaSolutions(v), viewFn: (id) => openSolutionPreview(`/api/admin/ea-workshop/solutions/preview/${id}`), titleKey: 'title' },
      indirect_prompt_injection: { objectives: ipiSolutions || [], idKey: 'objective_id', enabledKey: 'solutions_enabled', labels: LABELS.indirect_prompt_injection, loading: ipiSolutionLoading, toggle: (id, v) => toggleIpiSolution(id, v), bulkToggle: (v) => toggleAllIpiSolutions(v), viewFn: (id) => openSolutionPreview(`/api/admin/ipi-workshop/solutions/preview/${id}`), titleKey: 'title' },
      mcp_server_rce: { objectives: mcpSolutions || [], idKey: 'objective_id', enabledKey: 'solutions_enabled', labels: LABELS.mcp_server_rce, loading: mcpSolutionLoading, toggle: (id, v) => toggleMcpSolution(id, v), bulkToggle: (v) => toggleAllMcpSolutions(v), viewFn: (id) => openSolutionPreview(`/api/admin/mcp-workshop/solutions/preview/${id}`), editFn: openMcpSolutionEditor, titleKey: 'title' },
      reflected_xss_llm: { objectives: xssObjectives || [], idKey: 'objective_id', enabledKey: 'solutions_enabled', labels: {}, loading: xssLoading, toggle: (id, v) => toggleXssObjective(id, v), viewFn: (id) => openSolutionPreview(`/api/admin/xss-workshop/objective-solutions/preview/${id}`), editFn: (id) => handleEditXssObjective(id), bulkToggle: (v) => toggleXssAllSolutions(v), titleKey: 'title' },
      xss_email_builder: {
        objectives: (solutions || []).filter(solution => solution.challengeKey === 'xss_email_builder' || solution.challenge_key === 'xss_email_builder'),
        idKey: 'id', lookupKey: 'objective_id', enabledKey: 'isPublic', labels: {}, loading: loadingSolutions,
        toggle: (id, enabled) => toggleSolutionVisibility(id, enabled),
        viewFn: id => { const solution = (solutions || []).find(row => row.id === id); if (solution) { setSelectedSolution(solution); setSolutionModalOpen(true); } },
        editFn: id => { const solution = (solutions || []).find(row => row.id === id); if (solution) handleEditSolution(solution); },
        titleKey: 'title',
      },
      csrf_prompt_injection: { objectives: csrfObjectives || [], idKey: 'objective_id', enabledKey: 'solutions_enabled', labels: {}, loading: csrfLoading, toggle: (id, v) => toggleCsrfObjective(id, v), viewFn: (id) => openSolutionPreview(`/api/admin/csrf-workshop/objective-solutions/preview/${id}`), editFn: (id) => handleEditCsrfObjective(id), bulkToggle: (v) => toggleCsrfAllSolutions(v), titleKey: 'title' },
      sql_injection_workshop: { objectives: sqliObjectives || [], idKey: 'objective_id', enabledKey: 'solutions_enabled', labels: {}, loading: sqliLoading, toggle: (id, v) => toggleSqliObjective(id, v), bulkToggle: (v) => toggleAllSqliObjectives(v), viewFn: (id) => openSolutionPreview(`/api/admin/sql-injection-workshop/solutions/preview/${id}`), titleKey: 'title' },
      nosql_injection_workshop: { objectives: nosqliObjectives || [], idKey: 'objective_id', enabledKey: 'solutions_enabled', labels: {}, loading: nosqliLoading, toggle: (id, v) => toggleNosqliObjective(id, v), bulkToggle: (v) => toggleAllNosqliObjectives(v), viewFn: (id) => openSolutionPreview(`/api/admin/nosql-injection-workshop/solutions/preview/${id}`), titleKey: 'title' },
      // SecureShop uses the canonical cross-workshop solution ledger. Keep the
      // objective panel on that generic contract so pending objectives retain
      // the backend's authoritative 409 enablement guard.
      secureshop_agent_security: {
        objectives: (solutions || []).filter(solution =>
          solution.challengeKey === 'secureshop_agent_security'
          || solution.challenge_key === 'secureshop_agent_security'),
        idKey: 'id', lookupKey: 'objective_id', enabledKey: 'isPublic', labels: {}, loading: loadingSolutions,
        toggle: (id, enabled) => toggleSolutionVisibility(id, enabled),
        viewFn: id => {
          const solution = (solutions || []).find(row => row.id === id);
          if (solution) { setSelectedSolution(solution); setSolutionModalOpen(true); }
        },
        editFn: id => {
          const solution = (solutions || []).find(row => row.id === id);
          if (solution) handleEditSolution(solution);
        },
        titleKey: 'title',
      },
      legacy_sensitive_file_ssi: {
        objectives: (solutions || []).filter(solution =>
          solution.challengeKey === 'legacy_sensitive_file_ssi'
          || solution.challenge_key === 'legacy_sensitive_file_ssi'),
        idKey: 'id', lookupKey: 'objective_id', enabledKey: 'isPublic', labels: {}, loading: loadingSolutions,
        toggle: (id, enabled) => toggleSolutionVisibility(id, enabled),
        viewFn: id => {
          const solution = (solutions || []).find(row => row.id === id);
          if (solution) { setSelectedSolution(solution); setSolutionModalOpen(true); }
        },
        editFn: id => {
          const solution = (solutions || []).find(row => row.id === id);
          if (solution) handleEditSolution(solution);
        },
        titleKey: 'title',
      },
      direct_prompt_injection: { objectives: piSolutionChallenges || [], idKey: 'challengeId', enabledKey: 'solutionsEnabled', labels: LABELS.direct_prompt_injection, loading: piSolutionLoading, toggle: (id, v) => togglePiSolution(id, v), bulkToggle: (v) => toggleAllPiSolutions(v), viewFn: (id) => handleViewPiObjective(id), editFn: (id) => handleEditPiObjective(id) },
    };
    return configs[challengeKey] || null;
  };

  // XSS/CSRF objective edit modals (rendered inside Exercises Management)
  const renderObjEditModals = () => (
    <>
      {xssObjEditId && (
          <ModalOverlay initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} onClick={() => setXssObjEditId(null)}>
            <ModalContent
              initial={{ scale: 0.9, opacity: 0 }} animate={{ scale: 1, opacity: 1 }} exit={{ scale: 0.9, opacity: 0 }}
              onClick={e => e.stopPropagation()}
              style={{ maxWidth: '640px', maxHeight: '85vh' }}
            >
              <ModalHeader>
                <h2>Edit Objective Solution — {xssObjEditId}</h2>
                <button onClick={() => setXssObjEditId(null)}><FiX /></button>
              </ModalHeader>
              <ModalBody style={{ overflowY: 'auto', padding: '1.5rem', display: 'flex', flexDirection: 'column', gap: '1.1rem' }}>
                <div>
                  <label style={{ fontWeight: '600', fontSize: '0.9rem', display: 'block', marginBottom: '0.4rem' }}>Title</label>
                  <input value={xssObjEditFormData.title || ''} onChange={e => setXssObjEditFormData(p => ({ ...p, title: e.target.value }))}
                    style={{ width: '100%', padding: '0.6rem', borderRadius: '6px', border: '1px solid #e2e8f0', fontSize: '0.9rem', boxSizing: 'border-box' }} />
                </div>
                <div>
                  <label style={{ fontWeight: '600', fontSize: '0.9rem', display: 'block', marginBottom: '0.4rem' }}>Hint</label>
                  <textarea value={xssObjEditFormData.hint || ''} onChange={e => setXssObjEditFormData(p => ({ ...p, hint: e.target.value }))} rows={3}
                    style={{ width: '100%', padding: '0.6rem', borderRadius: '6px', border: '1px solid #e2e8f0', fontSize: '0.9rem', resize: 'vertical', boxSizing: 'border-box' }} />
                </div>
                <div>
                  <label style={{ fontWeight: '600', fontSize: '0.9rem', display: 'block', marginBottom: '0.4rem' }}>Example Prompt / Payload</label>
                  <textarea value={xssObjEditFormData.example || ''} onChange={e => setXssObjEditFormData(p => ({ ...p, example: e.target.value }))} rows={3}
                    style={{ width: '100%', padding: '0.6rem', borderRadius: '6px', border: '1px solid #e2e8f0', fontSize: '0.9rem', resize: 'vertical', boxSizing: 'border-box', fontFamily: 'monospace' }} />
                </div>
                <div>
                  <label style={{ fontWeight: '600', fontSize: '0.9rem', display: 'block', marginBottom: '0.4rem' }}>Explanation (Why it works)</label>
                  <textarea value={xssObjEditFormData.explanation || ''} onChange={e => setXssObjEditFormData(p => ({ ...p, explanation: e.target.value }))} rows={4}
                    style={{ width: '100%', padding: '0.6rem', borderRadius: '6px', border: '1px solid #e2e8f0', fontSize: '0.9rem', resize: 'vertical', boxSizing: 'border-box' }} />
                </div>
              </ModalBody>
              <div style={{ padding: '1rem 1.5rem', borderTop: '1px solid #e2e8f0', display: 'flex', justifyContent: 'flex-end', gap: '0.75rem' }}>
                <ActionButton onClick={() => setXssObjEditId(null)} style={{ background: '#718096' }}>Cancel</ActionButton>
                <ActionButton onClick={handleSaveXssObjective}>Save Changes</ActionButton>
              </div>
            </ModalContent>
          </ModalOverlay>
        )}

      {csrfObjEditId && (
          <ModalOverlay initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} onClick={() => setCsrfObjEditId(null)}>
            <ModalContent
              initial={{ scale: 0.9, opacity: 0 }} animate={{ scale: 1, opacity: 1 }} exit={{ scale: 0.9, opacity: 0 }}
              onClick={e => e.stopPropagation()}
              style={{ maxWidth: '640px', maxHeight: '85vh' }}
            >
              <ModalHeader>
                <h2>Edit Objective Solution — {csrfObjEditId}</h2>
                <button onClick={() => setCsrfObjEditId(null)}><FiX /></button>
              </ModalHeader>
              <ModalBody style={{ overflowY: 'auto', padding: '1.5rem', display: 'flex', flexDirection: 'column', gap: '1.1rem' }}>
                <div>
                  <label style={{ fontWeight: '600', fontSize: '0.9rem', display: 'block', marginBottom: '0.4rem' }}>Title</label>
                  <input value={csrfObjEditFormData.title || ''} onChange={e => setCsrfObjEditFormData(p => ({ ...p, title: e.target.value }))}
                    style={{ width: '100%', padding: '0.6rem', borderRadius: '6px', border: '1px solid #e2e8f0', fontSize: '0.9rem', boxSizing: 'border-box' }} />
                </div>
                <div>
                  <label style={{ fontWeight: '600', fontSize: '0.9rem', display: 'block', marginBottom: '0.4rem' }}>Hint</label>
                  <textarea value={csrfObjEditFormData.hint || ''} onChange={e => setCsrfObjEditFormData(p => ({ ...p, hint: e.target.value }))} rows={3}
                    style={{ width: '100%', padding: '0.6rem', borderRadius: '6px', border: '1px solid #e2e8f0', fontSize: '0.9rem', resize: 'vertical', boxSizing: 'border-box' }} />
                </div>
                <div>
                  <label style={{ fontWeight: '600', fontSize: '0.9rem', display: 'block', marginBottom: '0.4rem' }}>Example Prompt / Payload</label>
                  <textarea value={csrfObjEditFormData.example || ''} onChange={e => setCsrfObjEditFormData(p => ({ ...p, example: e.target.value }))} rows={3}
                    style={{ width: '100%', padding: '0.6rem', borderRadius: '6px', border: '1px solid #e2e8f0', fontSize: '0.9rem', resize: 'vertical', boxSizing: 'border-box', fontFamily: 'monospace' }} />
                </div>
                <div>
                  <label style={{ fontWeight: '600', fontSize: '0.9rem', display: 'block', marginBottom: '0.4rem' }}>Explanation (Why it works)</label>
                  <textarea value={csrfObjEditFormData.explanation || ''} onChange={e => setCsrfObjEditFormData(p => ({ ...p, explanation: e.target.value }))} rows={4}
                    style={{ width: '100%', padding: '0.6rem', borderRadius: '6px', border: '1px solid #e2e8f0', fontSize: '0.9rem', resize: 'vertical', boxSizing: 'border-box' }} />
                </div>
              </ModalBody>
              <div style={{ padding: '1rem 1.5rem', borderTop: '1px solid #e2e8f0', display: 'flex', justifyContent: 'flex-end', gap: '0.75rem' }}>
                <ActionButton onClick={() => setCsrfObjEditId(null)} style={{ background: '#718096' }}>Cancel</ActionButton>
                <ActionButton onClick={handleSaveCsrfObjective}>Save Changes</ActionButton>
              </div>
            </ModalContent>
          </ModalOverlay>
        )}

    </>
  );

  const renderPiAllSolutionsViewModal = () => {
    if (!piAllSolutions || piAllSolutions.length === 0) return null;
    return (
      <ModalOverlay
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
        onClick={() => setPiAllSolutionsViewModalOpen(false)}
      >
        <ModalContent
          initial={{ scale: 0.9, opacity: 0 }}
          animate={{ scale: 1, opacity: 1 }}
          exit={{ scale: 0.9, opacity: 0 }}
          onClick={(e) => e.stopPropagation()}
          style={{ maxWidth: '1000px', maxHeight: '85vh' }}
        >
          <ModalHeader>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
              <FiShield style={{ color: '#667eea' }} />
              <h2>Comprehensive Prompt Injection Solutions</h2>
            </div>
            <button onClick={() => setPiAllSolutionsViewModalOpen(false)}><FiX /></button>
          </ModalHeader>
          <ModalBody style={{ overflowY: 'auto', padding: '1.5rem' }}>
            <p style={{ color: '#718096', marginBottom: '2rem', fontSize: '0.95rem' }}>
              This view shows the solution content for all 7 prompt injection objectives currently configured in the database.
            </p>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '2.5rem' }}>
              {piAllSolutions.map((sol, index) => (
                <div key={sol.challenge_id || index} style={{ 
                  border: '1px solid #e2e8f0', 
                  borderRadius: '12px', 
                  overflow: 'hidden',
                  background: 'white',
                  boxShadow: '0 2px 4px rgba(0,0,0,0.05)'
                }}>
                  <div style={{ 
                    background: '#f8fafc', 
                    padding: '1rem 1.5rem', 
                    borderBottom: '1px solid #e2e8f0',
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center'
                  }}>
                    <h3 style={{ margin: 0, fontSize: '1.1rem', color: '#1a202c' }}>
                      {index + 1}. {sol.title}
                    </h3>
                    <span style={{ 
                      padding: '0.2rem 0.6rem', 
                      background: '#ebf4ff', 
                      color: '#4299e1', 
                      borderRadius: '9999px',
                      fontSize: '0.75rem',
                      fontWeight: '700'
                    }}>
                      {sol.difficulty}
                    </span>
                  </div>
                  
                  <div style={{ padding: '1.5rem' }}>
                    <div style={{ marginBottom: '1.5rem' }}>
                      <h4 style={{ fontSize: '0.9rem', color: '#4a5568', marginBottom: '0.5rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                        Approach
                      </h4>
                      <p style={{ color: '#2d3748', fontSize: '0.9rem', lineHeight: '1.5', margin: 0 }}>
                        {sol.approach}
                      </p>
                    </div>

                    <div style={{ marginBottom: '1.5rem' }}>
                      <h4 style={{ fontSize: '0.9rem', color: '#4a5568', marginBottom: '0.75rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                        Example Payloads
                      </h4>
                      <div style={{ display: 'grid', gridTemplateColumns: '1fr', gap: '0.75rem' }}>
                        {sol.examples?.map((ex, i) => (
                          <div key={i} style={{ background: '#f1f5f9', padding: '0.75rem', borderRadius: '8px', borderLeft: '3px solid #667eea' }}>
                            <code style={{ display: 'block', fontSize: '0.85rem', color: '#1e293b', marginBottom: '0.4rem' }}>
                              {ex.prompt}
                            </code>
                            <div style={{ fontSize: '0.8rem', color: '#64748b', fontStyle: 'italic' }}>
                              {ex.explanation}
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>

                    <div>
                      <h4 style={{ fontSize: '0.9rem', color: '#4a5568', marginBottom: '0.5rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                        Tips
                      </h4>
                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem' }}>
                        {sol.tips?.map((tip, i) => (
                          <span key={i} style={{ 
                            background: '#f0fdf4', 
                            color: '#166534', 
                            padding: '0.25rem 0.6rem', 
                            borderRadius: '6px', 
                            fontSize: '0.8rem',
                            border: '1px solid #dcfce7'
                          }}>
                            ✓ {tip}
                          </span>
                        ))}
                      </div>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </ModalBody>
          <ModalFooter>
            <ActionButton onClick={() => setPiAllSolutionsViewModalOpen(false)}>Close Overview</ActionButton>
          </ModalFooter>
        </ModalContent>
      </ModalOverlay>
    );
  };

  const renderSolutionPreviewModal = () => {
    if (!solutionPreview) return null;
    const examples = solutionPreview.examples || [];
    return (
      <ModalOverlay
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
        onClick={() => setSolutionPreview(null)}
      >
        <ModalContent
          initial={{ scale: 0.9, opacity: 0 }}
          animate={{ scale: 1, opacity: 1 }}
          exit={{ scale: 0.9, opacity: 0 }}
          onClick={(e) => e.stopPropagation()}
          style={{ maxWidth: '800px' }}
        >
          <ModalHeader>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
              <FiEye style={{ color: '#667eea' }} />
              <h2>{solutionPreview.title || 'Solution Preview'}</h2>
            </div>
            <button onClick={() => setSolutionPreview(null)}><FiX /></button>
          </ModalHeader>
          <ModalBody>
            {solutionPreview.difficulty && (
              <div style={{ display: 'flex', gap: '1rem', marginBottom: '1.5rem' }}>
                <span style={{
                  padding: '0.25rem 0.75rem',
                  background: '#ebf4ff',
                  color: '#4299e1',
                  borderRadius: '9999px',
                  fontSize: '0.875rem',
                  fontWeight: '600'
                }}>
                  Difficulty: {solutionPreview.difficulty}
                </span>
              </div>
            )}
            {solutionPreview.approach && (
              <>
                <h3 style={{ fontSize: '1.1rem', marginBottom: '0.75rem', color: '#2d3748' }}>Recommended Approach</h3>
                <p style={{ color: '#4a5568', lineHeight: '1.6', marginBottom: '1.5rem' }}>{solutionPreview.approach}</p>
              </>
            )}
            {solutionPreview.hint && (
              <>
                <h3 style={{ fontSize: '1.1rem', marginBottom: '0.75rem', color: '#2d3748' }}>Hint</h3>
                <p style={{ color: '#4a5568', lineHeight: '1.6', marginBottom: '1.5rem' }}>{solutionPreview.hint}</p>
              </>
            )}
            {solutionPreview.example && (
              <>
                <h3 style={{ fontSize: '1.1rem', marginBottom: '0.75rem', color: '#2d3748' }}>Example</h3>
                <code style={{ display: 'block', background: '#edf2f7', padding: '0.75rem', borderRadius: '4px', marginBottom: '1.5rem', fontSize: '0.9rem', whiteSpace: 'pre-wrap' }}>
                  {solutionPreview.example}
                </code>
              </>
            )}
            {solutionPreview.explanation && (
              <>
                <h3 style={{ fontSize: '1.1rem', marginBottom: '0.75rem', color: '#2d3748' }}>Explanation</h3>
                <p style={{ color: '#4a5568', lineHeight: '1.6', marginBottom: '1.5rem' }}>{solutionPreview.explanation}</p>
              </>
            )}
            {examples.length > 0 && (
              <>
                <h3 style={{ fontSize: '1.1rem', marginBottom: '0.75rem', color: '#2d3748' }}>Example Payloads</h3>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem', marginBottom: '1.5rem' }}>
                  {examples.map((ex, i) => (
                    <div key={i} style={{ background: '#f7fafc', padding: '1rem', borderRadius: '8px', borderLeft: '4px solid #667eea' }}>
                      {(ex.prompt || ex.payload) && (
                        <>
                          <div style={{ fontWeight: '600', color: '#4a5568', marginBottom: '0.5rem', fontSize: '0.9rem' }}>
                            {ex.payload ? 'Payload:' : 'Prompt:'}
                          </div>
                          <code style={{ display: 'block', background: '#edf2f7', padding: '0.75rem', borderRadius: '4px', marginBottom: '0.75rem', fontSize: '0.9rem', whiteSpace: 'pre-wrap' }}>
                            {ex.prompt || ex.payload}
                          </code>
                        </>
                      )}
                      {ex.explanation && (
                        <div style={{ fontSize: '0.85rem', color: '#718096' }}>
                          <strong>Explanation:</strong> {ex.explanation}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </>
            )}
            {(solutionPreview.hints || []).length > 0 && (
              <>
                <h3 style={{ fontSize: '1.1rem', marginBottom: '0.75rem', color: '#2d3748' }}>Hints</h3>
                <ul style={{ color: '#4a5568', paddingLeft: '1.25rem', marginBottom: '1.5rem' }}>
                  {solutionPreview.hints.map((hint, i) => (
                    <li key={i} style={{ marginBottom: '0.5rem' }}>{hint}</li>
                  ))}
                </ul>
              </>
            )}
            {(solutionPreview.tips || []).length > 0 && (
              <>
                <h3 style={{ fontSize: '1.1rem', marginBottom: '0.75rem', color: '#2d3748' }}>Quick Tips</h3>
                <ul style={{ color: '#4a5568', paddingLeft: '1.25rem' }}>
                  {solutionPreview.tips.map((tip, i) => (
                    <li key={i} style={{ marginBottom: '0.5rem' }}>{tip}</li>
                  ))}
                </ul>
              </>
            )}
          </ModalBody>
          <ModalFooter>
            <ActionButton onClick={() => setSolutionPreview(null)}>Close Preview</ActionButton>
          </ModalFooter>
        </ModalContent>
      </ModalOverlay>
    );
  };

  const renderScViewModal = () => {
    if (!selectedScObjective) return null;
    return (
      <ModalOverlay
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
        onClick={() => setScViewModalOpen(false)}
      >
        <ModalContent
          initial={{ scale: 0.9, opacity: 0 }}
          animate={{ scale: 1, opacity: 1 }}
          exit={{ scale: 0.9, opacity: 0 }}
          onClick={(e) => e.stopPropagation()}
          style={{ maxWidth: '800px' }}
        >
          <ModalHeader>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
              <FiEye style={{ color: '#667eea' }} />
              <h2>{selectedScObjective.title}</h2>
            </div>
            <button onClick={() => setScViewModalOpen(false)}><FiX /></button>
          </ModalHeader>
          <ModalBody>
            <div style={{ display: 'flex', gap: '1rem', marginBottom: '1.5rem' }}>
              <span style={{
                padding: '0.25rem 0.75rem',
                background: '#ebf4ff',
                color: '#4299e1',
                borderRadius: '9999px',
                fontSize: '0.875rem',
                fontWeight: '600'
              }}>
                Difficulty: {selectedScObjective.difficulty}
              </span>
            </div>

            <h3 style={{ fontSize: '1.1rem', marginBottom: '0.75rem', color: '#2d3748' }}>Recommended Approach</h3>
            <p style={{ color: '#4a5568', lineHeight: '1.6', marginBottom: '1.5rem' }}>{selectedScObjective.approach}</p>

            <h3 style={{ fontSize: '1.1rem', marginBottom: '0.75rem', color: '#2d3748' }}>Example Payloads</h3>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem', marginBottom: '1.5rem' }}>
              {selectedScObjective.examples?.map((ex, i) => (
                <div key={i} style={{ background: '#f7fafc', padding: '1rem', borderRadius: '8px', borderLeft: '4px solid #667eea' }}>
                  <div style={{ fontWeight: '600', color: '#4a5568', marginBottom: '0.5rem', fontSize: '0.9rem' }}>Prompt:</div>
                  <code style={{ display: 'block', background: '#edf2f7', padding: '0.75rem', borderRadius: '4px', marginBottom: '0.75rem', fontSize: '0.9rem' }}>
                    {ex.prompt}
                  </code>
                  <div style={{ fontSize: '0.85rem', color: '#718096' }}>
                    <strong>Explanation:</strong> {ex.explanation}
                  </div>
                </div>
              ))}
            </div>

            <h3 style={{ fontSize: '1.1rem', marginBottom: '0.75rem', color: '#2d3748' }}>Quick Tips</h3>
            <ul style={{ color: '#4a5568', paddingLeft: '1.25rem' }}>
              {selectedScObjective.tips?.map((tip, i) => (
                <li key={i} style={{ marginBottom: '0.5rem' }}>{tip}</li>
              ))}
            </ul>
          </ModalBody>
          <ModalFooter>
            <ActionButton onClick={() => setScViewModalOpen(false)}>Close Preview</ActionButton>
          </ModalFooter>
        </ModalContent>
      </ModalOverlay>
    );
  };

  const renderScEditModal = () => {
    if (!scEditFormData) return null;

    const updateExample = (index, field, value) => {
      const newExamples = [...scEditFormData.examples];
      newExamples[index][field] = value;
      setScEditFormData({ ...scEditFormData, examples: newExamples });
    };

    const addExample = () => {
      setScEditFormData({
        ...scEditFormData,
        examples: [...scEditFormData.examples, { prompt: '', explanation: '' }]
      });
    };

    const removeExample = (index) => {
      const newExamples = scEditFormData.examples.filter((_, i) => i !== index);
      setScEditFormData({ ...scEditFormData, examples: newExamples });
    };

    const updateTip = (index, value) => {
      const newTips = [...scEditFormData.tips];
      newTips[index] = value;
      setScEditFormData({ ...scEditFormData, tips: newTips });
    };

    const addTip = () => {
      setScEditFormData({ ...scEditFormData, tips: [...scEditFormData.tips, ''] });
    };

    const removeTip = (index) => {
      const newTips = scEditFormData.tips.filter((_, i) => i !== index);
      setScEditFormData({ ...scEditFormData, tips: newTips });
    };

    return (
      <ModalOverlay
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
      >
        <ModalContent
          initial={{ scale: 0.9, opacity: 0 }}
          animate={{ scale: 1, opacity: 1 }}
          exit={{ scale: 0.9, opacity: 0 }}
          style={{ maxWidth: '900px', maxHeight: '90vh' }}
        >
          <ModalHeader>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
              <FiEdit style={{ color: '#3b82f6' }} />
              <h2>Edit Solution: {scEditFormData.title}</h2>
            </div>
            <button onClick={() => setScEditModalOpen(false)}><FiX /></button>
          </ModalHeader>
          <ModalBody style={{ overflowY: 'auto' }}>
            <FormGroup>
              <label>Objective Title</label>
              <input
                type="text"
                value={scEditFormData.title}
                onChange={e => setScEditFormData({ ...scEditFormData, title: e.target.value })}
              />
            </FormGroup>

            <FormGrid>
              <FormGroup>
                <label>Difficulty</label>
                <select
                  value={scEditFormData.difficulty}
                  onChange={e => setScEditFormData({ ...scEditFormData, difficulty: e.target.value })}
                >
                  <option value="Easy">Easy</option>
                  <option value="Medium">Medium</option>
                  <option value="Hard">Hard</option>
                </select>
              </FormGroup>
            </FormGrid>

            <FormGroup>
              <label>Recommended Approach</label>
              <textarea
                rows={4}
                value={scEditFormData.approach}
                onChange={e => setScEditFormData({ ...scEditFormData, approach: e.target.value })}
              />
            </FormGroup>

            <div style={{ marginBottom: '2rem' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
                <h3 style={{ margin: 0, fontSize: '1.1rem' }}>Example Payloads</h3>
                <ActionButton onClick={addExample} style={{ padding: '0.4rem 0.8rem', fontSize: '0.8rem', background: '#48bb78' }}>
                  <FiPlus /> Add Example
                </ActionButton>
              </div>
              {scEditFormData.examples.map((ex, i) => (
                <div key={i} style={{
                  background: '#f8fafc',
                  padding: '1rem',
                  borderRadius: '8px',
                  border: '1px solid #e2e8f0',
                  marginBottom: '1rem',
                  position: 'relative'
                }}>
                  {scEditFormData.examples.length > 1 && (
                    <button
                      onClick={() => removeExample(i)}
                      style={{ position: 'absolute', top: '0.5rem', right: '0.5rem', background: 'none', border: 'none', color: '#e53e3e', cursor: 'pointer' }}
                    >
                      <FiTrash2 size={16} />
                    </button>
                  )}
                  <FormGroup style={{ marginBottom: '1rem' }}>
                    <label style={{ fontSize: '0.8rem' }}>Prompt</label>
                    <textarea
                      rows={2}
                      value={ex.prompt}
                      onChange={e => updateExample(i, 'prompt', e.target.value)}
                    />
                  </FormGroup>
                  <FormGroup style={{ marginBottom: 0 }}>
                    <label style={{ fontSize: '0.8rem' }}>Explanation</label>
                    <textarea
                      rows={2}
                      value={ex.explanation}
                      onChange={e => updateExample(i, 'explanation', e.target.value)}
                    />
                  </FormGroup>
                </div>
              ))}
            </div>

            <div style={{ marginBottom: '1rem' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
                <h3 style={{ margin: 0, fontSize: '1.1rem' }}>Quick Tips</h3>
                <ActionButton onClick={addTip} style={{ padding: '0.4rem 0.8rem', fontSize: '0.8rem', background: '#48bb78' }}>
                  <FiPlus /> Add Tip
                </ActionButton>
              </div>
              {scEditFormData.tips.map((tip, i) => (
                <div key={i} style={{ display: 'flex', gap: '0.5rem', marginBottom: '0.5rem' }}>
                  <input
                    type="text"
                    value={tip}
                    onChange={e => updateTip(i, e.target.value)}
                    style={{ flex: 1 }}
                  />
                  {scEditFormData.tips.length > 1 && (
                    <button
                      onClick={() => removeTip(i)}
                      style={{ background: 'none', border: 'none', color: '#e53e3e', cursor: 'pointer' }}
                    >
                      <FiTrash2 size={18} />
                    </button>
                  )}
                </div>
              ))}
            </div>
          </ModalBody>
          <ModalFooter>
            <SecondaryButton onClick={() => setScEditModalOpen(false)}>Cancel</SecondaryButton>
            <ActionButton onClick={handleSaveScObjective} style={{ background: '#3b82f6' }}>
              Save Changes
            </ActionButton>
          </ModalFooter>
        </ModalContent>
      </ModalOverlay>
    );
  };

  const renderPiViewModal = () => {
    if (!selectedPiObjective) return null;
    return (
      <ModalOverlay
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
        onClick={() => setPiViewModalOpen(false)}
      >
        <ModalContent
          initial={{ scale: 0.9, opacity: 0 }}
          animate={{ scale: 1, opacity: 1 }}
          exit={{ scale: 0.9, opacity: 0 }}
          onClick={(e) => e.stopPropagation()}
          style={{ maxWidth: '800px' }}
        >
          <ModalHeader>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
              <FiEye style={{ color: '#667eea' }} />
              <h2>{selectedPiObjective.title}</h2>
            </div>
            <button onClick={() => setPiViewModalOpen(false)}><FiX /></button>
          </ModalHeader>
          <ModalBody>
            <div style={{ display: 'flex', gap: '1rem', marginBottom: '1.5rem' }}>
              <span style={{ 
                padding: '0.25rem 0.75rem', 
                background: '#ebf4ff', 
                color: '#4299e1', 
                borderRadius: '9999px',
                fontSize: '0.875rem',
                fontWeight: '600'
              }}>
                Difficulty: {selectedPiObjective.difficulty}
              </span>
            </div>

            <h3 style={{ fontSize: '1.1rem', marginBottom: '0.75rem', color: '#2d3748' }}>Recommended Approach</h3>
            <p style={{ color: '#4a5568', lineHeight: '1.6', marginBottom: '1.5rem' }}>{selectedPiObjective.approach}</p>

            <h3 style={{ fontSize: '1.1rem', marginBottom: '0.75rem', color: '#2d3748' }}>Example Payloads</h3>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem', marginBottom: '1.5rem' }}>
              {selectedPiObjective.examples?.map((ex, i) => (
                <div key={i} style={{ background: '#f7fafc', padding: '1rem', borderRadius: '8px', borderLeft: '4px solid #667eea' }}>
                  <div style={{ fontWeight: '600', color: '#4a5568', marginBottom: '0.5rem', fontSize: '0.9rem' }}>Prompt:</div>
                  <code style={{ display: 'block', background: '#edf2f7', padding: '0.75rem', borderRadius: '4px', marginBottom: '0.75rem', fontSize: '0.9rem' }}>
                    {ex.prompt}
                  </code>
                  <div style={{ fontSize: '0.85rem', color: '#718096' }}>
                    <strong>Explanation:</strong> {ex.explanation}
                  </div>
                </div>
              ))}
            </div>

            <h3 style={{ fontSize: '1.1rem', marginBottom: '0.75rem', color: '#2d3748' }}>Quick Tips</h3>
            <ul style={{ color: '#4a5568', paddingLeft: '1.25rem' }}>
              {selectedPiObjective.tips?.map((tip, i) => (
                <li key={i} style={{ marginBottom: '0.5rem' }}>{tip}</li>
              ))}
            </ul>
          </ModalBody>
          <ModalFooter>
            <ActionButton onClick={() => setPiViewModalOpen(false)}>Close Preview</ActionButton>
          </ModalFooter>
        </ModalContent>
      </ModalOverlay>
    );
  };

  const renderPiEditModal = () => {
    if (!piEditFormData) return null;
    
    const updateExample = (index, field, value) => {
      const newExamples = [...piEditFormData.examples];
      newExamples[index][field] = value;
      setPiEditFormData({ ...piEditFormData, examples: newExamples });
    };

    const addExample = () => {
      setPiEditFormData({ 
        ...piEditFormData, 
        examples: [...piEditFormData.examples, { prompt: '', explanation: '' }] 
      });
    };

    const removeExample = (index) => {
      const newExamples = piEditFormData.examples.filter((_, i) => i !== index);
      setPiEditFormData({ ...piEditFormData, examples: newExamples });
    };

    const updateTip = (index, value) => {
      const newTips = [...piEditFormData.tips];
      newTips[index] = value;
      setPiEditFormData({ ...piEditFormData, tips: newTips });
    };

    const addTip = () => {
      setPiEditFormData({ ...piEditFormData, tips: [...piEditFormData.tips, ''] });
    };

    const removeTip = (index) => {
      const newTips = piEditFormData.tips.filter((_, i) => i !== index);
      setPiEditFormData({ ...piEditFormData, tips: newTips });
    };

    return (
      <ModalOverlay
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
      >
        <ModalContent
          initial={{ scale: 0.9, opacity: 0 }}
          animate={{ scale: 1, opacity: 1 }}
          exit={{ scale: 0.9, opacity: 0 }}
          style={{ maxWidth: '900px', maxHeight: '90vh' }}
        >
          <ModalHeader>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
              <FiEdit style={{ color: '#3b82f6' }} />
              <h2>Edit Solution: {piEditFormData.title}</h2>
            </div>
            <button onClick={() => setPiEditModalOpen(false)}><FiX /></button>
          </ModalHeader>
          <ModalBody style={{ overflowY: 'auto' }}>
            <FormGroup>
              <label>Objective Title</label>
              <input 
                type="text" 
                value={piEditFormData.title} 
                onChange={e => setPiEditFormData({ ...piEditFormData, title: e.target.value })}
              />
            </FormGroup>

            <FormGrid>
              <FormGroup>
                <label>Difficulty</label>
                <select 
                  value={piEditFormData.difficulty} 
                  onChange={e => setPiEditFormData({ ...piEditFormData, difficulty: e.target.value })}
                >
                  <option value="Easy">Easy</option>
                  <option value="Medium">Medium</option>
                  <option value="Hard">Hard</option>
                </select>
              </FormGroup>
            </FormGrid>

            <FormGroup>
              <label>Recommended Approach</label>
              <textarea 
                rows={4}
                value={piEditFormData.approach} 
                onChange={e => setPiEditFormData({ ...piEditFormData, approach: e.target.value })}
              />
            </FormGroup>

            <div style={{ marginBottom: '2rem' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
                <h3 style={{ margin: 0, fontSize: '1.1rem' }}>Example Payloads</h3>
                <ActionButton onClick={addExample} style={{ padding: '0.4rem 0.8rem', fontSize: '0.8rem', background: '#48bb78' }}>
                  <FiPlus /> Add Example
                </ActionButton>
              </div>
              {piEditFormData.examples.map((ex, i) => (
                <div key={i} style={{ 
                  background: '#f8fafc', 
                  padding: '1rem', 
                  borderRadius: '8px', 
                  border: '1px solid #e2e8f0',
                  marginBottom: '1rem',
                  position: 'relative'
                }}>
                  {piEditFormData.examples.length > 1 && (
                    <button 
                      onClick={() => removeExample(i)}
                      style={{ position: 'absolute', top: '0.5rem', right: '0.5rem', background: 'none', border: 'none', color: '#e53e3e', cursor: 'pointer' }}
                    >
                      <FiTrash2 size={16} />
                    </button>
                  )}
                  <FormGroup style={{ marginBottom: '1rem' }}>
                    <label style={{ fontSize: '0.8rem' }}>Prompt</label>
                    <textarea 
                      rows={2}
                      value={ex.prompt} 
                      onChange={e => updateExample(i, 'prompt', e.target.value)}
                    />
                  </FormGroup>
                  <FormGroup style={{ marginBottom: 0 }}>
                    <label style={{ fontSize: '0.8rem' }}>Explanation</label>
                    <textarea 
                      rows={2}
                      value={ex.explanation} 
                      onChange={e => updateExample(i, 'explanation', e.target.value)}
                    />
                  </FormGroup>
                </div>
              ))}
            </div>

            <div style={{ marginBottom: '1rem' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
                <h3 style={{ margin: 0, fontSize: '1.1rem' }}>Quick Tips</h3>
                <ActionButton onClick={addTip} style={{ padding: '0.4rem 0.8rem', fontSize: '0.8rem', background: '#48bb78' }}>
                  <FiPlus /> Add Tip
                </ActionButton>
              </div>
              {piEditFormData.tips.map((tip, i) => (
                <div key={i} style={{ display: 'flex', gap: '0.5rem', marginBottom: '0.5rem' }}>
                  <input 
                    type="text" 
                    value={tip} 
                    onChange={e => updateTip(i, e.target.value)} 
                    style={{ flex: 1 }}
                  />
                  {piEditFormData.tips.length > 1 && (
                    <button 
                      onClick={() => removeTip(i)}
                      style={{ background: 'none', border: 'none', color: '#e53e3e', cursor: 'pointer' }}
                    >
                      <FiTrash2 size={18} />
                    </button>
                  )}
                </div>
              ))}
            </div>
          </ModalBody>
          <ModalFooter>
            <SecondaryButton onClick={() => setPiEditModalOpen(false)}>Cancel</SecondaryButton>
            <ActionButton onClick={handleSavePiObjective} style={{ background: '#3b82f6' }}>
              Save Changes
            </ActionButton>
          </ModalFooter>
        </ModalContent>
      </ModalOverlay>
    );
  };

  const renderStudentDetailsModal = () => {
    if (!selectedStudent) return null;

    const { student, progress, stats, workshopObjectives = {} } = selectedStudent;
    
    return (
      <ModalOverlay
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
        onClick={closeStudentModal}
      >
        <ModalContent
          initial={{ scale: 0.9, opacity: 0 }}
          animate={{ scale: 1, opacity: 1 }}
          exit={{ scale: 0.9, opacity: 0 }}
          onClick={(e) => e.stopPropagation()}
        >
          <ModalHeader>
            <h2>Student Details</h2>
            <button onClick={closeStudentModal}>
              <FiX />
            </button>
          </ModalHeader>
          
          <ModalBody>
            {/* Student Information */}
            <StudentInfoGrid>
              <InfoCard>
                <div className="label">Username</div>
                <div className="value">{student.username}</div>
              </InfoCard>
              <InfoCard>
                <div className="label">Email</div>
                <div className="value">{student.email}</div>
              </InfoCard>
              <InfoCard>
                <div className="label">Full Name</div>
                <div className="value">{student.full_name || 'Not provided'}</div>
              </InfoCard>
              <InfoCard>
                <div className="label">Member Since</div>
                <div className="value">{new Date(student.created_at).toLocaleDateString()}</div>
              </InfoCard>
              <InfoCard>
                <div className="label">Last Login</div>
                <div className="value">{student.last_login ? new Date(student.last_login).toLocaleDateString() : 'Never'}</div>
              </InfoCard>
              <InfoCard>
                <div className="label">Total Score</div>
                <div className="value">{stats.pointsAvailable === false ? '—' : stats.totalScore}</div>
              </InfoCard>
            </StudentInfoGrid>

            {/* Progress Statistics */}
            <div style={{ 
              display: 'grid', 
              gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))', 
              gap: '1rem',
              marginBottom: '2rem'
            }}>
              <div style={{ 
                background: '#e6fffa', 
                padding: '1rem', 
                borderRadius: '8px', 
                border: '2px solid #38b2ac',
                textAlign: 'center'
              }}>
                <div style={{ fontSize: '1.5rem', fontWeight: 'bold', color: '#234e52' }}>
                  {stats.completedChallenges}
                </div>
                <div style={{ fontSize: '0.9rem', color: '#2c7a7b' }}>Completed</div>
              </div>
              <div style={{ 
                background: '#fed7aa', 
                padding: '1rem', 
                borderRadius: '8px', 
                border: '2px solid #ed8936',
                textAlign: 'center'
              }}>
                <div style={{ fontSize: '1.5rem', fontWeight: 'bold', color: '#7b341e' }}>
                  {stats.inProgressChallenges}
                </div>
                <div style={{ fontSize: '0.9rem', color: '#9c4221' }}>In Progress</div>
              </div>
              <div style={{ 
                background: '#f0fff4', 
                padding: '1rem', 
                borderRadius: '8px', 
                border: '2px solid #48bb78',
                textAlign: 'center'
              }}>
                <div style={{ fontSize: '1.5rem', fontWeight: 'bold', color: '#22543d' }}>
                  {stats.pointsAvailable === false ? '—' : `${stats.averageScore}%`}
                </div>
                <div style={{ fontSize: '0.9rem', color: '#276749' }}>Avg Score</div>
              </div>
              <div style={{
                background: '#e3f2fd',
                padding: '1rem',
                borderRadius: '8px',
                border: '2px solid #2196f3',
                textAlign: 'center'
              }}>
                <div style={{ fontSize: '1.5rem', fontWeight: 'bold', color: '#0d47a1' }}>
                  {Math.round(stats.totalTimeSpent / 60)}m
                </div>
                <div style={{ fontSize: '0.9rem', color: '#1565c0' }}>Time Spent</div>
              </div>
              {stats.totalObjectivesCompleted > 0 && (
                <div style={{
                  background: '#f3e8ff',
                  padding: '1rem',
                  borderRadius: '8px',
                  border: '2px solid #9333ea',
                  textAlign: 'center'
                }}>
                  <div style={{ fontSize: '1.5rem', fontWeight: 'bold', color: '#581c87' }}>
                    {stats.totalObjectivesCompleted}
                  </div>
                  <div style={{ fontSize: '0.9rem', color: '#7e22ce' }}>Objectives Done</div>
                </div>
              )}
            </div>

            {/* Challenge Progress */}
            <ProgressSection>
              <h3><FiTrendingUp /> Challenge Progress</h3>
              <ProgressList>
                {progress && progress.length > 0 ? progress.map(item => (
                  <ProgressItem key={item.id} status={item.status}>
                    <div className="header">
                      <h4>{item.challenge_name}</h4>
                      <div className="status">
                        {item.status === 'completed' ? 'Completed' : 
                         item.status === 'in_progress' ? 'In Progress' : 'Not Started'}
                      </div>
                    </div>
                    <div className="details">
                      <span>{stats.pointsAvailable === false
                        ? 'Score: —'
                        : `Score: ${item.score || 0}/${item.challenge_max_score || 100}`}</span>
                      <span>Difficulty: {item.difficulty_level}</span>
                      <span>Category: {item.category}</span>
                    </div>
                  </ProgressItem>
                )) : (
                  <div style={{ 
                    textAlign: 'center', 
                    padding: '2rem', 
                    color: '#718096',
                    background: '#f7fafc',
                    borderRadius: '12px'
                  }}>
                    No challenge progress available
                  </div>
                )}
              </ProgressList>
            </ProgressSection>

            {/* Workshop Objectives Breakdown */}
            {Object.keys(workshopObjectives).length > 0 && (
              <ProgressSection>
                <h3><FiTarget /> Workshop Objectives</h3>
                {Object.entries(workshopObjectives).map(([workshopKey, objectives]) => {
                  const completedCount = objectives.filter(o => o.completed).length;
                  return (
                    <div key={workshopKey} style={{ marginBottom: '1.5rem', border: '1px solid #e2e8f0', borderRadius: '10px', overflow: 'hidden' }}>
                      <div style={{ background: '#f7fafc', padding: '0.75rem 1rem', display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid #e2e8f0' }}>
                        <div>
                          <strong style={{ color: '#1a202c' }}>{workshopKey.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}</strong>
                          <span style={{ marginLeft: '0.75rem', fontSize: '0.85rem', color: completedCount === objectives.length ? '#28a745' : '#667eea', fontWeight: 600 }}>
                            {completedCount}/{objectives.length} objectives
                          </span>
                        </div>
                        <button
                          onClick={async () => {
                            if (!window.confirm(`Reset all objectives for "${workshopKey}" for ${student.username}?`)) return;
                            try {
                              const token = localStorage.getItem('token');
                              await axios.post(`/api/admin/students/${student.id}/workshops/${workshopKey}/reset`, {}, { headers: { 'Authorization': `Bearer ${token}` } });
                              toast.success(`Reset ${workshopKey} for ${student.username}`);
                              handleViewStudent(student.id);
                            } catch (e) {
                              toast.error('Reset failed');
                            }
                          }}
                          style={{ background: '#fff5f5', color: '#e53e3e', border: '1px solid #fc8181', borderRadius: '6px', padding: '0.3rem 0.8rem', fontSize: '0.8rem', cursor: 'pointer', fontWeight: 600 }}
                        >
                          Reset
                        </button>
                      </div>
                      <div style={{ padding: '0.5rem 1rem' }}>
                        {objectives.map(obj => (
                          <div key={obj.objective_id} style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', padding: '0.3rem 0', borderBottom: '1px solid #f7fafc', fontSize: '0.85rem', color: obj.completed ? '#2d6a4f' : '#718096' }}>
                            <span style={{ fontSize: '1rem' }}>{obj.completed ? '✅' : '⬜'}</span>
                            <span style={{ flex: 1 }}>{obj.objective_label || obj.objective_id}</span>
                            {obj.completed && obj.completed_at && (
                              <span style={{ fontSize: '0.75rem', color: '#a0aec0' }}>{new Date(obj.completed_at).toLocaleDateString()}</span>
                            )}
                          </div>
                        ))}
                      </div>
                    </div>
                  );
                })}
              </ProgressSection>
            )}
          </ModalBody>
        </ModalContent>
      </ModalOverlay>
    );
  };

  const renderSecuritySettingsModal = () => (
    <ModalOverlay
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      onClick={() => setSecuritySettingsModalOpen(false)}
    >
      <ModalContent
        initial={{ scale: 0.9, opacity: 0 }}
        animate={{ scale: 1, opacity: 1 }}
        exit={{ scale: 0.9, opacity: 0 }}
        onClick={(e) => e.stopPropagation()}
      >
        <ModalHeader>
          <h2>Security Settings</h2>
          <button onClick={() => setSecuritySettingsModalOpen(false)}>
            <FiX />
          </button>
        </ModalHeader>
        <ModalBody>
          <div style={{ marginBottom: '2rem' }}>
            <p style={{ color: '#718096', marginBottom: '1.5rem' }}>
              Configure platform security options and access controls.
            </p>
            
            {securitySettings && Object.keys(securitySettings).length > 0 ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
                {Object.entries(securitySettings).map(([key, config]) => (
                  <div key={key} style={{ 
                    padding: '1.5rem', 
                    border: '2px solid #e2e8f0', 
                    borderRadius: '12px',
                    background: '#f7fafc'
                  }}>
                    <div style={{ 
                      display: 'flex', 
                      justifyContent: 'space-between', 
                      alignItems: 'center',
                      marginBottom: '0.5rem'
                    }}>
                      <h4 style={{ margin: 0, color: '#1a202c' }}>
                        {key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}
                      </h4>
                      <input
                        type="text"
                        value={config.value}
                        onChange={(e) => setSecuritySettings({
                          ...securitySettings,
                          [key]: { ...config, value: e.target.value }
                        })}
                        style={{
                          padding: '0.5rem',
                          border: '1px solid #d1d5db',
                          borderRadius: '6px',
                          width: '200px'
                        }}
                      />
                    </div>
                    <p style={{ margin: 0, fontSize: '0.875rem', color: '#6b7280' }}>
                      {config.description}
                    </p>
                  </div>
                ))}
                
                <ActionButton 
                  onClick={() => saveSecuritySettings(securitySettings)}
                  style={{ alignSelf: 'flex-end' }}
                >
                  <FiSave /> Save Settings
                </ActionButton>
              </div>
            ) : (
              <div style={{ textAlign: 'center', padding: '2rem', color: '#718096' }}>
                Loading security settings...
              </div>
            )}
          </div>
        </ModalBody>
      </ModalContent>
    </ModalOverlay>
  );

  const renderUserManagementModal = () => (
    <UserManagementOverlay
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      onClick={closeUserManagementModal}
    >
      <UserManagementContent
        role="dialog"
        aria-modal="true"
        aria-labelledby="user-management-title"
        initial={{ scale: 0.9, opacity: 0 }}
        animate={{ scale: 1, opacity: 1 }}
        exit={{ scale: 0.9, opacity: 0 }}
        onClick={(e) => e.stopPropagation()}
      >
        <ModalHeader>
          <h2 id="user-management-title">User Management</h2>
          <button aria-label="Close user management" onClick={closeUserManagementModal}>
            <FiX />
          </button>
        </ModalHeader>
        <UserManagementBody>
          <UserManagementTabs role="tablist" aria-label="User type" onKeyDown={handleManagementTabKeyDown}>
            <UserManagementTab id="user-management-administrators-tab" type="button" role="tab"
              aria-controls="user-management-administrators-panel" tabIndex={userManagementTab === 'administrators' ? 0 : -1}
              aria-selected={userManagementTab === 'administrators'}
              $active={userManagementTab === 'administrators'} onClick={() => setUserManagementTab('administrators')}>
              Administrators
            </UserManagementTab>
            {canManageProgress && <UserManagementTab id="user-management-students-tab" type="button" role="tab"
              aria-controls="user-management-students-panel" tabIndex={userManagementTab === 'students' ? 0 : -1}
              aria-selected={userManagementTab === 'students'}
              $active={userManagementTab === 'students'} onClick={openManagementStudents}>
              Students
            </UserManagementTab>}
          </UserManagementTabs>
          {userManagementTab === 'administrators' && <div id="user-management-administrators-panel" role="tabpanel"
            aria-labelledby="user-management-administrators-tab" style={{ marginBottom: '2rem' }}>
            <h3>Administrators</h3>
            <p style={{ color: '#718096' }}>
              Level 1 can manage permitted teaching tasks. Level 2 is required for administrator grants and protected actions; both levels need explicit permissions.
            </p>
            {canCreateAdministrators && (
              <ActionButton type="button" onClick={stageAdministratorCreate}>
                {createAdministratorOpen ? 'Cancel administrator creation' : 'Add administrator'}
              </ActionButton>
            )}
            {canCreateAdministrators && createAdministratorOpen && (
              <AdministratorForm onSubmit={event => handleCreateAdministrator(event, administratorCreateStage)}>
                <AdministratorFields>
                <AdministratorField>
                <label htmlFor="new-admin-username">Username</label>
                <input id="new-admin-username" required minLength={3} maxLength={50} value={newAdministrator.username}
                  onChange={event => { const value = event.target.value;
                    updateAdministratorCreate(administratorCreateStage, () => ({ username: value })); }} />
                </AdministratorField>
                <AdministratorField>
                <label htmlFor="new-admin-email">Email</label>
                <input id="new-admin-email" type="email" required value={newAdministrator.email}
                  onChange={event => { const value = event.target.value;
                    updateAdministratorCreate(administratorCreateStage, () => ({ email: value })); }} />
                </AdministratorField>
                <AdministratorField>
                <label htmlFor="new-admin-name">Full name</label>
                <input id="new-admin-name" value={newAdministrator.fullName}
                  onChange={event => { const value = event.target.value;
                    updateAdministratorCreate(administratorCreateStage, () => ({ fullName: value })); }} />
                </AdministratorField>
                <AdministratorField>
                <label htmlFor="new-admin-password">Password</label>
                <input id="new-admin-password" type="password" required minLength={8} value={newAdministrator.password}
                  onChange={event => { const value = event.target.value;
                    updateAdministratorCreate(administratorCreateStage, () => ({ password: value })); }} />
                </AdministratorField>
                <AdministratorField>
                <label htmlFor="new-admin-confirm-password">Confirm password</label>
                <input id="new-admin-confirm-password" type="password" required value={newAdministrator.confirmPassword}
                  onChange={event => { const value = event.target.value;
                    updateAdministratorCreate(administratorCreateStage, () => ({ confirmPassword: value })); }} />
                </AdministratorField>
                <AdministratorField>
                <label htmlFor="new-admin-level">Administrator level</label>
                <select id="new-admin-level" value={newAdministrator.adminLevel}
                  onChange={event => { const value = Number(event.target.value);
                    updateAdministratorCreate(administratorCreateStage, () => ({ adminLevel: value })); }}>
                  <option value={1}>Level 1 — instructor</option>
                  <option value={2}>Level 2 — elevated administrator</option>
                </select>
                </AdministratorField>
                </AdministratorFields>
                <AdministratorPermissions>
                  <legend>Permissions</legend>
                  <div>
                  {[
                    ['challenge_management', 'Challenge management'], ['view_analytics', 'View analytics'],
                    ['manage_progress', 'Manage progress'], ['user_management', 'User management'],
                    ['system_config', 'System configuration'], ['send_notifications', 'Send notifications'],
                    ['export_data', 'Export data'], ['system_logs', 'System logs']
                  ].map(([value, label]) => (
                    <AdministratorChoice key={value}>
                      <input type="checkbox" value={value} checked={newAdministrator.permissions.includes(value)}
                        onChange={event => { const checked = event.target.checked;
                          updateAdministratorCreate(administratorCreateStage, current => ({
                            permissions: checked
                              ? current.permissions.includes(value) ? current.permissions : [...current.permissions, value]
                              : current.permissions.filter(permission => permission !== value),
                          })); }} />
                      {label}
                    </AdministratorChoice>
                  ))}
                  </div>
                </AdministratorPermissions>
                {administratorCreateOutcome?.kind === 'unknown' && <p role="alert">
                  The creation outcome could not be confirmed. No account ID was acknowledged.
                  Check the current administrator roster before deciding whether to start a new creation.
                  Do not assume a matching username proves this request committed.
                </p>}
                {administratorCreateOutcome?.kind === 'rejected' && <p role="alert">The server rejected this creation.</p>}
                <AdministratorActions>
                <ActionButton type="submit" disabled={creatingAdministrator || administratorCreateStage?.consumed}>
                  {creatingAdministrator ? 'Creating…' : 'Create administrator'}
                </ActionButton>
                {(administratorCreateOutcome?.kind === 'unknown' || administratorCreateOutcome?.kind === 'rejected') &&
                  <SecondaryButton type="button" onClick={() => closeAdministratorCreate(administratorCreateStage)}>Close</SecondaryButton>}
                </AdministratorActions>
              </AdministratorForm>
            )}
            {canCreateAdministrators && editingAdministrator && (
              <AdministratorForm onSubmit={event => handleUpdateAdministrator(event, administratorEditStage)}>
                <h4>Edit administrator: {adminAccounts.find(account => account.id === editingAdministrator.id)?.username}</h4>
                <AdministratorFields>
                <AdministratorField>
                <label htmlFor="edit-admin-username">Username</label>
                <input id="edit-admin-username" required minLength={3} maxLength={50} value={editingAdministrator.username}
                  onChange={event => { const value = event.target.value;
                    updateAdministratorEdit(administratorEditStage, () => ({ username: value })); }} />
                </AdministratorField>
                <AdministratorField>
                <label htmlFor="edit-admin-email">Email</label>
                <input id="edit-admin-email" type="email" required value={editingAdministrator.email}
                  onChange={event => { const value = event.target.value;
                    updateAdministratorEdit(administratorEditStage, () => ({ email: value })); }} />
                </AdministratorField>
                <AdministratorField>
                <label htmlFor="edit-admin-name">Full name</label>
                <input id="edit-admin-name" value={editingAdministrator.fullName}
                  onChange={event => { const value = event.target.value;
                    updateAdministratorEdit(administratorEditStage, () => ({ fullName: value })); }} />
                </AdministratorField>
                <AdministratorField>
                <label htmlFor="edit-admin-level">Administrator level</label>
                <select id="edit-admin-level" value={editingAdministrator.adminLevel}
                  onChange={event => { const value = Number(event.target.value);
                    updateAdministratorEdit(administratorEditStage, () => ({ adminLevel: value })); }}>
                  <option value={1}>Level 1 — instructor</option>
                  <option value={2}>Level 2 — elevated administrator</option>
                </select>
                </AdministratorField>
                </AdministratorFields>
                <AdministratorPermissions>
                  <legend>Permissions</legend>
                  <div>
                  {[
                    ['challenge_management', 'Challenge management'], ['view_analytics', 'View analytics'],
                    ['manage_progress', 'Manage progress'], ['user_management', 'User management'],
                    ['system_config', 'System configuration'], ['send_notifications', 'Send notifications'],
                    ['export_data', 'Export data'], ['system_logs', 'System logs']
                  ].map(([value, label]) => (
                    <AdministratorChoice key={value}>
                      <input type="checkbox" value={value} checked={editingAdministrator.permissions.includes(value)}
                        onChange={event => { const checked = event.target.checked;
                          updateAdministratorEdit(administratorEditStage, current => ({
                            permissions: checked
                              ? current.permissions.includes(value) ? current.permissions : [...current.permissions, value]
                              : current.permissions.filter(permission => permission !== value),
                          })); }} />
                      {label}
                    </AdministratorChoice>
                  ))}
                  </div>
                </AdministratorPermissions>
                <AdministratorChoice htmlFor="edit-admin-active">
                  <input id="edit-admin-active" type="checkbox" checked={editingAdministrator.isActive}
                    onChange={event => { const checked = event.target.checked;
                      updateAdministratorEdit(administratorEditStage, () => ({ isActive: checked })); }} />
                  Active (reactivate a deactivated account here)
                </AdministratorChoice>
                <p style={{ color: '#718096' }}>The last active level 2 administrator with user management permission cannot be removed. Editing your own account signs you out so your permissions can refresh.</p>
                {administratorEditOutcome?.kind === 'unknown' && <p role="alert">
                  The update outcome could not be confirmed.
                  {administratorEditOutcome.observed
                    ? ` A fresh account read shows ${administratorEditOutcome.observed.username} is currently ${administratorEditOutcome.observed.active ? 'active' : 'inactive'}; this does not prove this update made the change. Permission changes could not be confirmed.`
                    : ' Current account state could not be read.'}
                  {' '}Close this form and start a new edit before any further update.
                </p>}
                {administratorEditOutcome?.kind === 'rejected' && <p role="alert">The server rejected this update: {administratorEditOutcome.message}</p>}
                <AdministratorActions>
                <ActionButton type="submit" disabled={administratorMutationPending || administratorEditStage?.consumed}>
                  {administratorMutationPending ? 'Saving…' : 'Save administrator'}
                </ActionButton>
                <SecondaryButton type="button" disabled={administratorMutationPending}
                  onClick={() => closeAdministratorEdit(administratorEditStage)}>
                  {administratorEditOutcome?.kind === 'unknown' || administratorEditOutcome?.kind === 'rejected' ? 'Close' : 'Cancel'}
                </SecondaryButton>
                </AdministratorActions>
              </AdministratorForm>
            )}
            {adminAccountsLoading && <p role="status">Loading administrators…</p>}
            {adminAccountsError && <div role="alert" style={{ color: '#9b2c2c', marginTop: '1rem' }}>
              {adminAccountsError} <SecondaryButton type="button" onClick={() => loadAdminAccounts()}>Retry</SecondaryButton>
            </div>}
            {!adminAccountsLoading && !adminAccountsError && adminAccounts.length === 0 &&
              <p role="status">No administrators found.</p>}
            {!adminAccountsLoading && !adminAccountsError && adminAccounts.length > 0 && <StudentTable style={{ marginTop: '1rem' }}>
              <table>
                <thead><tr><th>Username</th><th>Email</th><th>Level</th><th>Status</th><th>Actions</th></tr></thead>
                <tbody>
                  {adminAccounts.map(account => <tr key={account.id}>
                    <td>{account.username}</td><td>{account.email}</td>
                    <td>{account.admin_level}</td><td>{account.is_active ? 'Active' : 'Inactive'}</td>
                    <td>
                      {canCreateAdministrators && <>
                        <SecondaryButton type="button" disabled={administratorMutationPending}
                          onClick={() => beginAdministratorEdit(account)}>Edit</SecondaryButton>{' '}
                        {Boolean(account.is_active) && <SecondaryButton type="button"
                          disabled={administratorMutationPending}
                          onClick={() => stageAdministratorDeactivation(account)}>
                          Deactivate
                        </SecondaryButton>}
                      </>}
                    </td>
                  </tr>)}
                </tbody>
              </table>
            </StudentTable>}
            {canCreateAdministrators && deactivatingAdministrator && (
              <div role="dialog" aria-label="Deactivate administrator" style={{ marginTop: '1rem', padding: '1rem', background: '#fff5f5', borderRadius: '8px' }}>
                <h4>Deactivate {deactivatingAdministrator.username}?</h4>
                <p>This removes sign-in access and revokes sessions. The account and its audit and learner evidence are retained. You can reactivate it from Edit. Deactivating your own account signs you out.</p>
                {deactivationOutcome?.kind === 'unknown' && <p role="alert">
                  The request outcome could not be confirmed.
                  {deactivationOutcome.observed
                    ? ` A fresh account read shows this administrator is currently ${deactivationOutcome.observed}; this does not prove this request made the change.`
                    : ' Current account status could not be read.'}
                  {' '}Close this dialog and start a new confirmation before any further change.
                </p>}
                {deactivationOutcome?.kind === 'rejected' && <p role="alert">The server rejected deactivation: {deactivationOutcome.message}</p>}
                {!deactivatingAdministrator.consumed && <ActionButton type="button" variant="danger" disabled={administratorMutationPending}
                  onClick={() => handleDeactivateAdministrator(deactivatingAdministrator)}>
                  {administratorMutationPending ? 'Deactivating…' : 'Confirm deactivation'}
                </ActionButton>}{' '}
                <SecondaryButton type="button" disabled={administratorMutationPending}
                  onClick={() => closeAdministratorDeactivation(deactivatingAdministrator)}>
                  {deactivationOutcome?.kind === 'unknown' || deactivationOutcome?.kind === 'rejected' ? 'Close' : 'Cancel'}
                </SecondaryButton>
              </div>
            )}
          </div>}
          {canManageProgress && userManagementTab === 'students' && (
          <div id="user-management-students-panel" role="tabpanel" aria-labelledby="user-management-students-tab"
            style={{ marginBottom: '2rem' }}>
            <h3>Students</h3>
            <p style={{ color: '#718096' }}>View and lock accounts here. The Students page has create, edit, and deletion controls.</p>
            <ActionButton type="button" onClick={() => { closeUserManagementModal(); navigate('/admin/students'); }}>
              Manage students
            </ActionButton>
            {managementStudentsLoading && <p role="status">Loading students…</p>}
            {managementStudentsError && <div role="alert" style={{ color: '#9b2c2c' }}>
              {managementStudentsError} <SecondaryButton type="button" onClick={openManagementStudents}>Retry</SecondaryButton>
            </div>}
            {!managementStudentsLoading && !managementStudentsError && students.length === 0 &&
              <p role="status">No students found.</p>}
            {!managementStudentsLoading && !managementStudentsError && students.length > 0 && <StudentTable>
              <table>
                <thead>
                  <tr>
                    <th>Username</th>
                    <th>Email</th>
                    <th>Role</th>
                    <th>Status</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {students.map(student => (
                    <tr key={student.id}>
                      <td>{student.username}</td>
                      <td>{student.email}</td>
                      <td>{student.role}</td>
                      <td>
                        <span style={{
                          padding: '0.25rem 0.75rem',
                          borderRadius: '20px',
                          fontSize: '0.875rem',
                          background: student.is_active ? '#c6f6d5' : '#fed7d7',
                          color: student.is_active ? '#276749' : '#9b2c2c'
                        }}>
                          {student.is_active ? 'Active' : 'Inactive'}
                        </span>
                      </td>
                      <td>
                        <ActionButton 
                          onClick={() => handleViewStudent(student.id)}
                          style={{ marginRight: '0.5rem' }}
                        >
                          <FiEye /> View
                        </ActionButton>
                        <ActionButton
                          variant="danger"
                          onClick={() => lockUser(student.id, student.username)}
                          title="Lock this account — blocks login and shows in Locked Users"
                        >
                          <FiLock /> Lock
                        </ActionButton>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </StudentTable>}
          </div>
          )}
        </UserManagementBody>
      </UserManagementContent>
    </UserManagementOverlay>
  );

  const renderSystemLogsModal = () => (
    <ModalOverlay
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      onClick={() => setSystemLogsModalOpen(false)}
    >
      <ModalContent
        initial={{ scale: 0.9, opacity: 0 }}
        animate={{ scale: 1, opacity: 1 }}
        exit={{ scale: 0.9, opacity: 0 }}
        onClick={(e) => e.stopPropagation()}
        style={{ maxWidth: '1000px' }}
      >
        <ModalHeader>
          <h2>System Activity Logs</h2>
          <button onClick={() => setSystemLogsModalOpen(false)}>
            <FiX />
          </button>
        </ModalHeader>
        <ModalBody>
          <div style={{ marginBottom: '1rem' }}>
            <p style={{ color: '#718096', marginBottom: '1.5rem' }}>
              Recent system activities and security events.
            </p>
            
            {systemLogs.length > 0 ? (
              <div style={{ maxHeight: '400px', overflowY: 'auto' }}>
                {systemLogs.map((log, index) => {
                  const getLogColor = (actionType, success) => {
                    if (actionType.includes('login')) return success ? '#48bb78' : '#e53e3e';
                    if (actionType.includes('admin')) return '#9f7aea';
                    if (actionType.includes('challenge')) return '#4299e1';
                    return '#718096';
                  };
                  
                  return (
                    <div key={log.id || index} style={{
                      padding: '1rem',
                      margin: '0.5rem 0',
                      background: 'white',
                      border: '1px solid #e2e8f0',
                      borderRadius: '8px',
                      borderLeft: `4px solid ${getLogColor(log.action_type, log.success)}`
                    }}>
                      <div style={{ 
                        display: 'flex', 
                        justifyContent: 'space-between', 
                        alignItems: 'flex-start',
                        marginBottom: '0.5rem'
                      }}>
                        <div>
                          <strong style={{ color: '#1a202c' }}>
                            {log.action_description || log.action_type}
                          </strong>
                          <div style={{ fontSize: '0.875rem', color: '#718096' }}>
                            User: {log.username || 'System'} • Type: {log.action_type}
                          </div>
                        </div>
                        <div style={{ fontSize: '0.875rem', color: '#718096' }}>
                          {new Date(log.timestamp).toLocaleString()}
                        </div>
                      </div>
                      {log.ip_address && (
                        <div style={{ fontSize: '0.875rem', color: '#718096' }}>
                          IP: {log.ip_address}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            ) : (
              <div style={{ textAlign: 'center', padding: '2rem', color: '#718096' }}>
                No system logs available
              </div>
            )}
          </div>
        </ModalBody>
      </ModalContent>
    </ModalOverlay>
  );

  const renderChangePasswordModal = () => {
    if (!selfPasswordStage) return null;
    const stage = selfPasswordStage;
    return (
      <ModalOverlay
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
        onClick={() => closeSelfPassword(stage)}
      >
        <ModalContent
          initial={{ scale: 0.9, opacity: 0 }}
          animate={{ scale: 1, opacity: 1 }}
          exit={{ scale: 0.9, opacity: 0 }}
          onClick={(e) => e.stopPropagation()}
          style={{ maxWidth: '500px' }}
        >
          <ModalHeader>
            <h2>Change Password</h2>
            <button type="button" aria-label="Close own password change" onClick={() => closeSelfPassword(stage)}>
              <FiX />
            </button>
          </ModalHeader>
          <ModalBody>
            <form onSubmit={event => handlePasswordSubmit(event, stage)}>
              <p>Changing your password revokes your current sessions. You will need to sign in again.</p>
              <div style={{ marginBottom: '1.5rem' }}>
                <label style={{ 
                  display: 'block', 
                  marginBottom: '0.5rem', 
                  fontWeight: '500',
                  color: '#374151' 
                }}>
                  Current Password
                </label>
                <input
                  type="password"
                  value={passwords.currentPassword}
                  onChange={(e) => updateSelfPassword(stage, { currentPassword: e.target.value })}
                  style={{
                    width: '100%',
                    padding: '0.75rem',
                    border: '2px solid #d1d5db',
                    borderRadius: '8px',
                    fontSize: '1rem'
                  }}
                  required
                />
              </div>
              
              <div style={{ marginBottom: '1.5rem' }}>
                <label style={{ 
                  display: 'block', 
                  marginBottom: '0.5rem', 
                  fontWeight: '500',
                  color: '#374151' 
                }}>
                  New Password
                </label>
                <input
                  type="password"
                  value={passwords.newPassword}
                  onChange={(e) => updateSelfPassword(stage, { newPassword: e.target.value })}
                  style={{
                    width: '100%',
                    padding: '0.75rem',
                    border: '2px solid #d1d5db',
                    borderRadius: '8px',
                    fontSize: '1rem'
                  }}
                  required
                  minLength="8"
                />
              </div>
              
              <div style={{ marginBottom: '2rem' }}>
                <label style={{ 
                  display: 'block', 
                  marginBottom: '0.5rem', 
                  fontWeight: '500',
                  color: '#374151' 
                }}>
                  Confirm New Password
                </label>
                <input
                  type="password"
                  value={passwords.confirmPassword}
                  onChange={(e) => updateSelfPassword(stage, { confirmPassword: e.target.value })}
                  style={{
                    width: '100%',
                    padding: '0.75rem',
                    border: '2px solid #d1d5db',
                    borderRadius: '8px',
                    fontSize: '1rem'
                  }}
                  required
                  minLength="8"
                />
              </div>
              
              {selfPasswordOutcome?.kind === 'unknown' && <p role="alert">
                The password-change outcome could not be confirmed. Your sessions may have been revoked.
                No automatic retry or credential check was made. Sign in again or contact an administrator before another change.
              </p>}
              {selfPasswordOutcome?.kind === 'rejected' && <p role="alert">The password change was rejected.</p>}
              <div style={{ display: 'flex', gap: '1rem', justifyContent: 'flex-end' }}>
                <ActionButton 
                  type="button"
                  onClick={() => closeSelfPassword(stage)}
                  disabled={selfPasswordPending}
                  style={{ background: '#6b7280' }}
                >
                  {selfPasswordOutcome?.kind === 'unknown' || selfPasswordOutcome?.kind === 'rejected' ? 'Close' : 'Cancel'}
                </ActionButton>
                <ActionButton type="submit" disabled={selfPasswordPending || stage.consumed}>
                  <FiSave /> Change Password
                </ActionButton>
              </div>
            </form>
          </ModalBody>
        </ModalContent>
      </ModalOverlay>
    );
  };

  const renderSolutionDetailsModal = () => {
    if (!selectedSolution) return null;
    const examples = Array.isArray(selectedSolution.examples) ? selectedSolution.examples : [];

    return (
      <ModalOverlay
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
        onClick={() => setSolutionModalOpen(false)}
      >
        <ModalContent
          initial={{ scale: 0.9, opacity: 0 }}
          animate={{ scale: 1, opacity: 1 }}
          exit={{ scale: 0.9, opacity: 0 }}
          onClick={(e) => e.stopPropagation()}
          style={{ maxWidth: '900px' }}
        >
          <ModalHeader>
            <h2>Solution Details</h2>
            <button onClick={() => setSolutionModalOpen(false)}>
              <FiX />
            </button>
          </ModalHeader>
          
          <ModalBody>
            <div style={{ marginBottom: '2rem' }}>
              <div style={{ 
                display: 'grid', 
                gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', 
                gap: '1rem',
                marginBottom: '2rem'
              }}>
                <InfoCard>
                  <div className="label">Challenge Key</div>
                  <div className="value">{selectedSolution.challengeKey}</div>
                </InfoCard>
                <InfoCard>
                  <div className="label">Difficulty</div>
                  <div className="value">{selectedSolution.difficultyLevel || 'Not set'}</div>
                </InfoCard>
                <InfoCard>
                  <div className="label">Estimated Time</div>
                  <div className="value">{selectedSolution.estimatedTime || 'Not set'}</div>
                </InfoCard>
                <InfoCard>
                  <div className="label">Visibility</div>
                  <div className="value">
                    <span style={{
                      color: selectedSolution.isPublic ? '#48bb78' : '#e53e3e',
                      fontWeight: '600'
                    }}>
                      {selectedSolution.isPublic ? 'Public' : 'Private'}
                    </span>
                  </div>
                </InfoCard>
              </div>

              {selectedSolution.description && (
                <div style={{ marginBottom: '2rem' }}>
                  <h3 style={{ color: '#1a202c', marginBottom: '1rem' }}>Description</h3>
                  <div style={{ 
                    background: '#f7fafc',
                    padding: '1.5rem',
                    borderRadius: '8px',
                    border: '1px solid #e2e8f0'
                  }}>
                    {selectedSolution.description}
                  </div>
                </div>
              )}

              {selectedSolution.steps && selectedSolution.steps.length > 0 && (
                <div style={{ marginBottom: '2rem' }}>
                  <h3 style={{ color: '#1a202c', marginBottom: '1rem' }}>Solution Steps</h3>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                    {selectedSolution.steps.map((step, index) => (
                      <div key={index} style={{
                        display: 'flex',
                        gap: '1rem',
                        padding: '1rem',
                        background: '#f7fafc',
                        borderRadius: '8px',
                        border: '1px solid #e2e8f0'
                      }}>
                        <div style={{
                          width: '2rem',
                          height: '2rem',
                          background: '#667eea',
                          color: 'white',
                          borderRadius: '50%',
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'center',
                          fontWeight: 'bold',
                          flexShrink: 0
                        }}>
                          {index + 1}
                        </div>
                        <div style={{ flex: 1 }}>
                          {typeof step === 'string' ? step : step.description || 'No description'}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {examples.length > 0 && (
                <div style={{ marginBottom: '2rem' }}>
                  <h3 style={{ color: '#1a202c', marginBottom: '1rem' }}>Examples</h3>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                    {examples.map((example, index) => {
                      if (typeof example === 'string') {
                        return <div key={index} style={{ background: '#f7fafc', padding: '1rem', borderRadius: '8px', border: '1px solid #e2e8f0' }}>{example}</div>;
                      }
                      const fields = ['prompt', 'payload', 'action'].filter(field => typeof example?.[field] === 'string' && example[field].trim());
                      return (
                        <div key={index} style={{ background: '#f7fafc', padding: '1rem', borderRadius: '8px', border: '1px solid #e2e8f0' }}>
                          {fields.map(field => (
                            <div key={field} style={{ marginBottom: '0.5rem' }}>
                              <strong style={{ textTransform: 'capitalize' }}>{field}</strong>
                              <div>{example[field]}</div>
                            </div>
                          ))}
                          {typeof example?.explanation === 'string' && example.explanation.trim() && (
                            <div><strong>Explanation</strong><div>{example.explanation}</div></div>
                          )}
                          {!fields.length && !(typeof example?.explanation === 'string' && example.explanation.trim()) && (
                            <div>{JSON.stringify(example)}</div>
                          )}
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}

              {selectedSolution.code && (
                <div style={{ marginBottom: '2rem' }}>
                  <h3 style={{ color: '#1a202c', marginBottom: '1rem' }}>Code Example</h3>
                  <pre style={{
                    background: '#1a202c',
                    color: '#f7fafc',
                    padding: '1.5rem',
                    borderRadius: '8px',
                    fontSize: '0.875rem',
                    overflow: 'auto',
                    margin: 0
                  }}>
                    <code>{selectedSolution.code}</code>
                  </pre>
                </div>
              )}

              {selectedSolution.explanation && (
                <div style={{ marginBottom: '2rem' }}>
                  <h3 style={{ color: '#1a202c', marginBottom: '1rem' }}>Explanation</h3>
                  <div style={{ 
                    background: '#f0fff4',
                    padding: '1.5rem',
                    borderRadius: '8px',
                    border: '2px solid #48bb78'
                  }}>
                    {selectedSolution.explanation}
                  </div>
                </div>
              )}

              {selectedSolution.references && selectedSolution.references.length > 0 && (
                <div style={{ marginBottom: '2rem' }}>
                  <h3 style={{ color: '#1a202c', marginBottom: '1rem' }}>References</h3>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                    {selectedSolution.references.map((ref, index) => (
                      <a key={index} 
                         href={ref} 
                         target="_blank" 
                         rel="noopener noreferrer"
                         style={{
                           color: '#667eea',
                           textDecoration: 'none',
                           padding: '0.5rem',
                           background: '#f7fafc',
                           borderRadius: '4px',
                           border: '1px solid #e2e8f0'
                         }}
                      >
                        {ref}
                      </a>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </ModalBody>
        </ModalContent>
      </ModalOverlay>
    );
  };

  const renderCreateStudentModal = () => {
    if (!studentCreateStage) return null;
    const stage = studentCreateStage;
    const handleSubmit = (e) => {
      void handleCreateStudent(e, stage);
    };

    return (
      <ModalOverlay
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
        onClick={() => closeStudentCreate(stage)}
      >
        <ModalContent
          initial={{ scale: 0.9, opacity: 0 }}
          animate={{ scale: 1, opacity: 1 }}
          exit={{ scale: 0.9, opacity: 0 }}
          onClick={(e) => e.stopPropagation()}
          style={{ maxWidth: '600px' }}
        >
          <ModalHeader>
            <h2>Create New Student</h2>
            <button type="button" aria-label="Close student creation" onClick={() => closeStudentCreate(stage)}>
              <FiX />
            </button>
          </ModalHeader>
          
          <ModalBody>
            <form onSubmit={handleSubmit}>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem', marginBottom: '1.5rem' }}>
                <div>
                  <label style={{ display: 'block', marginBottom: '0.5rem', fontWeight: '500', color: '#374151' }}>
                    Username *
                  </label>
                  <input
                    type="text"
                    value={newStudent.username}
                    onChange={(e) => updateStudentCreate(stage, { username: e.target.value })}
                    required
                    style={{
                      width: '100%',
                      padding: '0.75rem',
                      border: '2px solid #e2e8f0',
                      borderRadius: '8px',
                      fontSize: '1rem',
                      transition: 'border-color 0.2s',
                      outline: 'none'
                    }}
                    placeholder="Enter username"
                  />
                </div>
                
                <div>
                  <label style={{ display: 'block', marginBottom: '0.5rem', fontWeight: '500', color: '#374151' }}>
                    Email *
                  </label>
                  <input
                    type="email"
                    value={newStudent.email}
                    onChange={(e) => updateStudentCreate(stage, { email: e.target.value })}
                    required
                    style={{
                      width: '100%',
                      padding: '0.75rem',
                      border: '2px solid #e2e8f0',
                      borderRadius: '8px',
                      fontSize: '1rem',
                      transition: 'border-color 0.2s',
                      outline: 'none'
                    }}
                    placeholder="Enter email"
                  />
                </div>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem', marginBottom: '1.5rem' }}>
                <div>
                  <label style={{ display: 'block', marginBottom: '0.5rem', fontWeight: '500', color: '#374151' }}>
                    Password *
                  </label>
                  <input
                    type="password"
                    value={newStudent.password}
                    onChange={(e) => updateStudentCreate(stage, { password: e.target.value })}
                    required
                    style={{
                      width: '100%',
                      padding: '0.75rem',
                      border: '2px solid #e2e8f0',
                      borderRadius: '8px',
                      fontSize: '1rem',
                      transition: 'border-color 0.2s',
                      outline: 'none'
                    }}
                    placeholder="Enter password"
                  />
                </div>
                
                <div>
                  <label style={{ display: 'block', marginBottom: '0.5rem', fontWeight: '500', color: '#374151' }}>
                    Confirm Password *
                  </label>
                  <input
                    type="password"
                    value={newStudent.confirmPassword}
                    onChange={(e) => updateStudentCreate(stage, { confirmPassword: e.target.value })}
                    required
                    style={{
                      width: '100%',
                      padding: '0.75rem',
                      border: '2px solid #e2e8f0',
                      borderRadius: '8px',
                      fontSize: '1rem',
                      transition: 'border-color 0.2s',
                      outline: 'none'
                    }}
                    placeholder="Confirm password"
                  />
                </div>
              </div>

              <div style={{ marginBottom: '1.5rem' }}>
                <label style={{ display: 'block', marginBottom: '0.5rem', fontWeight: '500', color: '#374151' }}>
                  Full Name
                </label>
                <input
                  type="text"
                  value={newStudent.full_name}
                  onChange={(e) => updateStudentCreate(stage, { full_name: e.target.value })}
                  style={{
                    width: '100%',
                    padding: '0.75rem',
                    border: '2px solid #e2e8f0',
                    borderRadius: '8px',
                    fontSize: '1rem',
                    transition: 'border-color 0.2s',
                    outline: 'none'
                  }}
                  placeholder="Enter full name"
                />
              </div>

              <div style={{ marginBottom: '1.5rem' }}>
                <label style={{ display: 'block', marginBottom: '0.5rem', fontWeight: '500', color: '#374151' }}>
                  Role
                </label>
                <select
                  value={newStudent.role}
                  onChange={(e) => updateStudentCreate(stage, { role: e.target.value })}
                  style={{
                    width: '100%',
                    padding: '0.75rem',
                    border: '2px solid #e2e8f0',
                    borderRadius: '8px',
                    fontSize: '1rem',
                    backgroundColor: 'white',
                    outline: 'none'
                  }}
                >
                  <option value="student">Student</option>
                </select>
              </div>

              {studentCreateOutcome?.kind === 'unknown' && <p role="alert">
                Student creation could not be confirmed. No account ID was acknowledged. A matching name is not proof
                that this request succeeded. No automatic retry was made; inspect the roster before acting again.
              </p>}
              {studentCreateOutcome?.kind === 'rejected' && <p role="alert">Student creation was rejected.</p>}
              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '1rem', marginTop: '2rem' }}>
                <button
                  type="button"
                  onClick={() => closeStudentCreate(stage)}
                  disabled={studentAccountMutationPending}
                  style={{
                    padding: '0.75rem 1.5rem',
                    border: '2px solid #e2e8f0',
                    borderRadius: '8px',
                    background: 'white',
                    color: '#374151',
                    fontWeight: '500',
                    cursor: 'pointer',
                    transition: 'all 0.2s'
                  }}
                >
                  {studentCreateOutcome?.kind === 'unknown' || studentCreateOutcome?.kind === 'rejected' ? 'Close' : 'Cancel'}
                </button>
                <button
                  type="submit"
                  disabled={studentAccountMutationPending || stage.consumed}
                  style={{
                    padding: '0.75rem 1.5rem',
                    border: 'none',
                    borderRadius: '8px',
                    background: '#4f46e5',
                    color: 'white',
                    fontWeight: '500',
                    cursor: 'pointer',
                    transition: 'all 0.2s'
                  }}
                >
                  Create Student
                </button>
              </div>
            </form>
          </ModalBody>
        </ModalContent>
      </ModalOverlay>
    );
  };

  const renderEditStudentModal = () => {
    if (!studentToEdit || !studentEditStage) return null;
    const stage = studentEditStage;

    const handleSubmit = (e) => {
      e.preventDefault();
      void updateStudent(stage);
    };

    return (
      <ModalOverlay
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
        onClick={() => closeStudentEdit(stage)}
      >
        <ModalContent
          initial={{ scale: 0.9, opacity: 0 }}
          animate={{ scale: 1, opacity: 1 }}
          exit={{ scale: 0.9, opacity: 0 }}
          onClick={(e) => e.stopPropagation()}
          style={{ maxWidth: '600px' }}
        >
          <ModalHeader>
            <h2>Edit Student Profile</h2>
            <button type="button" aria-label="Close student edit" onClick={() => closeStudentEdit(stage)}>
              <FiX />
            </button>
          </ModalHeader>
          
          <ModalBody>
            <form onSubmit={handleSubmit}>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem', marginBottom: '1.5rem' }}>
                <div>
                  <label style={{ display: 'block', marginBottom: '0.5rem', fontWeight: '500', color: '#374151' }}>
                    Username *
                  </label>
                  <input
                    type="text"
                    value={editFormData.username}
                    onChange={(e) => updateStudentEdit(stage, { username: e.target.value })}
                    style={{
                      width: '100%',
                      padding: '0.75rem',
                      border: '2px solid #d1d5db',
                      borderRadius: '8px',
                      fontSize: '1rem'
                    }}
                    required
                  />
                </div>
                
                <div>
                  <label style={{ display: 'block', marginBottom: '0.5rem', fontWeight: '500', color: '#374151' }}>
                    Email *
                  </label>
                  <input
                    type="email"
                    value={editFormData.email}
                    onChange={(e) => updateStudentEdit(stage, { email: e.target.value })}
                    style={{
                      width: '100%',
                      padding: '0.75rem',
                      border: '2px solid #d1d5db',
                      borderRadius: '8px',
                      fontSize: '1rem'
                    }}
                    required
                  />
                </div>
              </div>

              <div style={{ marginBottom: '1.5rem' }}>
                <label style={{ display: 'block', marginBottom: '0.5rem', fontWeight: '500', color: '#374151' }}>
                  Full Name
                </label>
                <input
                  type="text"
                  value={editFormData.full_name}
                  onChange={(e) => updateStudentEdit(stage, { full_name: e.target.value })}
                  style={{
                    width: '100%',
                    padding: '0.75rem',
                    border: '2px solid #d1d5db',
                    borderRadius: '8px',
                    fontSize: '1rem'
                  }}
                />
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem', marginBottom: '1.5rem' }}>
                <div>
                  <label style={{ display: 'block', marginBottom: '0.5rem', fontWeight: '500', color: '#374151' }}>
                    Role
                  </label>
                  <select
                    value={editFormData.role}
                    onChange={(e) => updateStudentEdit(stage, { role: e.target.value })}
                    style={{
                      width: '100%',
                      padding: '0.75rem',
                      border: '2px solid #d1d5db',
                      borderRadius: '8px',
                      fontSize: '1rem'
                    }}
                  >
                    <option value="student">Student</option>
                  </select>
                </div>

                <div style={{ display: 'flex', alignItems: 'center', paddingTop: '2rem' }}>
                  <input
                    type="checkbox"
                    id="is_active"
                    checked={editFormData.is_active}
                    onChange={(e) => updateStudentEdit(stage, { is_active: e.target.checked })}
                    style={{ marginRight: '0.5rem' }}
                  />
                  <label htmlFor="is_active" style={{ fontWeight: '500', color: '#374151' }}>
                    Active Account
                  </label>
                </div>
              </div>
              {!editFormData.is_active && <p>
                Deactivating this student revokes active sessions. Reactivating later permits a fresh sign-in;
                it does not restore revoked sessions.
              </p>}

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem', marginBottom: '2rem' }}>
                <div>
                  <label style={{ display: 'block', marginBottom: '0.5rem', fontWeight: '500', color: '#374151' }}>
                    Department
                  </label>
                  <input
                    type="text"
                    value={editFormData.department}
                    onChange={(e) => updateStudentEdit(stage, { department: e.target.value })}
                    style={{
                      width: '100%',
                      padding: '0.75rem',
                      border: '2px solid #d1d5db',
                      borderRadius: '8px',
                      fontSize: '1rem'
                    }}
                  />
                </div>

                <div>
                  <label style={{ display: 'block', marginBottom: '0.5rem', fontWeight: '500', color: '#374151' }}>
                    Phone
                  </label>
                  <input
                    type="tel"
                    value={editFormData.phone}
                    onChange={(e) => updateStudentEdit(stage, { phone: e.target.value })}
                    style={{
                      width: '100%',
                      padding: '0.75rem',
                      border: '2px solid #d1d5db',
                      borderRadius: '8px',
                      fontSize: '1rem'
                    }}
                  />
                </div>
              </div>
              
              {studentEditOutcome?.kind === 'unknown' && <p role="alert">
                Student update could not be confirmed. The current account state is not proof this request succeeded.
                No automatic retry was made; review the student before starting a new update.
              </p>}
              {studentEditOutcome?.kind === 'rejected' && <p role="alert">Student update was rejected.</p>}
              <div style={{ display: 'flex', gap: '1rem', justifyContent: 'flex-end' }}>
                <ActionButton 
                  type="button"
                  onClick={() => closeStudentEdit(stage)}
                  disabled={studentAccountMutationPending}
                  style={{ background: '#6b7280' }}
                >
                  {studentEditOutcome?.kind === 'unknown' || studentEditOutcome?.kind === 'rejected' ? 'Close' : 'Cancel'}
                </ActionButton>
                <ActionButton type="submit" disabled={studentAccountMutationPending || stage.consumed}>
                  <FiSave /> Update Student
                </ActionButton>
              </div>
            </form>
          </ModalBody>
        </ModalContent>
      </ModalOverlay>
    );
  };

  const renderDeleteStudentModal = () => {
    if (!studentToDelete) return null;
    const stagedFromDialog = stagedStudentDeletionRef.current;

    return (
      <ModalOverlay
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
        onClick={closeDeleteStudentModal}
      >
        <ModalContent
          initial={{ scale: 0.9, opacity: 0 }}
          animate={{ scale: 1, opacity: 1 }}
          exit={{ scale: 0.9, opacity: 0 }}
          onClick={(e) => e.stopPropagation()}
          style={{ maxWidth: '500px' }}
        >
          <ModalHeader>
            <h2>Delete Student</h2>
            <button onClick={closeDeleteStudentModal}>
              <FiX />
            </button>
          </ModalHeader>
          
          <ModalBody>
            <div style={{ marginBottom: '2rem' }}>
              <div style={{ 
                background: '#fee2e2',
                border: '2px solid #ef4444',
                borderRadius: '8px',
                padding: '1rem',
                marginBottom: '1.5rem'
              }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.5rem' }}>
                  <FiAlertTriangle style={{ color: '#ef4444', fontSize: '1.2rem' }} />
                  <strong style={{ color: '#dc2626' }}>Warning: This action cannot be undone</strong>
                </div>
                <p style={{ margin: 0, color: '#7f1d1d', fontSize: '0.9rem' }}>
                  Deleting this student deactivates and anonymizes the account, removes workshop content,
                  and retains redacted assessment and audit records.
                </p>
              </div>

              <div style={{ 
                background: '#f9fafb',
                padding: '1rem',
                borderRadius: '8px',
                border: '1px solid #e5e7eb'
              }}>
                <h4 style={{ margin: '0 0 0.5rem 0', color: '#374151' }}>Student Information:</h4>
                <p style={{ margin: '0.25rem 0' }}>
                  <strong>Username:</strong> {studentToDelete.username}
                </p>
                <p style={{ margin: '0.25rem 0' }}>
                  <strong>Email:</strong> {studentToDelete.email}
                </p>
                <p style={{ margin: '0.25rem 0' }}>
                  <strong>Full Name:</strong> {studentToDelete.full_name || 'Not provided'}
                </p>
              </div>

              <p style={{ marginTop: '1rem', color: '#6b7280' }}>
                Type <strong>DELETE</strong> to confirm deletion:
              </p>
              <input
                type="text"
                placeholder="Type DELETE to confirm"
                id="delete-confirmation"
                style={{
                  width: '100%',
                  padding: '0.75rem',
                  border: '2px solid #d1d5db',
                  borderRadius: '8px',
                  fontSize: '1rem',
                  marginBottom: '1.5rem'
                }}
              />
            </div>
            
            <div style={{ display: 'flex', gap: '1rem', justifyContent: 'flex-end' }}>
              <ActionButton 
                type="button"
                onClick={closeDeleteStudentModal}
                style={{ background: '#6b7280' }}
              >
                Cancel
              </ActionButton>
              <ActionButton 
                variant="danger"
                disabled={!canDeleteStudents || studentDeletionPending}
                title={deleteStudentPermissionTitle}
                onClick={event => {
                  if (!canDeleteStudents) {
                    toast.error(deleteStudentPermissionTitle);
                    return;
                  }
                  const input = event.currentTarget.parentElement?.parentElement
                    ?.querySelector('#delete-confirmation');
                  if (input?.value === 'DELETE') {
                    deleteStudent(stagedFromDialog);
                  } else {
                    toast.error('Please type DELETE to confirm');
                  }
                }}
              >
                <FiTrash2 /> Delete Student
              </ActionButton>
            </div>
          </ModalBody>
        </ModalContent>
      </ModalOverlay>
    );
  };

  const renderChangeStudentPasswordModal = () => {
    if (!studentForPasswordChange || !studentPasswordStage) return null;
    const stage = studentPasswordStage;

    const handleSubmit = (e) => {
      e.preventDefault();
      void changeStudentPassword(stage);
    };

    return (
      <ModalOverlay
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
        onClick={() => closeStudentPassword(stage)}
      >
        <ModalContent
          initial={{ scale: 0.9, opacity: 0 }}
          animate={{ scale: 1, opacity: 1 }}
          exit={{ scale: 0.9, opacity: 0 }}
          onClick={(e) => e.stopPropagation()}
          style={{ maxWidth: '500px' }}
        >
          <ModalHeader>
            <h2>Change Student Password</h2>
            <button type="button" onClick={() => closeStudentPassword(stage)} aria-label="Close student password change">
              <FiX />
            </button>
          </ModalHeader>
          
          <ModalBody>
            <div style={{ 
              background: '#f0f9ff',
              padding: '1rem',
              borderRadius: '8px',
              border: '2px solid #3b82f6',
              marginBottom: '1.5rem'
            }}>
              <p style={{ margin: 0, color: '#1e40af' }}>
                <strong>Student:</strong> {studentForPasswordChange.username} ({studentForPasswordChange.email})
              </p>
              <p style={{ margin: '0.5rem 0 0', color: '#1e40af' }}>
                Changing this password revokes the student&apos;s existing sessions. They will need to sign in again.
              </p>
            </div>

            <form onSubmit={handleSubmit}>
              <div style={{ marginBottom: '1.5rem' }}>
                <label style={{ display: 'block', marginBottom: '0.5rem', fontWeight: '500', color: '#374151' }}>
                  New Password *
                </label>
                <input
                  type="password"
                  value={passwordChangeData.newPassword}
                  onChange={(e) => updateStudentPassword(stage, { newPassword: e.target.value })}
                  style={{
                    width: '100%',
                    padding: '0.75rem',
                    border: '2px solid #d1d5db',
                    borderRadius: '8px',
                    fontSize: '1rem'
                  }}
                  required
                  minLength="8"
                  placeholder="Enter new password (min 8 characters)"
                />
              </div>

              <div style={{ marginBottom: '2rem' }}>
                <label style={{ display: 'block', marginBottom: '0.5rem', fontWeight: '500', color: '#374151' }}>
                  Confirm Password *
                </label>
                <input
                  type="password"
                  value={passwordChangeData.confirmPassword}
                  onChange={(e) => updateStudentPassword(stage, { confirmPassword: e.target.value })}
                  style={{
                    width: '100%',
                    padding: '0.75rem',
                    border: '2px solid #d1d5db',
                    borderRadius: '8px',
                    fontSize: '1rem'
                  }}
                  required
                  minLength="8"
                  placeholder="Confirm new password"
                />
              </div>
              
              {studentPasswordOutcome?.kind === 'unknown' && <p role="alert">
                The password-change outcome could not be confirmed. The request may have changed the password and revoked sessions.
                No automatic retry was made. Contact the student or review the account before starting a new change.
              </p>}
              {studentPasswordOutcome?.kind === 'rejected' && <p role="alert">The password change was rejected.</p>}
              <div style={{ display: 'flex', gap: '1rem', justifyContent: 'flex-end' }}>
                <ActionButton 
                  type="button"
                  onClick={() => closeStudentPassword(stage)}
                  disabled={studentPasswordPending}
                  style={{ background: '#6b7280' }}
                >
                  {studentPasswordOutcome?.kind === 'unknown' || studentPasswordOutcome?.kind === 'rejected' ? 'Close' : 'Cancel'}
                </ActionButton>
                <ActionButton type="submit" disabled={studentPasswordPending || stage.consumed}>
                  <FiSave /> Change Password
                </ActionButton>
              </div>
            </form>
          </ModalBody>
        </ModalContent>
      </ModalOverlay>
    );
  };

  const renderSolutionEditModal = () => {
    if (!editingSolution) return null;

    const handleSolutionEditSubmit = (e) => {
      e.preventDefault();
      
      // Process data before sending
      const processedData = {
        ...solutionData,
        solution_steps: solutionData.solution_steps.split('\n').filter(step => step.trim()),
        reference_links: solutionData.reference_links.split('\n').filter(link => link.trim()),
        prerequisites: solutionData.prerequisites.split(',').map(p => p.trim()).filter(p => p),
        tags: solutionData.tags.split(',').map(t => t.trim()).filter(t => t)
      };

      updateSolution(editingSolution.id, processedData);
    };

    return (
      <ModalOverlay
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
        onClick={() => setSolutionEditModalOpen(false)}
      >
        <ModalContent
          initial={{ scale: 0.9, opacity: 0 }}
          animate={{ scale: 1, opacity: 1 }}
          exit={{ scale: 0.9, opacity: 0 }}
          onClick={(e) => e.stopPropagation()}
          style={{ maxWidth: '800px', maxHeight: '90vh', overflowY: 'auto' }}
        >
          <ModalHeader>
            <h2>Edit Solution</h2>
            <button onClick={() => setSolutionEditModalOpen(false)}>
              <FiX />
            </button>
          </ModalHeader>

          <ModalBody>
            <form onSubmit={handleSolutionEditSubmit}>
              <div style={{ marginBottom: '1.5rem' }}>
                <label style={{ display: 'block', marginBottom: '0.5rem', fontWeight: '500', color: '#374151' }}>
                  Solution Title *
                </label>
                <input
                  type="text"
                  value={solutionData.solution_title}
                  onChange={(e) => setSolutionData({...solutionData, solution_title: e.target.value})}
                  style={{
                    width: '100%',
                    padding: '0.75rem',
                    border: '2px solid #d1d5db',
                    borderRadius: '8px',
                    fontSize: '1rem'
                  }}
                  required
                />
              </div>

              <div style={{ marginBottom: '1.5rem' }}>
                <label style={{ display: 'block', marginBottom: '0.5rem', fontWeight: '500', color: '#374151' }}>
                  Description
                </label>
                <textarea
                  value={solutionData.solution_description}
                  onChange={(e) => setSolutionData({...solutionData, solution_description: e.target.value})}
                  style={{
                    width: '100%',
                    padding: '0.75rem',
                    border: '2px solid #d1d5db',
                    borderRadius: '8px',
                    fontSize: '1rem',
                    minHeight: '100px',
                    resize: 'vertical'
                  }}
                  placeholder="Brief description of the solution"
                />
              </div>

              <div style={{ marginBottom: '1.5rem' }}>
                <label style={{ display: 'block', marginBottom: '0.5rem', fontWeight: '500', color: '#374151' }}>
                  Solution Steps (one per line)
                </label>
                <textarea
                  value={solutionData.solution_steps}
                  onChange={(e) => setSolutionData({...solutionData, solution_steps: e.target.value})}
                  style={{
                    width: '100%',
                    padding: '0.75rem',
                    border: '2px solid #d1d5db',
                    borderRadius: '8px',
                    fontSize: '1rem',
                    minHeight: '120px',
                    resize: 'vertical'
                  }}
                  placeholder="Step 1: First action&#10;Step 2: Second action&#10;..."
                />
              </div>

              <div style={{ marginBottom: '1.5rem' }}>
                <label style={{ display: 'block', marginBottom: '0.5rem', fontWeight: '500', color: '#374151' }}>
                  Code Examples
                </label>
                <textarea
                  value={solutionData.solution_code}
                  onChange={(e) => setSolutionData({...solutionData, solution_code: e.target.value})}
                  style={{
                    width: '100%',
                    padding: '0.75rem',
                    border: '2px solid #d1d5db',
                    borderRadius: '8px',
                    fontSize: '0.9rem',
                    fontFamily: 'monospace',
                    minHeight: '120px',
                    resize: 'vertical'
                  }}
                  placeholder="// Code examples or payloads"
                />
              </div>

              <div style={{ marginBottom: '1.5rem' }}>
                <label style={{ display: 'block', marginBottom: '0.5rem', fontWeight: '500', color: '#374151' }}>
                  Explanation
                </label>
                <textarea
                  value={solutionData.explanation}
                  onChange={(e) => setSolutionData({...solutionData, explanation: e.target.value})}
                  style={{
                    width: '100%',
                    padding: '0.75rem',
                    border: '2px solid #d1d5db',
                    borderRadius: '8px',
                    fontSize: '1rem',
                    minHeight: '100px',
                    resize: 'vertical'
                  }}
                  placeholder="Detailed explanation of how the solution works"
                />
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem', marginBottom: '1.5rem' }}>
                <div>
                  <label style={{ display: 'block', marginBottom: '0.5rem', fontWeight: '500', color: '#374151' }}>
                    Difficulty Level
                  </label>
                  <select
                    value={solutionData.difficulty_level}
                    onChange={(e) => setSolutionData({...solutionData, difficulty_level: e.target.value})}
                    style={{
                      width: '100%',
                      padding: '0.75rem',
                      border: '2px solid #d1d5db',
                      borderRadius: '8px',
                      fontSize: '1rem'
                    }}
                  >
                    {solutionData.difficulty_level && !['easy', 'medium', 'hard'].includes(solutionData.difficulty_level) && (
                      <option value={solutionData.difficulty_level}>{solutionData.difficulty_level}</option>
                    )}
                    <option value="easy">Easy</option>
                    <option value="medium">Medium</option>
                    <option value="hard">Hard</option>
                  </select>
                </div>

                <div>
                  <label style={{ display: 'block', marginBottom: '0.5rem', fontWeight: '500', color: '#374151' }}>
                    Estimated Time
                  </label>
                  <input
                    type="text"
                    value={solutionData.estimated_time}
                    onChange={(e) => setSolutionData({...solutionData, estimated_time: e.target.value})}
                    style={{
                      width: '100%',
                      padding: '0.75rem',
                      border: '2px solid #d1d5db',
                      borderRadius: '8px',
                      fontSize: '1rem'
                    }}
                    placeholder="e.g., 15 minutes"
                  />
                </div>
              </div>

              <div style={{ marginBottom: '1.5rem' }}>
                <label style={{ display: 'block', marginBottom: '0.5rem', fontWeight: '500', color: '#374151' }}>
                  Reference Links (one per line)
                </label>
                <textarea
                  value={solutionData.reference_links}
                  onChange={(e) => setSolutionData({...solutionData, reference_links: e.target.value})}
                  style={{
                    width: '100%',
                    padding: '0.75rem',
                    border: '2px solid #d1d5db',
                    borderRadius: '8px',
                    fontSize: '1rem',
                    minHeight: '80px',
                    resize: 'vertical'
                  }}
                  placeholder="https://example.com/reference1&#10;https://example.com/reference2"
                />
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem', marginBottom: '1.5rem' }}>
                <div>
                  <label style={{ display: 'block', marginBottom: '0.5rem', fontWeight: '500', color: '#374151' }}>
                    Prerequisites (comma-separated)
                  </label>
                  <input
                    type="text"
                    value={solutionData.prerequisites}
                    onChange={(e) => setSolutionData({...solutionData, prerequisites: e.target.value})}
                    style={{
                      width: '100%',
                      padding: '0.75rem',
                      border: '2px solid #d1d5db',
                      borderRadius: '8px',
                      fontSize: '1rem'
                    }}
                    placeholder="HTML basics, HTTP knowledge"
                  />
                </div>

                <div>
                  <label style={{ display: 'block', marginBottom: '0.5rem', fontWeight: '500', color: '#374151' }}>
                    Tags (comma-separated)
                  </label>
                  <input
                    type="text"
                    value={solutionData.tags}
                    onChange={(e) => setSolutionData({...solutionData, tags: e.target.value})}
                    style={{
                      width: '100%',
                      padding: '0.75rem',
                      border: '2px solid #d1d5db',
                      borderRadius: '8px',
                      fontSize: '1rem'
                    }}
                    placeholder="sql, injection, security"
                  />
                </div>
              </div>

              <div style={{ marginBottom: '2rem' }}>
                <div style={{ display: 'flex', alignItems: 'center' }}>
                  <input
                    type="checkbox"
                    id="is_public"
                    checked={solutionData.is_public}
                    onChange={(e) => setSolutionData({...solutionData, is_public: e.target.checked})}
                    style={{ marginRight: '0.5rem' }}
                  />
                  <label htmlFor="is_public" style={{ fontWeight: '500', color: '#374151' }}>
                    Make solution publicly visible to students
                  </label>
                </div>
              </div>
              
              <div style={{ display: 'flex', gap: '1rem', justifyContent: 'flex-end' }}>
                <ActionButton 
                  type="button"
                  onClick={() => setSolutionEditModalOpen(false)}
                  style={{ background: '#6b7280' }}
                >
                  Cancel
                </ActionButton>
                <ActionButton type="submit">
                  <FiSave /> Update Solution
                </ActionButton>
              </div>
            </form>
          </ModalBody>
        </ModalContent>
      </ModalOverlay>
    );
  };

  // AI Provider Management Section
  const renderAIProviders = () => {
    return <AIProviderManagement />;
  };

  // LLM Health Monitoring Section
  const renderLLMHealth = () => {
    // NO HOOKS - using top-level state: llmHealthData, llmStatsData, llmHealthLoading, llmAutoRefresh
    
    const getStatusColor = (status) => {
      switch (status) {
        case 'healthy': return '#48bb78';
        case 'unhealthy': return '#f56565';
        case 'unknown': return '#ed8936';
        default: return '#a0aec0';
      }
    };

    if (llmHealthLoading) return <div>Loading LLM health data...</div>;

    return (
      <div>
        <SectionHeader>
          <h2>LLM Health Monitoring</h2>
          <div style={{ display: 'flex', gap: '1rem', alignItems: 'center' }}>
            <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: '#4a5568' }}>
              <input
                type="checkbox"
                checked={llmAutoRefresh}
                onChange={(e) => setLlmAutoRefresh(e.target.checked)}
              />
              Auto-refresh (30s)
            </label>
            <ActionButton onClick={() => fetchLlmHealthData(false)}>
              <FiActivity /> Quick Refresh
            </ActionButton>
            <ActionButton onClick={() => fetchLlmHealthData(true)}>
              <FiActivity /> Check All Providers (live)
            </ActionButton>
            <ActionButton
              onClick={() => window.open('/api/monitoring/health?format=html', '_blank', 'noopener')}
              style={{ background: '#4a5568' }}
            >
              <FiServer /> Server Health Dashboard
            </ActionButton>
          </div>
        </SectionHeader>

        <div style={{
          marginBottom: '1.5rem', padding: '0.6rem 1rem', borderRadius: '8px',
          background: '#ebf8ff', border: '1px solid #bee3f8', color: '#2c5282', fontSize: '0.85rem'
        }}>
          {llmHealthData?.mode === 'deep'
            ? 'Showing a live generation test (each configured provider was actually called).'
            : 'Showing a fast reachability check — this opens instantly. Click "Check All Providers (live)" to run a real generation test against each provider.'}
        </div>

        <StatsGrid style={{ marginBottom: '2rem' }}>
          <StatCard
            bgColor={`linear-gradient(135deg, ${getStatusColor(llmHealthData?.status || 'unknown')} 0%, ${getStatusColor(llmHealthData?.status || 'unknown')}80 100%)`}
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
          >
            <div className="icon"><FiMonitor /></div>
            <div className="content">
              <h3>AI Provider Status</h3>
              <p style={{ textTransform: 'capitalize' }}>{llmHealthData?.status || 'Unknown'}</p>
              <span style={{ fontSize: '0.8rem', opacity: 0.9 }}>
                {llmHealthData?.provider?.providerName || 'Unknown provider'}
              </span>
            </div>
          </StatCard>
          
          <StatCard
            bgColor="linear-gradient(135deg, #667eea 0%, #764ba2 100%)"
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.1 }}
          >
            <div className="icon"><FiClock /></div>
            <div className="content">
              <h3>Response Time</h3>
              <p>{llmHealthData?.responseTime || 0}ms</p>
            </div>
          </StatCard>

          <StatCard
            bgColor="linear-gradient(135deg, #ffecd2 0%, #fcb69f 100%)"
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.2 }}
          >
            <div className="icon"><FiSettings /></div>
            <div className="content">
              <h3>Models Available</h3>
              <p>{llmHealthData?.models?.length || 0}</p>
            </div>
          </StatCard>

          <StatCard
            bgColor="linear-gradient(135deg, #a8edea 0%, #fed6e3 100%)"
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.3 }}
          >
            <div className="icon"><FiTrendingUp /></div>
            <div className="content">
              <h3>Requests Today</h3>
              <p>{llmStatsData?.requestsToday || 0}</p>
            </div>
          </StatCard>
        </StatsGrid>

        {/* All AI providers health grid */}
        <TableCard style={{ marginBottom: '2rem' }}>
          <h3>All AI Providers</h3>
          {llmHealthData?.providers?.length > 0 ? (
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: '1rem', marginTop: '1rem' }}>
              {llmHealthData.providers.map((p) => {
                const state = p.healthy ? 'healthy' : (p.available ? 'reachable' : (p.configured ? 'unhealthy' : 'not configured'));
                const stateColor = p.healthy ? '#48bb78' : (p.available ? '#ed8936' : (p.configured ? '#f56565' : '#a0aec0'));
                const providerIcon = ['ollama', 'lmstudio'].includes(p.key)
                  ? <FiCpu />
                  : (p.key === 'chatgpt' ? <FiZap /> : <FiCloud />);
                return (
                  <div key={p.key} style={{
                    border: `1px solid ${p.active ? '#667eea' : '#e2e8f0'}`,
                    borderRadius: '10px', padding: '1rem',
                    background: p.active ? '#f7f8ff' : '#fff'
                  }}>
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.5rem' }}>
                      <span style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontWeight: 700, color: '#2d3748' }}>
                        {providerIcon} {p.name}
                      </span>
                      {p.active && (
                        <span style={{ fontSize: '0.7rem', fontWeight: 700, color: '#fff', background: '#667eea', borderRadius: '999px', padding: '0.1rem 0.5rem' }}>
                          ACTIVE
                        </span>
                      )}
                    </div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', marginBottom: '0.5rem' }}>
                      <span style={{ width: '10px', height: '10px', borderRadius: '50%', background: stateColor, display: 'inline-block' }} />
                      <span style={{ fontSize: '0.85rem', fontWeight: 600, color: stateColor, textTransform: 'capitalize' }}>{state}</span>
                      <span style={{ marginLeft: 'auto', fontSize: '0.75rem', color: '#718096' }}>{p.type}</span>
                    </div>
                    <div style={{ fontSize: '0.8rem', color: '#4a5568', display: 'grid', gap: '0.2rem' }}>
                      <div><strong>Model:</strong> {p.model || 'N/A'}</div>
                      {p.region && <div><strong>Region:</strong> {p.region}</div>}
                      {p.baseUrl && <div style={{ wordBreak: 'break-all' }}><strong>Endpoint:</strong> {p.baseUrl}</div>}
                      <div><strong>Configured:</strong> {p.configured ? 'Yes' : 'No'} · <strong>Latency:</strong> {p.responseTime || 0}ms</div>
                      {p.message && <div style={{ color: '#718096', fontSize: '0.75rem' }}>{p.message}</div>}
                    </div>
                  </div>
                );
              })}
            </div>
          ) : (
            <p style={{ marginTop: '1rem' }}>Provider health data not available. Click "Check All Providers".</p>
          )}
        </TableCard>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(400px, 1fr))', gap: '2rem' }}>
          <TableCard>
            <h3>Available Models</h3>
            <div style={{ maxHeight: '300px', overflowY: 'auto' }}>
              {llmHealthData?.models?.length > 0 ? (
                <table style={{ width: '100%' }}>
                  <thead>
                    <tr>
                      <th>Model Name</th>
                      <th>Size</th>
                      <th>Modified</th>
                    </tr>
                  </thead>
                  <tbody>
                    {llmHealthData.models.map((model, index) => (
                      <tr key={index}>
                        <td style={{ fontWeight: '500' }}>{model.name}</td>
                        <td>{model.size ? `${(model.size / 1024 / 1024 / 1024).toFixed(1)}GB` : 'N/A'}</td>
                        <td>{model.modified_at ? new Date(model.modified_at).toLocaleDateString() : 'N/A'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              ) : (
                <p>No models available or failed to fetch models</p>
              )}
            </div>
          </TableCard>

          <TableCard>
            <h3>System Information</h3>
            <div style={{ padding: '1rem 0' }}>
              {llmHealthData?.provider && (
                <div style={{
                  display: 'grid', gap: '0.4rem', marginBottom: '1rem',
                  padding: '0.75rem 1rem', borderRadius: '8px',
                  background: llmHealthData.provider.healthy ? '#f0fff4' : (llmHealthData.provider.available ? '#fffaf0' : '#fff5f5'),
                  border: `1px solid ${llmHealthData.provider.healthy ? '#9ae6b4' : (llmHealthData.provider.available ? '#fbd38d' : '#feb2b2')}`
                }}>
                  <div style={{ fontWeight: 700, color: '#2d3748' }}>
                    Active Provider: {llmHealthData.provider.providerName}
                    <span style={{
                      marginLeft: '0.5rem', fontSize: '0.75rem', fontWeight: 600,
                      padding: '0.1rem 0.5rem', borderRadius: '999px', color: '#fff',
                      background: llmHealthData.provider.healthy ? '#48bb78' : (llmHealthData.provider.available ? '#ed8936' : '#f56565')
                    }}>
                      {llmHealthData.provider.healthy ? 'Healthy' : (llmHealthData.provider.available ? 'Reachable' : 'Unavailable')}
                    </span>
                  </div>
                  <div><strong>Model:</strong> {llmHealthData.provider.model || 'N/A'}</div>
                  {llmHealthData.provider.region && <div><strong>Region:</strong> {llmHealthData.provider.region}</div>}
                  <div><strong>Configured:</strong> {llmHealthData.provider.configured ? 'Yes' : 'No'}</div>
                  <div><strong>Check latency:</strong> {llmHealthData.provider.responseTime || 0}ms</div>
                  {llmHealthData.provider.message && (
                    <div style={{ fontSize: '0.85rem', color: '#4a5568' }}>{llmHealthData.provider.message}</div>
                  )}
                </div>
              )}
              {llmHealthData?.ollama && (
                <div style={{ marginBottom: '1rem', fontSize: '0.9rem', color: '#4a5568' }}>
                  <strong>Local LLM (Ollama):</strong>{' '}
                  <span style={{ color: llmHealthData.ollama.status === 'healthy' ? '#2f855a' : '#c53030', fontWeight: 600, textTransform: 'capitalize' }}>
                    {llmHealthData.ollama.status}
                  </span>
                  {llmHealthData.ollama.status !== 'healthy' && (
                    <span style={{ color: '#718096' }}> — not used on this deployment (Bedrock is active)</span>
                  )}
                </div>
              )}
              {llmHealthData?.systemInfo ? (
                <div style={{ display: 'grid', gap: '0.5rem' }}>
                  <div><strong>Version:</strong> {llmHealthData.systemInfo.version || 'N/A'}</div>
                  <div><strong>Last Checked:</strong> {new Date(llmHealthData.lastChecked).toLocaleString()}</div>
                </div>
              ) : (
                <p>System information not available</p>
              )}
              
              {llmHealthData?.errors?.length > 0 && (
                <div style={{ marginTop: '1rem' }}>
                  <h4 style={{ color: '#f56565', marginBottom: '0.5rem' }}>Errors:</h4>
                  {llmHealthData.errors.map((error, index) => (
                    <div key={index} style={{ 
                      background: '#fed7d7', 
                      color: '#c53030', 
                      padding: '0.5rem',
                      borderRadius: '4px',
                      fontSize: '0.875rem',
                      marginBottom: '0.25rem'
                    }}>
                      {error}
                    </div>
                  ))}
                </div>
              )}
            </div>
          </TableCard>
        </div>

        {llmStatsData?.recentActivity?.length > 0 && (
          <TableCard style={{ marginTop: '2rem' }}>
            <h3>Recent Activity</h3>
            <div style={{ maxHeight: '300px', overflowY: 'auto' }}>
              <table>
                <thead>
                  <tr>
                    <th>Date</th>
                    <th>Model</th>
                    <th>Requests</th>
                    <th>Success Rate</th>
                  </tr>
                </thead>
                <tbody>
                  {llmStatsData.recentActivity.map((activity, index) => (
                    <tr key={index}>
                      <td>{activity.date}</td>
                      <td>{activity.model || 'Unknown'}</td>
                      <td>{activity.requests}</td>
                      <td>{(activity.successRate * 100).toFixed(1)}%</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </TableCard>
        )}
      </div>
    );
  };

  const renderProgressAnalytics = () => <ProgressAnalyticsPanel />;

  const renderContent = () => {
    switch (activeSection) {
      case 'dashboard':
        return renderDashboard();
      case 'exercises':
        return <>{renderExercises()}{renderObjEditModals()}</>;
      case 'students':
        return canManageProgress ? renderStudents() : <div role="alert">Permission denied: Students requires progress management access.</div>;
      case 'locked-users':
        return renderLockedUsers();
      case 'student-workshop-view':
        return canManageProgress
          ? <StudentWorkshopView />
          : <div role="alert">Permission denied: Student View requires progress management access.</div>;
      case 'ctf-management':
        return <CTFAdminPanel />;
      case 'progress-analytics':
        return canManageProgress
          ? renderProgressAnalytics()
          : <div role="alert">Permission denied: Student Progress requires progress management access.</div>;
      case 'llm-health':
        return renderLLMHealth();
      case 'ai-providers':
        return renderAIProviders();
      case 'activity':
        return renderActivityLogs();
      case 'server-logs':
        return <ServerLogs />;
      case 'agent-runs':
        return canViewAgentRuns
          ? <AgentRunInspector admin />
          : <div role="alert">Permission denied: Agent Runs requires analytics access.</div>;
      case 'settings':
        return renderSettings();
      default:
        return renderDashboard();
    }
  };

  if (!user || (!user.isAdmin && user.adminLevel === 0)) {
    navigate('/workshop-login');
    return null;
  }

  return (
    <AdminContainer>
      <MobileToggle onClick={() => setSidebarOpen(!sidebarOpen)}>
        {sidebarOpen ? <FiX /> : <FiMenu />}
      </MobileToggle>
      
      <Sidebar isOpen={sidebarOpen}>
        <SidebarHeader>
          <div className="brand">
            <div className="brand-icon"><FiShield /></div>
            <div className="brand-text">
              <h1>DVAIA Admin</h1>
              <p>Security Workshop</p>
            </div>
          </div>
          <div className="user-pill">
            <div className="user-avatar">{user?.username?.charAt(0)?.toUpperCase() || 'A'}</div>
            <div className="user-info">
              <div className="name">{user?.fullName || user?.username}</div>
              <div className="role">Admin</div>
            </div>
          </div>
        </SidebarHeader>

        <NavSection>
          <NavGroupLabel>Overview</NavGroupLabel>
          {[navItems[0]].map(item => (
            <NavItem key={item.id} active={activeSection === item.id}
              onClick={() => { navigate('/admin/dashboard'); setSidebarOpen(false); }}
              whileTap={{ scale: 0.97 }}
            >
              <item.icon /><span>{item.label}</span>
            </NavItem>
          ))}

          <NavGroupLabel>Users</NavGroupLabel>
          {navItems.slice(1, 4).filter(item => item.id !== 'students' && item.id !== 'student-workshop-view' || canManageProgress).map(item => (
            <NavItem key={item.id} active={activeSection === item.id}
              onClick={() => { navigate(`/admin/${item.id}`); setSidebarOpen(false); }}
              whileTap={{ scale: 0.97 }}
            >
              <item.icon /><span>{item.label}</span>
            </NavItem>
          ))}

          <NavGroupLabel>Content</NavGroupLabel>
          {navItems.slice(4, 6).map(item => (
            <NavItem key={item.id} active={activeSection === item.id}
              onClick={() => { navigate(`/admin/${item.id}`); setSidebarOpen(false); }}
              whileTap={{ scale: 0.97 }}
            >
              <item.icon /><span>{item.label}</span>
            </NavItem>
          ))}

          <NavGroupLabel>System</NavGroupLabel>
          {navItems.slice(6).filter(item => (item.id !== 'agent-runs' || canViewAgentRuns)
            && (item.id !== 'progress-analytics' || canManageProgress)).map(item => (
            <NavItem key={item.id} active={activeSection === item.id}
              onClick={() => { navigate(`/admin/${item.id}`); setSidebarOpen(false); }}
              whileTap={{ scale: 0.97 }}
            >
              <item.icon /><span>{item.label}</span>
            </NavItem>
          ))}
        </NavSection>

        <SidebarFooter>
          <NavItem
            onClick={handleLogout}
            whileTap={{ scale: 0.97 }}
            style={{ color: '#f56565', borderLeftColor: 'transparent' }}
          >
            <FiLogOut />
            <span>Logout</span>
          </NavItem>
        </SidebarFooter>
      </Sidebar>
      
      <MainContent>
        <Header>
          <HeaderTitle>
            <h1>Admin Dashboard</h1>
            <p>Manage your DVAIA security workshop platform</p>
          </HeaderTitle>
          <UserInfo>
            <div className="avatar">
              {user?.username?.charAt(0)?.toUpperCase() || 'A'}
            </div>
            <div className="details">
              <h3>{user?.fullName || user?.username}</h3>
              <p>Admin Level {user?.adminLevel}</p>
            </div>
          </UserInfo>
        </Header>
        
        {renderContent()}
      </MainContent>
      
      <AnimatePresence>
        {studentModalOpen && renderStudentDetailsModal()}
        {createStudentModalOpen && renderCreateStudentModal()}
        {editStudentModalOpen && renderEditStudentModal()}
        {deleteStudentModalOpen && renderDeleteStudentModal()}
        {changeStudentPasswordModalOpen && renderChangeStudentPasswordModal()}
        {securitySettingsModalOpen && renderSecuritySettingsModal()}
        {userManagementModalOpen && hasUserManagementPermission && renderUserManagementModal()}
        {systemLogsModalOpen && renderSystemLogsModal()}
        {changePasswordModalOpen && renderChangePasswordModal()}
        {solutionModalOpen && renderSolutionDetailsModal()}
        {solutionEditModalOpen && renderSolutionEditModal()}
        {scViewModalOpen && renderScViewModal()}
        {solutionPreview && renderSolutionPreviewModal()}
        {mcpSolutionEditor && <TypedObjectiveSolutionEditor key={mcpSolutionEditor.objectiveId} objectiveId={mcpSolutionEditor.objectiveId} solution={mcpSolutionEditor.solution} onSave={saveMcpSolutionEditor} onCancel={() => setMcpSolutionEditor(null)} />}
        {scEditModalOpen && renderScEditModal()}
        {piViewModalOpen && renderPiViewModal()}
        {piAllSolutionsViewModalOpen && renderPiAllSolutionsViewModal()}
        {piEditModalOpen && renderPiEditModal()}
        {hintEditor && (
          <PromptInjectionHintEditorModal
            objectiveLabel={hintEditor.objectiveLabel}
            hint={hintEditor.hint}
            saving={hintEditorSaving}
            onCancel={() => { if (!hintSavePending.current) setHintEditor(null); }}
            onSave={saveHintEditor}
          />
        )}
        {objectiveEditor && <WorkshopObjectiveEditor key={`${objectiveEditor.workshopKey}:${objectiveEditor.objectiveId}`}
          objective={objectiveEditor} onSave={saveObjectiveEditor} onCancel={() => setObjectiveEditor(null)} />}
        {solutionEditor && <WorkshopSolutionEditor key={`${solutionEditor.workshopKey}:${solutionEditor.objectiveId}`}
          workshopKey={toWorkshopKey(solutionEditor.workshopKey)} objectiveId={solutionEditor.objectiveId}
          solution={solutionEditor.solution} onSave={saveUniversalSolutionEditor} onCancel={() => setSolutionEditor(null)} />}
      </AnimatePresence>
      {accountAccessConfirm && renderAccountAccessConfirmModal()}
      {bulkVisibilityConfirm && renderBulkVisibilityConfirmModal()}
      {bulkContentConfirm && renderBulkContentVisibilityConfirmModal()}
    </AdminContainer>
  );
};

export default ComprehensiveAdminDashboard;
