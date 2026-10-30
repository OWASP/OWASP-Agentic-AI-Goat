import { hasPlatformAdminLevel } from '../utils/platformAdmin';
import React, { useState, useRef, useEffect } from 'react';
import { Link, useNavigate, useLocation } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { FiHome, FiShield, FiUser, FiLogOut, FiMenu, FiX, FiTarget, FiSettings, FiChevronDown, FiDatabase, FiCode, FiAward, FiAlertTriangle, FiCpu, FiPackage, FiFileText, FiTerminal, FiActivity, FiLock } from 'react-icons/fi';
import styled from 'styled-components';
import axios from 'axios';
import GoatBrand from './GoatBrand';

const NavbarContainer = styled.nav`
  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
  padding: 0;
  position: sticky;
  top: 0;
  z-index: 1000;
  box-shadow: 0 8px 32px rgba(102, 126, 234, 0.3);
`;

const WarningBanner = styled.div`
  background: linear-gradient(90deg, #ff6b6b, #ee5a24);
  color: white;
  text-align: center;
  padding: 0.5rem;
  font-weight: 500;
  font-size: 0.85rem;
  border-bottom: 2px solid rgba(255, 255, 255, 0.1);
`;

const NavContent = styled.div`
  max-width: 1400px;
  margin: 0 auto;
  padding: 1rem 2rem;
  display: flex;
  justify-content: space-between;
  align-items: center;
`;

const BrandSection = styled.div`
  display: flex;
  align-items: center;
  gap: 1rem;
`;

const Logo = styled(Link)`
  display: flex;
  align-items: center;
  text-decoration: none;
  font-size: 1.8rem;
  font-weight: 800;
  color: white;
  transition: all 0.3s ease;

  &:hover {
    transform: translateY(-2px);
  }
`;

const NavLinks = styled.div`
  display: flex;
  align-items: center;
  gap: 0.5rem;
  /* Hug the right side next to the user section instead of floating in the
     middle — with NavContent's space-between and 3 children, margin-left:auto
     collapses the empty gap the removed Progress tab left behind. */
  margin-left: auto;
  margin-right: 1.5rem;

  @media (max-width: 768px) {
    display: ${props => props.$isOpen ? 'flex' : 'none'};
    position: absolute;
    top: 100%;
    left: 0;
    right: 0;
    margin: 0;
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    flex-direction: column;
    padding: 2rem;
    gap: 1rem;
    box-shadow: 0 8px 32px rgba(0, 0, 0, 0.2);
  }
`;

const NavLink = styled(Link)`
  display: flex;
  align-items: center;
  gap: 0.5rem;
  text-decoration: none;
  color: rgba(255, 255, 255, 0.9);
  font-weight: 500;
  padding: 0.75rem 1.25rem;
  border-radius: 12px;
  transition: all 0.3s ease;
  position: relative;
  overflow: hidden;

  &::before {
    content: '';
    position: absolute;
    top: 0;
    left: -100%;
    width: 100%;
    height: 100%;
    background: linear-gradient(90deg, transparent, rgba(255,255,255,0.1), transparent);
    transition: left 0.5s ease;
  }

  &:hover::before {
    left: 100%;
  }

  &:hover {
    background: rgba(255, 255, 255, 0.15);
    color: white;
    transform: translateY(-2px);
  }

  &.active {
    background: rgba(255, 255, 255, 0.2);
    color: white;
    box-shadow: 0 4px 15px rgba(0, 0, 0, 0.1);
  }
`;

const UserSection = styled.div`
  display: flex;
  align-items: center;
  gap: 1rem;
`;

const ProfileDropdown = styled.div`
  position: relative;
  display: flex;
  align-items: center;
`;

const ProfileToggle = styled.button`
  display: flex;
  align-items: center;
  gap: 0.75rem;
  padding: 0.75rem 1.25rem;
  background: rgba(255, 255, 255, 0.15);
  border-radius: 12px;
  color: white;
  font-weight: 500;
  backdrop-filter: blur(10px);
  border: 1px solid rgba(255, 255, 255, 0.1);
  cursor: pointer;
  transition: all 0.3s ease;

  &:hover {
    background: rgba(255, 255, 255, 0.25);
    transform: translateY(-2px);
  }
`;

const UserAvatar = styled.div`
  width: 32px;
  height: 32px;
  border-radius: 8px;
  background: linear-gradient(135deg, #ff6b6b, #ee5a24);
  display: flex;
  align-items: center;
  justify-content: center;
  font-weight: 700;
  font-size: 0.9rem;
  color: white;
`;

const UserDetails = styled.div`
  display: flex;
  flex-direction: column;
  gap: 0.1rem;

  @media (max-width: 640px) {
    display: none;
  }
`;

const Username = styled.span`
  font-size: 0.9rem;
  font-weight: 600;
`;

const UserRole = styled.span`
  font-size: 0.75rem;
  opacity: 0.8;
  text-transform: uppercase;
  letter-spacing: 0.5px;
`;

const DropdownMenu = styled.div`
  position: absolute;
  top: calc(100% + 0.5rem);
  right: 0;
  background: rgba(255, 255, 255, 0.95);
  backdrop-filter: blur(20px);
  border-radius: 12px;
  box-shadow: 0 10px 40px rgba(0, 0, 0, 0.15);
  border: 1px solid rgba(255, 255, 255, 0.2);
  min-width: 200px;
  opacity: ${props => props.isOpen ? 1 : 0};
  visibility: ${props => props.isOpen ? 'visible' : 'hidden'};
  transform: ${props => props.isOpen ? 'translateY(0)' : 'translateY(-10px)'};
  transition: all 0.3s ease;
  z-index: 1000;
`;

const DropdownItem = styled.button`
  display: flex;
  align-items: center;
  gap: 0.75rem;
  width: 100%;
  padding: 0.75rem 1rem;
  background: transparent;
  border: none;
  color: #333;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.3s ease;
  border-radius: 8px;
  margin: 0.25rem;

  &:hover {
    background: rgba(102, 126, 234, 0.1);
    color: #667eea;
  }

  &:first-child {
    margin-top: 0.5rem;
  }

  &:last-child {
    margin-bottom: 0.5rem;
  }
`;

const DropdownLink = styled(Link)`
  display: flex;
  align-items: center;
  gap: 0.75rem;
  width: 100%;
  padding: 0.75rem 1rem;
  background: transparent;
  border: none;
  color: #333;
  font-weight: 500;
  text-decoration: none;
  cursor: pointer;
  transition: all 0.3s ease;
  border-radius: 8px;
  margin: 0.25rem;

  &:hover {
    background: rgba(102, 126, 234, 0.1);
    color: #667eea;
  }

  &:first-child {
    margin-top: 0.5rem;
  }
`;

const DropdownDivider = styled.hr`
  margin: 0.5rem;
  border: none;
  height: 1px;
  background: rgba(0, 0, 0, 0.1);
`;

const MobileToggle = styled.button`
  display: none;
  background: rgba(255, 255, 255, 0.15);
  border: 1px solid rgba(255, 255, 255, 0.1);
  border-radius: 8px;
  padding: 0.5rem;
  font-size: 1.25rem;
  cursor: pointer;
  color: white;
  transition: all 0.3s ease;

  &:hover {
    background: rgba(255, 255, 255, 0.25);
  }

  @media (max-width: 768px) {
    display: block;
  }
`;

const filterVisibleExercises = (challenges = []) => challenges.filter(
  challenge => challenge.id !== 'ctf_prompt_injection_challenge'
    && challenge.challenge_key !== 'ctf_prompt_injection_challenge'
    && challenge.id !== 'secureshop_agent_security'
    && challenge.workshopKey !== 'secureshop_agent_security'
);

const WorkshopNavbar = () => {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [isOpen, setIsOpen] = useState(false);
  const [dropdownOpen, setDropdownOpen] = useState(false);
  const [exercises, setExercises] = useState([]);
  const [exercisesDropdownOpen, setExercisesDropdownOpen] = useState(false);
  const [ctfDropdownOpen, setCTFDropdownOpen] = useState(false);
  const [ctfConfig, setCTFConfig] = useState({ ctf_enabled: 'false', ctf_visible_to_students: 'false' });
  const dropdownRef = useRef(null);
  const exercisesDropdownRef = useRef(null);
  const ctfDropdownRef = useRef(null);

  console.log('NavBar rendered - user:', user);

  const handleLogout = async () => {
    await logout();
    navigate('/');
    setIsOpen(false);
    setDropdownOpen(false);
  };

  const isActive = (path) => location.pathname === path;

  // Fetch visible exercises from admin-controlled API
  const fetchVisibleExercises = async () => {
    if (!user) return;

    try {
      const response = await axios.get('/api/workshop/challenges');
      const visibleExercises = filterVisibleExercises(response.data.challenges);
      setExercises(visibleExercises);
    } catch (error) {
      setExercises([]);
    }
  };

  // Fetch CTF configuration to check visibility
  const fetchCTFConfig = async () => {
    if (!user) return;

    try {
      const response = await axios.get('/api/ctf/config');
      const config = response.data.config || {};
      setCTFConfig(config);
      console.log('[NavBar] CTF config loaded:', config);
    } catch (error) {
      console.error('Error fetching CTF config for navbar:', error);
      setCTFConfig({ ctf_enabled: 'false', ctf_visible_to_students: 'false' });
    }
  };

  // Fetch exercises and CTF config on component mount and user login
  useEffect(() => {
    if (user) {
      fetchVisibleExercises();
      fetchCTFConfig();
    }
  }, [user]);

  // Real-time synchronization - silent background polling for navbar updates
  useEffect(() => {
    if (!user) return;

    const interval = setInterval(() => {
      // Silent updates - fetch data without logging for smoother UX
      axios.get('/api/workshop/challenges').then(response => {
        const exercises = filterVisibleExercises(response.data.challenges);
        setExercises(exercises);
      }).catch(() => {});

      axios.get('/api/ctf/config').then(response => {
        setCTFConfig(response.data.config);
      }).catch(() => {
        // Silent fail - don't log errors for background updates
      });
    }, 60000); // Poll every 60 seconds (reduced from 15s to prevent constant refreshing)

    return () => clearInterval(interval);
  }, [user]);

  // Close dropdown when clicking outside
  useEffect(() => {
    const handleClickOutside = (event) => {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target)) {
        setDropdownOpen(false);
      }
      if (exercisesDropdownRef.current && !exercisesDropdownRef.current.contains(event.target)) {
        setExercisesDropdownOpen(false);
      }
      if (ctfDropdownRef.current && !ctfDropdownRef.current.contains(event.target)) {
        setCTFDropdownOpen(false);
      }
    };

    document.addEventListener('mousedown', handleClickOutside);
    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
    };
  }, []);

  const toggleDropdown = () => {
    setDropdownOpen(!dropdownOpen);
  };

  const toggleExercisesDropdown = () => {
    setExercisesDropdownOpen(!exercisesDropdownOpen);
  };

  const toggleCTFDropdown = () => {
    setCTFDropdownOpen(!ctfDropdownOpen);
  };

  const getExerciseIcon = (exerciseKey) => {
    switch (exerciseKey) {
      case 'nosql_injection_workshop':
      case 'sql_injection_workshop':
        return <FiDatabase size={16} />;
      case 'sensitive_info_disclosure':
        return <FiAlertTriangle size={16} />;
      case 'excessive_agency':
        return <FiCpu size={16} />;
      case 'supply_chain_rce':
        return <FiPackage size={16} />;
      case 'direct_prompt_injection':
        return <FiShield size={16} />;
      case 'reflected_xss_llm':
        return <FiCode size={16} />;
      case 'indirect_prompt_injection':
        return <FiFileText size={16} />;
      case 'csrf_prompt_injection':
        return <FiShield size={16} />;
      case 'mcp_server_rce':
        return <FiTerminal size={16} />;
      case 'ctf_prompt_injection_challenge':
        return <FiTarget size={16} />;
      default:
        return <FiShield size={16} />;
    }
  };

  return (
    <>
      <WarningBanner>
        ⚠️ WORKSHOP MODE: This is a deliberately vulnerable application for educational purposes only!
      </WarningBanner>
      <NavbarContainer>
        <NavContent>
          <BrandSection>
            <Logo to={user ? "/workshop/challenges" : "/"}>
              <GoatBrand />
            </Logo>
          </BrandSection>

          <NavLinks $isOpen={isOpen}>
            {!user ? (
              <NavLink
                to="/"
                className={isActive('/') ? 'active' : ''}
                onClick={() => setIsOpen(false)}
              >
                <FiHome size={16} />
                Workshop Home
              </NavLink>
            ) : (
              <>
                <NavLink
                  to="/workshop/challenges"
                  className={isActive('/workshop/challenges') ? 'active' : ''}
                  aria-current={isActive('/workshop/challenges') ? 'page' : undefined}
                  onClick={() => {
                    setIsOpen(false);
                    setTimeout(() => {
                      window.scrollTo({ top: 0, behavior: 'smooth' });
                    }, 100);
                  }}
                >
                  <FiHome size={16} />
                  Student Dashboard
                </NavLink>

                {/* Show "Back to Admin" button if user is admin and came from admin panel */}
                {hasPlatformAdminLevel(user) &&
                 sessionStorage.getItem('adminReturnPath') && (
                  <NavLink
                    to={sessionStorage.getItem('adminReturnPath') || '/admin/dashboard'}
                    onClick={() => {
                      setIsOpen(false);
                      sessionStorage.removeItem('adminReturnPath');
                    }}
                    style={{
                      background: 'rgba(251, 191, 36, 0.15)',
                      border: '1px solid rgba(251, 191, 36, 0.3)',
                      color: '#fbbf24'
                    }}
                  >
                    <FiSettings size={16} />
                    ← Back to Admin
                  </NavLink>
                )}

                {(
                  <ProfileDropdown ref={exercisesDropdownRef}>
                    <ProfileToggle onClick={toggleExercisesDropdown} aria-label="Exercises menu" aria-expanded={exercisesDropdownOpen}>
                      <FiTarget size={16} />
                      <span>Exercises ({exercises.length})</span>
                      <FiChevronDown size={16} style={{
                        transform: exercisesDropdownOpen ? 'rotate(180deg)' : 'rotate(0deg)',
                        transition: 'transform 0.3s ease'
                      }} />
                    </ProfileToggle>

                    <DropdownMenu isOpen={exercisesDropdownOpen}>
                      <DropdownLink
                        to="/workshop/challenges"
                        onClick={() => {
                          setExercisesDropdownOpen(false);
                          setIsOpen(false);
                        }}
                      >
                        <FiTarget size={16} />
                        All exercises
                      </DropdownLink>
                      <DropdownDivider />
                      {exercises.slice(0, 6).map(exercise => exercise.status === 'locked' ? (
                        <DropdownItem key={exercise.id} disabled
                          title={`${exercise.title}: no enabled objectives`}
                          style={{ color: '#718096', cursor: 'not-allowed', opacity: 0.75 }}
                        >
                          <FiLock size={16} />
                          {exercise.title.length > 25 ? exercise.title.substring(0, 25) + '...' : exercise.title}
                          <span style={{ fontSize: '0.7rem' }}>Locked</span>
                        </DropdownItem>
                      ) : (
                        <DropdownLink
                          key={exercise.id}
                          to={exercise.route}
                          onClick={() => {
                            setExercisesDropdownOpen(false);
                            setIsOpen(false);
                            setTimeout(() => {
                              window.scrollTo({ top: 0, behavior: 'smooth' });
                            }, 100);
                          }}
                        >
                          {getExerciseIcon(exercise.id)}
                          {exercise.title.length > 25 ? exercise.title.substring(0, 25) + '...' : exercise.title}
                        </DropdownLink>
                      ))}
                      {exercises.length > 6 && (
                        <>
                          <DropdownDivider />
                          <DropdownLink
                            to="/workshop/challenges"
                            onClick={() => {
                              setExercisesDropdownOpen(false);
                              setIsOpen(false);
                              setTimeout(() => {
                                window.scrollTo({ top: 0, behavior: 'smooth' });
                              }, 100);
                            }}
                          >
                            <FiTarget size={16} />
                            Browse all {exercises.length} exercises
                          </DropdownLink>
                        </>
                      )}
                    </DropdownMenu>
                  </ProfileDropdown>
                )}
                <NavLink
                  to="/secureshop"
                  className={location.pathname.startsWith('/secureshop') ? 'active' : ''}
                  onClick={() => setIsOpen(false)}
                >
                  <FiPackage size={16} />
                  SecureShop
                </NavLink>
                <NavLink
                  to="/workshop/agent-runs"
                  className={isActive('/workshop/agent-runs') ? 'active' : ''}
                  onClick={() => setIsOpen(false)}
                >
                  <FiActivity size={16} />
                  Agent Runs
                </NavLink>

                {/* CTF Prompt Injection Challenge */}
                {ctfConfig && ctfConfig.ctf_enabled === 'true' && ctfConfig.ctf_visible_to_students === 'true' && (
                  <ProfileDropdown ref={ctfDropdownRef}>
                    <ProfileToggle onClick={toggleCTFDropdown}>
                      <FiTarget size={16} />
                      <span>CTF Challenge</span>
                      <FiChevronDown size={16} style={{
                        transform: ctfDropdownOpen ? 'rotate(180deg)' : 'rotate(0deg)',
                        transition: 'transform 0.3s ease'
                      }} />
                    </ProfileToggle>

                    <DropdownMenu isOpen={ctfDropdownOpen}>
                      <DropdownLink
                        to="/ctf"
                        onClick={() => {
                          setCTFDropdownOpen(false);
                          setIsOpen(false);
                          setTimeout(() => { window.scrollTo({ top: 0, behavior: 'smooth' }); }, 100);
                        }}
                      >
                        <FiTarget size={16} />
                        CTF Dashboard
                      </DropdownLink>
                      {ctfConfig.student_leaderboard_visible === 'true' && (
                        <>
                          <DropdownDivider />
                          <DropdownLink
                            to="/ctf/leaderboard"
                            onClick={() => {
                              setCTFDropdownOpen(false);
                              setIsOpen(false);
                              setTimeout(() => { window.scrollTo({ top: 0, behavior: 'smooth' }); }, 100);
                            }}
                          >
                            <FiAward size={16} />
                            Leaderboard
                          </DropdownLink>
                        </>
                      )}
                    </DropdownMenu>
                  </ProfileDropdown>
                )}
              </>
            )}
          </NavLinks>

          <UserSection>
            {user ? (
              <ProfileDropdown ref={dropdownRef}>
                <ProfileToggle onClick={toggleDropdown} aria-label="Account menu" aria-expanded={dropdownOpen}>
                  <UserAvatar>
                    {user.username?.charAt(0).toUpperCase()}
                  </UserAvatar>
                  <UserDetails>
                    <Username>{user.username}</Username>
                    <UserRole>Student</UserRole>
                  </UserDetails>
                  <FiChevronDown size={16} style={{
                    transform: dropdownOpen ? 'rotate(180deg)' : 'rotate(0deg)',
                    transition: 'transform 0.3s ease'
                  }} />
                </ProfileToggle>

                <DropdownMenu isOpen={dropdownOpen}>
                  <DropdownLink to="/workshop/profile" onClick={() => setDropdownOpen(false)}>
                    <FiUser size={16} />
                    Profile
                  </DropdownLink>
                  <DropdownLink to="/workshop/edit-profile" onClick={() => setDropdownOpen(false)}>
                    <FiSettings size={16} />
                    Edit Profile
                  </DropdownLink>
                  <DropdownLink to="/workshop/user-activity" onClick={() => setDropdownOpen(false)}>
                    <FiTarget size={16} />
                    User Activity
                  </DropdownLink>
                  <DropdownDivider />
                  <DropdownItem onClick={handleLogout}>
                    <FiLogOut size={16} />
                    Logout
                  </DropdownItem>
                </DropdownMenu>
              </ProfileDropdown>
            ) : (
              <NavLink to="/login" onClick={() => setIsOpen(false)}>
                <FiUser size={16} />
                Login
              </NavLink>
            )}
          </UserSection>

          <MobileToggle onClick={() => setIsOpen(!isOpen)} aria-label={isOpen ? 'Close navigation' : 'Open navigation'} aria-expanded={isOpen}>
            {isOpen ? <FiX /> : <FiMenu />}
          </MobileToggle>
        </NavContent>
      </NavbarContainer>
    </>
  );
};

export default WorkshopNavbar;
