import { hasPlatformAdminLevel } from '../utils/platformAdmin';
import React, { useState, useEffect } from 'react';
import { useNavigate, useLocation, Link } from 'react-router-dom';
import { FiShield, FiUser, FiLock, FiEye, FiEyeOff, FiArrowLeft, FiRefreshCw } from 'react-icons/fi';
import styled from 'styled-components';
import { motion } from 'framer-motion';
import { useAuth } from '../context/AuthContext';
import { toast } from 'react-toastify';
import axios from 'axios';

const LoginContainer = styled.div`
  min-height: 100vh;
  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 2rem;
  position: relative;
`;

const BackgroundPattern = styled.div`
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background-image: 
    radial-gradient(circle at 25% 25%, rgba(255, 255, 255, 0.1) 0%, transparent 50%),
    radial-gradient(circle at 75% 75%, rgba(255, 255, 255, 0.1) 0%, transparent 50%);
  pointer-events: none;
`;

const LoginWrapper = styled.div`
  max-width: 500px;
  width: 100%;
`;

const LoginCard = styled(motion.div)`
  background: rgba(255, 255, 255, 0.95);
  backdrop-filter: blur(20px);
  border-radius: 24px;
  padding: 3rem;
  box-shadow: 0 20px 60px rgba(0, 0, 0, 0.2);
  border: 1px solid rgba(255, 255, 255, 0.2);
`;

const BackButton = styled.button`
  position: absolute;
  top: 2rem;
  left: 2rem;
  background: rgba(255, 255, 255, 0.2);
  backdrop-filter: blur(10px);
  border: none;
  color: white;
  cursor: pointer;
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.75rem 1.5rem;
  border-radius: 12px;
  font-weight: 600;
  transition: all 0.3s ease;
  
  &:hover {
    background: rgba(255, 255, 255, 0.3);
    transform: translateX(-5px);
  }
`;

const CardHeader = styled.div`
  text-align: center;
  margin-bottom: 2rem;
`;

const CardIcon = styled.div`
  width: 80px;
  height: 80px;
  border-radius: 20px;
  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
  display: flex;
  align-items: center;
  justify-content: center;
  margin: 0 auto 1.5rem;
  font-size: 2.5rem;
  color: white;
  box-shadow: 0 10px 30px rgba(102, 126, 234, 0.3);
`;

const CardTitle = styled.h1`
  color: #333;
  font-size: 2rem;
  font-weight: 700;
  margin-bottom: 0.5rem;
`;

const CardSubtitle = styled.p`
  color: #666;
  font-size: 1.1rem;
  line-height: 1.6;
`;

const TabContainer = styled.div`
  display: flex;
  margin-bottom: 2rem;
  border-radius: 16px;
  overflow: hidden;
  background: #f8f9fa;
  padding: 0.25rem;
`;

const Tab = styled.button`
  flex: 1;
  padding: 1rem;
  border: none;
  background: ${props => props.$active ? 'white' : 'transparent'};
  color: ${props => props.$active ? '#667eea' : '#666'};
  font-weight: 600;
  cursor: pointer;
  transition: all 0.3s ease;
  border-radius: 12px;
  box-shadow: ${props => props.$active ? '0 2px 10px rgba(0, 0, 0, 0.1)' : 'none'};
`;

const Form = styled.form`
  display: flex;
  flex-direction: column;
  gap: 1.5rem;
`;

const InputGroup = styled.div`
  position: relative;
`;

const Label = styled.label`
  display: block;
  color: #333;
  font-weight: 600;
  margin-bottom: 0.75rem;
  font-size: 0.95rem;
`;

const InputWrapper = styled.div`
  position: relative;
`;

const InputIcon = styled.div`
  position: absolute;
  left: 1.25rem;
  top: 50%;
  transform: translateY(-50%);
  color: #666;
  font-size: 1.1rem;
`;

const Input = styled.input`
  width: 100%;
  padding: 1.25rem 1.25rem 1.25rem 3.5rem;
  border: 2px solid #e9ecef;
  border-radius: 16px;
  font-size: 1rem;
  transition: all 0.3s ease;
  background: #fafafa;
  
  &:focus {
    outline: none;
    border-color: #667eea;
    background: white;
    box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
  }
  
  &::placeholder {
    color: #999;
  }
`;

const TogglePassword = styled.button`
  position: absolute;
  right: 1.25rem;
  top: 50%;
  transform: translateY(-50%);
  background: none;
  border: none;
  color: #666;
  cursor: pointer;
  padding: 0.5rem;
  border-radius: 8px;
  transition: color 0.3s ease;
  
  &:hover {
    color: #667eea;
  }
`;

const SubmitButton = styled.button`
  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
  color: white;
  border: none;
  padding: 1.25rem;
  border-radius: 16px;
  font-size: 1.1rem;
  font-weight: 700;
  cursor: pointer;
  transition: all 0.3s ease;
  box-shadow: 0 8px 25px rgba(102, 126, 234, 0.3);
  
  &:hover {
    transform: translateY(-2px);
    box-shadow: 0 12px 35px rgba(102, 126, 234, 0.4);
  }
  
  &:disabled {
    opacity: 0.6;
    cursor: not-allowed;
    transform: none;
  }
`;


const WorkshopLogin = ({ application = 'workshop' }) => {
  const isSecureShop = application === 'secureshop';
  const navigate = useNavigate();
  const location = useLocation();
  const [activeTab, setActiveTab] = useState('login');
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const { login, register } = useAuth();
  
  const [loginData, setLoginData] = useState({
    username: '',
    password: ''
  });
  
  const [registerData, setRegisterData] = useState({
    username: '',
    email: '',
    password: '',
    confirmPassword: ''
  });

  // Random email button state
  const [randomEmailEnabled, setRandomEmailEnabled] = useState(false);
  const [registrationEnabled, setRegistrationEnabled] = useState(true);
  const [captchaRequired, setCaptchaRequired] = useState(false);
  const [captchaData, setCaptchaData] = useState(null);
  const [captchaAnswer, setCaptchaAnswer] = useState('');

  const fetchCaptcha = () => {
    axios.get('/api/auth/captcha')
      .then(res => { setCaptchaData(res.data); setCaptchaAnswer(''); })
      .catch(() => setCaptchaData(null));
  };

  // Fetch signup config on mount
  useEffect(() => {
    axios.get('/api/auth/signup-config')
      .then(res => {
        setRandomEmailEnabled(res.data.randomEmailEnabled === true);
        setRegistrationEnabled(res.data.registrationEnabled !== false);
        const needsCaptcha = res.data.captchaRequired === true;
        setCaptchaRequired(needsCaptcha);
        if (needsCaptcha) fetchCaptcha();
      })
      .catch(() => {
        setRandomEmailEnabled(false);
        setRegistrationEnabled(true);
      });
  }, []);

  // Generate random email function
  const generateRandomEmail = () => {
    const randomStr = Math.random().toString(36).slice(2, 8);
    const email = `user_${randomStr}@demo.local`;
    setRegisterData(prev => ({ ...prev, email }));
  };

  // Check for success message from signup page
  useEffect(() => {
    if (location.state?.message) {
      toast.success(location.state.message);
      if (location.state.username) {
        setLoginData(prev => ({ ...prev, username: location.state.username }));
      }
    }
  }, [location]);

  const handleLogin = async (e) => {
    e.preventDefault();
    setLoading(true);
    
    try {
      const result = await login(loginData.username, loginData.password);
      if (result.success) {
        const user = result.user; // Use the user data returned from login
        
        // Enhanced role-based redirection using the returned user data
        if (isSecureShop) {
          toast.success('Welcome to OWASP AI SecureShop!');
          navigate('/secureshop', { replace: true });
        } else if (hasPlatformAdminLevel(user)) {
          toast.success(`Welcome back, ${user.fullName || user.username}! Redirecting to Admin Dashboard...`);
          navigate('/admin/dashboard'); // Use the new admin route
        } else {
          toast.success('Welcome to the Security Workshop!');
          navigate('/workshop/challenges', { replace: true });
        }
      } else {
        toast.error(result.error || 'Login failed. Please check your credentials.');
      }
    } catch (error) {
      console.error('Login error:', error);
      toast.error('Login failed. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const handleRegister = async (e) => {
    e.preventDefault();

    const uname = (registerData.username || '').trim();
    if (!uname || uname.length < 3 || uname.length > 50) {
      toast.error('Username must be between 3 and 50 characters');
      return;
    }
    if (!/^[a-zA-Z0-9_-]+$/.test(uname)) {
      toast.error('Username can only contain letters, numbers, underscore, and hyphen');
      return;
    }

    if (registerData.password !== registerData.confirmPassword) {
      toast.error('Passwords do not match');
      return;
    }

    if (registerData.password.length < 8) {
      toast.error('Password must be at least 8 characters long');
      return;
    }

    setLoading(true);

    try {
      const payload = {
        username: uname,
        email: registerData.email,
        password: registerData.password
      };
      if (captchaRequired && captchaData) {
        payload.captchaId = captchaData.captchaId;
        payload.captchaAnswer = captchaAnswer;
      }
      const result = await register(payload);
      
      if (result.success) {
        toast.success('Registration successful! Please login with your new account.');
        setActiveTab('login');
        setRegisterData({ username: '', email: '', password: '', confirmPassword: '' });
        setCaptchaAnswer('');
      } else {
        if (result.details?.captchaRequired || result.error?.includes?.('Captcha')) {
          setCaptchaRequired(true);
          fetchCaptcha();
        }
        toast.error(result.error || 'Registration failed. Please try again.');
      }
    } catch (error) {
      console.error('Registration error:', error);
      toast.error('Registration failed. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <LoginContainer>
      <BackgroundPattern />
      
      <BackButton onClick={() => navigate('/')}>
        <FiArrowLeft />
        Back to Platform Selection
      </BackButton>
      
      <LoginWrapper>
        <LoginCard
          initial={{ opacity: 0, x: -50 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ duration: 0.8 }}
        >
          <CardHeader>
            <CardIcon>
              <FiShield />
            </CardIcon>
            <CardTitle>{isSecureShop ? 'OWASP AI SecureShop Access' : 'Workshop Access'}</CardTitle>
            <CardSubtitle>
              {isSecureShop
                ? 'Sign in with your platform account to open your OWASP AI SecureShop environment. Shop practice accounts are used inside the shop.'
                : 'Enter your credentials to access the security learning environment'}
            </CardSubtitle>
          </CardHeader>
          
          <TabContainer>
            <Tab
              $active={activeTab === 'login'}
              onClick={() => setActiveTab('login')}
            >
              Login
            </Tab>
            {registrationEnabled && (
              <Tab
                $active={activeTab === 'register'}
                onClick={() => setActiveTab('register')}
              >
                Register
              </Tab>
            )}
          </TabContainer>

          {activeTab === 'login' ? (
            <Form onSubmit={handleLogin}>
              <InputGroup>
                <Label>Username</Label>
                <InputWrapper>
                  <InputIcon><FiUser /></InputIcon>
                  <Input
                    type="text"
                    placeholder="Enter your username"
                    value={loginData.username}
                    onChange={(e) => { const value = e.target.value; setLoginData(previous => ({ ...previous, username: value })); }}
                    required
                  />
                </InputWrapper>
              </InputGroup>
              
              <InputGroup>
                <Label>Password</Label>
                <InputWrapper>
                  <InputIcon><FiLock /></InputIcon>
                  <Input
                    type={showPassword ? 'text' : 'password'}
                    placeholder="Enter your password"
                    value={loginData.password}
                    onChange={(e) => { const value = e.target.value; setLoginData(previous => ({ ...previous, password: value })); }}
                    required
                  />
                  <TogglePassword
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                  >
                    {showPassword ? <FiEyeOff /> : <FiEye />}
                  </TogglePassword>
                </InputWrapper>
              </InputGroup>
              
              <SubmitButton type="submit" disabled={loading}>
                {loading ? 'Signing In...' : isSecureShop ? 'Enter OWASP AI SecureShop' : 'Enter Workshop'}
              </SubmitButton>
              
              {registrationEnabled && (
                <div style={{
                  textAlign: 'center',
                  marginTop: '1.5rem',
                  paddingTop: '1.5rem',
                  borderTop: '1px solid #e5e7eb'
                }}>
                  <p style={{ color: '#6b7280', fontSize: '14px', marginBottom: '0.5rem' }}>
                    Don't have an account?
                  </p>
                  <Link
                    to={isSecureShop ? '/secureshop/login' : '/workshop/signup'}
                    onClick={isSecureShop ? (event) => { event.preventDefault(); setActiveTab('register'); } : undefined}
                    style={{
                      color: '#667eea',
                      textDecoration: 'none',
                      fontWeight: '600',
                      fontSize: '15px',
                      transition: 'color 0.2s'
                    }}
                    onMouseEnter={(e) => e.target.style.color = '#764ba2'}
                    onMouseLeave={(e) => e.target.style.color = '#667eea'}
                  >
                    Create a New Account →
                  </Link>
                </div>
              )}
            </Form>
          ) : (
            <Form onSubmit={handleRegister}>
              <InputGroup>
                <Label>Username</Label>
                <InputWrapper>
                  <InputIcon><FiUser /></InputIcon>
                  <Input
                    type="text"
                    placeholder="Choose a username"
                    value={registerData.username}
                    onChange={(e) => { const value = e.target.value; setRegisterData(previous => ({ ...previous, username: value })); }}
                    required
                  />
                </InputWrapper>
              </InputGroup>
              
              <InputGroup>
                <Label>Email</Label>
                <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'stretch' }}>
                  <InputWrapper style={{ flex: 1 }}>
                    <InputIcon>@</InputIcon>
                    <Input
                      type="email"
                      placeholder="Enter your email"
                      value={registerData.email}
                      onChange={(e) => { const value = e.target.value; setRegisterData(previous => ({ ...previous, email: value })); }}
                      required
                    />
                  </InputWrapper>
                  {randomEmailEnabled && (
                    <button
                      type="button"
                      onClick={generateRandomEmail}
                      disabled={loading}
                      style={{
                        background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
                        color: 'white',
                        border: 'none',
                        borderRadius: '12px',
                        padding: '0 1rem',
                        cursor: 'pointer',
                        display: 'flex',
                        alignItems: 'center',
                        gap: '0.5rem',
                        fontSize: '0.85rem',
                        fontWeight: '500',
                        whiteSpace: 'nowrap',
                        transition: 'transform 0.2s, box-shadow 0.2s',
                        boxShadow: '0 4px 15px rgba(102, 126, 234, 0.3)'
                      }}
                      onMouseOver={(e) => e.target.style.transform = 'translateY(-2px)'}
                      onMouseOut={(e) => e.target.style.transform = 'translateY(0)'}
                    >
                      <FiRefreshCw size={14} />
                      Random
                    </button>
                  )}
                </div>
              </InputGroup>
              
              <InputGroup>
                <Label>Password</Label>
                <InputWrapper>
                  <InputIcon><FiLock /></InputIcon>
                  <Input
                    type={showPassword ? 'text' : 'password'}
                    placeholder="Create a password"
                    value={registerData.password}
                    onChange={(e) => { const value = e.target.value; setRegisterData(previous => ({ ...previous, password: value })); }}
                    required
                  />
                  <TogglePassword
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                  >
                    {showPassword ? <FiEyeOff /> : <FiEye />}
                  </TogglePassword>
                </InputWrapper>
              </InputGroup>
              
              <InputGroup>
                <Label>Confirm Password</Label>
                <InputWrapper>
                  <InputIcon><FiLock /></InputIcon>
                  <Input
                    type="password"
                    placeholder="Confirm your password"
                    value={registerData.confirmPassword}
                    onChange={(e) => { const value = e.target.value; setRegisterData(previous => ({ ...previous, confirmPassword: value })); }}
                    required
                  />
                </InputWrapper>
              </InputGroup>

              {captchaRequired && captchaData && (
                <InputGroup>
                  <Label>{captchaData.question}</Label>
                  <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'stretch' }}>
                    <InputWrapper style={{ flex: 1 }}>
                      <InputIcon><FiShield /></InputIcon>
                      <Input
                        type="text"
                        placeholder="Your answer"
                        value={captchaAnswer}
                        onChange={(e) => setCaptchaAnswer(e.target.value)}
                        required
                      />
                    </InputWrapper>
                    <button
                      type="button"
                      onClick={fetchCaptcha}
                      style={{
                        background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
                        color: 'white', border: 'none', borderRadius: '12px',
                        padding: '0 1rem', cursor: 'pointer', display: 'flex',
                        alignItems: 'center', gap: '0.4rem', fontSize: '0.85rem', fontWeight: '500'
                      }}
                    >
                      <FiRefreshCw size={14} /> New
                    </button>
                  </div>
                </InputGroup>
              )}

              <SubmitButton type="submit" disabled={loading}>
                {loading ? 'Creating Account...' : isSecureShop ? 'Create Platform Account' : 'Join Workshop'}
              </SubmitButton>
            </Form>
          )}
        </LoginCard>
      </LoginWrapper>
    </LoginContainer>
  );
};

export default WorkshopLogin;