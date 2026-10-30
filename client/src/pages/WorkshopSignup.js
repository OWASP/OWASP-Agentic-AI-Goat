import React, { useState, useEffect } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import axios from 'axios';
import '../styles/WorkshopAuth.css';

const WorkshopSignup = () => {
  const navigate = useNavigate();
  const [formData, setFormData] = useState({
    username: '',
    email: '',
    password: '',
    confirmPassword: '',
    fullName: '',
    department: '',
    phone: ''
  });
  
  const [errors, setErrors] = useState({});
  const [loading, setLoading] = useState(false);
  const [passwordStrength, setPasswordStrength] = useState({
    strength: 'none',
    message: '',
    color: '#ccc'
  });
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [successMessage, setSuccessMessage] = useState('');
  const [randomEmailEnabled, setRandomEmailEnabled] = useState(false);
  const [registrationEnabled, setRegistrationEnabled] = useState(null);
  const [captchaRequired, setCaptchaRequired] = useState(false);
  const [captchaData, setCaptchaData] = useState(null);
  const [captchaAnswer, setCaptchaAnswer] = useState('');

  const fetchCaptcha = () => {
    axios.get('/api/auth/captcha')
      .then(res => { setCaptchaData(res.data); setCaptchaAnswer(''); })
      .catch(() => setCaptchaData(null));
  };

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
        setRegistrationEnabled(false);
      });
  }, []);

  useEffect(() => {
    if (registrationEnabled === false) {
      navigate('/workshop-login', { state: { message: 'Registration is currently disabled.' } });
    }
  }, [registrationEnabled, navigate]);

  const generateRandomEmail = () => {
    const randomStr = Math.random().toString(36).slice(2, 8);
    const email = `user_${randomStr}@demo.local`;
    setFormData(prev => ({ ...prev, email }));
    if (errors.email) setErrors(prev => ({ ...prev, email: '' }));
  };

  // Calculate password strength
  const calculatePasswordStrength = (password) => {
    if (!password) {
      return { strength: 'none', message: '', color: '#ccc' };
    }

    let score = 0;
    const checks = {
      length: password.length >= 8,
      lowercase: /[a-z]/.test(password),
      uppercase: /[A-Z]/.test(password),
      numbers: /[0-9]/.test(password),
      special: /[^a-zA-Z0-9]/.test(password)
    };

    // Count passed checks
    Object.values(checks).forEach(check => {
      if (check) score++;
    });

    if (score < 3) {
      return { strength: 'weak', message: 'Weak password', color: '#f44336' };
    } else if (score < 4) {
      return { strength: 'medium', message: 'Medium strength', color: '#ff9800' };
    } else if (score < 5) {
      return { strength: 'good', message: 'Good password', color: '#2196f3' };
    } else {
      return { strength: 'strong', message: 'Strong password', color: '#4caf50' };
    }
  };

  // Handle input changes
  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData(prev => ({
      ...prev,
      [name]: value
    }));

    // Clear field-specific error
    if (errors[name]) {
      setErrors(prev => ({
        ...prev,
        [name]: ''
      }));
    }

    // Update password strength
    if (name === 'password') {
      setPasswordStrength(calculatePasswordStrength(value));
    }
  };

  // Validate form
  const validateForm = () => {
    const newErrors = {};

    // Username validation
    if (!formData.username) {
      newErrors.username = 'Username is required';
    } else if (formData.username.length < 3) {
      newErrors.username = 'Username must be at least 3 characters';
    } else if (!/^[a-zA-Z0-9_-]+$/.test(formData.username)) {
      newErrors.username = 'Username can only contain letters, numbers, underscore, and hyphen';
    }

    // Email validation
    if (!formData.email) {
      newErrors.email = 'Email is required';
    } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(formData.email)) {
      newErrors.email = 'Please enter a valid email address';
    }

    // Password validation
    if (!formData.password) {
      newErrors.password = 'Password is required';
    } else if (formData.password.length < 8) {
      newErrors.password = 'Password must be at least 8 characters';
    } else if (!/[a-z]/.test(formData.password)) {
      newErrors.password = 'Password must contain at least one lowercase letter';
    } else if (!/[A-Z]/.test(formData.password)) {
      newErrors.password = 'Password must contain at least one uppercase letter';
    } else if (!/[0-9]/.test(formData.password)) {
      newErrors.password = 'Password must contain at least one number';
    } else if (!/[^a-zA-Z0-9]/.test(formData.password)) {
      newErrors.password = 'Password must contain at least one special character';
    }

    // Confirm password validation
    if (!formData.confirmPassword) {
      newErrors.confirmPassword = 'Please confirm your password';
    } else if (formData.password !== formData.confirmPassword) {
      newErrors.confirmPassword = 'Passwords do not match';
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  // Handle form submission
  const handleSubmit = async (e) => {
    e.preventDefault();
    
    if (!validateForm()) {
      return;
    }

    setLoading(true);
    setErrors({});

    try {
      const payload = {
        username: formData.username,
        email: formData.email,
        password: formData.password,
        fullName: formData.fullName,
        department: formData.department,
        phone: formData.phone
      };
      if (captchaRequired && captchaData) {
        payload.captchaId = captchaData.captchaId;
        payload.captchaAnswer = captchaAnswer;
      }
      const response = await axios.post('http://localhost:8081/api/auth/register', payload);

      if (response.data.success) {
        setSuccessMessage('Account created successfully! Redirecting to login...');
        
        // Show success message for 2 seconds then redirect
        setTimeout(() => {
          navigate('/workshop/login', { 
            state: { 
              message: 'Registration successful! Please login with your credentials.',
              username: formData.username
            }
          });
        }, 2000);
      }
    } catch (error) {
      console.error('Registration error:', error);
      
      if (error.response?.data?.error) {
        const errorMessage = error.response.data.message || error.response.data.error;

        if (error.response.data.captchaRequired) {
          setCaptchaRequired(true);
          fetchCaptcha();
        }

        if (errorMessage.includes('username')) {
          setErrors({ username: errorMessage });
        } else if (errorMessage.includes('email')) {
          setErrors({ email: errorMessage });
        } else if (errorMessage.includes('password')) {
          setErrors({ password: errorMessage });
        } else if (errorMessage.includes('aptcha')) {
          setErrors({ captcha: errorMessage });
        } else {
          setErrors({ submit: errorMessage });
        }
      } else if (error.response?.status === 429) {
        setErrors({ submit: 'Too many registration attempts. Please try again later.' });
      } else {
        setErrors({ submit: 'Registration failed. Please try again.' });
      }
    } finally {
      setLoading(false);
    }
  };

  if (registrationEnabled === null) return null;

  return (
    <div className="workshop-auth-container">
      <div className="auth-card">
        <div className="auth-header">
          <div className="auth-icon">
            <svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
              <path d="M16 7C16 9.20914 14.2091 11 12 11C9.79086 11 8 9.20914 8 7C8 4.79086 9.79086 3 12 3C14.2091 3 16 4.79086 16 7Z" stroke="currentColor" strokeWidth="2"/>
              <path d="M12 14C8.13401 14 5 17.134 5 21H19C19 17.134 15.866 14 12 14Z" stroke="currentColor" strokeWidth="2"/>
            </svg>
          </div>
          <h1 className="auth-title">Create Workshop Account</h1>
          <p className="auth-subtitle">Join the OWASP Agentic AI GOAT workshop</p>
          
          {/* Security badge */}
          <div className="security-badge">
            <svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
              <path d="M12 2L3 7V11C3 16.55 6.84 21.74 12 23C17.16 21.74 21 16.55 21 11V7L12 2Z" 
                    stroke="currentColor" strokeWidth="2" fill="none"/>
              <path d="M9 12L11 14L15 10" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/>
            </svg>
            <span>Secure Registration - Your data is protected</span>
          </div>
        </div>

        {successMessage && (
          <div className="alert alert-success">
            <svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
              <path d="M9 12L11 14L15 10M21 12C21 16.9706 16.9706 21 12 21C7.02944 21 3 16.9706 3 12C3 7.02944 7.02944 3 12 3C16.9706 3 21 7.02944 21 12Z" 
                    stroke="currentColor" strokeWidth="2" strokeLinecap="round"/>
            </svg>
            {successMessage}
          </div>
        )}

        {errors.submit && (
          <div className="alert alert-error">
            <svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
              <path d="M12 8V12M12 16H12.01M21 12C21 16.9706 16.9706 21 12 21C7.02944 21 3 16.9706 3 12C3 7.02944 7.02944 3 12 3C16.9706 3 21 7.02944 21 12Z" 
                    stroke="currentColor" strokeWidth="2" strokeLinecap="round"/>
            </svg>
            {errors.submit}
          </div>
        )}

        <form onSubmit={handleSubmit} className="auth-form">
          {/* Username */}
          <div className="form-group">
            <label htmlFor="username" className="form-label">
              Username *
            </label>
            <input
              type="text"
              id="username"
              name="username"
              value={formData.username}
              onChange={handleChange}
              className={`form-input ${errors.username ? 'error' : ''}`}
              placeholder="Choose a username"
              disabled={loading}
            />
            {errors.username && <span className="error-message">{errors.username}</span>}
            <span className="input-hint">3-50 characters, letters, numbers, underscore, hyphen</span>
          </div>

          {/* Email */}
          <div className="form-group">
            <label htmlFor="email" className="form-label">
              Email Address *
            </label>
            <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'stretch' }}>
              <input
                type="email"
                id="email"
                name="email"
                value={formData.email}
                onChange={handleChange}
                className={`form-input ${errors.email ? 'error' : ''}`}
                placeholder="your.email@example.com"
                disabled={loading}
                style={{ flex: 1 }}
              />
              {randomEmailEnabled && (
                <button
                  type="button"
                  onClick={generateRandomEmail}
                  disabled={loading}
                  className="submit-btn"
                  style={{ whiteSpace: 'nowrap', padding: '0.75rem 1rem', fontSize: '0.9rem' }}
                >
                  Generate random email
                </button>
              )}
            </div>
            {errors.email && <span className="error-message">{errors.email}</span>}
          </div>

          {/* Password */}
          <div className="form-group">
            <label htmlFor="password" className="form-label">
              Password *
            </label>
            <div className="password-input-wrapper">
              <input
                type={showPassword ? 'text' : 'password'}
                id="password"
                name="password"
                value={formData.password}
                onChange={handleChange}
                className={`form-input ${errors.password ? 'error' : ''}`}
                placeholder="Create a strong password"
                disabled={loading}
              />
              <button
                type="button"
                className="password-toggle"
                onClick={() => setShowPassword(!showPassword)}
                tabIndex={-1}
              >
                {showPassword ? (
                  <svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                    <path d="M13.875 18.825A10.05 10.05 0 0112 19c-4.478 0-8.268-2.943-9.543-7a9.97 9.97 0 011.563-3.029m5.858.908a3 3 0 114.243 4.243M9.878 9.878l4.242 4.242M9.88 9.88l-3.29-3.29m7.532 7.532l3.29 3.29M3 3l3.59 3.59m0 0A9.953 9.953 0 0112 5c4.478 0 8.268 2.943 9.543 7a10.025 10.025 0 01-4.132 5.411m0 0L21 21" 
                          stroke="currentColor" strokeWidth="2" strokeLinecap="round"/>
                  </svg>
                ) : (
                  <svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                    <path d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" stroke="currentColor" strokeWidth="2"/>
                    <path d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" 
                          stroke="currentColor" strokeWidth="2"/>
                  </svg>
                )}
              </button>
            </div>
            {errors.password && <span className="error-message">{errors.password}</span>}
            
            {/* Password strength indicator */}
            {formData.password && (
              <div className="password-strength">
                <div className="strength-bar">
                  <div 
                    className={`strength-fill strength-${passwordStrength.strength}`}
                    style={{ 
                      width: passwordStrength.strength === 'weak' ? '25%' :
                             passwordStrength.strength === 'medium' ? '50%' :
                             passwordStrength.strength === 'good' ? '75%' : '100%',
                      backgroundColor: passwordStrength.color
                    }}
                  />
                </div>
                <span className="strength-label" style={{ color: passwordStrength.color }}>
                  {passwordStrength.message}
                </span>
              </div>
            )}
            
            <div className="password-requirements">
              <p className="requirements-title">Password must contain:</p>
              <ul className="requirements-list">
                <li className={formData.password.length >= 8 ? 'met' : ''}>
                  {formData.password.length >= 8 ? '✓' : '○'} At least 8 characters
                </li>
                <li className={/[a-z]/.test(formData.password) ? 'met' : ''}>
                  {/[a-z]/.test(formData.password) ? '✓' : '○'} One lowercase letter
                </li>
                <li className={/[A-Z]/.test(formData.password) ? 'met' : ''}>
                  {/[A-Z]/.test(formData.password) ? '✓' : '○'} One uppercase letter
                </li>
                <li className={/[0-9]/.test(formData.password) ? 'met' : ''}>
                  {/[0-9]/.test(formData.password) ? '✓' : '○'} One number
                </li>
                <li className={/[^a-zA-Z0-9]/.test(formData.password) ? 'met' : ''}>
                  {/[^a-zA-Z0-9]/.test(formData.password) ? '✓' : '○'} One special character
                </li>
              </ul>
            </div>
          </div>

          {/* Confirm Password */}
          <div className="form-group">
            <label htmlFor="confirmPassword" className="form-label">
              Confirm Password *
            </label>
            <div className="password-input-wrapper">
              <input
                type={showConfirmPassword ? 'text' : 'password'}
                id="confirmPassword"
                name="confirmPassword"
                value={formData.confirmPassword}
                onChange={handleChange}
                className={`form-input ${errors.confirmPassword ? 'error' : ''}`}
                placeholder="Re-enter your password"
                disabled={loading}
              />
              <button
                type="button"
                className="password-toggle"
                onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                tabIndex={-1}
              >
                {showConfirmPassword ? (
                  <svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                    <path d="M13.875 18.825A10.05 10.05 0 0112 19c-4.478 0-8.268-2.943-9.543-7a9.97 9.97 0 011.563-3.029m5.858.908a3 3 0 114.243 4.243M9.878 9.878l4.242 4.242M9.88 9.88l-3.29-3.29m7.532 7.532l3.29 3.29M3 3l3.59 3.59m0 0A9.953 9.953 0 0112 5c4.478 0 8.268 2.943 9.543 7a10.025 10.025 0 01-4.132 5.411m0 0L21 21" 
                          stroke="currentColor" strokeWidth="2" strokeLinecap="round"/>
                  </svg>
                ) : (
                  <svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                    <path d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" stroke="currentColor" strokeWidth="2"/>
                    <path d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" 
                          stroke="currentColor" strokeWidth="2"/>
                  </svg>
                )}
              </button>
            </div>
            {errors.confirmPassword && <span className="error-message">{errors.confirmPassword}</span>}
            {formData.confirmPassword && formData.password === formData.confirmPassword && (
              <span className="success-message">✓ Passwords match</span>
            )}
          </div>

          {/* Optional Fields */}
          <div className="optional-section">
            <p className="section-title">Optional Information</p>
            
            <div className="form-group">
              <label htmlFor="fullName" className="form-label">
                Full Name
              </label>
              <input
                type="text"
                id="fullName"
                name="fullName"
                value={formData.fullName}
                onChange={handleChange}
                className="form-input"
                placeholder="Your full name"
                disabled={loading}
              />
            </div>

            <div className="form-row">
              <div className="form-group">
                <label htmlFor="department" className="form-label">
                  Department/Organization
                </label>
                <input
                  type="text"
                  id="department"
                  name="department"
                  value={formData.department}
                  onChange={handleChange}
                  className="form-input"
                  placeholder="e.g., IT Security"
                  disabled={loading}
                />
              </div>

              <div className="form-group">
                <label htmlFor="phone" className="form-label">
                  Phone (optional)
                </label>
                <input
                  type="tel"
                  id="phone"
                  name="phone"
                  value={formData.phone}
                  onChange={handleChange}
                  className="form-input"
                  placeholder="+1 234 567 8900"
                  disabled={loading}
                />
              </div>
            </div>
          </div>

          {/* Captcha */}
          {captchaRequired && captchaData && (
            <div className="form-group" style={{ marginBottom: '1.5rem' }}>
              <label className="form-label" style={{ fontWeight: 600, marginBottom: '0.5rem', display: 'block' }}>
                {captchaData.question}
              </label>
              <div style={{ display: 'flex', gap: '0.5rem' }}>
                <input
                  type="text"
                  className="form-input"
                  placeholder="Your answer"
                  value={captchaAnswer}
                  onChange={(e) => setCaptchaAnswer(e.target.value)}
                  required
                  style={{ flex: 1, padding: '0.75rem 1rem', borderRadius: '10px', border: '2px solid #e1e5e9', fontSize: '1rem' }}
                />
                <button
                  type="button"
                  onClick={fetchCaptcha}
                  style={{
                    background: 'linear-gradient(135deg, #667eea, #764ba2)',
                    color: 'white', border: 'none', borderRadius: '10px',
                    padding: '0.75rem 1rem', cursor: 'pointer', fontSize: '0.85rem', fontWeight: 600
                  }}
                >
                  New
                </button>
              </div>
              {errors.captcha && <span className="error-text" style={{ color: '#dc3545', fontSize: '0.85rem' }}>{errors.captcha}</span>}
            </div>
          )}

          {/* Submit Button */}
          <button 
            type="submit" 
            className="submit-btn"
            disabled={loading}
          >
            {loading ? (
              <>
                <span className="spinner"></span>
                Creating Account...
              </>
            ) : (
              <>
                <svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                  <path d="M16 7C16 9.20914 14.2091 11 12 11C9.79086 11 8 9.20914 8 7C8 4.79086 9.79086 3 12 3C14.2091 3 16 4.79086 16 7Z" 
                        stroke="currentColor" strokeWidth="2"/>
                  <path d="M12 14C8.13401 14 5 17.134 5 21H19C19 17.134 15.866 14 12 14Z" 
                        stroke="currentColor" strokeWidth="2"/>
                </svg>
                Create Account
              </>
            )}
          </button>

          {/* Login Link */}
          <div className="auth-footer">
            <p>
              Already have an account?{' '}
              <Link to="/workshop/login" className="auth-link">
                Sign in here
              </Link>
            </p>
          </div>
        </form>

        {/* Security Information */}
        <div className="security-info">
          <p className="info-title">🔒 Your data is secure</p>
          <ul className="info-list">
            <li>✓ Passwords encrypted with bcrypt</li>
            <li>✓ Stored in isolated secure database</li>
            <li>✓ Protected from workshop vulnerabilities</li>
            <li>✓ Rate-limited registration (3 per hour)</li>
          </ul>
        </div>
      </div>
    </div>
  );
};

export default WorkshopSignup;

