import React, { createContext, useContext, useState, useEffect, useRef } from 'react';
import axios from 'axios';
import { projectPlatformUser } from '../utils/platformAdmin';

const AuthContext = createContext();

// Decode a JWT's exp claim (client-side, no verification) and report whether it
// is actually expired. Used to decide if a 401 should destroy the local session.
// A 401 from a *specific* feature endpoint (e.g. an admin previewing a student
// exercise in "Student View", where some workshop routes authenticate via a
// server session that may not be present on the ECS task serving the request)
// must NOT log the admin out while their platform JWT is still perfectly valid.
const isJwtExpired = (token) => {
  if (!token) return true;
  try {
    const payload = JSON.parse(atob(token.split('.')[1]));
    if (!payload.exp) return false; // no expiry claim → treat as non-expired
    // 10s skew guard
    return Date.now() >= (payload.exp * 1000) - 10000;
  } catch (_) {
    return true; // malformed token → treat as invalid
  }
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [authError, setAuthError] = useState(null);
  const authRevision = useRef(0);

  useEffect(() => {
    checkAuthStatus();
    
    // Set up axios interceptor for session management
    const token = localStorage.getItem('token');
    if (token) {
      axios.defaults.headers.common['Authorization'] = `Bearer ${token}`;
    }
    
    // Add response interceptor to handle session expiry - with proper error handling
    let responseInterceptor;
    try {
      if (axios.interceptors && axios.interceptors.response && typeof axios.interceptors.response.use === 'function') {
        responseInterceptor = axios.interceptors.response.use(
          (response) => response,
          (error) => {
            const path = window.location.pathname;
            const isLoginPage = path === '/workshop-login' || path === '/workshop/login' || path === '/secureshop/login';
            const token = localStorage.getItem('token');
            const requestHadAuth = !!error.config?.headers?.Authorization;
            // Only tear down the session when the JWT is ACTUALLY expired/invalid.
            // Otherwise a 401 from one feature endpoint (workshop preview, a route
            // whose server session isn't on this task, etc.) would wrongly wipe a
            // still-valid platform token — the exact bug that logged admins out
            // when they used Student View to try a student exercise.
            if (error.response?.status === 401 && !isLoginPage && !!token && requestHadAuth && isJwtExpired(token)) {
              localStorage.removeItem('token');
              delete axios.defaults.headers.common['Authorization'];
              setUser(null);
              if (path.startsWith('/secureshop')) {
                window.location.href = '/secureshop/login';
              } else {
                window.location.href = '/workshop-login';
              }
            }
            return Promise.reject(error);
          }
        );
      }
    } catch (interceptorError) {
      console.warn('Could not set up axios interceptor:', interceptorError);
    }
    
    // A different tab can replace or remove the platform session. Revalidate
    // the new identity before showing any previous user's workshop state.
    const onStorage = event => {
      if (event.storageArea !== localStorage || (event.key !== 'token' && event.key !== null)) return;
      authRevision.current += 1;
      setUser(null);
      setAuthError(null);
      if (!localStorage.getItem('token')) {
        delete axios.defaults.headers.common['Authorization'];
        setLoading(false);
      } else {
        checkAuthStatus();
      }
    };
    window.addEventListener('storage', onStorage);
    return () => {
      window.removeEventListener('storage', onStorage);
      authRevision.current += 1;
      if (responseInterceptor && axios.interceptors && axios.interceptors.response && typeof axios.interceptors.response.eject === 'function') {
        try {
          axios.interceptors.response.eject(responseInterceptor);
        } catch (ejectError) {
          console.warn('Could not eject axios interceptor:', ejectError);
        }
      }
    };
  }, []);

  const checkAuthStatus = async () => {
    const revision = ++authRevision.current;
    const token = localStorage.getItem('token');
    const isCurrent = () => revision === authRevision.current && token === localStorage.getItem('token');
    setAuthError(null);
    setLoading(true);
    try {
      if (token) {
        axios.defaults.headers.common['Authorization'] = `Bearer ${token}`;
      }
      
      const response = await axios.get('/api/auth/status', { timeout: 15000 });
      if (!isCurrent()) return;
      if (response.data.authenticated) {
        setUser(projectPlatformUser(response.data.user));
      } else {
        // Server explicitly says this token is no longer valid → clear it.
        setUser(null);
        localStorage.removeItem('token');
        delete axios.defaults.headers.common['Authorization'];
      }
    } catch (error) {
      if (!isCurrent()) return;
      // Distinguish a real auth rejection from a transient failure. Behind a
      // flaky proxy/VPN, /api/auth/status can time out or error with no response;
      // wiping the token there would spuriously log the user out. This canonical
      // status endpoint can revoke an otherwise unexpired JWT; trust its rejection.
      if (error.response?.status === 401 || error.response?.status === 403) {
        setUser(null);
        localStorage.removeItem('token');
        delete axios.defaults.headers.common['Authorization'];
      } else {
        // Transient (network/timeout/5xx) or still-valid token: preserve the
        // session so a reload recovers instead of forcing a re-login.
        setAuthError('Unable to check your session. Please retry when the server is available.');
      }
    } finally {
      if (revision === authRevision.current) setLoading(false);
    }
  };

  const login = async (username, password) => {
    const revision = ++authRevision.current;
    setAuthError(null);
    setLoading(false);
    try {
      const response = await axios.post('/api/auth/login', { username, password });
      if (revision !== authRevision.current) return { success: false, error: 'Session changed during login' };
      const { token, user } = response.data;
      
      localStorage.setItem('token', token);
      axios.defaults.headers.common['Authorization'] = `Bearer ${token}`;
      const projected = projectPlatformUser(user);
      setUser(projected);
      return { success: true, user: projected };
    } catch (error) {
      return { 
        success: false, 
        error: error.response?.data?.error || 'Login failed' 
      };
    }
  };

  const register = async (userData) => {
    try {
      const response = await axios.post('/api/auth/register', userData);
      return { success: true, data: response.data };
    } catch (error) {
      return { 
        success: false, 
        error: error.response?.data?.error || 'Registration failed',
        details: error.response?.data?.details
      };
    }
  };

  const updateUser = (updatedFields) => {
    setUser(prev => projectPlatformUser(prev ? { ...prev, ...updatedFields } : updatedFields));
  };

  const logout = async () => {
    authRevision.current += 1;
    const token = localStorage.getItem('token');
    localStorage.removeItem('token');
    delete axios.defaults.headers.common['Authorization'];
    setUser(null);
    setAuthError(null);
    setLoading(false);
    try {
      await axios.post('/api/auth/logout', null, {
        headers: token ? { Authorization: `Bearer ${token}` } : {},
        timeout: 15000
      });
      return { success: true };
    } catch (error) {
      return { success: false, error: 'Logout failed' };
    }
  };

  const value = {
    user,
    loading,
    authError,
    login,
    register,
    logout,
    updateUser,
    checkAuthStatus
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
};
