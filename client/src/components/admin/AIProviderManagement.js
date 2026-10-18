import React, { useState, useEffect } from 'react';
import styled from 'styled-components';
import { motion, AnimatePresence } from 'framer-motion';
import { toast } from 'react-toastify';
import {
  FiCpu, FiCloud, FiZap, FiRefreshCw, FiCheckCircle, 
  FiAlertCircle, FiSettings, FiSave, FiEye, FiEyeOff,
  FiActivity, FiDollarSign, FiServer, FiKey
} from 'react-icons/fi';

const Container = styled.div`
  display: flex;
  flex-direction: column;
  gap: 2rem;
`;

const PageHeader = styled.div`
  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
  padding: 2rem;
  border-radius: 16px;
  color: white;
  box-shadow: 0 10px 40px rgba(102, 126, 234, 0.3);
  
  h2 {
    margin: 0 0 0.5rem 0;
    font-size: 2rem;
    font-weight: 700;
    display: flex;
    align-items: center;
    gap: 1rem;
  }
  
  p {
    margin: 0;
    opacity: 0.95;
    font-size: 1.125rem;
  }
`;

const StatusBanner = styled.div`
  padding: 1.5rem;
  border-radius: 12px;
  display: flex;
  align-items: center;
  gap: 1rem;
  font-weight: 500;
  
  &.success {
    background: #d1fae5;
    color: #065f46;
    border: 2px solid #10b981;
  }
  
  &.warning {
    background: #fef3c7;
    color: #92400e;
    border: 2px solid #f59e0b;
  }
  
  &.error {
    background: #fee2e2;
    color: #991b1b;
    border: 2px solid #ef4444;
  }
  
  svg {
    font-size: 1.5rem;
  }
`;

const ProvidersGrid = styled.div`
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
  gap: 1.5rem;
`;

const ProviderCard = styled(motion.div)`
  background: white;
  border-radius: 16px;
  padding: 2rem;
  box-shadow: 0 4px 6px rgba(0, 0, 0, 0.07);
  border: 2px solid ${props => props.isActive ? '#667eea' : '#e2e8f0'};
  position: relative;
  overflow: hidden;
  transition: all 0.3s ease;
  
  &:hover {
    box-shadow: 0 8px 25px rgba(0, 0, 0, 0.12);
    transform: translateY(-2px);
  }
  
  ${props => props.isActive && `
    &::before {
      content: '';
      position: absolute;
      top: 0;
      left: 0;
      right: 0;
      height: 4px;
      background: linear-gradient(90deg, #667eea, #764ba2);
    }
  `}
`;

const ProviderHeader = styled.div`
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: 1.5rem;
  
  .provider-info {
    flex: 1;
    
    h3 {
      margin: 0 0 0.5rem 0;
      font-size: 1.5rem;
      color: #1a202c;
      display: flex;
      align-items: center;
      gap: 0.75rem;
      
      svg {
        color: ${props => props.iconColor || '#667eea'};
        font-size: 1.75rem;
      }
    }
    
    .provider-type {
      color: #718096;
      font-size: 0.875rem;
      font-weight: 500;
    }
  }
`;

const StatusBadge = styled.div`
  display: inline-flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.5rem 1rem;
  border-radius: 20px;
  font-size: 0.875rem;
  font-weight: 600;
  
  &.healthy {
    background: #d1fae5;
    color: #065f46;
    
    svg {
      color: #10b981;
    }
  }
  
  &.configured {
    background: #dbeafe;
    color: #1e40af;
    
    svg {
      color: #3b82f6;
    }
  }
  
  &.unhealthy {
    background: #fee2e2;
    color: #991b1b;
    
    svg {
      color: #ef4444;
    }
  }
  
  &.not_configured {
    background: #f3f4f6;
    color: #6b7280;
    
    svg {
      color: #9ca3af;
    }
  }
`;

const ProviderDetails = styled.div`
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
  margin-bottom: 1.5rem;
  
  .detail-row {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 0.75rem;
    background: #f8fafc;
    border-radius: 8px;
    
    .label {
      color: #4a5568;
      font-size: 0.875rem;
      font-weight: 500;
    }
    
    .value {
      color: #1a202c;
      font-weight: 600;
      font-size: 0.875rem;
      font-family: 'Monaco', 'Menlo', monospace;
    }
  }
`;

const CostBadge = styled.div`
  display: inline-flex;
  align-items: center;
  gap: 0.375rem;
  padding: 0.375rem 0.75rem;
  border-radius: 6px;
  font-size: 0.75rem;
  font-weight: 600;
  
  &.free {
    background: #d1fae5;
    color: #065f46;
  }
  
  &.paid {
    background: #fef3c7;
    color: #92400e;
  }
`;

const ButtonGroup = styled.div`
  display: flex;
  gap: 0.75rem;
  flex-wrap: wrap;
`;

const Button = styled.button`
  padding: 0.75rem 1.25rem;
  border: none;
  border-radius: 10px;
  font-weight: 600;
  font-size: 0.875rem;
  cursor: pointer;
  display: flex;
  align-items: center;
  gap: 0.5rem;
  transition: all 0.2s ease;
  flex: 1;
  justify-content: center;
  
  &:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }
  
  &.primary {
    background: #667eea;
    color: white;
    
    &:hover:not(:disabled) {
      background: #5a67d8;
      transform: translateY(-1px);
      box-shadow: 0 4px 12px rgba(102, 126, 234, 0.4);
    }
  }
  
  &.secondary {
    background: #f7fafc;
    color: #4a5568;
    border: 2px solid #e2e8f0;
    
    &:hover:not(:disabled) {
      background: #edf2f7;
      border-color: #cbd5e0;
    }
  }
  
  &.success {
    background: #10b981;
    color: white;
    
    &:hover:not(:disabled) {
      background: #059669;
      transform: translateY(-1px);
      box-shadow: 0 4px 12px rgba(16, 185, 129, 0.4);
    }
  }
  
  &.warning {
    background: #f59e0b;
    color: white;
    
    &:hover:not(:disabled) {
      background: #d97706;
    }
  }
`;

const ConfigSection = styled(motion.div)`
  background: white;
  border-radius: 16px;
  padding: 2rem;
  box-shadow: 0 4px 6px rgba(0, 0, 0, 0.07);
  margin-top: 1rem;
`;

const FormGroup = styled.div`
  margin-bottom: 1.5rem;
  
  label {
    display: block;
    margin-bottom: 0.5rem;
    color: #1a202c;
    font-weight: 600;
    font-size: 0.875rem;
  }
  
  .input-wrapper {
    position: relative;
    display: flex;
    align-items: center;
  }
  
  input, select {
    width: 100%;
    padding: 0.875rem 1rem;
    border: 2px solid #e2e8f0;
    border-radius: 10px;
    font-size: 0.875rem;
    transition: all 0.2s ease;
    font-family: 'Monaco', 'Menlo', monospace;
    
    &:focus {
      outline: none;
      border-color: #667eea;
      box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
    }
  }
  
  .toggle-visibility {
    position: absolute;
    right: 1rem;
    background: none;
    border: none;
    color: #718096;
    cursor: pointer;
    padding: 0.5rem;
    display: flex;
    align-items: center;
    
    &:hover {
      color: #4a5568;
    }
  }
  
  .hint {
    margin-top: 0.5rem;
    font-size: 0.75rem;
    color: #718096;
  }
`;

const StatsSection = styled.div`
  background: white;
  border-radius: 16px;
  padding: 2rem;
  box-shadow: 0 4px 6px rgba(0, 0, 0, 0.07);
  
  h3 {
    margin: 0 0 1.5rem 0;
    color: #1a202c;
    font-size: 1.5rem;
    display: flex;
    align-items: center;
    gap: 0.75rem;
  }
`;

const StatsGrid = styled.div`
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 1rem;
`;

const StatCard = styled.div`
  background: ${props => props.bgColor || '#f8fafc'};
  padding: 1.5rem;
  border-radius: 12px;
  text-align: center;
  
  .stat-value {
    font-size: 2rem;
    font-weight: 700;
    color: #1a202c;
    margin-bottom: 0.5rem;
  }
  
  .stat-label {
    font-size: 0.875rem;
    color: #718096;
    font-weight: 500;
  }
`;

const LoadingSpinner = styled(motion.div)`
  display: flex;
  justify-content: center;
  align-items: center;
  padding: 3rem;
  font-size: 2rem;
  color: #667eea;
`;

const AIProviderManagement = () => {
  const [loading, setLoading] = useState(true);
  const [providersConfig, setProvidersConfig] = useState(null);
  const [currentProvider, setCurrentProvider] = useState('');
  const [stats, setStats] = useState(null);
  const [configuring, setConfiguring] = useState(null);
  const [testing, setTesting] = useState(null);
  const [switching, setSwitching] = useState(false);
  
  // Configuration form states
  const [showApiKey, setShowApiKey] = useState(false);
  const [configForm, setConfigForm] = useState({
    provider: '',
    apiKey: '',
    model: '',
    baseUrl: '',
    region: '',
    accessKeyId: '',
    secretAccessKey: '',
    sessionToken: ''
  });

  // Providers configured without an API key (local server / AWS credential chain)
  const KEYLESS_PROVIDERS = ['lmstudio', 'bedrock'];

  useEffect(() => {
    fetchProviderStatus();
    fetchStats();
  }, []);

  const fetchProviderStatus = async () => {
    try {
      setLoading(true);
      const token = localStorage.getItem('token');
      
      const response = await fetch('/api/admin/ai/providers', {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      });

      if (response.ok) {
        const data = await response.json();
        setProvidersConfig(data.config);
        setCurrentProvider(data.config.currentProvider);
        toast.success('Provider status loaded');
      } else {
        toast.error('Failed to fetch provider status');
      }
    } catch (error) {
      console.error('Error fetching provider status:', error);
      toast.error('Error loading provider status');
    } finally {
      setLoading(false);
    }
  };

  const fetchStats = async () => {
    try {
      const token = localStorage.getItem('token');
      
      const response = await fetch('/api/admin/ai/stats', {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      });

      if (response.ok) {
        const data = await response.json();
        setStats(data.summary);
      }
    } catch (error) {
      console.error('Error fetching stats:', error);
    }
  };

  const handleTestProvider = async (providerName) => {
    const testToastId = `test-${providerName}`;
    
    try {
      setTesting(providerName);
      toast.info(`🔍 Testing ${providerName} connection...`, { autoClose: false, toastId: testToastId });
      
      const token = localStorage.getItem('token');
      
      const response = await fetch('/api/admin/ai/providers/test', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ provider: providerName })
      });

      let data;
      try {
        data = await response.json();
      } catch (parseError) {
        console.error('Failed to parse test response:', parseError);
        toast.dismiss(testToastId);
        toast.error('Server returned invalid response');
        return;
      }
      
      toast.dismiss(testToastId);
      
      if (data.success && data.test && data.test.success) {
        toast.success(
          <div>
            <strong>✅ {providerName} connection successful!</strong><br/>
            <small style={{ display: 'block', marginTop: '8px', lineHeight: '1.6' }}>
              • Status: {data.test.message || 'Connection verified'}<br/>
              • Response time: {data.test.responseTime || 0}ms<br/>
              {data.test.model && `• Model: ${data.test.model}`}
            </small>
          </div>,
          { autoClose: 5000 }
        );
      } else {
        const testResult = data.test || {};
        toast.error(
          <div>
            <strong>❌ {providerName} connection failed</strong><br/>
            <small style={{ display: 'block', marginTop: '8px', lineHeight: '1.6' }}>
              {testResult.message || data.error || 'Connection test failed'}<br/>
              Response time: {testResult.responseTime || 0}ms
              {testResult.error && <><br/>Error: {testResult.error}</>}
            </small>
          </div>,
          { autoClose: 6000 }
        );
      }
    } catch (error) {
      toast.dismiss(testToastId);
      console.error('Error testing provider:', error);
      
      const errorMessage = error?.message || error?.toString() || 'Connection failed';
      toast.error(
        <div>
          <strong>❌ Test failed</strong><br/>
          <small>Error testing {providerName}: {errorMessage}</small>
        </div>
      );
    } finally {
      setTesting(null);
    }
  };

  const handleSwitchProvider = async (providerName) => {
    const verifyToastId = `verify-${providerName}`;
    
    try {
      setSwitching(true);
      const token = localStorage.getItem('token');
      
      // Show verification in progress
      toast.info(`🔍 Verifying ${providerName} connection and health...`, { autoClose: false, toastId: verifyToastId });
      
      const response = await fetch('/api/admin/ai/providers/switch', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ provider: providerName })
      });

      let data;
      try {
        data = await response.json();
      } catch (parseError) {
        console.error('Failed to parse response:', parseError);
        toast.dismiss(verifyToastId);
        toast.error(
          <div>
            <strong>❌ Server Error</strong><br/>
            <small>Server returned invalid response. Please check server logs.</small>
          </div>,
          { autoClose: 6000 }
        );
        return;
      }
      
      // Dismiss verification toast
      toast.dismiss(verifyToastId);
      
      if (response.ok && data.success) {
        const verif = data.verification || {};
        
        // Show detailed success message with verification info
        toast.success(
          <div>
            <strong>✅ Successfully switched to {providerName}!</strong><br/>
            <small style={{ display: 'block', marginTop: '8px', lineHeight: '1.6' }}>
              <strong>Verification Results:</strong><br/>
              • Status: {verif.message || 'Provider verified'}<br/>
              • Response time: {verif.responseTime || 0}ms<br/>
              • Configuration: {verif.configured ? '✓ Configured' : '✗ Not Configured'}<br/>
              • Health: {verif.healthy ? '✓ Healthy' : '✗ Unhealthy'}<br/>
              • In-flight requests handled: {data.inFlightRequestsHandled || 0}<br/>
              <strong style={{ color: '#059669', marginTop: '4px', display: 'block' }}>
                ⚡ Active immediately for all users!
              </strong>
            </small>
          </div>,
          { autoClose: 8000 }
        );
        
        setCurrentProvider(providerName);
        await fetchProviderStatus();
      } else {
        // Show detailed error with verification results
        const verif = data.verification || {};
        
        if (verif && (verif.message || data.message)) {
          toast.error(
            <div>
              <strong>❌ Cannot switch to {providerName}</strong><br/>
              <small style={{ display: 'block', marginTop: '8px', lineHeight: '1.6' }}>
                <strong>Verification Failed:</strong><br/>
                • {verif.message || data.message || data.error || 'Unknown error'}<br/>
                • Response time: {verif.responseTime || 0}ms<br/>
                • Configured: {verif.configured ? '✓ Yes' : '✗ No - Add API key first'}<br/>
                • Healthy: {verif.healthy ? '✓ Yes' : '✗ No'}<br/>
                {verif.error && `• Error: ${verif.error}`}<br/>
                <strong style={{ color: '#dc2626', marginTop: '4px', display: 'block' }}>
                  {!verif.configured 
                    ? '📋 Please configure API key first' 
                    : '⚠️ Check your connection and credentials'}
                </strong>
              </small>
            </div>,
            { autoClose: 10000 }
          );
        } else {
          toast.error(
            <div>
              <strong>❌ Failed to switch provider</strong><br/>
              <small>{data.error || data.message || 'Unknown error occurred. Check server logs.'}</small>
            </div>,
            { autoClose: 6000 }
          );
        }
      }
    } catch (error) {
      toast.dismiss(verifyToastId);
      console.error('Error switching provider:', error);
      
      const errorMessage = error?.message || error?.toString() || 'Unable to connect to server';
      
      toast.error(
        <div>
          <strong>❌ Network Error</strong><br/>
          <small>
            Failed to communicate with server.<br/>
            {errorMessage}<br/>
            <strong style={{ marginTop: '4px', display: 'block' }}>
              • Check if server is running<br/>
              • Check browser console for details
            </strong>
          </small>
        </div>,
        { autoClose: 8000 }
      );
    } finally {
      setSwitching(false);
    }
  };

  const handleConfigureProvider = async (e) => {
    e.preventDefault();
    
    const requiresApiKey = !KEYLESS_PROVIDERS.includes(configForm.provider);
    if (!configForm.provider || (requiresApiKey && !configForm.apiKey)) {
      toast.error('Please fill in all required fields');
      return;
    }
    
    const configToastId = 'configuring';
    
    try {
      setConfiguring(configForm.provider);
      toast.info(`🔧 Configuring ${configForm.provider}...`, { autoClose: false, toastId: configToastId });
      
      const token = localStorage.getItem('token');
      
      const response = await fetch('/api/admin/ai/providers/configure', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(configForm)
      });

      let data;
      try {
        data = await response.json();
      } catch (parseError) {
        console.error('Failed to parse configure response:', parseError);
        toast.dismiss(configToastId);
        toast.error('Server returned invalid response');
        return;
      }
      
      toast.dismiss(configToastId);
      
      if (response.ok && data.success) {
        const verif = data.verification || {};
        
        if (verif.healthy) {
          toast.success(
            <div>
              <strong>✅ {configForm.provider} configured successfully!</strong><br/>
              <small style={{ display: 'block', marginTop: '8px', lineHeight: '1.6' }}>
                • Connection verified: {verif.message || 'Provider verified'}<br/>
                • Response time: {verif.responseTime || 0}ms<br/>
                • Status: Ready to use immediately<br/>
                {data.modelConfigured && configForm.model && `• Model: ${configForm.model}`}
              </small>
            </div>,
            { autoClose: 6000 }
          );
        } else if (verif && verif.message) {
          toast.warning(
            <div>
              <strong>⚠️ {configForm.provider} configured with warnings</strong><br/>
              <small style={{ display: 'block', marginTop: '8px', lineHeight: '1.6' }}>
                Configuration saved but verification failed:<br/>
                {verif.message}<br/>
                Please check your API key and try testing the connection.
              </small>
            </div>,
            { autoClose: 8000 }
          );
        } else {
          toast.success(`✅ ${configForm.provider} configured successfully!`);
        }
        
        setConfigForm({ provider: '', apiKey: '', model: '', baseUrl: '', region: '', accessKeyId: '', secretAccessKey: '', sessionToken: '' });
        setConfiguring(null);
        await fetchProviderStatus();
      } else {
        toast.error(
          <div>
            <strong>❌ Configuration failed</strong><br/>
            <small>{data.error || data.message || 'Unknown error occurred'}</small>
          </div>,
          { autoClose: 6000 }
        );
      }
    } catch (error) {
      toast.dismiss(configToastId);
      console.error('Error configuring provider:', error);
      
      const errorMessage = error?.message || error?.toString() || 'Configuration failed';
      toast.error(
        <div>
          <strong>❌ Configuration Error</strong><br/>
          <small>Failed to configure provider: {errorMessage}</small>
        </div>
      );
    } finally {
      setConfiguring(null);
    }
  };

  const getProviderIcon = (providerName) => {
    switch (providerName) {
      case 'ollama':
        return <FiCpu />;
      case 'lmstudio':
        return <FiCpu />;
      case 'claude':
        return <FiCloud />;
      case 'chatgpt':
        return <FiZap />;
      case 'bedrock':
        return <FiCloud />;
      default:
        return <FiServer />;
    }
  };

  const getProviderIconColor = (providerName) => {
    switch (providerName) {
      case 'ollama':
        return '#10b981';
      case 'lmstudio':
        return '#14b8a6';
      case 'claude':
        return '#8b5cf6';
      case 'chatgpt':
        return '#f59e0b';
      case 'bedrock':
        return '#ff9900';
      default:
        return '#667eea';
    }
  };

  const LOCAL_PROVIDERS = ['ollama', 'lmstudio'];

  const getStatusClass = (status) => {
    if (status === 'healthy') return 'healthy';
    if (status === 'configured') return 'configured';
    if (status === 'unhealthy') return 'unhealthy';
    return 'not_configured';
  };

  if (loading) {
    return (
      <Container>
        <PageHeader>
          <h2><FiSettings /> AI Provider Management</h2>
          <p>Configure and manage AI providers for your application</p>
        </PageHeader>
        <LoadingSpinner
          animate={{ rotate: 360 }}
          transition={{ duration: 1, repeat: Infinity, ease: 'linear' }}
        >
          <FiRefreshCw />
        </LoadingSpinner>
      </Container>
    );
  }

  const anyProviderHealthy = providersConfig && Object.values(providersConfig.providers).some(p => p.available);

  return (
    <Container>
      <PageHeader>
        <h2><FiSettings /> AI Provider Management</h2>
        <p>Configure and manage AI providers for your application</p>
      </PageHeader>

      {/* Status Banner */}
      {providersConfig && (
        <>
          <StatusBanner className={anyProviderHealthy ? 'success' : 'warning'}>
            {anyProviderHealthy ? (
              <>
                <FiCheckCircle />
                <div>
                  <strong>AI Services Operational</strong> - Currently using {currentProvider}
                  <div style={{ fontSize: '0.875rem', marginTop: '0.25rem', opacity: 0.9 }}>
                    ⚡ Hot-reload enabled: Provider changes apply instantly to all users
                  </div>
                </div>
              </>
            ) : (
              <>
                <FiAlertCircle />
                <div>
                  <strong>Running in Fallback Mode</strong> - No AI providers available. Application continues with intelligent responses.
                  <div style={{ fontSize: '0.875rem', marginTop: '0.25rem', opacity: 0.9 }}>
                    Configure a provider below to enable AI features
                  </div>
                </div>
              </>
            )}
          </StatusBanner>
          
          {/* Info banner about instant switching */}
          <div style={{ 
            padding: '1rem 1.5rem', 
            background: 'linear-gradient(135deg, #dbeafe 0%, #bfdbfe 100%)', 
            borderRadius: '12px',
            border: '2px solid #3b82f6',
            display: 'flex',
            alignItems: 'center',
            gap: '1rem'
          }}>
            <FiZap style={{ fontSize: '1.5rem', color: '#1e40af' }} />
            <div style={{ flex: 1 }}>
              <strong style={{ color: '#1e40af' }}>Instant Provider Switching</strong>
              <p style={{ margin: '0.25rem 0 0 0', fontSize: '0.875rem', color: '#1e3a8a' }}>
                All provider changes are applied immediately without server restart. In-flight requests are handled gracefully. 
                All users will use the new provider instantly.
              </p>
            </div>
          </div>
        </>
      )}

      {/* Current Provider */}
      {providersConfig && (
        <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', padding: '1rem', background: 'white', borderRadius: '12px', boxShadow: '0 2px 4px rgba(0,0,0,0.05)' }}>
          <strong style={{ color: '#1a202c' }}>Current Active Provider:</strong>
          <div style={{ 
            padding: '0.5rem 1rem', 
            background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)', 
            color: 'white', 
            borderRadius: '8px',
            fontWeight: '600',
            textTransform: 'uppercase',
            fontSize: '0.875rem'
          }}>
            {currentProvider}
          </div>
          <Button className="secondary" onClick={fetchProviderStatus} style={{ marginLeft: 'auto', flex: 'initial' }}>
            <FiRefreshCw /> Refresh Status
          </Button>
        </div>
      )}

      {/* Providers Grid */}
      <ProvidersGrid>
        {providersConfig && Object.entries(providersConfig.providers).map(([key, provider]) => (
          <ProviderCard
            key={key}
            isActive={currentProvider === key}
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.3 }}
          >
            <ProviderHeader iconColor={getProviderIconColor(key)}>
              <div className="provider-info">
                <h3>
                  {getProviderIcon(key)}
                  {provider.name}
                </h3>
                <div className="provider-type">
                  {LOCAL_PROVIDERS.includes(key) ? 'Local LLM' : 'Cloud API'}
                </div>
              </div>
              <StatusBadge className={getStatusClass(provider.status)}>
                {provider.available ? <FiCheckCircle /> : <FiAlertCircle />}
                {provider.status}
              </StatusBadge>
            </ProviderHeader>

            <ProviderDetails>
              <div className="detail-row">
                <span className="label">Model</span>
                <span className="value">{provider.model}</span>
              </div>
              {provider.baseUrl && (
                <div className="detail-row">
                  <span className="label">Endpoint</span>
                  <span className="value">{provider.baseUrl}</span>
                </div>
              )}
              <div className="detail-row">
                <span className="label">Cost</span>
                <CostBadge className={provider.cost === 'FREE' ? 'free' : 'paid'}>
                  <FiDollarSign />
                  {provider.cost}
                </CostBadge>
              </div>
              <div className="detail-row">
                <span className="label">Configured</span>
                <span className="value">{provider.configured ? '✅ Yes' : '❌ No'}</span>
              </div>
            </ProviderDetails>

            <ButtonGroup>
              <Button
                className="secondary"
                onClick={() => handleTestProvider(key)}
                disabled={testing === key || !provider.configured}
              >
                {testing === key ? <FiRefreshCw className="spin" /> : <FiActivity />}
                Test Connection
              </Button>
              <Button
                className={currentProvider === key ? 'success' : 'primary'}
                onClick={() => handleSwitchProvider(key)}
                disabled={switching || currentProvider === key}
              >
                {currentProvider === key ? (
                  <>
                    <FiCheckCircle /> Active
                  </>
                ) : (
                  <>
                    <FiZap /> Switch To
                  </>
                )}
              </Button>
            </ButtonGroup>
          </ProviderCard>
        ))}
      </ProvidersGrid>

      {/* Configuration Section */}
      <ConfigSection
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.3 }}
      >
        <h3 style={{ margin: '0 0 1.5rem 0', display: 'flex', alignItems: 'center', gap: '0.75rem', color: '#1a202c' }}>
          <FiKey /> Configure API Provider
        </h3>
        <p style={{ color: '#718096', marginBottom: '1.5rem' }}>
          Add or update API keys for Claude or ChatGPT, point LM Studio at your local server, or set the
          Amazon Bedrock model, region, and (optionally) AWS credentials. Ollama and LM Studio run locally and
          need no API key; Bedrock can use static AWS keys entered here or your AWS credential chain (role/profile/SSO).
        </p>
        
        <form onSubmit={handleConfigureProvider}>
          <FormGroup>
            <label htmlFor="provider-select">Provider *</label>
            <select
              id="provider-select"
              value={configForm.provider}
              onChange={(e) => setConfigForm({ ...configForm, provider: e.target.value })}
              required
            >
              <option value="">Select a provider...</option>
              <option value="claude">Claude (Anthropic)</option>
              <option value="chatgpt">ChatGPT (OpenAI)</option>
              <option value="lmstudio">LM Studio (Local)</option>
              <option value="bedrock">Amazon Bedrock (AWS)</option>
            </select>
          </FormGroup>

          {configForm.provider && (
            <>
              {/* API key — only for cloud key-based providers */}
              {!KEYLESS_PROVIDERS.includes(configForm.provider) && (
                <FormGroup>
                  <label htmlFor="api-key">API Key *</label>
                  <div className="input-wrapper">
                    <input
                      id="api-key"
                      type={showApiKey ? 'text' : 'password'}
                      value={configForm.apiKey}
                      onChange={(e) => setConfigForm({ ...configForm, apiKey: e.target.value })}
                      placeholder={configForm.provider === 'claude' ? 'sk-ant-api03-...' : 'sk-...'}
                      required
                    />
                    <button
                      type="button"
                      className="toggle-visibility"
                      onClick={() => setShowApiKey(!showApiKey)}
                    >
                      {showApiKey ? <FiEyeOff /> : <FiEye />}
                    </button>
                  </div>
                  <div className="hint">
                    {configForm.provider === 'claude' && 'Get your API key from https://console.anthropic.com/'}
                    {configForm.provider === 'chatgpt' && 'Get your API key from https://platform.openai.com/api-keys'}
                  </div>
                </FormGroup>
              )}

              {/* LM Studio — local OpenAI-compatible base URL */}
              {configForm.provider === 'lmstudio' && (
                <FormGroup>
                  <label htmlFor="base-url">Base URL</label>
                  <input
                    id="base-url"
                    type="text"
                    value={configForm.baseUrl}
                    onChange={(e) => setConfigForm({ ...configForm, baseUrl: e.target.value })}
                    placeholder="http://localhost:1234/v1"
                  />
                  <div className="hint">
                    LM Studio "Local Server" endpoint. Leave blank to keep the current value (default http://localhost:1234/v1).
                  </div>
                </FormGroup>
              )}

              {/* Bedrock — AWS region + optional static credentials */}
              {configForm.provider === 'bedrock' && (
                <>
                  <FormGroup>
                    <label htmlFor="region">AWS Region</label>
                    <input
                      id="region"
                      type="text"
                      value={configForm.region}
                      onChange={(e) => setConfigForm({ ...configForm, region: e.target.value })}
                      placeholder="us-east-1"
                    />
                    <div className="hint">
                      Region where your Bedrock model is enabled (e.g. us-east-1, us-west-2).
                    </div>
                  </FormGroup>

                  <FormGroup>
                    <label htmlFor="accessKeyId">AWS Access Key ID <span style={{ color: '#94a3b8' }}>(optional)</span></label>
                    <input
                      id="accessKeyId"
                      type="text"
                      autoComplete="off"
                      value={configForm.accessKeyId}
                      onChange={(e) => setConfigForm({ ...configForm, accessKeyId: e.target.value })}
                      placeholder="AKIA..."
                    />
                  </FormGroup>

                  <FormGroup>
                    <label htmlFor="secretAccessKey">AWS Secret Access Key <span style={{ color: '#94a3b8' }}>(optional)</span></label>
                    <input
                      id="secretAccessKey"
                      type="password"
                      autoComplete="off"
                      value={configForm.secretAccessKey}
                      onChange={(e) => setConfigForm({ ...configForm, secretAccessKey: e.target.value })}
                      placeholder="••••••••••••••••"
                    />
                  </FormGroup>

                  <FormGroup>
                    <label htmlFor="sessionToken">AWS Session Token <span style={{ color: '#94a3b8' }}>(optional — for temporary creds)</span></label>
                    <input
                      id="sessionToken"
                      type="password"
                      autoComplete="off"
                      value={configForm.sessionToken}
                      onChange={(e) => setConfigForm({ ...configForm, sessionToken: e.target.value })}
                      placeholder="••••••••••••••••"
                    />
                    <div className="hint">
                      Leave the three credential fields blank to use the AWS credential chain (IAM role / shared profile / SSO). Fill them in to run Bedrock locally with static keys.
                    </div>
                  </FormGroup>
                </>
              )}

              <FormGroup>
                <label htmlFor="model">Model {configForm.provider === 'bedrock' ? '(Model ID)' : '(Optional)'}</label>
                <input
                  id="model"
                  type="text"
                  value={configForm.model}
                  onChange={(e) => setConfigForm({ ...configForm, model: e.target.value })}
                  placeholder={
                    configForm.provider === 'claude'
                      ? 'claude-3-5-sonnet-20241022'
                      : configForm.provider === 'chatgpt'
                        ? 'gpt-4'
                        : configForm.provider === 'lmstudio'
                          ? 'local-model'
                          : configForm.provider === 'bedrock'
                            ? 'us.meta.llama3-1-8b-instruct-v1:0'
                            : ''
                  }
                />
                <div className="hint">
                  Leave blank to use default model
                </div>
              </FormGroup>

              <Button 
                type="submit" 
                className="primary" 
                disabled={configuring}
                style={{ width: '100%' }}
              >
                {configuring ? (
                  <>
                    <FiRefreshCw className="spin" /> Configuring...
                  </>
                ) : (
                  <>
                    <FiSave /> Save Configuration
                  </>
                )}
              </Button>
            </>
          )}
        </form>
      </ConfigSection>

      {/* Usage Statistics */}
      {stats && (
        <StatsSection>
          <h3>
            <FiActivity /> Usage Statistics
          </h3>
          <StatsGrid>
            <StatCard bgColor="linear-gradient(135deg, #667eea 0%, #764ba2 100%)">
              <div className="stat-value" style={{ color: 'white' }}>{stats.totalRequests || 0}</div>
              <div className="stat-label" style={{ color: 'rgba(255,255,255,0.9)' }}>Total Requests</div>
            </StatCard>
            <StatCard bgColor="#f0fdf4">
              <div className="stat-value" style={{ color: '#10b981' }}>{stats.ollamaRequests || 0}</div>
              <div className="stat-label">Ollama Requests</div>
            </StatCard>
            <StatCard bgColor="#faf5ff">
              <div className="stat-value" style={{ color: '#8b5cf6' }}>{stats.claudeRequests || 0}</div>
              <div className="stat-label">Claude Requests</div>
            </StatCard>
            <StatCard bgColor="#fffbeb">
              <div className="stat-value" style={{ color: '#f59e0b' }}>{stats.openaiRequests || 0}</div>
              <div className="stat-label">ChatGPT Requests</div>
            </StatCard>
            <StatCard bgColor="#fef2f2">
              <div className="stat-value" style={{ color: '#ef4444' }}>{stats.fallbackRequests || 0}</div>
              <div className="stat-label">Fallback Requests</div>
            </StatCard>
          </StatsGrid>
        </StatsSection>
      )}
    </Container>
  );
};

export default AIProviderManagement;

