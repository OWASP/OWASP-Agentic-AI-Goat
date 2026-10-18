import React, { useState, useEffect } from 'react';
import { useAuth } from '../context/AuthContext';
import { FiUser, FiMail, FiSave, FiEdit, FiLock } from 'react-icons/fi';
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
  max-width: 800px;
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

const ProfileForm = styled(motion.form)`
  background: rgba(255, 255, 255, 0.95);
  backdrop-filter: blur(20px);
  border-radius: 24px;
  padding: 2.5rem;
  box-shadow: 0 25px 50px rgba(0, 0, 0, 0.15);
  border: 1px solid rgba(255, 255, 255, 0.3);
`;

const FormGroup = styled.div`
  margin-bottom: 2rem;
`;

const Label = styled.label`
  display: block;
  margin-bottom: 0.5rem;
  font-weight: 600;
  color: #333;
  font-size: 1rem;
`;

const Input = styled.input`
  width: 100%;
  padding: 1rem;
  border: 2px solid #e1e5e9;
  border-radius: 12px;
  font-size: 1rem;
  transition: all 0.3s ease;
  background: rgba(255, 255, 255, 0.8);
  
  &:focus {
    outline: none;
    border-color: #667eea;
    background: rgba(255, 255, 255, 1);
    box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
  }
  
  &:disabled {
    background: #f8f9fa;
    color: #666;
    cursor: not-allowed;
  }
`;

const ButtonGroup = styled.div`
  display: flex;
  gap: 1rem;
  justify-content: flex-end;
  margin-top: 2rem;
`;

const Button = styled.button`
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 1rem 2rem;
  border-radius: 12px;
  font-weight: 600;
  font-size: 1rem;
  transition: all 0.3s ease;
  border: none;
  cursor: pointer;
  
  ${props => props.primary ? `
    background: linear-gradient(135deg, #667eea, #764ba2);
    color: white;
    
    &:hover {
      transform: translateY(-2px);
      box-shadow: 0 8px 25px rgba(102, 126, 234, 0.3);
    }
    
    &:disabled {
      background: #ccc;
      cursor: not-allowed;
      transform: none;
      box-shadow: none;
    }
  ` : `
    background: transparent;
    color: #666;
    border: 2px solid #dee2e6;
    
    &:hover {
      border-color: #667eea;
      color: #667eea;
      transform: translateY(-1px);
    }
  `}
`;

const SuccessMessage = styled.div`
  background: linear-gradient(135deg, #28a745, #20c997);
  color: white;
  padding: 1rem;
  border-radius: 12px;
  margin-bottom: 2rem;
  text-align: center;
  font-weight: 600;
`;

const ErrorMessage = styled.div`
  background: linear-gradient(135deg, #dc3545, #fd7e14);
  color: white;
  padding: 1rem;
  border-radius: 12px;
  margin-bottom: 2rem;
  text-align: center;
  font-weight: 600;
`;

const EditProfile = () => {
  const { user, updateUser } = useAuth();
  const [formData, setFormData] = useState({ email: '' });
  const [isEditing, setIsEditing] = useState(false);
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState({ type: '', text: '' });

  useEffect(() => {
    if (user) {
      setFormData({ email: user.email || '' });
    }
  }, [user]);

  const handleInputChange = (e) => {
    const { name, value } = e.target;
    setFormData(prev => ({ ...prev, [name]: value }));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setMessage({ type: '', text: '' });

    if (!formData.email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(formData.email)) {
      setMessage({ type: 'error', text: 'Please enter a valid email address' });
      setLoading(false);
      return;
    }

    try {
      const response = await axios.put('/api/auth/profile', {
        email: formData.email,
        fullName: user?.full_name || ''
      });
      if (updateUser) updateUser(response.data.user);
      setMessage({ type: 'success', text: 'Profile updated successfully!' });
      setIsEditing(false);
    } catch (error) {
      setMessage({
        type: 'error',
        text: error.response?.data?.error || error.response?.data?.message || 'Failed to update profile'
      });
    } finally {
      setLoading(false);
    }
  };

  const handleCancel = () => {
    setFormData({ email: user?.email || '' });
    setIsEditing(false);
    setMessage({ type: '', text: '' });
  };

  return (
    <PageContainer>
      <ContentWrapper>
        <Header
          initial={{ y: -50, opacity: 0 }}
          animate={{ y: 0, opacity: 1 }}
          transition={{ duration: 0.8 }}
        >
          <h1>
            <FiUser />
            Edit Profile
          </h1>
          <div className="subtitle">
            Update your account information and preferences
          </div>
        </Header>

        <ProfileForm
          onSubmit={handleSubmit}
          initial={{ y: 50, opacity: 0 }}
          animate={{ y: 0, opacity: 1 }}
          transition={{ duration: 0.8, delay: 0.2 }}
        >
          {message.text && (
            message.type === 'success' ? 
              <SuccessMessage>{message.text}</SuccessMessage> :
              <ErrorMessage>{message.text}</ErrorMessage>
          )}

          <FormGroup>
            <Label htmlFor="username">
              <FiLock size={16} style={{ marginRight: '0.5rem' }} />
              Username
            </Label>
            <Input
              id="username"
              name="username"
              type="text"
              value={user?.username || ''}
              disabled
            />
            <span style={{ fontSize: '0.8rem', color: '#888', marginTop: '0.35rem', display: 'block' }}>
              Username cannot be changed after account creation.
            </span>
          </FormGroup>

          <FormGroup>
            <Label htmlFor="email">
              <FiMail size={16} style={{ marginRight: '0.5rem' }} />
              Email Address
            </Label>
            <Input
              id="email"
              name="email"
              type="email"
              value={formData.email}
              onChange={handleInputChange}
              disabled={!isEditing}
              required
            />
          </FormGroup>

          <ButtonGroup>
            {!isEditing ? (
              <Button type="button" primary onClick={() => setIsEditing(true)}>
                <FiEdit size={16} />
                Edit Profile
              </Button>
            ) : (
              <>
                <Button type="button" onClick={handleCancel}>
                  Cancel
                </Button>
                <Button type="submit" primary disabled={loading}>
                  <FiSave size={16} />
                  {loading ? 'Saving...' : 'Save Changes'}
                </Button>
              </>
            )}
          </ButtonGroup>
        </ProfileForm>
      </ContentWrapper>
    </PageContainer>
  );
};

export default EditProfile;