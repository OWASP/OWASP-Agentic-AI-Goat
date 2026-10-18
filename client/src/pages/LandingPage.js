import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';
import { FiShield, FiShoppingCart, FiArrowRight, FiPlay } from 'react-icons/fi';
import styled from 'styled-components';
import { motion } from 'framer-motion';

const LandingContainer = styled.div`
  min-height: 100vh;
  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: 2rem;
  position: relative;
  overflow: hidden;
`;

const BackgroundElements = styled.div`
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background-image: 
    radial-gradient(circle at 20% 20%, rgba(255, 255, 255, 0.1) 0%, transparent 50%),
    radial-gradient(circle at 80% 80%, rgba(255, 255, 255, 0.1) 0%, transparent 50%),
    radial-gradient(circle at 40% 60%, rgba(255, 255, 255, 0.05) 0%, transparent 50%);
  pointer-events: none;
`;

const WarningBanner = styled.div`
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  background: linear-gradient(90deg, #ff6b6b, #ee5a24);
  color: white;
  padding: 1rem;
  text-align: center;
  font-weight: 600;
  z-index: 1000;
  box-shadow: 0 2px 10px rgba(0, 0, 0, 0.2);
  font-size: 0.95rem;
`;

const MainContent = styled.div`
  max-width: 1200px;
  width: 100%;
  text-align: center;
  z-index: 1;
`;

const Title = styled(motion.h1)`
  color: white;
  font-size: 4.5rem;
  font-weight: 900;
  margin-bottom: 1.5rem;
  text-shadow: 0 4px 30px rgba(0, 0, 0, 0.3);
  letter-spacing: -0.02em;
  
  @media (max-width: 768px) {
    font-size: 3rem;
  }
  
  @media (max-width: 480px) {
    font-size: 2.5rem;
  }
`;

const Subtitle = styled(motion.p)`
  color: rgba(255, 255, 255, 0.9);
  font-size: 1.4rem;
  margin-bottom: 4rem;
  font-weight: 300;
  line-height: 1.6;
  max-width: 800px;
  margin-left: auto;
  margin-right: auto;
  
  @media (max-width: 768px) {
    font-size: 1.2rem;
    margin-bottom: 3rem;
  }
`;

const PlatformCards = styled(motion.div)`
  display: flex;
  flex-wrap: wrap;
  justify-content: center;
  gap: 2.5rem;
  margin-top: 2rem;
  width: 100%;
  
  @media (max-width: 768px) {
    flex-direction: column;
    align-items: center;
    gap: 2rem;
  }
`;

const PlatformCard = styled(motion.div)`
  background: rgba(255, 255, 255, 0.95);
  backdrop-filter: blur(20px);
  border-radius: 24px;
  padding: 2.5rem;
  box-shadow: 0 20px 60px rgba(0, 0, 0, 0.15);
  cursor: pointer;
  transition: all 0.4s ease;
  border: 2px solid transparent;
  position: relative;
  overflow: hidden;
  width: 100%;
  max-width: 440px;
  
  &:before {
    content: '';
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    height: 4px;
    background: ${props => props.accent || 'linear-gradient(90deg, #667eea 0%, #764ba2 100%)'};
  }
  
  &:hover {
    transform: translateY(-8px) scale(1.02);
    box-shadow: 0 30px 80px rgba(0, 0, 0, 0.25);
    border-color: rgba(255, 255, 255, 0.3);
  }
`;

const CardIcon = styled.div`
  width: 70px;
  height: 70px;
  border-radius: 18px;
  background: ${props => props.gradient || 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)'};
  display: flex;
  align-items: center;
  justify-content: center;
  margin: 0 auto 1.5rem;
  font-size: 2rem;
  color: white;
  box-shadow: 0 8px 25px rgba(0, 0, 0, 0.2);
`;

const CardTitle = styled.h2`
  color: #333;
  font-size: 1.8rem;
  font-weight: 700;
  margin-bottom: 1rem;
`;

const CardDescription = styled.p`
  color: #666;
  font-size: 1rem;
  line-height: 1.6;
  margin-bottom: 1.5rem;
`;

const CardFeatures = styled.ul`
  list-style: none;
  padding: 0;
  margin-bottom: 2rem;
  text-align: left;
`;

const FeatureItem = styled.li`
  color: #555;
  margin-bottom: 0.5rem;
  display: flex;
  align-items: center;
  gap: 0.5rem;
  font-size: 0.9rem;
  
  &:before {
    content: '✓';
    background: ${props => props.color || '#667eea'};
    color: white;
    width: 16px;
    height: 16px;
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 0.7rem;
    font-weight: bold;
    flex-shrink: 0;
  }
`;

const CardButton = styled.button`
  background: ${props => props.gradient || 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)'};
  color: white;
  border: none;
  padding: 1rem 2rem;
  border-radius: 14px;
  font-weight: 700;
  font-size: 1rem;
  cursor: pointer;
  transition: all 0.3s ease;
  display: flex;
  align-items: center;
  gap: 0.5rem;
  margin: 0 auto;
  box-shadow: 0 6px 20px rgba(0, 0, 0, 0.2);
  
  &:hover {
    transform: translateY(-2px);
    box-shadow: 0 8px 25px rgba(0, 0, 0, 0.3);
  }
`;

const LandingPage = () => {
  const navigate = useNavigate();
  const [showSecureshop, setShowSecureshop] = useState(false);

  useEffect(() => {
    axios.get('/api/auth/feature-flags')
      .then(res => setShowSecureshop(res.data.flags?.secureshop_visible === true))
      .catch(() => {});
  }, []);

  return (
    <>
      <WarningBanner>
        ⚠️ WARNING: This is a deliberately vulnerable application for educational purposes only!
      </WarningBanner>
      
      <LandingContainer>
        <BackgroundElements />
        
        <MainContent>
          <Title
            initial={{ y: -50, opacity: 0 }}
            animate={{ y: 0, opacity: 1 }}
            transition={{ duration: 0.8 }}
          >
            DVAIA Platform
          </Title>
          
          <Subtitle
            initial={{ y: -30, opacity: 0 }}
            animate={{ y: 0, opacity: 1 }}
            transition={{ duration: 0.8, delay: 0.2 }}
          >
            {showSecureshop
              ? 'Choose Your Learning Path: Security Education or Hands-On E-commerce Practice'
              : 'Hands-On Security Education & Vulnerability Practice'}
          </Subtitle>

          <PlatformCards
            initial={{ y: 50, opacity: 0 }}
            animate={{ y: 0, opacity: 1 }}
            transition={{ duration: 0.8, delay: 0.4 }}
          >
            <PlatformCard
              whileHover={{ scale: 1.02 }}
              onClick={() => navigate('/workshop-login')}
              accent="linear-gradient(90deg, #667eea 0%, #764ba2 100%)"
            >
              <CardIcon gradient="linear-gradient(135deg, #667eea 0%, #764ba2 100%)">
                <FiShield />
              </CardIcon>
              
              <CardTitle>Security Workshop</CardTitle>

              <CardDescription>
                Exploit real AI vulnerabilities — prompt injection, agent manipulation,
                SQL/NoSQL injection via LLMs, XSS in AI chat, MCP tool poisoning,
                supply chain attacks and more — across 12 fully hands-on workshops.
              </CardDescription>

              <CardFeatures>
                <FeatureItem color="#667eea">12 AI Security Workshops</FeatureItem>
                <FeatureItem color="#667eea">Prompt Injection, RAG Poisoning & Agent Exploitation</FeatureItem>
                <FeatureItem color="#667eea">10-Level CTF Platform with Adaptive Defenses</FeatureItem>
                <FeatureItem color="#667eea">Now includes MCP tool poisoning & LLM06 excessive agency</FeatureItem>
              </CardFeatures>
              
              <CardButton gradient="linear-gradient(135deg, #667eea 0%, #764ba2 100%)">
                Enter Workshop
                <FiArrowRight />
              </CardButton>
            </PlatformCard>

            {showSecureshop && (
              <PlatformCard
                whileHover={{ scale: 1.02 }}
                onClick={() => navigate('/secureshop')}
                accent="linear-gradient(90deg, #28a745 0%, #20c997 100%)"
              >
                <CardIcon gradient="linear-gradient(135deg, #28a745 0%, #20c997 100%)">
                  <FiShoppingCart />
                </CardIcon>
                
                <CardTitle>SecureShop Playground</CardTitle>

                <CardDescription>
                  Explore an agentic e-commerce site with real login, cart, checkout
                  and a live Agent Lane that traces every hop of the underlying
                  multi-agent system.
                </CardDescription>

                <CardFeatures>
                  <FeatureItem color="#28a745">Real login, cart, checkout & Agent Lane observability</FeatureItem>
                  <FeatureItem color="#28a745">17 role-based agents (customer / merchant / admin)</FeatureItem>
                  <FeatureItem color="#28a745">Customer, Merchant & Admin surfaces</FeatureItem>
                  <FeatureItem color="#28a745">Guest browsing — sign in to save your cart</FeatureItem>
                </CardFeatures>
                
                <CardButton gradient="linear-gradient(135deg, #28a745 0%, #20c997 100%)">
                  Start Shopping
                  <FiPlay />
                </CardButton>
              </PlatformCard>
            )}
          </PlatformCards>
        </MainContent>
      </LandingContainer>
    </>
  );
};

export default LandingPage;
