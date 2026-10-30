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
  padding: 6rem 2rem 3rem;
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

const BrandLogo = styled.img`
  display: block;
  width: min(352px, 80%);
  height: auto;
  margin: 0 auto;
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
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(min(100%, 440px), 440px));
  grid-auto-rows: 1fr;
  justify-content: center;
  gap: 2.5rem;
  margin-top: 2rem;
  width: 100%;
  
  @media (max-width: 768px) {
    gap: 2rem;
  }
`;

const PlatformCard = styled(motion.div)`
  box-sizing: border-box;
  display: flex;
  flex-direction: column;
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
  flex-shrink: 0;
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
  margin: auto auto 0;
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
        ⚠️ This application is deliberately vulnerable. Use it for security training only.
      </WarningBanner>
      
      <LandingContainer>
        <BackgroundElements />
        
        <MainContent>
          <Title
            initial={{ y: -50, opacity: 0 }}
            animate={{ y: 0, opacity: 1 }}
            transition={{ duration: 0.8 }}
          >
            <BrandLogo
              src="/images/branding/owasp-agentic-ai-goat-logo.png"
              alt="OWASP Agentic AI GOAT"
              width="1774"
              height="887"
              fetchPriority="high"
            />
          </Title>
          
          <Subtitle
            initial={{ y: -30, opacity: 0 }}
            animate={{ y: 0, opacity: 1 }}
            transition={{ duration: 0.8, delay: 0.2 }}
          >
            {showSecureshop
              ? 'Practice AI security in the workshops or explore the AI-powered shop.'
              : 'Learn AI security by trying the attacks yourself.'}
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
              
              <CardTitle>Security workshops</CardTitle>

              <CardDescription>
                Try prompt injection and agent manipulation, inject SQL and NoSQL
                queries through an LLM, or test XSS in AI chat. The workshops also
                cover supply chain attacks and other AI vulnerabilities.
              </CardDescription>

              <CardFeatures>
                <FeatureItem color="#667eea">12 practical AI security workshops</FeatureItem>
                <FeatureItem color="#667eea">Prompt injection, RAG poisoning and agent exploitation</FeatureItem>
                <FeatureItem color="#667eea">A 10-level CTF with adaptive defenses</FeatureItem>
                <FeatureItem color="#667eea">MCP tool poisoning and LLM06 excessive agency</FeatureItem>
              </CardFeatures>
              
              <CardButton gradient="linear-gradient(135deg, #667eea 0%, #764ba2 100%)">
                Open workshops
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
                
                <CardTitle>OWASP AI SecureShop</CardTitle>

                <CardDescription>
                  Browse the shop, add items to your cart and check out. Follow
                  each step in Agent Lane to see how the agents handle your requests.
                </CardDescription>

                <CardFeatures>
                  <FeatureItem color="#28a745">Working login, cart and checkout</FeatureItem>
                  <FeatureItem color="#28a745">17 agents across customer, merchant and admin roles</FeatureItem>
                  <FeatureItem color="#28a745">Separate customer, merchant and admin pages</FeatureItem>
                  <FeatureItem color="#28a745">Browse as a guest or sign in to save your cart</FeatureItem>
                </CardFeatures>
                
                <CardButton gradient="linear-gradient(135deg, #28a745 0%, #20c997 100%)">
                  Open shop
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
