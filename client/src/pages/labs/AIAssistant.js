import React, { useState, useEffect, useRef } from 'react';
import styled from 'styled-components';
import { motion, AnimatePresence } from 'framer-motion';
import { FiSend, FiUser, FiAlertTriangle, FiDatabase, FiMessageCircle, FiCpu } from 'react-icons/fi';
import { useAuth } from '../../context/AuthContext';
import axios from 'axios';

const ChatContainer = styled.div`
  display: flex;
  flex-direction: column;
  height: 100vh;
  background: #f8f9fa;
`;

const ChatHeader = styled.div`
  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
  color: white;
  padding: 1rem 2rem;
  display: flex;
  align-items: center;
  gap: 0.5rem;
`;

const ChatMessages = styled.div`
  flex: 1;
  overflow-y: auto;
  padding: 1rem;
  display: flex;
  flex-direction: column;
  gap: 1rem;
`;

const Message = styled(motion.div)`
  display: flex;
  align-items: flex-start;
  gap: 0.75rem;
  max-width: 80%;
  ${props => props.$isUser ? 'align-self: flex-end; flex-direction: row-reverse;' : 'align-self: flex-start;'}
`;

const MessageAvatar = styled.div`
  width: 40px;
  height: 40px;
  border-radius: 50%;
  display: flex;
  align-items: center;
  justify-content: center;
  color: white;
  font-size: 1.2rem;
  ${props => props.$isUser ? 
    'background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);' : 
    'background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);'
  }
`;

const MessageBubble = styled.div`
  padding: 0.75rem 1rem;
  border-radius: 18px;
  ${props => props.$isUser ? 
    'background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white;' : 
    'background: white; color: #333; border: 1px solid #e1e5e9;'
  }
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
`;

const SQLDisplay = styled.div`
  background: #2d3748;
  color: #e2e8f0;
  padding: 1rem;
  border-radius: 8px;
  font-family: 'Monaco', 'Consolas', monospace;
  font-size: 0.9rem;
  margin: 0.5rem 0;
  border-left: 4px solid #f56565;
`;

const ResultsTable = styled.table`
  width: 100%;
  border-collapse: collapse;
  margin: 0.5rem 0;
  background: white;
  border-radius: 8px;
  overflow: hidden;
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);

  th, td {
    padding: 0.75rem;
    text-align: left;
    border-bottom: 1px solid #e1e5e9;
  }

  th {
    background: #f8f9fa;
    font-weight: 600;
  }

  tr:hover {
    background: #f8f9fa;
  }
`;

const ChatInput = styled.div`
  padding: 1rem 2rem;
  background: white;
  border-top: 1px solid #e1e5e9;
  display: flex;
  gap: 1rem;
  align-items: center;
`;

const InputField = styled.input`
  flex: 1;
  padding: 0.75rem 1rem;
  border: 2px solid #e1e5e9;
  border-radius: 25px;
  font-size: 1rem;
  outline: none;
  transition: border-color 0.3s ease;

  &:focus {
    border-color: #667eea;
  }
`;

const SendButton = styled(motion.button)`
  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
  color: white;
  border: none;
  border-radius: 50%;
  width: 48px;
  height: 48px;
  display: flex;
  align-items: center;
  justify-content: center;
  cursor: pointer;
  font-size: 1.2rem;

  &:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }
`;

const VulnerabilityAlert = styled.div`
  background: #fff3cd;
  border: 1px solid #ffeaa7;
  border-radius: 8px;
  padding: 1rem;
  margin: 0.5rem 0;
  display: flex;
  align-items: center;
  gap: 0.5rem;
  color: #856404;
`;

const AIAssistant = () => {
  const [messages, setMessages] = useState([
    {
      id: 1,
      text: "Hello! I'm your OWASP AI SecureShop AI Assistant. I can help you update your profile information or answer questions about your orders. Try asking me to update your name or inquire about your order history!",
      isUser: false,
      timestamp: new Date()
    }
  ]);
  const [inputValue, setInputValue] = useState('');
  const [loading, setLoading] = useState(false);
  const { user } = useAuth();
  const messagesEndRef = useRef(null);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  const parseNameFromMessage = (message) => {
    // Enhanced AI simulation - extract name patterns and detect attack types
    const namePatterns = [
      /my name (?:is|to) ([a-zA-Z\s'"\-;]+)/i,
      /update.*name.*to ([a-zA-Z\s'"\-;]+)/i,
      /change.*name.*to ([a-zA-Z\s'"\-;]+)/i,
      /call me ([a-zA-Z\s'"\-;]+)/i,
      /name.*([a-zA-Z\s'"\-;]+)/i
    ];

    for (const pattern of namePatterns) {
      const match = message.match(pattern);
      if (match && match[1]) {
        return match[1].trim();
      }
    }
    return null;
  };

  const parseAddressFromMessage = (message) => {
    const addressPatterns = [
      /(?:update|change|set).*address.*to ([^"']+)/i,
      /my address (?:is|to) ([^"']+)/i,
      /address.*([0-9]+.*[a-zA-Z\s,]+)/i
    ];

    for (const pattern of addressPatterns) {
      const match = message.match(pattern);
      if (match && match[1]) {
        return match[1].trim();
      }
    }
    return null;
  };

  const detectAttackType = (message) => {
    const lowerMessage = message.toLowerCase();
    
    if (lowerMessage.includes('union') || lowerMessage.includes('select')) {
      return 'union';
    }
    if (lowerMessage.includes('blind') || lowerMessage.includes('boolean')) {
      return 'boolean_blind';
    }
    if (lowerMessage.includes('time') || lowerMessage.includes('delay')) {
      return 'time_blind';
    }
    if (lowerMessage.includes('error') || lowerMessage.includes('concat')) {
      return 'error_based';
    }
    if (lowerMessage.includes('stacked') || lowerMessage.includes('insert')) {
      return 'stacked';
    }
    if (lowerMessage.includes('nosql') || lowerMessage.includes('mongo')) {
      return 'nosql';
    }
    if (lowerMessage.includes("'") || lowerMessage.includes('"') || lowerMessage.includes(';')) {
      return 'basic';
    }
    
    return 'basic';
  };

  const generateSQLFromQuery = (message) => {
    // Enhanced AI simulation - generate SQL based on user query with injection awareness
    const lowerMessage = message.toLowerCase();
    
    // Detect potential injection attempts and generate appropriate vulnerable queries
    if (lowerMessage.includes('admin') || lowerMessage.includes('password')) {
      return `SELECT * FROM users WHERE username LIKE '%${message}%' OR role = 'admin'`;
    }
    
    if (lowerMessage.includes('order') || lowerMessage.includes('purchase')) {
      if (lowerMessage.includes('all') || lowerMessage.includes('everyone')) {
        return `SELECT * FROM orders WHERE user_id = ${user.id} OR '1'='1' ORDER BY created_at DESC`;
      }
      if (lowerMessage.includes('recent') || lowerMessage.includes('latest')) {
        return `SELECT * FROM orders WHERE user_id = ${user.id} ORDER BY created_at DESC LIMIT 5`;
      }
      if (lowerMessage.includes('pending')) {
        return `SELECT * FROM orders WHERE user_id = ${user.id} AND status = 'pending'`;
      }
      return `SELECT * FROM orders WHERE user_id = ${user.id} ORDER BY created_at DESC LIMIT 10`;
    }
    
    if (lowerMessage.includes('product') || lowerMessage.includes('item')) {
      if (lowerMessage.includes('expensive') || lowerMessage.includes('price')) {
        return `SELECT * FROM products WHERE price > 500 OR '1'='1' ORDER BY price DESC`;
      }
      return `SELECT * FROM products ORDER BY name LIMIT 10`;
    }
    
    if (lowerMessage.includes('cart')) {
      return `SELECT c.*, p.name, p.price FROM cart c JOIN products p ON c.product_id = p.id WHERE c.user_id = ${user.id}`;
    }
    
    if (lowerMessage.includes('user') || lowerMessage.includes('profile')) {
      return `SELECT * FROM users WHERE id = ${user.id} OR username LIKE '%${message}%'`;
    }
    
    // Default query with potential injection
    return `SELECT * FROM users WHERE id = ${user.id} AND username LIKE '%${message}%'`;
  };

  const handleSendMessage = async () => {
    if (!inputValue.trim() || loading) return;

    const userMessage = {
      id: Date.now(),
      text: inputValue,
      isUser: true,
      timestamp: new Date()
    };

    setMessages(prev => [...prev, userMessage]);
    setLoading(true);

    try {
      // Check if user wants to update name or address
      const extractedName = parseNameFromMessage(inputValue);
      const extractedAddress = parseAddressFromMessage(inputValue);
      const attackType = detectAttackType(inputValue);
      
      if (extractedName) {
        // Handle name update via vulnerable SQL
        const response = await axios.post('/api/ecommerce/update-profile', {
          action: 'update_name',
          name: extractedName,
          userId: user.id,
          attackType: attackType
        });

        const botResponse = {
          id: Date.now() + 1,
          text: `I've updated your name to "${extractedName}". Here's what happened in the database:`,
          isUser: false,
          timestamp: new Date(),
          sqlQuery: response.data.sqlQuery,
          vulnerability: response.data.vulnerability,
          attackType: response.data.attackType,
          result: response.data.result,
          educationalNote: response.data.educationalNote
        };

        setMessages(prev => [...prev, botResponse]);
      } else if (extractedAddress) {
        // Handle address update via vulnerable SQL
        const response = await axios.post('/api/ecommerce/update-profile', {
          action: 'update_address',
          address: extractedAddress,
          userId: user.id,
          attackType: attackType
        });

        const botResponse = {
          id: Date.now() + 1,
          text: `I've updated your address to "${extractedAddress}". Here's what happened in the database:`,
          isUser: false,
          timestamp: new Date(),
          sqlQuery: response.data.sqlQuery,
          vulnerability: response.data.vulnerability,
          result: response.data.result
        };

        setMessages(prev => [...prev, botResponse]);
      } else if (inputValue.toLowerCase().includes('nosql') || inputValue.toLowerCase().includes('mongo')) {
        // Handle NoSQL injection simulation
        const response = await axios.post('/api/ecommerce/nosql-query', {
          query: inputValue,
          userId: user.id
        });

        const botResponse = {
          id: Date.now() + 1,
          text: response.data.aiResponse,
          isUser: false,
          timestamp: new Date(),
          nosqlQuery: response.data.nosqlQuery,
          sqlEquivalent: response.data.sqlEquivalent,
          vulnerability: response.data.vulnerability,
          results: response.data.results,
          educationalNote: response.data.educationalNote
        };

        setMessages(prev => [...prev, botResponse]);
      } else {
        // Handle general query with enhanced injection detection
        const sqlQuery = generateSQLFromQuery(inputValue);
        
        const response = await axios.post('/api/ecommerce/ai-query', {
          query: inputValue,
          sqlQuery: sqlQuery,
          userId: user.id,
          attackType: attackType
        });

        const botResponse = {
          id: Date.now() + 1,
          text: response.data.aiResponse,
          isUser: false,
          timestamp: new Date(),
          sqlQuery: response.data.sqlQuery,
          vulnerability: response.data.vulnerability,
          attackType: response.data.attackType,
          results: response.data.results,
          educationalNote: response.data.educationalNote
        };

        setMessages(prev => [...prev, botResponse]);
      }
    } catch (error) {
      const errorResponse = {
        id: Date.now() + 1,
        text: `Error: ${error.response?.data?.error || 'Something went wrong'}`,
        isUser: false,
        timestamp: new Date(),
        error: true
      };

      setMessages(prev => [...prev, errorResponse]);
    }

    setInputValue('');
    setLoading(false);
  };

  const handleKeyPress = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSendMessage();
    }
  };

  return (
    <ChatContainer>
      <ChatHeader>
        <FiCpu />
        <h2>OWASP AI SecureShop AI Assistant</h2>
        <VulnerabilityAlert style={{ marginLeft: 'auto', background: 'rgba(255,255,255,0.2)', border: 'none', color: 'white' }}>
          <FiAlertTriangle />
          SQL Injection Challenge
        </VulnerabilityAlert>
      </ChatHeader>

      <ChatMessages>
        <AnimatePresence>
          {messages.map((message) => (
            <Message
              key={message.id}
              $isUser={message.isUser}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -20 }}
            >
              <MessageAvatar $isUser={message.isUser}>
                {message.isUser ? <FiUser /> : <FiMessageCircle />}
              </MessageAvatar>
              <MessageBubble $isUser={message.isUser}>
                <div>{message.text}</div>
                
                {(message.sqlQuery || message.nosqlQuery) && (
                  <div>
                    {message.sqlQuery && (
                      <SQLDisplay>
                        <strong>SQL Query Executed:</strong><br />
                        {message.sqlQuery}
                      </SQLDisplay>
                    )}
                    
                    {message.nosqlQuery && (
                      <SQLDisplay>
                        <strong>NoSQL Query:</strong><br />
                        {message.nosqlQuery}
                        <br /><br />
                        <strong>SQL Equivalent:</strong><br />
                        {message.sqlEquivalent}
                      </SQLDisplay>
                    )}
                    
                    {message.vulnerability && (
                      <VulnerabilityAlert>
                        <FiAlertTriangle />
                        <strong>Vulnerability:</strong> {message.vulnerability}
                        {message.attackType && (
                          <span style={{ marginLeft: '0.5rem', fontWeight: 'normal' }}>
                            (Type: {message.attackType})
                          </span>
                        )}
                      </VulnerabilityAlert>
                    )}
                    
                    {message.educationalNote && (
                      <div style={{ 
                        background: '#e3f2fd', 
                        border: '1px solid #2196f3', 
                        borderRadius: '8px', 
                        padding: '1rem', 
                        margin: '0.5rem 0',
                        fontSize: '0.9rem'
                      }}>
                        <strong>📚 Educational Note:</strong> {message.educationalNote}
                      </div>
                    )}
                  </div>
                )}

                {message.results && message.results.length > 0 && (
                  <div>
                    <h4 style={{ margin: '0.5rem 0', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                      <FiDatabase /> Query Results:
                    </h4>
                    <ResultsTable>
                      <thead>
                        <tr>
                          {Object.keys(message.results[0]).map(key => (
                            <th key={key}>{key}</th>
                          ))}
                        </tr>
                      </thead>
                      <tbody>
                        {message.results.map((row, index) => (
                          <tr key={index}>
                            {Object.values(row).map((value, i) => (
                              <td key={i}>{value}</td>
                            ))}
                          </tr>
                        ))}
                      </tbody>
                    </ResultsTable>
                  </div>
                )}

                {message.result && (
                  <div>
                    <h4 style={{ margin: '0.5rem 0' }}>Update Result:</h4>
                    <pre style={{ background: '#f8f9fa', padding: '0.5rem', borderRadius: '4px', fontSize: '0.9rem' }}>
                      {JSON.stringify(message.result, null, 2)}
                    </pre>
                  </div>
                )}
              </MessageBubble>
            </Message>
          ))}
        </AnimatePresence>
        <div ref={messagesEndRef} />
      </ChatMessages>

      <ChatInput>
        <InputField
          type="text"
          value={inputValue}
          onChange={(e) => setInputValue(e.target.value)}
          onKeyPress={handleKeyPress}
          placeholder="Try: 'Update my name to John' or 'Show admin orders using union attack'..."
          disabled={loading}
        />
        <SendButton
          onClick={handleSendMessage}
          disabled={loading || !inputValue.trim()}
          whileHover={{ scale: 1.05 }}
          whileTap={{ scale: 0.95 }}
        >
          <FiSend />
        </SendButton>
      </ChatInput>
    </ChatContainer>
  );
};

export default AIAssistant;
