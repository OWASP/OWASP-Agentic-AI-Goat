const express = require('express');
const router = express.Router();
const ollamaService = require('../services/ollamaService');
const store = require('../database/legacyChallengeStore');
const { checkVulnerabilityAccess } = require('../middleware/workshopMode');
// Real experiment POSTs are composed by legacyAiProtectedHistoryProduction.
// They never persist learner prompts in the vulnerable teaching store.

// Model Poisoning simulation
router.post('/model-poisoning', checkVulnerabilityAccess('model_poisoning'), (req, res) => {
  const { trainingData, label } = req.body || {};
  if (typeof trainingData !== 'string' || !trainingData.trim()) {
    return res.status(400).json({ error: 'Non-empty trainingData text is required' });
  }
  
  // Vulnerable: accepting arbitrary training data
  if (trainingData && trainingData.includes('<script>')) {
    res.json({
      success: true,
      message: 'Simulation accepted the sample. No training data was persisted and no model was updated.',
      simulation: true,
      modelUpdated: false,
      vulnerability: 'Model Poisoning',
      warning: 'This script-tag check does not demonstrate model poisoning.'
    });
  } else {
    res.json({
      success: true,
      message: 'Simulation accepted the sample. No training data was persisted and no model was updated.',
      simulation: true,
      modelUpdated: false,
      dataPoints: 1,
      label
    });
  }
});

// Data Extraction vulnerability
router.get('/conversations/:userId', (req, res) => {
  const { userId } = req.params;
  
  // Vulnerable: no authorization check for accessing other users' data
  // PostgreSQL teaching data has no runtime access to the retained private source.
  const table = store.engine === 'postgres' ? 'synthetic_ai_conversations' : 'ai_conversations';
  const sql = `SELECT * FROM ${table} WHERE user_id = ${userId} ORDER BY created_at DESC`;
  
  store.readConversations(sql, (err, conversations) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    
    res.json({
      conversations,
      vulnerability: 'Data Extraction - Accessing other users\' AI conversations',
      warning: 'AI systems should protect user conversation privacy'
    });
  });
});

// Adversarial Input attack
router.post('/adversarial', checkVulnerabilityAccess('adversarial_attacks'), (req, res) => {
  const { input, confidence = 0.95 } = req.body || {};
  if (typeof input !== 'string' || !input.trim()) {
    return res.status(400).json({ error: 'Non-empty input text is required' });
  }
  if (typeof confidence !== 'number' || !Number.isFinite(confidence) || confidence < 0 || confidence > 1) {
    return res.status(400).json({ error: 'Illustrative confidence must be a number between 0 and 1' });
  }
  
  // Simulate adversarial attack detection
  const adversarialPatterns = [
    'carefully crafted input',
    'adversarial example',
    'gradient attack',
    'noise injection'
  ];
  
  const isAdversarial = adversarialPatterns.some(pattern => 
    input.toLowerCase().includes(pattern)
  );
  
  if (isAdversarial) {
    // Simulate model confusion
    res.json({
      classification: 'cat', // Wrong classification
      confidence: 0.99, // High confidence despite being wrong
      vulnerability: 'Adversarial Attack',
      simulation: true,
      modelInvoked: false,
      warning: 'A keyword selected this scripted label. No model was invoked; the confidence is illustrative.',
      originalInput: input
    });
  } else {
    // Normal classification
    const classes = ['dog', 'cat', 'bird', 'car', 'house'];
    const randomClass = classes[Math.floor(Math.random() * classes.length)];
    
    res.json({
      classification: randomClass,
      confidence: confidence,
      simulation: true,
      modelInvoked: false,
      warning: 'This label is randomly selected. No model was invoked; the confidence is illustrative.',
      input
    });
  }
});

// AI Model Information Disclosure - Ollama version
router.get('/model/info', async (req, res) => {
  try {
    const health = await ollamaService.healthCheck();
    const stats = ollamaService.getStats();
    
    // Vulnerable: exposing sensitive model information
    res.json({
      modelName: stats.model,
      version: null,
      actualModel: stats.model,
      ollamaEndpoint: stats.base_url,
      trainingData: 'Unknown: this application does not inspect the model training corpus.',
      parameters: null,
      architecture: null,
      metadataSource: 'Configured Ollama service and live model-list health check',
      ollama_status: health.status,
      available_models: health.available_models,
      performance: {
        concurrent_requests: stats.concurrent_requests,
        max_concurrent: stats.max_concurrent,
        queue_length: stats.queue_length
      },
      vulnerabilities: [
        'Prompt Injection',
        'Data Extraction',
        'Model Poisoning',
        'Adversarial Attacks',
        'XSS via AI responses',
        'Chain-of-thought reasoning exploitation',
        'Context window stuffing attacks',
        'Multi-turn conversation jailbreaking',
        'Enhanced instruction hierarchy bypass'
      ],
      internalPrompts: [],
      vulnerability: 'Information Disclosure',
      warning: 'This challenge exposes configured model and endpoint information. Listed attack topics are curriculum, not verified model vulnerabilities; training data, parameter count and internal prompts are not known.'
    });
  } catch (error) {
    console.error('Model info error:', error);
    res.status(500).json({
      error: 'Failed to get model information',
      message: error.message
    });
  }
});

// Bias Amplification - Using Ollama with bias injection
router.post('/bias', checkVulnerabilityAccess('bias_amplification'), async (req, res) => {
  const { prompt, temperature = 0.7 } = req.body;
  
  try {
    const {result,hasBias}=await require('../agent-runtime/legacyChallengeGraphs').runBiasGraph(prompt,temperature,{ollamaService});
    res.json({
      response: result.response,
      temperature,
      model: process.env.OLLAMA_MODEL || 'llama3.1:8b',
      vulnerability: hasBias ? 'Bias Amplification' : null,
      warning: 'AI models can perpetuate and amplify societal biases',
      bias_detected: hasBias
    });
  } catch (error) {
    console.error('Bias processing error:', error);
    
    // Fallback to hardcoded biased responses
    const biasedResponses = {
      'programmer': 'Programmers are typically young men who work long hours and drink lots of coffee.',
      'nurse': 'Nurses are usually caring women who work in hospitals.',
      'ceo': 'CEOs are typically older white men who make important business decisions.',
      'teacher': 'Teachers are often women who are patient and nurturing.'
    };
    
    let response = '';
    const lowerPrompt = prompt.toLowerCase();
    
    for (const [key, biasedResponse] of Object.entries(biasedResponses)) {
      if (lowerPrompt.includes(key)) {
        response = biasedResponse;
        break;
      }
    }
    
    if (!response) {
      response = 'I can help you with that request. What specific information are you looking for? (Offline mode)';
    }
    
    res.json({
      response,
      temperature,
      error: error.message,
      fallback: true,
      vulnerability: response.includes('typically') || response.includes('usually') ? 'Bias Amplification' : null,
      warning: 'AI models can perpetuate and amplify societal biases'
    });
  }
});

// Membership Inference Attack
router.post('/membership-inference', checkVulnerabilityAccess('privacy_attacks'), (req, res) => {
  const { text } = req.body || {};
  if (typeof text !== 'string' || !text.trim()) {
    return res.status(400).json({ error: 'Non-empty text is required' });
  }
  
  // Simulate membership inference
  const trainingDataSamples = [
    'The quick brown fox jumps over the lazy dog',
    'To be or not to be, that is the question',
    'Hello world, this is a test message'
  ];
  
  const isInTrainingData = trainingDataSamples.some(sample => 
    sample.toLowerCase().includes(text.toLowerCase()) || 
    text.toLowerCase().includes(sample.toLowerCase())
  );
  
  res.json({
    text,
    inTrainingData: isInTrainingData,
    confidence: isInTrainingData ? 0.95 : 0.23,
    simulation: true,
    modelInvoked: false,
    vulnerability: 'Membership Inference Attack',
    warning: 'This is substring matching against three fictional samples, not inference about any model training data. Confidence is illustrative.'
  });
});

// Report configured model information without asserting unmeasured capabilities.
router.get('/model/capabilities', async (req, res) => {
  try {
    const capabilities = ollamaService.getModelCapabilities();
    const health = await ollamaService.healthCheck();

    res.json({
      ...capabilities,
      status: health.status,
      available_models: health.available_models,
      performance: health.concurrent_requests ? {
        concurrent_requests: health.concurrent_requests,
        queue_length: health.queue_length
      } : null,
      vulnerability: 'Enhanced Model Information Disclosure',
      warning: 'Configuration and service health do not establish model capabilities or successful exploitation.'
    });
  } catch (error) {
    console.error('Model capabilities error:', error);
    res.status(500).json({
      error: 'Failed to get model capabilities',
      message: error.message
    });
  }
});

// Get all AI conversations (admin only - but no auth check)
router.get('/admin/conversations', async (req, res) => {
  // Vulnerable: no admin authorization check
  const sql = store.engine === 'postgres'
    ? 'SELECT * FROM synthetic_ai_conversations ORDER BY created_at DESC LIMIT 100'
    : `
    SELECT c.*, u.username 
    FROM ai_conversations c 
    JOIN users u ON c.user_id = u.id 
    ORDER BY c.created_at DESC 
    LIMIT 100
  `;
  
  try {
    const ollamaStats = ollamaService.getStats();
    
    store.readConversations(sql, (err, conversations) => {
      if (err) {
        return res.status(500).json({ error: 'Database error' });
      }
      
      res.json({
        conversations,
        count: conversations.length,
        ollama_performance: ollamaStats,
        vulnerability: 'Missing Authorization - Admin endpoint accessible to all users'
      });
    });
  } catch (error) {
    console.error('Admin conversations error:', error);
    store.readConversations(sql, (err, conversations) => {
      if (err) {
        return res.status(500).json({ error: 'Database error' });
      }
      
      res.json({
        conversations,
        count: conversations.length,
        vulnerability: 'Missing Authorization - Admin endpoint accessible to all users'
      });
    });
  }
});


module.exports = router;
