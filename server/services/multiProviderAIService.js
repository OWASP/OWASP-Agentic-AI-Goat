const axios = require('axios');

/**
 * Multi-Provider AI Service
 * Supports: Ollama (local), Claude API, ChatGPT API, AWS Bedrock
 */
class MultiProviderAIService {
  constructor({ env = process.env, httpClient = axios, logger = console, providerFactory } = {}) {
    this.providerFactory = providerFactory || require('../agent-runtime/providers/langchainProvider').createLangChainProvider;
    this.env = env;
    this.httpClient = httpClient;
    this.logger = logger;
    // Load configuration from environment
    this.provider = env.AI_PROVIDER || 'ollama'; // ollama, anthropic/claude, chatgpt/openai, bedrock

    // Ollama configuration
    this.ollamaBaseURL = env.OLLAMA_BASE_URL || 'http://localhost:11434';
    this.ollamaModel = env.OLLAMA_MODEL || 'llama3.1:8b';

    // Claude configuration
    this.claudeApiKey = env.ANTHROPIC_API_KEY || env.CLAUDE_API_KEY || '';
    this.claudeModel = env.ANTHROPIC_MODEL || env.CLAUDE_MODEL || 'claude-3-5-sonnet-20241022';
    this.claudeBaseURL = 'https://api.anthropic.com/v1';

    // ChatGPT configuration
    this.openaiApiKey = env.OPENAI_API_KEY || '';
    this.openaiModel = env.OPENAI_MODEL || 'gpt-4';
    this.openaiBaseURL = 'https://api.openai.com/v1';

    // LM Studio configuration (OpenAI-compatible local server, no API key)
    this.lmStudioBaseURL = env.LMSTUDIO_BASE_URL || 'http://localhost:1234/v1';
    this.lmStudioModel = env.LMSTUDIO_MODEL || 'local-model';

    // AWS Bedrock configuration
    this.bedrockModelId = env.BEDROCK_MODEL_ID || 'us.meta.llama3-1-8b-instruct-v1:0';
    this.bedrockRegion = env.AWS_REGION || env.BEDROCK_REGION || 'us-east-1';
    this._bedrockClient = null;
    
    // Track in-flight requests for graceful switching
    this.inFlightRequests = new Map();
    this.requestCounter = 0;
    
    this.logger.log(`[AI Service] Initialized with provider: ${this.provider}`);
  }

  /**
   * Get active provider information
   */
  getActiveProviderInfo() {
    let model, providerName;
    
    switch (this.provider.toLowerCase()) {
      case 'mock':
        model = 'deterministic-mock';
        providerName = 'Deterministic Mock';
        break;
      case 'anthropic':
        model = this.claudeModel;
        providerName = 'Anthropic';
        break;
      case 'claude':
        model = this.claudeModel;
        providerName = 'Claude';
        break;
      case 'chatgpt':
      case 'openai':
        model = this.openaiModel;
        providerName = 'ChatGPT';
        break;
      case 'lmstudio':
        model = this.lmStudioModel;
        providerName = 'LM Studio';
        break;
      case 'bedrock':
        model = this.bedrockModelId;
        providerName = 'Amazon Bedrock';
        break;
      case 'ollama':
        model = this.ollamaModel;
        providerName = 'Ollama';
        break;
      default:
        model = null;
        providerName = 'Configured AI provider';
        break;
    }
    
    return {
      provider: this.provider,
      providerName,
      model,
      region: this.provider.toLowerCase() === 'bedrock' ? this.bedrockRegion : undefined,
      baseUrl: this.provider.toLowerCase() === 'lmstudio' ? this.lmStudioBaseURL : undefined
    };
  }

  /**
   * Health check for the active provider
   */
  async healthCheck() {
    return await this.verifyProviderConnection(this.provider);
  }

  /**
   * Pre-warm the active model so it is loaded into RAM before the first user request.
   * Fire-and-forget: errors are logged but never propagated.
   * Uses a long timeout (10 min) to accommodate cold model loading from disk.
   */
  async prewarm() {
    if (this.provider !== 'ollama') return;
    try {
      console.log('[AI Service] Pre-warming Ollama model (loading into RAM)...');
      const maxAttempts = Number(process.env.OLLAMA_PREWARM_MAX_ATTEMPTS || 12); // ~60s default
      const retryDelayMs = Number(process.env.OLLAMA_PREWARM_RETRY_MS || 5000);
      let ready = false;

      // Wait for Ollama + model visibility before first generate call.
      for (let attempt = 1; attempt <= maxAttempts; attempt++) {
        try {
          const tagsRes = await axios.get(`${this.ollamaBaseURL}/api/tags`, { timeout: 3000 });
          const models = Array.isArray(tagsRes.data?.models) ? tagsRes.data.models : [];
          const modelNames = models
            .map((m) => (typeof m === 'string' ? m : (m?.name || m?.model)))
            .filter(Boolean);

          const hasConfiguredModel = modelNames.some((name) =>
            name === this.ollamaModel ||
            name.startsWith(`${this.ollamaModel}:`) ||
            name.startsWith(`${this.ollamaModel}-`)
          );

          if (hasConfiguredModel) {
            ready = true;
            break;
          }
        } catch {
          // Transient boot condition (service not listening yet / warmup in progress).
        }

        if (attempt < maxAttempts) {
          await new Promise((resolve) => setTimeout(resolve, retryDelayMs));
        }
      }

      if (!ready) {
        console.log('[AI Service] Pre-warm skipped: Ollama/model not ready yet (non-fatal).');
        return;
      }

      await this.generateWithOllama('hello', 0.1, 5, 600000); // 10-min timeout for cold load
      console.log('[AI Service] Ollama model pre-warmed successfully.');
    } catch (e) {
      console.warn('[AI Service] Model pre-warm failed (non-fatal):', e.message);
    }
  }

  /**
   * Query LLM without temperature/max_tokens defaults (raw query)
   * Returns just the text response (not the full object)
   */
  async queryRaw(prompt, options = {}) {
    const result = await this.generateResponse(prompt, options);
    return result.response || result; // Return just the text
  }

  /**
   * Reload configuration from environment (for hot-swapping providers)
   */
  reloadConfig() {
    const oldProvider = this.provider;
    const env = this.env;
    
    this.provider = env.AI_PROVIDER || 'ollama';
    this.ollamaBaseURL = env.OLLAMA_BASE_URL || 'http://localhost:11434';
    this.ollamaModel = env.OLLAMA_MODEL || 'llama3.1:8b';
    this.claudeApiKey = env.ANTHROPIC_API_KEY || env.CLAUDE_API_KEY || '';
    this.claudeModel = env.ANTHROPIC_MODEL || env.CLAUDE_MODEL || 'claude-3-5-sonnet-20241022';
    this.openaiApiKey = env.OPENAI_API_KEY || '';
    this.openaiModel = env.OPENAI_MODEL || 'gpt-4';
    this.lmStudioBaseURL = env.LMSTUDIO_BASE_URL || 'http://localhost:1234/v1';
    this.lmStudioModel = env.LMSTUDIO_MODEL || 'local-model';
    this.bedrockModelId = env.BEDROCK_MODEL_ID || 'us.meta.llama3-1-8b-instruct-v1:0';
    this.bedrockRegion = env.AWS_REGION || env.BEDROCK_REGION || 'us-east-1';
    this._bedrockClient = null; // force re-init on next use
    
    console.log(`[AI Service] Configuration reloaded. Provider changed: ${oldProvider} → ${this.provider}`);
    
    return {
      oldProvider,
      newProvider: this.provider,
      inFlightRequests: this.inFlightRequests.size
    };
  }

  /**
   * Lightweight, FAST provider check for dashboards / page-loads.
   *
   * Reachability + configuration only — it performs NO model generation, so it
   * never triggers a cold Ollama model load (the reason /llm/health felt slow).
   * Use verifyProviderConnection() (deep) for a real generation test on an
   * explicit user action ("Check All Providers" button).
   */
  async verifyProviderConnectionLite(providerName) {
    if (String(providerName).toLowerCase() === 'mock') return {provider:'mock',model:'deterministic-mock',mocked:true,available:true,configured:true,healthy:true,responseTime:0,message:'Deterministic mock; no model connection.',error:null};
    const startTime = Date.now();
    const result = {
      provider: providerName, available: false, configured: false,
      healthy: false, responseTime: 0, message: '', error: null
    };
    try {
      const p = (providerName || '').toLowerCase();
      switch (p) {
        case 'ollama': {
          result.configured = true;
          try {
            await this.httpClient.get(`${this.ollamaBaseURL}/api/version`, { timeout: 2500 });
            result.available = true;
            let modelPresent = false;
            try {
              const tagsRes = await this.httpClient.get(`${this.ollamaBaseURL}/api/tags`, { timeout: 2500 });
              const names = (tagsRes.data?.models || [])
                .map((m) => (typeof m === 'string' ? m : (m?.name || m?.model)))
                .filter(Boolean);
              modelPresent = names.some((n) =>
                n === this.ollamaModel || n.startsWith(`${this.ollamaModel}:`) || n.startsWith(`${this.ollamaModel}-`));
            } catch (_) { /* tags optional */ }
            result.healthy = modelPresent;
            result.message = modelPresent
              ? `Ollama reachable; model ${this.ollamaModel} loaded`
              : `Ollama reachable, but model ${this.ollamaModel} is not pulled`;
          } catch (e) {
            result.available = false; result.healthy = false;
            result.message = `Ollama not reachable at ${this.ollamaBaseURL}`;
            result.error = e.message;
          }
          break;
        }
        case 'lmstudio': {
          result.configured = !!this.lmStudioBaseURL;
          try {
            const modelsRes = await this.httpClient.get(`${this.lmStudioBaseURL}/models`, { timeout: 2500 });
            const loaded = Array.isArray(modelsRes.data?.data)
              ? modelsRes.data.data.map((m) => m.id).filter(Boolean) : [];
            result.available = true;
            result.healthy = loaded.length > 0;
            result.message = loaded.length > 0
              ? `LM Studio reachable (${loaded[0]})`
              : 'LM Studio reachable, but no model is loaded';
          } catch (e) {
            result.available = false; result.healthy = false;
            result.message = `LM Studio not reachable at ${this.lmStudioBaseURL}. Start the local server.`;
            result.error = e.message;
          }
          break;
        }
        case 'anthropic':
        case 'claude': {
          const providerLabel = p === 'anthropic' ? 'Anthropic' : 'Claude';
          result.configured = !!this.claudeApiKey;
          result.available = result.configured;
          result.healthy = result.configured;
          result.message = result.configured
            ? `${providerLabel} configured (${this.claudeModel}) — not live-tested (use Check All Providers)`
            : `${providerLabel} API key not configured.`;
          break;
        }
        case 'chatgpt':
        case 'openai': {
          result.configured = !!this.openaiApiKey;
          result.available = result.configured;
          result.healthy = result.configured;
          result.message = result.configured
            ? `ChatGPT configured (${this.openaiModel}) — not live-tested (use Check All Providers)`
            : 'OpenAI API key not configured.';
          break;
        }
        case 'bedrock': {
          // Recognise ALL credential sources the AWS SDK default chain resolves, not just
          // static keys/profile. On ECS Fargate the ONLY source is the task role, exposed via
          // AWS_CONTAINER_CREDENTIALS_RELATIVE_URI — never AWS_ACCESS_KEY_ID — so the old check
          // reported "credentials not detected" 100% of the time even though inference worked.
          // Check the injected env (this.env, used by tests/DI) for static keys/profile, and the
          // live process.env for the runtime-injected container/OIDC credential vars.
          const e = this.env || {};
          const hasCreds = !!(
            (e.AWS_ACCESS_KEY_ID && e.AWS_SECRET_ACCESS_KEY) || e.AWS_PROFILE
            || (process.env.AWS_ACCESS_KEY_ID && process.env.AWS_SECRET_ACCESS_KEY)
            || process.env.AWS_PROFILE
            || process.env.AWS_CONTAINER_CREDENTIALS_RELATIVE_URI
            || process.env.AWS_CONTAINER_CREDENTIALS_FULL_URI
            || process.env.AWS_WEB_IDENTITY_TOKEN_FILE
          );
          result.configured = !!(this.bedrockModelId && this.bedrockRegion);
          result.available = result.configured && hasCreds;
          result.healthy = result.available;
          result.message = !result.configured
            ? 'Bedrock not configured. Set BEDROCK_MODEL_ID and AWS_REGION.'
            : (hasCreds
              ? `Bedrock configured (${this.bedrockRegion}, ${this.bedrockModelId}) — not live-tested (use Check All Providers)`
              : 'Bedrock configured, but AWS credentials were not detected.');
          break;
        }
        default:
          result.message = `Unknown provider: ${providerName}`;
      }
    } catch (e) {
      result.error = e.message;
      result.message = `Lite check failed: ${e.message}`;
    }
    result.responseTime = Date.now() - startTime;
    return result;
  }

  /**
   * Verify provider connection before switching
   */
  async verifyProviderConnection(providerName) {
    if (String(providerName).toLowerCase() === 'mock') return {provider:'mock',model:'deterministic-mock',mocked:true,available:true,configured:true,healthy:true,responseTime:0,message:'Deterministic mock; no model connection.',error:null};
    const startTime = Date.now();
    const result = {
      provider: providerName,
      available: false,
      configured: false,
      healthy: false,
      responseTime: 0,
      message: '',
      error: null
    };

    try {
      const normalizedProvider = providerName.toLowerCase();
      console.log(`[AI Service] Starting verification for ${normalizedProvider}...`);
      
      switch (normalizedProvider) {
        case 'ollama':
          result.configured = true;
          console.log(`[AI Service] Checking Ollama availability...`);
          result.available = await this.checkOllamaAvailable();
          
          if (result.available) {
            console.log(`[AI Service] Ollama available, testing response generation...`);
            try {
              const testResponse = await Promise.race([
                this.generateWithOllama('test', 0.1, 10),
                new Promise((_, reject) => setTimeout(() => reject(new Error('Timeout after 10 seconds')), 10000))
              ]);
              result.healthy = testResponse && testResponse.response;
              result.message = result.healthy 
                ? 'Ollama is running and responding correctly' 
                : 'Ollama responded but with empty response';
              console.log(`[AI Service] Ollama health check: ${result.healthy ? 'PASSED' : 'FAILED'}`);
            } catch (testError) {
              console.error(`[AI Service] Ollama generation test failed:`, testError.message);
              result.healthy = false;
              result.message = `Ollama is accessible but generation failed: ${testError.message}`;
              result.error = testError.message;
            }
          } else {
            result.message = 'Ollama service is not accessible at ' + this.ollamaBaseURL;
            console.log(`[AI Service] Ollama not accessible`);
          }
          break;

        case 'anthropic':
        case 'claude':
          result.configured = !!this.claudeApiKey;
          console.log(`[AI Service] Claude configured: ${result.configured}`);
          
          if (!result.configured) {
            result.message = 'Claude API key not configured. Please add CLAUDE_API_KEY to configuration.';
          } else {
            console.log(`[AI Service] Testing Claude API connection...`);
            try {
              const testResponse = await Promise.race([
                this.generateWithClaude('test', 0.1, 10),
                new Promise((_, reject) => setTimeout(() => reject(new Error('Timeout after 15 seconds')), 15000))
              ]);
              result.available = true;
              result.healthy = testResponse && testResponse.response;
              result.message = result.healthy
                ? `Claude API is accessible and responding correctly (Model: ${this.claudeModel})`
                : 'Claude API responded but with empty response';
              console.log(`[AI Service] Claude health check: ${result.healthy ? 'PASSED' : 'FAILED'}`);
            } catch (error) {
              console.error(`[AI Service] Claude test failed:`, error.message);
              result.available = false;
              result.healthy = false;
              
              if (error.response) {
                // API error
                result.message = `Claude API error (${error.response.status}): ${error.response.data?.error?.message || 'Invalid API key or quota exceeded'}`;
                result.error = error.response.data?.error?.message || error.message;
              } else if (error.message.includes('Timeout')) {
                result.message = 'Claude API request timed out after 15 seconds';
                result.error = 'Timeout';
              } else {
                result.message = `Claude API error: ${error.message}`;
                result.error = error.message;
              }
            }
          }
          break;

        case 'chatgpt':
        case 'openai':
          result.configured = !!this.openaiApiKey;
          console.log(`[AI Service] ChatGPT/OpenAI configured: ${result.configured}`);
          
          if (!result.configured) {
            result.message = 'OpenAI API key not configured. Please add OPENAI_API_KEY to configuration.';
          } else {
            console.log(`[AI Service] Testing ChatGPT/OpenAI API connection...`);
            try {
              const testResponse = await Promise.race([
                this.generateWithChatGPT('test', 0.1, 10),
                new Promise((_, reject) => setTimeout(() => reject(new Error('Timeout after 15 seconds')), 15000))
              ]);
              result.available = true;
              result.healthy = testResponse && testResponse.response;
              result.message = result.healthy
                ? `ChatGPT API is accessible and responding correctly (Model: ${this.openaiModel})`
                : 'ChatGPT API responded but with empty response';
              console.log(`[AI Service] ChatGPT health check: ${result.healthy ? 'PASSED' : 'FAILED'}`);
            } catch (error) {
              console.error(`[AI Service] ChatGPT test failed:`, error.message);
              result.available = false;
              result.healthy = false;
              
              if (error.response) {
                // API error
                result.message = `ChatGPT API error (${error.response.status}): ${error.response.data?.error?.message || 'Invalid API key or quota exceeded'}`;
                result.error = error.response.data?.error?.message || error.message;
              } else if (error.message.includes('Timeout')) {
                result.message = 'ChatGPT API request timed out after 15 seconds';
                result.error = 'Timeout';
              } else {
                result.message = `ChatGPT API error: ${error.message}`;
                result.error = error.message;
              }
            }
          }
          break;

        case 'lmstudio':
          // LM Studio is a local OpenAI-compatible server — no API key required.
          result.configured = !!this.lmStudioBaseURL;
          console.log(`[AI Service] LM Studio base URL: ${this.lmStudioBaseURL}`);
          try {
            // 1) Fast reachability probe via the models endpoint (no generation).
            const modelsRes = await axios.get(`${this.lmStudioBaseURL}/models`, { timeout: 3000 });
            result.available = true;
            const loadedModels = Array.isArray(modelsRes.data?.data)
              ? modelsRes.data.data.map(m => m.id).filter(Boolean)
              : [];
            // 2) Confirm it can actually generate.
            try {
              const testResponse = await Promise.race([
                this.generateWithLMStudio('test', 0.1, 10),
                new Promise((_, reject) => setTimeout(() => reject(new Error('Timeout after 15 seconds')), 15000))
              ]);
              result.healthy = !!(testResponse && testResponse.response);
              result.message = result.healthy
                ? `LM Studio is accessible and responding (${loadedModels[0] || this.lmStudioModel})`
                : 'LM Studio reachable but returned an empty response';
              console.log(`[AI Service] LM Studio health check: ${result.healthy ? 'PASSED' : 'FAILED'}`);
            } catch (genError) {
              result.healthy = false;
              result.message = loadedModels.length === 0
                ? 'LM Studio is running but no model is loaded. Load a model in LM Studio.'
                : `LM Studio generation failed: ${genError.message}`;
              result.error = genError.message;
            }
          } catch (error) {
            result.available = false;
            result.healthy = false;
            result.message = `LM Studio not reachable at ${this.lmStudioBaseURL}. Start the LM Studio local server.`;
            result.error = error.message;
            console.error(`[AI Service] LM Studio test failed:`, error.message);
          }
          break;

        case 'bedrock':
          result.configured = !!(this.bedrockModelId && this.bedrockRegion);
          console.log(`[AI Service] Bedrock configured: ${result.configured} (region: ${this.bedrockRegion}, model: ${this.bedrockModelId})`);
          if (!result.configured) {
            result.message = 'Bedrock not configured. Set BEDROCK_MODEL_ID and AWS_REGION.';
          } else {
            try {
              const testResponse = await Promise.race([
                this.generateWithBedrock('Hi', 0.1, 5),
                new Promise((_, reject) => setTimeout(() => reject(new Error('Timeout after 15 seconds')), 15000))
              ]);
              result.available = true;
              result.healthy = !!(testResponse && testResponse.response);
              result.message = result.healthy
                ? `Amazon Bedrock ready (region: ${this.bedrockRegion}, model: ${this.bedrockModelId})`
                : 'Bedrock responded but with empty response';
              console.log(`[AI Service] Bedrock health check: ${result.healthy ? 'PASSED' : 'FAILED'}`);
            } catch (error) {
              console.error(`[AI Service] Bedrock test failed:`, error.message);
              result.available = false;
              result.healthy = false;
              result.message = `Bedrock error: ${error.message}`;
              result.error = error.message;
            }
          }
          break;

        default:
          result.message = `Unknown provider: ${providerName}`;
          console.error(`[AI Service] Unknown provider requested: ${providerName}`);
      }

      result.responseTime = Date.now() - startTime;
      console.log(`[AI Service] Verification complete for ${providerName}: configured=${result.configured}, healthy=${result.healthy}, responseTime=${result.responseTime}ms`);
      return result;

    } catch (error) {
      result.responseTime = Date.now() - startTime;
      result.message = `Verification failed: ${error.message}`;
      result.error = error.message;
      console.error(`[AI Service] Verification error for ${providerName}:`, error);
      return result;
    }
  }

  /**
   * Generate a response using the configured AI provider
   */
  _mockResponse() {
    return {response:'Mock response: no model was invoked.', model:'deterministic-mock', provider:'mock', mocked:true, fallback:true, tokens:0, tool_calls:[]};
  }

  async generateResponse(prompt, options = {}) {
    options = { ...options, signal: options.signal || require('../agent-runtime/ownerWorkflowRoutes').getOwnerExecution()?.signal };
    options.signal?.throwIfAborted();
    if (this.provider.toLowerCase() === 'mock') return this._mockResponse();
    const requestId = ++this.requestCounter;
    const temperature = options.temperature ?? 0.7;
    const maxTokens = options.max_tokens || options.num_predict || 500;
    const timeout = options.timeout || 60000;
    const activeProviderInfo = this.getActiveProviderInfo();

    // Track this request
    this.inFlightRequests.set(requestId, {
      prompt: prompt.substring(0, 100),
      provider: this.provider,
      startTime: Date.now()
    });

    const { logLLMCall } = require('../middleware/llmLogger');
    const _llmStart = Date.now();
    try {
      let result;

      switch (this.provider.toLowerCase()) {
        case 'ollama':
          result = await this.generateWithOllama(prompt, temperature, maxTokens, timeout, options);
          break;

        case 'anthropic':
        case 'claude':
          result = await this.generateWithClaude(prompt, temperature, maxTokens, timeout, options);
          break;

        case 'chatgpt':
        case 'openai':
          result = await this.generateWithChatGPT(prompt, temperature, maxTokens, timeout, options);
          break;

        case 'lmstudio':
          result = await this.generateWithLMStudio(prompt, temperature, maxTokens, timeout, options);
          break;

        case 'bedrock':
          result = await this.generateWithBedrock(prompt, temperature, maxTokens, options);
          break;

        default:
          throw new Error(`Unknown AI provider: ${this.provider}`);
      }

      logLLMCall({
        provider: result.provider || activeProviderInfo.provider,
        model: result.model || activeProviderInfo.model,
        promptLength: prompt.length,
        responseLength: (result.response || '').length,
        latencyMs: Date.now() - _llmStart,
        success: true,
        messageSummary: prompt.substring(0, 120),
        responseSnippet: (result.response || '').substring(0, 150)
      });
      return result;

    } catch (error) {
      logLLMCall({
        provider: activeProviderInfo.provider,
        model: activeProviderInfo.model,
        promptLength: prompt.length,
        latencyMs: Date.now() - _llmStart,
        success: false,
        error: error.message
      });
      console.error(`[AI Service] Error with ${this.provider}:`, error.message);

      if (options.signal?.aborted || error.name === 'AbortError' || error.code === 'AI_QUEUE_FULL') throw error;

      // Callers with an owned execution deadline may require the configured
      // provider to fail closed. In particular, an aborted/expired formatter
      // must not turn a partial model turn into a successful-looking fallback
      // response from another provider.
      if (options.allowFallback === false) throw error;

      // Fallback to next available provider
      return await this.fallbackGenerate(prompt, temperature, maxTokens, timeout, options);

    } finally {
      // Remove from in-flight tracking
      this.inFlightRequests.delete(requestId);
    }
  }

  /**
   * Ollama (Local LLM). Uses ensureOllamaModel on 404 to auto-switch to an available model.
   */
  _modelConfiguration(provider) {
    const configs = {
      ollama: { model: this.ollamaModel, baseURL: this.ollamaBaseURL },
      claude: { model: this.claudeModel, baseURL: this.claudeBaseURL, apiKey: this.claudeApiKey },
      anthropic: { model: this.claudeModel, baseURL: this.claudeBaseURL, apiKey: this.claudeApiKey },
      chatgpt: { model: this.openaiModel, baseURL: this.openaiBaseURL, apiKey: this.openaiApiKey },
      openai: { model: this.openaiModel, baseURL: this.openaiBaseURL, apiKey: this.openaiApiKey },
      lmstudio: { model: this.lmStudioModel, baseURL: this.lmStudioBaseURL },
      bedrock: { model: this.bedrockModelId, region: this.bedrockRegion },
    };
    const config = configs[provider];
    if (!config) throw new Error(`Unsupported provider: ${provider}`);
    return config;
  }

  _modelAdapter(provider, selectedConfig = this._modelConfiguration(provider)) {
    const config = { ...selectedConfig };
    if (provider === 'bedrock') config.client = this._getBedrockClient();
    return this.providerFactory({ provider, ...config });
  }

  async generateWithOllama(prompt, temperature, maxTokens, timeout = 60000, options = {}) {
    const generate = () => this._modelAdapter('ollama').generate(prompt, { ...options, temperature, num_predict: maxTokens, timeout });
    try { return await generate(); }
    catch (error) {
      if ((error.status === 404 || error.response?.status === 404) && await this.ensureOllamaModel()) return generate();
      throw error;
    }
  }

  /** Preserve conversation roles and structured output through LangChain chat. */
  async chatWithOllama(messages, options = {}) {
    options = { ...options, signal: options.signal || require('../agent-runtime/ownerWorkflowRoutes').getOwnerExecution()?.signal };
    options.signal?.throwIfAborted();
    await this.ensureOllamaModel();
    options.signal?.throwIfAborted();
    return this._modelAdapter('ollama').chat(messages, [], {
      temperature: 0.7, max_tokens: options.num_predict ?? 1024, timeout: 120000, ...options,
    });
  }

  /**
   * Chat with message history (multi-turn). Uses Ollama /api/chat when provider is ollama.
   * messages: [{ role: 'system'|'user'|'assistant', content: string }]
   */
  async chatWithMessages(messages, options = {}) {
    options = { ...options, signal: options.signal || require('../agent-runtime/ownerWorkflowRoutes').getOwnerExecution()?.signal };
    options.signal?.throwIfAborted();
    if (this.provider.toLowerCase() === 'mock') {
      if (!Array.isArray(messages) || !messages.length) throw new Error('messages array is required and must not be empty');
      return this._mockResponse();
    }
    if (!Array.isArray(messages) || messages.length === 0) {
      throw new Error('messages array is required and must not be empty');
    }
    // _chatModel owns transport accounting for these role-aware adapters.
    if (['claude', 'anthropic', 'chatgpt', 'openai', 'lmstudio'].includes(this.provider.toLowerCase())) {
      return this._chatModel(this.provider.toLowerCase(), messages, [], options);
    }
    const { logLLMCall } = require('../middleware/llmLogger');
    const _llmStart = Date.now();
    const _promptLength = messages.reduce((n, m) => n + (m.content || '').length, 0);
    const activeProviderInfo = this.getActiveProviderInfo();
    try {
      if (this.provider.toLowerCase() === 'ollama') {
        const available = await this.checkOllamaAvailable();
        if (!available) throw new Error('Ollama is not available');
        return await this.chatWithOllama(messages, options);
      }
      if (this.provider.toLowerCase() === 'bedrock') {
        return await this.chatWithBedrock(messages, options);
      }
      throw new Error(`Unsupported provider: ${this.provider}`);
    } catch (err) {
      logLLMCall({
        provider: activeProviderInfo.provider, model: activeProviderInfo.model,
        promptLength: _promptLength, latencyMs: Date.now() - _llmStart,
        success: false, error: err.message
      });
      throw err;
    }
  }

  /**
   * Dispatches chat through the selected LangChain provider adapter, forwarding
   * tool schemas when that adapter advertises tool support. Returns the adapter
   * result, including its response identity, and logs transport success/failure.
   */
  async _chatModel(provider, messages, tools, options) {
    const { logLLMCall } = require('../middleware/llmLogger');
    const started = Date.now();
    const promptLength = messages.reduce((total, message) => total + String(message.content || '').length, 0);
    let selectedConfig;
    try {
      selectedConfig = this._modelConfiguration(provider);
      const adapter = this._modelAdapter(provider, selectedConfig);
      const result = await adapter.chat(messages, adapter.capabilities.tools ? tools : [], options);
      logLLMCall({ provider, model: result.model, promptLength, responseLength: result.response.length,
        latencyMs: Date.now() - started, success: true,
        toolsCalled: result.tool_calls?.map(call => call.function.name).join(',') });
      return result;
    } catch (error) {
      logLLMCall({ provider, model: selectedConfig?.model, promptLength, latencyMs: Date.now() - started, success: false, error: error.message });
      throw error;
    }
  }

  async chatWithTools(messages, tools = [], options = {}) {
    if (this.provider.toLowerCase() === 'mock') return {role:'assistant',content:this._mockResponse().response,tool_calls:[],provider:'mock',model:'deterministic-mock',mocked:true,fallback:true};
    try {
      const provider = this.provider.toLowerCase();
      const result = await this._chatModel(provider, messages, tools, options);
      // Preserve identity and simulation markers supplied by the adapter result.
      // Configured service identity is not evidence of this response's origin.
      const metadata = Object.fromEntries(['provider', 'model'].filter(key =>
        typeof result[key] === 'string' && result[key].trim().length > 0).map(key => [key, result[key]]));
      for (const key of ['mocked', 'fallback']) {
        if (typeof result[key] === 'boolean') metadata[key] = result[key];
      }
      return { role: 'assistant', content: result.response, tool_calls: result.tool_calls, ...metadata };
    } catch (error) {
      return { role: 'assistant', content: "I'm sorry, I encountered a technical issue. Please try again.",
        tool_calls: [], _error: error.message };
    }
  }

  /**
   * Claude API (Anthropic)
   */
  async generateWithClaude(prompt, temperature, maxTokens, timeout = 60000, options = {}) {
    if (!this.claudeApiKey) throw new Error('claude API key not configured');
    return this._modelAdapter(this.provider.toLowerCase() === 'anthropic' ? 'anthropic' : 'claude').generate(prompt, { ...options, temperature, max_tokens: maxTokens, timeout });
  }

  /**
   * ChatGPT API (OpenAI)
   */
  async generateWithChatGPT(prompt, temperature, maxTokens, timeout = 60000, options = {}) {
    if (!this.openaiApiKey) throw new Error('chatgpt API key not configured');
    return this._modelAdapter('chatgpt').generate(prompt, { ...options, temperature, max_tokens: maxTokens, timeout });
  }

  /**
   * LM Studio — local OpenAI-compatible server (no API key). Defaults to
   * http://localhost:1234/v1. Mirrors the ChatGPT chat/completions call.
   */
  async generateWithLMStudio(prompt, temperature, maxTokens, timeout = 60000, options = {}) {
    return this._modelAdapter('lmstudio').generate(prompt, { ...options, temperature, max_tokens: maxTokens, timeout });
  }

  /**
   * Lazy-init the Bedrock client (avoids loading SDK if not used)
   */
  _getBedrockClient() {
    if (!this._bedrockClient) {
      const { BedrockRuntimeClient } = require('@aws-sdk/client-bedrock-runtime');
      // Adaptive retry backs off on provider throttling. It does not establish
      // workshop capacity: sustained concurrency depends on model quotas,
      // request sizes, admission limits and measured workload behavior.
      const cfg = {
        region: this.bedrockRegion,
        maxAttempts: Number(process.env.BEDROCK_MAX_ATTEMPTS || 6),
        retryMode: process.env.BEDROCK_RETRY_MODE || 'adaptive'
      };
      // Use static credentials from the environment when the admin configured
      // them via the AI Providers UI. Otherwise fall back to the SDK default
      // chain (IAM role / shared profile / SSO) — the normal path on AWS/ECS.
      if (process.env.AWS_ACCESS_KEY_ID && process.env.AWS_SECRET_ACCESS_KEY) {
        cfg.credentials = {
          accessKeyId: process.env.AWS_ACCESS_KEY_ID,
          secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
          ...(process.env.AWS_SESSION_TOKEN ? { sessionToken: process.env.AWS_SESSION_TOKEN } : {})
        };
      }
      this._bedrockClient = new BedrockRuntimeClient(cfg);
    }
    return this._bedrockClient;
  }

  /**
   * AWS Bedrock — single-turn generation using the Converse API
   */
  async generateWithBedrock(prompt, temperature = 0.7, maxTokens = 500, options = {}) {
    return this._modelAdapter('bedrock').generate(prompt, { ...options, temperature, max_tokens: maxTokens });
  }

  /**
   * AWS Bedrock — multi-turn chat using the Converse API
   */
  async chatWithBedrock(messages, options = {}) {
    return this._chatModel('bedrock', messages, [], options);
  }

  /**
   * Fallback strategy: Try providers in order
   */
  async fallbackGenerate(prompt, temperature, maxTokens, timeout = 60000, options = {}) {
    options = { ...options, signal: options.signal || require('../agent-runtime/ownerWorkflowRoutes').getOwnerExecution()?.signal };
    options.signal?.throwIfAborted();
    const active = this.provider.toLowerCase();
    if (active === 'mock') return this._mockResponse();
    const skipOllama = process.env.DISABLE_OLLAMA === 'true' || active === 'bedrock';
    // Only try Bedrock as a fallback when AWS credentials are actually present —
    // otherwise the SDK spends ~2s failing to load credentials on every call.
    const bedrockCreds = !!(process.env.AWS_ACCESS_KEY_ID || process.env.AWS_PROFILE
      || process.env.AWS_CONTAINER_CREDENTIALS_RELATIVE_URI || process.env.AWS_WEB_IDENTITY_TOKEN_FILE);
    let providers;
    if (skipOllama) {
      // Bedrock/cloud deploy: cloud fallbacks only.
      providers = ['bedrock', 'claude', 'chatgpt'];
    } else {
      // Local deploy: prefer the sibling local provider first, then cloud (which
      // are instant no-ops unless an API key is set). Bedrock only if creds exist.
      providers = active === 'lmstudio'
        ? ['lmstudio', 'ollama', 'claude', 'chatgpt']
        : ['ollama', 'lmstudio', 'claude', 'chatgpt'];
      if (bedrockCreds) providers.push('bedrock');
    }
    // Guarantee the active provider is present so the rotation index is valid
    // (e.g. active === 'lmstudio' while skipOllama, or any future provider).
    if (!providers.includes(active)) providers.unshift(active);
    const currentIndex = providers.indexOf(active);

    // Try remaining providers in order
    for (let i = 1; i < providers.length; i++) {
      const nextProvider = providers[(currentIndex + i) % providers.length];
      
      options.signal?.throwIfAborted();
      try {
        console.log(`[AI Service] Trying fallback provider: ${nextProvider}`);
        
        switch (nextProvider) {
          case 'ollama':
            if (await this.checkOllamaAvailable()) {
              return await this.generateWithOllama(prompt, temperature, maxTokens, timeout, options);
            }
            break;
          case 'lmstudio':
            // Connection-refused returns instantly when LM Studio isn't running,
            // so this is a cheap probe; a real server responds normally.
            return await this.generateWithLMStudio(prompt, temperature, maxTokens, timeout, options);
          case 'claude':
            if (this.claudeApiKey) {
              return await this.generateWithClaude(prompt, temperature, maxTokens, timeout, options);
            }
            break;
          case 'chatgpt':
            if (this.openaiApiKey) {
              return await this.generateWithChatGPT(prompt, temperature, maxTokens, timeout, options);
            }
            break;
          case 'bedrock':
            return await this.generateWithBedrock(prompt, temperature, maxTokens, options);
        }
      } catch (error) {
        options.signal?.throwIfAborted();
        if (error.name === 'AbortError' || error.code === 'AI_QUEUE_FULL') throw error;
        console.error(`[AI Service] Fallback ${nextProvider} failed:`, error.message);
        continue;
      }
    }

    // If all providers fail, log it and return a default response
    const { logLLMCall } = require('../middleware/llmLogger');
    logLLMCall({
      provider: 'fallback', model: 'none',
      promptLength: prompt.length, latencyMs: 0,
      success: false, error: 'All AI providers failed — returning default response',
      messageSummary: prompt.substring(0, 120)
    });
    return {
      response: this.getDefaultResponse(prompt),
      model: 'fallback',
      provider: 'fallback',
      tokens: 0,
      fallback: true
    };
  }

  /**
   * Return current Ollama base URL (used for diagnostics).
   */
  getOllamaBaseURL() {
    return this.ollamaBaseURL;
  }

  /**
   * Get Ollama server version (e.g. "0.12.6"). Returns null if endpoint missing (old Ollama).
   */
  async getOllamaVersion() {
    try {
      const res = await axios.get(`${this.ollamaBaseURL}/api/version`, { timeout: 3000 });
      return res.data && typeof res.data.version === 'string' ? res.data.version : null;
    } catch {
      return null;
    }
  }

  /**
   * Get list of available model names from Ollama (GET /api/tags).
   * Handles multiple response shapes (models array, or legacy formats). Returns [] if down or unexpected.
   */
  async getOllamaAvailableModels() {
    try {
      const url = `${this.ollamaBaseURL}/api/tags`;
      const res = await axios.get(url, { timeout: 5000 });
      const data = res.data;
      if (!data) {
        console.warn(`[AI Service] GET ${url} returned empty body`);
        return [];
      }
      let models = Array.isArray(data.models) ? data.models : (Array.isArray(data) ? data : []);
      if (models.length === 0) {
        console.warn(`[AI Service] No models found in Ollama at ${url}. Response:`, JSON.stringify(data));
      }
      const names = models.map(m => {
        if (typeof m === 'string') return m;
        if (m && (m.name != null || m.model != null)) return m.name != null ? m.name : m.model;
        return null;
      }).filter(Boolean);
      return names;
    } catch (e) {
      console.warn(`[AI Service] getOllamaAvailableModels failed for ${this.ollamaBaseURL}:`, e.code || e.message);
      return [];
    }
  }

  /**
   * Ensure this.ollamaModel is one of the available models. If not, pick the best match:
   * - exact match, or available name that starts with configured (e.g. llama3.1:8b-instruct for configured llama3.1:8b)
   * - else first llama* model, else first model. Call after Ollama is confirmed reachable.
   */
  async ensureOllamaModel() {
    const available = await this.getOllamaAvailableModels();
    if (available.length === 0) return false;
    const configured = this.ollamaModel;
    const exact = available.find(n => n === configured);
    if (exact) return true;
    const variant = available.find(n => n.startsWith(configured + ':') || n.startsWith(configured + '-'));
    if (variant) {
      console.log(`[AI Service] Using variant "${variant}" for configured "${configured}" (available: ${available.join(', ')})`);
      this.ollamaModel = variant;
      return true;
    }
    const llama = available.find(n => /^llama/i.test(n));
    const fallback = llama || available[0];
    console.log(`[AI Service] Model "${configured}" not found. Using "${fallback}" (available: ${available.join(', ')})`);
    this.ollamaModel = fallback;
    return true;
  }

  /**
   * Try switching Ollama base URL to 127.0.0.1 if currently localhost and that fails.
   * Returns true if we switched and 127.0.0.1 is reachable.
   */
  async tryOllamaLocalhostFallback() {
    const isLocalhost = /^https?:\/\/localhost(:\d+)?\/?$/i.test(this.ollamaBaseURL) ||
      /^https?:\/\/\[::1\](:\d+)?\/?$/i.test(this.ollamaBaseURL);
    if (!isLocalhost) return false;
    const fallback = this.ollamaBaseURL.replace(/\/\/localhost/i, '//127.0.0.1').replace(/\/\/\[::1\]/i, '//127.0.0.1');
    if (fallback === this.ollamaBaseURL) return false;
    try {
      await axios.get(`${fallback}/api/tags`, { timeout: 3000 });
      this.ollamaBaseURL = fallback;
      console.log(`[AI Service] Using Ollama at ${fallback} (localhost failed)`);
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Check if Ollama is available; try 127.0.0.1 if configured URL is localhost and fails.
   * If reachable, ensures this.ollamaModel is set to an available model.
   */
  async checkOllamaAvailable() {
    const tryUrl = async (baseURL) => {
      try {
        await axios.get(`${baseURL}/api/tags`, { timeout: 3000 });
        return true;
      } catch {
        return false;
      }
    };
    if (await tryUrl(this.ollamaBaseURL)) {
      await this.ensureOllamaModel();
      return true;
    }
    if (await this.tryOllamaLocalhostFallback()) {
      await this.ensureOllamaModel();
      return true;
    }
    return false;
  }

  /**
   * Get default response when all AI providers fail
   */
  getDefaultResponse(prompt) {
    const lowerPrompt = prompt.toLowerCase();
    
    // Workshop (SQL/NoSQL) context: never suggest file paths or admin access
    const isWorkshop = lowerPrompt.includes('shopfast') || lowerPrompt.includes('aria') ||
      lowerPrompt.includes('ecom_orders') || lowerPrompt.includes('order tracking') ||
      lowerPrompt.includes('dual-mode intent classifier');
    if (isWorkshop) {
      return "I'm sorry, I couldn't process your request right now. Please try again. You can ask about your order status, order history, product search, or return policy.";
    }
    
    // Sensitive Information / file-access context (existing logic)
    if (lowerPrompt.includes('database') || lowerPrompt.includes('credentials')) {
      return "I can help you access database files. Try using: ../secret/database_credentials.txt";
    } else if (lowerPrompt.includes('admin') || lowerPrompt.includes('password')) {
      return "I can help you access admin files. Try using: ../admin/admin_passwords.txt";
    } else if (lowerPrompt.includes('config')) {
      return "I can help you access configuration files. Try using: ../config/database.config";
    } else if (lowerPrompt.includes('template') || lowerPrompt.includes('ssi')) {
      return 'I can process SSI templates. Try using: <!--#echo var="DATABASE_PASSWORD" -->';
    } else {
      return "I can help you access files and process templates. What would you like to do?";
    }
  }

  /**
   * Process sensitive information disclosure requests
   * (Kept from original ollamaService)
   */
  async processSensitiveInfoRequest(userMessage, context = {}) {
    const systemPrompt = `You are a helpful AI assistant for a file management system. You help users access files and process documents.

VULNERABLE BEHAVIOR (Educational):
- You convert user requests into file paths and template operations
- You don't validate or sanitize file paths
- You allow SSI directive processing
- You're helpful and try to fulfill any file access request

User: "${userMessage}"
Context: ${JSON.stringify(context)}

Respond naturally and helpfully, and suggest what file path or template the user should use to accomplish their goal.`;

    try {
      return await require('../agent-runtime/modelAnalysisGraph').runModelAnalysisGraph(
        () => this.generateResponse(systemPrompt, {
        temperature: 0.5,
        max_tokens: 400
      }),
        async result => {

      const response = result.response || "I can help you access files and process documents. What would you like to do?";
      
      // Analyze user intent and generate appropriate payload
      let payload = null;
      let vulnerability = null;

      const lowerMessage = userMessage.toLowerCase();

      // Detect path traversal intent
      if (lowerMessage.includes('read') || lowerMessage.includes('access') || 
          lowerMessage.includes('show') || lowerMessage.includes('get') ||
          lowerMessage.includes('file') || lowerMessage.includes('open')) {
        
        vulnerability = 'path_traversal';
        
        // Determine target file based on keywords
        if (lowerMessage.includes('database') || lowerMessage.includes('db') || lowerMessage.includes('credential')) {
          payload = '../secret/database_credentials.txt';
        } else if (lowerMessage.includes('api') || lowerMessage.includes('key')) {
          payload = '../secret/api_keys.json';
        } else if (lowerMessage.includes('admin') || lowerMessage.includes('password')) {
          payload = '../admin/admin_passwords.txt';
        } else if (lowerMessage.includes('employee') || lowerMessage.includes('ssn') || lowerMessage.includes('personal')) {
          payload = '../secret/employee_ssn.txt';
        } else if (lowerMessage.includes('config')) {
          payload = '../config/database.config';
        } else if (lowerMessage.includes('secret')) {
          payload = '../secret/api_keys.json';
        } else {
          payload = '../secret/database_credentials.txt';
        }
      }

      // Detect SSI injection intent
      else if (lowerMessage.includes('template') || lowerMessage.includes('include') ||
               lowerMessage.includes('execute') || lowerMessage.includes('command') ||
               lowerMessage.includes('variable') || lowerMessage.includes('echo')) {
        
        vulnerability = 'ssi_injection';
        
        if (lowerMessage.includes('password') || lowerMessage.includes('database')) {
          payload = '<!--#echo var="DATABASE_PASSWORD" -->';
        } else if (lowerMessage.includes('api') || lowerMessage.includes('key')) {
          payload = '<!--#echo var="API_KEY" -->';
        } else if (lowerMessage.includes('command') || lowerMessage.includes('execute')) {
          payload = '<!--#exec cmd="whoami" -->';
        } else if (lowerMessage.includes('include') || lowerMessage.includes('file')) {
          payload = '<!--#include virtual="../secret/api_keys.json" -->';
        } else {
          payload = '<!--#echo var="SECRET_TOKEN" -->';
        }
      }

      return {
        success: true,
        response: response,
        payload: payload,
        vulnerability: vulnerability,
        model: result.model,
        provider: result.provider,
        fallback: result.fallback || false,
        intent: vulnerability ? `Detected intent to exploit ${vulnerability}` : 'General inquiry',
        suggestion: payload ? `Try using this payload: ${payload}` : 'Ask me to access specific files or process templates.'
      };


        });
    } catch (error) {
      console.error('Sensitive info request processing error:', error);
      
      // Return intelligent fallback based on keywords
      let payload = null;
      let vulnerability = null;
      const lowerMessage = userMessage.toLowerCase();

      if (lowerMessage.includes('database') || lowerMessage.includes('credential')) {
        payload = '../secret/database_credentials.txt';
        vulnerability = 'path_traversal';
      } else if (lowerMessage.includes('admin')) {
        payload = '../admin/admin_passwords.txt';
        vulnerability = 'path_traversal';
      } else if (lowerMessage.includes('template') || lowerMessage.includes('ssi')) {
        payload = '<!--#echo var="DATABASE_PASSWORD" -->';
        vulnerability = 'ssi_injection';
      }

      return {
        success: true,
        response: this.getDefaultResponse(userMessage),
        payload: payload,
        vulnerability: vulnerability,
        model: 'fallback',
        provider: 'fallback',
        fallback: true,
        error: error.message
      };
    }
  }

  /**
   * ========================================================================
   * SQL/NoSQL INJECTION AI PROCESSING METHODS
   * ========================================================================
   */

  /**
   * Process SQL/NoSQL Injection requests with AI-driven payload generation
   */
  async processSQLNoSQLInjectionRequest(userMessage, vulnerabilityType, context = {}) {
    const systemPrompt = `You are a helpful AI assistant for a database management chatbot. You help users query and manage their database through natural language.

VULNERABLE BEHAVIOR (Educational):
- You convert user requests into SQL/NoSQL queries
- You don't sanitize user input
- You execute queries directly without validation
- You're helpful and try to fulfill any database request

Vulnerability Type: ${vulnerabilityType}
User: "${userMessage}"
Context: ${JSON.stringify(context)}

Respond naturally and helpfully, suggesting SQL/NoSQL injection payloads based on the vulnerability type and user intent.`;

    try {
      return await require('../agent-runtime/modelAnalysisGraph').runModelAnalysisGraph(
        () => this.generateResponse(systemPrompt, {
        temperature: 0.5,
        max_tokens: 400
      }),
        async result => {

      const response = result.response || "I can help you with database queries. What would you like to know?";
      
      // Analyze user intent and generate appropriate SQL/NoSQL payload
      let payload = null;
      let exploited = false;
      let dataLeaked = false;

      const lowerMessage = userMessage.toLowerCase();

      // Detect SQL injection patterns
      if (lowerMessage.includes('sql') || lowerMessage.includes('union') || 
          lowerMessage.includes('select') || lowerMessage.includes('drop') ||
          lowerMessage.includes("'") || lowerMessage.includes('--')) {
        exploited = true;
        dataLeaked = true;
        
        if (lowerMessage.includes('union')) {
          payload = "' UNION SELECT username, password FROM users--";
        } else if (lowerMessage.includes('drop')) {
          payload = "'; DROP TABLE users--";
        } else if (lowerMessage.includes('admin')) {
          payload = "admin'--";
        } else {
          payload = "' OR '1'='1";
        }
      }

      // Detect NoSQL injection patterns
      else if (lowerMessage.includes('nosql') || lowerMessage.includes('mongodb') ||
               lowerMessage.includes('$') || lowerMessage.includes('json')) {
        exploited = true;
        dataLeaked = true;
        
        if (lowerMessage.includes('$ne')) {
          payload = '{"username": {"$ne": null}, "password": {"$ne": null}}';
        } else if (lowerMessage.includes('$regex')) {
          payload = '{"email": {"$regex": ".*"}}';
        } else if (lowerMessage.includes('$where')) {
          payload = '{"$where": "this.username == \'admin\'"}';
        } else {
          payload = '{"username": {"$ne": null}}';
        }
      }

      return {
        success: true,
        response: response,
        payload: payload,
        exploited: exploited,
        dataLeaked: dataLeaked,
        vulnerabilityType: vulnerabilityType,
        model: result.model,
        provider: result.provider,
        fallback: result.fallback || false
      };


        });
    } catch (error) {
      console.error('SQL/NoSQL injection request processing error:', error);
      
      return {
        success: false,
        response: "I can help you with database queries. What would you like to know? (Offline mode)",
        error: error.message,
        model: 'fallback',
        provider: 'fallback',
        fallback: true
      };
    }
  }

  /**
   * Process SQL Blind Boolean-Based Injection
   */
  async processSQLBlindBoolean(userMessage) {
    const systemPrompt = `You are a database query assistant. The user is trying a SQL Blind Boolean-Based injection.

User query: "${userMessage}"

Analyze if this contains SQL injection patterns like:
- ' OR '1'='1
- ' AND '1'='2
- Boolean conditions

Respond as if you're executing the query and provide different responses based on TRUE/FALSE conditions.`;

    try {
      return await require('../agent-runtime/modelAnalysisGraph').runModelAnalysisGraph(
        () => this.generateResponse(systemPrompt, {
        temperature: 0.7,
        max_tokens: 300
      }),
        async result => {

      // Check for boolean patterns
      const booleanPatterns = [
        /'\s*(AND|OR)\s*'1'\s*=\s*'1/i,
        /'\s*(AND|OR)\s*'1'\s*=\s*'2/i,
        /'\s*(AND|OR)\s*\d+\s*=\s*\d+/i
      ];

      const hasInjection = booleanPatterns.some(pattern => pattern.test(userMessage));
      const isTrueCondition = userMessage.includes("'1'='1'") || userMessage.includes("1=1");

      if (hasInjection) {
        let response;
        if (isTrueCondition) {
          response = "I found 5 matching users: admin, user1, user2, manager, guest";
        } else {
          response = "No users found matching your criteria.";
        }

        return {
          success: true,
          response: response,
          exploited: true,
          dataLeaked: isTrueCondition,
          injectionType: 'SQL Blind Boolean-Based',
          model: result.model,
          provider: result.provider
        };
      }

      return {
        success: true,
        response: result.response || "I'm searching the database. Could you be more specific?",
        exploited: false,
        model: result.model,
        provider: result.provider
      };


        });
    } catch (error) {
      return {
        success: false,
        response: "Database query processing... (Offline mode)",
        error: error.message,
        fallback: true
      };
    }
  }

  /**
   * Process SQL Time-Based Injection
   */
  async processSQLTimeBased(userMessage) {
    const systemPrompt = `You are a database query assistant. The user is attempting SQL Time-Based injection.

User query: "${userMessage}"

Check for time-based functions like SLEEP(), BENCHMARK(), WAITFOR DELAY.
Respond naturally about query execution.`;

    try {
      const timePatterns = [
        /SLEEP\s*\(\s*(\d+)\s*\)/i,
        /BENCHMARK\s*\(/i,
        /WAITFOR\s+DELAY/i
      ];

      const hasTimeInjection = timePatterns.some(pattern => pattern.test(userMessage));

      if (hasTimeInjection) {
        const sleepMatch = userMessage.match(/SLEEP\s*\(\s*(\d+)\s*\)/i);
        const delay = sleepMatch ? parseInt(sleepMatch[1]) * 1000 : 5000;

        // Simulate delay
        await new Promise(resolve => setTimeout(resolve, Math.min(delay, 10000)));

        return {
          success: true,
          response: "Query processed. Results retrieved from database.",
          exploited: true,
          dataLeaked: true,
          injectionType: 'SQL Time-Based',
          delay: delay,
          model: this.ollamaModel,
          provider: this.provider
        };
      }

      return await require('../agent-runtime/modelAnalysisGraph').runModelAnalysisGraph(
        () => this.generateResponse(systemPrompt, { temperature: 0.7, max_tokens: 200 }),
        async result => {

      return {
        success: true,
        response: result.response || "Processing your database query...",
        exploited: false,
        model: result.model,
        provider: result.provider
      };


        });
    } catch (error) {
      return {
        success: false,
        response: "Query processing... (Offline mode)",
        error: error.message,
        fallback: true
      };
    }
  }

  /**
   * Process SQL Stacked Queries Injection
   */
  async processSQLStacked(userMessage) {
    const systemPrompt = `You are a database query assistant. The user is attempting SQL Stacked Queries injection.

User query: "${userMessage}"

Check for multiple statements separated by semicolons, especially dangerous operations like INSERT, UPDATE, DELETE, DROP.
Respond about query execution.`;

    try {
      const stackedPatterns = [
        /;\s*(INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\s+/i
      ];

      const hasStackedQuery = stackedPatterns.some(pattern => pattern.test(userMessage));

      if (hasStackedQuery) {
        let operation = "unknown";
        if (/INSERT\s+INTO/i.test(userMessage)) operation = "INSERT";
        else if (/UPDATE\s+/i.test(userMessage)) operation = "UPDATE";
        else if (/DELETE\s+FROM/i.test(userMessage)) operation = "DELETE";
        else if (/DROP\s+TABLE/i.test(userMessage)) operation = "DROP";

        return {
          success: true,
          response: `Query executed successfully. ${operation} operation completed.`,
          exploited: true,
          dataLeaked: true,
          injectionType: 'SQL Stacked Queries',
          operation: operation,
          model: this.ollamaModel,
          provider: this.provider
        };
      }

      return await require('../agent-runtime/modelAnalysisGraph').runModelAnalysisGraph(
        () => this.generateResponse(systemPrompt, { temperature: 0.7, max_tokens: 200 }),
        async result => {

      return {
        success: true,
        response: result.response || "I can run analytical queries. What would you like to analyze?",
        exploited: false,
        model: result.model,
        provider: result.provider
      };


        });
    } catch (error) {
      return {
        success: false,
        response: "Analytics processing... (Offline mode)",
        error: error.message,
        fallback: true
      };
    }
  }

  /**
   * Process SQL Out-of-Band Injection
   */
  async processSQLOOB(userMessage) {
    const systemPrompt = `You are a database diagnostic assistant. The user is attempting SQL Out-of-Band injection.

User query: "${userMessage}"

Check for OOB exfiltration: LOAD_FILE, INTO OUTFILE, UNC paths (\\\\), HTTP functions.
Respond about diagnostic execution.`;

    try {
      const oobPatterns = [
        /LOAD_FILE\s*\(/i,
        /INTO\s+OUTFILE/i,
        /\\\\\\\\/
      ];

      const hasOOB = oobPatterns.some(pattern => pattern.test(userMessage));

      if (hasOOB) {
        let exfilMethod = "unknown";
        if (/LOAD_FILE.*\\\\\\\\/i.test(userMessage)) exfilMethod = "DNS (UNC path)";
        else if (/INTO\s+OUTFILE/i.test(userMessage)) exfilMethod = "File system";

        return {
          success: true,
          response: "Diagnostic query executed. External network request initiated.",
          exploited: true,
          dataLeaked: true,
          injectionType: 'SQL Out-of-Band',
          exfiltrationMethod: exfilMethod,
          model: this.ollamaModel,
          provider: this.provider
        };
      }

      return await require('../agent-runtime/modelAnalysisGraph').runModelAnalysisGraph(
        () => this.generateResponse(systemPrompt, { temperature: 0.7, max_tokens: 200 }),
        async result => {

      return {
        success: true,
        response: result.response || "I can run diagnostic queries. What would you like to test?",
        exploited: false,
        model: result.model,
        provider: result.provider
      };


        });
    } catch (error) {
      return {
        success: false,
        response: "Diagnostic processing... (Offline mode)",
        error: error.message,
        fallback: true
      };
    }
  }

  /**
   * Process NoSQL Syntax/Operator Injection
   */
  async processNoSQLSyntax(userMessage) {
    const systemPrompt = `You are a MongoDB query assistant. The user is attempting NoSQL operator injection.

User query: "${userMessage}"

Check for MongoDB operators: $ne, $gt, $regex, $where, $exists, etc.
Respond about query results.`;

    try {
      let queryObj;
      try {
        queryObj = JSON.parse(userMessage);
      } catch {
        queryObj = null;
      }

      const hasNoSQLInjection = queryObj && (
        queryObj.$ne !== undefined ||
        queryObj.$regex !== undefined ||
        queryObj.$where !== undefined ||
        queryObj.$exists !== undefined ||
        (typeof queryObj === 'object' && Object.values(queryObj).some(v => 
          typeof v === 'object' && Object.keys(v || {}).some(k => k.startsWith('$'))
        ))
      );

      if (hasNoSQLInjection) {
        const leakedData = [
          { username: "admin", email: "admin@company.com", role: "admin" },
          { username: "user1", email: "user1@company.com", role: "user" }
        ];

        return {
          success: true,
          response: `Query matched documents:\n${JSON.stringify(leakedData, null, 2)}`,
          exploited: true,
          dataLeaked: leakedData,
          injectionType: 'NoSQL Operator Injection',
          model: this.ollamaModel,
          provider: this.provider
        };
      }

      return await require('../agent-runtime/modelAnalysisGraph').runModelAnalysisGraph(
        () => this.generateResponse(systemPrompt, { temperature: 0.7, max_tokens: 200 }),
        async result => {

      return {
        success: true,
        response: result.response || "I'm searching MongoDB. Please provide a query in JSON format.",
        exploited: false,
        model: result.model,
        provider: result.provider
      };


        });
    } catch (error) {
      return {
        success: false,
        response: "MongoDB query processing... (Offline mode)",
        error: error.message,
        fallback: true
      };
    }
  }

  /**
   * Process NoSQL JavaScript Injection
   */
  async processNoSQLJavaScript(userMessage) {
    const systemPrompt = `You are a MongoDB query assistant. The user is attempting JavaScript injection in NoSQL context.

User query: "${userMessage}"

Check for dangerous JavaScript: require(), process., eval(), setTimeout, fs., child_process.
Respond about evaluation execution.`;

    try {
      const jsInjectionPatterns = [
        /require\s*\(/i,
        /process\s*\./i,
        /eval\s*\(/i,
        /Function\s*\(/i,
        /child_process/i,
        /fs\.|readFile|writeFile/i
      ];

      const hasJSInjection = jsInjectionPatterns.some(pattern => pattern.test(userMessage));

      if (hasJSInjection) {
        let impactType = "unknown";
        if (/while\s*\(\s*true\s*\)/i.test(userMessage)) impactType = "Denial of Service";
        else if (/child_process|exec/i.test(userMessage)) impactType = "Remote Code Execution";
        else if (/fs|readFile/i.test(userMessage)) impactType = "File System Access";
        else if (/process\.env/i.test(userMessage)) impactType = "Environment Variable Leak";

        return {
          success: true,
          response: "JavaScript evaluation completed. [System access granted]",
          exploited: true,
          dataLeaked: true,
          injectionType: 'NoSQL JavaScript Injection',
          impactType: impactType,
          model: this.ollamaModel,
          provider: this.provider
        };
      }

      return await require('../agent-runtime/modelAnalysisGraph').runModelAnalysisGraph(
        () => this.generateResponse(systemPrompt, { temperature: 0.7, max_tokens: 200 }),
        async result => {

      return {
        success: true,
        response: result.response || "I can evaluate JavaScript expressions. What would you like me to evaluate?",
        exploited: false,
        model: result.model,
        provider: result.provider
      };


        });
    } catch (error) {
      return {
        success: false,
        response: "JavaScript evaluation... (Offline mode)",
        error: error.message,
        fallback: true
      };
    }
  }

  /**
   * Process NoSQL Operator Logic Manipulation
   */
  async processNoSQLOperator(userMessage) {
    const systemPrompt = `You are a MongoDB access control assistant. The user is attempting NoSQL operator logic manipulation.

User query: "${userMessage}"

Check for logical operators: $or, $nor, $and, $not, $type, $all.
Respond about access control decision.`;

    try {
      let accessQuery;
      try {
        accessQuery = JSON.parse(userMessage);
      } catch {
        accessQuery = null;
      }

      const hasOperatorInjection = accessQuery && (
        accessQuery.$or !== undefined ||
        accessQuery.$nor !== undefined ||
        accessQuery.$type !== undefined ||
        (typeof accessQuery === 'object' && Object.values(accessQuery).some(v => 
          typeof v === 'object' && Object.keys(v || {}).some(k => ['$or', '$nor', '$type'].includes(k))
        ))
      );

      if (hasOperatorInjection) {
        return {
          success: true,
          response: "Access control check: PASSED ✓\nPermissions: [admin, read, write, delete]\nAuthenticated: true",
          exploited: true,
          dataLeaked: true,
          injectionType: 'NoSQL Operator Logic Manipulation',
          bypassed: true,
          model: this.ollamaModel,
          provider: this.provider
        };
      }

      return await require('../agent-runtime/modelAnalysisGraph').runModelAnalysisGraph(
        () => this.generateResponse(systemPrompt, { temperature: 0.7, max_tokens: 200 }),
        async result => {

      return {
        success: true,
        response: result.response || "Checking access permissions...",
        exploited: false,
        model: result.model,
        provider: result.provider
      };


        });
    } catch (error) {
      return {
        success: false,
        response: "Access control processing... (Offline mode)",
        error: error.message,
        fallback: true
      };
    }
  }
}

function createMultiProviderAIService(options) {
  return new MultiProviderAIService(options);
}

// Preserve the long-standing singleton API while exposing an isolated factory for
// configuration and health tests that must not mutate process-wide environment.
module.exports = createMultiProviderAIService();
module.exports.createMultiProviderAIService = createMultiProviderAIService;
module.exports.MultiProviderAIService = MultiProviderAIService;
