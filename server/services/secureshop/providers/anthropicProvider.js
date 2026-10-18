'use strict';
const { LangChainAdapter } = require('./langchainAdapter');
class AnthropicProvider extends LangChainAdapter {
  constructor({ apiKey = process.env.ANTHROPIC_API_KEY, baseUrl = 'https://api.anthropic.com', model = process.env.ANTHROPIC_MODEL || 'claude-sonnet-4-6' } = {}, dependencies) {
    super({ provider: 'anthropic', apiKey, baseURL: baseUrl, model }, dependencies);
    Object.assign(this, { apiKey, baseUrl, model });
  }
  async isReachable() { return !!this.apiKey; }
}
module.exports = { AnthropicProvider };
