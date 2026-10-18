'use strict';
const { LangChainAdapter } = require('./langchainAdapter');
class OpenAIProvider extends LangChainAdapter {
  constructor({ apiKey = process.env.OPENAI_API_KEY, baseUrl = 'https://api.openai.com', model = process.env.OPENAI_MODEL || 'gpt-4o' } = {}, dependencies) {
    super({ provider: 'openai', apiKey, baseURL: `${baseUrl.replace(/\/$/, '').replace(/\/v1$/, '')}/v1`, model }, dependencies);
    Object.assign(this, { apiKey, baseUrl, model });
  }
  async isReachable() { return !!this.apiKey; }
}
module.exports = { OpenAIProvider };
