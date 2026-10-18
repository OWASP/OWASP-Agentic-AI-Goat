'use strict';
const { LangChainAdapter } = require('./langchainAdapter');
class BedrockProvider extends LangChainAdapter {
  constructor({ region = process.env.AWS_REGION || 'us-west-2', modelId = process.env.BEDROCK_MODEL_ID, client } = {}, dependencies) {
    super({ provider: 'bedrock', region, model: modelId, client }, dependencies);
    this.region = region;
    this.modelId = modelId;
  }
  // SDK credential resolution includes instance/task roles. Chat reports failures.
  async isReachable() { return !!this.modelId; }
}
module.exports = { BedrockProvider };
