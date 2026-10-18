'use strict';
const configurations=new WeakMap();
function resolveJudgeProviderConfig(env=process.env){
 const selected=env.JUDGE_PROVIDER||'ollama',provider=({claude:'anthropic',chatgpt:'openai'})[selected]||selected;
 const settings={ollama:{model:env.JUDGE_MODEL||env.OLLAMA_MODEL||'llama3.1:8b',baseURL:env.OLLAMA_BASE_URL||'http://localhost:11434'},openai:{model:env.JUDGE_MODEL||env.OPENAI_MODEL,apiKey:env.OPENAI_API_KEY},anthropic:{model:env.JUDGE_MODEL||env.ANTHROPIC_MODEL||env.CLAUDE_MODEL,apiKey:env.ANTHROPIC_API_KEY||env.CLAUDE_API_KEY},bedrock:{model:env.JUDGE_MODEL||env.BEDROCK_MODEL_ID,region:env.AWS_REGION||env.BEDROCK_REGION}};
 if(!settings[provider]?.model)throw Error('Judge provider/model is not configured');
 return {provider,...settings[provider]};
}
function registerConfiguredJudge(judge,resolve){configurations.set(judge,resolve);return judge;}
function readJudgeProviderConfig(judge){const resolve=configurations.get(judge);return resolve?resolve():null;}
module.exports={resolveJudgeProviderConfig,registerConfiguredJudge,readJudgeProviderConfig};
