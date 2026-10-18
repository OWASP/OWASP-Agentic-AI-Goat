const WELCOME_MESSAGE = "Hello! I'm the AWS Assistant. I can help you with questions about EC2, S3, Lambda, and more. What would you like to know?";

export function createObjectiveTranscript(objective) {
  const objectiveId = objective?.id || 'objective';
  const objectiveName = objective?.name || objective?.title || objectiveId;
  const timestamp = new Date();
  const transcript = [
    {
      id: `${objectiveId}-system`,
      type: 'system',
      content: `Exercise: ${objectiveName}`,
      timestamp,
    },
    {
      id: `${objectiveId}-welcome`,
      type: 'ai',
      content: WELCOME_MESSAGE,
      timestamp,
    },
  ];
  return transcript;
}

export function buildConversationHistory(transcript = []) {
  return transcript
    .filter((message) => message?.type === 'user' || message?.type === 'ai')
    .map(({ type, content }) => ({ type, content }));
}

export function appendToTranscript(transcripts, objectiveId, message) {
  return {
    ...transcripts,
    [objectiveId]: [...(transcripts[objectiveId] || []), message],
  };
}

export function getVisibleObjectives(objectives = [], config = {}) {
  if (config?.isVisible === false) return [];
  return objectives.filter((objective) => config?.objectives?.[objective.id]?.isVisible === true);
}

function examplePayload(example) {
  if (typeof example === 'string') return example.trim();
  const value = example?.prompt || example?.input || example?.code || example?.payload || '';
  return typeof value === 'string' ? value.trim() : '';
}

export function normalizeSolution(solution = {}) {
  const examples = Array.isArray(solution.examples) ? solution.examples : [];
  const normalizedExamples = examples
    .map((example, index) => {
      const payload = examplePayload(example);
      if (!payload) return null;
      const title = typeof example === 'object' && typeof example?.title === 'string'
        ? example.title.trim()
        : '';
      const explanation = typeof example === 'object' && typeof example?.explanation === 'string'
        ? example.explanation.trim()
        : '';
      return {
        title: title || `Example ${index + 1}`,
        payload,
        explanation,
      };
    })
    .filter(Boolean);
  const approach = typeof solution.approach === 'string' ? solution.approach.trim() : '';
  const tips = [...new Set((Array.isArray(solution.tips) ? solution.tips : [])
    .filter((tip) => typeof tip === 'string')
    .map((tip) => tip.trim())
    .filter((tip) => tip && !approach.includes(tip)))];
  const explanation = [approach, ...tips].filter(Boolean).join('\n\n');

  return {
    title: solution.title || 'Solution',
    explanation,
    examples: normalizedExamples,
  };
}
