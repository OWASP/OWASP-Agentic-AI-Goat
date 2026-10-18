import React, { useEffect, useRef, useState } from 'react';
import axios from 'axios';
import ObjectiveHelpModal from './workshop/ObjectiveHelpModal';
import { ObjectiveHelpActions } from './workshop/WorkshopExperience';

function valueFromExample(example) {
  if (typeof example === 'string') return example;
  return example?.prompt || example?.input || example?.code || example?.payload || '';
}

function authoredText(value) {
  return typeof value === 'string' ? value.trim() : '';
}

function normalizeSolution(solution) {
  const examples = (Array.isArray(solution?.examples) ? solution.examples : [])
    .map((example, index) => ({
      title: authoredText(example?.title) || `Example ${index + 1}`,
      payload: authoredText(valueFromExample(example)),
      explanation: authoredText(example?.explanation),
    }))
    .filter((example) => example.payload || example.explanation);
  const directExamples = [
    { title: 'Example payload', payload: authoredText(solution?.payload), explanation: '' },
    {
      title: authoredText(solution?.example?.title) || 'Example payload',
      payload: authoredText(valueFromExample(solution?.example)),
      explanation: authoredText(solution?.example?.explanation),
    },
  ];
  for (const direct of directExamples) {
    if (!direct.payload && !direct.explanation) continue;
    const existing = examples.find((example) => example.payload === direct.payload);
    if (existing) {
      if (direct.explanation && !existing.explanation.includes(direct.explanation)) {
        existing.explanation = [existing.explanation, direct.explanation].filter(Boolean).join('\n\n');
      }
    } else {
      examples.unshift(direct);
    }
  }
  return {
    title: solution?.title || 'Solution',
    examples,
    explanation: authoredText(solution?.explanation || solution?.hint),
    approach: authoredText(solution?.approach),
    tips: Array.isArray(solution?.tips) ? solution.tips.map(authoredText).filter(Boolean) : [],
  };
}

/**
 * Backwards-compatible solution trigger. Content is fetched on each opening;
 * the shared modal renders every authored example and guidance field.
 */
function SolutionPanel({
  solutionEndpoint,
  objectiveId,
  objective,
  onUsePayload,
  revision,
  solutionVisible = true,
}) {
  const [open, setOpen] = useState(false);
  const [content, setContent] = useState(null);
  const [status, setStatus] = useState('loading');
  const [error, setError] = useState('');
  const requestRef = useRef(0);

  const close = () => {
    requestRef.current += 1;
    setOpen(false);
    setContent(null);
    setError('');
  };

  const openSolution = async () => {
    if (!solutionVisible || !solutionEndpoint) return;
    const requestId = requestRef.current + 1;
    requestRef.current = requestId;
    setOpen(true);
    setContent(null);
    setError('');
    setStatus('loading');
    try {
      const response = await axios.get(solutionEndpoint);
      if (requestRef.current !== requestId) return;
      setContent(normalizeSolution(response.data?.solution));
      setStatus('ready');
    } catch (requestError) {
      if (requestRef.current !== requestId) return;
      setContent(null);
      if (requestError.response?.status === 403) {
        setStatus('revoked');
        setOpen(false);
        return;
      }
      if (requestError.response?.status === 404) {
        setStatus('empty');
        return;
      }
      setError('Could not load this solution. Try again.');
      setStatus('error');
    }
  };

  useEffect(() => {
    requestRef.current += 1;
    setOpen(false);
    setContent(null);
    setError('');
  }, [solutionEndpoint, objectiveId, revision, solutionVisible]);

  useEffect(() => () => {
    requestRef.current += 1;
  }, []);

  return (
    <>
      <ObjectiveHelpActions
        objectiveId={objectiveId || objective?.id || solutionEndpoint || 'solution'}
        solutionVisible={solutionVisible}
        onOpen={openSolution}
        activeKind={open ? 'solution' : undefined}
        disabled={!solutionEndpoint}
      />
      {open && solutionVisible && (
        <ObjectiveHelpModal
          kind="solution"
          appearance="legacy-light"
          objective={objective || { name: 'Objective' }}
          content={content}
          status={status}
          error={error}
          onUsePayload={onUsePayload}
          onClose={close}
        />
      )}
    </>
  );
}

export default SolutionPanel;
