import React, { useEffect, useRef, useState } from 'react';
import axios from 'axios';
import ObjectiveHelpModal from './workshop/ObjectiveHelpModal';
import { ObjectiveHelpActions } from './workshop/WorkshopExperience';


/**
 * Backwards-compatible hint trigger. Content is fetched fresh for every open;
 * the shared modal owns presentation, progressive reveal, and focus behavior.
 */
function HintPanel({
  workshopKey,
  objectiveId,
  objective,
  revision,
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

  const openHint = async () => {
    const requestId = requestRef.current + 1;
    requestRef.current = requestId;
    setOpen(true);
    setContent(null);
    setError('');
    setStatus('loading');
    try {
      const response = await axios.get(`/api/hints/${workshopKey}/${objectiveId}`);
      if (requestRef.current !== requestId) return;
      const hint = response.data?.hint;
      setContent({
        title: hint?.title || 'Hint',
        hints: Array.isArray(hint?.hints) ? hint.hints : [],
      });
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
      setError('Could not load this hint. Try again.');
      setStatus('error');
    }
  };

  useEffect(() => {
    requestRef.current += 1;
    setOpen(false);
    setContent(null);
    setError('');
  }, [workshopKey, objectiveId, revision]);

  useEffect(() => () => {
    requestRef.current += 1;
  }, []);

  return (
    <>
      <ObjectiveHelpActions
        objectiveId={objectiveId}
        hintVisible
        onOpen={openHint}
        activeKind={open ? 'hint' : undefined}
      />
      {open && (
        <ObjectiveHelpModal
          kind="hint"
          appearance="legacy-light"
          objective={objective || { name: objectiveId }}
          content={content}
          status={status}
          error={error}
          onClose={close}
        />
      )}
    </>
  );
}

export default HintPanel;
