import React, { useCallback, useEffect, useRef, useState } from 'react';
import { Navigate } from 'react-router-dom';
import axios from 'axios';
import VulnerabilityTemplate, { ConfirmedVisibilityContext } from './VulnerabilityTemplate';

const isValidVisibilityPayload = (data) => (
  data !== null
  && typeof data === 'object'
  && !Array.isArray(data)
  && data.success === true
  && Array.isArray(data.challenges)
  && data.challenges.every((challenge) => (
    challenge !== null
    && typeof challenge === 'object'
    && !Array.isArray(challenge)
    && typeof challenge.id === 'string'
    && challenge.id.trim().length > 0
  ))
);

const VisibilityProtectedRoute = ({ challengeId, alternateChallengeId, children, fallbackRoute = '/workshop/challenges', visibilityEndpoint = '/api/workshop/challenges', presentation = 'workshop' }) => {
  const eligibilityKey = `${challengeId}\0${alternateChallengeId || ''}\0${visibilityEndpoint}`;
  const requestGeneration = useRef(0);
  const activeRequestController = useRef(null);
  const [visibility, setVisibility] = useState({ status: 'loading', eligibilityKey });

  const checkVisibility = useCallback(async () => {
    const generation = ++requestGeneration.current;
    activeRequestController.current?.abort();
    const controller = typeof AbortController === 'undefined' ? null : new AbortController();
    activeRequestController.current = controller;
    setVisibility({ status: 'loading', eligibilityKey });
    try {
      // Get visible challenges from admin-controlled API
      const response = await axios.get(
        visibilityEndpoint,
        controller ? { signal: controller.signal } : undefined,
      );
      if (!isValidVisibilityPayload(response.data)) {
        throw new Error('Malformed challenge visibility response');
      }

      // A shared page can serve two independently visible catalog exercises.
      const challenge = response.data.challenges.find((entry) => entry.id === challengeId)
        || (alternateChallengeId && response.data.challenges.find((entry) => entry.id === alternateChallengeId));
      const status = challenge ? 'visible' : 'hidden';
      if (generation === requestGeneration.current) {
        setVisibility({ status, eligibilityKey, challenge: challenge || null });
      }
    } catch (error) {
      if (generation === requestGeneration.current) {
        console.error(`Failed to check visibility for ${challengeId}:`, error);
        setVisibility({ status: 'error', eligibilityKey });
      }
    }
  }, [challengeId, alternateChallengeId, eligibilityKey, visibilityEndpoint]);

  useEffect(() => {
    checkVisibility();
    return () => {
      requestGeneration.current += 1;
      activeRequestController.current?.abort();
    };
  }, [checkVisibility]);

  // Never reuse a decision made for a previous challenge while this effect starts.
  const status = visibility.eligibilityKey === eligibilityKey ? visibility.status : 'loading';

  // Still loading
  if (status === 'loading' && presentation === 'application') {
    return <div role="status" style={{ padding: '4rem', textAlign: 'center' }}>Opening SecureShop…</div>;
  }
  if (status === 'loading') {
    return (
      <VulnerabilityTemplate 
        challengeId={challengeId}
        loading={true}
        visibilityManagedExternally={true}
      />
    );
  }

  if (status === 'error') {
    return (
      <div
        role="alert"
        style={{
          maxWidth: '520px',
          margin: '15vh auto',
          padding: '2rem',
          textAlign: 'center',
          background: 'white',
          border: '1px solid #ddd',
          borderRadius: '12px',
        }}
      >
        <h2>{presentation === 'application' ? 'SecureShop is unavailable' : 'Unable to verify exercise availability'}</h2>
        <p>Please check your connection and try again.</p>
        <button type="button" onClick={checkVisibility}>Retry</button>
      </div>
    );
  }

  // Not visible - redirect to dashboard
  if (status === 'hidden') {
    return <Navigate to={fallbackRoute} replace />;
  }

  // Visible - render children
  return (
    <ConfirmedVisibilityContext.Provider value={{
      challengeId: visibility.challenge.id,
      challenge: visibility.challenge,
    }}>
      {children}
    </ConfirmedVisibilityContext.Provider>
  );
};

export default VisibilityProtectedRoute;
