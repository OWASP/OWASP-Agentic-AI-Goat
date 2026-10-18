import React, { useEffect, useRef, useState } from 'react';
import axios from 'axios';
import { useWorkshopConfig } from '../../context/WorkshopConfigContext';
import useChangePolling from '../../hooks/useChangePolling';
import ObjectiveHelpModal from '../../components/workshop/ObjectiveHelpModal';
import { EmptyState, ExerciseProgress, ObjectiveCard, ObjectiveHelpActions, ObjectiveList, StatusNotice, WorkshopButton } from '../../components/workshop/WorkshopExperience';

const KEY = 'secureshop_agent_security';

export default function SecureShopObjectives() {
  const { snapshot, revision } = useWorkshopConfig();
  const [challenge, setChallenge] = useState(undefined);
  const [error, setError] = useState(false);
  const [help, setHelp] = useState(null);
  const [content, setContent] = useState(null);
  const [helpStatus, setHelpStatus] = useState('loading');
  const request = useRef(0);
  const mounted = useRef(false);
  const gate = snapshot?.exercises?.[KEY];
  const helpGate = help && gate?.objectives?.[help.id];
  const helpObjective = help && challenge?.exerciseGroups?.flatMap(group => group.objectives)
    .find(objective => objective.id === help.id);
  const helpField = help?.kind === 'hint' ? 'hintVisible' : 'solutionVisible';
  const helpAllowed = Boolean(gate?.isVisible && helpGate?.isVisible
    && helpGate[helpField] && helpObjective?.[helpField]);

  async function refresh({ signal } = {}) {
    const sequence = ++request.current;
    try {
      const { data } = await axios.get('/api/workshop/applications/secureshop', { signal });
      if (!Array.isArray(data?.challenges)) throw new Error('Invalid challenges');
      if (mounted.current && sequence === request.current && !signal?.aborted) {
        setChallenge(data.challenges.find(row => row.workshopKey === KEY) || null);
        setError(false);
      }
    } catch (cause) {
      if (mounted.current && sequence === request.current && !signal?.aborted) {
        setChallenge(null); setError(true);
      }
    }
  }
  useEffect(() => {
    mounted.current = true;
    return () => { mounted.current = false; request.current += 1; };
  }, []);
  useEffect(() => {
    const controller = new AbortController();
    void refresh({ signal: controller.signal });
    return () => controller.abort();
  }, [revision]);
  useChangePolling((_next, _previous, context) => refresh(context), [KEY]);

  useEffect(() => {
    if (!helpAllowed) { setHelp(null); setContent(null); return undefined; }
    const controller = new AbortController();
    let current = true;
    setContent(null); setHelpStatus('loading');
    const endpoint = help.kind === 'hint'
      ? `/api/hints/${KEY}/${encodeURIComponent(help.id)}`
      : `/api/solutions/secureshop-agent-security/${encodeURIComponent(help.id)}`;
    axios.get(endpoint, { signal: controller.signal }).then(({ data }) => {
      if (!current) return;
      const source = data?.[help.kind];
      setContent(help.kind === 'hint' ? source : {
        ...source, explanation: source?.approach || '',
        examples: (source?.examples || []).map(example => ({
          ...example, payload: example.payload || example.prompt || example.action || '',
        })),
      });
      setHelpStatus('ready');
    }).catch(() => { if (current) setHelpStatus('error'); });
    return () => { current = false; controller.abort(); };
  }, [help?.id, help?.kind, helpAllowed, revision]);

  const groups = (challenge?.exerciseGroups || []).map(group => ({ ...group,
    objectives: group.objectives.filter(objective => gate?.isVisible && gate.objectives?.[objective.id]?.isVisible),
  })).filter(group => group.objectives.length);
  const objectives = groups.flatMap(group => group.objectives);
  return (
    <section aria-label="Exercise objectives">
      <h3>Exercise objectives</h3>
      {error ? <StatusNotice status="error">Unable to load objective progress. <WorkshopButton onClick={() => refresh()}>Retry</WorkshopButton></StatusNotice>
        : challenge === undefined ? <StatusNotice>Loading available objectives…</StatusNotice>
          : <>
            <ExerciseProgress completed={objectives.filter(objective => objective.completed === true).length} total={objectives.length} />
            {!groups.length && <EmptyState>No objectives are currently enabled.</EmptyState>}
            {groups.map(group => <section key={group.id} aria-label={group.title}>
              <h4>{group.title}</h4>
              <ObjectiveList>{group.objectives.map(objective => {
                const visibility = gate.objectives[objective.id];
                const title = visibility.label || objective.text || objective.label;
                const description = visibility.description || objective.description;
                return <ObjectiveCard as="div" key={objective.id} $completed={objective.completed === true}>
                  <div><span>{objective.completed === true ? 'Completed: ' : ''}{title}</span>
                    {description && <p style={{ margin: '0.25rem 0 0', color: 'var(--muted, #64748b)', fontSize: '0.85rem' }}>{description}</p>}
                  </div>
                  <ObjectiveHelpActions
                    objectiveId={objective.id}
                    hintVisible={visibility.hintVisible && objective.hintVisible}
                    solutionVisible={visibility.solutionVisible && objective.solutionVisible}
                    activeKind={help?.id === objective.id ? help.kind : undefined}
                    onOpen={(kind, id) => setHelp({ id, kind, title })}
                  />
                </ObjectiveCard>;
              })}</ObjectiveList>
            </section>)}
          </>}
      {help && helpAllowed && <ObjectiveHelpModal kind={help.kind} objective={{ title: help.title }}
        content={content} status={helpStatus} error="Unable to load objective help."
        appearance="legacy-light" onClose={() => setHelp(null)} />}
    </section>
  );
}
