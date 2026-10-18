import React from 'react';
import styled from 'styled-components';
import AgentRunInspector from '../components/observability/AgentRunInspector';

const Page = styled.main`
  min-height: 100vh; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 2rem;
  @media (max-width: 640px) { padding: 1rem; }
`;
const Content = styled.div`
  max-width: 1200px; margin: 0 auto;
  > h1 { color: white; margin: 0 0 .45rem; font-size: clamp(1.7rem, 4vw, 2.35rem); }
  > p { color: rgba(255,255,255,.88); margin: 0 0 1.3rem; max-width: 720px; line-height: 1.55; }
`;

export default function AgentRunsPage() {
  return <Page><Content><h1>Your agent runs</h1>
    <p>Inspect model decisions, graph transitions, tool calls, judge verdicts, and timing recorded for your workshop sessions.</p>
    <AgentRunInspector />
  </Content></Page>;
}
