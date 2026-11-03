import React, { useId, useRef, useState } from 'react';
import styled from 'styled-components';
import { FiActivity, FiMessageSquare } from 'react-icons/fi';
import { workshopTokens } from './experience.mjs';

const Views = styled.div`
  display: flex;
  flex-direction: column;
  flex: 1;
  min-height: 0;
  min-width: 0;
`;
const TabList = styled.div`
  display: flex;
  flex-shrink: 0;
  border-bottom: 1px solid ${workshopTokens.border};
  background: ${workshopTokens.surface};
`;
const Tab = styled.button`
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 0.5rem;
  min-height: 44px;
  padding: 0.65rem 1rem;
  border: 0;
  border-bottom: 3px solid transparent;
  background: transparent;
  color: ${workshopTokens.mutedText};
  font: inherit;
  font-size: 0.9rem;
  font-weight: 600;
  cursor: pointer;
  &[aria-selected='true'] {
    color: ${workshopTokens.focus};
    border-bottom-color: ${workshopTokens.brand};
    background: #f8f9ff;
  }
  &:focus-visible { outline: 2px solid ${workshopTokens.focus}; outline-offset: -3px; }
  @media (max-width: 600px) { flex: 1; padding-inline: 0.5rem; }
`;
const Count = styled.span`
  padding: 0.1rem 0.45rem;
  border-radius: 1rem;
  background: #eef0ff;
  color: ${workshopTokens.focus};
  font-size: 0.8rem;
`;
const Panel = styled.div`
  display: flex;
  flex-direction: column;
  flex: 1;
  min-height: 0;
  min-width: 0;
  &[hidden] { display: none; }
  &:focus-visible { outline: 2px solid ${workshopTokens.focus}; outline-offset: -3px; }
`;
const Activity = styled.div`
  flex: 1;
  min-height: 0;
  overflow: auto;
  padding: 1.25rem;
  background: ${workshopTokens.canvas};
  color: ${workshopTokens.text};
  > p { margin: 0 0 1rem; color: ${workshopTokens.mutedText}; font-size: 0.85rem; }
  > ol { list-style: none; margin: 0; padding: 0; }
`;
const Entry = styled.li`
  padding: 1rem;
  margin-bottom: 1rem;
  border: 1px solid ${workshopTokens.controlBorder};
  border-radius: ${workshopTokens.controlRadius};
  background: ${workshopTokens.surface};
  overflow-wrap: anywhere;
  header { display: flex; flex-wrap: wrap; align-items: center; gap: 0.5rem 0.75rem; }
  h4 { margin: 0; font-size: 0.95rem; }
  time, .time-unavailable { color: ${workshopTokens.mutedText}; font-size: 0.8rem; }
  .status { font-size: 0.8rem; font-weight: 600; }
  .status[data-status='success'] { color: #166534; }
  .status[data-status='error'], .status[data-status='failed'] { color: #b91c1c; }
  .controlled { font-size: 0.8rem; color: ${workshopTokens.warningText}; }
  dl { margin: 0.75rem 0 0; }
  dt { font-size: 0.8rem; font-weight: 600; margin-top: 0.75rem; }
  dd { margin: 0.35rem 0 0; }
`;
const Output = styled.pre`
  margin: 0;
  padding: 0.75rem;
  max-height: 200px;
  overflow: auto;
  white-space: pre-wrap;
  overflow-wrap: anywhere;
  background: ${workshopTokens.canvas};
  border: 1px solid ${workshopTokens.border};
  border-radius: ${workshopTokens.controlRadius};
  font-family: 'Fira Code', monospace;
  font-size: 0.8rem;
  line-height: 1.5;
  &:focus-visible { outline: 2px solid ${workshopTokens.focus}; outline-offset: 2px; }
`;
const EMPTY_ACTIVITY = [];
const STATUS_LABELS = { success: 'Success', error: 'Error', failed: 'Error', pending: 'Pending', running: 'Running' };
const formatValue = value => typeof value === 'string'
  ? (value === '' ? '""' : value)
  : JSON.stringify(value, null, 2);

function ActivityEntry({ entry }) {
  const date = entry.timestamp == null ? null : new Date(entry.timestamp);
  const validDate = date && Number.isFinite(date.getTime());
  return (
    <Entry>
      <header>
        <h4>{entry.name}</h4>
        {entry.status && <span className="status" data-status={entry.status}>{STATUS_LABELS[entry.status] || entry.status}</span>}
        {validDate
          ? <time dateTime={date.toISOString()}>{date.toLocaleString()}</time>
          : <span className="time-unavailable">Time unavailable</span>}
        {entry.controlled && <span className="controlled">Controlled/mock execution</span>}
      </header>
      <dl>
        <dt>Arguments</dt>
        <dd>{entry.arguments === undefined ? 'Arguments unavailable' : <Output tabIndex={0} aria-label={`${entry.name} arguments`}>{formatValue(entry.arguments)}</Output>}</dd>
        {entry.error !== undefined && <>
          <dt>Error</dt>
          <dd><Output tabIndex={0} aria-label={`${entry.name} error`}>{formatValue(entry.error)}</Output></dd>
        </>}
        <dt>Result</dt>
        <dd>{entry.result === undefined ? 'No result recorded' : <Output tabIndex={0} aria-label={`${entry.name} result`}>{formatValue(entry.result)}</Output>}</dd>
      </dl>
    </Entry>
  );
}

/** Views over one caller-owned conversation; activity must come from its authorized server adapter. */
export default function ChatActivityTabs({ activity = EMPTY_ACTIVITY, children }) {
  const id = useId();
  const [selected, setSelected] = useState(0);
  const tabs = useRef([]);
  const selectWithKeyboard = event => {
    const index = { ArrowRight: (selected + 1) % 2, ArrowLeft: (selected + 1) % 2, Home: 0, End: 1 }[event.key];
    if (index === undefined) return;
    event.preventDefault();
    setSelected(index);
    tabs.current[index]?.focus();
  };
  return (
    <Views>
      <TabList role="tablist" aria-label="Conversation views">
        {['Chat', 'Tool Activity'].map((label, index) => (
          <Tab key={label} ref={element => { tabs.current[index] = element; }}
            type="button" role="tab" id={`${id}-tab-${index}`} aria-controls={`${id}-panel-${index}`}
            aria-selected={selected === index} tabIndex={selected === index ? 0 : -1}
            onClick={() => setSelected(index)} onKeyDown={selectWithKeyboard}>
            {index === 0 ? <FiMessageSquare aria-hidden="true" /> : <FiActivity aria-hidden="true" />}
            {label}{index === 1 && <Count aria-label={`${activity.length} recorded tool calls`}>{activity.length}</Count>}
          </Tab>
        ))}
      </TabList>
      <Panel role="tabpanel" id={`${id}-panel-0`} aria-labelledby={`${id}-tab-0`} hidden={selected !== 0}>
        {children}
      </Panel>
      <Panel role="tabpanel" id={`${id}-panel-1`} aria-labelledby={`${id}-tab-1`} hidden={selected !== 1} tabIndex={0}>
        <Activity>
          {activity.length === 0 ? <>
            <h4>No tool executions yet</h4>
            <p>Recorded tool calls for this conversation will appear here when the agent uses a tool.</p>
          </> : <>
            <p>Newest calls first. Tool execution does not by itself complete an objective.</p>
            <ol aria-label="Recorded tool calls">
              {[...activity].reverse().map((entry, index) => <ActivityEntry key={entry.id ?? index} entry={entry} />)}
            </ol>
          </>}
        </Activity>
      </Panel>
    </Views>
  );
}
