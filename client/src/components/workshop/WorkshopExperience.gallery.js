import React, { useState } from 'react';
import {
  ActionGroup,
  EmptyState,
  ExerciseProgress,
  MultiScenarioWorkshop,
  ObjectiveCard,
  ObjectiveList,
  ScenarioNavigator,
  ScenarioWorkspace,
  SingleScenarioWorkshop,
  StatusNotice,
  WorkshopButton,
  WorkspaceLayout,
} from './WorkshopExperience';
import { multiScenarioFixture, singleScenarioFixture } from './fixtures.mjs';

function StateGallery() {
  return (
    <>
      <ActionGroup>
        <WorkshopButton>Primary</WorkshopButton>
        <WorkshopButton variant="secondary">Secondary</WorkshopButton>
        <WorkshopButton variant="tertiary">Help</WorkshopButton>
        <WorkshopButton variant="danger">Danger</WorkshopButton>
        <WorkshopButton disabled>Disabled</WorkshopButton>
      </ActionGroup>
      <StatusNotice>Ready</StatusNotice>
      <StatusNotice status="warning">Provider status is unknown</StatusNotice>
      <StatusNotice status="error">Run failed; prior evidence is retained</StatusNotice>
      <ObjectiveList>
        <ObjectiveCard $active>Selected objective</ObjectiveCard>
        <ObjectiveCard $completed>Completed objective</ObjectiveCard>
        <ObjectiveCard disabled>Unavailable objective</ObjectiveCard>
      </ObjectiveList>
      <ExerciseProgress completed={1} total={3} />
      <EmptyState>No enabled objectives (0 of 0)</EmptyState>
    </>
  );
}

export default function WorkshopExperienceGallery() {
  const [scenarioId, setScenarioId] = useState('documents');
  return (
    <div style={{ display: 'grid', gap: '3rem' }}>
      <SingleScenarioWorkshop definition={singleScenarioFixture}>
        <h2>Single scenario fixture</h2>
        <WorkspaceLayout><StateGallery /><aside>Objective rail</aside></WorkspaceLayout>
      </SingleScenarioWorkshop>
      <MultiScenarioWorkshop definition={multiScenarioFixture} activeScenarioId={scenarioId}>
        <h2>Multi scenario fixture</h2>
        <ScenarioNavigator definition={multiScenarioFixture} activeScenarioId={scenarioId} onScenarioChange={setScenarioId} />
        <ScenarioWorkspace scenarioId="documents" activeScenarioId={scenarioId}>Document workflow fixture</ScenarioWorkspace>
        <ScenarioWorkspace scenarioId="messages" activeScenarioId={scenarioId}>Message workflow fixture</ScenarioWorkspace>
      </MultiScenarioWorkshop>
    </div>
  );
}
