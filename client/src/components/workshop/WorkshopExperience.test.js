import React, { act, useState } from 'react';
import { createRoot } from 'react-dom/client';
import {
  MultiScenarioWorkshop,
  ObjectiveHelpActions,
  ResetConfirmation,
  SafeChatBody,
  ScenarioNavigator,
  ScenarioWorkspace,
  ScopedResetButton,
  SingleScenarioWorkshop,
  WorkshopModeBadge,
  WorkshopModeControl,
} from './WorkshopExperience';
import useWorkshopResetController from './useWorkshopResetController';
import {
  createScenarioFence,
  defineWorkshop,
} from './experience.mjs';
import { multiScenarioFixture, singleScenarioFixture } from './fixtures.mjs';

const click = (element) => act(() => element.dispatchEvent(new MouseEvent('click', { bubbles: true })));
const change = (element, value) => act(() => {
  const setter = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(element), 'value').set;
  setter.call(element, value);
  element.dispatchEvent(new Event('input', { bubbles: true }));
});
const flush = async () => act(async () => { await Promise.resolve(); await Promise.resolve(); });
const deferred = () => {
  let resolve;
  let reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
};

beforeEach(() => { global.IS_REACT_ACT_ENVIRONMENT = true; });
afterEach(() => { document.body.replaceChildren(); });

test('definitions enforce exactly the two template shapes and canonical objective ownership', () => {
  expect(() => defineWorkshop({
    ...singleScenarioFixture,
    workshopKey: 'invalid-single',
    scenarios: [...singleScenarioFixture.scenarios, ...singleScenarioFixture.scenarios],
  })).toThrow('Scenario count');
  expect(() => defineWorkshop({
    ...multiScenarioFixture,
    workshopKey: 'invalid-source',
    scenarios: multiScenarioFixture.scenarios.map((scenario, index) => (
      index ? scenario : { ...scenario, objectiveSource: 'page-array' }
    )),
  })).toThrow('Canonical objectives');
  expect(Object.isFrozen(singleScenarioFixture.scenarios[0].capabilities)).toBe(true);
});

test('single and multi templates expose their stable workshop and scenario contracts', () => {
  const node = document.createElement('div');
  const root = createRoot(node);
  act(() => root.render(
    <>
      <SingleScenarioWorkshop definition={singleScenarioFixture}>Single</SingleScenarioWorkshop>
      <MultiScenarioWorkshop definition={multiScenarioFixture} activeScenarioId="documents">Multi</MultiScenarioWorkshop>
    </>,
  ));
  expect(node.querySelector('[data-workshop="fixture_single_scenario"]').dataset.activeScenario).toBe('chat');
  expect(node.querySelector('[data-workshop="fixture_multi_scenario"]').dataset.activeScenario).toBe('documents');
  act(() => root.unmount());
});

test('mode control shows the true mode and cannot select an unsupported fixed mode', () => {
  const onChange = jest.fn();
  const node = document.createElement('div');
  const root = createRoot(node);
  act(() => root.render(<WorkshopModeControl mode="vuln" onChange={onChange} reason="This objective has no fixed implementation." />));
  expect(node.querySelector('[data-workshop-mode-control]').dataset.workshopMode).toBe('vuln');
  expect(node.querySelector('button[aria-pressed="true"]').textContent).toBe('Vulnerable');
  expect([...node.querySelectorAll('button')].find((button) => button.textContent === 'Fixed').disabled).toBe(true);
  expect(node.textContent).toContain('This objective has no fixed implementation.');
  click([...node.querySelectorAll('button')].find((button) => button.textContent === 'Fixed'));
  expect(onChange).not.toHaveBeenCalled();
  act(() => root.render(<WorkshopModeControl mode="vuln" allowedModes={['vuln', 'fixed']} onChange={onChange} />));
  click([...node.querySelectorAll('button')].find((button) => button.textContent === 'Fixed'));
  expect(onChange).toHaveBeenCalledWith('fixed');
  act(() => root.render(<WorkshopModeControl mode="vuln" allowedModes={['vuln', 'fixed']} onChange={onChange} pending />));
  expect([...node.querySelectorAll('button')].every((button) => button.disabled)).toBe(true);
  expect(node.textContent).toContain('Changing mode');
  act(() => root.render(<WorkshopModeBadge mode="unknown" scopeLabel="Scenario mode" />));
  expect(node.textContent).toBe('Scenario mode: Unavailable');
  act(() => root.unmount());
});

test('an explicitly opted-in null mode offers unpressed choices without changing unknown-mode defaults', () => {
  const node = document.createElement('div');
  const root = createRoot(node);
  const onChange = jest.fn();
  const props = { allowedModes: ['vuln', 'fixed'], unselectedModeLabel: 'Existing lesson mode',
    scopeLabel: 'Document and email agents', onChange };
  act(() => root.render(<WorkshopModeControl mode={null} allowedModes={props.allowedModes} onChange={onChange} />));
  expect(node.textContent).toBe('Lab mode: Unavailable');
  act(() => root.render(<WorkshopModeControl mode="unknown" {...props} />));
  expect(node.textContent).toBe('Document and email agents: Unavailable');
  act(() => root.render(<WorkshopModeControl mode={null} {...props} />));
  expect(node.querySelector('[data-workshop-mode-control]').dataset.workshopMode).toBe('unselected');
  expect(node.textContent).toContain('Existing lesson mode');
  const buttons = [...node.querySelectorAll('button')];
  expect(buttons).toHaveLength(2);
  expect(buttons.every(button => button.getAttribute('aria-pressed') === 'false')).toBe(true);
  click(buttons[1]);
  expect(onChange).toHaveBeenCalledWith('fixed');
  act(() => root.render(<WorkshopModeControl mode={null} {...props} pending />));
  expect([...node.querySelectorAll('button')].every(button => button.disabled)).toBe(true);
  act(() => root.unmount());
});

test.each([
  [false, false, []],
  [true, false, ['Hint']],
  [false, true, ['Solution']],
  [true, true, ['Hint', 'Solution']],
])('help actions respect independent gates: hint %s, solution %s', (hintVisible, solutionVisible, labels) => {
  const onOpen = jest.fn();
  const node = document.createElement('div');
  const root = createRoot(node);
  act(() => root.render(
    <ObjectiveHelpActions objectiveId="objective-one" hintVisible={hintVisible} solutionVisible={solutionVisible} onOpen={onOpen} activeKind="hint" />,
  ));
  const buttons = [...node.querySelectorAll('button')];
  expect(buttons.map((button) => button.textContent.trim())).toEqual(labels);
  buttons.forEach(click);
  expect(onOpen.mock.calls).toEqual(labels.map((label) => [label.toLowerCase(), 'objective-one']));
  act(() => root.unmount());
});

test('hint and solution retain the DPI palette with compact content-width sizing', () => {
  const node = document.createElement('div');
  const root = createRoot(node);
  act(() => root.render(
    <ObjectiveHelpActions objectiveId="objective-one" hintVisible solutionVisible onOpen={() => {}} />,
  ));
  const buttons = [...node.querySelectorAll('button')];
  expect(buttons).toHaveLength(2);
  buttons.forEach((button) => {
    const style = getComputedStyle(button);
    expect(style.backgroundColor).toBe('rgb(102, 126, 234)');
    expect(style.color).toBe('rgb(255, 255, 255)');
    expect(style.borderTopColor).toBe('rgb(102, 126, 234)');
    expect(style.minHeight).toBe('32px');
    expect(style.width).toBe('auto');
    expect(style.flexGrow).toBe('0');
    expect(style.borderRadius).toBe('10px');
  });
  act(() => root.unmount());
});

test('reset action keeps the caller supplied scope and safe chat renders text without HTML execution', () => {
  const onClick = jest.fn();
  const node = document.createElement('div');
  const root = createRoot(node);
  act(() => root.render(
    <>
      <ScopedResetButton label="Reset Document Upload scenario" onClick={onClick} />
      <SafeChatBody content={'<img src=x onerror=alert(1)>\n| Tool | Result |'} />
      <SafeChatBody content={'<script>alert(1)</script>'} plain />
    </>,
  ));
  click(node.querySelector('button'));
  expect(onClick).toHaveBeenCalledTimes(1);
  expect(node.querySelector('button').textContent).toContain('Reset Document Upload scenario');
  expect(node.querySelector('script')).toBeNull();
  expect(node.querySelector('img')).toBeNull();
  expect(node.querySelectorAll('[data-safe-chat-body]')).toHaveLength(2);
  act(() => root.unmount());
});

test('scenario navigation is keyboard accessible and switching preserves sibling drafts', () => {
  function Harness() {
    const [active, setActive] = useState('documents');
    const [documents, setDocuments] = useState('');
    const [messages, setMessages] = useState('');
    return (
      <MultiScenarioWorkshop definition={multiScenarioFixture} activeScenarioId={active}>
        <ScenarioNavigator definition={multiScenarioFixture} activeScenarioId={active} onScenarioChange={setActive} />
        <ScenarioWorkspace scenarioId="documents" activeScenarioId={active}>
          <input aria-label="Document draft" value={documents} onChange={(event) => setDocuments(event.target.value)} />
        </ScenarioWorkspace>
        <ScenarioWorkspace scenarioId="messages" activeScenarioId={active}>
          <input aria-label="Message draft" value={messages} onChange={(event) => setMessages(event.target.value)} />
        </ScenarioWorkspace>
      </MultiScenarioWorkshop>
    );
  }
  const node = document.createElement('div');
  const root = createRoot(node);
  act(() => root.render(<Harness />));
  change(node.querySelector('[aria-label="Document draft"]'), 'document evidence');
  const documentTab = node.querySelector('[data-scenario-tab="documents"]');
  act(() => documentTab.dispatchEvent(new KeyboardEvent('keydown', { key: 'ArrowRight', bubbles: true })));
  expect(node.querySelector('[data-scenario-tab="messages"]').getAttribute('aria-selected')).toBe('true');
  change(node.querySelector('[aria-label="Message draft"]'), 'message evidence');
  click(node.querySelector('[data-scenario-tab="documents"]'));
  expect(node.querySelector('[aria-label="Document draft"]').value).toBe('document evidence');
  expect(node.querySelector('[aria-label="Message draft"]').value).toBe('message evidence');
  expect(node.querySelector('[data-scenario-workspace="messages"]').hidden).toBe(true);
  act(() => root.unmount());
});

test('scenario fence invalidates only the named owner', () => {
  const fence = createScenarioFence();
  const documentOwner = { attendeeId: 7, workshopKey: 'ipi', scenarioId: 'document' };
  const emailOwner = { attendeeId: 7, workshopKey: 'ipi', scenarioId: 'email' };
  const documentRun = fence.capture(documentOwner);
  const emailRun = fence.capture(emailOwner);
  fence.invalidate(documentOwner);
  expect(documentRun.isCurrent()).toBe(false);
  expect(emailRun.isCurrent()).toBe(true);
});

test('reset waits for durable acknowledgement, rejects repeat confirmation, and preserves siblings', async () => {
  const pending = deferred();
  const mutation = jest.fn(() => pending.promise);
  function Harness() {
    const [documentState, setDocumentState] = useState('document evidence');
    const [emailState] = useState('email evidence');
    const reset = useWorkshopResetController({
      owner: { attendeeId: 7, workshopKey: 'ipi', scenarioId: 'document' },
      title: 'Reset documents?',
      description: 'Email is preserved.',
      mutation,
      onCommit: () => setDocumentState(''),
    });
    return (
      <div>
        <output data-testid="document-state">{documentState}</output>
        <output data-testid="email-state">{emailState}</output>
        <button onClick={reset.requestReset}>Request reset</button>
        <ResetConfirmation {...reset.confirmation} />
      </div>
    );
  }
  const node = document.createElement('div');
  document.body.appendChild(node);
  const root = createRoot(node);
  act(() => root.render(<Harness />));
  click([...node.querySelectorAll('button')].find((button) => button.textContent === 'Request reset'));
  const confirm = [...document.querySelector('[role=\"alertdialog\"]').querySelectorAll('button')].find((button) => button.textContent === 'Confirm reset');
  click(confirm);
  click(confirm);
  expect(mutation).toHaveBeenCalledTimes(1);
  expect(node.querySelector('[data-testid="document-state"]').textContent).toBe('document evidence');
  await act(async () => { pending.resolve({ ok: true }); await pending.promise; });
  await flush();
  expect(node.querySelector('[data-testid="document-state"]').textContent).toBe('');
  expect(node.querySelector('[data-testid="email-state"]').textContent).toBe('email evidence');
  expect(document.querySelector('[role="alertdialog"]')).toBeNull();
  act(() => root.unmount());
});

test('reset confirmation traps focus, supports Escape, and restores its trigger', () => {
  function Harness() {
    const reset = useWorkshopResetController({
      owner: { attendeeId: 7, workshopKey: 'ipi', scenarioId: 'email' },
      title: 'Reset email?',
      description: 'Documents are preserved.',
      mutation: () => Promise.resolve(),
    });
    return (
      <>
        <button onClick={reset.requestReset}>Open reset</button>
        <ResetConfirmation {...reset.confirmation} />
      </>
    );
  }
  const node = document.createElement('div');
  document.body.appendChild(node);
  const root = createRoot(node);
  act(() => root.render(<Harness />));
  const trigger = node.querySelector('button');
  trigger.focus();
  click(trigger);
  expect(document.activeElement.textContent).toBe('Confirm reset');
  act(() => document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Tab', bubbles: true })));
  expect(document.activeElement.textContent).toBe('Cancel');
  act(() => document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true })));
  expect(document.querySelector('[role="alertdialog"]')).toBeNull();
  expect(document.activeElement).toBe(trigger);
  act(() => root.unmount());
});

test('reset portal escapes transformed ancestors and unmount removes the dialog', () => {
  const node = document.createElement('div'); node.style.transform = 'translateY(0)';
  document.body.appendChild(node); const root = createRoot(node);
  act(() => root.render(<ResetConfirmation open status="confirming" title="Reset documents?" description="Preserve sibling scenario." onCancel={() => {}} onConfirm={() => {}} />));
  const dialog = document.querySelector('[role="alertdialog"]');
  expect(dialog).not.toBeNull(); expect(node.contains(dialog)).toBe(false);
  expect(dialog.parentElement.parentElement).toBe(document.body);
  act(() => root.unmount()); expect(document.querySelector('[role="alertdialog"]')).toBeNull(); node.remove();
});
