/* eslint-disable testing-library/no-unnecessary-act -- React DOM createRoot is used directly. */
import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import PromptInjectionHintEditorModal from './PromptInjectionHintEditorModal';

let root;
let node;

const click = (element) => {
  act(() => element.dispatchEvent(new MouseEvent('click', { bubbles: true })));
};

const change = (element, value) => {
  act(() => {
    const setter = Object.getOwnPropertyDescriptor(
      Object.getPrototypeOf(element),
      'value',
    ).set;
    setter.call(element, value);
    element.dispatchEvent(new Event('input', { bubbles: true }));
  });
};

beforeEach(() => {
  global.IS_REACT_ACT_ENVIRONMENT = true;
  node = document.createElement('div');
  document.body.appendChild(node);
  root = createRoot(node);
});

afterEach(() => {
  act(() => root.unmount());
  node.remove();
});

test('compact hint editor preserves progressive order while adding and removing hints', () => {
  const onSave = jest.fn();
  act(() => root.render(
    <PromptInjectionHintEditorModal
      objectiveLabel="Jailbreak"
      hint={{ title: 'Jailbreak clue', hints: ['First', 'Second'] }}
      onCancel={() => {}}
      onSave={onSave}
    />,
  ));

  const dialog = node.querySelector('[role="dialog"]');
  expect(dialog.textContent).toContain('Edit Hint — Jailbreak');
  expect([...dialog.querySelectorAll('textarea')].map((field) => field.value))
    .toEqual(['First', 'Second']);

  change(dialog.querySelector('input'), ' Updated title ');
  click([...dialog.querySelectorAll('button')].find((button) => button.textContent.includes('Add Hint')));
  const hints = [...dialog.querySelectorAll('textarea')];
  change(hints[2], ' Third ');
  click(dialog.querySelector('button[aria-label="Remove hint 2"]'));
  click([...dialog.querySelectorAll('button')].find((button) => button.textContent.includes('Save Changes')));

  expect(onSave).toHaveBeenCalledWith({
    title: 'Updated title',
    hints: ['First', 'Third'],
  });
});

test('cancel closes without saving', () => {
  const onCancel = jest.fn();
  const onSave = jest.fn();
  act(() => root.render(
    <PromptInjectionHintEditorModal
      objectiveLabel="Upload Document"
      hint={{ title: 'Upload clue', hints: ['First'] }}
      onCancel={onCancel}
      onSave={onSave}
    />,
  ));

  click([...node.querySelectorAll('button')].find((button) => button.textContent === 'Cancel'));

  expect(onCancel).toHaveBeenCalledTimes(1);
  expect(onSave).not.toHaveBeenCalled();
});
