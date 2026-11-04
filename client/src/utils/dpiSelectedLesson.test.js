import { LESSONS, readSelectedLesson, describeSelectedLesson } from './dpiSelectedLesson';

const selected = (objectiveId, mode = 'vuln') => ({
  version: 'dpi-selected-lesson-v1', objectiveId, mode,
  lessonKind: LESSONS[objectiveId].kind,
  profile: mode === 'fixed' ? 'fixed' : 'guided',
  policyVersion: mode === 'fixed' ? 'dpi-bounded-fixed-v1' : 'dpi-bounded-v1',
});

test.each(['format_override', 'classification_override'])('bounded %s metadata is closed and mode-specific', objectiveId => {
  for (const mode of ['vuln', 'fixed']) {
    const value = selected(objectiveId, mode);
    expect(readSelectedLesson(value, objectiveId)).toEqual(value);
    expect(describeSelectedLesson(value)).toContain(mode === 'fixed' ? '(fixed mode)' : '(vulnerable mode)');
    expect(readSelectedLesson({ ...value, policyVersion: 'dpi-guided-v1' })).toBeNull();
    expect(readSelectedLesson({ ...value, profile: mode === 'fixed' ? 'guided' : 'fixed' })).toBeNull();
    expect(readSelectedLesson({ ...value, extra: 'private proof' })).toBeNull();
    expect(readSelectedLesson(value, 'other')).toBeNull();
  }
});

test('existing fixed text metadata is rendered without accepting a guided policy', () => {
  const value = { ...selected('role_playing', 'fixed'), policyVersion: 'dpi-aws-scope-fixed-v1' };
  expect(readSelectedLesson(value)).toEqual(value);
  expect(readSelectedLesson({ ...value, profile: 'guided', policyVersion: 'dpi-guided-v1' })).toBeNull();
});
