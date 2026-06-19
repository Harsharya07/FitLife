import type { UserProfile } from '../types';

const FIELDS: { key: keyof UserProfile; label: string }[] = [
  { key: 'age', label: 'Age' },
  { key: 'gender', label: 'Gender' },
  { key: 'height_cm', label: 'Height' },
  { key: 'weight_kg', label: 'Weight' },
  { key: 'goal', label: 'Goal' },
  { key: 'activity_level', label: 'Activity level' },
  { key: 'dietary_preference', label: 'Diet preference' },
  { key: 'experience_level', label: 'Experience' },
  { key: 'workout_days_per_week', label: 'Workout days/week' },
];

export function getProfileCompletion(profile: UserProfile | null | undefined) {
  if (!profile) {
    return { percent: 0, missing: FIELDS.map((f) => f.label) };
  }
  const filled = FIELDS.filter(({ key }) => {
    const v = profile[key];
    return v !== null && v !== undefined && v !== '';
  });
  const missing = FIELDS.filter(({ key }) => {
    const v = profile[key];
    return v === null || v === undefined || v === '';
  }).map((f) => f.label);

  return {
    percent: Math.round((filled.length / FIELDS.length) * 100),
    missing,
  };
}

export function onboardingKey(userId: number) {
  return `fitlife_onboarding_done_${userId}`;
}

export function isOnboardingDone(userId: number) {
  return localStorage.getItem(onboardingKey(userId)) === '1';
}

export function markOnboardingDone(userId: number) {
  localStorage.setItem(onboardingKey(userId), '1');
}
