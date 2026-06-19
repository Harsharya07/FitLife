import { motion } from 'framer-motion';
import { Save, UserCircle } from 'lucide-react';
import { useEffect, useState } from 'react';
import toast from 'react-hot-toast';
import axios from 'axios';
import { aiApi } from '../lib/api';
import type { UserProfile } from '../types';

const GOALS = ['Lose Weight', 'Build Muscle', 'Maintain Fitness', 'Improve Endurance', 'General Health'];
const ACTIVITY = ['Sedentary', 'Light', 'Moderate', 'Active', 'Very Active'];
const DIETS = ['Non-Vegetarian', 'Vegetarian', 'Vegan', 'Eggetarian', 'Keto', 'No Preference'];
const EXPERIENCE = ['Beginner', 'Intermediate', 'Advanced'];

const emptyProfile: UserProfile = {
  age: null,
  gender: '',
  height_cm: null,
  weight_kg: null,
  goal: '',
  activity_level: '',
  dietary_preference: '',
  allergies: '',
  health_conditions: '',
  target_calories: null,
  workout_days_per_week: null,
  experience_level: '',
};

interface ProfileFormProps {
  onSaved?: () => void;
  compact?: boolean;
}

export default function ProfileForm({ onSaved, compact = false }: ProfileFormProps) {
  const [profile, setProfile] = useState<UserProfile>(emptyProfile);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    aiApi
      .getProfile()
      .then((p) => p && setProfile({ ...emptyProfile, ...p }))
      .finally(() => setLoading(false));
  }, []);

  const update = (key: keyof UserProfile, value: string | number | null) => {
    setProfile((prev) => ({ ...prev, [key]: value }));
  };

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    setSaving(true);
    try {
      await aiApi.saveProfile(profile);
      toast.success('Profile saved! AI will use this for personalized plans.');
      onSaved?.();
    } catch (err) {
      const msg = axios.isAxiosError(err) ? err.response?.data?.detail : 'Failed to save';
      toast.error(typeof msg === 'string' ? msg : 'Failed to save profile');
    } finally {
      setSaving(false);
    }
  };

  if (loading) {
    return (
      <div className="flex justify-center py-10">
        <div className="h-8 w-8 animate-spin rounded-full border-4 border-primary/20 border-t-primary" />
      </div>
    );
  }

  const inputClass =
    'w-full rounded-xl border-2 border-[#e0c3fc] bg-[#f8f6fc] px-4 py-2.5 text-sm outline-none transition focus:border-primary focus:ring-2 focus:ring-primary/20';
  const labelClass = 'mb-1 block text-sm font-semibold text-ink';

  return (
    <motion.form
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      onSubmit={handleSave}
      className={`space-y-4 ${compact ? '' : 'rounded-2xl bg-white p-6 shadow-lg'}`}
    >
      {!compact && (
        <div className="mb-2 flex items-center gap-2">
          <UserCircle className="text-primary" size={22} />
          <h3 className="font-display text-lg font-bold text-primary">Your Fitness Profile</h3>
        </div>
      )}
      <p className="text-sm text-muted">
        Fill in your details so AI can generate personalized diet plans, workout routines, and advice.
      </p>

      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        <div>
          <label className={labelClass}>Age</label>
          <input
            type="number"
            min={13}
            max={100}
            value={profile.age ?? ''}
            onChange={(e) => update('age', e.target.value ? Number(e.target.value) : null)}
            className={inputClass}
            placeholder="25"
          />
        </div>
        <div>
          <label className={labelClass}>Gender</label>
          <select
            value={profile.gender ?? ''}
            onChange={(e) => update('gender', e.target.value)}
            className={inputClass}
          >
            <option value="">Select</option>
            <option value="Male">Male</option>
            <option value="Female">Female</option>
            <option value="Other">Other</option>
            <option value="Prefer not to say">Prefer not to say</option>
          </select>
        </div>
        <div>
          <label className={labelClass}>Height (cm)</label>
          <input
            type="number"
            value={profile.height_cm ?? ''}
            onChange={(e) => update('height_cm', e.target.value ? Number(e.target.value) : null)}
            className={inputClass}
            placeholder="170"
          />
        </div>
        <div>
          <label className={labelClass}>Weight (kg)</label>
          <input
            type="number"
            value={profile.weight_kg ?? ''}
            onChange={(e) => update('weight_kg', e.target.value ? Number(e.target.value) : null)}
            className={inputClass}
            placeholder="70"
          />
        </div>
        <div>
          <label className={labelClass}>Fitness Goal</label>
          <select
            value={profile.goal ?? ''}
            onChange={(e) => update('goal', e.target.value)}
            className={inputClass}
          >
            <option value="">Select goal</option>
            {GOALS.map((g) => (
              <option key={g} value={g}>{g}</option>
            ))}
          </select>
        </div>
        <div>
          <label className={labelClass}>Activity Level</label>
          <select
            value={profile.activity_level ?? ''}
            onChange={(e) => update('activity_level', e.target.value)}
            className={inputClass}
          >
            <option value="">Select</option>
            {ACTIVITY.map((a) => (
              <option key={a} value={a}>{a}</option>
            ))}
          </select>
        </div>
        <div>
          <label className={labelClass}>Diet Preference</label>
          <select
            value={profile.dietary_preference ?? ''}
            onChange={(e) => update('dietary_preference', e.target.value)}
            className={inputClass}
          >
            <option value="">Select</option>
            {DIETS.map((d) => (
              <option key={d} value={d}>{d}</option>
            ))}
          </select>
        </div>
        <div>
          <label className={labelClass}>Experience Level</label>
          <select
            value={profile.experience_level ?? ''}
            onChange={(e) => update('experience_level', e.target.value)}
            className={inputClass}
          >
            <option value="">Select</option>
            {EXPERIENCE.map((e) => (
              <option key={e} value={e}>{e}</option>
            ))}
          </select>
        </div>
        <div>
          <label className={labelClass}>Workout Days / Week</label>
          <input
            type="number"
            min={1}
            max={7}
            value={profile.workout_days_per_week ?? ''}
            onChange={(e) =>
              update('workout_days_per_week', e.target.value ? Number(e.target.value) : null)
            }
            className={inputClass}
            placeholder="4"
          />
        </div>
        <div>
          <label className={labelClass}>Target Calories / Day</label>
          <input
            type="number"
            value={profile.target_calories ?? ''}
            onChange={(e) => update('target_calories', e.target.value ? Number(e.target.value) : null)}
            className={inputClass}
            placeholder="2000 (optional)"
          />
        </div>
        <div className="sm:col-span-2">
          <label className={labelClass}>Allergies / Restrictions</label>
          <input
            type="text"
            value={profile.allergies ?? ''}
            onChange={(e) => update('allergies', e.target.value)}
            className={inputClass}
            placeholder="e.g. nuts, dairy, gluten"
          />
        </div>
        <div className="sm:col-span-2 lg:col-span-3">
          <label className={labelClass}>Health Conditions (optional)</label>
          <input
            type="text"
            value={profile.health_conditions ?? ''}
            onChange={(e) => update('health_conditions', e.target.value)}
            className={inputClass}
            placeholder="e.g. diabetes, hypertension — consult your doctor"
          />
        </div>
      </div>

      <button
        type="submit"
        disabled={saving}
        className="flex items-center gap-2 rounded-xl gradient-primary px-6 py-3 font-bold text-white shadow-lg transition hover:shadow-xl disabled:opacity-60"
      >
        <Save size={18} />
        {saving ? 'Saving...' : 'Save Profile'}
      </button>
    </motion.form>
  );
}
