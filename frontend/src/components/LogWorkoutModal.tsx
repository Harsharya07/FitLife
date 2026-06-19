import { motion, AnimatePresence } from 'framer-motion';
import { Check, X } from 'lucide-react';
import { useState } from 'react';
import toast from 'react-hot-toast';
import { celebrate, streakMilestone } from '../lib/celebrate';
import { activityApi } from '../lib/api';
import type { Exercise } from '../types';

interface LogWorkoutModalProps {
  exercise: Exercise;
  onClose: () => void;
  onLogged?: () => void;
}

export default function LogWorkoutModal({ exercise, onClose, onLogged }: LogWorkoutModalProps) {
  const [sets, setSets] = useState(3);
  const [reps, setReps] = useState(10);
  const [weight, setWeight] = useState<number | ''>('');
  const [duration, setDuration] = useState<number | ''>('');
  const [notes, setNotes] = useState('');
  const [loading, setLoading] = useState(false);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    try {
      await activityApi.logWorkout({
        exercise_id: exercise.id,
        exercise_name: exercise.name,
        sets: sets || null,
        reps: reps || null,
        weight_kg: weight === '' ? null : Number(weight),
        duration_min: duration === '' ? null : Number(duration),
        notes: notes || null,
      });
      celebrate(`Logged ${exercise.name}!`);
      activityApi.dashboard().then((s) => streakMilestone(s.current_streak)).catch(() => null);
      onLogged?.();
      onClose();
    } catch {
      toast.error('Failed to log workout');
    } finally {
      setLoading(false);
    }
  };

  return (
    <AnimatePresence>
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
        className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4 backdrop-blur-sm"
        onClick={onClose}
      >
        <motion.form
          initial={{ scale: 0.95, opacity: 0 }}
          animate={{ scale: 1, opacity: 1 }}
          exit={{ scale: 0.95, opacity: 0 }}
          onClick={(e) => e.stopPropagation()}
          onSubmit={submit}
          className="w-full max-w-md rounded-2xl bg-white p-6 shadow-2xl"
        >
          <div className="mb-4 flex items-start justify-between">
            <div>
              <h3 className="font-display text-lg font-bold text-primary">Log Workout</h3>
              <p className="text-sm text-muted">{exercise.name}</p>
            </div>
            <button type="button" onClick={onClose} className="rounded-lg p-1 hover:bg-slate-100">
              <X size={20} />
            </button>
          </div>

          <div className="grid grid-cols-2 gap-3">
            <label className="text-sm font-semibold text-ink">
              Sets
              <input
                type="number"
                min={1}
                max={50}
                value={sets}
                onChange={(e) => setSets(Number(e.target.value))}
                className="mt-1 w-full rounded-xl border-2 border-[#e0c3fc] bg-[#f8f6fc] px-3 py-2 outline-none focus:border-primary"
              />
            </label>
            <label className="text-sm font-semibold text-ink">
              Reps
              <input
                type="number"
                min={1}
                max={500}
                value={reps}
                onChange={(e) => setReps(Number(e.target.value))}
                className="mt-1 w-full rounded-xl border-2 border-[#e0c3fc] bg-[#f8f6fc] px-3 py-2 outline-none focus:border-primary"
              />
            </label>
            <label className="text-sm font-semibold text-ink">
              Weight (kg)
              <input
                type="number"
                min={0}
                step={0.5}
                value={weight}
                onChange={(e) => setWeight(e.target.value === '' ? '' : Number(e.target.value))}
                placeholder="Optional"
                className="mt-1 w-full rounded-xl border-2 border-[#e0c3fc] bg-[#f8f6fc] px-3 py-2 outline-none focus:border-primary"
              />
            </label>
            <label className="text-sm font-semibold text-ink">
              Duration (min)
              <input
                type="number"
                min={0}
                step={1}
                value={duration}
                onChange={(e) => setDuration(e.target.value === '' ? '' : Number(e.target.value))}
                placeholder="Optional"
                className="mt-1 w-full rounded-xl border-2 border-[#e0c3fc] bg-[#f8f6fc] px-3 py-2 outline-none focus:border-primary"
              />
            </label>
          </div>

          <label className="mt-3 block text-sm font-semibold text-ink">
            Notes
            <textarea
              value={notes}
              onChange={(e) => setNotes(e.target.value)}
              rows={2}
              placeholder="How did it feel?"
              className="mt-1 w-full rounded-xl border-2 border-[#e0c3fc] bg-[#f8f6fc] px-3 py-2 text-sm outline-none focus:border-primary"
            />
          </label>

          <button
            type="submit"
            disabled={loading}
            className="btn-accent mt-4 flex w-full items-center justify-center gap-2 rounded-xl py-3 font-bold disabled:opacity-60"
          >
            <Check size={18} />
            {loading ? 'Saving...' : 'Log Workout'}
          </button>
        </motion.form>
      </motion.div>
    </AnimatePresence>
  );
}
