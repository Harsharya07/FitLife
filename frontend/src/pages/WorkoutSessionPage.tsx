import { motion } from 'framer-motion';
import { CheckCircle, Dumbbell, Play, Square, Timer } from 'lucide-react';
import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import toast from 'react-hot-toast';
import PageHero from '../components/PageHero';
import RestTimer from '../components/RestTimer';
import { contentApi, sessionsApi } from '../lib/api';
import { celebrate } from '../lib/celebrate';
import { IMAGES } from '../lib/images';
import type { Exercise, ExerciseCategory, WorkoutLog, WorkoutSession } from '../types';

export default function WorkoutSessionPage() {
  const [session, setSession] = useState<WorkoutSession | null>(null);
  const [logs, setLogs] = useState<WorkoutLog[]>([]);
  const [categories, setCategories] = useState<ExerciseCategory[]>([]);
  const [selected, setSelected] = useState<Exercise | null>(null);
  const [sets, setSets] = useState(3);
  const [reps, setReps] = useState(10);
  const [weight, setWeight] = useState<number | ''>('');
  const [restSeconds, setRestSeconds] = useState(60);
  const [loading, setLoading] = useState(true);
  const [logging, setLogging] = useState(false);
  const [finishing, setFinishing] = useState(false);

  useEffect(() => {
    Promise.all([sessionsApi.active(), contentApi.exercises()])
      .then(([active, ex]) => {
        setSession(active);
        setCategories(ex);
      })
      .finally(() => setLoading(false));
  }, []);

  const startSession = async () => {
    try {
      const s = await sessionsApi.start('Gym Session');
      setSession(s);
      toast.success('Session started!');
    } catch {
      toast.error('Could not start session');
    }
  };

  const logExercise = async () => {
    if (!session || !selected) return;
    setLogging(true);
    try {
      const log = await sessionsApi.log(session.id, {
        exercise_id: selected.id,
        exercise_name: selected.name,
        sets: sets || null,
        reps: reps || null,
        weight_kg: weight === '' ? null : Number(weight),
        duration_min: null,
        notes: null,
      });
      setLogs((prev) => [log, ...prev]);
      celebrate(`Logged ${selected.name}!`);
      setSelected(null);
    } catch {
      toast.error('Failed to log exercise');
    } finally {
      setLogging(false);
    }
  };

  const finishSession = async () => {
    if (!session) return;
    setFinishing(true);
    try {
      const finished = await sessionsApi.finish(session.id);
      celebrate('Session complete!');
      setSession(finished);
      toast.success(`Finished! ${finished.exercise_count} exercises logged.`);
    } catch {
      toast.error('Could not finish session');
    } finally {
      setFinishing(false);
    }
  };

  const allExercises = categories.flatMap((c) => c.exercises.map((e) => ({ ...e, category: c.name })));

  if (loading) {
    return (
      <div className="flex min-h-[50vh] items-center justify-center">
        <div className="h-10 w-10 animate-spin rounded-full border-4 border-primary/20 border-t-primary" />
      </div>
    );
  }

  const isActive = session?.status === 'active';

  return (
    <div className="pb-24 lg:pb-12">
      <PageHero
        title="Workout Session"
        subtitle="Guided session mode with rest timer and exercise logging."
        icon={<Timer className="text-white" />}
        image={IMAGES.heroes.exercises}
      />

      <div className="mx-auto mt-8 max-w-6xl space-y-6 px-4 sm:px-6">
        {!session || !isActive ? (
          <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="card-modern p-8 text-center">
            {session?.status === 'completed' ? (
              <>
                <CheckCircle className="mx-auto text-accent" size={48} />
                <h2 className="font-display mt-4 text-xl font-bold text-ink">Session complete!</h2>
                <p className="mt-2 text-muted">{session.exercise_count} exercises logged.</p>
                <button onClick={startSession} className="btn-primary mt-6 inline-flex items-center gap-2 px-6 py-3">
                  <Play size={18} /> Start new session
                </button>
              </>
            ) : (
              <>
                <Dumbbell className="mx-auto text-primary" size={48} />
                <h2 className="font-display mt-4 text-xl font-bold text-ink">Ready to train?</h2>
                <p className="mt-2 text-muted">Start a session to log exercises with a built-in rest timer.</p>
                <button onClick={startSession} className="btn-accent mt-6 inline-flex items-center gap-2 px-8 py-3">
                  <Play size={18} /> Start session
                </button>
              </>
            )}
          </motion.div>
        ) : (
          <>
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <h2 className="font-display text-xl font-bold text-ink">{session.name}</h2>
                <p className="text-sm text-muted">
                  Started {new Date(session.started_at).toLocaleTimeString()} · {logs.length} logged
                </p>
              </div>
              <button
                onClick={finishSession}
                disabled={finishing}
                className="flex items-center gap-2 rounded-xl bg-red-500 px-4 py-2 text-sm font-bold text-white hover:bg-red-600 disabled:opacity-60"
              >
                <Square size={16} /> {finishing ? 'Finishing...' : 'Finish session'}
              </button>
            </div>

            <div className="grid gap-6 lg:grid-cols-3">
              <div className="space-y-4 lg:col-span-2">
                <div className="card-modern p-4">
                  <h3 className="font-display font-bold text-ink">Pick exercise</h3>
                  <div className="mt-3 max-h-48 space-y-1 overflow-y-auto">
                    {allExercises.slice(0, 30).map((ex) => (
                      <button
                        key={ex.id}
                        onClick={() => setSelected(ex)}
                        className={`w-full rounded-lg px-3 py-2 text-left text-sm transition ${
                          selected?.id === ex.id ? 'gradient-primary text-white' : 'hover:bg-surface-2'
                        }`}
                      >
                        {ex.name}
                        <span className="ml-2 text-xs opacity-70">{ex.category}</span>
                      </button>
                    ))}
                  </div>
                  <Link to="/exercises" className="mt-2 block text-xs font-bold text-primary hover:text-accent">
                    Browse full library →
                  </Link>
                </div>

                {selected && (
                  <div className="card-modern p-4">
                    <h3 className="font-display font-bold text-ink">{selected.name}</h3>
                    <div className="mt-3 grid grid-cols-3 gap-3">
                      <label className="text-sm font-semibold">
                        Sets
                        <input type="number" min={1} value={sets} onChange={(e) => setSets(Number(e.target.value))} className="mt-1 w-full rounded-lg border-2 border-border bg-input-bg px-3 py-2" />
                      </label>
                      <label className="text-sm font-semibold">
                        Reps
                        <input type="number" min={1} value={reps} onChange={(e) => setReps(Number(e.target.value))} className="mt-1 w-full rounded-lg border-2 border-border bg-input-bg px-3 py-2" />
                      </label>
                      <label className="text-sm font-semibold">
                        Weight (kg)
                        <input type="number" min={0} step={0.5} value={weight} onChange={(e) => setWeight(e.target.value === '' ? '' : Number(e.target.value))} placeholder="—" className="mt-1 w-full rounded-lg border-2 border-border bg-input-bg px-3 py-2" />
                      </label>
                    </div>
                    <button onClick={logExercise} disabled={logging} className="btn-accent mt-4 w-full py-2.5 disabled:opacity-60">
                      {logging ? 'Logging...' : 'Log set'}
                    </button>
                  </div>
                )}

                {logs.length > 0 && (
                  <div className="card-modern p-4">
                    <h3 className="font-display font-bold text-ink">Session log</h3>
                    <ul className="mt-3 space-y-2">
                      {logs.map((l) => (
                        <li key={l.id} className="flex justify-between text-sm">
                          <span className="font-semibold text-ink">{l.exercise_name}</span>
                          <span className="text-muted">
                            {[l.sets && `${l.sets}×${l.reps}`, l.weight_kg && `${l.weight_kg}kg`].filter(Boolean).join(' · ')}
                          </span>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>

              <div className="space-y-4">
                <RestTimer seconds={restSeconds} />
                <div className="card-modern p-4">
                  <label className="text-sm font-semibold text-ink">
                    Rest duration (sec)
                    <input
                      type="number"
                      min={15}
                      max={300}
                      step={15}
                      value={restSeconds}
                      onChange={(e) => setRestSeconds(Number(e.target.value))}
                      className="mt-1 w-full rounded-lg border-2 border-border bg-input-bg px-3 py-2"
                    />
                  </label>
                </div>
              </div>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
