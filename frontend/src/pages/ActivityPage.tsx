import { motion } from 'framer-motion';
import {
  Activity,
  Award,
  Medal,
  Scale,
  Target,
  TrendingUp,
  Dumbbell,
} from 'lucide-react';
import { useEffect, useState } from 'react';
import toast from 'react-hot-toast';
import PageHero from '../components/PageHero';
import StreakHero from '../components/StreakHero';
import LineChart from '../components/LineChart';
import WeeklyChart from '../components/WeeklyChart';
import WaterTracker from '../components/WaterTracker';
import CalendarHeatmap from '../components/CalendarHeatmap';
import { ListSkeleton } from '../components/Skeleton';
import EmptyState from '../components/EmptyState';
import { activityApi, wellnessApi } from '../lib/api';
import { IMAGES } from '../lib/images';
import type {
  BadgeInfo,
  BodyMetric,
  CalendarDay,
  DashboardStats,
  ExercisePR,
  Goal,
  MonthlyActivity,
  WeeklyActivity,
  WorkoutLog,
} from '../types';

const TABS = ['Overview', 'Metrics', 'Goals', 'Badges', 'Calendar'] as const;
type Tab = (typeof TABS)[number];

export default function ActivityPage() {
  const [tab, setTab] = useState<Tab>('Overview');
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [weekly, setWeekly] = useState<WeeklyActivity[]>([]);
  const [monthly, setMonthly] = useState<MonthlyActivity[]>([]);
  const [workouts, setWorkouts] = useState<WorkoutLog[]>([]);
  const [prs, setPrs] = useState<ExercisePR[]>([]);
  const [metrics, setMetrics] = useState<BodyMetric[]>([]);
  const [goals, setGoals] = useState<Goal[]>([]);
  const [badges, setBadges] = useState<BadgeInfo[]>([]);
  const [calendar, setCalendar] = useState<CalendarDay[]>([]);
  const [loading, setLoading] = useState(true);

  const [weight, setWeight] = useState('');
  const [bodyFat, setBodyFat] = useState('');
  const [metricNotes, setMetricNotes] = useState('');
  const [goalTitle, setGoalTitle] = useState('');
  const [goalTarget, setGoalTarget] = useState('10');

  useEffect(() => {
    Promise.all([
      activityApi.dashboard(),
      activityApi.weekly(),
      activityApi.monthly(),
      activityApi.workouts(30),
      activityApi.prs(),
      wellnessApi.metrics(),
      wellnessApi.goals(),
      wellnessApi.badges(),
      wellnessApi.calendar(30),
    ])
      .then(([s, w, m, logs, p, met, g, b, cal]) => {
        setStats(s);
        setWeekly(w);
        setMonthly(m);
        setWorkouts(logs);
        setPrs(p);
        setMetrics(met);
        setGoals(g);
        setBadges(b);
        setCalendar(cal);
      })
      .finally(() => setLoading(false));
  }, []);

  const logMetric = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const m = await wellnessApi.logMetric({
        weight_kg: weight ? Number(weight) : null,
        body_fat_pct: bodyFat ? Number(bodyFat) : null,
        notes: metricNotes || null,
      });
      setMetrics((prev) => [m, ...prev]);
      setWeight('');
      setBodyFat('');
      setMetricNotes('');
      toast.success('Metric logged');
    } catch {
      toast.error('Failed to log metric');
    }
  };

  const addGoal = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!goalTitle.trim()) return;
    try {
      const g = await wellnessApi.createGoal({
        title: goalTitle.trim(),
        goal_type: 'workouts',
        target_value: Number(goalTarget) || 10,
        unit: 'workouts',
      });
      setGoals((prev) => [g, ...prev]);
      setGoalTitle('');
      toast.success('Goal created');
    } catch {
      toast.error('Failed to create goal');
    }
  };

  const updateGoalProgress = async (goal: Goal, delta: number) => {
    const next = Math.max(0, goal.current_value + delta);
    try {
      const updated = await wellnessApi.updateGoal(goal.id, {
        current_value: next,
        completed: next >= goal.target_value,
      });
      setGoals((prev) => prev.map((g) => (g.id === goal.id ? updated : g)));
    } catch {
      toast.error('Failed to update goal');
    }
  };

  return (
    <div className="pb-24 lg:pb-12">
      <PageHero
        title="Activity & Progress"
        subtitle="Track workouts, streaks, body metrics, goals, badges, and more."
        icon={<TrendingUp className="text-white" />}
        image={IMAGES.heroes.exercises}
      />

      <div className="mx-auto mt-8 max-w-6xl space-y-6 px-4 sm:px-6">
        <div className="flex flex-wrap gap-2">
          {TABS.map((t) => (
            <button
              key={t}
              onClick={() => setTab(t)}
              className={`rounded-xl px-4 py-2 text-sm font-bold transition ${
                tab === t ? 'gradient-primary text-white' : 'bg-card text-ink hover:bg-surface-2'
              }`}
            >
              {t}
            </button>
          ))}
        </div>

        <WaterTracker />

        {loading ? (
          <ListSkeleton count={4} />
        ) : (
          <>
            {tab === 'Overview' && (
              <>
                {stats && <StreakHero streak={stats.current_streak} />}
                <div className="grid gap-6 lg:grid-cols-2">
                  {weekly.length > 0 && <WeeklyChart data={weekly} />}
                  {monthly.length > 0 && <LineChart data={monthly} />}
                </div>
                {prs.length > 0 && (
                  <section>
                    <h2 className="font-display mb-4 flex items-center gap-2 text-xl font-bold text-ink">
                      <Award className="text-accent" size={22} /> Personal Records
                    </h2>
                    <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
                      {prs.map((pr, i) => (
                        <motion.div key={pr.exercise_id} initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.05 }} className="card-modern p-4">
                          <p className="font-display font-bold text-primary">{pr.exercise_name}</p>
                          <p className="mt-1 text-sm text-muted">{pr.total_sessions} sessions</p>
                        </motion.div>
                      ))}
                    </div>
                  </section>
                )}
                <section>
                  <h2 className="font-display mb-4 flex items-center gap-2 text-xl font-bold text-ink">
                    <Activity size={22} className="text-primary" /> Workout History
                  </h2>
                  {workouts.length === 0 ? (
                    <EmptyState icon={Dumbbell} title="No workouts logged" description="Start logging exercises to build your history." actionLabel="Browse exercises" actionTo="/exercises" />
                  ) : (
                    <div className="space-y-3">
                      {workouts.map((w) => (
                        <div key={w.id} className="card-modern flex flex-wrap items-center justify-between gap-3 p-4">
                          <div>
                            <p className="font-display font-bold text-ink">{w.exercise_name}</p>
                            <p className="text-sm text-muted">
                              {[w.sets && `${w.sets} sets`, w.reps && `${w.reps} reps`, w.weight_kg && `${w.weight_kg} kg`].filter(Boolean).join(' · ') || 'Logged'}
                            </p>
                          </div>
                          <time className="text-xs text-muted">{new Date(w.logged_at).toLocaleString()}</time>
                        </div>
                      ))}
                    </div>
                  )}
                </section>
              </>
            )}

            {tab === 'Metrics' && (
              <div className="grid gap-6 lg:grid-cols-2">
                <form onSubmit={logMetric} className="card-modern space-y-3 p-5">
                  <h3 className="font-display flex items-center gap-2 font-bold text-ink">
                    <Scale size={18} /> Log body metric
                  </h3>
                  <input type="number" step="0.1" placeholder="Weight (kg)" value={weight} onChange={(e) => setWeight(e.target.value)} className="w-full rounded-xl border-2 border-border bg-input-bg px-3 py-2" />
                  <input type="number" step="0.1" placeholder="Body fat (%)" value={bodyFat} onChange={(e) => setBodyFat(e.target.value)} className="w-full rounded-xl border-2 border-border bg-input-bg px-3 py-2" />
                  <input type="text" placeholder="Notes" value={metricNotes} onChange={(e) => setMetricNotes(e.target.value)} className="w-full rounded-xl border-2 border-border bg-input-bg px-3 py-2" />
                  <button type="submit" className="btn-accent w-full py-2">Save metric</button>
                </form>
                <div className="card-modern p-5">
                  <h3 className="font-display font-bold text-ink">History</h3>
                  {metrics.length === 0 ? (
                    <p className="mt-3 text-sm text-muted">No metrics logged yet.</p>
                  ) : (
                    <ul className="mt-3 space-y-2">
                      {metrics.map((m) => (
                        <li key={m.id} className="flex justify-between text-sm">
                          <span>{new Date(m.logged_at).toLocaleDateString()}</span>
                          <span className="font-semibold text-ink">
                            {[m.weight_kg && `${m.weight_kg} kg`, m.body_fat_pct && `${m.body_fat_pct}% fat`].filter(Boolean).join(' · ')}
                          </span>
                        </li>
                      ))}
                    </ul>
                  )}
                </div>
              </div>
            )}

            {tab === 'Goals' && (
              <div className="grid gap-6 lg:grid-cols-2">
                <form onSubmit={addGoal} className="card-modern space-y-3 p-5">
                  <h3 className="font-display flex items-center gap-2 font-bold text-ink">
                    <Target size={18} /> New goal
                  </h3>
                  <input type="text" placeholder="Goal title" value={goalTitle} onChange={(e) => setGoalTitle(e.target.value)} required className="w-full rounded-xl border-2 border-border bg-input-bg px-3 py-2" />
                  <input type="number" min={1} placeholder="Target" value={goalTarget} onChange={(e) => setGoalTarget(e.target.value)} className="w-full rounded-xl border-2 border-border bg-input-bg px-3 py-2" />
                  <button type="submit" className="btn-primary w-full py-2">Create goal</button>
                </form>
                <div className="space-y-3">
                  {goals.length === 0 ? (
                    <p className="text-sm text-muted">No goals yet.</p>
                  ) : (
                    goals.map((g) => {
                      const pct = Math.min(100, (g.current_value / g.target_value) * 100);
                      return (
                        <div key={g.id} className="card-modern p-4">
                          <div className="flex items-start justify-between">
                            <div>
                              <p className="font-display font-bold text-ink">{g.title}</p>
                              <p className="text-sm text-muted">{g.current_value} / {g.target_value} {g.unit || ''}</p>
                            </div>
                            {g.completed && <Medal className="text-amber-500" size={20} />}
                          </div>
                          <div className="mt-2 h-2 overflow-hidden rounded-full bg-surface-2">
                            <div className="h-full bg-accent" style={{ width: `${pct}%` }} />
                          </div>
                          {!g.completed && (
                            <div className="mt-2 flex gap-2">
                              <button onClick={() => updateGoalProgress(g, 1)} className="btn-accent flex-1 py-1.5 text-xs">+1</button>
                              <button onClick={() => wellnessApi.deleteGoal(g.id).then(() => setGoals((prev) => prev.filter((x) => x.id !== g.id)))} className="rounded-lg px-3 py-1.5 text-xs text-red-500 hover:bg-red-50">Delete</button>
                            </div>
                          )}
                        </div>
                      );
                    })
                  )}
                </div>
              </div>
            )}

            {tab === 'Badges' && (
              <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
                {badges.map((b, i) => (
                  <motion.div
                    key={b.badge_id}
                    initial={{ opacity: 0, scale: 0.95 }}
                    animate={{ opacity: 1, scale: 1 }}
                    transition={{ delay: i * 0.04 }}
                    className={`card-modern p-5 ${b.earned ? '' : 'opacity-50 grayscale'}`}
                  >
                    <Medal className={b.earned ? 'text-amber-500' : 'text-muted'} size={32} />
                    <h3 className="font-display mt-2 font-bold text-ink">{b.title}</h3>
                    <p className="mt-1 text-sm text-muted">{b.description}</p>
                    {b.earned_at && (
                      <p className="mt-2 text-xs font-semibold text-accent">Earned {new Date(b.earned_at).toLocaleDateString()}</p>
                    )}
                  </motion.div>
                ))}
              </div>
            )}

            {tab === 'Calendar' && calendar.length > 0 && <CalendarHeatmap days={calendar} />}
          </>
        )}
      </div>
    </div>
  );
}
